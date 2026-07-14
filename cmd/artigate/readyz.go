package main

// The /readyz endpoint: the go/no-go readiness probe next to /metrics
// (telemetry) and the webhooks (push alerts). /healthz stays the liveness
// check — "the process is up", unconditionally — while /readyz answers the
// operational question monitoring actually needs: is this side able to do its
// job right now?
//
// The low side is ready when its control plane works: the schedule store
// answers, the export spool is reachable, and no bundle's last diode transfer
// failed while its files still wait in the outbound spool. The high side is
// ready when the import pipeline is moving: import status is computable, no
// stream is blocked behind a missing bundle, import passes keep completing
// (and the last one succeeded), landed bundles are not piling up undrained,
// and the unverified-transport quota has room for the diode to land more.
//
// Every check reads the same live state the dashboard and /metrics use;
// nothing is probed by mutating disk, so scraping /readyz never changes
// state. Responses follow the Kubernetes convention: 200 with "ok" when
// ready (append ?verbose for the per-check list), 503 with the full check
// list when not.

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// serveObservability routes the always-open monitoring endpoints both sides
// share — /healthz (liveness), /readyz (readiness), /metrics (telemetry) —
// to the given side-specific handlers. It reports whether it wrote a response.
func serveObservability(w http.ResponseWriter, r *http.Request, readyz, metrics http.HandlerFunc) bool {
	switch r.URL.Path {
	case "/healthz":
		_, _ = w.Write([]byte("ok\n"))
	case "/readyz":
		readyz(w, r)
	case "/metrics":
		metrics(w, r)
	default:
		return false
	}
	return true
}

// readyCheck is one named readiness probe outcome. The check passed when fail
// is empty; info optionally annotates a passing check in verbose output.
type readyCheck struct {
	name string
	fail string
	info string
}

func (c readyCheck) ok() bool { return c.fail == "" }

// writeReadyzResponse renders a check list Kubernetes-style: 200 "ok" when
// everything passed (the per-check detail behind ?verbose), 503 with every
// check spelled out when something failed.
func writeReadyzResponse(w http.ResponseWriter, r *http.Request, checks []readyCheck) {
	ready := true
	for _, c := range checks {
		ready = ready && c.ok()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if r.Method == http.MethodHead {
		return
	}
	if ready && !r.URL.Query().Has("verbose") {
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	var b strings.Builder
	for _, c := range checks {
		switch {
		case !c.ok():
			fmt.Fprintf(&b, "[-] %s: %s\n", c.name, c.fail)
		case c.info != "":
			fmt.Fprintf(&b, "[+] %s ok (%s)\n", c.name, c.info)
		default:
			fmt.Fprintf(&b, "[+] %s ok\n", c.name)
		}
	}
	if ready {
		b.WriteString("ready\n")
	} else {
		b.WriteString("not ready\n")
	}
	_, _ = w.Write([]byte(b.String()))
}

// readyzImportGrace is how long the high side may go without completing an
// import pass before readiness fails: three background intervals, but never
// less than a minute so kick-driven and manual deployments (interval 0) get a
// sane default and a probe can never flap on one slow tick.
func readyzImportGrace(interval time.Duration) time.Duration {
	grace := 3 * interval
	if grace < time.Minute {
		grace = time.Minute
	}
	return grace
}

// -----------------------------------------------------------------------------
// Low-side readiness
// -----------------------------------------------------------------------------

// serveReadyz answers GET/HEAD /readyz on the low side.
func (s *LowServer) serveReadyz(w http.ResponseWriter, r *http.Request) {
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeReadyzResponse(w, r, []readyCheck{
		s.checkWatchStore(),
		s.checkExportSpool(),
		s.checkDiodeTransfers(),
	})
}

// checkWatchStore fails when the schedule database cannot be read: the
// scheduler and the dashboard are blind until it answers again.
func (s *LowServer) checkWatchStore() readyCheck {
	c := readyCheck{name: "watch-store"}
	if _, err := s.watches.List(); err != nil {
		c.fail = fmt.Sprintf("cannot read the schedule store: %v", err)
	}
	return c
}

// checkExportSpool fails when the export directory is gone (an unmounted
// spool, say): every collect would fail to stage its bundle.
func (s *LowServer) checkExportSpool() readyCheck {
	c := readyCheck{name: "export-spool"}
	info, err := os.Stat(s.cfg.ExportDir)
	switch {
	case err != nil:
		c.fail = fmt.Sprintf("export directory unavailable: %v", err)
	case !info.IsDir():
		c.fail = fmt.Sprintf("export path %s is not a directory", s.cfg.ExportDir)
	}
	return c
}

// checkDiodeTransfers fails while any bundle's last diode transfer (UDP pitch
// or HTTP upload) failed and its files still sit in the outbound spool
// awaiting a re-transmit. A transfer that later succeeds clears the record;
// files that leave the spool any other way (an operator carrying them across
// by hand) clear it too, since the failure is then moot. Restarts do not
// clear it: startup re-marks whatever is still staged in the spool
// (restoreDiodeTransferBacklog), so the check keeps failing across a redeploy
// until the bundle actually transfers.
func (s *LowServer) checkDiodeTransfers() readyCheck {
	c := readyCheck{name: "diode-transfer"}
	var stuck []string
	for id, detail := range s.metrics.diodeFailures() {
		if bundleCompleteInDir(s.cfg.ExportDir, id) {
			stuck = append(stuck, fmt.Sprintf("%s (%s)", id, detail))
		}
	}
	if len(stuck) > 0 {
		sort.Strings(stuck)
		c.fail = "transfer failed, staged for re-transmit: " + strings.Join(stuck, "; ")
	}
	return c
}

// -----------------------------------------------------------------------------
// High-side readiness
// -----------------------------------------------------------------------------

// serveReadyz answers GET/HEAD /readyz on the high side.
func (s *HighServer) serveReadyz(w http.ResponseWriter, r *http.Request) {
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	snap := s.snapshotHighMetrics()
	var checks []readyCheck
	status, err := s.importStatusReadOnly()
	if err != nil {
		checks = append(checks, readyCheck{
			name: "import-status",
			fail: fmt.Sprintf("cannot compute import status: %v", err),
		})
	} else {
		checks = append(checks,
			readyCheck{name: "import-status"},
			checkStreamGaps(status, snap.gapSince, now),
			checkImportBacklog(status, snap, s.cfg.ImportInterval, now),
		)
	}
	checks = append(checks,
		checkImportPipeline(snap, s.cfg.ImportInterval, now),
		s.checkTransportQuota(),
	)
	writeReadyzResponse(w, r, checks)
}

// checkStreamGaps fails while any stream is blocked waiting for a missing
// bundle: everything behind the gap sits in quarantine until the low side
// re-sends the missing sequence.
func checkStreamGaps(status ImportStatus, gapSince map[string]time.Time, now time.Time) readyCheck {
	c := readyCheck{name: "stream-gaps"}
	var blocked []string
	for _, st := range status.Streams {
		if st.BlockingMissing <= 0 {
			continue
		}
		msg := fmt.Sprintf("stream %s waiting for missing bundle %d", st.Stream, st.BlockingMissing)
		if since, open := gapSince[st.Stream]; open {
			msg += fmt.Sprintf(" for %s", now.Sub(since).Round(time.Second))
		}
		blocked = append(blocked, msg)
	}
	if len(blocked) > 0 {
		c.fail = strings.Join(blocked, "; ")
	}
	return c
}

// checkImportBacklog fails when complete bundles sit ready to import but no
// import pass has completed within the grace window — nothing is draining
// them (a dead loop, or a manual deployment awaiting POST /admin/import). A
// backlog mid-drain never trips it: the draining pass holds the status lock,
// so by the time this check can read the status the pass has finished and
// refreshed the pass clock.
func checkImportBacklog(status ImportStatus, snap highSnapshot, interval time.Duration, now time.Time) readyCheck {
	c := readyCheck{name: "import-backlog"}
	var waiting []string
	for _, st := range status.Streams {
		if st.ReadyToImport {
			waiting = append(waiting, st.Stream)
		}
	}
	if len(waiting) == 0 {
		return c
	}
	if age := now.Sub(snap.lastImportPassEnd); age > readyzImportGrace(interval) {
		c.fail = fmt.Sprintf("bundles ready to import on %s but no import pass has completed for %s",
			strings.Join(waiting, ", "), age.Round(time.Second))
	}
	return c
}

// checkImportPipeline fails when the last completed import pass failed, or —
// with background import enabled — when passes stop completing at all (the
// loop goroutine died, or every pass hangs).
func checkImportPipeline(snap highSnapshot, interval time.Duration, now time.Time) readyCheck {
	c := readyCheck{name: "import-pipeline"}
	if snap.lastImportPassErr != "" {
		c.fail = "last import pass failed: " + snap.lastImportPassErr
		return c
	}
	if interval <= 0 {
		c.info = "background import disabled"
		return c
	}
	age := now.Sub(snap.lastImportPassEnd)
	if age > readyzImportGrace(interval) {
		c.fail = fmt.Sprintf("no import pass has completed for %s (background interval %s)",
			age.Round(time.Second), interval)
		return c
	}
	c.info = fmt.Sprintf("last pass %s ago", age.Round(time.Second))
	return c
}

// checkTransportQuota reports the shared unverified-transport quota (landing +
// quarantine + rejected), failing when it is exhausted: the diode cannot land
// new bundles — ingest answers 507 and the UDP catcher drops transfers — until
// an operator clears space.
func (s *HighServer) checkTransportQuota() readyCheck {
	used, err := s.unverifiedTransportBytes()
	if err != nil {
		return readyCheck{
			name: "transport-quota",
			fail: fmt.Sprintf("cannot measure unverified transport storage: %v", err),
		}
	}
	return transportQuotaCheck(used, diodeMaxUnverifiedBytes)
}

func transportQuotaCheck(used, maxBytes int64) readyCheck {
	c := readyCheck{name: "transport-quota"}
	if used >= maxBytes {
		c.fail = fmt.Sprintf("unverified transport storage quota exhausted (%s of %s); the diode cannot land new bundles",
			formatBytes(used), formatBytes(maxBytes))
		return c
	}
	c.info = fmt.Sprintf("%s of %s used", formatBytes(used), formatBytes(maxBytes))
	return c
}
