package main

// Tests for the /readyz readiness endpoint on both sides: response shape,
// method gating, and each go/no-go check (low: schedule store, export spool,
// diode transfers; high: blocked streams, import pass staleness/failure,
// undrained backlog, transport quota).

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// getReady serves one /readyz request against a side's handler and returns the
// status code and body.
func getReady(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

// -----------------------------------------------------------------------------
// Response shape and method gating
// -----------------------------------------------------------------------------

func TestLowReadyzOK(t *testing.T) {
	ls, _ := newAptLowServer(t)

	if code, body := getReady(t, ls, "/readyz"); code != http.StatusOK || body != "ok\n" {
		t.Errorf("GET /readyz = %d %q, want 200 ok", code, body)
	}
	code, body := getReady(t, ls, "/readyz?verbose")
	if code != http.StatusOK {
		t.Fatalf("GET /readyz?verbose = %d", code)
	}
	for _, want := range []string{
		"[+] watch-store ok",
		"[+] export-spool ok",
		"[+] diode-transfer ok",
		"ready\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("verbose body missing %q\n---\n%s", want, body)
		}
	}
}

func TestReadyzMethodAndHead(t *testing.T) {
	ls, _ := newAptLowServer(t)
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	for name, h := range map[string]http.Handler{"low": ls, "high": hs} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/readyz", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s POST /readyz = %d, want 405", name, rec.Code)
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/readyz", nil))
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Errorf("%s HEAD /readyz = %d with %d body bytes, want 200 and none", name, rec.Code, rec.Body.Len())
		}
	}
}

// -----------------------------------------------------------------------------
// Low-side checks
// -----------------------------------------------------------------------------

func TestLowReadyzExportSpoolMissing(t *testing.T) {
	ls, _ := newAptLowServer(t)
	if err := os.RemoveAll(ls.cfg.ExportDir); err != nil {
		t.Fatal(err)
	}
	code, body := getReady(t, ls, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz = %d, want 503", code)
	}
	if !strings.Contains(body, "[-] export-spool") || !strings.Contains(body, "not ready\n") {
		t.Errorf("body does not report the missing export spool:\n%s", body)
	}
	// The passing checks are still listed alongside the failure.
	if !strings.Contains(body, "[+] watch-store ok") {
		t.Errorf("failure body should list passing checks too:\n%s", body)
	}
}

func TestLowReadyzWatchStoreBroken(t *testing.T) {
	ls, _ := newAptLowServer(t)
	if err := ls.watches.Close(); err != nil {
		t.Fatal(err)
	}
	code, body := getReady(t, ls, "/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "[-] watch-store") {
		t.Errorf("closed watch store: GET /readyz = %d\n%s", code, body)
	}
}

// stageFakeOutboundBundle writes the three bundle files directly into the
// export dir, as a committed-but-untransferred export would leave them.
func stageFakeOutboundBundle(t *testing.T, dir, bundleID string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, suf := range bundleSuffixes() {
		writeFile(t, filepath.Join(dir, bundleID+suf), []byte("x"))
	}
}

// The full diode-transfer readiness lifecycle over the HTTP transport: a
// failed upload marks the bundle stuck and fails readiness; a later successful
// transfer of the same bundle clears both the spool and the failure record.
func TestLowReadyzDiodeTransferLifecycle(t *testing.T) {
	ls, _ := newAptLowServer(t)
	id := bundleIDFor(streamGo, 1)
	stageFakeOutboundBundle(t, ls.cfg.ExportDir, id)

	var accept atomic.Bool
	diode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accept.Load() {
			http.Error(w, "diode down", http.StatusBadGateway)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer diode.Close()
	ls.cfg.DiodeURL = diode.URL

	res := ExportResult{BundleID: id}
	ls.uploadBundleIfConfigured(context.Background(), &res)
	if res.DiodeError == "" {
		t.Fatal("upload against a failing endpoint should report a diode error")
	}
	code, body := getReady(t, ls, "/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "[-] diode-transfer") || !strings.Contains(body, id) {
		t.Errorf("failed transfer: GET /readyz = %d\n%s", code, body)
	}

	// A successful re-transmit clears the outbound spool and the failure.
	accept.Store(true)
	retry := ExportResult{BundleID: id}
	ls.uploadBundleIfConfigured(context.Background(), &retry)
	if retry.DiodeError != "" {
		t.Fatalf("retry upload failed: %s", retry.DiodeError)
	}
	if code, body := getReady(t, ls, "/readyz"); code != http.StatusOK {
		t.Errorf("after successful re-transmit: GET /readyz = %d\n%s", code, body)
	}
	if bundleCompleteInDir(ls.cfg.ExportDir, id) {
		t.Error("successful transfer should clear the outbound spool")
	}
}

// A recorded failure whose files are no longer staged (an operator carried
// them across by hand) must not hold readiness down.
func TestLowReadyzDiodeFailureClearedBySpool(t *testing.T) {
	ls, _ := newAptLowServer(t)
	ls.metrics.recordDiodeTransfer(bundleIDFor(streamGo, 7), "send failed")
	if code, body := getReady(t, ls, "/readyz"); code != http.StatusOK {
		t.Errorf("failure without staged files: GET /readyz = %d\n%s", code, body)
	}
}

// -----------------------------------------------------------------------------
// High-side checks
// -----------------------------------------------------------------------------

func TestHighReadyzOK(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	if code, body := getReady(t, hs, "/readyz"); code != http.StatusOK || body != "ok\n" {
		t.Errorf("GET /readyz = %d %q, want 200 ok", code, body)
	}
	code, body := getReady(t, hs, "/readyz?verbose")
	if code != http.StatusOK {
		t.Fatalf("GET /readyz?verbose = %d", code)
	}
	for _, want := range []string{
		"[+] import-status ok",
		"[+] stream-gaps ok",
		"[+] import-backlog ok",
		"[+] import-pipeline ok (background import disabled)",
		"[+] transport-quota ok",
		"ready\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("verbose body missing %q\n---\n%s", want, body)
		}
	}
}

func TestHighReadyzBlockedStream(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// Sequence 2 arrives with 1 still missing: the stream blocks on the gap.
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("ImportNext: %v", err)
	}

	code, body := getReady(t, hs, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("blocked stream: GET /readyz = %d, want 503", code)
	}
	if !strings.Contains(body, "[-] stream-gaps") || !strings.Contains(body, "stream go waiting for missing bundle 1") {
		t.Errorf("body does not name the blocking gap:\n%s", body)
	}
}

func TestHighReadyzImportPassFailure(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	hs.metrics.recordImportPass(errors.New("no space left on device"), time.Now().UTC())

	code, body := getReady(t, hs, "/readyz")
	if code != http.StatusServiceUnavailable ||
		!strings.Contains(body, "[-] import-pipeline: last import pass failed: no space left on device") {
		t.Errorf("failed pass: GET /readyz = %d\n%s", code, body)
	}

	// The next clean pass recovers readiness.
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	if code, body := getReady(t, hs, "/readyz"); code != http.StatusOK {
		t.Errorf("after clean pass: GET /readyz = %d\n%s", code, body)
	}
}

func TestHighReadyzStalledImportLoop(t *testing.T) {
	pub, _ := newTestKeys(t)
	cfg := HighConfig{Root: t.TempDir(), Landing: t.TempDir(), ImportInterval: 10 * time.Second}
	hs, err := NewHighServer(cfg, pub)
	if err != nil {
		t.Fatal(err)
	}

	// Fresh from construction the pass clock is within the grace window.
	if code, body := getReady(t, hs, "/readyz"); code != http.StatusOK {
		t.Errorf("fresh server: GET /readyz = %d\n%s", code, body)
	}

	// No pass for far longer than three intervals: the loop is dead or wedged.
	hs.metrics.recordImportPass(nil, time.Now().UTC().Add(-10*time.Minute))
	code, body := getReady(t, hs, "/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "[-] import-pipeline: no import pass has completed") {
		t.Errorf("stalled loop: GET /readyz = %d\n%s", code, body)
	}
}

func TestHighReadyzBacklogUndrained(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)

	// A just-landed bundle is within the grace window: still ready.
	if code, body := getReady(t, hs, "/readyz"); code != http.StatusOK {
		t.Errorf("fresh backlog: GET /readyz = %d\n%s", code, body)
	}

	// Nothing has drained it past the grace window: not ready.
	hs.metrics.recordImportPass(nil, time.Now().UTC().Add(-2*time.Minute))
	code, body := getReady(t, hs, "/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "[-] import-backlog: bundles ready to import on go") {
		t.Errorf("undrained backlog: GET /readyz = %d\n%s", code, body)
	}

	// Importing the backlog recovers readiness.
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	if code, body := getReady(t, hs, "/readyz"); code != http.StatusOK {
		t.Errorf("after import: GET /readyz = %d\n%s", code, body)
	}
}

// -----------------------------------------------------------------------------
// Check helpers
// -----------------------------------------------------------------------------

func TestReadyzImportGrace(t *testing.T) {
	for _, tt := range []struct {
		interval, want time.Duration
	}{
		{0, time.Minute},
		{10 * time.Second, time.Minute},
		{10 * time.Minute, 30 * time.Minute},
	} {
		if got := readyzImportGrace(tt.interval); got != tt.want {
			t.Errorf("readyzImportGrace(%s) = %s, want %s", tt.interval, got, tt.want)
		}
	}
}

func TestTransportQuotaCheck(t *testing.T) {
	if c := transportQuotaCheck(1, 100); !c.ok() || !strings.Contains(c.info, "of") {
		t.Errorf("under quota should pass with usage info, got %+v", c)
	}
	if c := transportQuotaCheck(100, 100); c.ok() || !strings.Contains(c.fail, "quota exhausted") {
		t.Errorf("exhausted quota should fail, got %+v", c)
	}
}

func TestCheckStreamGapsReportsAge(t *testing.T) {
	status := ImportStatus{Streams: []StreamImportStatus{
		{Stream: "go", BlockingMissing: 3},
		{Stream: "npm"},
	}}
	now := time.Unix(1720000000, 0).UTC()
	since := map[string]time.Time{"go": now.Add(-90 * time.Second)}
	c := checkStreamGaps(status, since, now)
	if c.ok() || !strings.Contains(c.fail, "stream go waiting for missing bundle 3 for 1m30s") {
		t.Errorf("gap age missing: %+v", c)
	}
	if strings.Contains(c.fail, "npm") {
		t.Errorf("unblocked stream reported: %+v", c)
	}
}
