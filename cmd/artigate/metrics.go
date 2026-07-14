package main

// The /metrics endpoint: Prometheus text-exposition telemetry for both sides,
// the polling half of ArtiGate's observability (webhooks in notify.go are the
// push half). It answers the day-2 questions an ops team running air-gapped
// mirrors asks first: is a stream falling behind, has a gap opened, when did a
// stream last collect or import, how much quota and disk is left, and are the
// nightly schedules succeeding.
//
// Everything derivable from on-disk state (sequence numbers, bundle counts and
// bytes, quota usage, disk space, schedule rows) is computed live at scrape
// time from the same status functions the dashboard uses, so /metrics never
// drifts from reality. The handful of facts that are not on disk — schedule and
// import outcome counters, per-stream last-success timestamps, and how long a
// gap has been open — live in the small in-memory lowMetrics/highMetrics values
// below, updated at the same choke points that fire the webhooks. Counters
// reset to zero on restart, which is the standard Prometheus counter contract.
//
// No Prometheus client library is pulled in: the text format is a few lines and
// the project deliberately stays close to the standard library.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// metricsContentType is the Prometheus text exposition format version served.
const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// -----------------------------------------------------------------------------
// Prometheus text encoder
// -----------------------------------------------------------------------------

// promWriter accumulates one exposition response. It emits each metric family's
// HELP/TYPE header exactly once (on the family's first sample) so callers can
// interleave samples of different families freely and in any order.
type promWriter struct {
	b       strings.Builder
	emitted map[string]bool
}

func newPromWriter() *promWriter {
	return &promWriter{emitted: map[string]bool{}}
}

// metric writes one sample, emitting the family header first if needed. labels
// is a flat list of alternating key, value pairs.
func (p *promWriter) metric(name, typ, help string, value float64, labels ...string) {
	if !p.emitted[name] {
		p.emitted[name] = true
		fmt.Fprintf(&p.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	p.b.WriteString(name)
	writeMetricLabels(&p.b, labels)
	p.b.WriteByte(' ')
	p.b.WriteString(formatMetricValue(value))
	p.b.WriteByte('\n')
}

func (p *promWriter) String() string { return p.b.String() }

// writeMetricLabels renders the {k="v",...} label set, escaping each value per
// the exposition format (backslash, double-quote, newline).
func writeMetricLabels(b *strings.Builder, labels []string) {
	if len(labels) < 2 {
		return
	}
	b.WriteByte('{')
	first := true
	for i := 0; i+1 < len(labels); i += 2 {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(labels[i])
		b.WriteString(`="`)
		b.WriteString(escapeMetricLabel(labels[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
}

func escapeMetricLabel(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// formatMetricValue renders a value without an exponent for whole numbers, so a
// unix timestamp or a byte count reads naturally.
func formatMetricValue(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// diskTarget names a directory to report filesystem space for.
type diskTarget struct {
	label string
	path  string
}

// writeDiskMetrics reports free/total bytes for each target whose filesystem can
// be measured (Linux only; elsewhere the samples are omitted).
func writeDiskMetrics(p *promWriter, targets []diskTarget) {
	for _, t := range targets {
		free, total, ok := diskUsage(t.path)
		if !ok {
			continue
		}
		p.metric("artigate_disk_free_bytes", "gauge",
			"Free bytes on the filesystem backing an ArtiGate directory.", float64(free), "dir", t.label)
		p.metric("artigate_disk_total_bytes", "gauge",
			"Total bytes on the filesystem backing an ArtiGate directory.", float64(total), "dir", t.label)
	}
}

// -----------------------------------------------------------------------------
// Low-side in-memory metric state
// -----------------------------------------------------------------------------

// lowMetrics holds the low-side facts that cannot be recomputed from disk at
// scrape time: scheduled-collect outcome counters, the last time each stream
// collected successfully, and which bundles' diode transfers last failed.
type lowMetrics struct {
	mu          sync.Mutex
	runsOK      map[string]int64
	runsFailed  map[string]int64
	lastSuccess map[string]time.Time
	// diodeFailed maps a bundle ID to its last failed diode transfer's error;
	// a later successful transfer of the same bundle clears it. /readyz reports
	// the entries whose files still wait in the outbound spool. Unlike the
	// counters, this state survives restarts: with a push diode configured,
	// startup rebuilds it from the bundles still staged in the spool
	// (restoreDiodeTransferBacklog), so a restart cannot hide a stuck transfer.
	diodeFailed map[string]string
}

func newLowMetrics() *lowMetrics {
	return &lowMetrics{
		runsOK:      map[string]int64{},
		runsFailed:  map[string]int64{},
		lastSuccess: map[string]time.Time{},
		diodeFailed: map[string]string{},
	}
}

// recordCollect records one scheduled-collect outcome for a stream. Safe on a
// nil receiver (a server built without metrics, as some tests do).
func (m *lowMetrics) recordCollect(stream string, ok bool, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.runsOK[stream]++
		m.lastSuccess[stream] = at
		return
	}
	m.runsFailed[stream]++
}

// recordDiodeTransfer records one bundle transfer's outcome (empty errDetail
// means success) for the /readyz diode-transfer check. Safe on a nil receiver.
func (m *lowMetrics) recordDiodeTransfer(bundleID, errDetail string) {
	if m == nil || bundleID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if errDetail == "" {
		delete(m.diodeFailed, bundleID)
		return
	}
	m.diodeFailed[bundleID] = errDetail
}

// diodeFailures copies the failed-transfer records for /readyz to read without
// holding the lock while it stats the outbound spool.
func (m *lowMetrics) diodeFailures() map[string]string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.diodeFailed))
	for k, v := range m.diodeFailed {
		out[k] = v
	}
	return out
}

// snapshot copies the counters and timestamps for the scrape handler to read
// without holding the lock while formatting.
func (m *lowMetrics) snapshot() (ok, failed map[string]int64, last map[string]time.Time) {
	if m == nil {
		return map[string]int64{}, map[string]int64{}, map[string]time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyInt64Map(m.runsOK), copyInt64Map(m.runsFailed), copyTimeMap(m.lastSuccess)
}

// -----------------------------------------------------------------------------
// High-side in-memory metric state
// -----------------------------------------------------------------------------

// gapEvent identifies a stream that has just become blocked by a missing
// bundle, so ImportNext can fire one gap_detected webhook per new gap.
type gapEvent struct {
	stream string
	seq    int64
}

// highMetrics holds the high-side facts not recomputable from disk: import and
// rejection counters, per-stream last-import timestamps, import-loop errors,
// when each currently-open gap first appeared (for gap-age reporting and
// edge-triggered gap webhooks), and the last import pass's completion time and
// outcome (for the /readyz pipeline and backlog checks).
type highMetrics struct {
	mu                sync.Mutex
	imported          map[string]int64
	rejected          map[string]int64
	gapsDetected      map[string]int64
	lastImport        map[string]time.Time
	gapSince          map[string]time.Time
	importErrors      int64
	lastImportPassEnd time.Time
	lastImportPassErr string
}

func newHighMetrics() *highMetrics {
	return &highMetrics{
		imported:     map[string]int64{},
		rejected:     map[string]int64{},
		gapsDetected: map[string]int64{},
		lastImport:   map[string]time.Time{},
		gapSince:     map[string]time.Time{},
	}
}

func (m *highMetrics) recordImport(stream string, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imported[stream]++
	m.lastImport[stream] = at
}

func (m *highMetrics) recordReject(stream string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejected[stream]++
}

func (m *highMetrics) recordImportError() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.importErrors++
}

// recordImportPass notes the completion of one full import pass (ImportNext),
// whatever triggered it — the background loop, a diode-ingest kick, or a
// manual /admin/import. /readyz fails when passes stop completing or the last
// one failed. Safe on a nil receiver.
func (m *highMetrics) recordImportPass(err error, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastImportPassEnd = at
	m.lastImportPassErr = ""
	if err != nil {
		m.lastImportPassErr = err.Error()
	}
}

// observeGaps reconciles the per-stream gap state against a fresh import status
// and returns the streams that have newly become blocked. A stream stays "since
// first seen" until it unblocks, so a persistent gap ages without re-firing;
// clearing a gap forgets its start time.
func (m *highMetrics) observeGaps(status ImportStatus, now time.Time) []gapEvent {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var events []gapEvent
	for _, st := range status.Streams {
		if st.BlockingMissing > 0 {
			if _, open := m.gapSince[st.Stream]; !open {
				m.gapSince[st.Stream] = now
				m.gapsDetected[st.Stream]++
				events = append(events, gapEvent{stream: st.Stream, seq: st.BlockingMissing})
			}
			continue
		}
		delete(m.gapSince, st.Stream)
	}
	return events
}

// highSnapshot is a lock-free copy of the high-side counters for the scrape
// and readiness handlers to format.
type highSnapshot struct {
	imported          map[string]int64
	rejected          map[string]int64
	gapsDetected      map[string]int64
	lastImport        map[string]time.Time
	gapSince          map[string]time.Time
	importErrors      int64
	lastImportPassEnd time.Time
	lastImportPassErr string
}

func (m *highMetrics) snapshot() highSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return highSnapshot{
		imported:          copyInt64Map(m.imported),
		rejected:          copyInt64Map(m.rejected),
		gapsDetected:      copyInt64Map(m.gapsDetected),
		lastImport:        copyTimeMap(m.lastImport),
		gapSince:          copyTimeMap(m.gapSince),
		importErrors:      m.importErrors,
		lastImportPassEnd: m.lastImportPassEnd,
		lastImportPassErr: m.lastImportPassErr,
	}
}

func copyInt64Map(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyTimeMap(m map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortedStreamKeys returns the union of the given maps' keys, sorted, so metric
// samples are emitted in a stable order.
func sortedStreamKeys(maps ...map[string]int64) []string {
	set := map[string]bool{}
	for _, mp := range maps {
		for k := range mp {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------------
// Low-side scrape handler
// -----------------------------------------------------------------------------

// serveMetrics answers GET/HEAD /metrics on the low side.
func (s *LowServer) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := newPromWriter()
	p.metric("artigate_up", "gauge", "1 when the ArtiGate process is serving.", 1, "side", "low")
	s.collectBundleMetrics(p)
	s.collectScheduleMetrics(p)
	s.collectJobMetrics(p)
	s.collectCollectMetrics(p)
	writeDiskMetrics(p, []diskTarget{
		{label: "root", path: s.cfg.Root},
		{label: "export", path: s.cfg.ExportDir},
	})
	writeMetricsResponse(w, r, p)
}

// collectBundleMetrics reports per-stream next sequence, retained bundle count,
// and on-diode bytes from the live bundle status.
func (s *LowServer) collectBundleMetrics(p *promWriter) {
	status := s.BundleStatus()
	for _, ss := range status.Streams {
		var retained, outbound, bytes int64
		for _, seq := range ss.ExportedSequences {
			bytes += seq.SizeBytes
			if seq.InArchive {
				retained++
			}
			if seq.InOutbound {
				outbound++
			}
		}
		p.metric("artigate_low_next_sequence", "gauge",
			"Next bundle sequence number to be allocated for a stream.", float64(ss.NextSequence), "stream", ss.Stream)
		p.metric("artigate_low_bundles_retained", "gauge",
			"Bundles retained in the low-side archive for a stream.", float64(retained), "stream", ss.Stream)
		p.metric("artigate_low_bundles_outbound", "gauge",
			"Bundles still staged in the export directory awaiting diode transfer.", float64(outbound), "stream", ss.Stream)
		p.metric("artigate_low_bundle_bytes", "gauge",
			"Total on-diode bytes of a stream's known bundles.", float64(bytes), "stream", ss.Stream)
	}
}

// collectScheduleMetrics reports the scheduled watches: how many are enabled,
// and each one's last run time and success.
func (s *LowServer) collectScheduleMetrics(p *promWriter) {
	watches, err := s.watches.List()
	if err != nil {
		p.metric("artigate_low_schedules_list_error", "gauge",
			"1 when the scheduler's watch list could not be read for metrics.", 1)
		return
	}
	var enabled int64
	for _, w := range watches {
		if w.Enabled {
			enabled++
		}
		id := strconv.FormatInt(w.ID, 10)
		success := float64(0)
		if w.LastStatus == "ok" {
			success = 1
		}
		if w.LastRunAt != nil {
			p.metric("artigate_low_schedule_last_run_timestamp_seconds", "gauge",
				"Unix time a scheduled collect last ran.", float64(w.LastRunAt.Unix()), "stream", w.Stream, "id", id)
			p.metric("artigate_low_schedule_last_run_success", "gauge",
				"1 if a scheduled collect's last run succeeded, 0 if it failed.", success, "stream", w.Stream, "id", id)
		}
	}
	p.metric("artigate_low_schedules", "gauge", "Enabled scheduled collects.", float64(enabled), "state", "enabled")
	p.metric("artigate_low_schedules", "gauge", "Enabled scheduled collects.", float64(len(watches)-int(enabled)), "state", "disabled")
}

// collectJobMetrics reports how many collect jobs are queued, running, or
// finished in each terminal state.
func (s *LowServer) collectJobMetrics(p *promWriter) {
	byState := map[string]int64{}
	for _, j := range s.jobs.list() {
		byState[j.State]++
	}
	for _, state := range []string{"queued", "running", "ok", "error", "canceled"} {
		p.metric("artigate_low_jobs", "gauge", "Collect jobs currently tracked, by state.", float64(byState[state]), "state", state)
	}
}

// collectCollectMetrics reports the scheduled-collect outcome counters and the
// per-stream last-successful-collect timestamp from the in-memory state.
func (s *LowServer) collectCollectMetrics(p *promWriter) {
	ok, failed, last := s.metrics.snapshot()
	for _, stream := range sortedStreamKeys(ok, failed) {
		p.metric("artigate_low_schedule_runs_total", "counter",
			"Scheduled collect runs since start, by outcome.", float64(ok[stream]), "stream", stream, "status", "ok")
		p.metric("artigate_low_schedule_runs_total", "counter",
			"Scheduled collect runs since start, by outcome.", float64(failed[stream]), "stream", stream, "status", "error")
	}
	for stream, t := range last {
		p.metric("artigate_low_last_successful_collect_timestamp_seconds", "gauge",
			"Unix time a stream last collected successfully.", float64(t.Unix()), "stream", stream)
	}
}

// -----------------------------------------------------------------------------
// High-side scrape handler
// -----------------------------------------------------------------------------

// serveMetrics answers GET/HEAD /metrics on the high side.
func (s *HighServer) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	p := newPromWriter()
	p.metric("artigate_up", "gauge", "1 when the ArtiGate process is serving.", 1, "side", "high")
	s.collectImportMetrics(p)
	s.collectQuotaMetrics(p)
	s.collectEventMetrics(p, now)
	writeDiskMetrics(p, []diskTarget{
		{label: "root", path: s.cfg.Root},
		{label: "landing", path: s.cfg.Landing},
	})
	writeMetricsResponse(w, r, p)
}

// collectImportMetrics reports per-stream sequence progress, import lag, gap
// state, and quarantine depth from the live import status.
func (s *HighServer) collectImportMetrics(p *promWriter) {
	status, err := s.importStatusReadOnly()
	if err != nil {
		p.metric("artigate_high_status_error", "gauge",
			"1 when import status could not be computed for metrics.", 1)
		return
	}
	for _, st := range status.Streams {
		lag := st.HighestSeenSequence - st.LastImportedSequence
		if lag < 0 {
			lag = 0
		}
		blocked := float64(0)
		if st.BlockingMissing > 0 {
			blocked = 1
		}
		p.metric("artigate_high_last_imported_sequence", "gauge",
			"Highest bundle sequence imported for a stream.", float64(st.LastImportedSequence), "stream", st.Stream)
		p.metric("artigate_high_highest_seen_sequence", "gauge",
			"Highest complete bundle sequence seen (landing or quarantine) for a stream.", float64(st.HighestSeenSequence), "stream", st.Stream)
		p.metric("artigate_high_import_lag", "gauge",
			"Bundles seen but not yet imported for a stream (highest_seen - last_imported).", float64(lag), "stream", st.Stream)
		p.metric("artigate_high_stream_blocked", "gauge",
			"1 when a stream is blocked waiting for a missing bundle.", blocked, "stream", st.Stream)
		p.metric("artigate_high_blocking_missing_sequence", "gauge",
			"The missing bundle sequence blocking a stream, 0 when none.", float64(st.BlockingMissing), "stream", st.Stream)
		p.metric("artigate_high_quarantined_bundles", "gauge",
			"Complete future bundles held in quarantine for a stream.", float64(len(st.QuarantinedSequences)), "stream", st.Stream)
	}
}

// collectQuotaMetrics reports the shared unverified-transport quota usage.
func (s *HighServer) collectQuotaMetrics(p *promWriter) {
	used, err := s.unverifiedTransportBytes()
	if err == nil {
		p.metric("artigate_high_unverified_transport_bytes", "gauge",
			"Bytes of unverified transport data (landing + quarantine + rejected).", float64(used))
	}
	p.metric("artigate_high_unverified_transport_max_bytes", "gauge",
		"The shared unverified-transport storage quota.", float64(diodeMaxUnverifiedBytes))
}

// collectEventMetrics reports the import/reject/gap counters, per-stream last
// import time, and how long each open gap has been open.
func (s *HighServer) collectEventMetrics(p *promWriter, now time.Time) {
	snap := s.snapshotHighMetrics()
	p.metric("artigate_high_import_errors_total", "counter",
		"Import-loop failures since start.", float64(snap.importErrors))
	for _, stream := range sortedStreamKeys(snap.imported, snap.rejected, snap.gapsDetected) {
		p.metric("artigate_high_bundles_imported_total", "counter",
			"Bundles imported since start, by stream.", float64(snap.imported[stream]), "stream", stream)
		p.metric("artigate_high_bundles_rejected_total", "counter",
			"Bundles rejected since start, by stream.", float64(snap.rejected[stream]), "stream", stream)
		p.metric("artigate_high_gaps_detected_total", "counter",
			"Sequencing gaps detected since start, by stream.", float64(snap.gapsDetected[stream]), "stream", stream)
	}
	for stream, t := range snap.lastImport {
		p.metric("artigate_high_last_import_timestamp_seconds", "gauge",
			"Unix time a stream last imported a bundle.", float64(t.Unix()), "stream", stream)
	}
	for stream, since := range snap.gapSince {
		age := now.Sub(since).Seconds()
		if age < 0 {
			age = 0
		}
		p.metric("artigate_high_gap_age_seconds", "gauge",
			"How long a stream's current blocking gap has been open.", age, "stream", stream)
	}
}

// snapshotHighMetrics reads the high-side counters, tolerating a nil metrics
// value (defensive; the server always constructs one).
func (s *HighServer) snapshotHighMetrics() highSnapshot {
	if s.metrics == nil {
		return highSnapshot{}
	}
	return s.metrics.snapshot()
}

// -----------------------------------------------------------------------------
// Shared response
// -----------------------------------------------------------------------------

func writeMetricsResponse(w http.ResponseWriter, r *http.Request, p *promWriter) {
	w.Header().Set("Content-Type", metricsContentType)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write([]byte(p.String()))
}
