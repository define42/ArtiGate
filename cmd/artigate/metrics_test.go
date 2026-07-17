package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// promWriter formatting
// -----------------------------------------------------------------------------

func TestPromWriterHeaderOnce(t *testing.T) {
	p := newPromWriter()
	p.metric("x_total", "counter", "help text", 1, "stream", "go")
	p.metric("x_total", "counter", "help text", 2, "stream", "npm")
	out := p.String()
	if n := strings.Count(out, "# TYPE x_total counter"); n != 1 {
		t.Errorf("TYPE header emitted %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, `x_total{stream="go"} 1`) {
		t.Errorf("missing first sample:\n%s", out)
	}
	if !strings.Contains(out, `x_total{stream="npm"} 2`) {
		t.Errorf("missing second sample:\n%s", out)
	}
}

func TestPromWriterFormatting(t *testing.T) {
	if got := formatMetricValue(1720000000); got != "1720000000" {
		t.Errorf("big int rendered with exponent: %q", got)
	}
	if got := formatMetricValue(12.5); got != "12.5" {
		t.Errorf("fractional value = %q", got)
	}
	if got := escapeMetricLabel(`a"b\c` + "\n"); got != `a\"b\\c\n` {
		t.Errorf("label escaping = %q", got)
	}
}

func TestPromWriterNoLabels(t *testing.T) {
	p := newPromWriter()
	p.metric("plain_gauge", "gauge", "h", 3)
	if !strings.Contains(p.String(), "plain_gauge 3\n") {
		t.Errorf("no-label sample malformed:\n%s", p.String())
	}
}

// -----------------------------------------------------------------------------
// Low-side /metrics
// -----------------------------------------------------------------------------

func TestLowMetricsEndpoint(t *testing.T) {
	ls, _ := newAptLowServer(t)
	ls.metrics.recordCollect("python", true, time.Unix(1720000000, 0))
	ls.metrics.recordCollect("python", false, time.Unix(1720000001, 0))

	srv := httptest.NewServer(ls)
	defer srv.Close()
	code, body := httpGet(t, srv.URL+"/metrics")
	if code != 200 {
		t.Fatalf("GET /metrics = %d", code)
	}
	for _, want := range []string{
		`artigate_up{side="low"} 1`,
		fmt.Sprintf(`artigate_build_info{side="low",version="%s",manifest_format="%d"} 1`, versionString(), manifestFormatCurrent),
		"artigate_low_next_sequence",
		"artigate_low_bundle_bytes",
		"artigate_low_jobs{state=\"queued\"}",
		`artigate_low_schedule_runs_total{stream="python",status="ok"} 1`,
		`artigate_low_schedule_runs_total{stream="python",status="error"} 1`,
		`artigate_low_last_successful_collect_timestamp_seconds{stream="python"} 1720000000`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("low /metrics missing %q\n---\n%s", want, body)
		}
	}
	ct := "text/plain; version=0.0.4"
	if !strings.Contains(bodyContentType(t, srv.URL+"/metrics"), ct) {
		t.Errorf("content-type is not the prometheus exposition type")
	}
}

// -----------------------------------------------------------------------------
// High-side /metrics: import lag, timestamps, quota
// -----------------------------------------------------------------------------

func TestHighMetricsAfterImport(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("ImportNext: %v", err)
	}

	body := scrapeMetrics(t, hs)
	for _, want := range []string{
		`artigate_up{side="high"} 1`,
		fmt.Sprintf(`artigate_build_info{side="high",version="%s",manifest_format="%d"} 1`, versionString(), manifestFormatCurrent),
		`artigate_high_last_imported_sequence{stream="go"} 1`,
		`artigate_high_import_lag{stream="go"} 0`,
		`artigate_high_stream_blocked{stream="go"} 0`,
		`artigate_high_bundles_imported_total{stream="go"} 1`,
		"artigate_high_last_import_timestamp_seconds{stream=\"go\"}",
		"artigate_high_unverified_transport_max_bytes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("high /metrics missing %q\n---\n%s", want, body)
		}
	}
}

func TestHighMetricsGapDetection(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// Sequence 2 arrives with 1 still missing: a real blocking gap.
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("ImportNext: %v", err)
	}

	body := scrapeMetrics(t, hs)
	for _, want := range []string{
		`artigate_high_stream_blocked{stream="go"} 1`,
		`artigate_high_blocking_missing_sequence{stream="go"} 1`,
		`artigate_high_import_lag{stream="go"} 2`,
		`artigate_high_gaps_detected_total{stream="go"} 1`,
		"artigate_high_gap_age_seconds{stream=\"go\"}",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("high /metrics missing %q\n---\n%s", want, body)
		}
	}

	// The gap is edge-triggered: a second import pass must not double-count it.
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	if got := hs.metrics.snapshot().gapsDetected[streamGo]; got != 1 {
		t.Errorf("gaps_detected re-counted a standing gap: got %d, want 1", got)
	}
}

func TestHighMetricsRejectCounter(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)
	// Corrupt the signature so the bundle is rejected as content-invalid.
	sigPath := filepath.Join(hs.cfg.Landing, bundleIDFor(streamGo, 1)+".manifest.json.sig")
	writeFile(t, sigPath, []byte("bm90LWEtcmVhbC1zaWduYXR1cmU=\n"))

	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if len(res.RejectedBundles) != 1 {
		t.Fatalf("bundle was not rejected: %+v", res)
	}
	body := scrapeMetrics(t, hs)
	if !strings.Contains(body, `artigate_high_bundles_rejected_total{stream="go"} 1`) {
		t.Errorf("reject counter missing\n---\n%s", body)
	}
}

func TestGapWebhookFires(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	got := make(chan map[string]any, 4)
	recv := webhookReceiver(t, got)
	defer recv.Close()
	hs.notifier = &webhookNotifier{url: recv.URL, side: "high", client: recv.Client()}

	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}

	select {
	case doc := <-got:
		if doc["event"] != "gap_detected" || doc["stream"] != "go" {
			t.Errorf("unexpected gap webhook: %+v", doc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gap_detected webhook was not delivered")
	}
}

// -----------------------------------------------------------------------------
// Read-only status does not fire webhooks or count gaps
// -----------------------------------------------------------------------------

func TestScrapeDoesNotCountGaps(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)

	// Scraping alone (no ImportNext) must not fire gap counters — only the
	// import loop is edge-triggered.
	_ = scrapeMetrics(t, hs)
	if got := hs.metrics.snapshot().gapsDetected[streamGo]; got != 0 {
		t.Errorf("scrape counted a gap: got %d, want 0", got)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func scrapeMetrics(t *testing.T, hs *HighServer) string {
	t.Helper()
	srv := httptest.NewServer(hs)
	defer srv.Close()
	code, body := httpGet(t, srv.URL+"/metrics")
	if code != 200 {
		t.Fatalf("GET /metrics = %d", code)
	}
	return body
}

func webhookReceiver(t *testing.T, sink chan map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		sink <- doc
	}))
}

func bodyContentType(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("Content-Type")
}

// TestDiskMetricsPresentOnLinux verifies the disk gauges appear where statfs is
// available; on non-Linux the samples are legitimately absent.
func TestDiskMetricsPresent(t *testing.T) {
	dir := t.TempDir()
	_, _, ok := diskUsage(dir)
	if !ok {
		t.Skip("disk usage not supported on this platform")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	p := newPromWriter()
	writeDiskMetrics(p, []diskTarget{{label: "root", path: dir}})
	if !strings.Contains(p.String(), `artigate_disk_total_bytes{dir="root"}`) {
		t.Errorf("disk metrics missing:\n%s", p.String())
	}
}
