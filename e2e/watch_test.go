//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestWatchScheduler drives the scheduled-collect subsystem end-to-end, which
// no e2e test touches otherwise: a watch created through the low-side API must
// be picked up by the timer, run its stored collect on its own (no operator
// trigger), record the outcome, and — because this pair is wired over the HTTP
// diode — deliver the resulting bundle across to the high side, which imports
// and serves it. It reuses the rubygems compact-index collector, which is
// pure-HTTP (no client toolchain needed on the collect side).
func TestWatchScheduler(t *testing.T) {
	p := startTestPair(t, pairConfig{name: "watch", httpDiode: true, watchInterval: "1s"})

	// Create an enabled watch. A fresh watch is due immediately, so the 1s
	// scheduler tick runs it within a second or two — no manual /run.
	id := createWatch(t, p.LowURL, "rubygems", "e2e-rake",
		`{"gems":["rake@`+rakeNewVersion+`"]}`, 3600)

	// Wait for the scheduler to run the watch and record an outcome. A busy or
	// throttled rubygems.org is upstream weather, not a scheduler regression, so
	// a transient failure skips rather than fails.
	w := waitWatchRan(t, p.LowURL, id)
	if w.LastStatus != "ok" {
		if isTransientUpstreamError(w.LastMessage) {
			t.Skipf("watch collect hit transient upstream trouble: %s", w.LastMessage)
		}
		t.Fatalf("scheduled watch did not succeed: status=%q message=%q", w.LastStatus, w.LastMessage)
	}

	// The scheduler advanced the next run one interval past the run it just did.
	if !w.NextRunAt.After(*w.LastRunAt) {
		t.Fatalf("watch next_run_at %v not scheduled after last_run_at %v", w.NextRunAt, w.LastRunAt)
	}

	// The bundle the scheduled collect produced crossed the diode and imports,
	// and the high side serves the regenerated index for it.
	waitHighStream(t, p.HighURL, "rubygems", "scheduled bundle imported", func(s streamStatus) bool {
		return s.LastImportedSequence >= 1
	})
	code, body := httpGet(t, p.HighURL+"/rubygems/info/rake")
	if code != 200 || !strings.Contains(string(body), rakeNewVersion+" ") {
		t.Fatalf("high side does not serve the scheduled rake collect: HTTP %d\n%s", code, body)
	}
}

// watchJSON mirrors the subset of cmd/artigate's Watch the scheduler test
// inspects.
type watchJSON struct {
	ID          int64      `json:"id"`
	LastStatus  string     `json:"last_status"`
	LastMessage string     `json:"last_message"`
	LastRunAt   *time.Time `json:"last_run_at"`
	NextRunAt   time.Time  `json:"next_run_at"`
}

// createWatch POSTs a new watch and returns its assigned id.
func createWatch(t *testing.T, lowURL, stream, label, spec string, intervalSeconds int64) int64 {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"stream":           stream,
		"label":            label,
		"spec":             json.RawMessage(spec),
		"interval_seconds": intervalSeconds,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(lowURL+"/admin/watches", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create watch: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create watch: HTTP %d: %s", resp.StatusCode, body)
	}
	var w watchJSON
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatalf("parse created watch: %v\n%s", err, body)
	}
	if w.ID == 0 {
		t.Fatalf("created watch has no id: %s", body)
	}
	return w.ID
}

// waitWatchRan polls the watch list until the named watch has recorded a run
// (last_run_at set), returning its state.
func waitWatchRan(t *testing.T, lowURL string, id int64) watchJSON {
	t.Helper()
	deadline := time.Now().Add(importTimeout)
	for time.Now().Before(deadline) {
		for _, w := range listWatches(t, lowURL) {
			if w.ID == id && w.LastRunAt != nil {
				return w
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("watch %d never recorded a run within %s", id, importTimeout)
	return watchJSON{}
}

func listWatches(t *testing.T, lowURL string) []watchJSON {
	t.Helper()
	code, body := httpGet(t, lowURL+"/admin/watches")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/watches = %d: %s", code, body)
	}
	var out struct {
		Watches []watchJSON `json:"watches"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("parse /admin/watches: %v\n%s", err, body)
	}
	return out.Watches
}
