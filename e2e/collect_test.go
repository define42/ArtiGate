//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// ExportResult mirrors the low side's collect response (cmd/artigate is
// package main, so the shape is duplicated here; see ExportResult in
// cmd/artigate/main.go).
type ExportResult struct {
	Stream          string         `json:"stream"`
	Sequence        int64          `json:"sequence"`
	ExportedModules int            `json:"exported_modules"`
	BundleID        string         `json:"bundle_id"`
	Skipped         bool           `json:"skipped"`
	PriorFiles      int            `json:"prior_files"`
	Message         string         `json:"message"`
	SkippedModules  []FailedModule `json:"skipped_modules"`
	DiodeError      string         `json:"diode_error"`
}

// FailedModule mirrors cmd/artigate's per-item collect failure record.
type FailedModule struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Error   string `json:"error"`
}

// importStatus mirrors the high side's GET /admin/status payload.
type importStatus struct {
	Streams []struct {
		Stream               string `json:"stream"`
		LastImportedSequence int64  `json:"last_imported_sequence"`
		NextExpectedSequence int64  `json:"next_expected_sequence"`
	} `json:"streams"`
}

// collectEvent is one NDJSON progress line from /admin/<eco>/collect?stream=1.
type collectEvent struct {
	Type    string          `json:"type"`
	Message string          `json:"message"`
	Error   string          `json:"error"`
	Result  json.RawMessage `json:"result"`
	Name    string          `json:"name"`
	Done    int64           `json:"done"`
	Total   int64           `json:"total"`
}

const (
	collectTimeout   = 10 * time.Minute
	importTimeout    = 3 * time.Minute
	transientBackoff = 30 * time.Second
)

// Collect runs one collect on the low side and returns the terminal
// ExportResult. Progress is streamed into the test log. A failure that
// looks like upstream weather (throttling, 5xx, timeouts) is retried once
// and then skips the test — a real regression must not hide behind a busy
// mirror, but a busy mirror must not page anyone either. Everything else
// fails the test immediately.
func (s *Stack) Collect(t *testing.T, eco string, body any) ExportResult {
	t.Helper()
	res, err := s.collectOnce(t, eco, body)
	if err != nil && isTransientUpstreamError(err.Error()) {
		t.Logf("collect %s: transient upstream error, retrying in %s: %v", eco, transientBackoff, err)
		time.Sleep(transientBackoff)
		res, err = s.collectOnce(t, eco, body)
		if err != nil && isTransientUpstreamError(err.Error()) {
			t.Skipf("collect %s: upstream unavailable after retry: %v", eco, err)
		}
	}
	if err != nil {
		t.Fatalf("collect %s: %v", eco, err)
	}
	return s.checkResult(t, eco, res)
}

// checkResult enforces the invariants of a fresh-stack collect: the roots
// start empty, so nothing can dedup-skip; the diode upload must have
// succeeded; and no requested item may have been silently dropped.
func (s *Stack) checkResult(t *testing.T, eco string, res ExportResult) ExportResult {
	t.Helper()
	if res.Skipped {
		t.Fatalf("collect %s: unexpected dedup skip on a fresh stack: %+v", eco, res)
	}
	if res.DiodeError != "" {
		t.Fatalf("collect %s: bundle upload to the high side failed: %s", eco, res.DiodeError)
	}
	if len(res.SkippedModules) > 0 {
		t.Fatalf("collect %s: upstream items were skipped: %+v", eco, res.SkippedModules)
	}
	if res.BundleID == "" || res.Sequence == 0 {
		t.Fatalf("collect %s: no bundle produced: %+v", eco, res)
	}
	t.Logf("collect %s: %s (%d unit(s))", eco, res.BundleID, res.ExportedModules)
	return res
}

func (s *Stack) collectOnce(t *testing.T, eco string, body any) (ExportResult, error) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s collect body: %v", eco, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.LowURL+"/admin/"+eco+"/collect?stream=1", bytes.NewReader(payload))
	if err != nil {
		return ExportResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExportResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return ExportResult{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return readCollectStream(t, eco, resp.Body)
}

func readCollectStream(t *testing.T, eco string, body io.Reader) (ExportResult, error) {
	t.Helper()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lastDL time.Time
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev collectEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return ExportResult{}, fmt.Errorf("bad NDJSON line %q: %v", line, err)
		}
		switch ev.Type {
		case "log":
			t.Logf("[%s] %s", eco, ev.Message)
		case "dl":
			// Download samples arrive twice a second; one line every few
			// seconds is plenty for a test log.
			if time.Since(lastDL) >= 5*time.Second {
				t.Logf("[%s] transferring %s (%s / %s)", eco, ev.Name, formatMiB(ev.Done), formatMiB(ev.Total))
				lastDL = time.Now()
			}
		case "done":
			var res ExportResult
			if err := json.Unmarshal(ev.Result, &res); err != nil {
				return ExportResult{}, fmt.Errorf("bad done result %q: %v", ev.Result, err)
			}
			return res, nil
		case "error":
			return ExportResult{}, errors.New(ev.Error)
		}
	}
	if err := sc.Err(); err != nil {
		return ExportResult{}, fmt.Errorf("reading collect stream: %w", err)
	}
	return ExportResult{}, errors.New("collect stream ended without a done/error event")
}

func formatMiB(n int64) string {
	if n <= 0 {
		return "?"
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
}

// WaitImported blocks until the high side reports the stream imported at
// least through seq. The HTTP diode ingest triggers an immediate import, so
// this normally returns within seconds; the 2s scan interval is the safety
// net. A stream missing from the status just hasn't imported anything yet.
func (s *Stack) WaitImported(t *testing.T, stream string, seq int64) {
	t.Helper()
	deadline := time.Now().Add(importTimeout)
	var lastStatus []byte
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.HighURL + "/admin/status")
		if err == nil {
			b, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				lastStatus = b
				var st importStatus
				if json.Unmarshal(b, &st) == nil {
					for _, entry := range st.Streams {
						if entry.Stream == stream && entry.LastImportedSequence >= seq {
							return
						}
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("bundle %s/%d not imported within %s; last status: %s", stream, seq, importTimeout, lastStatus)
}
