package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decodeNDJSON reads the recorder body as newline-delimited JSON events.
func decodeNDJSON(t *testing.T, body string) []map[string]any {
	t.Helper()
	var events []map[string]any
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("event %q is not JSON: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}

func TestStreamCollectForwardsProgressThenDone(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/containers/collect?stream=1", nil)
	w := httptest.NewRecorder()

	(&LowServer{}).streamCollect(w, r, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "→ %s", "alpine:3.20")
		emitProgress(ctx, "    ↓ blob %s (%s)", "ab12cd34ef56", "3.1 MiB")
		return ExportResult{Stream: "containers", Sequence: 7, ExportedModules: 1, BundleID: "containers-000007"}, nil
	})

	if ct := w.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson", ct)
	}
	events := decodeNDJSON(t, w.Body.String())
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %v", len(events), events)
	}
	if events[0]["type"] != "log" || events[0]["message"] != "→ alpine:3.20" {
		t.Errorf("first event = %v, want log '→ alpine:3.20'", events[0])
	}
	if events[1]["type"] != "log" || !strings.Contains(events[1]["message"].(string), "3.1 MiB") {
		t.Errorf("second event = %v, want blob log", events[1])
	}
	last := events[2]
	if last["type"] != "done" {
		t.Fatalf("final event type = %v, want done", last["type"])
	}
	result, ok := last["result"].(map[string]any)
	if !ok {
		t.Fatalf("done event has no result object: %v", last)
	}
	if result["bundle_id"] != "containers-000007" {
		t.Errorf("result bundle_id = %v, want containers-000007", result["bundle_id"])
	}
}

// The collect goroutine reads r.Body after streamCollect has already written
// the streaming response headers. streamCollect buffers the body up front so
// that read succeeds instead of failing with "invalid Read on closed Body".
func TestStreamCollectRunCanReadBodyAfterHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/containers/collect?stream=1",
		strings.NewReader(`{"images":["alpine:3.20"]}`))
	w := httptest.NewRecorder()

	(&LowServer{}).streamCollect(w, r, func(ctx context.Context) (ExportResult, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return ExportResult{}, err
		}
		emitProgress(ctx, "read %d body bytes", len(b))
		return ExportResult{BundleID: "ok"}, nil
	})

	events := decodeNDJSON(t, w.Body.String())
	last := events[len(events)-1]
	if last["type"] != "done" {
		t.Fatalf("final event = %v, want done (body read must not fail)", last)
	}
	if events[0]["message"] != "read 26 body bytes" {
		t.Errorf("body read log = %v, want 'read 26 body bytes'", events[0]["message"])
	}
}

func TestStreamCollectReportsError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/go/collect?stream=1", nil)
	w := httptest.NewRecorder()

	(&LowServer{}).streamCollect(w, r, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "Resolving the Go module graph…")
		return ExportResult{}, errors.New("no go modules resolved")
	})

	events := decodeNDJSON(t, w.Body.String())
	if len(events) == 0 {
		t.Fatal("no events emitted")
	}
	last := events[len(events)-1]
	if last["type"] != "error" || last["error"] != "no go modules resolved" {
		t.Errorf("final event = %v, want error 'no go modules resolved'", last)
	}
}

// emitProgress must be a no-op (never panic) when no sink is installed, so the
// plain /collect endpoints and scheduled watches run unaffected.
func TestEmitProgressNoSinkIsNoop(_ *testing.T) {
	emitProgress(context.Background(), "should be dropped: %d", 42)
}

func TestWantsStreamingCollect(t *testing.T) {
	yes := httptest.NewRequest(http.MethodPost, "/admin/go/collect?stream=1", nil)
	no := httptest.NewRequest(http.MethodPost, "/admin/go/collect", nil)
	if !wantsStreamingCollect(yes) {
		t.Error("stream=1 should request streaming")
	}
	if wantsStreamingCollect(no) {
		t.Error("no query should not request streaming")
	}
}
