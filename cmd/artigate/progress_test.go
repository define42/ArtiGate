package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

	m := newJobManager()
	j := testJob(streamContainers, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "→ %s", "alpine:3.20")
		emitProgress(ctx, "    ↓ blob %s (%s)", "ab12cd34ef56", "3.1 MiB")
		return ExportResult{Stream: "containers", Sequence: 7, ExportedModules: 1, BundleID: "containers-000007"}, nil
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	waitJobDone(t, j)
	followJobNDJSON(w, r, j, false) // replay of a finished job: log…, terminal

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

// The job worker reads r.Body after the response headers have long been
// written (and possibly after the handler goroutine moved on). enqueueCollect
// buffers the body up front so that read succeeds instead of failing with
// "invalid Read on closed Body".
func TestStreamCollectRunCanReadBodyAfterHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/containers/collect?stream=1",
		strings.NewReader(`{"images":["alpine:3.20"]}`))
	w := httptest.NewRecorder()

	ls := &LowServer{jobs: newJobManager()}
	j, ok := ls.enqueueCollect(w, r, streamContainers, func(ctx context.Context) (ExportResult, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return ExportResult{}, err
		}
		emitProgress(ctx, "read %d body bytes", len(b))
		return ExportResult{BundleID: "ok"}, nil
	})
	if !ok {
		t.Fatalf("enqueueCollect refused: %s", w.Body.String())
	}
	followJobNDJSON(w, r, j, false)

	events := decodeNDJSON(t, w.Body.String())
	last := events[len(events)-1]
	if last["type"] != "done" {
		t.Fatalf("final event = %v, want done (body read must not fail)", last)
	}
	if events[0]["message"] != "read 26 body bytes" {
		t.Errorf("body read log = %v, want 'read 26 body bytes'", events[0]["message"])
	}
	if j.Label != "containers: alpine:3.20" {
		t.Errorf("job label = %q, want derived from the image list", j.Label)
	}
}

func TestStreamCollectReportsError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/go/collect?stream=1", nil)
	w := httptest.NewRecorder()

	m := newJobManager()
	j := testJob(streamGo, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "Resolving the Go module graph…")
		return ExportResult{}, errors.New("no go modules resolved")
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	followJobNDJSON(w, r, j, false)

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

// dlSample is one captured download-progress emission.
type dlSample struct {
	name        string
	done, total int64
	bps         int64
}

// TestProgressReaderReportsLargeDownloads checks the per-file progress
// plumbing: a download outlasting the report interval emits samples with
// cumulative bytes and a rate, and lands on a final done==total sample.
func TestProgressReaderReportsLargeDownloads(t *testing.T) {
	var samples []dlSample
	ctx := withDownloadProgress(context.Background(), func(name string, done, total, bps int64) {
		samples = append(samples, dlSample{name, done, total, bps})
	})
	content := strings.Repeat("x", 1<<20)
	pr := newProgressReader(ctx, strings.NewReader(content), "model.gguf", int64(len(content)))

	// First read arms the interval; a read after the interval reports.
	buf := make([]byte, 512<<10)
	if _, err := pr.Read(buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(dlProgressInterval + 50*time.Millisecond)
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatal(err)
	}
	if len(samples) == 0 {
		t.Fatal("no progress samples for a download outlasting the interval")
	}
	first := samples[0]
	if first.name != "model.gguf" || first.total != int64(len(content)) || first.done <= 0 || first.bps <= 0 {
		t.Fatalf("first sample = %+v", first)
	}
	last := samples[len(samples)-1]
	if last.done != int64(len(content)) {
		t.Fatalf("final sample done = %d, want %d", last.done, len(content))
	}
}

// TestProgressReaderSilentForSmallDownloads checks that a download finishing
// inside the first interval emits nothing (indexes and configs must not flash
// the bar) and that without a sink the reader is returned untouched.
func TestProgressReaderSilentForSmallDownloads(t *testing.T) {
	var samples []dlSample
	ctx := withDownloadProgress(context.Background(), func(name string, done, total, bps int64) {
		samples = append(samples, dlSample{name, done, total, bps})
	})
	pr := newProgressReader(ctx, strings.NewReader("tiny"), "Packages.gz", 4)
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatal(err)
	}
	if len(samples) != 0 {
		t.Fatalf("small download emitted %d samples, want 0", len(samples))
	}

	plain := strings.NewReader("no sink")
	if got := newProgressReader(context.Background(), plain, "x", 7); got != io.Reader(plain) {
		t.Error("without a sink the reader must be returned untouched")
	}
}

// dlTriggerWriter is a recorder that releases the collect once the follower
// has streamed the dl event, so the live-sample assertion below is
// deterministic without concurrent recorder access.
type dlTriggerWriter struct {
	*httptest.ResponseRecorder

	once sync.Once
	hold chan struct{}
}

func (w *dlTriggerWriter) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte(`"type":"dl"`)) {
		w.once.Do(func() { close(w.hold) })
	}
	return w.ResponseRecorder.Write(b)
}

// TestStreamCollectForwardsDownloadEvents checks the wire format: download
// samples reach a live follower as {"type":"dl",...} events among the log
// lines. The run holds the job open until the follower has seen the sample,
// because dl samples are ephemeral — a finished job replays only its log.
func TestStreamCollectForwardsDownloadEvents(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/hf/collect?stream=1", nil)
	w := &dlTriggerWriter{ResponseRecorder: httptest.NewRecorder(), hold: make(chan struct{})}

	m := newJobManager()
	emitted := make(chan struct{})
	j := testJob(streamHF, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "→ hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0")
		emitDownloadProgress(ctx, "blob ab12cd34ef56", 5<<20, 100<<20, 42<<20)
		close(emitted)
		<-w.hold // hold the job open until the follower streamed the sample
		return ExportResult{BundleID: "hf-bundle-000001"}, nil
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	<-emitted
	followJobNDJSON(w, r, j, false) // returns once the job's terminal event is written

	events := decodeNDJSON(t, w.Body.String())
	var dl map[string]any
	for _, ev := range events {
		if ev["type"] == "dl" {
			dl = ev
		}
	}
	if dl == nil {
		t.Fatalf("no dl event in %v", events)
	}
	if dl["name"] != "blob ab12cd34ef56" || dl["done"].(float64) != float64(5<<20) ||
		dl["total"].(float64) != float64(100<<20) || dl["bps"].(float64) != float64(42<<20) {
		t.Errorf("dl event = %v", dl)
	}
	if events[len(events)-1]["type"] != "done" {
		t.Errorf("final event = %v, want done", events[len(events)-1])
	}
}

func TestDlNameFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://mirror.example.com/pool/main/c/code/code_1.101.2_amd64.deb": "code_1.101.2_amd64.deb",
		"https://example.com/repodata/primary.xml.gz?auth=t":                 "primary.xml.gz",
	} {
		if got := dlNameFromURL(in); got != want {
			t.Errorf("dlNameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}
