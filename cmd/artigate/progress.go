package main

// Live collect progress. The dashboard's "Collect & export" modal streams what
// a collect is doing as it runs, rather than blocking on a single request until
// the bundle is finished. Collectors report human-readable lines with
// emitProgress; streamCollect forwards them to the browser as newline-delimited
// JSON. The plumbing is a no-op unless a streaming client installed a sink, so
// the plain /admin/*/collect endpoints and the scheduled watches are unaffected.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxStreamCollectBody caps the buffered request body for a streaming collect.
// It sits above every collect handler's own body limit, so a valid request is
// never truncated; it only guards against an unbounded upload before the
// handler's own limit would apply.
const maxStreamCollectBody = 16 << 20

// progressSink receives one progress line at a time. Sends must never block the
// collect for long: streamCollect's sink drops a line only if the client has
// gone away (its context is done).
type progressSink func(line string)

// progressKey identifies the sink stored in a context. The unexported empty
// struct type makes it a collision-free key without needing a package global.
type progressKey struct{}

// withProgress returns a context carrying sink, so deeply nested collector code
// can call emitProgress without threading a parameter through every signature.
func withProgress(ctx context.Context, sink progressSink) context.Context {
	return context.WithValue(ctx, progressKey{}, sink)
}

// emitProgress reports one progress line to the sink in ctx, if one is
// installed. With no sink it is a cheap no-op, so it is safe to sprinkle through
// the collectors regardless of how a collect was triggered.
func emitProgress(ctx context.Context, format string, args ...any) {
	sink, _ := ctx.Value(progressKey{}).(progressSink)
	if sink == nil {
		return
	}
	if len(args) == 0 {
		sink(format)
	} else {
		sink(fmt.Sprintf(format, args...))
	}
}

// wantsStreamingCollect reports whether the client asked for a live NDJSON
// progress stream (the dashboard's collect modal appends ?stream=1) instead of
// a single buffered JSON result.
func wantsStreamingCollect(r *http.Request) bool {
	return r.URL.Query().Get("stream") == "1"
}

// streamCollect runs a collect while streaming its progress to the client as
// newline-delimited JSON (application/x-ndjson): one {"type":"log","message":…}
// object per progress line, then a terminal {"type":"done","result":…} or
// {"type":"error","error":…}. The collect runs in its own goroutine so this
// goroutine is free to forward and flush progress as it arrives; only this
// goroutine ever writes to w.
func (s *LowServer) streamCollect(w http.ResponseWriter, r *http.Request, run func(context.Context) (ExportResult, error)) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// net/http's ResponseWriter is a Flusher; this only guards exotic
		// wrappers. Fall back to a buffered result so the client still answers.
		res, err := run(r.Context())
		respondJSONOrError(w, http.StatusBadRequest, res, err)
		return
	}
	// Buffer the request body before writing any response: once the streaming
	// headers go out, the server closes the request body, so the collect
	// goroutine — which reads r.Body — must read an in-memory copy instead, or
	// it fails with "invalid Read on closed Body".
	body, err := io.ReadAll(io.LimitReader(r.Body, maxStreamCollectBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	enc := json.NewEncoder(w)
	writeEvent := func(ev map[string]any) {
		_ = enc.Encode(ev) // Encoder appends the newline that frames each event.
		flusher.Flush()
	}

	lines := make(chan string, 64)
	ctx := withProgress(r.Context(), func(line string) {
		select {
		case lines <- line:
		case <-r.Context().Done():
		}
	})

	done := make(chan collectOutcome, 1)
	go func() { res, err := run(ctx); done <- collectOutcome{res, err} }()

	for {
		select {
		case line := <-lines:
			writeEvent(logEvent(line))
		case o := <-done:
			drainProgress(lines, writeEvent)
			writeEvent(o.event())
			return
		case <-r.Context().Done():
			return
		}
	}
}

// collectOutcome is a finished collect's result or error, rendered into the
// stream's terminal event.
type collectOutcome struct {
	res ExportResult
	err error
}

func (o collectOutcome) event() map[string]any {
	if o.err != nil {
		return map[string]any{"type": "error", "error": o.err.Error()}
	}
	return map[string]any{"type": "done", "result": o.res}
}

func logEvent(line string) map[string]any {
	return map[string]any{"type": "log", "message": line}
}

// drainProgress flushes any progress buffered in the moment before the collect
// returned, so nothing is lost before the terminal event.
func drainProgress(lines <-chan string, writeEvent func(map[string]any)) {
	for {
		select {
		case line := <-lines:
			writeEvent(logEvent(line))
		default:
			return
		}
	}
}
