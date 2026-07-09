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
	"net/url"
	"path"
	"strings"
	"time"
)

// maxStreamCollectBody caps the buffered request body for a streaming collect.
// It sits above every JSON collect handler's own body limit, so a valid
// request is never truncated (multipart uploads are not buffered at all — see
// prepareStreamCollectBody); an oversized body is refused with a clear error.
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

// downloadSink receives byte-level progress for one in-flight file download:
// the file's display name, bytes downloaded so far, the expected total (0 when
// unknown), and the current transfer rate in bytes/second.
type downloadSink func(name string, done, total, bps int64)

type downloadKey struct{}

// withDownloadProgress returns a context carrying a download sink, alongside
// the line sink, so long downloads can drive the dashboard's progress bar.
func withDownloadProgress(ctx context.Context, sink downloadSink) context.Context {
	return context.WithValue(ctx, downloadKey{}, sink)
}

// emitDownloadProgress reports one download-progress sample to the sink in
// ctx, if one is installed.
func emitDownloadProgress(ctx context.Context, name string, done, total, bps int64) {
	if sink, _ := ctx.Value(downloadKey{}).(downloadSink); sink != nil {
		sink(name, done, total, bps)
	}
}

// dlNameFromURL renders a download's display name from its URL: the file's
// base name, query dropped.
func dlNameFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return path.Base(u.Path)
	}
	return path.Base(rawURL)
}

// dlProgressInterval is how often an in-flight download reports progress. It
// also acts as the reporting threshold: a download that completes inside the
// first interval never reports at all, so small files (indexes, configs)
// don't flash the dashboard's progress bar.
const dlProgressInterval = 500 * time.Millisecond

// progressTracker accumulates byte progress toward a known total — one
// download body, or all the files packed into one archive — and reports it
// through ctx's download sink at most every dlProgressInterval. Work that
// finishes inside the first interval never reports, so small files and small
// bundles stay silent.
type progressTracker struct {
	ctx         context.Context
	name        string
	total       int64
	done        int64
	window      int64     // bytes since the last report
	windowStart time.Time // zero until the first byte arrives
	reported    bool
}

// newProgressTracker returns nil when ctx carries no download sink (plain
// admin collects, scheduled watches); the nil tracker's methods are no-ops,
// so callers need no guards and the tracking is free.
func newProgressTracker(ctx context.Context, name string, total int64) *progressTracker {
	if sink, _ := ctx.Value(downloadKey{}).(downloadSink); sink == nil {
		return nil
	}
	if total < 0 {
		total = 0 // an unknown total renders as bytes+speed, no bar
	}
	return &progressTracker{ctx: ctx, name: name, total: total}
}

// add records n more bytes of progress, reporting when the interval is due.
func (p *progressTracker) add(n int64) {
	if p == nil || n <= 0 {
		return
	}
	p.done += n
	p.window += n
	now := time.Now()
	if p.windowStart.IsZero() {
		p.windowStart = now // arm the interval; no report yet
		return
	}
	if elapsed := now.Sub(p.windowStart); elapsed >= dlProgressInterval {
		bps := int64(float64(p.window) / elapsed.Seconds())
		emitDownloadProgress(p.ctx, p.name, p.done, p.total, bps)
		p.reported = true
		p.windowStart, p.window = now, 0
	}
}

// finish lands the bar on its final position — but only if it ever appeared.
func (p *progressTracker) finish() {
	if p == nil || !p.reported {
		return
	}
	emitDownloadProgress(p.ctx, p.name, p.done, p.total, 0)
}

// newProgressReader wraps a download body so the bytes flowing through it are
// reported to ctx's download sink. Without a sink the reader is returned
// untouched, making this free.
func newProgressReader(ctx context.Context, r io.Reader, name string, total int64) io.Reader {
	t := newProgressTracker(ctx, name, total)
	if t == nil {
		return r
	}
	return &progressReader{r: r, t: t}
}

type progressReader struct {
	r io.Reader
	t *progressTracker
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.t.add(int64(n))
	if err != nil {
		p.t.finish() // land on 100% before the completion log line
	}
	return n, err
}

// wantsStreamingCollect reports whether the client asked for a live NDJSON
// progress stream (the dashboard's collect modal appends ?stream=1) instead of
// a single buffered JSON result.
func wantsStreamingCollect(r *http.Request) bool {
	return r.URL.Query().Get("stream") == "1"
}

// prepareStreamCollectBody arranges for the collect goroutine to read the
// request body while progress events are already streaming back. HTTP/1.x is
// half-duplex by default — the server shuts the request body down once the
// response starts — so a multipart upload (arbitrarily large, cannot be
// buffered) switches the connection to full duplex instead. Everything else
// (the JSON collects, all small) is buffered in memory, erroring clearly when
// a body exceeds the cap rather than silently truncating it and leaving the
// client with an opaque network error.
func prepareStreamCollectBody(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := http.NewResponseController(w).EnableFullDuplex(); err == nil {
			return nil
		}
		// A transport that cannot interleave reads and writes falls through to
		// buffering — and, for a big upload, to the clear size error below.
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxStreamCollectBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxStreamCollectBody {
		return fmt.Errorf("request body exceeds %s; POST without ?stream=1 to send more", formatBytes(maxStreamCollectBody))
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil
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
	if err := prepareStreamCollectBody(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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

	events := make(chan map[string]any, 64)
	// Log lines wait for room (none may be lost); download samples are
	// ephemeral and dropped when the channel is full — a fresh one follows.
	ctx := withProgress(r.Context(), func(line string) {
		select {
		case events <- logEvent(line):
		case <-r.Context().Done():
		}
	})
	ctx = withDownloadProgress(ctx, func(name string, done, total, bps int64) {
		select {
		case events <- dlEvent(name, done, total, bps):
		default:
		}
	})

	done := make(chan collectOutcome, 1)
	go func() { res, err := run(ctx); done <- collectOutcome{res, err} }()

	for {
		select {
		case ev := <-events:
			writeEvent(ev)
		case o := <-done:
			drainProgress(events, writeEvent)
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

// dlEvent frames one download-progress sample for the dashboard's per-file
// progress bar.
func dlEvent(name string, done, total, bps int64) map[string]any {
	return map[string]any{"type": "dl", "name": name, "done": done, "total": total, "bps": bps}
}

// drainProgress flushes any progress buffered in the moment before the collect
// returned, so nothing is lost before the terminal event.
func drainProgress(events <-chan map[string]any, writeEvent func(map[string]any)) {
	for {
		select {
		case ev := <-events:
			writeEvent(ev)
		default:
			return
		}
	}
}
