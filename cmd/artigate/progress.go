package main

// Live collect progress. Collectors report human-readable lines with
// emitProgress and byte-level download samples with emitDownloadProgress;
// both write to sinks carried on the context. The job queue installs sinks
// pointed at the running job's log ring, from which any number of dashboard
// sessions can follow along as newline-delimited JSON (see jobs_http.go). The
// plumbing is a cheap no-op when no sink is installed, so collectors emit
// unconditionally.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

// maxStreamCollectBody caps the request body buffered when a collect is
// enqueued as a job (see bufferCollectBody). It sits above every JSON collect
// handler's own body limit, so a valid request is never truncated (multipart
// uploads are not buffered at all); an oversized body is refused with a clear
// error.
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
