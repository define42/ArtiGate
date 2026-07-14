package main

// HTTP surface of the job queue. GET /admin/jobs lists every queued, running,
// and recently finished job; GET /admin/jobs/follow?id=N streams one job's
// progress as the same NDJSON the collect modal already speaks; POST
// /admin/jobs/cancel stops a job. The collect endpoints themselves enqueue
// here too: a plain POST waits for its job and answers with the buffered JSON
// result exactly as before, while ?stream=1 follows the job live.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// JobListResponse is the body of GET /admin/jobs.
type JobListResponse struct {
	Jobs []JobInfo `json:"jobs"`
}

// serveLowJobs handles the /admin/jobs* endpoints. It reports whether it
// handled the request.
func (s *LowServer) serveLowJobs(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/admin/jobs":
		if !isReadMethod(r) {
			return false
		}
		writeJSON(w, JobListResponse{Jobs: s.jobs.list()})
	case "/admin/jobs/follow":
		if !isReadMethod(r) {
			return false
		}
		s.handleJobFollow(w, r)
	case "/admin/jobs/cancel":
		if r.Method != http.MethodPost {
			return false
		}
		s.handleJobCancel(w, r)
	default:
		return false
	}
	return true
}

func (s *LowServer) handleJobFollow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "missing or invalid job id", http.StatusBadRequest)
		return
	}
	j := s.jobs.get(id)
	if j == nil {
		http.Error(w, errJobNotFound.Error(), http.StatusNotFound)
		return
	}
	followJobNDJSON(w, r, j, true)
}

func (s *LowServer) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	id, err := watchIDFromBody(r) // {"id":N}, same shape the watch actions use
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch err := s.jobs.cancel(id); {
	case errors.Is(err, errJobNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errJobFinished):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]string{"status": "ok"})
	}
}

// followJobNDJSON streams one job's progress as newline-delimited JSON: an
// optional leading {"type":"job",…} identity event, the buffered log replayed
// from the start, then live events until the terminal {"type":"done"} or
// {"type":"error"}. Any number of followers can watch the same job; a
// follower's pace never slows the collect (it reads the job's ring at its own
// cursor). Following an already-finished job replays its log and terminal
// event immediately.
func followJobNDJSON(w http.ResponseWriter, r *http.Request, j *Job, withJobEvent bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// net/http's ResponseWriter is a Flusher; this only guards exotic
		// wrappers. Fall back to a buffered result so the client still answers.
		waitCollectJob(w, r, j)
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
	if withJobEvent {
		writeEvent(jobEvent(j))
	}
	cursor := 0
	var sentDL *dlSnapshot
	for {
		batch := j.logSince(cursor)
		cursor = batch.cursor
		for _, line := range batch.lines {
			writeEvent(logEvent(line))
		}
		if batch.dl != nil && batch.dl != sentDL {
			sentDL = batch.dl
			writeEvent(dlEvent(batch.dl.Name, batch.dl.Done, batch.dl.Total, batch.dl.BPS))
		}
		if batch.state.terminal() {
			writeEvent(jobTerminalEvent(batch))
			return
		}
		select {
		case <-batch.updated:
		case <-r.Context().Done():
			return // the follower left; the job carries on
		}
	}
}

// jobEvent identifies the job a stream reports on, so the dashboard can wire
// its Stop button to /admin/jobs/cancel and title the modal.
func jobEvent(j *Job) map[string]any {
	info := j.snapshotInfo(0)
	return map[string]any{
		"type":   "job",
		"id":     info.ID,
		"stream": info.Stream,
		"label":  info.Label,
		"state":  info.State,
	}
}

// jobTerminalEvent renders a finished job's terminal stream event, matching
// collectOutcome's vocabulary: done with the result, or error with the reason
// (a canceled job reports "collect canceled").
func jobTerminalEvent(batch jobLogBatch) map[string]any {
	if batch.state == jobOK {
		return collectOutcome{res: batch.result}.event()
	}
	return map[string]any{"type": "error", "error": batch.errMsg}
}

// enqueueCollect turns one collect request into a queued job. JSON bodies are
// buffered up front so the job is fully detached from the request (the
// browser may close; the job keeps running). Multipart bodies (uploads) are
// not buffered — they can be tens of gigabytes and stream straight from the
// client — so an upload job's context is the request's and dies with it; a
// queued upload whose client vanishes is canceled rather than left holding
// its queue slot. On any error the response has been written and (nil, false)
// is returned.
func (s *LowServer) enqueueCollect(w http.ResponseWriter, r *http.Request, stream string,
	run func(context.Context) (ExportResult, error),
) (*Job, bool) {
	j := &Job{Stream: stream, Kind: jobKindManual, RequestedBy: requestUser(r.Context()), run: run}
	parent := context.Background()
	multipart := strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/")
	if multipart {
		parent = r.Context()
		j.Label = stream + ": file upload"
		if wantsStreamingCollect(r) {
			// Progress must stream back while the request body is still being
			// read; HTTP/1.x is half-duplex by default. Best effort: a
			// transport that cannot interleave answers buffered instead.
			_ = http.NewResponseController(w).EnableFullDuplex()
		}
	} else {
		body, err := bufferCollectBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return nil, false
		}
		j.Label = manualCollectLabel(stream, body)
	}
	if wantsDryRunCollect(r) {
		j.Label += " (dry run)"
	}
	if _, err := s.jobs.enqueue(parent, j); err != nil {
		http.Error(w, err.Error(), jobEnqueueStatus(err))
		return nil, false
	}
	if multipart {
		// The request context ends when the client disconnects (or the upload
		// completes); cancel is a no-op on a finished job.
		context.AfterFunc(r.Context(), func() { _ = s.jobs.cancel(j.ID) })
	}
	return j, true
}

// jobEnqueueStatus maps an enqueue refusal to its HTTP status.
func jobEnqueueStatus(err error) int {
	switch {
	case errors.Is(err, errJobQueueFull):
		return http.StatusTooManyRequests
	case errors.Is(err, errJobsClosed):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// waitCollectJob blocks until the job finishes and writes the same buffered
// JSON result (or plain-text error) the synchronous collect endpoints always
// produced. A client that disconnects while waiting abandons only the
// response — the job keeps running.
func waitCollectJob(w http.ResponseWriter, r *http.Request, j *Job) {
	select {
	case <-j.done:
		res, errMsg := j.outcome()
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}
		writeJSON(w, res)
	case <-r.Context().Done():
	}
}

// bufferCollectBody reads the whole request body into memory and rearms
// r.Body with it, so the collect can parse it later from the job worker, long
// after this handler returned. An oversized body is refused with a clear
// error rather than silently truncated.
func bufferCollectBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxStreamCollectBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxStreamCollectBody {
		return nil, fmt.Errorf("request body exceeds %s; split the collect into smaller requests", formatBytes(maxStreamCollectBody))
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
