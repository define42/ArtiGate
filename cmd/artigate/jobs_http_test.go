package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestJobsEndpointListsCollects drives a buffered collect through the real
// dispatch and confirms the jobs list reports it: manual kind, derived label,
// ok state, and a success message.
func TestJobsEndpointListsCollects(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	res := doLowReq(t, ls, http.MethodPost, "/admin/go/collect",
		`{"modules":["example.com/foo/bar@v1.0.0"]}`)
	if res.Code != http.StatusOK {
		t.Fatalf("buffered collect status %d: %s", res.Code, res.Body.String())
	}
	var result ExportResult
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.BundleID == "" || result.ExportedModules == 0 {
		t.Fatalf("buffered collect result = %+v, want a bundle", result)
	}

	list := doLowReq(t, ls, http.MethodGet, "/admin/jobs", "")
	if list.Code != http.StatusOK {
		t.Fatalf("jobs list status %d", list.Code)
	}
	var jobs JobListResponse
	if err := json.Unmarshal(list.Body.Bytes(), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Jobs) != 1 {
		t.Fatalf("jobs list = %+v, want 1 entry", jobs.Jobs)
	}
	job := jobs.Jobs[0]
	if job.State != string(jobOK) || job.Kind != string(jobKindManual) {
		t.Errorf("job = %+v, want finished manual job", job)
	}
	if job.Label != "go: example.com/foo/bar@v1.0.0" {
		t.Errorf("job label = %q", job.Label)
	}
	if job.Message == "" || job.BundleID != result.BundleID {
		t.Errorf("job summary = %+v, want message and bundle id %s", job, result.BundleID)
	}
}

func TestJobsFollowEndpointErrors(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	if res := doLowReq(t, ls, http.MethodGet, "/admin/jobs/follow?id=abc", ""); res.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d, want 400", res.Code)
	}
	if res := doLowReq(t, ls, http.MethodGet, "/admin/jobs/follow", ""); res.Code != http.StatusBadRequest {
		t.Errorf("missing id status = %d, want 400", res.Code)
	}
	if res := doLowReq(t, ls, http.MethodGet, "/admin/jobs/follow?id=999", ""); res.Code != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", res.Code)
	}
}

// A finished job's follow replays its identity event, log, and terminal event.
func TestJobsFollowFinishedJobReplays(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	if res := doLowReq(t, ls, http.MethodPost, "/admin/go/collect",
		`{"modules":["example.com/foo/bar@v1.0.0"]}`); res.Code != http.StatusOK {
		t.Fatalf("collect failed: %s", res.Body.String())
	}
	job := ls.jobs.list()[0]

	res := doLowReq(t, ls, http.MethodGet, "/admin/jobs/follow?id="+strconv.FormatInt(job.ID, 10), "")
	if res.Code != http.StatusOK {
		t.Fatalf("follow status %d", res.Code)
	}
	events := decodeNDJSON(t, res.Body.String())
	if len(events) < 2 {
		t.Fatalf("follow replayed %d events, want identity + terminal at least", len(events))
	}
	first := events[0]
	if first["type"] != "job" || first["state"] != string(jobOK) || first["label"] != job.Label {
		t.Errorf("identity event = %v", first)
	}
	if last := events[len(events)-1]; last["type"] != "done" {
		t.Errorf("terminal event = %v, want done", last)
	}
}

func TestJobsCancelEndpoint(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	if res := doLowReq(t, ls, http.MethodPost, "/admin/jobs/cancel", "{bad"); res.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d, want 400", res.Code)
	}
	if res := doLowReq(t, ls, http.MethodPost, "/admin/jobs/cancel", `{"id":999}`); res.Code != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", res.Code)
	}

	// A queued job cancels cleanly over HTTP.
	release := make(chan struct{})
	defer close(release)
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	queued := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), queued); err != nil {
		t.Fatal(err)
	}
	idBody := `{"id":` + strconv.FormatInt(queued.ID, 10) + `}`
	if res := doLowReq(t, ls, http.MethodPost, "/admin/jobs/cancel", idBody); res.Code != http.StatusOK {
		t.Fatalf("cancel queued status = %d: %s", res.Code, res.Body.String())
	}
	waitJobDone(t, queued)

	// Canceling it again reports the conflict.
	if res := doLowReq(t, ls, http.MethodPost, "/admin/jobs/cancel", idBody); res.Code != http.StatusConflict {
		t.Errorf("cancel finished status = %d, want 409", res.Code)
	}
}

// A full per-stream queue refuses further collects with 429 while other
// streams keep accepting.
func TestCollectRefusedWhenQueueFull(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	release := make(chan struct{})
	defer close(release)
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	waitJobState(t, blocker, jobRunning)
	for i := 0; i < jobQueueCap; i++ {
		j := testJob(streamGo, func(context.Context) (ExportResult, error) {
			return ExportResult{}, nil
		})
		if _, err := ls.jobs.enqueue(context.Background(), j); err != nil {
			t.Fatal(err)
		}
	}
	res := doLowReq(t, ls, http.MethodPost, "/admin/go/collect", `{"modules":["example.com/foo/bar@v1.0.0"]}`)
	if res.Code != http.StatusTooManyRequests {
		t.Errorf("collect on full queue status = %d, want 429", res.Code)
	}
}

// The dashboard's streaming collect shows its place in line: a second collect
// on a busy stream streams the identity event and a "Queued behind" line
// immediately, then proceeds once the stream frees up.
func TestStreamingCollectReportsQueuedPosition(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	release := make(chan struct{})
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(srv.URL+"/admin/go/collect?stream=1", "application/json", //nolint:noctx // test request
		strings.NewReader(`{"modules":["example.com/foo/bar@v1.0.0"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q", ct)
	}

	sc := bufio.NewScanner(resp.Body)
	readEvent := func() map[string]any {
		t.Helper()
		if !sc.Scan() {
			t.Fatalf("stream ended early: %v", sc.Err())
		}
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("bad event %q: %v", sc.Text(), err)
		}
		return ev
	}

	first := readEvent()
	if first["type"] != "job" || first["state"] != string(jobQueued) {
		t.Fatalf("first event = %v, want queued job identity", first)
	}
	queuedLine := readEvent()
	if queuedLine["type"] != "log" || !strings.Contains(queuedLine["message"].(string), "Queued behind 1 job(s) on stream go") {
		t.Fatalf("second event = %v, want the queued-behind line", queuedLine)
	}

	close(release) // free the stream; the queued collect now runs
	sawDone := false
	for !sawDone {
		ev := readEvent()
		if ev["type"] == "error" {
			t.Fatalf("collect failed: %v", ev)
		}
		sawDone = ev["type"] == "done"
	}
}

// Buffered waiters survive a client disconnect: the job keeps running and
// records its outcome even though nobody is left to read the response.
func TestBufferedCollectClientDisconnect(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	started := make(chan struct{})
	release := make(chan struct{})
	j := testJob(streamGo, func(context.Context) (ExportResult, error) {
		close(started)
		<-release
		return ExportResult{BundleID: "go-bundle-000009"}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}

	reqCtx, cancelReq := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/admin/jobs/follow?id=1", nil).WithContext(reqCtx)
	w := httptest.NewRecorder()
	waited := make(chan struct{})
	go func() {
		defer close(waited)
		waitCollectJob(w, r, j)
	}()
	<-started
	cancelReq() // the client goes away mid-collect
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("waitCollectJob did not return on client disconnect")
	}
	close(release) // the job still finishes on its own
	waitJobDone(t, j)
	if got := j.snapshotInfo(0); got.State != string(jobOK) || got.BundleID != "go-bundle-000009" {
		t.Errorf("job after abandoned wait = %+v, want ok", got)
	}
}

// The authenticated username travels from the session middleware into the job.
func TestRequestUserReachesJob(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	r := httptest.NewRequest(http.MethodPost, "/admin/go/collect", strings.NewReader(`{}`))
	r = r.WithContext(withRequestUser(r.Context(), "alice"))
	j, ok := ls.enqueueCollect(httptest.NewRecorder(), r, streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	if !ok {
		t.Fatal("enqueue refused")
	}
	waitJobDone(t, j)
	if got := j.snapshotInfo(0).RequestedBy; got != "alice" {
		t.Errorf("requested_by = %q, want alice", got)
	}
	if requestUser(context.Background()) != "" {
		t.Error("requestUser without a session should be empty")
	}
}
