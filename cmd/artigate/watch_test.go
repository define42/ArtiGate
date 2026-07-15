package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestWatchStore(t *testing.T) *WatchStore {
	t.Helper()
	store, err := OpenWatchStore(filepath.Join(t.TempDir(), "watches.db"))
	if err != nil {
		t.Fatalf("OpenWatchStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func assertDueCount(t *testing.T, store *WatchStore, at time.Time, want int) {
	t.Helper()
	due, err := store.Due(at)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != want {
		t.Fatalf("Due count = %d, want %d", len(due), want)
	}
}

func TestWatchStoreCRUD(t *testing.T) {
	store := newTestWatchStore(t)

	w, err := store.Create(Watch{
		Stream: streamPython, Label: "py: requests",
		Spec: `{"requirements":["requests"]}`, IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w.ID == 0 {
		t.Fatal("Create did not assign an ID")
	}

	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Label != "py: requests" || list[0].Stream != streamPython {
		t.Fatalf("List = %+v", list)
	}
	got, err := store.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalSeconds != 3600 || !got.Enabled {
		t.Fatalf("Get = %+v", got)
	}

	if err := store.Delete(w.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := store.List(); len(list) != 0 {
		t.Fatalf("expected no watches after delete, got %d", len(list))
	}
}

func TestWatchStoreDueAndEnable(t *testing.T) {
	store := newTestWatchStore(t)

	w, err := store.Create(Watch{
		Stream: streamPython, Label: "py", Spec: `{"requirements":["requests"]}`,
		IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDueCount(t, store, time.Now().UTC().Add(time.Second), 1) // freshly created → due

	// Recording a run pushes the next run one interval into the future, so it
	// is no longer due.
	ranAt := time.Now().UTC().Truncate(time.Second)
	if err := store.RecordRun(w.ID, ranAt, "ok", "bundle python-bundle-000001: 1 unit(s)"); err != nil {
		t.Fatal(err)
	}
	assertDueCount(t, store, time.Now().UTC(), 0)
	got, err := store.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != "ok" || got.LastRunAt == nil {
		t.Fatalf("run not recorded: %+v", got)
	}
	if want := ranAt.Add(time.Hour); !got.NextRunAt.Equal(want) {
		t.Errorf("next_run_at = %s, want %s (ranAt + stored interval)", got.NextRunAt, want)
	}

	// Disabling excludes it even once the time passes; re-enabling makes it due.
	if err := store.SetEnabled(w.ID, false); err != nil {
		t.Fatal(err)
	}
	assertDueCount(t, store, time.Now().UTC().Add(2*time.Hour), 0)
	if err := store.SetEnabled(w.ID, true); err != nil {
		t.Fatal(err)
	}
	assertDueCount(t, store, time.Now().UTC().Add(time.Second), 1)
}

// TestWatchStoreUpdate covers editing a watch in place: label, spec, and
// interval change; the next run is re-spaced from the last run at the new
// interval, while a never-run watch keeps its existing next_run_at.
func TestWatchStoreUpdate(t *testing.T) {
	store := newTestWatchStore(t)

	w, err := store.Create(Watch{
		Stream: streamPython, Label: "py: requests",
		Spec: `{"requirements":["requests"]}`, IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Never run: the edit keeps next_run_at (still due from creation).
	before, _ := store.Get(w.ID)
	w.Label, w.Spec, w.IntervalSeconds = "py: urllib3", `{"requirements":["urllib3"]}`, 7200
	updated, err := store.Update(w)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Label != "py: urllib3" || updated.Spec != `{"requirements":["urllib3"]}` || updated.IntervalSeconds != 7200 {
		t.Fatalf("Update = %+v", updated)
	}
	if !updated.NextRunAt.Equal(before.NextRunAt) {
		t.Errorf("never-run next_run_at changed: %s -> %s", before.NextRunAt, updated.NextRunAt)
	}

	// Has run: the edit re-spaces the next run from that last run.
	ranAt := time.Now().UTC().Truncate(time.Second)
	if err := store.RecordRun(w.ID, ranAt, "ok", "bundle"); err != nil {
		t.Fatal(err)
	}
	w, _ = store.Get(w.ID)
	w.IntervalSeconds = 86400
	updated, err = store.Update(w)
	if err != nil {
		t.Fatal(err)
	}
	if want := ranAt.Add(24 * time.Hour); !updated.NextRunAt.Equal(want) {
		t.Errorf("next_run_at = %s, want %s (last run + new interval)", updated.NextRunAt, want)
	}
	if updated.LastStatus != "ok" || updated.LastRunAt == nil || !updated.Enabled {
		t.Errorf("edit must keep the run history and enabled state: %+v", updated)
	}
}

// TestWatchStorePersists confirms watches survive a database reopen.
func TestWatchStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watches.db")
	store, err := OpenWatchStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(Watch{
		Stream: streamGo, Label: "go: foo", Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`,
		IntervalSeconds: 86400, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWatchStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	list, err := reopened.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Stream != streamGo || list[0].Label != "go: foo" {
		t.Fatalf("reopened List = %+v", list)
	}
}

// TestRunDueWatchesProducesBundle drives the scheduler end to end: a due Go
// watch resolves and exports a bundle through the same collect path as a manual
// request, and its outcome is recorded.
func TestRunDueWatchesProducesBundle(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	if _, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: foo/bar",
		Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`, IntervalSeconds: 3600, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	ls.runDueWatches()

	// The run is now a job on the go stream's queue; wait for its outcome to
	// be recorded before asserting.
	waitWatchRecorded(t, ls, 1)

	// The collect ran: the go stream's sequence advanced past bundle 1.
	if got := ls.peekSequence(streamGo); got != 2 {
		t.Errorf("go next sequence after watch run = %d, want 2", got)
	}
	list, err := ls.watches.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].LastStatus != "ok" || list[0].LastRunAt == nil {
		t.Fatalf("watch run not recorded ok: %+v", list)
	}
	// Its next run is now in the future, so a second drain does nothing.
	if due, _ := ls.watches.Due(time.Now().UTC()); len(due) != 0 {
		t.Errorf("watch should not be due right after running, got %d", len(due))
	}
}

// waitWatchRecorded polls until the watch has a recorded run — scheduled runs
// now execute asynchronously on the job queue.
func waitWatchRecorded(t *testing.T, ls *LowServer, id int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := ls.watches.Get(id); err == nil && got.LastRunAt != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watch %d never recorded a run", id)
}

// A watch whose previous run is still queued or running is not enqueued again
// by a due tick or a run-now — the queue dedups on the watch id.
func TestWatchJobDedupAcrossTickAndRunNow(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	w, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: foo/bar",
		Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`, IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Hold the go stream busy so the watch job stays queued.
	release := make(chan struct{})
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}

	first, err := ls.enqueueWatch(w)
	if err != nil || first == 0 {
		t.Fatalf("first enqueue = job %d, %v; want a job", first, err)
	}
	if _, err := ls.enqueueWatch(w); !errors.Is(err, errWatchJobExists) {
		t.Errorf("second enqueue err = %v, want errWatchJobExists", err)
	}
	ls.runDueWatches() // the due tick is deduped the same way
	if got := len(ls.jobs.list()); got != 2 {
		t.Errorf("job list has %d entries, want 2 (blocker + one watch job)", got)
	}

	// Run-now over HTTP reports the dedup as job_id 0.
	res := doLowReq(t, ls, http.MethodPost, "/admin/watches/run",
		`{"id":`+strconv.FormatInt(w.ID, 10)+`}`)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"job_id": 0`) {
		t.Errorf("run-now while queued = %d %s, want job_id 0", res.Code, res.Body.String())
	}

	close(release)
	waitWatchRecorded(t, ls, w.ID)
	got, err := ls.watches.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != "ok" {
		t.Errorf("watch outcome = %s (%s), want ok", got.LastStatus, got.LastMessage)
	}
}

// An interval edited while the watch's job is queued or running is honored
// when that run's completion schedules the next one: enqueueWatch captured
// the pre-edit Watch, but RecordRun spaces from the interval stored at record
// time. Regression: switching a daily watch to hourly mid-run used to
// schedule the next run a day out from the stale captured interval.
func TestWatchIntervalEditDuringRunHonored(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	w, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: foo/bar",
		Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`, IntervalSeconds: 86400, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Hold the go stream busy so the watch's job is still pending when the
	// edit lands.
	release := make(chan struct{})
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := ls.enqueueWatch(w); err != nil {
		t.Fatal(err)
	}

	// Edit the schedule from daily to hourly while the run is in flight.
	w.IntervalSeconds = 3600
	if _, err := ls.watches.Update(w); err != nil {
		t.Fatal(err)
	}

	close(release)
	waitWatchRecorded(t, ls, w.ID)
	got, err := ls.watches.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalSeconds != 3600 {
		t.Fatalf("interval after run = %d, want the edited 3600: %+v", got.IntervalSeconds, got)
	}
	if want := got.LastRunAt.Add(time.Hour); !got.NextRunAt.Equal(want) {
		t.Errorf("next_run_at = %s, want %s (finish + edited interval, not + the enqueue-time day)",
			got.NextRunAt, want)
	}
}

// A run-now that cannot be queued because the stream's queue is full is an
// error the operator must see (429), not a silent "started" — unlike the
// dedup case, nothing is pending, so the requested run would otherwise be
// dropped until the schedule next fires (or forever, for a disabled watch).
func TestRunWatchNowQueueFullIsError(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	w, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: foo/bar",
		Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`, IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fill the go stream: one running job plus a full pending queue.
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

	if _, err := ls.enqueueWatch(w); !errors.Is(err, errJobQueueFull) {
		t.Fatalf("enqueueWatch on full queue err = %v, want errJobQueueFull", err)
	}
	res := doLowReq(t, ls, http.MethodPost, "/admin/watches/run",
		`{"id":`+strconv.FormatInt(w.ID, 10)+`}`)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("run-now on full queue = %d %s, want 429", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "started") {
		t.Errorf("run-now on full queue must not report started: %s", res.Body.String())
	}
}

// Canceling a watch's job records the outcome, so the schedule advances
// instead of immediately re-enqueueing the canceled run.
func TestWatchJobCancelRecordsOutcome(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	w, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: foo/bar",
		Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`, IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	jobID, err := ls.enqueueWatch(w)
	if err != nil || jobID == 0 {
		t.Fatalf("watch job not enqueued: job %d, %v", jobID, err)
	}
	if err := ls.jobs.cancel(jobID); err != nil {
		t.Fatal(err)
	}
	waitWatchRecorded(t, ls, w.ID)
	got, err := ls.watches.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != "error" || got.NextRunAt.IsZero() {
		t.Errorf("canceled watch run = %+v, want recorded error with next run scheduled", got)
	}
	if due, _ := ls.watches.Due(time.Now().UTC()); len(due) != 0 {
		t.Errorf("canceled watch still due: %d", len(due))
	}
}

// doLowReq drives one request straight through the low server's handler, without
// a live HTTP client.
func doLowReq(t *testing.T, ls *LowServer, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	ls.ServeHTTP(w, r)
	return w
}

func TestLowServerWatchEndpoints(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	// Create.
	create := doLowReq(t, ls, http.MethodPost, "/admin/watches",
		`{"stream":"python","label":"py: requests","interval_seconds":86400,"spec":{"requirements":["requests"]}}`)
	if create.Code != http.StatusOK {
		t.Fatalf("create status %d: %s", create.Code, create.Body.String())
	}
	var created Watch
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 || created.Stream != streamPython || !created.Enabled {
		t.Fatalf("create returned %+v", created)
	}

	// List shows it.
	if list := doLowReq(t, ls, http.MethodGet, "/admin/watches", ""); list.Code != http.StatusOK ||
		!strings.Contains(list.Body.String(), "py: requests") {
		t.Fatalf("list: status %d body %s", list.Code, list.Body.String())
	}

	idBody := `{"id":` + strconv.FormatInt(created.ID, 10) + `}`

	// Disable → enabled=false persisted.
	if w := doLowReq(t, ls, http.MethodPost, "/admin/watches/disable", idBody); w.Code != http.StatusOK {
		t.Fatalf("disable status %d", w.Code)
	}
	if got, _ := ls.watches.Get(created.ID); got.Enabled {
		t.Error("watch should be disabled")
	}

	// Delete → gone.
	if w := doLowReq(t, ls, http.MethodPost, "/admin/watches/delete", idBody); w.Code != http.StatusOK {
		t.Fatalf("delete status %d", w.Code)
	}
	if list, _ := ls.watches.List(); len(list) != 0 {
		t.Fatalf("expected no watches after delete, got %d", len(list))
	}

	// Too-short interval is rejected.
	if bad := doLowReq(t, ls, http.MethodPost, "/admin/watches",
		`{"stream":"python","interval_seconds":5,"spec":{"requirements":["x"]}}`); bad.Code != http.StatusBadRequest {
		t.Errorf("short-interval create status = %d, want 400", bad.Code)
	}
	// Unknown stream is rejected.
	if bad := doLowReq(t, ls, http.MethodPost, "/admin/watches",
		`{"stream":"nope","interval_seconds":3600,"spec":{"x":1}}`); bad.Code != http.StatusBadRequest {
		t.Errorf("unknown-stream create status = %d, want 400", bad.Code)
	}
	// A spec carrying a login is rejected: watches are stored and echoed in
	// plaintext, so credentials must never be scheduled.
	if bad := doLowReq(t, ls, http.MethodPost, "/admin/watches",
		`{"stream":"containers","interval_seconds":3600,"spec":{"images":["ghcr.io/org/app:v1"],"auth":{"username":"u","password":"p"}}}`); bad.Code != http.StatusBadRequest {
		t.Errorf("credentialed-spec create status = %d, want 400", bad.Code)
	}
}

// TestWatchLegacyCredentialedSpecRefusedAtRun covers upgraded installs: a row
// stored before the auth guard existed (when an "auth" key was an ignored
// unknown field) must be refused at run time — never decoded into the
// collector's Auth field — and the refusal must land in the watch's recorded
// outcome.
func TestWatchLegacyCredentialedSpecRefusedAtRun(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	spec := `{"images":["ghcr.io/org/app:v1"],"auth":{"username":"u","password":"hunter2"}}`

	// The dispatcher refuses the spec outright, on every path (scheduled and
	// run-now both funnel through runWatchCollect), without echoing the login.
	_, err := ls.runWatchCollect(context.Background(), "containers", spec)
	if err == nil || !strings.Contains(err.Error(), "must not carry credentials") {
		t.Fatalf("credentialed legacy spec error = %v", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error must not echo the login: %v", err)
	}

	// The store does not validate (only the HTTP handlers do), simulating the
	// pre-guard row; a full run records the refusal on the watch.
	w, err := ls.watches.Create(Watch{Stream: "containers", Label: "legacy", Spec: spec, IntervalSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := ls.enqueueWatch(w); err != nil || id == 0 {
		t.Fatalf("watch job not enqueued: job %d, %v", id, err)
	}
	waitWatchRecorded(t, ls, w.ID)
	got, err := ls.watches.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != "error" || !strings.Contains(got.LastMessage, "must not carry credentials") {
		t.Fatalf("recorded outcome = %q / %q", got.LastStatus, got.LastMessage)
	}
}

// TestLowServerWatchUpdateEndpoint drives POST /admin/watches/update: a full
// edit, a partial edit (blank fields keep their values), and the rejections.
func TestLowServerWatchUpdateEndpoint(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	created, err := ls.watches.Create(Watch{
		Stream: streamPython, Label: "py: requests",
		Spec: `{"requirements":["requests"]}`, IntervalSeconds: 86400, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(created.ID, 10)

	// Full edit: label, interval, and spec all change; the response is the
	// updated watch.
	res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":`+id+`,"label":"py: urllib3","interval_seconds":3600,"spec":{"requirements":["urllib3"]}}`)
	if res.Code != http.StatusOK {
		t.Fatalf("update status %d: %s", res.Code, res.Body.String())
	}
	var updated Watch
	if err := json.Unmarshal(res.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Label != "py: urllib3" || updated.IntervalSeconds != 3600 ||
		updated.Spec != `{"requirements":["urllib3"]}` || updated.Stream != streamPython {
		t.Fatalf("update returned %+v", updated)
	}

	// Partial edit: only the interval; label and spec keep their values.
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":`+id+`,"interval_seconds":7200}`); res.Code != http.StatusOK {
		t.Fatalf("partial update status %d: %s", res.Code, res.Body.String())
	}
	got, err := ls.watches.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalSeconds != 7200 || got.Label != "py: urllib3" || got.Spec != `{"requirements":["urllib3"]}` {
		t.Fatalf("partial update stored %+v", got)
	}

	// A JSON-null spec also means "keep".
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":`+id+`,"spec":null,"label":"py: pinned"}`); res.Code != http.StatusOK {
		t.Fatalf("null-spec update status %d: %s", res.Code, res.Body.String())
	}
	if got, _ := ls.watches.Get(created.ID); got.Spec != `{"requirements":["urllib3"]}` || got.Label != "py: pinned" {
		t.Fatalf("null-spec update stored %+v", got)
	}

	// Rejections: too-short interval, unknown id, missing id, bad JSON.
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":`+id+`,"interval_seconds":5}`); res.Code != http.StatusBadRequest {
		t.Errorf("short-interval update status = %d, want 400", res.Code)
	}
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":99999,"interval_seconds":3600}`); res.Code != http.StatusNotFound {
		t.Errorf("unknown-id update status = %d, want 404", res.Code)
	}
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"interval_seconds":3600}`); res.Code != http.StatusBadRequest {
		t.Errorf("missing-id update status = %d, want 400", res.Code)
	}
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":`); res.Code != http.StatusBadRequest {
		t.Errorf("bad-JSON update status = %d, want 400", res.Code)
	}
	// A spec carrying a login is rejected on update too — an edit must not be
	// able to smuggle credentials into the plaintext store.
	if res := doLowReq(t, ls, http.MethodPost, "/admin/watches/update",
		`{"id":`+id+`,"spec":{"requirements":["x"],"auth":{"username":"u","password":"p"}}}`); res.Code != http.StatusBadRequest {
		t.Errorf("credentialed-spec update status = %d, want 400", res.Code)
	}
	// The rejected edits changed nothing.
	if got, _ := ls.watches.Get(created.ID); got.IntervalSeconds != 7200 || got.Spec != `{"requirements":["urllib3"]}` {
		t.Errorf("rejected updates must not change the watch: %+v", got)
	}
}
