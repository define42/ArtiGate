package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// testJob builds a manual job for stream whose collect is run.
func testJob(stream string, run func(context.Context) (ExportResult, error)) *Job {
	return &Job{Stream: stream, Kind: jobKindManual, Label: stream + " test", run: run}
}

func waitJobDone(t *testing.T, j *Job) {
	t.Helper()
	select {
	case <-j.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("job %d (%s) never finished", j.ID, j.Label)
	}
}

// waitJobState polls until the job reaches state (running is never signalled
// on a channel, so polling is the only way to observe it).
func waitJobState(t *testing.T, j *Job, state jobState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j.snapshotInfo(0).State == string(state) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %d never reached state %s (now %s)", j.ID, state, j.snapshotInfo(0).State)
}

func TestJobQueueRunsFIFOPerStream(t *testing.T) {
	m := newJobManager()
	release := make(chan struct{})
	var mu sync.Mutex
	var order []int

	jobs := make([]*Job, 0, 3)
	for n := 1; n <= 3; n++ {
		j := testJob(streamGo, func(context.Context) (ExportResult, error) {
			<-release
			mu.Lock()
			order = append(order, n)
			mu.Unlock()
			return ExportResult{}, nil
		})
		ahead, err := m.enqueue(context.Background(), j)
		if err != nil {
			t.Fatal(err)
		}
		if ahead != n-1 {
			t.Errorf("job %d: %d ahead, want %d", n, ahead, n-1)
		}
		jobs = append(jobs, j)
	}
	close(release)
	for _, j := range jobs {
		waitJobDone(t, j)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(order) != "[1 2 3]" {
		t.Errorf("run order = %v, want [1 2 3]", order)
	}
}

// A blocked stream must not hold up another stream's jobs.
func TestJobQueueStreamsRunConcurrently(t *testing.T) {
	m := newJobManager()
	release := make(chan struct{})
	blocked := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), blocked); err != nil {
		t.Fatal(err)
	}
	free := testJob(streamPython, func(context.Context) (ExportResult, error) {
		return ExportResult{BundleID: "python-000001"}, nil
	})
	if _, err := m.enqueue(context.Background(), free); err != nil {
		t.Fatal(err)
	}
	waitJobDone(t, free) // completes while the go stream is still blocked
	if got := jobState(blocked.snapshotInfo(0).State); got.terminal() {
		t.Errorf("blocked job state = %s, want still queued/running", got)
	}
	close(release)
	waitJobDone(t, blocked)
	if got := free.snapshotInfo(0); got.State != string(jobOK) || got.BundleID != "python-000001" {
		t.Errorf("free job = %+v, want ok with bundle", got)
	}
}

func TestJobCancelQueuedNeverRuns(t *testing.T) {
	m := newJobManager()
	release := make(chan struct{})
	first := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	secondRan := make(chan struct{})
	second := testJob(streamGo, func(context.Context) (ExportResult, error) {
		close(secondRan)
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	if err := m.cancel(second.ID); err != nil {
		t.Fatalf("cancel queued: %v", err)
	}
	waitJobDone(t, second)
	if got := second.snapshotInfo(0); got.State != string(jobCanceled) || got.Error != "collect canceled" {
		t.Errorf("canceled queued job = %+v", got)
	}
	close(release)
	waitJobDone(t, first)
	select {
	case <-secondRan:
		t.Error("canceled queued job still ran")
	default:
	}
	if got := first.snapshotInfo(0).State; got != string(jobOK) {
		t.Errorf("first job state = %s, want ok", got)
	}
}

func TestJobCancelRunning(t *testing.T) {
	m := newJobManager()
	j := testJob(streamGo, func(ctx context.Context) (ExportResult, error) {
		<-ctx.Done()
		return ExportResult{}, ctx.Err()
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	waitJobState(t, j, jobRunning)
	if err := m.cancel(j.ID); err != nil {
		t.Fatalf("cancel running: %v", err)
	}
	waitJobDone(t, j)
	if got := j.snapshotInfo(0); got.State != string(jobCanceled) || got.Error != "collect canceled" {
		t.Errorf("canceled running job = %+v", got)
	}
}

func TestJobCancelErrors(t *testing.T) {
	m := newJobManager()
	if err := m.cancel(42); !errors.Is(err, errJobNotFound) {
		t.Errorf("cancel unknown = %v, want errJobNotFound", err)
	}
	j := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	waitJobDone(t, j)
	if err := m.cancel(j.ID); !errors.Is(err, errJobFinished) {
		t.Errorf("cancel finished = %v, want errJobFinished", err)
	}
}

func TestJobQueueCapRejects(t *testing.T) {
	m := newJobManager()
	release := make(chan struct{})
	defer close(release)
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	waitJobState(t, blocker, jobRunning) // queue is now empty, stream busy
	for i := 0; i < jobQueueCap; i++ {
		j := testJob(streamGo, func(context.Context) (ExportResult, error) {
			return ExportResult{}, nil
		})
		if _, err := m.enqueue(context.Background(), j); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	over := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), over); !errors.Is(err, errJobQueueFull) {
		t.Errorf("enqueue over cap = %v, want errJobQueueFull", err)
	}
	// Another stream is unaffected by the full queue.
	other := testJob(streamPython, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), other); err != nil {
		t.Errorf("other stream enqueue: %v", err)
	}
	waitJobDone(t, other)
}

func TestJobHistoryBound(t *testing.T) {
	m := newJobManager()
	var jobs []*Job
	for i := 0; i < jobHistoryCap+5; i++ {
		j := testJob(streamGo, func(context.Context) (ExportResult, error) {
			return ExportResult{}, nil
		})
		if _, err := m.enqueue(context.Background(), j); err != nil {
			t.Fatal(err)
		}
		waitJobDone(t, j) // serialize so the queue cap is never the limit here
		jobs = append(jobs, j)
	}
	if got := len(m.list()); got != jobHistoryCap {
		t.Errorf("listed %d jobs, want %d", got, jobHistoryCap)
	}
	// The oldest five were evicted, byID included.
	for _, j := range jobs[:5] {
		if m.get(j.ID) != nil {
			t.Errorf("job %d should have been evicted from byID", j.ID)
		}
	}
	if m.get(jobs[len(jobs)-1].ID) == nil {
		t.Error("newest finished job missing from byID")
	}
}

func TestJobLogRingDropsOldest(t *testing.T) {
	m := newJobManager()
	const extra = 50
	j := testJob(streamGo, func(ctx context.Context) (ExportResult, error) {
		for i := 0; i < jobLogCap+extra; i++ {
			emitProgress(ctx, "line %d", i)
		}
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	waitJobDone(t, j)

	batch := j.logSince(0)
	if len(batch.lines) != jobLogCap+1 {
		t.Fatalf("replayed %d lines, want %d (marker + ring)", len(batch.lines), jobLogCap+1)
	}
	if want := fmt.Sprintf("… %d earlier line(s) not shown …", extra); batch.lines[0] != want {
		t.Errorf("marker = %q, want %q", batch.lines[0], want)
	}
	if want := fmt.Sprintf("line %d", extra); batch.lines[1] != want {
		t.Errorf("first kept line = %q, want %q", batch.lines[1], want)
	}
	if want := fmt.Sprintf("line %d", jobLogCap+extra-1); batch.lines[len(batch.lines)-1] != want {
		t.Errorf("last line = %q, want %q", batch.lines[len(batch.lines)-1], want)
	}
	if batch.cursor != jobLogCap+extra {
		t.Errorf("cursor = %d, want %d", batch.cursor, jobLogCap+extra)
	}
}

// A follower replays buffered lines, then is woken for live ones, and sees the
// terminal state — with no line lost or duplicated in between.
func TestJobFollowerReplayThenLive(t *testing.T) {
	m := newJobManager()
	emitted := make(chan struct{})
	proceed := make(chan struct{})
	j := testJob(streamGo, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "first")
		emitProgress(ctx, "second")
		emitted <- struct{}{}
		<-proceed
		emitProgress(ctx, "third")
		return ExportResult{BundleID: "go-bundle-000042"}, nil
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	<-emitted

	batch := j.logSince(0)
	if strings.Join(batch.lines, "|") != "first|second" {
		t.Fatalf("replay = %v, want [first second]", batch.lines)
	}
	if batch.state != jobRunning {
		t.Fatalf("state during run = %s, want running", batch.state)
	}
	close(proceed)
	var lines []string
	deadline := time.After(5 * time.Second)
	for batch.state == jobRunning {
		select {
		case <-batch.updated:
		case <-deadline:
			t.Fatal("follower never saw the job finish")
		}
		batch = j.logSince(batch.cursor)
		lines = append(lines, batch.lines...)
	}
	if strings.Join(lines, "|") != "third" {
		t.Errorf("live lines = %v, want [third]", lines)
	}
	if batch.state != jobOK || batch.result.BundleID != "go-bundle-000042" {
		t.Errorf("terminal batch = state %s result %+v", batch.state, batch.result)
	}
}

func TestJobRunPanicBecomesError(t *testing.T) {
	m := newJobManager()
	j := testJob(streamGo, func(context.Context) (ExportResult, error) {
		panic("upstream returned garbage")
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	waitJobDone(t, j)
	got := j.snapshotInfo(0)
	if got.State != string(jobError) || !strings.Contains(got.Error, "collect panicked: upstream returned garbage") {
		t.Errorf("panicking job = %+v, want error state with panic message", got)
	}
}

func TestJobManagerShutdown(t *testing.T) {
	m := newJobManager()
	running := testJob(streamGo, func(ctx context.Context) (ExportResult, error) {
		<-ctx.Done()
		return ExportResult{}, ctx.Err()
	})
	if _, err := m.enqueue(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	waitJobState(t, running, jobRunning)
	queued := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), queued); err != nil {
		t.Fatal(err)
	}

	m.shutdown()
	waitJobDone(t, running)
	waitJobDone(t, queued)
	if got := running.snapshotInfo(0).State; got != string(jobCanceled) {
		t.Errorf("running job after shutdown = %s, want canceled", got)
	}
	if got := queued.snapshotInfo(0).State; got != string(jobCanceled) {
		t.Errorf("queued job after shutdown = %s, want canceled", got)
	}
	if _, err := m.enqueue(context.Background(), testJob(streamGo, nil)); !errors.Is(err, errJobsClosed) {
		t.Errorf("enqueue after shutdown = %v, want errJobsClosed", err)
	}
	m.shutdown() // idempotent
}

func TestJobWatchDedup(t *testing.T) {
	m := newJobManager()
	release := make(chan struct{})
	defer close(release)
	blocked := &Job{
		Stream: streamGo, Kind: jobKindWatch, WatchID: 7, Label: "w7",
		run: func(context.Context) (ExportResult, error) { <-release; return ExportResult{}, nil },
	}
	if _, err := m.enqueue(context.Background(), blocked); err != nil {
		t.Fatal(err)
	}
	dup := &Job{
		Stream: streamGo, Kind: jobKindWatch, WatchID: 7, Label: "w7 again",
		run: func(context.Context) (ExportResult, error) { return ExportResult{}, nil },
	}
	if _, err := m.enqueue(context.Background(), dup); !errors.Is(err, errWatchJobExists) {
		t.Errorf("duplicate watch enqueue = %v, want errWatchJobExists", err)
	}
	other := &Job{
		Stream: streamGo, Kind: jobKindWatch, WatchID: 8, Label: "w8",
		run: func(context.Context) (ExportResult, error) { return ExportResult{}, nil },
	}
	if _, err := m.enqueue(context.Background(), other); err != nil {
		t.Errorf("distinct watch enqueue = %v", err)
	}
}

// afterRun observes the outcome exactly once, after the terminal state is
// visible — including for a canceled queued job that never ran.
func TestJobAfterRunHook(t *testing.T) {
	m := newJobManager()
	outcome := make(chan error, 1)
	j := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, errors.New("boom")
	})
	j.afterRun = func(_ ExportResult, err error) { outcome <- err }
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-outcome:
		if err == nil || err.Error() != "boom" {
			t.Errorf("afterRun err = %v, want boom", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("afterRun never ran")
	}
	if got := j.snapshotInfo(0); got.State != string(jobError) || got.Error != "boom" {
		t.Errorf("failed job = %+v", got)
	}

	// Canceled while queued: the hook still fires with the cancellation.
	release := make(chan struct{})
	defer close(release)
	blocker := testJob(streamGo, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}
	queued := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	queuedOutcome := make(chan error, 1)
	queued.afterRun = func(_ ExportResult, err error) { queuedOutcome <- err }
	if _, err := m.enqueue(context.Background(), queued); err != nil {
		t.Fatal(err)
	}
	if err := m.cancel(queued.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-queuedOutcome:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("canceled queued afterRun err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("afterRun for canceled queued job never ran")
	}
}

func TestJobListOrderingAndFields(t *testing.T) {
	m := newJobManager()
	finished := testJob(streamPython, func(context.Context) (ExportResult, error) {
		return ExportResult{BundleID: "python-bundle-000001", ExportedModules: 2, Sequence: 1}, nil
	})
	if _, err := m.enqueue(context.Background(), finished); err != nil {
		t.Fatal(err)
	}
	waitJobDone(t, finished)

	release := make(chan struct{})
	defer close(release)
	logged := make(chan struct{})
	running := testJob(streamGo, func(ctx context.Context) (ExportResult, error) {
		emitProgress(ctx, "working on it")
		close(logged)
		<-release
		return ExportResult{}, nil
	})
	if _, err := m.enqueue(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	<-logged
	queued := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{}, nil
	})
	queued.RequestedBy = "alice"
	if _, err := m.enqueue(context.Background(), queued); err != nil {
		t.Fatal(err)
	}

	list := m.list()
	if len(list) != 3 {
		t.Fatalf("list has %d entries, want 3: %+v", len(list), list)
	}
	if list[0].ID != running.ID || list[0].State != string(jobRunning) {
		t.Errorf("list[0] = %+v, want the running job", list[0])
	}
	if list[0].LastLog != "working on it" {
		t.Errorf("running job last_log = %q", list[0].LastLog)
	}
	if list[1].ID != queued.ID || list[1].State != string(jobQueued) || list[1].Position != 1 {
		t.Errorf("list[1] = %+v, want the queued job at position 1", list[1])
	}
	if list[1].RequestedBy != "alice" {
		t.Errorf("queued job requested_by = %q, want alice", list[1].RequestedBy)
	}
	if list[2].ID != finished.ID || list[2].State != string(jobOK) {
		t.Errorf("list[2] = %+v, want the finished job", list[2])
	}
	if list[2].Message == "" || list[2].BundleID != "python-bundle-000001" {
		t.Errorf("finished job summary = %+v, want message and bundle id", list[2])
	}
	if list[2].StartedAt == nil || list[2].FinishedAt == nil {
		t.Errorf("finished job missing timestamps: %+v", list[2])
	}
}

func TestManualCollectLabel(t *testing.T) {
	cases := []struct {
		name   string
		stream string
		body   string
		want   string
	}{
		{"modules", "go", `{"modules":["example.com/a@v1","example.com/b"]}`, "go: example.com/a@v1, example.com/b"},
		{"truncates list", "npm", `{"packages":["a","b","c","d","e"]}`, "npm: a, b, c (+2 more)"},
		{"requirements", "python", `{"requirements":["requests==2.32.4"]}`, "python: requests==2.32.4"},
		{"project file", "go", `{"go_mod":"module x"}`, "go: uploaded project file"},
		{"apt source", "apt", `{"source_list":"Types: deb\nURIs: https://pkg.example/repo\nSuites: stable"}`, "apt: https://pkg.example/repo"},
		{"rpm repo", "rpm", `{"repo_file":"[code]\nname=Code\n"}`, "rpm: code"},
		{"invalid json", "go", `{nope`, "go"},
		{"empty body", "hf", ``, "hf"},
		{"empty spec", "hf", `{}`, "hf"},
	}
	for _, tc := range cases {
		if got := manualCollectLabel(tc.stream, []byte(tc.body)); got != tc.want {
			t.Errorf("%s: label = %q, want %q", tc.name, got, tc.want)
		}
	}
	long := manualCollectLabel("go", []byte(`{"modules":["example.com/`+strings.Repeat("x", 200)+`@v1"]}`))
	if len(long) > 90 {
		t.Errorf("long label not clipped: %d chars", len(long))
	}
}
