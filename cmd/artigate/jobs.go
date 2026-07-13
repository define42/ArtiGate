package main

// Per-stream job queue. Every collect — manual (HTTP) or scheduled (watch) —
// runs as a Job on its stream's FIFO queue: one job runs per stream at a time,
// and different streams run concurrently, mirroring streamLock's
// serialization (which stays in place as the low-level correctness guard; the
// queue is the scheduling and visibility layer above it). Any dashboard
// session can list all queued/running/finished jobs, follow a job's live
// progress, cancel it, and read why it failed. History is in-memory only:
// jobHistoryCap finished jobs survive until restart, while scheduled pulls
// additionally persist their last outcome on the watch row as before.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// jobLogCap bounds one job's progress-log ring. A follower sees at most
	// this many buffered lines plus a "… not shown …" marker; lines emitted
	// while it is attached are never lost to it.
	jobLogCap = 500
	// jobHistoryCap bounds how many finished jobs the dashboard can list.
	jobHistoryCap = 100
	// jobQueueCap bounds queued jobs per stream; enqueueing beyond it is
	// refused (HTTP 429). It also bounds the memory pinned by buffered
	// request bodies waiting in the queue.
	jobQueueCap = 20
	// jobShutdownWait bounds how long shutdown waits for canceled jobs to
	// unwind before giving up (the process is exiting anyway).
	jobShutdownWait = 5 * time.Second
)

// Sentinel errors the HTTP layer maps to status codes.
var (
	errJobNotFound  = errors.New("job not found")
	errJobFinished  = errors.New("job already finished")
	errJobQueueFull = errors.New("job queue for this stream is full; retry later")
	errJobsClosed   = errors.New("server is shutting down")
	// errWatchJobExists reports that a watch already has a queued or running
	// job, so a new run would be a duplicate (a due tick overlapping run-now,
	// or a slow collect still going when the next interval arrives).
	errWatchJobExists = errors.New("watch already queued or running")
)

type jobState string

const (
	jobQueued   jobState = "queued"
	jobRunning  jobState = "running"
	jobOK       jobState = "ok"
	jobError    jobState = "error"
	jobCanceled jobState = "canceled"
)

// terminal reports whether a job in this state will never run again.
func (s jobState) terminal() bool {
	return s == jobOK || s == jobError || s == jobCanceled
}

type jobKind string

const (
	jobKindManual jobKind = "manual"
	jobKindWatch  jobKind = "watch"
)

// dlSnapshot is the latest byte-progress sample of a job's in-flight download,
// mirroring the dl NDJSON event. Samples are latest-only: a slow reader sees
// the current one, never a backlog.
type dlSnapshot struct {
	Name  string `json:"name"`
	Done  int64  `json:"done"`
	Total int64  `json:"total"`
	BPS   int64  `json:"bps"`
}

// Job is one queued, running, or finished collect. Identity fields are set
// before the job becomes visible to other goroutines and are immutable from
// then on; everything below mu is guarded by it.
type Job struct {
	ID          int64
	Stream      string
	Kind        jobKind
	WatchID     int64 // 0 for manual jobs
	Label       string
	RequestedBy string // authenticated username, or "schedule" for watch jobs

	// run executes the collect. afterRun, if set, observes the outcome (the
	// watch integration records it); it runs after the job reaches a terminal
	// state, outside all queue locks. ctx/cancel govern the run: ctx derives
	// from context.Background() for detached jobs, or from the request context
	// for uploads (whose body streams from the client).
	run      func(context.Context) (ExportResult, error)
	afterRun func(ExportResult, error)
	ctx      context.Context
	cancel   context.CancelFunc

	mu         sync.Mutex
	state      jobState
	createdAt  time.Time
	startedAt  time.Time
	finishedAt time.Time
	errMsg     string
	result     ExportResult
	log        []string // progress-line ring, at most jobLogCap entries
	logHead    int      // ring start once len(log) == jobLogCap
	logDropped int      // lines evicted from the front, ever
	dl         *dlSnapshot
	updated    chan struct{} // closed and replaced on every visible change
	done       chan struct{} // closed once state is terminal
}

// jobManager owns every stream's queue. Lock order is always m.mu before
// j.mu; broadcastLocked-style helpers expect j.mu held.
type jobManager struct {
	mu       sync.Mutex
	closed   bool
	nextID   int64
	queues   map[string][]*Job // queued jobs per stream, FIFO
	running  map[string]*Job   // at most one per stream
	byID     map[int64]*Job    // queued + running + retained history
	history  []*Job            // finished jobs, oldest first, capped
	dispatch map[string]bool   // stream has a live dispatcher goroutine
	wg       sync.WaitGroup
}

func newJobManager() *jobManager {
	return &jobManager{
		queues:   map[string][]*Job{},
		running:  map[string]*Job{},
		byID:     map[int64]*Job{},
		dispatch: map[string]bool{},
	}
}

// enqueue adds j to its stream's queue and returns how many jobs are ahead of
// it (0 = it will run immediately). The job's ID, state, and context are
// assigned here, before it becomes visible to any other goroutine.
func (m *jobManager) enqueue(parent context.Context, j *Job) (int, error) {
	if parent == nil {
		parent = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errJobsClosed
	}
	if j.WatchID != 0 && m.watchJobExistsLocked(j.WatchID) {
		return 0, errWatchJobExists
	}
	queue := m.queues[j.Stream]
	if len(queue) >= jobQueueCap {
		return 0, errJobQueueFull
	}
	m.nextID++
	j.ID = m.nextID
	j.state = jobQueued
	j.createdAt = time.Now()
	j.ctx, j.cancel = context.WithCancel(parent)
	j.updated = make(chan struct{})
	j.done = make(chan struct{})
	ahead := len(queue)
	if m.running[j.Stream] != nil {
		ahead++
	}
	if ahead > 0 {
		j.log = append(j.log, fmt.Sprintf("Queued behind %d job(s) on stream %s…", ahead, j.Stream))
	}
	m.queues[j.Stream] = append(queue, j)
	m.byID[j.ID] = j
	if !m.dispatch[j.Stream] {
		m.dispatch[j.Stream] = true
		m.wg.Add(1)
		go m.runStream(j.Stream)
	}
	return ahead, nil
}

// watchJobExistsLocked reports whether a job for this watch is already queued
// or running on any stream. Caller holds m.mu.
func (m *jobManager) watchJobExistsLocked(watchID int64) bool {
	for _, j := range m.running {
		if j.WatchID == watchID {
			return true
		}
	}
	for _, queue := range m.queues {
		for _, j := range queue {
			if j.WatchID == watchID {
				return true
			}
		}
	}
	return false
}

// runStream is one stream's dispatcher: it pops and runs queued jobs in FIFO
// order until the queue drains, then exits (a later enqueue starts a fresh
// one). A recover guards the loop so a bookkeeping bug can never kill the
// stream's dispatching — the collect's own panics are already contained by
// recoverCollectPanic inside runJob.
func (m *jobManager) runStream(stream string) {
	defer m.wg.Done()
	for {
		j := m.nextJob(stream)
		if j == nil {
			return
		}
		m.runJob(j)
	}
}

// nextJob pops the stream's next queued job and marks it running, or clears
// the dispatch flag and returns nil when the queue is empty (or shutting
// down, in which case shutdown owns the queued jobs).
func (m *jobManager) nextJob(stream string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	queue := m.queues[stream]
	if len(queue) == 0 || m.closed {
		m.dispatch[stream] = false
		return nil
	}
	j := queue[0]
	m.queues[stream] = queue[1:]
	m.running[stream] = j
	j.mu.Lock()
	j.state = jobRunning
	j.startedAt = time.Now()
	j.broadcastLocked()
	j.mu.Unlock()
	return j
}

// runJob executes one job with the progress sinks pointed at its ring and
// records the outcome. Collector panics become errors via recoverCollectPanic;
// the extra recover contains bookkeeping bugs in the queue itself.
func (m *jobManager) runJob(j *Job) {
	defer func() {
		if r := recover(); r != nil {
			m.finishJob(j, ExportResult{}, fmt.Errorf("job runner panicked: %v", r))
		}
	}()
	ctx := withProgress(j.ctx, j.appendLog)
	ctx = withDownloadProgress(ctx, j.setDL)
	res, err := recoverCollectPanic(j.Stream, func() (ExportResult, error) {
		return j.run(ctx)
	})
	m.finishJob(j, res, err)
}

// finishJob moves j to a terminal state, retires it into history, and runs the
// afterRun hook outside all locks. It is a no-op when the job is already
// terminal (a canceled queued job whose cancel raced the dispatcher).
func (m *jobManager) finishJob(j *Job, res ExportResult, err error) {
	m.mu.Lock()
	j.mu.Lock()
	if j.state.terminal() {
		j.mu.Unlock()
		m.mu.Unlock()
		return
	}
	j.applyOutcomeLocked(res, err)
	after := j.afterRun
	// Free what the closures pin (a buffered request body can be MiBs) —
	// history only needs the outcome fields.
	j.run, j.afterRun = nil, nil
	j.mu.Unlock()
	if m.running[j.Stream] == j {
		delete(m.running, j.Stream)
	}
	m.history = append(m.history, j)
	for len(m.history) > jobHistoryCap {
		delete(m.byID, m.history[0].ID)
		m.history = m.history[1:]
	}
	m.mu.Unlock()
	j.cancel() // release the context's resources; no-op if already canceled
	if after != nil {
		after(res, err)
	}
}

// applyOutcomeLocked sets the terminal state fields. A run that failed because
// the job's context was canceled reports as canceled, not errored — that is
// the operator's Stop, or the client vanishing under an upload. Caller holds
// j.mu.
func (j *Job) applyOutcomeLocked(res ExportResult, err error) {
	switch {
	case err == nil:
		j.state = jobOK
		j.result = res
	case errors.Is(err, context.Canceled) || j.ctx.Err() != nil:
		j.state = jobCanceled
		j.errMsg = "collect canceled"
	default:
		j.state = jobError
		j.errMsg = err.Error()
	}
	j.finishedAt = time.Now()
	j.dl = nil
	j.broadcastLocked()
	close(j.done)
}

// cancel stops a job: a queued one finishes as canceled without ever running;
// a running one has its context canceled and finishes when the collect
// unwinds. Canceling a finished job reports errJobFinished.
func (m *jobManager) cancel(id int64) error {
	m.mu.Lock()
	j := m.byID[id]
	if j == nil {
		m.mu.Unlock()
		return errJobNotFound
	}
	j.mu.Lock()
	state := j.state
	j.mu.Unlock()
	if state.terminal() {
		m.mu.Unlock()
		return errJobFinished
	}
	if state == jobQueued {
		m.removeQueuedLocked(j)
	}
	m.mu.Unlock()
	j.cancel()
	if state == jobQueued {
		m.finishJob(j, ExportResult{}, context.Canceled)
	}
	return nil
}

// removeQueuedLocked takes j out of its stream's pending queue. Caller holds
// m.mu.
func (m *jobManager) removeQueuedLocked(j *Job) {
	queue := m.queues[j.Stream]
	for i, queued := range queue {
		if queued == j {
			m.queues[j.Stream] = append(queue[:i:i], queue[i+1:]...)
			return
		}
	}
}

// shutdown refuses new work, cancels every queued and running job, and waits
// (bounded) for the dispatchers to unwind. It is idempotent: LowServer.Close
// always calls it, and serveLow additionally triggers it on SIGINT/SIGTERM so
// buffered waiters unblock before the HTTP server drains.
func (m *jobManager) shutdown() {
	m.mu.Lock()
	first := !m.closed
	m.closed = true
	var queued, running []*Job
	if first {
		for stream, queue := range m.queues {
			queued = append(queued, queue...)
			delete(m.queues, stream)
		}
		for _, j := range m.running {
			running = append(running, j)
		}
	}
	m.mu.Unlock()
	for _, j := range queued {
		j.cancel()
		m.finishJob(j, ExportResult{}, context.Canceled)
	}
	for _, j := range running {
		j.cancel()
	}
	drained := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(jobShutdownWait):
	}
}

// get returns the job with this id, or nil.
func (m *jobManager) get(id int64) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byID[id]
}

// list snapshots every known job for the dashboard: running first (stream
// order), then queued in FIFO order with their positions, then finished jobs
// newest-first.
func (m *jobManager) list() []JobInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	infos := []JobInfo{}
	for _, stream := range knownStreams() {
		if j := m.running[stream]; j != nil {
			infos = append(infos, j.snapshotInfo(0))
		}
	}
	for _, stream := range knownStreams() {
		base := 0
		if m.running[stream] != nil {
			base = 1
		}
		for i, j := range m.queues[stream] {
			infos = append(infos, j.snapshotInfo(base+i))
		}
	}
	for i := len(m.history) - 1; i >= 0; i-- {
		infos = append(infos, m.history[i].snapshotInfo(0))
	}
	return infos
}

// broadcastLocked wakes every follower by closing the current update channel
// and arming a fresh one. Caller holds j.mu.
func (j *Job) broadcastLocked() {
	close(j.updated)
	j.updated = make(chan struct{})
}

// appendLog adds one progress line to the job's ring, evicting the oldest
// line once full. It is the job's progressSink and must never block.
func (j *Job) appendLog(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.log) < jobLogCap {
		j.log = append(j.log, line)
	} else {
		j.log[j.logHead] = line
		j.logHead = (j.logHead + 1) % jobLogCap
		j.logDropped++
	}
	j.broadcastLocked()
}

// setDL records the latest download sample. It is the job's downloadSink;
// samples are latest-only, so a fresh allocation gives followers a cheap
// change test (pointer identity).
func (j *Job) setDL(name string, done, total, bps int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.dl = &dlSnapshot{Name: name, Done: done, Total: total, BPS: bps}
	j.broadcastLocked()
}

// jobLogBatch is one follower catch-up: the log lines at and after the
// follower's cursor, the advanced cursor, and the state needed to decide
// whether (and how) the stream ends. updated is closed on the next change.
type jobLogBatch struct {
	lines   []string
	cursor  int
	dl      *dlSnapshot
	state   jobState
	result  ExportResult
	errMsg  string
	updated <-chan struct{}
}

// logSince returns everything a follower needs in one locked read, making
// replay-then-live free of gaps and duplicates. cursor counts lines from job
// start including evicted ones; a cursor older than the ring yields a
// "… not shown …" marker first.
func (j *Job) logSince(cursor int) jobLogBatch {
	j.mu.Lock()
	defer j.mu.Unlock()
	batch := jobLogBatch{
		dl:      j.dl,
		state:   j.state,
		result:  j.result,
		errMsg:  j.errMsg,
		updated: j.updated,
	}
	total := j.logDropped + len(j.log)
	if cursor < j.logDropped {
		batch.lines = append(batch.lines, fmt.Sprintf("… %d earlier line(s) not shown …", j.logDropped-cursor))
		cursor = j.logDropped
	}
	for ; cursor < total; cursor++ {
		idx := cursor - j.logDropped
		batch.lines = append(batch.lines, j.log[(j.logHead+idx)%jobLogCap])
	}
	batch.cursor = total
	return batch
}

// JobInfo is one job as reported by GET /admin/jobs.
type JobInfo struct {
	ID          int64       `json:"id"`
	Stream      string      `json:"stream"`
	Kind        string      `json:"kind"`
	WatchID     int64       `json:"watch_id,omitempty"`
	Label       string      `json:"label"`
	RequestedBy string      `json:"requested_by,omitempty"`
	State       string      `json:"state"`
	Position    int         `json:"position,omitempty"` // queued only: jobs ahead
	CreatedAt   time.Time   `json:"created_at"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	FinishedAt  *time.Time  `json:"finished_at,omitempty"`
	Message     string      `json:"message,omitempty"` // success summary
	Error       string      `json:"error,omitempty"`   // why the job failed
	BundleID    string      `json:"bundle_id,omitempty"`
	LastLog     string      `json:"last_log,omitempty"` // newest progress line
	DL          *dlSnapshot `json:"dl,omitempty"`
}

// snapshotInfo renders the job's current public view.
func (j *Job) snapshotInfo(position int) JobInfo {
	j.mu.Lock()
	defer j.mu.Unlock()
	info := JobInfo{
		ID:          j.ID,
		Stream:      j.Stream,
		Kind:        string(j.Kind),
		WatchID:     j.WatchID,
		Label:       j.Label,
		RequestedBy: j.RequestedBy,
		State:       string(j.state),
		CreatedAt:   j.createdAt,
		Error:       j.errMsg,
		BundleID:    j.result.BundleID,
		DL:          j.dl,
	}
	if j.state == jobQueued {
		info.Position = position
	}
	if !j.startedAt.IsZero() {
		t := j.startedAt
		info.StartedAt = &t
	}
	if !j.finishedAt.IsZero() {
		t := j.finishedAt
		info.FinishedAt = &t
	}
	if j.state == jobOK {
		info.Message = watchRunMessage(j.result)
	}
	if j.state == jobRunning && len(j.log) > 0 {
		last := len(j.log) - 1
		info.LastLog = j.log[(j.logHead+last)%jobLogCap]
	}
	return info
}

// manualCollectLabel derives a human label for a manual collect from its JSON
// body, best-effort: the first entries of whichever reference list the spec
// carries, or the kind of uploaded project file. It must never fail — an
// unparseable body just labels as the bare stream name.
func manualCollectLabel(stream string, body []byte) string {
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(body, &spec); err != nil || len(spec) == 0 {
		return stream
	}
	if label := labelFromLists(stream, spec); label != "" {
		return label
	}
	if label := labelFromProjectFile(stream, spec); label != "" {
		return label
	}
	return stream
}

// labelFromLists summarizes the first string-list field present in the spec.
func labelFromLists(stream string, spec map[string]json.RawMessage) string {
	for _, key := range []string{"modules", "requirements", "coordinates", "packages", "images", "models", "repos"} {
		raw, ok := spec[key]
		if !ok {
			continue
		}
		var items []string
		if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
			continue
		}
		label := stream + ": " + strings.Join(firstN(items, 3), ", ")
		if len(items) > 3 {
			label += fmt.Sprintf(" (+%d more)", len(items)-3)
		}
		return clipLabel(label)
	}
	return ""
}

// labelFromProjectFile names specs built from an uploaded project file or a
// pasted repository definition.
func labelFromProjectFile(stream string, spec map[string]json.RawMessage) string {
	for _, key := range []string{"go_mod", "package_json", "pom_xml"} {
		if _, ok := spec[key]; ok {
			return stream + ": uploaded project file"
		}
	}
	var text string
	if raw, ok := spec["source_list"]; ok { // APT deb822 stanza: name it by its URI
		_ = json.Unmarshal(raw, &text)
		for _, line := range strings.Split(text, "\n") {
			if uri, found := strings.CutPrefix(strings.TrimSpace(line), "URIs:"); found {
				return clipLabel(stream + ": " + strings.TrimSpace(uri))
			}
		}
		return stream + ": source stanza"
	}
	if raw, ok := spec["repo_file"]; ok { // RPM .repo stanza: name it by its section
		_ = json.Unmarshal(raw, &text)
		if start := strings.Index(text, "["); start >= 0 {
			if end := strings.Index(text[start:], "]"); end > 1 {
				return clipLabel(stream + ": " + text[start+1:start+end])
			}
		}
		return stream + ": repo stanza"
	}
	return ""
}

func firstN(items []string, n int) []string {
	if len(items) > n {
		return items[:n]
	}
	return items
}

// clipLabel keeps labels table-friendly.
func clipLabel(label string) string {
	const maxLabel = 80
	if len(label) <= maxLabel {
		return label
	}
	return label[:maxLabel-1] + "…"
}
