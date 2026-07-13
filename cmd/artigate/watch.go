package main

// Scheduled "watches": recurring collects configured from the low-side UI and
// persisted in SQLite. A watch re-runs a stored collect spec for one ecosystem
// stream on a fixed interval, so e.g. Python "requests" can be pulled every hour
// or every day without an operator triggering it each time.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// minWatchInterval is the floor for a schedule's interval. The UI only offers
// hours and days; this guards the API against hammering upstreams.
const minWatchInterval = time.Minute

// watchTimeLayout is how schedule timestamps are stored: RFC3339 in UTC, which
// is fixed-width and therefore also sorts/compares correctly as text in SQL.
const watchTimeLayout = time.RFC3339

// Watch is a scheduled, recurring collect.
type Watch struct {
	ID              int64      `json:"id"`
	Stream          string     `json:"stream"`
	Label           string     `json:"label"`
	Spec            string     `json:"spec"` // JSON collect payload for the stream
	IntervalSeconds int64      `json:"interval_seconds"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	LastStatus      string     `json:"last_status,omitempty"`
	LastMessage     string     `json:"last_message,omitempty"`
	NextRunAt       time.Time  `json:"next_run_at"`
}

// WatchStore persists watches in a SQLite database.
type WatchStore struct {
	db *sql.DB
}

const watchSchema = `CREATE TABLE IF NOT EXISTS watches (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  stream           TEXT    NOT NULL,
  label            TEXT    NOT NULL,
  spec             TEXT    NOT NULL,
  interval_seconds INTEGER NOT NULL,
  enabled          INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT    NOT NULL,
  last_run_at      TEXT,
  last_status      TEXT    NOT NULL DEFAULT '',
  last_message     TEXT    NOT NULL DEFAULT '',
  next_run_at      TEXT    NOT NULL
)`

const watchCols = "id, stream, label, spec, interval_seconds, enabled, created_at, last_run_at, last_status, last_message, next_run_at"

// OpenWatchStore opens (creating if needed) the watch database at path.
func OpenWatchStore(path string) (*WatchStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open watch db: %w", err)
	}
	// SQLite has a single writer; serialize all access so the scheduler and the
	// UI never collide on "database is locked", waiting briefly if contended.
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{"PRAGMA busy_timeout=5000", watchSchema} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init watch db: %w", err)
		}
	}
	return &WatchStore{db: db}, nil
}

// Close releases the database. It is safe to call on a nil store.
func (s *WatchStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type rowScanner interface{ Scan(dest ...any) error }

func scanWatch(sc rowScanner) (Watch, error) {
	var (
		w         Watch
		enabled   int
		createdAt string
		lastRunAt sql.NullString
		nextRunAt string
	)
	if err := sc.Scan(&w.ID, &w.Stream, &w.Label, &w.Spec, &w.IntervalSeconds, &enabled,
		&createdAt, &lastRunAt, &w.LastStatus, &w.LastMessage, &nextRunAt); err != nil {
		return Watch{}, err
	}
	w.Enabled = enabled != 0
	w.CreatedAt, _ = time.Parse(watchTimeLayout, createdAt)
	w.NextRunAt, _ = time.Parse(watchTimeLayout, nextRunAt)
	if lastRunAt.Valid && lastRunAt.String != "" {
		if t, err := time.Parse(watchTimeLayout, lastRunAt.String); err == nil {
			w.LastRunAt = &t
		}
	}
	return w, nil
}

// Create inserts a watch (enabled, due on the next scheduler tick) and returns
// it with its assigned ID.
func (s *WatchStore) Create(w Watch) (Watch, error) {
	now := time.Now().UTC()
	w.CreatedAt = now
	if w.NextRunAt.IsZero() {
		w.NextRunAt = now
	}
	res, err := s.db.Exec(
		`INSERT INTO watches (stream, label, spec, interval_seconds, enabled, created_at, next_run_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		w.Stream, w.Label, w.Spec, w.IntervalSeconds, boolToInt(w.Enabled),
		now.Format(watchTimeLayout), w.NextRunAt.UTC().Format(watchTimeLayout))
	if err != nil {
		return Watch{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Watch{}, err
	}
	w.ID = id
	return w, nil
}

// List returns all watches ordered by ID.
func (s *WatchStore) List() ([]Watch, error) {
	rows, err := s.db.Query("SELECT " + watchCols + " FROM watches ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	watches := []Watch{}
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			return nil, err
		}
		watches = append(watches, w)
	}
	return watches, rows.Err()
}

// Get returns one watch by ID.
func (s *WatchStore) Get(id int64) (Watch, error) {
	return scanWatch(s.db.QueryRow("SELECT "+watchCols+" FROM watches WHERE id = ?", id))
}

// Delete removes a watch.
func (s *WatchStore) Delete(id int64) error {
	_, err := s.db.Exec("DELETE FROM watches WHERE id = ?", id)
	return err
}

// SetEnabled enables or disables a watch. Re-enabling makes it due promptly.
func (s *WatchStore) SetEnabled(id int64, enabled bool) error {
	if enabled {
		_, err := s.db.Exec("UPDATE watches SET enabled = 1, next_run_at = ? WHERE id = ?",
			time.Now().UTC().Format(watchTimeLayout), id)
		return err
	}
	_, err := s.db.Exec("UPDATE watches SET enabled = 0 WHERE id = ?", id)
	return err
}

// Update stores a watch's edited label, spec, and interval, and returns the
// updated row. A watch that has run before gets its next run re-spaced from
// that last run at the new interval — shortening the interval pulls the next
// run forward (possibly making it due immediately), lengthening pushes it out.
// A never-run watch keeps its existing next_run_at, which is already due.
func (s *WatchStore) Update(w Watch) (Watch, error) {
	next := w.NextRunAt
	if w.LastRunAt != nil {
		next = w.LastRunAt.Add(time.Duration(w.IntervalSeconds) * time.Second)
	}
	if _, err := s.db.Exec(
		"UPDATE watches SET label = ?, spec = ?, interval_seconds = ?, next_run_at = ? WHERE id = ?",
		w.Label, w.Spec, w.IntervalSeconds, next.UTC().Format(watchTimeLayout), w.ID); err != nil {
		return Watch{}, err
	}
	return s.Get(w.ID)
}

// Due returns the enabled watches whose next run time has arrived.
func (s *WatchStore) Due(now time.Time) ([]Watch, error) {
	rows, err := s.db.Query("SELECT "+watchCols+" FROM watches WHERE enabled = 1 AND next_run_at <= ? ORDER BY id",
		now.UTC().Format(watchTimeLayout))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var due []Watch
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			return nil, err
		}
		due = append(due, w)
	}
	return due, rows.Err()
}

// RecordRun stores the outcome of a run and schedules the next one, one
// interval after ranAt. The interval is read from the row inside the UPDATE —
// not captured by the caller when the run was enqueued — so an interval
// edited while the run was queued or in flight spaces the next run; the
// strftime renders watchTimeLayout (RFC3339 UTC).
func (s *WatchStore) RecordRun(id int64, ranAt time.Time, status, message string) error {
	at := ranAt.UTC().Format(watchTimeLayout)
	_, err := s.db.Exec(
		`UPDATE watches SET last_run_at = ?, last_status = ?, last_message = ?,
		 next_run_at = strftime('%Y-%m-%dT%H:%M:%SZ', ?, '+' || interval_seconds || ' seconds')
		 WHERE id = ?`,
		at, status, message, at, id)
	return err
}

// validateWatch checks a watch's stream, interval, and spec before it is stored.
func validateWatch(w Watch) error {
	if !isKnownStream(w.Stream) {
		return fmt.Errorf("unknown stream %q", w.Stream)
	}
	// An upload has no upstream to re-pull — the file bytes arrive with the
	// request — so scheduling one can never do anything useful.
	if w.Stream == streamUploads {
		return errors.New("uploads cannot be scheduled; upload again when the content changes")
	}
	if time.Duration(w.IntervalSeconds)*time.Second < minWatchInterval {
		return fmt.Errorf("interval must be at least %s", minWatchInterval)
	}
	if strings.TrimSpace(w.Spec) == "" {
		return errors.New("empty watch spec")
	}
	if !json.Valid([]byte(w.Spec)) {
		return errors.New("watch spec must be valid JSON")
	}
	return nil
}

func isKnownStream(stream string) bool {
	for _, k := range knownStreams() {
		if k == stream {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Scheduler
// -----------------------------------------------------------------------------

// watchLoop runs due watches on a fixed tick until ctx is cancelled.
func (s *LowServer) watchLoop(ctx context.Context) {
	t := time.NewTicker(s.watchTick)
	defer t.Stop()
	log.Printf("watch scheduler: checking schedules every %s", s.watchTick)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runDueWatches()
		}
	}
}

// runDueWatches enqueues every enabled watch whose time has come on its
// stream's job queue. The scheduler never blocks on a collect: due watches on
// different streams run concurrently (each stream still runs one job at a
// time), and a watch whose previous run is still queued or running is left
// alone until it finishes.
func (s *LowServer) runDueWatches() {
	due, err := s.watches.Due(time.Now().UTC())
	if err != nil {
		log.Printf("watch scheduler: %v", err)
		return
	}
	for _, w := range due {
		if _, err := s.enqueueWatch(w); err != nil && !errors.Is(err, errWatchJobExists) {
			// A full queue or a shutdown: the watch stays due, so the skipped
			// run is retried on a later tick rather than lost.
			log.Printf("watch %d (%s): not queued: %v", w.ID, w.Label, err)
		}
	}
}

// enqueueWatch queues one run of w and returns the job's id. It returns
// errWatchJobExists when a job for this watch is already queued or running (a
// due tick overlapping a run-now, or a slow collect still going when the next
// interval arrived), and the queue's other refusals (errJobQueueFull,
// errJobsClosed) verbatim so callers can tell a deduplicated run from a
// dropped one. The outcome is recorded from the job's completion hook; a
// watch deleted while its job is queued still runs, and its RecordRun then
// updates zero rows — harmless.
func (s *LowServer) enqueueWatch(w Watch) (int64, error) {
	j := &Job{
		Stream:      w.Stream,
		Kind:        jobKindWatch,
		WatchID:     w.ID,
		Label:       w.Label,
		RequestedBy: "schedule",
		run: func(ctx context.Context) (ExportResult, error) {
			return s.runWatchCollect(ctx, w.Stream, w.Spec)
		},
		afterRun: func(res ExportResult, err error) { s.recordWatchOutcome(w, res, err) },
	}
	if _, err := s.jobs.enqueue(context.Background(), j); err != nil {
		return 0, err
	}
	return j.ID, nil
}

// executeWatch runs one watch's collect closure and records the outcome. The
// collect is passed in rather than called directly so the record path can be
// driven in tests with a failing or panic-recovering collect and no real
// upstream.
func (s *LowServer) executeWatch(w Watch, collect func() (ExportResult, error)) {
	res, err := collect()
	s.recordWatchOutcome(w, res, err)
}

// recordWatchOutcome stores a run's status and message and schedules the next
// run one interval after completion. Any error — including a canceled or
// panicked collect (the job worker's recoverCollectPanic turns panics into
// errors) — is recorded as a failed run, which advances next_run_at and so
// cannot wedge the schedule into a tight retry. The spacing comes from the
// watch's stored interval at record time, not from the stale w captured when
// the run was enqueued, so an interval edited mid-run is honored (w only
// labels the log lines here).
func (s *LowServer) recordWatchOutcome(w Watch, res ExportResult, err error) {
	status, message := "ok", watchRunMessage(res)
	if err != nil {
		status, message = "error", err.Error()
		log.Printf("watch %d (%s) failed: %v", w.ID, w.Label, err)
	} else {
		log.Printf("watch %d (%s): %s", w.ID, w.Label, message)
	}
	if rerr := s.watches.RecordRun(w.ID, time.Now().UTC(), status, message); rerr != nil {
		log.Printf("watch %d: record run: %v", w.ID, rerr)
	}
}

// recoverCollectPanic runs fn and turns any panic into an error so a collector
// bug cannot crash the scheduler goroutine. Kept as a standalone function (not a
// closure inline in runWatchCollectSafely) so the recovery is unit-testable with
// a deliberately panicking fn.
func recoverCollectPanic(stream string, fn func() (ExportResult, error)) (res ExportResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collect panicked: %v", r)
			log.Printf("watch collect panic recovered (stream %s): %v\n%s", stream, r, debug.Stack())
		}
	}()
	return fn()
}

func watchRunMessage(res ExportResult) string {
	if res.Skipped {
		return "no new content since last export; skipped"
	}
	if res.BundleID == "" {
		return "no bundle produced"
	}
	msg := fmt.Sprintf("bundle %s: %d unit(s)", res.BundleID, res.ExportedModules)
	if n := len(res.Bundles); n > 1 {
		msg = fmt.Sprintf("%d bundles (%s … %s): %d unit(s)", n, res.Bundles[0], res.BundleID, res.ExportedModules)
	}
	if res.PriorFiles > 0 {
		msg += fmt.Sprintf(", %d file(s) already forwarded", res.PriorFiles)
	}
	if n := len(res.SkippedModules); n > 0 {
		msg += fmt.Sprintf(", %d skipped", n)
	}
	if res.DiodeError != "" {
		msg += "; diode upload failed: " + res.DiodeError
	}
	return msg
}

// runWatchCollect dispatches a stored watch spec to the matching collector.
func (s *LowServer) runWatchCollect(ctx context.Context, stream, spec string) (ExportResult, error) {
	b := []byte(spec)
	switch stream {
	case streamGo:
		return decodeAndCollect(ctx, b, s.CollectGo)
	case streamPython:
		return decodeAndCollect(ctx, b, s.CollectPython)
	case streamMaven:
		return decodeAndCollect(ctx, b, s.CollectMaven)
	case streamApt:
		return decodeAndCollect(ctx, b, s.CollectApt)
	case streamRpm:
		return decodeAndCollect(ctx, b, s.CollectRpm)
	case streamContainers:
		return decodeAndCollect(ctx, b, s.CollectContainers)
	case streamNpm:
		return decodeAndCollect(ctx, b, s.CollectNpm)
	case streamHF:
		return decodeAndCollect(ctx, b, s.CollectHF)
	case streamCrates:
		return decodeAndCollect(ctx, b, s.CollectCrates)
	case streamTerraform:
		return decodeAndCollect(ctx, b, s.CollectTerraform)
	case streamHelm:
		return decodeAndCollect(ctx, b, s.CollectHelm)
	case streamNuget:
		return decodeAndCollect(ctx, b, s.CollectNuget)
	case streamApk:
		return decodeAndCollect(ctx, b, s.CollectApk)
	default:
		return ExportResult{}, fmt.Errorf("unknown stream %q", stream)
	}
}

// decodeAndCollect unmarshals a watch spec into the collector's request type and
// runs it. The request type is inferred from the collector function.
func decodeAndCollect[T any](ctx context.Context, spec []byte, collect func(context.Context, T) (ExportResult, error)) (ExportResult, error) {
	var req T
	if err := json.Unmarshal(spec, &req); err != nil {
		return ExportResult{}, fmt.Errorf("parse watch spec: %w", err)
	}
	return collect(ctx, req)
}

// -----------------------------------------------------------------------------
// HTTP endpoints
// -----------------------------------------------------------------------------

// WatchListResponse is the body of GET /admin/watches.
type WatchListResponse struct {
	Watches []Watch `json:"watches"`
}

type createWatchRequest struct {
	Stream          string          `json:"stream"`
	Label           string          `json:"label"`
	Spec            json.RawMessage `json:"spec"`
	IntervalSeconds int64           `json:"interval_seconds"`
}

// updateWatchRequest is the body of POST /admin/watches/update. The stream is
// fixed at creation and cannot be changed; a blank/zero field keeps the
// watch's current value, so a partial edit can never wipe the spec or label.
type updateWatchRequest struct {
	ID              int64           `json:"id"`
	Label           string          `json:"label"`
	Spec            json.RawMessage `json:"spec"`
	IntervalSeconds int64           `json:"interval_seconds"`
}

type watchIDRequest struct {
	ID int64 `json:"id"`
}

// serveLowWatches handles the /admin/watches* endpoints. It reports whether it
// handled the request.
func (s *LowServer) serveLowWatches(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/admin/watches":
		switch {
		case isReadMethod(r):
			list, err := s.watches.List()
			return respondJSONOrError(w, http.StatusInternalServerError, WatchListResponse{Watches: list}, err)
		case r.Method == http.MethodPost:
			return s.handleCreateWatch(w, r)
		}
		return false
	case "/admin/watches/update":
		return s.handleUpdateWatch(w, r)
	case "/admin/watches/delete":
		return s.watchAction(w, r, s.watches.Delete)
	case "/admin/watches/enable":
		return s.watchAction(w, r, func(id int64) error { return s.watches.SetEnabled(id, true) })
	case "/admin/watches/disable":
		return s.watchAction(w, r, func(id int64) error { return s.watches.SetEnabled(id, false) })
	case "/admin/watches/run":
		return s.handleRunWatch(w, r)
	default:
		return false
	}
}

func (s *LowServer) handleCreateWatch(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	var req createWatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse watch request: %v", err), http.StatusBadRequest)
		return true
	}
	watch := Watch{
		Stream:          strings.TrimSpace(req.Stream),
		Label:           strings.TrimSpace(req.Label),
		Spec:            strings.TrimSpace(string(req.Spec)),
		IntervalSeconds: req.IntervalSeconds,
		Enabled:         true,
	}
	if watch.Label == "" {
		watch.Label = watch.Stream
	}
	if err := validateWatch(watch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	created, err := s.watches.Create(watch)
	return respondJSONOrError(w, http.StatusInternalServerError, created, err)
}

// handleUpdateWatch edits an existing watch's label, spec, and interval in
// place, keeping its id, stream, enabled state, and run history. A job already
// queued or running for the watch still collects with the spec it was enqueued
// with — the new spec applies from the next run — but when that run completes
// it is re-scheduled at the edited interval (RecordRun reads the stored
// interval), so switching a daily watch to hourly mid-run schedules the next
// run an hour after this one finishes, not a day.
func (s *LowServer) handleUpdateWatch(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	var req updateWatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse watch request: %v", err), http.StatusBadRequest)
		return true
	}
	if req.ID <= 0 {
		http.Error(w, "missing watch id", http.StatusBadRequest)
		return true
	}
	watch, err := s.watches.Get(req.ID)
	if err != nil {
		http.Error(w, "watch not found", http.StatusNotFound)
		return true
	}
	applyWatchUpdate(&watch, req)
	if err := validateWatch(watch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	updated, err := s.watches.Update(watch)
	return respondJSONOrError(w, http.StatusInternalServerError, updated, err)
}

// applyWatchUpdate merges an edit's fields into the stored watch. Blank/zero
// fields (and a JSON null spec) keep their current value; the merged result
// still goes through validateWatch before being stored.
func applyWatchUpdate(w *Watch, req updateWatchRequest) {
	if label := strings.TrimSpace(req.Label); label != "" {
		w.Label = label
	}
	if spec := strings.TrimSpace(string(req.Spec)); spec != "" && spec != "null" {
		w.Spec = spec
	}
	if req.IntervalSeconds != 0 {
		w.IntervalSeconds = req.IntervalSeconds
	}
}

func (s *LowServer) watchAction(w http.ResponseWriter, r *http.Request, action func(int64) error) bool {
	if r.Method != http.MethodPost {
		return false
	}
	id, err := watchIDFromBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	if err := action(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	writeJSON(w, map[string]string{"status": "ok"})
	return true
}

func (s *LowServer) handleRunWatch(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	id, err := watchIDFromBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	watch, err := s.watches.Get(id)
	if err != nil {
		http.Error(w, "watch not found", http.StatusNotFound)
		return true
	}
	// Queue the run: a collect can take minutes, far longer than the request.
	// job_id 0 means a job for this watch is already queued or running (the
	// queue's dedup prevents it colliding with the scheduler) — the requested
	// work is pending either way. Any other refusal (queue full, shutdown)
	// means the run was dropped, which must reach the operator as an error,
	// not a silent success.
	jobID, err := s.enqueueWatch(watch)
	if err != nil && !errors.Is(err, errWatchJobExists) {
		http.Error(w, err.Error(), jobEnqueueStatus(err))
		return true
	}
	writeJSON(w, map[string]any{"status": "started", "job_id": jobID})
	return true
}

func watchIDFromBody(r *http.Request) (int64, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return 0, err
	}
	var req watchIDRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("parse request: %w", err)
	}
	if req.ID <= 0 {
		return 0, errors.New("missing watch id")
	}
	return req.ID, nil
}
