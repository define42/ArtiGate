package main

import (
	"context"
	"encoding/json"
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

	// Recording a run pushes the next run into the future, so it is no longer due.
	if err := store.RecordRun(w.ID, time.Now().UTC(), "ok", "bundle python-bundle-000001: 1 unit(s)",
		time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertDueCount(t, store, time.Now().UTC(), 0)
	if got, _ := store.Get(w.ID); got.LastStatus != "ok" || got.LastRunAt == nil {
		t.Fatalf("run not recorded: %+v", got)
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

	ls.runDueWatches(context.Background())

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
}
