package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestHighServerImportInvalidatesPayloadTrees(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	docs := filepath.Join(hs.uploadsDir(), "docs")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(docs, "a.txt"), []byte("a"))
	srv := httptest.NewServer(hs)
	defer srv.Close()
	for _, eco := range []string{streamGo, streamPython} {
		if got := getTree(t, srv.URL, eco, ""); len(got) != 0 {
			t.Fatalf("initial %s tree = %+v, want empty", eco, got)
		}
	}
	if got := treeLabels(getTree(t, srv.URL, streamUploads, "docs")); got != "a.txt" {
		t.Fatalf("initial uploads tree = %q, want a.txt", got)
	}
	// Direct disk changes stay hidden in an unrelated ecosystem's warm cache.
	writeFile(t, filepath.Join(docs, "b.txt"), []byte("b"))

	// Legacy Python bundles use the Go sequencing stream. Invalidation must
	// follow their payload too, or a warmed Python tree misses the new wheel.
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 1, 0, map[string]string{
		"requests-2.32.4-py3-none-any.whl": "wheel-requests",
	})
	mustImportNext(t, hs)
	if got := treeLabels(getTree(t, srv.URL, streamPython, "")); got != "requests" {
		t.Errorf("Python tree after import = %q, want requests", got)
	}
	if got := treeLabels(getTree(t, srv.URL, streamUploads, "docs")); got != "a.txt" {
		t.Errorf("Python import refreshed unrelated uploads tree: %q", got)
	}

	writeSignedBundle(t, hs.cfg.Landing, priv, 2, 1, []moduleSpec{{"example.com/mod", "v1.0.0"}})
	mustImportNext(t, hs)
	if got := treeLabels(getTree(t, srv.URL, streamGo, "")); got != "example.com" {
		t.Errorf("Go tree after import = %q, want example.com", got)
	}
	if got := treeLabels(getTree(t, srv.URL, streamUploads, "docs")); got != "a.txt" {
		t.Errorf("Go import refreshed unrelated uploads tree: %q", got)
	}
}

func TestHighServerImportAdditionalFilesInvalidateTrees(t *testing.T) {
	for _, contentPart := range []bool{false, true} {
		name := "project records"
		if contentPart {
			name = "content part without records"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pub, priv := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			srv := httptest.NewServer(hs)
			defer srv.Close()
			for _, eco := range []string{streamPython, streamUploads} {
				if got := getTree(t, srv.URL, eco, ""); len(got) != 0 {
					t.Fatalf("initial %s tree = %+v, want empty", eco, got)
				}
			}
			stage := t.TempDir()
			packages := filepath.Join(stage, "python", "packages")
			if err := os.MkdirAll(packages, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(packages, "demo-1.0-py3-none-any.whl"), []byte("wheel-demo"))
			files, projects, _, err := collectPythonDist(packages)
			if err != nil {
				t.Fatal(err)
			}
			// Extra verified files are installed even without an Uploads record.
			const uploadPath = "uploads/docs/readme.txt"
			upload := filepath.Join(stage, filepath.FromSlash(uploadPath))
			if err := os.MkdirAll(filepath.Dir(upload), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, upload, []byte("readme"))
			uploadFile, err := hashManifestFile(upload, uploadPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest := BundleManifest{
				Type: manifestType, Format: manifestFormatCurrent, Stream: streamPython,
				Sequence: 1, BundleID: bundleIDFor(streamPython, 1),
				Created: time.Unix(0, 0).UTC(), Generator: "test",
				Files: append(files, uploadFile), Python: &PythonManifest{Projects: projects},
			}
			if contentPart {
				manifest.Python = nil
				manifest.Part = &BundlePartInfo{Index: 1, Count: 2}
			}
			signAndWriteBundle(t, hs.cfg.Landing, priv, manifest, stage)
			if result := mustImportNext(t, hs); !result.Imported {
				t.Fatalf("bundle was not imported: %+v", result)
			}
			if got := treeLabels(getTree(t, srv.URL, streamPython, "")); got != "demo" {
				t.Errorf("Python tree after import = %q, want demo", got)
			}
			if got := treeLabels(getTree(t, srv.URL, streamUploads, "docs")); got != "readme.txt" {
				t.Errorf("uploads tree after import = %q, want readme.txt", got)
			}
		})
	}
}

func TestBundleTreeStreamsGoRelocation(t *testing.T) {
	t.Parallel()
	file := ManifestFile{Path: "uploads/docs/readme.txt"}
	for _, tc := range []struct {
		name     string
		manifest BundleManifest
	}{
		{
			name: "module records",
			manifest: BundleManifest{
				Modules: []ManifestMod{{Files: map[string]ManifestFile{"info": file}}},
				Files:   []ManifestFile{file},
			},
		},
		{
			name: "content part without records",
			manifest: BundleManifest{
				Stream: streamGo, Part: &BundlePartInfo{Index: 1, Count: 2},
				Files: []ManifestFile{file},
			},
		},
		{
			name: "checksum database",
			manifest: BundleManifest{
				Stream: streamGo,
				Files:  []ManifestFile{{Path: "sumdb/sum.golang.org/latest"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bundleTreeStreams(tc.manifest); !slices.Equal(got, []string{streamGo}) {
				t.Errorf("affected trees = %v, want only Go after relocation", got)
			}
		})
	}
}

func TestHighServerImportStatusCachedSnapshot(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 3, 2)
	initial, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st := initial.Stream(streamGo); st.HighestSeenSequence != 3 || !slices.Equal(st.MissingRanges, []string{"1-2"}) || !slices.Equal(st.QuarantinedSequences, []int64{3}) {
		t.Fatalf("initial status = %+v", st)
	}
	// Mutating an explicitly refreshed result must not change the published
	// snapshot that all monitoring requests share.
	initial.Streams[0].MissingRanges[0] = "changed"
	initial.Streams[0].QuarantinedSequences[0] = 99
	initial.Streams[0].Stream = "changed"
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 4, 3)

	// Heartbeats arrive independently of imports and must be visible immediately,
	// even while the filesystem portion of status remains cached.
	now := time.Now().UTC()
	hb := testHeartbeat(map[string]int64{streamGo: 6, streamPython: 2})
	hs.heartbeat.recordHeartbeat(hb, now.Add(-2*time.Minute))
	cached, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	goStatus := cached.Stream(streamGo)
	if goStatus.HighestSeenSequence != 3 || !slices.Equal(goStatus.MissingRanges, []string{"1-2"}) || !slices.Equal(goStatus.QuarantinedSequences, []int64{3}) {
		t.Fatalf("cached status changed before an import refresh: %+v", goStatus)
	}
	if goStatus.LowLastSequence != 6 || !slices.Equal(goStatus.AwaitingFromLow, []string{"4-6"}) {
		t.Errorf("live heartbeat not applied to cached stream: %+v", goStatus)
	}
	if st := cached.Stream(streamPython); st.LowLastSequence != 2 || !slices.Equal(st.AwaitingFromLow, []string{"1-2"}) {
		t.Errorf("heartbeat-only stream missing: %+v", st)
	}
	if cached.DiodeHeartbeat == nil || cached.DiodeHeartbeat.AgeSeconds < 120 {
		t.Fatalf("heartbeat age = %+v, want at least two minutes", cached.DiodeHeartbeat)
	}
	cached.Streams[0].MissingRanges[0] = "changed again"
	cached.Streams[0].QuarantinedSequences[0] = 100
	cached.Streams[0].AwaitingFromLow[0] = "changed"
	cached.DiodeHeartbeat.LowVersion = "changed"
	again, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	if st := again.Stream(streamGo); !slices.Equal(st.MissingRanges, []string{"1-2"}) || !slices.Equal(st.QuarantinedSequences, []int64{3}) || !slices.Equal(st.AwaitingFromLow, []string{"4-6"}) {
		t.Errorf("monitoring caller mutated the shared snapshot: %+v", st)
	}
	if again.DiodeHeartbeat.LowVersion != hb.Generator {
		t.Errorf("monitoring caller mutated heartbeat: %+v", again.DiodeHeartbeat)
	}
	refreshed, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st := refreshed.Stream(streamGo); st.HighestSeenSequence != 4 || !slices.Equal(st.QuarantinedSequences, []int64{3, 4}) {
		t.Errorf("explicit refresh did not publish new backlog: %+v", st)
	}
}

func TestHighServerImportStatusSnapshotAfterRestart(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)
	mustImportNext(t, hs)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 3, 2)
	restarted, err := NewHighServer(hs.cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	st := status.Stream(streamGo)
	if st.LastImportedSequence != 1 || st.NextExpectedSequence != 2 || st.HighestSeenSequence != 3 || st.BlockingMissing != 2 {
		t.Errorf("startup status = %+v, want imported 1 and missing 2 before 3", st)
	}
	if !bundleCompleteInDir(hs.cfg.Landing, bundleIDFor(streamGo, 3)) {
		t.Error("seeding startup status moved a landing bundle")
	}
}

func TestHighServerImportNextRoundRobin(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	var want []string
	for seq := int64(1); seq <= 3; seq++ {
		for _, stream := range []string{streamGo, streamPython} {
			writeSignedStreamBundle(t, hs.cfg.Landing, priv, stream, seq, seq-1)
			want = append(want, bundleIDFor(stream, seq))
		}
	}
	result := mustImportNext(t, hs)
	if !slices.Equal(result.ImportedBundles, want) {
		t.Errorf("import order = %v, want bounded stream turns %v", result.ImportedBundles, want)
	}
	status, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []string{streamGo, streamPython} {
		if st := status.Stream(stream); st.LastImportedSequence != 3 || st.ReadyToImport {
			t.Errorf("completed pass status for %s = %+v", stream, st)
		}
	}
}

func TestHighServerImportNextDefersNewArrivals(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)
	hs.tree.mu.Lock()
	var workers sync.WaitGroup
	unlock := sync.OnceFunc(hs.tree.mu.Unlock)
	defer func() {
		unlock()
		workers.Wait()
	}()
	var result ImportResult
	var importErr error
	workers.Go(func() {
		result, importErr = hs.ImportNext()
	})
	waitForImportedState(t, hs, streamGo, 1)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)
	unlock()
	workers.Wait()
	if importErr != nil {
		t.Fatal(importErr)
	}
	if !slices.Equal(result.ImportedBundles, []string{bundleIDFor(streamGo, 1)}) {
		t.Fatalf("pass imported newly arrived backlog: %v", result.ImportedBundles)
	}
	status, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	if st := status.Stream(streamGo); st.LastImportedSequence != 1 || st.HighestSeenSequence != 2 || !st.ReadyToImport {
		t.Errorf("new arrival absent from published status: %+v", st)
	}
	result = mustImportNext(t, hs)
	if !slices.Equal(result.ImportedBundles, []string{bundleIDFor(streamGo, 2)}) {
		t.Errorf("next pass imported %v, want newly arrived bundle 2", result.ImportedBundles)
	}
}

func TestHighServerImportNextContinuesBoundedBacklog(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	const last = int64(maxImportRoundsPerPass + 1)
	for seq := int64(1); seq <= last; seq++ {
		writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, seq, seq-1)
	}
	hs.tree.mu.Lock()
	var workers sync.WaitGroup
	unlock := sync.OnceFunc(hs.tree.mu.Unlock)
	defer func() {
		unlock()
		workers.Wait()
		// Once the final pass releases importMu, no further continuation can
		// be scheduled. Closing the kick channel lets its idle worker exit.
		hs.importMu.Lock()
		close(hs.importKick)
		hs.importMu.Unlock()
	}()
	var result ImportResult
	var importErr error
	workers.Go(func() {
		result, importErr = hs.ImportNext()
	})
	waitForImportedState(t, hs, streamGo, 1)
	// This stream was absent from the initial snapshot. A bounded pass must
	// yield and rediscover it without waiting for a background timer or upload.
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamPython, 1, 0)
	unlock()
	workers.Wait()
	if importErr != nil {
		t.Fatal(importErr)
	}
	if len(result.ImportedBundles) != maxImportRoundsPerPass {
		t.Errorf("first pass imported %d bundles, want limit %d", len(result.ImportedBundles), maxImportRoundsPerPass)
	}
	waitForImportedState(t, hs, streamGo, last)
	waitForImportedState(t, hs, streamPython, 1)
	hs.importMu.Lock()
	hs.importMu.Unlock()
	status, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	if st := status.Stream(streamGo); st.LastImportedSequence != last || st.ReadyToImport {
		t.Errorf("continued Go status = %+v", st)
	}
	if st := status.Stream(streamPython); st.LastImportedSequence != 1 || st.ReadyToImport {
		t.Errorf("new stream was not drained by continuation: %+v", st)
	}
}

func TestHighServerImportStatusClearsFilledGapDuringPass(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 3, 2)
	hs.tree.mu.Lock()
	var workers sync.WaitGroup
	unlockTree := sync.OnceFunc(hs.tree.mu.Unlock)
	defer func() {
		unlockTree()
		workers.Wait()
	}()
	var importErr error
	workers.Go(func() {
		_, importErr = hs.ImportNext()
	})
	waitForImportedState(t, hs, streamGo, 1)
	before, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	if st := before.Stream(streamGo); !slices.Equal(st.MissingRanges, []string{"2"}) {
		t.Fatalf("initial missing ranges = %v, want [2]", st.MissingRanges)
	}

	// Pause the next commit's metrics update after it publishes status. This
	// lets us inspect progress before the final pass refresh hides stale gaps.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		hs.metrics.mu.Lock()
		if hs.metrics.imported[streamGo] == 1 {
			break
		}
		hs.metrics.mu.Unlock()
		select {
		case <-deadline.C:
			t.Fatal("first import did not finish recording its metrics")
		case <-tick.C:
		}
	}
	unlockMetrics := sync.OnceFunc(hs.metrics.mu.Unlock)
	defer unlockMetrics()
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)
	unlockTree()
	waitForImportedState(t, hs, streamGo, 2)
	for {
		status, err := hs.importStatusReadOnly()
		if err != nil {
			t.Fatal(err)
		}
		if st := status.Stream(streamGo); st.LastImportedSequence == 2 {
			if len(st.MissingRanges) != 0 || st.BlockingMissing != 0 || !st.ReadyToImport {
				t.Errorf("filled gap still appears in published progress: %+v", st)
			}
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("import did not publish its progress during the pass")
		case <-tick.C:
		}
	}
	if st := before.Stream(streamGo); !slices.Equal(st.MissingRanges, []string{"2"}) {
		t.Errorf("publishing progress mutated an older snapshot: %+v", st)
	}
	unlockMetrics()
	workers.Wait()
	if importErr != nil {
		t.Fatal(importErr)
	}
}

func TestHighServerMonitoringDuringImport(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)
	if _, err := hs.ImportStatus(); err != nil {
		t.Fatal(err)
	}

	// Hold the importer at the dashboard-cache invalidation after it has
	// installed a real bundle and durably committed its sequence. This keeps
	// filesystem work in flight without relying on a large/slow test fixture.
	hs.tree.mu.Lock()
	var workers sync.WaitGroup
	var importErr error
	defer func() {
		hs.tree.mu.Unlock()
		workers.Wait()
		if importErr != nil {
			t.Errorf("ImportNext: %v", importErr)
		}
	}()
	workers.Go(func() {
		_, importErr = hs.ImportNext()
	})
	waitForImportedState(t, hs, streamGo, 1)

	type response struct {
		path string
		code int
		body string
	}
	paths := []string{"/readyz", "/metrics", "/admin/status", "/admin/missing", "/ui/api/overview"}
	responses := make(chan response, len(paths))
	for _, path := range paths {
		workers.Go(func() {
			w := httptest.NewRecorder()
			hs.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			responses <- response{path: path, code: w.Code, body: w.Body.String()}
		})
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for range paths {
		select {
		case got := <-responses:
			if got.code != http.StatusOK {
				t.Errorf("%s during import = %d: %s", got.path, got.code, got.body)
			}
		case <-deadline.C:
			t.Fatal("monitoring did not respond while an import was blocked")
		}
	}
}

func TestHighServerConcurrentImportNext(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	const bundleCount = 3
	for seq := int64(1); seq <= bundleCount; seq++ {
		writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, seq, seq-1)
	}
	hs.tree.mu.Lock()
	var workers sync.WaitGroup
	unlock := sync.OnceFunc(hs.tree.mu.Unlock)
	defer func() {
		unlock()
		workers.Wait()
	}()
	type completion struct {
		result ImportResult
		err    error
	}
	const callers = 5
	results := make(chan completion, callers)
	runImport := func() {
		result, err := hs.ImportNext()
		results <- completion{result: result, err: err}
	}
	workers.Go(runImport)
	waitForImportedState(t, hs, streamGo, 1)
	for range callers - 1 {
		workers.Go(runImport)
	}
	unlock()
	workers.Wait()
	imported := make(map[string]int)
	for range callers {
		got := <-results
		if got.err != nil {
			t.Errorf("concurrent ImportNext: %v", got.err)
		}
		for _, id := range got.result.ImportedBundles {
			imported[id]++
		}
		if len(got.result.RejectedBundles) != 0 {
			t.Errorf("concurrent import rejected valid bundles: %v", got.result.RejectedBundles)
		}
	}
	for seq := int64(1); seq <= bundleCount; seq++ {
		id := bundleIDFor(streamGo, seq)
		if imported[id] != 1 {
			t.Errorf("bundle %s imported %d times, want once", id, imported[id])
		}
	}
	status, err := hs.importStatusReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	if st := status.Stream(streamGo); st.LastImportedSequence != bundleCount || st.ReadyToImport {
		t.Errorf("final status after concurrent imports = %+v", st)
	}
}

func waitForImportedState(t *testing.T, hs *HighServer, stream string, sequence int64) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		b, err := os.ReadFile(hs.statePath)
		if err == nil {
			var state HighState
			if err := json.Unmarshal(b, &state); err != nil {
				t.Fatal(err)
			}
			if state.Imported[stream] == sequence {
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("import did not commit %s sequence %d", stream, sequence)
		case <-tick.C:
		}
	}
}
