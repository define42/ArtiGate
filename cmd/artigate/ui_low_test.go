package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLowServerUIStatus(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	if _, err := ls.CollectGo(context.Background(), GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(ls)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/ui/api/status")
	if code != http.StatusOK {
		t.Fatalf("status endpoint = %d", code)
	}
	var st LowBundleStatus
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	goStream := st.Stream(streamGo)
	if len(goStream.ExportedSequences) != 1 || goStream.ExportedSequences[0].Sequence != 1 {
		t.Fatalf("go exported sequences = %+v", goStream.ExportedSequences)
	}
	seq0 := goStream.ExportedSequences[0]
	if !seq0.InArchive || !seq0.InOutbound {
		t.Errorf("a fresh bundle should be both archived and staged, got %+v", seq0)
	}
	if seq0.SizeBytes <= 0 {
		t.Errorf("exported bundle should report a nonzero size, got %d", seq0.SizeBytes)
	}

	// Simulate forwarding across the diode: the transfer moves the bundle files
	// out of the export dir. The bundle stays listed (still archived) but flips
	// to "sent" (no longer outbound) rather than dropping off or erroring.
	for _, suffix := range bundleSuffixes() {
		if err := os.Remove(filepath.Join(ls.cfg.ExportDir, seq0.BundleID+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	after := ls.BundleStatus().Stream(streamGo)
	if len(after.ExportedSequences) != 1 {
		t.Fatalf("bundle should still be listed from the archive after forwarding, got %+v", after.ExportedSequences)
	}
	if fwd := after.ExportedSequences[0]; !fwd.InArchive || fwd.InOutbound {
		t.Errorf("after forwarding: want archived & not outbound, got %+v", fwd)
	}
}

func TestLowServerUIPage(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/")
	if code != http.StatusOK {
		t.Fatalf("index status = %d", code)
	}
	for _, want := range []string{
		"<title>ArtiGate low-side</title>",
		"/admin/reexport", "Re-transmit bundles", "/ui/api/status",
		// Export-status table shows each bundle's size.
		"formatBytes", "size_bytes", `<th class="num">Size</th>`,
		// Top menu splits each ecosystem onto its own view/page.
		"function setView(", `data-view="overview"`, `data-view="go"`, `data-view="maven"`, `data-view="status"`,
		`id="view-overview"`, `id="view-go"`, `id="view-maven"`, `id="view-status"`,
		// Overview page lists every schedule and whether it is working.
		`id="allWatches"`, "loadAllWatches",
		// The Jobs card shows every queued/running/finished collect across all
		// sessions, polled live, with follow and cancel controls.
		`id="jobsBox"`, "loadJobs", "pollJobs", "function jobRow", "/admin/jobs",
		"/admin/jobs/follow", "/admin/jobs/cancel", "cancelJob(", "viewJobById",
		"ev.type==='job'", "Closing this window does not stop the job",
		// Scheduling lives on each ecosystem page, reusing that page's inputs.
		"/admin/watches", "loadWatchesInto", "Add schedule",
		"scheduleGo()", `id="goEvery"`, `id="goWatches"`,
		"schedulePython()", "scheduleApt()", "scheduleRpm()", "scheduleMaven()",
		"Mirror Go modules", `id="gomods"`, `id="gomod"`, `id="gosum"`, "collectGoMod", "/admin/go/collect",

		"Mirror Python packages", `id="pyreqs"`, "collectPython", "/admin/python/collect",
		"source distributions are never downloaded", "Wheels-only mode is always enforced",
		"Mirror Maven artifacts", `id="mvncoords"`, `id="mvnpom"`, "collectMaven", "/admin/maven/collect",
		"Mirror an APT (deb) repository", `id="aptsrc"`, `id="aptfile"`, "loadAptFile", "collectApt", "/admin/apt/collect",
		`id="aptnewest" type="checkbox" checked`, "newest_only",
		"Mirror an RPM (yum/dnf) repository", `id="rpmrepo"`, `id="rpmfile"`, "loadRpmFile", "collectRpm", "/admin/rpm/collect",
		`id="rpmnewest" type="checkbox" checked`,
		// Every ecosystem offers a one-shot "full bundle" checkbox that adds
		// force to the immediate collect (never to a schedule).
		"applyForce", `id="goForce"`, `id="pyForce"`, `id="mvnForce"`, `id="npmForce"`,
		`id="aptForce"`, `id="rpmForce"`, `id="ctrForce"`, `id="hfForce"`,
		// The uploads page sends arbitrary files as multipart form data over
		// XHR, so the modal can show real upload progress.
		`data-view="uploads"`, "Upload files", `id="upfolder"`, `id="upfiles"`,
		"collectUploads", "/admin/uploads/collect", "function uploadCollect", "xhr.upload",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("low-side index page missing %q", want)
		}
		if strings.Contains(body, `id="pyonly"`) {
			t.Error("low-side UI still exposes a switch that can disable mandatory wheels-only collection")
		}
	}
}

// TestLowServerUIPythonCollectFlow drives the request the requirements form
// issues: POST {requirements, target} to /admin/python/collect and confirm the
// wheels are packed into a signed bundle.
func TestLowServerUIPythonCollectFlow(t *testing.T) {
	ls, _ := newPyLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	reqBody, err := json.Marshal(map[string]any{
		"requirements": []string{"requests==2.32.4", "urllib3"},
		"target":       map[string]any{"only_binary": true},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(srv.URL+"/admin/python/collect", "application/json", strings.NewReader(string(reqBody))) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("python collect status = %d", resp.StatusCode)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "python-bundle-000001" || res.ExportedModules < 1 {
		t.Errorf("unexpected python collect result: %+v", res)
	}
}

// TestLowServerUIGoModCollectFlow drives the exact request the go.mod upload
// form issues: POST {go_mod, go_sum} to /admin/go/collect and confirm the
// project's module graph is resolved into a signed bundle.
func TestLowServerUIGoModCollectFlow(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	goMod := "module example.com/myapp\n\ngo 1.22\n\n" +
		"require (\n" +
		"\texample.com/foo/bar v1.0.0\n" +
		"\texample.com/foo/baz v1.1.0 // indirect\n" +
		")\n"
	reqBody, err := json.Marshal(map[string]string{"go_mod": goMod, "go_sum": ""})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(srv.URL+"/admin/go/collect", "application/json", strings.NewReader(string(reqBody))) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("collect status = %d", resp.StatusCode)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "go-bundle-000001" || res.ExportedModules < 2 {
		t.Errorf("unexpected collect result: %+v", res)
	}
}

// reexportRestoresFiles deletes the export-dir copy of a bundle (as the diode
// transfer would consume it), re-exports the sequence, and asserts every file
// is restored from the archive.
func reexportRestoresFiles(t *testing.T, ls *LowServer, stream string, seq int64) ReexportResult {
	t.Helper()
	bundleID := bundleIDFor(stream, seq)
	for _, suffix := range bundleSuffixes() {
		if err := os.Remove(filepath.Join(ls.cfg.ExportDir, bundleID+suffix)); err != nil {
			t.Fatalf("remove %s%s: %v", bundleID, suffix, err)
		}
	}
	res := ls.ReexportSequences(stream, []SequenceRange{{Start: seq, End: seq}})
	if len(res.Reexported) != 1 || len(res.Failed) != 0 {
		t.Fatalf("reexport %s seq %d result: %+v", stream, seq, res)
	}
	for _, suffix := range bundleSuffixes() {
		if !fileExists(filepath.Join(ls.cfg.ExportDir, bundleID+suffix)) {
			t.Errorf("bundle file %s%s not restored after re-export", bundleID, suffix)
		}
	}
	return res
}

func TestLowServerReexportPython(t *testing.T) {
	ls, _ := newPyLowServer(t)
	res, err := ls.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"requests"}})
	if err != nil {
		t.Fatalf("CollectPython: %v", err)
	}
	rr := reexportRestoresFiles(t, ls, streamPython, res.Sequence)
	if rr.Reexported[0].ExportedModules != 2 {
		t.Errorf("re-exported python unit count = %d, want 2", rr.Reexported[0].ExportedModules)
	}
}

func TestLowServerReexportGoCollect(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	res, err := ls.CollectGo(context.Background(), GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err != nil {
		t.Fatalf("CollectGo: %v", err)
	}
	reexportRestoresFiles(t, ls, streamGo, res.Sequence)
}

// TestLowServerUIReexportFlow drives the same request the UI issues: POST a
// sequence range to /admin/reexport and confirm it regenerates the bundle.
func TestLowServerUIReexportFlow(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	if _, err := ls.CollectGo(context.Background(), GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(ls)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/admin/reexport", "application/json", strings.NewReader(`{"sequences":"1"}`)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reexport status = %d", resp.StatusCode)
	}
	var res ReexportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if len(res.Reexported) != 1 || res.Reexported[0].Sequence != 1 || len(res.Failed) != 0 {
		t.Errorf("unexpected reexport result: %+v", res)
	}
}

// TestLowUICollectStopButton checks the collect modal ships a Stop control
// wired to cancel the job server-side (uploads, whose bytes stream from the
// page, still abort the request itself).
func TestLowUICollectStopButton(t *testing.T) {
	for _, want := range []string{`id="cmStop"`, "stopCollect()", "AbortController", "AbortError", "/admin/jobs/cancel"} {
		if !strings.Contains(lowUIHTML, want) {
			t.Errorf("low UI missing %q", want)
		}
	}
}

// TestLowUIDownloadProgressBar checks the collect modal ships the per-file
// download progress bar and handles the server's "dl" events.
func TestLowUIDownloadProgressBar(t *testing.T) {
	for _, want := range []string{`id="cmDl"`, `id="cmDlFill"`, `id="cmDlStats"`, "ev.type==='dl'", "updateCollectDl", "fmtETA"} {
		if !strings.Contains(lowUIHTML, want) {
			t.Errorf("low UI missing %q", want)
		}
	}
}
