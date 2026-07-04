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
	ls.recordRequest("example.com/foo/bar", "v1.0.0")
	if _, err := ls.ExportPending(context.Background()); err != nil {
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
	if !goStream.ExportedSequences[0].FilesPresent {
		t.Error("exported bundle files should be present")
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
		// Top menu splits each ecosystem onto its own view/page.
		"function setView(", `data-view="go"`, `data-view="java"`, `data-view="status"`,
		`id="view-go"`, `id="view-java"`, `id="view-status"`,
		"Mirror a Go project", `id="gomod"`, `id="gosum"`, "collectGoMod", "/admin/go/collect",
		"Mirror Python packages", `id="pyreqs"`, "collectPython", "/admin/python/collect",
		"Mirror Java/Maven artifacts", `id="mvncoords"`, `id="mvnpom"`, "collectMaven", "/admin/maven/collect",
		"Mirror an APT (deb) repository", `id="aptsrc"`, `id="aptfile"`, "loadAptFile", "collectApt", "/admin/apt/collect",
		"Mirror an RPM (yum/dnf) repository", `id="rpmrepo"`, `id="rpmfile"`, "loadRpmFile", "collectRpm", "/admin/rpm/collect",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("low-side index page missing %q", want)
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
	res := ls.ReexportSequences(context.Background(), stream, []SequenceRange{{Start: seq, End: seq}})
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
	ls.recordRequest("example.com/foo/bar", "v1.0.0")
	if _, err := ls.ExportPending(context.Background()); err != nil {
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
