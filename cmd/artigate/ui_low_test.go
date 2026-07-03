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
	if len(st.ExportedSequences) != 1 || st.ExportedSequences[0].Sequence != 1 {
		t.Fatalf("exported sequences = %+v", st.ExportedSequences)
	}
	if !st.ExportedSequences[0].FilesPresent {
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
	for _, want := range []string{"<title>ArtiGate low-side</title>", "/admin/reexport", "Re-transmit bundles", "/ui/api/status"} {
		if !strings.Contains(body, want) {
			t.Errorf("low-side index page missing %q", want)
		}
	}
}

// reexportRestoresFiles deletes the export-dir copy of a bundle (as the diode
// transfer would consume it), re-exports the sequence, and asserts every file
// is restored from the archive.
func reexportRestoresFiles(t *testing.T, ls *LowServer, seq int64) ReexportResult {
	t.Helper()
	bundleID := bundleIDForSequence(seq)
	for _, suffix := range bundleSuffixes() {
		if err := os.Remove(filepath.Join(ls.cfg.ExportDir, bundleID+suffix)); err != nil {
			t.Fatalf("remove %s%s: %v", bundleID, suffix, err)
		}
	}
	res := ls.ReexportSequences(context.Background(), []SequenceRange{{Start: seq, End: seq}})
	if len(res.Reexported) != 1 || len(res.Failed) != 0 {
		t.Fatalf("reexport seq %d result: %+v", seq, res)
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
	rr := reexportRestoresFiles(t, ls, res.Sequence)
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
	reexportRestoresFiles(t, ls, res.Sequence)
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
