package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
