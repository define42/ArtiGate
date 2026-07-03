package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHighServerUIOverview(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// Bundle 1 (Go) and bundle 2 (Python) are delivered and imported.
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 2, 1, map[string]string{
		"requests-2.32.4-py3-none-any.whl": "wheel-requests",
	})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}

	// Bundle 4 arrives while 3 is missing, so it is quarantined and 3 is flagged.
	writeSignedBundle(t, hs.cfg.Landing, priv, 4, 3, []moduleSpec{{"github.com/foo/baz", "v2.0.0"}})

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/ui/api/overview")
	if code != http.StatusOK {
		t.Fatalf("overview status = %d", code)
	}
	var ov UIOverview
	if err := json.Unmarshal([]byte(body), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	// Missing bundle is reported.
	if strings.Join(ov.Status.MissingRanges, ",") != "3" {
		t.Errorf("MissingRanges = %v, want [3]", ov.Status.MissingRanges)
	}
	if len(ov.Status.QuarantinedSequences) != 1 || ov.Status.QuarantinedSequences[0] != 4 {
		t.Errorf("QuarantinedSequences = %v, want [4]", ov.Status.QuarantinedSequences)
	}

	assertGoTree(t, ov.Go)
	assertPythonTree(t, ov.Python)
}

func assertGoTree(t *testing.T, mods []UIModule) {
	t.Helper()
	if len(mods) != 1 || mods[0].Module != "github.com/foo/bar" || mods[0].Versions[0] != "v1.0.0" {
		t.Errorf("Go tree = %+v", mods)
	}
	for _, m := range mods {
		// The quarantined bundle 4's module must not appear (not imported yet).
		if m.Module == "github.com/foo/baz" {
			t.Error("quarantined module should not be listed as available")
		}
	}
}

func assertPythonTree(t *testing.T, projects []UIProject) {
	t.Helper()
	if len(projects) != 1 || projects[0].Project != "requests" {
		t.Errorf("Python tree = %+v", projects)
		return
	}
	if len(projects[0].Files) != 1 || projects[0].Files[0].Version != "2.32.4" {
		t.Errorf("Python files = %+v", projects[0].Files)
	}
}

func TestHighServerUIPage(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/")
	if code != http.StatusOK {
		t.Fatalf("index status = %d", code)
	}
	for _, want := range []string{"<title>ArtiGate</title>", "/ui/api/overview", "Go modules", "Python packages"} {
		if !strings.Contains(body, want) {
			t.Errorf("index page missing %q", want)
		}
	}
}
