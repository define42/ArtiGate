package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHighServerUIOverview(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	// Bundle 3 arrives while 2 is missing: quarantined, and 2 is flagged missing.
	writeSignedBundle(t, hs.cfg.Landing, priv, 3, 2, []moduleSpec{{"github.com/foo/baz", "v2.0.0"}})

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
	if strings.Join(ov.Status.MissingRanges, ",") != "2" {
		t.Errorf("MissingRanges = %v, want [2]", ov.Status.MissingRanges)
	}
	if len(ov.Status.QuarantinedSequences) != 1 || ov.Status.QuarantinedSequences[0] != 3 {
		t.Errorf("QuarantinedSequences = %v, want [3]", ov.Status.QuarantinedSequences)
	}
}

func getTree(t *testing.T, base, eco, path string) []UITreeNode {
	t.Helper()
	code, body := httpGet(t, base+"/ui/api/tree?eco="+eco+"&path="+url.QueryEscape(path))
	if code != http.StatusOK {
		t.Fatalf("tree(%s,%q) status = %d", eco, path, code)
	}
	var resp struct {
		Nodes []UITreeNode `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode tree: %v", err)
	}
	return resp.Nodes
}

// mixedHighServer imports two github.com Go modules and one Python project, and
// returns a running test server.
func mixedHighServer(t *testing.T) *httptest.Server {
	t.Helper()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	writeSignedBundle(t, hs.cfg.Landing, priv, 2, 1, []moduleSpec{{"github.com/foo/baz", "v2.0.0"}})
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 3, 2, map[string]string{
		"requests-2.32.4-py3-none-any.whl": "wheel-requests",
	})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)
	return srv
}

func treeLabels(nodes []UITreeNode) string {
	ls := make([]string, len(nodes))
	for i, n := range nodes {
		ls[i] = n.Label
	}
	return strings.Join(ls, ",")
}

// TestHighServerUITreeGo walks the lazy Go tree level by level: both modules
// collapse under a single github.com path node.
func TestHighServerUITreeGo(t *testing.T) {
	srv := mixedHighServer(t)

	root := getTree(t, srv.URL, "go", "")
	if treeLabels(root) != "github.com" || root[0].Kind != "dir" || root[0].Count != 2 {
		t.Fatalf("go root = %+v", root)
	}
	if treeLabels(getTree(t, srv.URL, "go", "github.com")) != "foo" {
		t.Fatalf("github.com children should be a single 'foo' node")
	}

	mods := getTree(t, srv.URL, "go", "github.com/foo")
	if treeLabels(mods) != "bar,baz" || mods[0].Kind != "module" {
		t.Fatalf("foo children = %+v", mods)
	}

	vers := getTree(t, srv.URL, "go", "github.com/foo/bar")
	if treeLabels(vers) != "v1.0.0" || vers[0].Kind != "version" || vers[0].Expandable {
		t.Fatalf("bar versions = %+v", vers)
	}
}

// TestHighServerUITreePython walks the two-level Python tree: root lists
// projects, expanding one lists its wheels.
func TestHighServerUITreePython(t *testing.T) {
	srv := mixedHighServer(t)

	py := getTree(t, srv.URL, "python", "")
	if len(py) != 1 || py[0].Label != "requests" || py[0].Kind != "project" {
		t.Fatalf("python root = %+v", py)
	}

	files := getTree(t, srv.URL, "python", "requests")
	if len(files) != 1 || files[0].Kind != "file" {
		t.Fatalf("python files = %+v", files)
	}
	if !strings.Contains(files[0].Label, "requests-2.32.4") {
		t.Errorf("wheel label = %q", files[0].Label)
	}
}

func TestGoTreeChildren(t *testing.T) {
	mods := []UIModule{
		{Module: "github.com/foo/bar", Versions: []string{"v1.0.0"}},
		{Module: "github.com/foo/baz", Versions: []string{"v2.0.0", "v2.1.0"}},
		{Module: "golang.org/x/text", Versions: []string{"v0.14.0"}},
	}

	root := goTreeChildren(mods, "")
	if treeLabels(root) != "github.com,golang.org" {
		t.Errorf("root labels = %q, want github.com,golang.org", treeLabels(root))
	}
	if root[0].Kind != "dir" || root[0].Count != 2 {
		t.Errorf("github.com node = %+v, want dir count 2", root[0])
	}

	foo := goTreeChildren(mods, "github.com/foo")
	if len(foo) != 2 || foo[0].Label != "bar" || foo[0].Count != 1 || foo[1].Label != "baz" || foo[1].Count != 2 {
		t.Errorf("github.com/foo children = %+v", foo)
	}

	versions := goTreeChildren(mods, "github.com/foo/baz")
	if len(versions) != 2 || versions[0].Kind != "version" || versions[0].Expandable {
		t.Errorf("baz versions = %+v", versions)
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
	// The page shell has the title, the top menu (Go / Python), and loads the JS.
	for _, want := range []string{
		"<title>ArtiGate</title>",
		`data-view="go"`,
		`data-view="python"`,
		"Go modules",
		"Python packages",
		`src="/ui/app.js"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index page missing %q", want)
		}
	}
}

func TestHighServerUIAppJS(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ui/app.js") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("app.js status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("app.js content-type = %q, want javascript", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// The compiled bundle drives the lazy tree fetch and the view switch.
	for _, want := range []string{"/ui/api/tree", "fetchChildren", "loadTree", "currentView"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}
