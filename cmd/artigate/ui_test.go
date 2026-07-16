package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHighServerUIOverview(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	// Bundle 3 arrives while 2 is missing: an import pass quarantines it and
	// flags 2 as missing. The read-only overview endpoint reports that state
	// but no longer runs the quarantine sweep itself.
	writeSignedBundle(t, hs.cfg.Landing, priv, 3, 2, []moduleSpec{{"github.com/foo/baz", "v2.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}

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
	st := ov.Status.Stream(streamGo)
	if strings.Join(st.MissingRanges, ",") != "2" {
		t.Errorf("MissingRanges = %v, want [2]", st.MissingRanges)
	}
	if len(st.QuarantinedSequences) != 1 || st.QuarantinedSequences[0] != 3 {
		t.Errorf("QuarantinedSequences = %v, want [3]", st.QuarantinedSequences)
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

func getDetail(t *testing.T, base, eco, path string) UIDetail {
	t.Helper()
	code, body := httpGet(t, base+"/ui/api/detail?eco="+eco+"&path="+url.QueryEscape(path))
	if code != http.StatusOK {
		t.Fatalf("detail(%s,%q) status = %d", eco, path, code)
	}
	var d UIDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	return d
}

func fieldValue(d UIDetail, label string) string {
	for _, f := range d.Fields {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func TestHighServerUIDetailGo(t *testing.T) {
	srv := mixedHighServer(t)

	d := getDetail(t, srv.URL, "go", "github.com/foo/bar@v1.0.0")
	if d.Title != "github.com/foo/bar" || d.Subtitle != "v1.0.0" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	if fieldValue(d, "Version") != "v1.0.0" {
		t.Errorf("Version field = %q", fieldValue(d, "Version"))
	}
	// The .mod file content is surfaced (the test fixture writes a stub go.mod).
	if !strings.Contains(d.GoMod, "github.com/foo/bar") {
		t.Errorf("go.mod not included: %q", d.GoMod)
	}
	if fieldValue(d, "Zip size") == "" || fieldValue(d, "Zip SHA-256") == "" {
		t.Errorf("missing zip fields: %+v", d.Fields)
	}
	// The download button points at the module zip, and that URL is live.
	wantZip := "/go/github.com/foo/bar/@v/v1.0.0.zip"
	if len(d.Downloads) != 1 || d.Downloads[0].URL != wantZip || d.Downloads[0].Label != "v1.0.0.zip" {
		t.Errorf("Downloads = %+v, want one link to %s", d.Downloads, wantZip)
	}
	if code, _ := httpGet(t, srv.URL+wantZip); code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", wantZip, code)
	}

	// Unknown version 404s.
	if code, _ := httpGet(t, srv.URL+"/ui/api/detail?eco=go&path=github.com/foo/bar@v9.9.9"); code != http.StatusNotFound {
		t.Errorf("unknown version status = %d, want 404", code)
	}
}

// TestGoDetailRejectsPathTraversal plants a complete-looking module version
// outside the module cache and proves goDetail refuses a "../" module path
// before touching it — without the guard, isComplete would succeed and the
// planted go.mod would leak.
func TestGoDetailRejectsPathTraversal(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	outside := filepath.Join(t.TempDir(), "secret")
	vdir := filepath.Join(outside, "@v")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"v1.0.0.info", "v1.0.0.mod", "v1.0.0.zip", "v1.0.0.complete"} {
		if err := os.WriteFile(filepath.Join(vdir, f), []byte("SECRET"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rel, err := filepath.Rel(hs.downloadDir, outside)
	if err != nil {
		t.Fatal(err)
	}
	spec := filepath.ToSlash(rel) + "@v1.0.0" // e.g. "../../secret@v1.0.0"

	d, err := hs.goDetail(spec)
	if err == nil {
		t.Fatalf("goDetail(%q) succeeded and leaked %q; traversal not blocked", spec, d.GoMod)
	}
}

func TestHighServerUIDetailPython(t *testing.T) {
	srv := mixedHighServer(t)

	d := getDetail(t, srv.URL, "python", "requests-2.32.4-py3-none-any.whl")
	if d.Title != "requests" || d.Subtitle != "2.32.4" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	if fieldValue(d, "Download") != "/packages/requests-2.32.4-py3-none-any.whl" {
		t.Errorf("Download field = %q", fieldValue(d, "Download"))
	}
	if fieldValue(d, "SHA-256") == "" || fieldValue(d, "Size") == "" {
		t.Errorf("missing wheel fields: %+v", d.Fields)
	}
	// The download button points at the wheel, and that URL is live.
	wantWheel := "/packages/requests-2.32.4-py3-none-any.whl"
	if len(d.Downloads) != 1 || d.Downloads[0].URL != wantWheel || d.Downloads[0].Label != "requests-2.32.4-py3-none-any.whl" {
		t.Errorf("Downloads = %+v, want one link to %s", d.Downloads, wantWheel)
	}
	if code, _ := httpGet(t, srv.URL+wantWheel); code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", wantWheel, code)
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

func getSearch(t *testing.T, base, q string) []UISearchGroup {
	t.Helper()
	code, body := httpGet(t, base+"/ui/api/search?q="+url.QueryEscape(q))
	if code != http.StatusOK {
		t.Fatalf("search(%q) status = %d", q, code)
	}
	var resp UISearchResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode search: %v", err)
	}
	return resp.Groups
}

// TestHighServerUISearch covers the cross-ecosystem search endpoint: hits are
// grouped per ecosystem, matched case-insensitively, capped with a full total,
// and each hit's path plugs straight back into the lazy tree.
func TestHighServerUISearch(t *testing.T) {
	srv := mixedHighServer(t)

	groups := getSearch(t, srv.URL, "bar")
	if len(groups) != 1 || groups[0].Eco != "go" || groups[0].Label != "Go modules" {
		t.Fatalf("search(bar) groups = %+v, want one go group", groups)
	}
	if groups[0].Total != 1 || len(groups[0].Nodes) != 1 {
		t.Fatalf("go group = %+v", groups[0])
	}
	hit := groups[0].Nodes[0]
	if hit.Label != "github.com/foo/bar" || hit.Path != "github.com/foo/bar" ||
		hit.Kind != "module" || !hit.Expandable || hit.Count != 1 {
		t.Errorf("hit = %+v", hit)
	}
	// The hit's path is a live tree node: expanding it yields the version leaf.
	if vers := getTree(t, srv.URL, "go", hit.Path); treeLabels(vers) != "v1.0.0" {
		t.Errorf("expanding the hit = %+v, want the v1.0.0 leaf", vers)
	}

	// Case-insensitive and cross-ecosystem: REQUESTS finds the Python project.
	groups = getSearch(t, srv.URL, "REQUESTS")
	if len(groups) != 1 || groups[0].Eco != "python" || groups[0].Nodes[0].Label != "requests" {
		t.Fatalf("search(REQUESTS) groups = %+v, want the requests project", groups)
	}

	// "foo" matches both mirrored modules; the total counts them all.
	groups = getSearch(t, srv.URL, "foo")
	if len(groups) != 1 || groups[0].Total != 2 || len(groups[0].Nodes) != 2 {
		t.Fatalf("search(foo) groups = %+v, want 2 go hits", groups)
	}

	// No match and blank queries return no groups (never the whole inventory).
	for _, q := range []string{"nosuchpackage", "", "   "} {
		if groups := getSearch(t, srv.URL, q); len(groups) != 0 {
			t.Errorf("search(%q) groups = %+v, want none", q, groups)
		}
	}
}

// TestHighServerUISearchRejects covers the endpoint's input guards: an
// over-long query and a write method.
func TestHighServerUISearchRejects(t *testing.T) {
	srv := mixedHighServer(t)

	if code, _ := httpGet(t, srv.URL+"/ui/api/search?q="+strings.Repeat("a", maxUISearchQueryLen+1)); code != http.StatusBadRequest {
		t.Errorf("overlong query status = %d, want 400", code)
	}
	resp, err := http.Post(srv.URL+"/ui/api/search?q=x", "text/plain", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST search status = %d, want 405", resp.StatusCode)
	}
}

// TestUITreeSearch pins each tree shape's search behavior: what is matched,
// the node a hit renders as, and the cap-with-total accounting.
func TestUITreeSearch(t *testing.T) {
	mods := segmentTree{
		{Module: "github.com/foo/bar", Versions: []string{"v1.0.0"}},
		{Module: "github.com/foo/baz", Versions: []string{"v2.0.0", "v2.1.0"}},
	}
	nodes, total := mods.search("BAZ", 10)
	if total != 1 || len(nodes) != 1 || nodes[0].Path != "github.com/foo/baz" ||
		nodes[0].Kind != "module" || !nodes[0].Expandable || nodes[0].Count != 2 {
		t.Errorf("segment search = %+v (total %d)", nodes, total)
	}

	// The cap bounds the returned nodes; the total still counts every match.
	if nodes, total := mods.search("foo", 1); total != 2 || len(nodes) != 1 {
		t.Errorf("capped search = %d nodes (total %d), want 1 node of 2", len(nodes), total)
	}

	flat := flatTree{{Module: "@scope/pkg", Versions: []string{"1.0.0"}}}
	if nodes, total := flat.search("scope", 10); total != 1 || len(nodes) != 1 || nodes[0].Kind != "module" {
		t.Errorf("flat search = %+v (total %d)", nodes, total)
	}

	py := pythonTree{{Project: "requests", Files: []UIPyFile{{Filename: "requests-2.32.4-py3-none-any.whl"}}}}
	if nodes, total := py.search("req", 10); total != 1 || nodes[0].Kind != "project" || nodes[0].Count != 1 {
		t.Errorf("python search = %+v (total %d)", nodes, total)
	}

	up := uploadsTree{{Folder: "docs", Files: []UploadedFile{{Name: "report.pdf"}, {Name: "notes.txt"}}}}
	if nodes, total := up.search("docs", 10); total != 1 || nodes[0].Kind != "project" || !nodes[0].Expandable {
		t.Errorf("uploads folder search = %+v (total %d)", nodes, total)
	}
	// A file hit is a selectable leaf whose label carries its folder.
	if nodes, total := up.search("report", 10); total != 1 || nodes[0].Kind != "file" ||
		nodes[0].Path != "docs/report.pdf" || nodes[0].Label != "docs/report.pdf" {
		t.Errorf("uploads file search = %+v (total %d)", nodes, total)
	}
}

// TestHighServerUIReposApt checks the per-repo data the "Set me up" guide uses:
// an imported APT mirror is listed with the suites/components/architectures it
// was mirrored with, so the generated client .sources is exact.
func TestHighServerUIReposApt(t *testing.T) {
	hs, _, _ := collectAndImportApt(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/ui/api/repos?eco=apt")
	if code != http.StatusOK {
		t.Fatalf("apt repos status = %d", code)
	}
	var resp UIReposResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Repos) != 1 {
		t.Fatalf("apt repos = %+v, want 1", resp.Repos)
	}
	r := resp.Repos[0]
	if r.Name != "microsoft-code" || len(r.Suites) != 1 {
		t.Fatalf("apt repo = %+v", r)
	}
	s := r.Suites[0]
	if s.Name != "stable" ||
		len(s.Components) != 1 || s.Components[0] != "main" ||
		len(s.Architectures) != 1 || s.Architectures[0] != "amd64" {
		t.Errorf("apt suite = %+v", s)
	}
	if r.Signed { // this test's high server has no signing key
		t.Error("apt repo reported signed, but the high server has no signing key")
	}

	// rpm has no mirror here → empty list (not an error); unknown eco → 400.
	if code, _ := httpGet(t, srv.URL+"/ui/api/repos?eco=rpm"); code != http.StatusOK {
		t.Errorf("rpm repos status = %d, want 200", code)
	}
	if code, _ := httpGet(t, srv.URL+"/ui/api/repos?eco=go"); code != http.StatusBadRequest {
		t.Errorf("go repos status = %d, want 400", code)
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
	// The page shell has the title, the header search box, the stream sidebar
	// menu (Go / Python), the "Set me up" guide toggle and its container, and
	// loads the JS.
	for _, want := range []string{
		"<title>ArtiGate</title>",
		`id="search"`,
		`data-view="overview"`,
		"Import status",
		`id="view-overview"`,
		`id="view-tree"`,
		`data-view="go"`,
		`data-view="python"`,
		`data-view="maven"`,
		`data-view="apt"`,
		`data-view="rpm"`,
		`data-view="uploads"`,
		">Go</button>",
		">Python</button>",
		">Maven</button>",
		">APT</button>",
		">RPM</button>",
		">Uploads</button>",
		`id="guideBtn"`,
		"Set me up",
		`<dialog id="guide"`,
		`id="guideClose"`,
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
	// The compiled bundle drives the lazy tree fetch, the view switch, the
	// detail panel with its direct-download buttons, the "Set me up"
	// client-setup guide, the uploads delete action, and the cross-ecosystem
	// package search.
	for _, want := range []string{"/ui/api/tree", "/ui/api/detail", "/ui/api/repos", "fetchChildren", "selectLeaf", "renderDetail", "downloadRow", "download-link", "encodePath", "openGuide", "openRepoGuide", "aptGuideSection", "fetchRepos", "showModal", "GOPROXY", "index-url", "uploadActions", "uploadDeleteButton", "/admin/uploads/delete", "/ui/api/search", "runSearch", "scheduleSearch", "renderSearchResults", "searchGroupEl"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}

// TestDetailDigestCacheMemoizesAndInvalidates proves the shared /ui/api/detail
// digest cache serves a stored hash without re-reading the artifact, and
// re-hashes only when the file's size or modtime changes — so the
// unauthenticated detail panel cannot be amplified into an O(artifact-bytes)
// re-hash on every request (exercised through the uploads hook; every
// ecosystem's detail hook shares s.detailDigests).
func TestDetailDigestCacheMemoizesAndInvalidates(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	abs := filepath.Join(hs.uploadsDir(), "docs", "readme.md")
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, []byte("original-bytes")) // 14 bytes
	fixed := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(abs, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	digestOf := func() string {
		t.Helper()
		detail, err := hs.uploadsDetail("docs/readme.md")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range detail.Fields {
			if f.Label == "SHA-256" {
				return f.Value
			}
		}
		t.Fatal("detail has no SHA-256 field")
		return ""
	}

	origSum, err := sha256File(abs)
	if err != nil {
		t.Fatal(err)
	}
	if got := digestOf(); got != origSum {
		t.Fatalf("first digest = %q, want %q", got, origSum)
	}

	// Overwrite the content but restore the identical size and modtime. A
	// re-hash would pick up the new bytes; a cache hit keeps the old digest.
	writeFile(t, abs, []byte("tampered_bytes")) // also 14 bytes
	if err := os.Chtimes(abs, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	if got := digestOf(); got != origSum {
		t.Errorf("cache miss: digest = %q, want the memoized %q", got, origSum)
	}

	// Bumping the modtime invalidates the entry, so the new content is hashed.
	if err := os.Chtimes(abs, fixed.Add(time.Second), fixed.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	newSum, err := sha256File(abs)
	if err != nil {
		t.Fatal(err)
	}
	if got := digestOf(); got != newSum || newSum == origSum {
		t.Errorf("stale after modtime change: digest = %q, want re-hashed %q (orig %q)", got, newSum, origSum)
	}
}
