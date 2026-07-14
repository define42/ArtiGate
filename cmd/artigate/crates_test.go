package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// cratesTestDeps is the dependency table of the fixture's mylib 1.0.0 line: a
// renamed normal dependency (resolved under its registry name "dep"), a dev
// dependency, and an optional dependency. The latter two point at versions the
// fake index does not know, so following them by mistake would fail loudly.
const cratesTestDeps = `[` +
	`{"name":"depalias","package":"dep","req":"^0.1","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal"},` +
	`{"name":"devdep","req":"^9.9","optional":false,"kind":"dev"},` +
	`{"name":"optdep","req":"^9.9","optional":true,"kind":"normal"}` +
	`]`

func TestCratesValidateNameAndVersion(t *testing.T) {
	validNames := []string{"a", "A", "0ad", "serde", "my-lib", "my_lib", "x" + strings.Repeat("y", 63)}
	invalidNames := []string{"", ".", "..", "-flag", "_private", "a/b", "a.b", "a b", "café", strings.Repeat("x", 65)}
	for _, name := range validNames {
		if err := validateCrateName(name); err != nil {
			t.Errorf("validateCrateName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range invalidNames {
		if err := validateCrateName(name); err == nil {
			t.Errorf("validateCrateName(%q) = nil, want error", name)
		}
	}

	// The version check is a charset/path-safety gate (a version always starts
	// with a digit, so it can never be ".." or "-flag"); full semver shape is
	// enforced where ordering matters, so a bare "1" passes here.
	validVersions := []string{"1.0.0", "0.1.5", "1.0.0-alpha.1", "2.0.0-rc.1+build.5", "1", "10.20.30"}
	invalidVersions := []string{"", "v1.0.0", "-1.0.0", "^1.0.0", "..", "1.0.0/..", "1.0.0 ", "1.0.0\n", "latest"}
	for _, v := range validVersions {
		if err := validateCrateVersion(v); err != nil {
			t.Errorf("validateCrateVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVersions {
		if err := validateCrateVersion(v); err == nil {
			t.Errorf("validateCrateVersion(%q) = nil, want error", v)
		}
	}
}

func TestCratesPaths(t *testing.T) {
	tests := []struct{ name, want string }{
		{"a", "1/a"},
		{"ab", "2/ab"},
		{"abc", "3/a/abc"},
		{"abcd", "ab/cd/abcd"},
		{"serde", "se/rd/serde"},
		{"MyLib", "my/li/mylib"}, // index paths are lowercase
	}
	for _, tt := range tests {
		if got := crateIndexPath(tt.name); got != tt.want {
			t.Errorf("crateIndexPath(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	// The storage path is canonical: one lowercase location however a
	// dependency spells the crate.
	if got := crateFileRel("MyLib", "1.0.0"); got != "crates/files/mylib/mylib-1.0.0.crate" {
		t.Errorf("crateFileRel(MyLib, 1.0.0) = %q", got)
	}
	if got := crateFileRel("dep", "0.1.5-alpha.1"); got != "crates/files/dep/dep-0.1.5-alpha.1.crate" {
		t.Errorf("crateFileRel(dep, 0.1.5-alpha.1) = %q", got)
	}
}

func TestCratesVersionOrdering(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	parse := func(s string) crateVer {
		t.Helper()
		v, err := parseCrateVer(s)
		if err != nil {
			t.Fatalf("parseCrateVer(%q): %v", s, err)
		}
		return v
	}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := parse(ordered[i]), parse(ordered[i+1])
		if compareCrateVer(a, b) >= 0 || compareCrateVer(b, a) <= 0 {
			t.Errorf("want %s < %s", ordered[i], ordered[i+1])
		}
	}

	// Build metadata is ignored for ordering and stripped by the parser.
	if compareCrateVer(parse("1.0.0+build.5"), parse("1.0.0")) != 0 {
		t.Error("build metadata must not affect ordering")
	}
	if v := parse("1.2.3-rc.1+meta"); v.major != 1 || v.minor != 2 || v.patch != 3 || v.pre != "rc.1" {
		t.Errorf("parseCrateVer(1.2.3-rc.1+meta) = %+v", v)
	}

	for _, bad := range []string{"", "1", "1.0", "1.0.0.0", "1.a.0", "x.y.z", "1.0.-1"} {
		if _, err := parseCrateVer(bad); err == nil {
			t.Errorf("parseCrateVer(%q) = nil error, want error", bad)
		}
	}

	// crateVersionLess orders semver properly and falls back to lexical order
	// for versions that do not parse.
	if !crateVersionLess("0.9.0", "1.0.0") || crateVersionLess("1.0.0", "0.9.0") {
		t.Error("crateVersionLess semver ordering wrong")
	}
	if !crateVersionLess("not-semver", "z") || crateVersionLess("z", "not-semver") {
		t.Error("crateVersionLess lexical fallback wrong")
	}
}

func TestCratesReqMatching(t *testing.T) {
	tests := []struct {
		req, version string
		want         bool
	}{
		{"1.2.3", "1.2.3", true}, // a bare requirement is a caret
		{"1.2.3", "1.9.9", true},
		{"1.2.3", "1.2.2", false},
		{"1.2.3", "2.0.0", false},
		{"^0.2.3", "0.2.3", true},
		{"^0.2.3", "0.2.9", true},
		{"^0.2.3", "0.3.0", false},
		{"^0.0.3", "0.0.3", true},
		{"^0.0.3", "0.0.4", false},
		{"~1.2.3", "1.2.3", true},
		{"~1.2.3", "1.2.9", true},
		{"~1.2.3", "1.3.0", false},
		{"~1.2", "1.2.0", true},
		{"~1.2", "1.2.9", true},
		{"~1.2", "1.3.0", false},
		{"~1", "1.9.9", true},
		{"~1", "2.0.0", false},
		{"=1.2.3", "1.2.3", true},
		{"=1.2.3", "1.2.4", false},
		{"=1.2", "1.2.9", true}, // partial "=" accepts any 1.2.x
		{"=1.2", "1.3.0", false},
		{"=1", "1.9.9", true},
		{">=1.0, <2.0", "1.0.0", true}, // comma is AND
		{">=1.0, <2.0", "1.5.0", true},
		{">=1.0, <2.0", "0.9.9", false},
		{">=1.0, <2.0", "2.0.0", false},
		{">1.0.0", "1.0.0", false},
		{">1.0.0", "1.0.1", true},
		{"<=1.2.3", "1.2.3", true},
		{"<1.2.3", "1.2.3", false},
		{"*", "3.4.5", true},
		{"*", "1.0.0-alpha", false}, // wildcards never match pre-releases
		{"1.*", "1.9.0", true},
		{"1.*", "2.0.0", false},
		{"1.2.*", "1.2.7", true},
		{"1.2.*", "1.3.0", false},
		// cargo's pre-release rule: a pre-release version matches only when a
		// comparator names the same major.minor.patch with a pre-release tag.
		{"^1.0.0-alpha", "1.0.0-alpha", true},
		{"^1.0.0-alpha", "1.0.0-beta", true},
		{"^1.0.0-alpha", "1.0.1-alpha", false},
		{"^1.0.0-alpha", "1.5.0", true},
		{"^1.0.0", "1.0.1-alpha", false},
		{"1.2.3", "1.2.3-beta", false},
		{"=1.0.0-beta", "1.0.0-beta", true},
	}
	for _, tt := range tests {
		preds, err := parseCrateReq(tt.req)
		if err != nil {
			t.Errorf("parseCrateReq(%q) = %v, want nil", tt.req, err)
			continue
		}
		v, err := parseCrateVer(tt.version)
		if err != nil {
			t.Fatalf("parseCrateVer(%q): %v", tt.version, err)
		}
		if got := crateReqMatches(preds, v); got != tt.want {
			t.Errorf("crateReqMatches(%q, %s) = %v, want %v", tt.req, tt.version, got, tt.want)
		}
	}

	for _, bad := range []string{"", " ", "1,,2", "bogus", "1.2.3.4", ">=!"} {
		if _, err := parseCrateReq(bad); err == nil {
			t.Errorf("parseCrateReq(%q) = nil error, want error", bad)
		}
	}
}

func TestCratesDlURL(t *testing.T) {
	tests := []struct {
		dl, name, version, cksum, want string
	}{
		// Explicit {marker}s are substituted, {prefix} being the index shard.
		{
			"https://x/{crate}/{version}/{prefix}/{sha256-checksum}",
			"serde", "1.0.0", "deadbeef",
			"https://x/serde/1.0.0/se/rd/deadbeef",
		},
		{
			"https://x/{lowerprefix}/{crate}-{version}.crate",
			"MyLib", "2.0.0", "s",
			"https://x/my/li/MyLib-2.0.0.crate",
		},
		{"https://x/{prefix}", "a", "1.0.0", "s", "https://x/1"},
		// A template without markers gets the standard cargo suffix.
		{
			"https://mirror.example/api/v1/crates",
			"dep", "0.1.5", "s",
			"https://mirror.example/api/v1/crates/dep/0.1.5/download",
		},
	}
	for _, tt := range tests {
		if got := crateDlURL(tt.dl, tt.name, tt.version, tt.cksum); got != tt.want {
			t.Errorf("crateDlURL(%q, %s@%s) = %q, want %q", tt.dl, tt.name, tt.version, got, tt.want)
		}
	}
}

func TestCratesValidateRecords(t *testing.T) {
	sum := aptSHA256([]byte("crate bytes"))
	line := func(name, vers, cksum string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"name":%q,"vers":%q,"cksum":%q}`, name, vers, cksum))
	}
	canonical := crateFileRel("mylib", "1.0.0")
	good := CrateVersion{Name: "mylib", Version: "1.0.0", Path: canonical, SHA256: sum, IndexLine: line("mylib", "1.0.0", sum)}
	seen := map[string]bool{canonical: true}
	files := []ManifestFile{{Path: canonical, SHA256: sum, Size: 11}}

	if err := validateCrates(nil, nil, nil); err != nil {
		t.Errorf("empty crate list = %v, want nil", err)
	}
	if err := validateCrates([]CrateVersion{good}, seen, files); err != nil {
		t.Errorf("valid record rejected: %v", err)
	}

	// Mixed-case spellings normalize to the same canonical path and compare
	// case-insensitively against the index line's name and cksum.
	mixed := good
	mixed.Name = "MyLib"
	mixed.IndexLine = line("mylib", "1.0.0", strings.ToUpper(sum))
	if err := validateCrates([]CrateVersion{mixed}, seen, files); err != nil {
		t.Errorf("mixed-case record rejected: %v", err)
	}

	mutate := func(f func(*CrateVersion)) CrateVersion {
		c := good
		f(&c)
		return c
	}
	bad := []struct {
		name string
		c    CrateVersion
		seen map[string]bool
	}{
		{"invalid name", mutate(func(c *CrateVersion) { c.Name = "../evil" }), seen},
		{"invalid version", mutate(func(c *CrateVersion) { c.Version = "1.0.0/.." }), seen},
		{"non-canonical path", mutate(func(c *CrateVersion) { c.Path = "crates/files/mylib/MYLIB-1.0.0.crate" }), seen},
		{"path outside crates tree", mutate(func(c *CrateVersion) { c.Path = "npm/packages/mylib-1.0.0.crate" }), seen},
		{"file not listed in manifest", good, map[string]bool{}},
		{"unparsable index line", mutate(func(c *CrateVersion) { c.IndexLine = json.RawMessage("not json") }), seen},
		{"index line names another crate", mutate(func(c *CrateVersion) { c.IndexLine = line("other", "1.0.0", sum) }), seen},
		{"index line names another version", mutate(func(c *CrateVersion) { c.IndexLine = line("mylib", "2.0.0", sum) }), seen},
		{"index cksum mismatch", mutate(func(c *CrateVersion) { c.IndexLine = line("mylib", "1.0.0", aptSHA256([]byte("other bytes"))) }), seen},
		{"empty sha256", mutate(func(c *CrateVersion) { c.SHA256 = ""; c.IndexLine = line("mylib", "1.0.0", "") }), seen},
		// The record's own claim must also match the byte-verified
		// manifest.files hash for its path.
		{"record sha disagrees with manifest.files", mutate(func(c *CrateVersion) {
			other := aptSHA256([]byte("other bytes"))
			c.SHA256 = other
			c.IndexLine = line("mylib", "1.0.0", other)
		}), seen},
	}
	for _, tt := range bad {
		if err := validateCrates([]CrateVersion{tt.c}, tt.seen, files); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// cratesTestPayload is the deterministic fake .crate archive for a release, so
// every assertion can recompute the expected bytes and SHA-256.
func cratesTestPayload(name, version string) []byte {
	return []byte("fake-crate " + name + " " + version)
}

// fakeCratesRegistry is an httptest sparse index plus download host:
// /config.json advertises "<self>/dl" as the marker-less download template,
// index files and payloads are registered per release, and every request is
// counted so tests can assert what was (not) fetched.
type fakeCratesRegistry struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	index map[string]string // "/my/li/mylib" -> newline-delimited index lines
	dl    map[string][]byte // "/dl/mylib/1.0.0/download" -> .crate payload
}

func fakeCratesUpstream(t *testing.T) *fakeCratesRegistry {
	t.Helper()
	reg := &fakeCratesRegistry{hits: map[string]int{}, index: map[string]string{}, dl: map[string][]byte{}}
	reg.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.mu.Lock()
		reg.hits[r.URL.Path]++
		idx, okIdx := reg.index[r.URL.Path]
		body, okDl := reg.dl[r.URL.Path]
		reg.mu.Unlock()
		switch {
		case r.URL.Path == "/config.json":
			writeJSON(w, map[string]string{"dl": "http://" + r.Host + "/dl"})
		case okIdx:
			_, _ = w.Write([]byte(idx))
		case okDl:
			_, _ = w.Write(body)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(reg.srv.Close)
	return reg
}

// add registers one release: an index line whose cksum is the real SHA-256 of
// the deterministic payload, plus the payload on the download route.
func (f *fakeCratesRegistry) add(name, vers, depsJSON string, yanked bool) {
	payload := cratesTestPayload(name, vers)
	if depsJSON == "" {
		depsJSON = "[]"
	}
	line := fmt.Sprintf(`{"name":%q,"vers":%q,"deps":%s,"cksum":%q,"features":{},"yanked":%v}`,
		name, vers, depsJSON, aptSHA256(payload), yanked)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.index["/"+crateIndexPath(name)] += line + "\n"
	f.dl["/dl/"+name+"/"+vers+"/download"] = payload
}

func (f *fakeCratesRegistry) count(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[p]
}

// cratesTestSetup stands up the fake upstream (mylib 0.9.0 and 1.0.0, a yanked
// mylib 1.1.0, and dep 0.1.5) plus a low server resolving against it.
func cratesTestSetup(t *testing.T) (*fakeCratesRegistry, *LowServer, ed25519.PrivateKey) {
	t.Helper()
	reg := fakeCratesUpstream(t)
	reg.add("mylib", "0.9.0", "", false)
	reg.add("mylib", "1.0.0", cratesTestDeps, false)
	reg.add("mylib", "1.1.0", "", true) // yanked: must never be selected
	reg.add("dep", "0.1.5", "", false)

	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), CratesIndex: reg.srv.URL}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return reg, ls, priv
}

// cratesFetchIndexLines GETs a served sparse-index file and parses its lines.
func cratesFetchIndexLines(t *testing.T, url string) []crateIndexLine {
	t.Helper()
	code, body := httpGet(t, url)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, code, body)
	}
	var out []crateIndexLine
	for _, raw := range strings.Split(strings.TrimSpace(body), "\n") {
		if raw == "" {
			continue
		}
		var line crateIndexLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("index line %q is not JSON: %v", raw, err)
		}
		out = append(out, line)
	}
	return out
}

// cratesAssertBundleManifest checks the first collect's exported manifest:
// dep 0.1.5 and mylib 1.0.0 with canonical paths, real hashes, and verbatim
// index lines whose cksum equals each record's artifact SHA-256.
func cratesAssertBundleManifest(t *testing.T, ls *LowServer, bundleID string) {
	t.Helper()
	m := readBundleManifest(t, ls, bundleID)
	if m.Crates == nil || len(m.Crates.Crates) != 2 {
		t.Fatalf("bundle manifest crates = %+v, want dep and mylib", m.Crates)
	}
	if len(m.Files) != 2 {
		t.Fatalf("bundle files = %+v, want 2", m.Files)
	}
	wants := []struct{ name, version string }{{"dep", "0.1.5"}, {"mylib", "1.0.0"}} // sorted by name/path
	for i, want := range wants {
		payload := cratesTestPayload(want.name, want.version)
		rel := crateFileRel(want.name, want.version)
		c := m.Crates.Crates[i]
		if c.Name != want.name || c.Version != want.version || c.Path != rel || c.SHA256 != aptSHA256(payload) {
			t.Errorf("crate record %d = %+v, want %s@%s at %s", i, c, want.name, want.version, rel)
		}
		var line crateIndexLine
		if err := json.Unmarshal(c.IndexLine, &line); err != nil {
			t.Fatalf("record %d index line: %v", i, err)
		}
		if line.Name != want.name || line.Vers != want.version || line.Cksum != aptSHA256(payload) {
			t.Errorf("record %d index line = %+v, want cksum %s", i, line, aptSHA256(payload))
		}
		f := m.Files[i]
		if f.Path != rel || f.SHA256 != aptSHA256(payload) || f.Size != int64(len(payload)) {
			t.Errorf("bundle file %d = %+v, want %s", i, f, rel)
		}
	}
}

// cratesAssertDownload checks one .crate download returns the exact collected
// bytes.
func cratesAssertDownload(t *testing.T, base, name, version string) {
	t.Helper()
	payload := cratesTestPayload(name, version)
	code, got := httpGet(t, base+"/crates/dl/"+name+"/"+version+"/download")
	if code != http.StatusOK || got != string(payload) {
		t.Errorf("download %s@%s: status %d, %d byte(s), want %d", name, version, code, len(got), len(payload))
	}
}

// cratesAssertServedIndex is the strict sparse-index expectation (used by the
// skipped line-format test, see TestCratesServedIndexLineFormat): one line per
// mirrored version, ascending, each cksum matching its payload, and every
// listed .crate downloading byte-identically.
func cratesAssertServedIndex(t *testing.T, base, name string, versions ...string) {
	t.Helper()
	lines := cratesFetchIndexLines(t, base+"/crates/index/"+crateIndexPath(name))
	if len(lines) != len(versions) {
		t.Fatalf("%s index lines = %+v, want versions %v", name, lines, versions)
	}
	for i, v := range versions {
		payload := cratesTestPayload(name, v)
		if lines[i].Name != name || lines[i].Vers != v || lines[i].Cksum != aptSHA256(payload) {
			t.Errorf("%s index line %d = %+v, want %s@%s cksum %s", name, i, lines[i], name, v, aptSHA256(payload))
		}
		cratesAssertDownload(t, base, name, v)
	}
}

// TestCratesLowToHighPipeline is the full round-trip: resolve against a fake
// sparse index, download with cksum verification, export a signed bundle,
// import it on the high side, and serve the regenerated sparse registry.
func TestCratesLowToHighPipeline(t *testing.T) {
	reg, ls, priv := cratesTestSetup(t)
	ctx := context.Background()

	// Collect the root crate: the newest non-yanked release plus its normal
	// (renamed) dependency; dev and optional dependencies stay out by default.
	res, err := ls.CollectCrates(ctx, CratesCollectRequest{Crates: []string{"mylib"}})
	if err != nil {
		t.Fatalf("CollectCrates: %v", err)
	}
	if res.BundleID != "crates-bundle-000001" || res.ExportedModules != 2 || res.Skipped || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	for _, p := range []string{
		"/" + crateIndexPath("devdep"),
		"/" + crateIndexPath("optdep"),
		"/dl/mylib/1.1.0/download", // yanked
		"/dl/mylib/0.9.0/download", // not the latest
	} {
		if n := reg.count(p); n != 0 {
			t.Errorf("upstream %s fetched %d time(s), want 0", p, n)
		}
	}
	cratesAssertBundleManifest(t, ls, res.BundleID)

	// Transfer the bundle to a high server and import it.
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	imp, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if !imp.Imported || len(imp.ImportedBundles) != 1 || imp.ImportedBundles[0] != "crates-bundle-000001" {
		t.Fatalf("unexpected import result: %+v", imp)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// config.json advertises this server's own download base (cargo appends
	// /{crate}/{version}/download itself).
	code, body := httpGet(t, srv.URL+"/crates/index/config.json")
	if code != http.StatusOK {
		t.Fatalf("config.json status %d: %s", code, body)
	}
	var regCfg struct {
		DL string `json:"dl"`
	}
	if err := json.Unmarshal([]byte(body), &regCfg); err != nil {
		t.Fatalf("config.json is not JSON: %v\n%s", err, body)
	}
	if want := srv.URL + "/crates/dl"; regCfg.DL != want {
		t.Errorf("config.json dl = %q, want %q", regCfg.DL, want)
	}

	// Only the mirrored release was published — its cksum appears in the
	// served index file — and the .crate bytes round-trip exactly. (Strict
	// one-line-per-version format assertions live in the skipped
	// TestCratesServedIndexLineFormat; the format is currently broken.)
	code, body = httpGet(t, srv.URL+"/crates/index/my/li/mylib")
	if code != http.StatusOK || !strings.Contains(body, aptSHA256(cratesTestPayload("mylib", "1.0.0"))) ||
		strings.Contains(body, "0.9.0") {
		t.Errorf("mylib index: status %d, body %q, want only the 1.0.0 line", code, body)
	}
	code, body = httpGet(t, srv.URL+"/crates/index/3/d/dep")
	if code != http.StatusOK || !strings.Contains(body, aptSHA256(cratesTestPayload("dep", "0.1.5"))) {
		t.Errorf("dep index: status %d, body %q", code, body)
	}
	cratesAssertDownload(t, srv.URL, "mylib", "1.0.0")
	cratesAssertDownload(t, srv.URL, "dep", "0.1.5")
	if code, _ := httpGet(t, srv.URL+"/crates/index/MY/LI/MYLIB"); code != http.StatusOK {
		t.Errorf("mixed-case index path status %d, want 200", code)
	}

	// A second bundle adds the older release; the regenerated index file merges
	// both versions in ascending order and keeps serving the first one.
	noDeps := false
	res2, err := ls.CollectCrates(ctx, CratesCollectRequest{Crates: []string{"mylib@0.9.0"}, ResolveDeps: &noDeps})
	if err != nil {
		t.Fatalf("second CollectCrates: %v", err)
	}
	if res2.BundleID != "crates-bundle-000002" || res2.ExportedModules != 1 {
		t.Fatalf("second collect result: %+v", res2)
	}
	transferAptBundle(t, ls, hs, res2.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("second import: %v", err)
	}
	code, body = httpGet(t, srv.URL+"/crates/index/my/li/mylib")
	if code != http.StatusOK || !strings.Contains(body, aptSHA256(cratesTestPayload("mylib", "0.9.0"))) {
		t.Errorf("mylib index after second import: status %d, body %q", code, body)
	}
	// Both archives stay served byte-identically. (That the index file also
	// still LISTS 1.0.0 after the merge is asserted in the skipped
	// TestCratesServedIndexLineFormat — the current line format makes the
	// merge drop earlier versions.)
	cratesAssertDownload(t, srv.URL, "mylib", "0.9.0")
	cratesAssertDownload(t, srv.URL, "mylib", "1.0.0")

	// Everything already forwarded: the collect skips and burns no sequence.
	res3, err := ls.CollectCrates(ctx, CratesCollectRequest{Crates: []string{"mylib"}})
	if err != nil {
		t.Fatalf("third CollectCrates: %v", err)
	}
	if !res3.Skipped || res3.BundleID != "" {
		t.Fatalf("all-prior collect = %+v, want skipped", res3)
	}
	if seq := ls.peekSequence(streamCrates); seq != 3 {
		t.Errorf("next sequence = %d, want 3 (a skip must not burn a number)", seq)
	}

	// A crate the index does not know (404) cannot resolve; the collect errors.
	_, err = ls.CollectCrates(ctx, CratesCollectRequest{Crates: []string{"nosuchcrate"}})
	if err == nil || !strings.Contains(err.Error(), "no crates could be resolved") {
		t.Fatalf("unknown crate collect = %v, want 'no crates could be resolved'", err)
	}
}

// TestCratesServedIndexLineFormat pins the sparse-index format the high side
// serves: one compact JSON line per mirrored version, ascending, each line's
// cksum equal to the artifact's SHA-256, and later bundles merging into (not
// clobbering) the file. This is a regression test: the bundle manifest is
// written indented, which spreads the embedded raw index line over several
// lines — publishCrateIndex must re-compact it or cargo cannot parse the file
// and the merge parser drops earlier versions.
func TestCratesServedIndexLineFormat(t *testing.T) {
	_, ls, priv := cratesTestSetup(t)
	ctx := context.Background()
	res, err := ls.CollectCrates(ctx, CratesCollectRequest{Crates: []string{"mylib"}})
	if err != nil {
		t.Fatalf("CollectCrates: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Exactly one line per mirrored release, cksum matching the artifact.
	cratesAssertServedIndex(t, srv.URL, "mylib", "1.0.0")
	cratesAssertServedIndex(t, srv.URL, "dep", "0.1.5")

	// A later bundle merges: the index file lists both versions ascending and
	// keeps serving the earlier one.
	noDeps := false
	res2, err := ls.CollectCrates(ctx, CratesCollectRequest{Crates: []string{"mylib@0.9.0"}, ResolveDeps: &noDeps})
	if err != nil {
		t.Fatalf("second CollectCrates: %v", err)
	}
	transferAptBundle(t, ls, hs, res2.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("second import: %v", err)
	}
	cratesAssertServedIndex(t, srv.URL, "mylib", "0.9.0", "1.0.0")
}

// TestCratesDashboardListAndDetail covers the high-side dashboard helpers over
// an imported bundle: package/version listing (with junk filtered out) and the
// per-version detail panel.
func TestCratesDashboardListAndDetail(t *testing.T) {
	_, ls, priv := cratesTestSetup(t)
	res, err := ls.CollectCrates(context.Background(), CratesCollectRequest{Crates: []string{"mylib"}})
	if err != nil {
		t.Fatalf("CollectCrates: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Junk in the archive store is filtered out of the listings: stray files,
	// foreign filenames, and an invalidly named directory.
	junkDir := filepath.Join(hs.cratesFilesDir(), "mylib")
	writeFile(t, filepath.Join(junkDir, "README.txt"), []byte("junk"))
	writeFile(t, filepath.Join(junkDir, "other-1.0.0.crate"), []byte("junk"))
	if err := os.MkdirAll(filepath.Join(hs.cratesFilesDir(), ".hidden"), 0o755); err != nil {
		t.Fatal(err)
	}

	mods, err := hs.listCratesPackages()
	if err != nil {
		t.Fatalf("listCratesPackages: %v", err)
	}
	if len(mods) != 2 || mods[0].Module != "dep" || mods[1].Module != "mylib" {
		t.Fatalf("listCratesPackages = %+v, want dep and mylib", mods)
	}
	if strings.Join(mods[0].Versions, " ") != "0.1.5" || strings.Join(mods[1].Versions, " ") != "1.0.0" {
		t.Errorf("listed versions = %+v", mods)
	}

	det, err := hs.cratesDetail("mylib@1.0.0")
	if err != nil {
		t.Fatalf("cratesDetail: %v", err)
	}
	if det.Title != "mylib" || det.Subtitle != "1.0.0" {
		t.Errorf("detail identity = %q %q, want mylib 1.0.0", det.Title, det.Subtitle)
	}
	if len(det.Downloads) != 1 || det.Downloads[0].URL != "/crates/dl/mylib/1.0.0/download" ||
		det.Downloads[0].Label != "mylib-1.0.0.crate" {
		t.Errorf("detail downloads = %+v", det.Downloads)
	}
	fields := map[string]string{}
	for _, f := range det.Fields {
		fields[f.Label] = f.Value
	}
	if fields["SHA-256"] != aptSHA256(cratesTestPayload("mylib", "1.0.0")) {
		t.Errorf("detail SHA-256 = %q", fields["SHA-256"])
	}
	if fields["Index path"] != "/crates/index/my/li/mylib" {
		t.Errorf("detail index path = %q", fields["Index path"])
	}

	for _, spec := range []string{"mylib@9.9.9", "nope", "..@1.0.0", "mylib@../etc"} {
		if _, err := hs.cratesDetail(spec); err == nil {
			t.Errorf("cratesDetail(%q) = nil error, want error", spec)
		}
	}
}

// TestCratesRouteHardening checks the /crates/ routes reject traversal, odd
// shapes, and non-read methods without serving anything.
func TestCratesRouteHardening(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	for _, p := range []string{
		"/crates",
		"/crates/",
		"/crates/index/",
		"/crates/index/../../etc",
		"/crates/index/..%2f..%2fimport-state.json",
		"/crates/index//etc/passwd",
		"/crates/dl/../x/download",
		"/crates/dl/..%2f..%2fx/download",
		"/crates/dl/mylib/1.0.0",
		"/crates/dl/mylib/1.0.0/steal",
		"/crates/dl/mylib/1.0.0/download/extra",
		"/crates/dl/-flag/1.0.0/download",
		"/crates/dl/mylib/v1.0.0/download",
	} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("GET %s = 200, want rejection", p)
		}
	}

	resp, err := http.Post(srv.URL+"/crates/index/config.json", "application/json", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST config.json status = %d, want 405", resp.StatusCode)
	}
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/crates/dl/mylib/1.0.0/download", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE download status = %d, want 405", resp.StatusCode)
	}
}

// cratesWriteSignedBundle assembles a signed crates bundle in landing from raw
// payloads (keyed by repository-relative path) and the given crate records,
// reusing the production tar/sign helpers. Records are taken verbatim so tests
// can craft inconsistent manifests.
func cratesWriteSignedBundle(t *testing.T, landing string, priv ed25519.PrivateKey, seq int64, records []CrateVersion, payloads map[string][]byte) {
	t.Helper()
	src := t.TempDir()
	var files []ManifestFile
	for rel, content := range payloads {
		abs := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, content)
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, mf)
	}
	bundleID := bundleIDFor(streamCrates, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamCrates,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Ecosystems:       []string{"crates"},
		Crates:           &CratesManifest{Crates: records},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestBytes)
	if err := os.MkdirAll(landing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createTarGzAtomic(context.Background(), filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json"), manifestBytes)
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
}

// TestCratesImportRejectsTamperedRecord proves the import-side validator is
// wired in: a signed bundle whose index line cksum disagrees with the record's
// own artifact hash is rejected as a whole, and nothing from it is served.
func TestCratesImportRejectsTamperedRecord(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	payload := cratesTestPayload("mylib", "1.0.0")
	rel := crateFileRel("mylib", "1.0.0")
	rec := CrateVersion{
		Name: "mylib", Version: "1.0.0", Path: rel, SHA256: aptSHA256(payload),
		IndexLine: json.RawMessage(fmt.Sprintf(`{"name":"mylib","vers":"1.0.0","cksum":%q}`, aptSHA256([]byte("tampered")))),
	}
	cratesWriteSignedBundle(t, hs.cfg.Landing, priv, 1, []CrateVersion{rec}, map[string][]byte{rel: payload})

	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if res.Imported || len(res.RejectedBundles) != 1 || res.RejectedBundles[0] != "crates-bundle-000001" {
		t.Fatalf("import result = %+v, want the bundle rejected", res)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	if code, _ := httpGet(t, srv.URL+"/crates/dl/mylib/1.0.0/download"); code == http.StatusOK {
		t.Error("rejected bundle's crate must not be served")
	}
	if code, _ := httpGet(t, srv.URL+"/crates/index/my/li/mylib"); code == http.StatusOK {
		t.Error("rejected bundle's index file must not be served")
	}
}

// TestCratesImportCksumMustMatchDeliveredArtifact documents a hardening gap in
// crates.go. Its stated contract is that the high side "never serves a line
// whose cksum does not equal the byte-verified artifact's SHA-256 (checked
// again at import)". validateCrateRecord checks the index line's cksum against
// the record's own SHA256 claim, and the installer checks manifest.files
// hashes against the delivered bytes — but nothing ties the record's SHA256
// claim to the manifest.files entry for the same path. A signed manifest
// carrying a self-consistent wrong pair (record.SHA256 == line.cksum !=
// files[].sha256) therefore imports, and the high side serves an index line
// whose cksum can never verify against the artifact it points at. cargo fails
// closed on download, so the impact is a poisoned, uninstallable index entry
// rather than a compromise, but the documented invariant is not enforced.
func TestCratesImportCksumMustMatchDeliveredArtifact(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	payload := cratesTestPayload("mylib", "1.0.0") // the delivered, byte-verified artifact
	wrong := aptSHA256([]byte("not the delivered bytes"))
	rel := crateFileRel("mylib", "1.0.0")
	rec := CrateVersion{
		Name: "mylib", Version: "1.0.0", Path: rel, SHA256: wrong,
		IndexLine: json.RawMessage(fmt.Sprintf(`{"name":"mylib","vers":"1.0.0","cksum":%q}`, wrong)),
	}
	cratesWriteSignedBundle(t, hs.cfg.Landing, priv, 1, []CrateVersion{rec}, map[string][]byte{rel: payload})

	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	// Expected behavior per the module's contract: the bundle is rejected, or
	// at minimum the inconsistent line is never served.
	if res.Imported {
		srv := httptest.NewServer(hs)
		defer srv.Close()
		_, body := httpGet(t, srv.URL+"/crates/index/my/li/mylib")
		if strings.Contains(body, wrong) {
			t.Error("served index line carries a cksum that does not match the byte-verified artifact")
		}
	}
}
