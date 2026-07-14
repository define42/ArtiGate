package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

func galaxyTestSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// galaxyTestTgz builds a collection archive with an embedded MANIFEST.json
// declaring the given identity and dependencies. member names the manifest's
// tar entry so tests can cover the "./MANIFEST.json" form or omit it ("").
func galaxyTestTgz(t *testing.T, member, ns, name, version string, deps map[string]string) []byte {
	t.Helper()
	info := map[string]any{"namespace": ns, "name": name, "version": version, "dependencies": deps}
	manifest, err := json.Marshal(map[string]any{"collection_info": info, "format": 1})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := []struct {
		name string
		body []byte
	}{
		{member, manifest},
		{"FILES.json", []byte(`{"files":[]}`)},
		{"plugins/README.md", []byte("mirrored test collection for " + ns + "." + name + "\n")},
	}
	for _, f := range files {
		if f.name == "" {
			continue
		}
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// galaxyTestCollection builds a well-formed collection archive.
func galaxyTestCollection(t *testing.T, ns, name, version string, deps map[string]string) []byte {
	t.Helper()
	return galaxyTestTgz(t, "MANIFEST.json", ns, name, version, deps)
}

// galaxyTestVersion is one published version of a fake upstream collection.
type galaxyTestVersion struct {
	version string
	deps    map[string]string
	body    []byte
	absURL  bool   // render download_url absolute instead of server-relative
	badName bool   // declare a non-canonical artifact filename
	badSHA  string // declare this sha256 instead of the body's real one
}

// fakeGalaxyUpstream serves the Galaxy v3 endpoints the collector uses:
// collection pages, (optionally paginated) version lists, version details,
// and artifact downloads. cols maps "ns.name" to its versions.
func fakeGalaxyUpstream(t *testing.T, cols map[string][]galaxyTestVersion, pageSize int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if file, ok := strings.CutPrefix(r.URL.Path, "/artifacts/"); ok {
			galaxyUpstreamArtifact(w, r, cols, file)
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/api/v3/collections/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		segs := strings.Split(strings.Trim(rest, "/"), "/")
		if len(segs) < 2 {
			http.NotFound(w, r)
			return
		}
		ns, name := segs[0], segs[1]
		vs, ok := cols[ns+"."+name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(segs) == 2:
			galaxyUpstreamCollectionPage(w, vs)
		case len(segs) == 3 && segs[2] == "versions":
			galaxyUpstreamVersionList(w, r, ns, name, vs, pageSize)
		case len(segs) == 4 && segs[2] == "versions":
			galaxyUpstreamVersionDetail(w, r, ns, name, vs, segs[3])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func galaxyUpstreamJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func galaxyUpstreamArtifact(w http.ResponseWriter, r *http.Request, cols map[string][]galaxyTestVersion, file string) {
	for key, vs := range cols {
		ns, name, _ := strings.Cut(key, ".")
		for _, v := range vs {
			if file == ns+"-"+name+"-"+v.version+".tar.gz" {
				_, _ = w.Write(v.body)
				return
			}
		}
	}
	http.NotFound(w, r)
}

func galaxyUpstreamCollectionPage(w http.ResponseWriter, vs []galaxyTestVersion) {
	highest := ""
	for _, v := range vs {
		if highest == "" || galaxyVersionLess(highest, v.version) {
			highest = v.version
		}
	}
	galaxyUpstreamJSON(w, map[string]any{"highest_version": map[string]any{"version": highest}})
}

// galaxyUpstreamVersionList pages through the versions with relative
// links.next URLs, like galaxy.ansible.com's pulp-backed API does.
func galaxyUpstreamVersionList(w http.ResponseWriter, r *http.Request, ns, name string, vs []galaxyTestVersion, pageSize int) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 || offset > len(vs) {
		offset = len(vs)
	}
	end := len(vs)
	var next any
	if pageSize > 0 && offset+pageSize < len(vs) {
		end = offset + pageSize
		next = "/api/v3/collections/" + ns + "/" + name + "/versions/?limit=" + strconv.Itoa(pageSize) + "&offset=" + strconv.Itoa(end)
	}
	data := make([]map[string]any, 0, end-offset)
	for _, v := range vs[offset:end] {
		data = append(data, map[string]any{"version": v.version})
	}
	galaxyUpstreamJSON(w, map[string]any{
		"meta":  map[string]any{"count": len(vs)},
		"links": map[string]any{"next": next},
		"data":  data,
	})
}

func galaxyUpstreamVersionDetail(w http.ResponseWriter, r *http.Request, ns, name string, vs []galaxyTestVersion, version string) {
	for _, v := range vs {
		if v.version != version {
			continue
		}
		file := ns + "-" + name + "-" + version + ".tar.gz"
		declared := file
		if v.badName {
			declared = "wrong-" + file
		}
		sum := galaxyTestSHA256(v.body)
		if v.badSHA != "" {
			sum = v.badSHA
		}
		dl := "/artifacts/" + file
		if v.absURL {
			dl = "http://" + r.Host + dl
		}
		galaxyUpstreamJSON(w, map[string]any{
			"artifact":     map[string]any{"filename": declared, "sha256": sum, "size": len(v.body)},
			"download_url": dl,
			"metadata":     map[string]any{"dependencies": v.deps},
		})
		return
	}
	http.NotFound(w, r)
}

func newGalaxyLowServer(t *testing.T, serverURL string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), GalaxyServerURL: serverURL}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// galaxyManifestFromExport reads one exported bundle's manifest and requires
// galaxy content in it.
func galaxyManifestFromExport(t *testing.T, ls *LowServer, bundleID string) BundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Galaxy == nil || len(m.Galaxy.Collections) == 0 {
		t.Fatalf("manifest carries no galaxy collections: %s", b)
	}
	return m
}

// galaxyTestHigh lands collected galaxy bundles on a fresh high server by
// unpacking each bundle archive into the repository and running the publish
// hook — the registry-independent core of an import.
func galaxyTestHigh(t *testing.T, ls *LowServer, pub ed25519.PublicKey, bundleIDs ...string) *HighServer {
	t.Helper()
	hs := newTestHighServer(t, pub)
	for _, id := range bundleIDs {
		m := galaxyManifestFromExport(t, ls, id)
		if err := extractTarGzTree(filepath.Join(ls.cfg.ExportDir, id+".tar.gz"), hs.downloadDir); err != nil {
			t.Fatal(err)
		}
		if err := hs.publishGalaxy(m.Galaxy); err != nil {
			t.Fatal(err)
		}
	}
	return hs
}

// galaxyTestServer serves just the galaxy routes of a high server (the full
// serve chain is registry-driven and the galaxy stream registers later).
func galaxyTestServer(t *testing.T, hs *HighServer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hs.serveGalaxy(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// -----------------------------------------------------------------------------
// Unit: descriptor, naming, specs
// -----------------------------------------------------------------------------

func TestGalaxyEcosystemDescriptor(t *testing.T) {
	eco := galaxyEcosystem()
	if eco.stream != streamGalaxy || eco.label != "Ansible" || eco.contentDesc != "ansible collections" {
		t.Errorf("unexpected descriptor identity: %q/%q/%q", eco.stream, eco.label, eco.contentDesc)
	}
	if eco.collect == nil || eco.watchCollect == nil || eco.validateContent == nil ||
		eco.publish == nil || eco.serve == nil || eco.scanTree == nil || eco.detail == nil {
		t.Error("descriptor leaves hooks nil")
	}

	fs := flag.NewFlagSet("galaxy-test", flag.ContinueOnError)
	var cfg LowConfig
	eco.flags(fs, &cfg)
	if err := fs.Parse([]string{"-galaxy-server", "http://galaxy.example"}); err != nil {
		t.Fatal(err)
	}
	if cfg.GalaxyServerURL != "http://galaxy.example" {
		t.Errorf("galaxy-server flag wired to %q", cfg.GalaxyServerURL)
	}

	m := BundleManifest{Galaxy: &GalaxyManifest{Collections: []GalaxyCollection{{}}}}
	if !eco.manifestContent(m) || eco.manifestContent(BundleManifest{}) {
		t.Error("manifestContent misreports galaxy content")
	}
	// The publish hook must no-op on a manifest without galaxy content.
	pub, _ := newTestKeys(t)
	if err := eco.publish(newTestHighServer(t, pub), BundleManifest{}); err != nil {
		t.Errorf("publish on empty manifest: %v", err)
	}
}

func TestGalaxyValidateNamesAndVersions(t *testing.T) {
	validNames := []string{"ansible", "posix", "a", "a0", "my_ns2", strings.Repeat("x", 64)}
	invalidNames := []string{"", "_lead", "Upper", "dot.ted", "da-sh", "a b", "..", strings.Repeat("x", 65)}
	for _, n := range validNames {
		if err := validateGalaxyName(n); err != nil {
			t.Errorf("validateGalaxyName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateGalaxyName(n); err == nil {
			t.Errorf("validateGalaxyName(%q) = nil, want error", n)
		}
	}

	validVersions := []string{"1.5.4", "0.0.1", "2.0.0-beta.1", "1.0.0+build.5", "10.20.30"}
	invalidVersions := []string{"", "1", "1.2", "v1.2.3", "latest", "-1.0.0", "1.2.3/..", "1.2.3 "}
	for _, v := range validVersions {
		if err := validateGalaxyVersion(v); err != nil {
			t.Errorf("validateGalaxyVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVersions {
		if err := validateGalaxyVersion(v); err == nil {
			t.Errorf("validateGalaxyVersion(%q) = nil, want error", v)
		}
	}
}

func TestGalaxyParseSpec(t *testing.T) {
	tests := []struct {
		spec, ns, name, version string
		wantErr                 bool
	}{
		{"ansible.posix", "ansible", "posix", "", false},
		{"ansible.posix@1.5.4", "ansible", "posix", "1.5.4", false},
		{"ansible.posix@latest", "ansible", "posix", "", false},
		{" ansible.posix ", "ansible", "posix", "", false},
		{"posix", "", "", "", true},
		{"Ansible.posix", "", "", "", true},
		{"ansible.posix@^1.0", "", "", "", true},
		{"ansible.posix@1.5", "", "", "", true},
		{"a.b.c", "", "", "", true}, // "b.c" is not a valid name
	}
	for _, tt := range tests {
		ns, name, version, err := parseGalaxySpec(tt.spec)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseGalaxySpec(%q) = %q/%q/%q, want error", tt.spec, ns, name, version)
			}
			continue
		}
		if err != nil || ns != tt.ns || name != tt.name || version != tt.version {
			t.Errorf("parseGalaxySpec(%q) = %q/%q/%q, %v; want %q/%q/%q",
				tt.spec, ns, name, version, err, tt.ns, tt.name, tt.version)
		}
	}
}

func TestGalaxyParseArtifactFilename(t *testing.T) {
	tests := []struct {
		file, ns, name, version string
		ok                      bool
	}{
		{"ansible-posix-1.5.4.tar.gz", "ansible", "posix", "1.5.4", true},
		{"acme-web-2.0.0-beta.1.tar.gz", "acme", "web", "2.0.0-beta.1", true},
		{"ansible-posix-1.5.4.zip", "", "", "", false},
		{"ansibleposix1.5.4.tar.gz", "", "", "", false},
		{"ansible-posix-latest.tar.gz", "", "", "", false},
		{"../x-posix-1.5.4.tar.gz", "", "", "", false},
	}
	for _, tt := range tests {
		ns, name, version, ok := galaxyParseArtifactFilename(tt.file)
		if ns != tt.ns || name != tt.name || version != tt.version || ok != tt.ok {
			t.Errorf("galaxyParseArtifactFilename(%q) = %q/%q/%q/%v, want %q/%q/%q/%v",
				tt.file, ns, name, version, ok, tt.ns, tt.name, tt.version, tt.ok)
		}
	}
}

func TestGalaxyResolveURL(t *testing.T) {
	base := "https://galaxy.example/sub"
	tests := []struct {
		ref, want string
		wantErr   bool
	}{
		{"https://cdn.example/a.tar.gz", "https://cdn.example/a.tar.gz", false},
		{"/api/v3/x/?limit=2&offset=2", "https://galaxy.example/api/v3/x/?limit=2&offset=2", false},
		{"artifacts/a.tar.gz", "https://galaxy.example/sub/artifacts/a.tar.gz", false},
		{"ftp://evil.example/x", "", true},
	}
	for _, tt := range tests {
		got, err := galaxyResolveURL(base, tt.ref)
		if tt.wantErr {
			if err == nil {
				t.Errorf("galaxyResolveURL(%q) = %q, want error", tt.ref, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("galaxyResolveURL(%q) = %q, %v; want %q", tt.ref, got, err, tt.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: semver constraints
// -----------------------------------------------------------------------------

func TestGalaxySemverMatch(t *testing.T) {
	tests := []struct {
		constraint, version string
		want                bool
	}{
		{"*", "1.2.3", true},
		{"*", "2.0.0-beta.1", false}, // prerelease needs a constraint that names one
		{"*", "not.a.version", false},
		{"", "1.2.3", true},
		{">=1.0.0", "1.0.0", true},
		{">=1.0.0", "0.9.9", false},
		{">1.0.0", "1.0.1", true},
		{">1.0.0", "1.0.0", false},
		{"<1.0.0", "1.0.0", false},
		{"<=1.0.0", "1.0.0", true},
		{">=1.0.0,<2.0.0", "1.9.9", true},
		{">=1.0.0,<2.0.0", "2.0.0", false},
		{">=1.0.0,<2.0.0", "0.9.0", false},
		{">= 1.0.0, < 2.0.0", "1.5.0", true}, // spaces tolerated
		{"==1.2.3", "1.2.3", true},
		{"=1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.3", true},
		{"==1.2.3", "1.2.4", false},
		{"==1.2.3", "1.2.3+build.7", true}, // build metadata ignored
		{"!=1.2.3", "1.2.4", true},
		{"!=1.2.3", "1.2.3", false},
		{">=2.0.0-beta.1", "2.0.0-beta.2", true}, // constraint names a prerelease
		{">=2.0.0-beta.1", "2.0.0", true},
		{">=2.0.0-beta.1", "1.9.0", false},
		{"^1.2", "1.9.9", true},
		{"^1.2", "2.0.0", false},
		{"^1.2", "1.1.0", false},
		{"^0.1.2", "0.1.9", true},
		{"^0.1.2", "0.2.0", false},
		{"^0.0.3", "0.0.3", true},
		{"^0.0.3", "0.0.4", false},
		{"~1.2", "1.2.9", true},
		{"~1.2", "1.3.0", false},
		{"~1.2.3", "1.2.2", false},
		{"~1.2.3", "1.2.9", true},
		{"~1", "1.9.9", true},
		{"~1", "2.0.0", false},
		{"garbage", "1.2.3", false},
		{">=x", "1.0.0", false},
	}
	for _, tt := range tests {
		if got := galaxySemverMatch(tt.constraint, tt.version); got != tt.want {
			t.Errorf("galaxySemverMatch(%q, %q) = %v, want %v", tt.constraint, tt.version, got, tt.want)
		}
	}
}

func TestGalaxyPickVersion(t *testing.T) {
	vs := []string{"0.9.0", "1.0.0", "1.2.0", "2.1.0", "3.0.0-rc.1"}
	pick := func(constraint string) string {
		t.Helper()
		c, err := galaxyParseConstraint(constraint)
		if err != nil {
			t.Fatalf("parse %q: %v", constraint, err)
		}
		v, _ := galaxyPickVersion(vs, c)
		return v
	}
	if got := pick(">=1.0.0,<2.0.0"); got != "1.2.0" {
		t.Errorf("range pick = %q, want 1.2.0", got)
	}
	if got := pick("*"); got != "2.1.0" {
		t.Errorf("wildcard pick = %q, want 2.1.0 (prerelease excluded)", got)
	}
	if got := pick(">=3.0.0-rc.0"); got != "3.0.0-rc.1" {
		t.Errorf("prerelease-naming pick = %q, want 3.0.0-rc.1", got)
	}
	if got := pick(">=9.0.0"); got != "" {
		t.Errorf("unsatisfiable pick = %q, want none", got)
	}

	// The exact shortcut only fires for full three-part equality pins.
	for constraint, want := range map[string]string{"==1.2.3": "1.2.3", "1.2.3": "1.2.3", ">=1.0.0": "", "~1.2.3": "", "==1.2": ""} {
		c, err := galaxyParseConstraint(constraint)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := c.exact()
		if got != want || ok != (want != "") {
			t.Errorf("exact(%q) = %q/%v, want %q", constraint, got, ok, want)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: import-side manifest validation
// -----------------------------------------------------------------------------

func TestGalaxyValidateCollections(t *testing.T) {
	canon := GalaxyCollection{
		Namespace: "ansible", Name: "posix", Version: "1.5.4",
		Filename: "ansible-posix-1.5.4.tar.gz",
		Path:     "galaxy/collections/ansible/posix/ansible-posix-1.5.4.tar.gz",
		SHA256:   strings.Repeat("a", 64),
	}
	seen := map[string]bool{canon.Path: true}
	if err := validateGalaxyCollections([]GalaxyCollection{canon}, seen); err != nil {
		t.Errorf("valid collection rejected: %v", err)
	}

	mutate := func(f func(*GalaxyCollection)) []GalaxyCollection {
		c := canon
		f(&c)
		return []GalaxyCollection{c}
	}
	bad := []struct {
		name string
		cols []GalaxyCollection
		seen map[string]bool
	}{
		{"bad namespace", mutate(func(c *GalaxyCollection) { c.Namespace = "../x" }), seen},
		{"bad name", mutate(func(c *GalaxyCollection) { c.Name = "Posix" }), seen},
		{"bad version", mutate(func(c *GalaxyCollection) { c.Version = "latest" }), seen},
		{"non-canonical filename", mutate(func(c *GalaxyCollection) { c.Filename = "posix.tar.gz" }), seen},
		{"wrong path", mutate(func(c *GalaxyCollection) { c.Path = "galaxy/collections/posix.tar.gz" }), seen},
		{"path not in seen map", []GalaxyCollection{canon}, map[string]bool{}},
	}
	for _, tt := range bad {
		if err := validateGalaxyCollections(tt.cols, tt.seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration: collect -> publish -> serve pipeline
// -----------------------------------------------------------------------------

// TestGalaxyCollectPipeline mirrors a dependency chain from a fake Galaxy v3
// upstream — a latest-version request whose dependencies use a two-page
// paginated range constraint, a "*" constraint (prerelease excluded), and a
// missing collection — plus a pinned request, then publishes the bundles on
// a high server and asserts the regenerated v3 API end to end.
func TestGalaxyCollectPipeline(t *testing.T) {
	webDeps := map[string]string{"acme.db": ">=1.0.0,<2.0.0", "acme.util": "*", "acme.gone": "*"}
	web200 := galaxyTestCollection(t, "acme", "web", "2.0.0", webDeps)
	web100 := galaxyTestCollection(t, "acme", "web", "1.0.0", nil)
	db120 := galaxyTestCollection(t, "acme", "db", "1.2.0", nil)
	util050 := galaxyTestCollection(t, "acme", "util", "0.5.0", nil)
	pin100 := galaxyTestCollection(t, "acme", "pin", "1.0.0", map[string]string{"acme.web": "*"})
	upstream := fakeGalaxyUpstream(t, map[string][]galaxyTestVersion{
		"acme.web": {
			{version: "1.0.0", body: web100},
			{version: "2.0.0", deps: webDeps, body: web200, absURL: true},
		},
		// Four versions across two pages (pageSize 2): the range constraint
		// must follow links.next and still pick 1.2.0.
		"acme.db": {
			{version: "0.9.0"},
			{version: "1.0.0"},
			{version: "1.2.0", body: db120},
			{version: "2.1.0"},
		},
		// "*" must skip the newer prerelease.
		"acme.util": {
			{version: "0.5.0", body: util050}, {version: "1.0.0-rc.1"},
		},
		"acme.pin": {
			{version: "1.0.0", deps: map[string]string{"acme.web": "*"}, body: pin100},
		},
	}, 2)

	ls, priv := newGalaxyLowServer(t, upstream.URL)
	res, err := ls.CollectGalaxy(context.Background(), GalaxyCollectRequest{
		Collections: []string{"acme.web", "acme.pin@1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectGalaxy: %v", err)
	}
	if res.BundleID != "galaxy-bundle-000001" || res.ExportedModules != 4 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	// acme.gone failed and was reported; acme.web was deduplicated when it
	// came back around as acme.pin's dependency.
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "acme.gone" {
		t.Fatalf("expected acme.gone in SkippedModules, got %+v", res.SkippedModules)
	}

	m := galaxyManifestFromExport(t, ls, res.BundleID)
	got := map[string]string{}
	for _, c := range m.Galaxy.Collections {
		got[c.Namespace+"."+c.Name] = c.Version
	}
	want := map[string]string{"acme.web": "2.0.0", "acme.db": "1.2.0", "acme.util": "0.5.0", "acme.pin": "1.0.0"}
	if !maps.Equal(got, want) {
		t.Fatalf("collected versions = %v, want %v", got, want)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateGalaxyCollections(m.Galaxy.Collections, seen); err != nil {
		t.Fatalf("exported manifest fails content validation: %v", err)
	}

	// A second collect pins the older web release into a second bundle.
	res2, err := ls.CollectGalaxy(context.Background(), GalaxyCollectRequest{
		Collections: []string{"acme.web@1.0.0"},
	})
	if err != nil {
		t.Fatalf("second CollectGalaxy: %v", err)
	}
	if res2.BundleID != "galaxy-bundle-000002" || res2.ExportedModules != 1 {
		t.Fatalf("unexpected second collect result: %+v", res2)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := galaxyTestHigh(t, ls, pub, res.BundleID, res2.BundleID)
	srv := galaxyTestServer(t, hs)

	assertGalaxyDiscovery(t, srv.URL)
	assertGalaxyCollectionPage(t, srv.URL)
	assertGalaxyVersionList(t, srv.URL)
	assertGalaxyVersionDetail(t, srv.URL, web200)
	assertGalaxyTreeAndDetail(t, hs)
	assertGalaxyGating(t, hs, srv.URL)
	assertGalaxyHardening(t, srv.URL)
}

func assertGalaxyDiscovery(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/galaxy/api/")
	if code != http.StatusOK {
		t.Fatalf("api discovery status %d: %s", code, body)
	}
	var disc struct {
		Available map[string]string `json:"available_versions"`
	}
	if err := json.Unmarshal([]byte(body), &disc); err != nil || disc.Available["v3"] != "v3/" {
		t.Errorf("api discovery advertises %v (err %v): %s", disc.Available, err, body)
	}
}

func assertGalaxyCollectionPage(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/galaxy/api/v3/collections/acme/web/")
	if code != http.StatusOK {
		t.Fatalf("collection page status %d: %s", code, body)
	}
	var page struct {
		Href      string
		Namespace string
		Name      string
		Highest   struct {
			Href    string
			Version string
		} `json:"highest_version"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatal(err)
	}
	if page.Namespace != "acme" || page.Name != "web" || page.Highest.Version != "2.0.0" {
		t.Errorf("collection page = %+v", page)
	}
	if page.Href != base+"/galaxy/api/v3/collections/acme/web/" ||
		page.Highest.Href != base+"/galaxy/api/v3/collections/acme/web/versions/2.0.0/" {
		t.Errorf("collection page hrefs not absolute: %+v", page)
	}
	// The slashless form serves identically.
	if code2, body2 := httpGet(t, base+"/galaxy/api/v3/collections/acme/web"); code2 != http.StatusOK || body2 != body {
		t.Errorf("slashless collection page: status %d, body equal %v", code2, body2 == body)
	}
}

func assertGalaxyVersionList(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/galaxy/api/v3/collections/acme/web/versions/?limit=1&offset=7")
	if code != http.StatusOK {
		t.Fatalf("version list status %d: %s", code, body)
	}
	var list struct {
		Meta  struct{ Count int }
		Links struct {
			First string
			Next  *string
		}
		Data []struct {
			Version string
			Href    string
		}
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	// Everything on one page, newest first; limit/offset are ignored.
	if list.Meta.Count != 2 || len(list.Data) != 2 || list.Data[0].Version != "2.0.0" || list.Data[1].Version != "1.0.0" {
		t.Errorf("version list = %s", body)
	}
	if list.Links.Next != nil || list.Links.First != base+"/galaxy/api/v3/collections/acme/web/versions/" {
		t.Errorf("version list links = %s", body)
	}
	if list.Data[0].Href != base+"/galaxy/api/v3/collections/acme/web/versions/2.0.0/" {
		t.Errorf("version href = %q", list.Data[0].Href)
	}
}

func assertGalaxyVersionDetail(t *testing.T, base string, web200 []byte) {
	t.Helper()
	code, body := httpGet(t, base+"/galaxy/api/v3/collections/acme/web/versions/2.0.0/")
	if code != http.StatusOK {
		t.Fatalf("version detail status %d: %s", code, body)
	}
	var detail struct {
		Artifact struct {
			Filename string
			SHA256   string `json:"sha256"`
			Size     int64
		}
		Collection  struct{ Name, Href string }
		Namespace   struct{ Name string }
		DownloadURL string `json:"download_url"`
		Href        string
		Metadata    struct{ Dependencies map[string]string }
	}
	if err := json.Unmarshal([]byte(body), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Artifact.Filename != "acme-web-2.0.0.tar.gz" ||
		detail.Artifact.SHA256 != galaxyTestSHA256(web200) ||
		detail.Artifact.Size != int64(len(web200)) {
		t.Errorf("version detail artifact = %+v", detail.Artifact)
	}
	if detail.DownloadURL != base+"/galaxy/download/acme-web-2.0.0.tar.gz" {
		t.Errorf("download_url = %q, want absolute mirror URL", detail.DownloadURL)
	}
	if detail.Namespace.Name != "acme" || detail.Collection.Name != "web" || detail.Href == "" {
		t.Errorf("version detail identity = %s", body)
	}
	// Dependencies come from the artifact's own embedded MANIFEST.json.
	if detail.Metadata.Dependencies["acme.db"] != ">=1.0.0,<2.0.0" {
		t.Errorf("version detail dependencies = %v", detail.Metadata.Dependencies)
	}

	// The advertised artifact downloads with the exact collected bytes.
	if code, got := httpGet(t, detail.DownloadURL); code != http.StatusOK || got != string(web200) {
		t.Errorf("artifact download: status %d, %d bytes (want %d)", code, len(got), len(web200))
	}
}

func assertGalaxyTreeAndDetail(t *testing.T, hs *HighServer) {
	t.Helper()
	mods, err := hs.listGalaxyCollections()
	if err != nil {
		t.Fatal(err)
	}
	byModule := map[string][]string{}
	for _, m := range mods {
		byModule[m.Module] = m.Versions
	}
	if got := byModule["acme/web"]; len(got) != 2 || got[0] != "1.0.0" || got[1] != "2.0.0" {
		t.Errorf("tree versions for acme/web = %v, want [1.0.0 2.0.0]", got)
	}
	if _, ok := byModule["acme/util"]; !ok {
		t.Errorf("tree misses acme/util: %+v", mods)
	}

	d, err := hs.galaxyDetail("acme/web@2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if d.Title != "acme.web" || d.Subtitle != "2.0.0" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/galaxy/download/acme-web-2.0.0.tar.gz" {
		t.Errorf("detail downloads = %+v", d.Downloads)
	}
	var depsField string
	for _, f := range d.Fields {
		if f.Label == "Dependencies" {
			depsField = f.Value
		}
	}
	if !strings.Contains(depsField, "acme.db >=1.0.0,<2.0.0") {
		t.Errorf("detail dependencies field = %q", depsField)
	}
	if _, err := hs.galaxyDetail("acme/web@9.9.9"); err == nil {
		t.Error("missing version detail should error")
	}
	if _, err := hs.galaxyDetail("acme-web@2.0.0"); err == nil {
		t.Error("malformed detail spec should error")
	}
}

// assertGalaxyGating removes one artifact and proves every route for it
// 404s (stored metadata alone must never be served).
func assertGalaxyGating(t *testing.T, hs *HighServer, base string) {
	t.Helper()
	abs := filepath.Join(hs.downloadDir, "galaxy", "collections", "acme", "util", "acme-util-0.5.0.tar.gz")
	if err := os.Remove(abs); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/galaxy/api/v3/collections/acme/util/",
		"/galaxy/api/v3/collections/acme/util/versions/",
		"/galaxy/api/v3/collections/acme/util/versions/0.5.0/",
		"/galaxy/download/acme-util-0.5.0.tar.gz",
	} {
		if code, _ := httpGet(t, base+p); code != http.StatusNotFound {
			t.Errorf("GET %s after artifact removal = %d, want 404", p, code)
		}
	}
	if _, err := hs.galaxyDetail("acme/util@0.5.0"); err == nil {
		t.Error("detail should fail once the artifact is gone")
	}
}

func assertGalaxyHardening(t *testing.T, base string) {
	t.Helper()
	// Non-read methods are rejected.
	resp, err := http.Post(base+"/galaxy/api/", "application/json", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /galaxy/api/ status %d, want 405", resp.StatusCode)
	}
	// Everything else 404s: the bare root, other API versions, partial
	// collection paths, unknown artifacts, and traversal attempts.
	for _, p := range []string{
		"/galaxy/",
		"/galaxy/api/v2/",
		"/galaxy/api/v3/collections/acme/",
		"/galaxy/api/v3/collections/acme/nope/",
		"/galaxy/api/v3/collections/acme/web/versions/2.0.0/extra/",
		"/galaxy/download/nope-nope-9.9.9.tar.gz",
		"/galaxy/download/..%2fweb%2facme-web-2.0.0.tar.gz",
		"/galaxy/download/acme-web-2.0.0.json",
		"/galaxy/metadata/acme/web/2.0.0.json",
	} {
		if code, _ := httpGet(t, base+p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
}

// TestGalaxyCollectVerifiesSHA256 proves an upstream whose declared sha256
// does not match the served artifact is skipped (and reported), and that a
// sole tampered collection fails the whole collect without burning a
// sequence number.
func TestGalaxyCollectVerifiesSHA256(t *testing.T) {
	web := galaxyTestCollection(t, "acme", "web", "1.0.0", nil)
	db := galaxyTestCollection(t, "acme", "db", "1.0.0", nil)
	upstream := fakeGalaxyUpstream(t, map[string][]galaxyTestVersion{
		"acme.web": {{version: "1.0.0", body: web, badSHA: galaxyTestSHA256([]byte("not the real artifact"))}},
		"acme.db":  {{version: "1.0.0", body: db}},
	}, 0)

	ls, _ := newGalaxyLowServer(t, upstream.URL)
	res, err := ls.CollectGalaxy(context.Background(), GalaxyCollectRequest{
		Collections: []string{"acme.web@1.0.0", "acme.db@1.0.0"}, NoDeps: true,
	})
	if err != nil {
		t.Fatalf("collect with one good collection should succeed: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Errorf("ExportedModules = %d, want 1 (only acme.db)", res.ExportedModules)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "acme.web" ||
		!strings.Contains(res.SkippedModules[0].Error, "sha256") {
		t.Fatalf("expected acme.web skipped with a sha256 error, got %+v", res.SkippedModules)
	}

	// The tampered collection on its own leaves nothing to export.
	if _, err := ls.CollectGalaxy(context.Background(), GalaxyCollectRequest{
		Collections: []string{"acme.web@1.0.0"},
	}); err == nil {
		t.Fatal("a tampered sole collection should fail the collect")
	}
	if seq := ls.peekSequence(streamGalaxy); seq != 2 {
		t.Errorf("sequence advanced to %d after failed collect, want 2", seq)
	}
}

// TestGalaxyCollectNoDepsAndFilenameCheck covers NoDeps (declared
// dependencies stay untouched) and the canonical-filename cross-check
// against the upstream artifact record.
func TestGalaxyCollectNoDepsAndFilenameCheck(t *testing.T) {
	web := galaxyTestCollection(t, "acme", "web", "1.0.0", map[string]string{"acme.db": "*"})
	odd := galaxyTestCollection(t, "acme", "odd", "1.0.0", nil)
	upstream := fakeGalaxyUpstream(t, map[string][]galaxyTestVersion{
		"acme.web": {{version: "1.0.0", body: web, deps: map[string]string{"acme.db": "*"}}},
		"acme.odd": {{version: "1.0.0", body: odd, badName: true}},
	}, 0)

	ls, _ := newGalaxyLowServer(t, upstream.URL)
	res, err := ls.CollectGalaxy(context.Background(), GalaxyCollectRequest{
		Collections: []string{"acme.web"}, NoDeps: true,
	})
	if err != nil {
		t.Fatalf("CollectGalaxy: %v", err)
	}
	// Only web itself: its acme.db dependency was not followed (and, being
	// unfetched rather than failed, is not in SkippedModules either).
	if res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("NoDeps collect = %+v, want exactly the requested collection", res)
	}

	res, err = ls.CollectGalaxy(context.Background(), GalaxyCollectRequest{
		Collections: []string{"acme.odd@1.0.0", "acme.web@1.0.0"}, NoDeps: true, Force: true,
	})
	if err != nil {
		t.Fatalf("CollectGalaxy: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 ||
		res.SkippedModules[0].Module != "acme.odd" ||
		!strings.Contains(res.SkippedModules[0].Error, "canonical") {
		t.Fatalf("non-canonical filename should skip acme.odd: %+v", res)
	}
}

// -----------------------------------------------------------------------------
// Admin endpoint
// -----------------------------------------------------------------------------

// TestGalaxyHandleCollect drives the admin collect handler directly (the
// /admin route dispatch derives from the registry, which the galaxy stream
// joins separately).
func TestGalaxyHandleCollect(t *testing.T) {
	web := galaxyTestCollection(t, "acme", "web", "1.0.0", nil)
	upstream := fakeGalaxyUpstream(t, map[string][]galaxyTestVersion{
		"acme.web": {{version: "1.0.0", body: web}},
	}, 0)
	ls, _ := newGalaxyLowServer(t, upstream.URL)

	post := func(body string) (ExportResult, error) {
		req := httptest.NewRequest(http.MethodPost, "/admin/galaxy/collect", strings.NewReader(body))
		return ls.HandleGalaxyCollect(context.Background(), req)
	}

	res, err := post(`{"collections":["acme.web@1.0.0"]}`)
	if err != nil {
		t.Fatalf("HandleGalaxyCollect: %v", err)
	}
	if res.BundleID != "galaxy-bundle-000001" || res.ExportedModules != 1 {
		t.Errorf("unexpected collect result: %+v", res)
	}

	if _, err := post(`{}`); err == nil || !strings.Contains(err.Error(), "no collections") {
		t.Errorf("empty request error = %v", err)
	}
	if _, err := post(`not json`); err == nil || !strings.Contains(err.Error(), "parse galaxy collect request") {
		t.Errorf("bad JSON error = %v", err)
	}
	if _, err := post(`{"collections":["Acme.Web"]}`); err == nil {
		t.Error("invalid collection name accepted")
	}
}

// -----------------------------------------------------------------------------
// Publish: MANIFEST.json extraction and cross-checks
// -----------------------------------------------------------------------------

// galaxyTestRecord builds the canonical bundle record for one collection and
// writes its artifact bytes into the high server's repository.
func galaxyTestRecord(t *testing.T, hs *HighServer, ns, name, version string, body []byte) GalaxyCollection {
	t.Helper()
	c := GalaxyCollection{
		Namespace: ns, Name: name, Version: version,
		Filename: galaxyFilename(ns, name, version),
		Path:     galaxyFileRel(ns, name, galaxyFilename(ns, name, version)),
		SHA256:   galaxyTestSHA256(body),
	}
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(c.Path))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, body)
	return c
}

// TestGalaxyPublishCrossChecks proves publish regenerates metadata from the
// artifact's own MANIFEST.json — accepting the "./" member spelling — and
// logs-and-skips archives whose embedded identity disagrees with the bundle
// record, or that carry no parseable manifest at all.
func TestGalaxyPublishCrossChecks(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	goodBody := galaxyTestCollection(t, "acme", "web", "1.0.0", map[string]string{"acme.db": "*"})
	good := galaxyTestRecord(t, hs, "acme", "web", "1.0.0", goodBody)
	dotSlash := galaxyTestRecord(t, hs, "acme", "dot", "1.0.0",
		galaxyTestTgz(t, "./MANIFEST.json", "acme", "dot", "1.0.0", nil))
	forgedName := galaxyTestRecord(t, hs, "acme", "forged", "1.0.0",
		galaxyTestTgz(t, "MANIFEST.json", "acme", "other", "1.0.0", nil))
	forgedVersion := galaxyTestRecord(t, hs, "acme", "wrongver", "1.0.0",
		galaxyTestTgz(t, "MANIFEST.json", "acme", "wrongver", "2.0.0", nil))
	noManifest := galaxyTestRecord(t, hs, "acme", "nomanifest", "1.0.0",
		galaxyTestTgz(t, "", "acme", "nomanifest", "1.0.0", nil))
	corrupt := galaxyTestRecord(t, hs, "acme", "corrupt", "1.0.0", []byte("not a tar.gz at all"))

	all := []GalaxyCollection{good, dotSlash, forgedName, forgedVersion, noManifest, corrupt}
	if err := hs.publishGalaxy(&GalaxyManifest{Collections: all}); err != nil {
		t.Fatalf("publish must log-and-skip bad archives, not fail: %v", err)
	}

	st, err := hs.readGalaxyStored("acme", "web", "1.0.0")
	if err != nil {
		t.Fatalf("good version not stored: %v", err)
	}
	if st.SHA256 != galaxyTestSHA256(goodBody) || st.Size != int64(len(goodBody)) || st.Dependencies["acme.db"] != "*" {
		t.Errorf("stored metadata = %+v", st)
	}
	if _, err := hs.readGalaxyStored("acme", "dot", "1.0.0"); err != nil {
		t.Errorf("./MANIFEST.json member form not stored: %v", err)
	}
	for _, name := range []string{"forged", "wrongver", "nomanifest", "corrupt"} {
		if _, err := hs.readGalaxyStored("acme", name, "1.0.0"); err == nil {
			t.Errorf("%s should have no served metadata", name)
		}
	}

	// The per-collection errors name the cross-check that failed.
	if err := hs.publishGalaxyCollection(forgedName); err == nil || !strings.Contains(err.Error(), "MANIFEST.json names") {
		t.Errorf("forged name error = %v", err)
	}
	if err := hs.publishGalaxyCollection(forgedVersion); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("forged version error = %v", err)
	}
	// A record whose path escapes the galaxy tree is rejected outright.
	evil := good
	evil.Path = "npm/packages/x/x-1.0.0.tgz"
	if err := hs.publishGalaxyCollection(evil); err == nil || !strings.Contains(err.Error(), "unsafe artifact path") {
		t.Errorf("non-galaxy path error = %v", err)
	}
}
