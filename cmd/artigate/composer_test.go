package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // asserting the legacy composer dist.shasum field
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

func composerTestSHA1(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // asserting the legacy shasum field
	return hex.EncodeToString(sum[:])
}

// composerTestRepo is a fake Composer v2 upstream: minified p2 metadata plus
// dist zips, mirroring packagist's shapes.
type composerTestRepo struct {
	srv  *httptest.Server
	pkgs map[string][]map[string]any
	zips map[string][]byte
}

func newComposerTestRepo(t *testing.T) *composerTestRepo {
	t.Helper()
	f := &composerTestRepo{pkgs: map[string][]map[string]any{}, zips: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/p2/", f.handleMetadata)
	mux.HandleFunc("/dist/", f.handleDist)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *composerTestRepo) handleMetadata(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/p2/"), ".json")
	list, ok := f.pkgs[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"minified": "composer/2.0",
		"packages": map[string]any{name: composerTestMinify(list)},
	})
}

func (f *composerTestRepo) handleDist(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/dist/"), ".zip")
	b, ok := f.zips[key]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _ = w.Write(b)
}

// add registers one release (listed after any previously added versions,
// like packagist lists newest first) and returns its zip bytes. The object
// carries dist and source sections the collector must strip.
func (f *composerTestRepo) add(name, version, vnorm string, require map[string]any) []byte {
	zip := []byte("zip:" + name + "@" + vnorm)
	f.zips[name+"/"+vnorm] = zip
	obj := map[string]any{
		"name":               name,
		"version":            version,
		"version_normalized": vnorm,
		"description":        "test package " + name,
		"type":               "library",
		"license":            []any{"MIT"},
		"source": map[string]any{
			"type": "git", "url": "ssh://git@internal.example/" + name + ".git", "reference": "ref-" + vnorm,
		},
		"dist": map[string]any{
			"type": "zip", "url": f.srv.URL + "/dist/" + name + "/" + vnorm + ".zip",
			"shasum": "", "reference": "ref-" + vnorm,
		},
	}
	if require != nil {
		obj["require"] = require
	}
	f.pkgs[name] = append(f.pkgs[name], obj)
	return zip
}

// composerTestMinify renders full version objects into the composer/2.0
// minified form the way packagist does: the first entry complete, later
// entries carrying only changed keys, dropped keys becoming "__unset".
func composerTestMinify(objs []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(objs))
	prev := map[string]any{}
	for _, obj := range objs {
		diff := map[string]any{}
		for k, v := range obj {
			if pv, ok := prev[k]; !ok || !reflect.DeepEqual(pv, v) {
				diff[k] = v
			}
		}
		for k := range prev {
			if _, ok := obj[k]; !ok {
				diff[k] = "__unset"
			}
		}
		out = append(out, diff)
		prev = obj
	}
	return out
}

func newComposerLowServer(t *testing.T, repoURL string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), ComposerRepoURL: repoURL}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// composerManifestFromExport reads back the signed manifest of an exported
// composer bundle.
func composerManifestFromExport(t *testing.T, ls *LowServer, bundleID string) BundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Composer == nil {
		t.Fatalf("manifest carries no composer content: %s", b)
	}
	return m
}

// composerTestMetadata builds a pruned version object as the manifest
// carries it.
func composerTestMetadata(t *testing.T, name, version, vnorm string, extra map[string]any) json.RawMessage {
	t.Helper()
	obj := map[string]any{"name": name, "version": version, "version_normalized": vnorm}
	for k, v := range extra {
		obj[k] = v
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// composerTestPublish installs one release on a high server the way an
// import would: the zip at its bundle path plus a publish of its record.
func composerTestPublish(t *testing.T, hs *HighServer, name, version, vnorm string, zip []byte, extra map[string]any) {
	t.Helper()
	rel := composerDistRel(name, vnorm)
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, zip)
	err := hs.publishComposer(&ComposerManifest{Packages: []ComposerPackage{{
		Name: name, Version: version, VersionNormalized: vnorm,
		Path: rel, SHA256: helmTestSHA256(zip),
		Metadata: composerTestMetadata(t, name, version, vnorm, extra),
	}}})
	if err != nil {
		t.Fatal(err)
	}
}

// composerServe drives serveComposer directly (the ecosystem is not yet in
// the registry, so the high mux does not route /composer).
func composerServe(t *testing.T, hs *HighServer, method, target string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()
	if !hs.serveComposer(w, r) {
		t.Fatalf("serveComposer did not claim %s", target)
	}
	resp := w.Result()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// -----------------------------------------------------------------------------
// Unit: minified expansion
// -----------------------------------------------------------------------------

// TestComposerExpandMinified feeds a fixture shaped like packagist's real
// p2 output (psr/container ships exactly this pattern): full first object,
// diff-only followers, and an "__unset" removal.
func TestComposerExpandMinified(t *testing.T) {
	raw := `[
	  {"name":"psr/container","version":"2.0.2","version_normalized":"2.0.2.0","type":"library",
	   "require":{"php":">=7.4.0"},"extra":{"branch-alias":{"dev-master":"2.0.x-dev"}}},
	  {"version":"2.0.1","version_normalized":"2.0.1.0","require":{"php":">=7.2.0"}},
	  {"version":"1.1.2","version_normalized":"1.1.2.0","require":{"php":">=7.4.0"},"extra":"__unset"}
	]`
	var list []map[string]any
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}
	out := composerExpandMinified(list)
	if len(out) != 3 {
		t.Fatalf("expanded %d objects, want 3", len(out))
	}
	// Untouched keys carry forward into the diff-only entries.
	for i, obj := range out {
		if composerString(obj, "name") != "psr/container" || composerString(obj, "type") != "library" {
			t.Errorf("entry %d lost carried keys: %v", i, obj)
		}
	}
	if composerString(out[1], "version") != "2.0.1" {
		t.Errorf("entry 1 version = %q", composerString(out[1], "version"))
	}
	// Changed keys are replaced wholesale.
	req1, _ := out[1]["require"].(map[string]any)
	if req1["php"] != ">=7.2.0" {
		t.Errorf("entry 1 require not overridden: %v", out[1]["require"])
	}
	if _, ok := out[1]["extra"]; !ok {
		t.Errorf("entry 1 should still carry extra: %v", out[1])
	}
	// "__unset" removes the key from that point on.
	if _, ok := out[2]["extra"]; ok {
		t.Errorf("entry 2 should have dropped extra: %v", out[2])
	}
	req2, _ := out[2]["require"].(map[string]any)
	if req2["php"] != ">=7.4.0" {
		t.Errorf("entry 2 require = %v", out[2]["require"])
	}
}

// -----------------------------------------------------------------------------
// Unit: version ordering and stability
// -----------------------------------------------------------------------------

func TestComposerCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.0.2.0", "2.0.1.0", 1},
		{"1.2", "1.2.0.0", 0},
		{"0.9.9.9", "1.0", -1},
		{"10.0.0.0", "9.0.0.0", 1},
		{"1.0.0.0", "1.0.0.0-RC1", 1},
		{"1.0.0.0-RC1", "1.0.0.0-beta2", 1},
		{"1.0.0.0-beta2", "1.0.0.0-beta1", 1},
		{"1.0.0.0-beta1", "1.0.0.0-alpha3", 1},
		{"1.0.0.0-alpha1", "1.0.0.0-dev", 1},
		{"1.0.0.0-patch1", "1.0.0.0", 1},
		{"1.0.0.0-beta1", "1.0.0.0-beta1", 0},
	}
	for _, tt := range tests {
		if got := composerCompareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("composerCompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := composerCompareVersions(tt.b, tt.a); got != -tt.want {
			t.Errorf("composerCompareVersions(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
	if !composerVersionStable("2.0.2.0") || composerVersionStable("2.0.0.0-beta1") {
		t.Error("composerVersionStable misclassifies suffixes")
	}
}

// -----------------------------------------------------------------------------
// Unit: constraint subset
// -----------------------------------------------------------------------------

func TestComposerConstraintMatches(t *testing.T) {
	tests := []struct {
		constraint, version string
		want                bool
	}{
		{"*", "1.2.3.0", true},
		{"^2.0", "2.5.0.0", true},
		{"^2.0", "2.0.0.0", true},
		{"^2.0", "3.0.0.0", false},
		{"^2.0", "1.9.0.0", false},
		{"^0.3", "0.3.9.0", true},
		{"^0.3", "0.4.0.0", false},
		{"^0", "0.9.0.0", true},
		{"^v1.2", "1.3.0.0", true},
		{"^2.0-beta1", "2.0.0.0", true},
		{"~1.2", "1.9.0.0", true},
		{"~1.2", "2.0.0.0", false},
		{"~1.2", "1.1.0.0", false},
		{"~1.2.3", "1.2.9.0", true},
		{"~1.2.3", "1.3.0.0", false},
		{">=7.4.0", "8.0.0.0", true},
		{">=7.4.0", "7.3.0.0", false},
		{">1.0 <2.0", "1.5.0.0", true},
		{">1.0 <2.0", "2.0.0.0", false},
		{">=1.0,<2.0", "1.5.0.0", true},
		{"<=1.5", "1.5.0.0", true},
		{"<2", "1.9.9.9", true},
		{"1.2.*", "1.2.3.0", true},
		{"1.2.*", "1.3.0.0", false},
		{"2.*", "2.9.0.0", true},
		{"2.*", "3.0.0.0", false},
		{"^1.0 || ^2.0", "2.1.0.0", true},
		{"^1.0 || ^2.0", "3.0.0.0", false},
		{"^1.0|^2.0", "2.1.0.0", true},
		{"2.0.2", "2.0.2.0", true},
		{"2.0.2", "2.0.3.0", false},
		{"v2.0.2", "2.0.2.0", true},
		{"=1.2.3", "1.2.3.0", true},
		{"!=1.2.3", "1.2.4.0", true},
		{"!=1.2.3", "1.2.3.0", false},
		{"1.0.0-beta1", "1.0.0.0-beta1", true},
		{"1.0.0-beta1", "1.0.0.0", false},
	}
	for _, tt := range tests {
		got, err := composerConstraintMatches(tt.constraint, tt.version)
		if err != nil || got != tt.want {
			t.Errorf("composerConstraintMatches(%q, %q) = %v, %v; want %v", tt.constraint, tt.version, got, err, tt.want)
		}
	}

	// Anything outside the subset must error — never guess.
	unsupported := []string{
		"1.0 - 2.0", "~1", "dev-master", "", ">=1.x", "^1.0@stable",
		"spooky", "1.*.*", ">=1.0 bogus", "^1.x",
	}
	for _, c := range unsupported {
		if _, err := composerConstraintMatches(c, "1.0.0.0"); err == nil {
			t.Errorf("composerConstraintMatches(%q) = nil error, want unsupported-constraint error", c)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: naming, versions, and specs
// -----------------------------------------------------------------------------

func TestComposerValidateNames(t *testing.T) {
	validNames := []string{"psr/container", "monolog/monolog", "a1/b2", "acme/x_y.z-w", "php-http/message"}
	invalidNames := []string{
		"", "psr", "PSR/container", "psr/", "/x", "a//b", "psr/../x",
		"-a/b", "a./b", "a..b/c", "vendor/pro ject", "a/b/c",
	}
	for _, n := range validNames {
		if err := validateComposerName(n); err != nil {
			t.Errorf("validateComposerName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateComposerName(n); err == nil {
			t.Errorf("validateComposerName(%q) = nil, want error", n)
		}
	}

	validNorm := []string{"2.0.2.0", "1.0.0.0-beta1", "0.1.0.0"}
	invalidNorm := []string{"", "v2.0.2.0", "..", "-1", "x.y", strings.Repeat("1", 70), "1/0"}
	for _, v := range validNorm {
		if err := validateComposerVersionNormalized(v); err != nil {
			t.Errorf("validateComposerVersionNormalized(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidNorm {
		if err := validateComposerVersionNormalized(v); err == nil {
			t.Errorf("validateComposerVersionNormalized(%q) = nil, want error", v)
		}
	}

	if err := validateComposerVersion("v2.0.2"); err != nil {
		t.Errorf("pretty version with v prefix rejected: %v", err)
	}
	for _, v := range []string{"", " 1.0", "1/0", "..", ".hidden"} {
		if err := validateComposerVersion(v); err == nil {
			t.Errorf("validateComposerVersion(%q) = nil, want error", v)
		}
	}
}

func TestParseComposerSpec(t *testing.T) {
	name, version, err := parseComposerSpec("psr/container")
	if err != nil || name != "psr/container" || version != "" {
		t.Errorf("plain spec = (%q, %q, %v)", name, version, err)
	}
	name, version, err = parseComposerSpec(" psr/container:v2.0.2 ")
	if err != nil || name != "psr/container" || version != "v2.0.2" {
		t.Errorf("pinned spec = (%q, %q, %v)", name, version, err)
	}
	for _, spec := range []string{"", "psr:2.0", "PSR/c:1.0", "a/b:!!", "a/b:", "a/b: 1.0"} {
		if _, _, err := parseComposerSpec(spec); err == nil && spec != "a/b:" {
			t.Errorf("parseComposerSpec(%q) = nil, want error", spec)
		}
	}
	// A trailing colon degrades to an unpinned request.
	if _, version, err := parseComposerSpec("a/b:"); err != nil || version != "" {
		t.Errorf("empty pin = (%q, %v)", version, err)
	}
}

// -----------------------------------------------------------------------------
// Unit: release selection
// -----------------------------------------------------------------------------

func TestComposerSelectRelease(t *testing.T) {
	mk := func(version, vnorm string) map[string]any {
		return map[string]any{"name": "acme/x", "version": version, "version_normalized": vnorm}
	}
	versions := []map[string]any{
		mk("2.0.0-beta1", "2.0.0.0-beta1"),
		mk("1.2.0", "1.2.0.0"),
		mk("v1.0.0", "1.0.0.0"),
	}

	// A stable release wins over a newer prerelease when nothing is pinned.
	obj, err := composerSelectRelease(versions, "")
	if err != nil || composerString(obj, "version_normalized") != "1.2.0.0" {
		t.Errorf("unpinned select = %v, %v; want 1.2.0.0", obj, err)
	}
	if obj, err = composerSelectRelease(versions, "v1.0.0"); err != nil || composerString(obj, "version_normalized") != "1.0.0.0" {
		t.Errorf("pretty pin = %v, %v", obj, err)
	}
	if obj, err = composerSelectRelease(versions, "1.2.0.0"); err != nil || composerString(obj, "version") != "1.2.0" {
		t.Errorf("normalized pin = %v, %v", obj, err)
	}
	if _, err := composerSelectRelease(versions, "9.9.9"); err == nil {
		t.Error("missing pinned version should error")
	}
	// With only prereleases, the newest prerelease is used.
	pre := []map[string]any{mk("2.0.0-beta1", "2.0.0.0-beta1")}
	if obj, err = composerSelectRelease(pre, ""); err != nil || composerString(obj, "version_normalized") != "2.0.0.0-beta1" {
		t.Errorf("prerelease fallback = %v, %v", obj, err)
	}

	// Dependencies resolve to the newest stable release satisfying the
	// constraint; prereleases never qualify.
	if obj, err = composerSelectDependency(versions, "^1.0"); err != nil || composerString(obj, "version_normalized") != "1.2.0.0" {
		t.Errorf("dependency select = %v, %v", obj, err)
	}
	if _, err := composerSelectDependency(versions, "^2.0"); err == nil {
		t.Error("beta-only match should leave no stable candidate")
	}
	if _, err := composerSelectDependency(versions, "1.0 - 2.0"); err == nil {
		t.Error("unsupported constraint should error")
	}
}

// -----------------------------------------------------------------------------
// Unit: import-side manifest validation
// -----------------------------------------------------------------------------

func TestValidateComposerPackages(t *testing.T) {
	canonPath := "composer/dist/acme/app/1.2.0.0.zip"
	good := func() ComposerPackage {
		return ComposerPackage{
			Name: "acme/app", Version: "1.2.0", VersionNormalized: "1.2.0.0",
			Path: canonPath, SHA256: strings.Repeat("a", 64),
			Metadata: composerTestMetadata(t, "acme/app", "1.2.0", "1.2.0.0", nil),
		}
	}
	seen := map[string]bool{canonPath: true}
	if err := validateComposerPackages([]ComposerPackage{good()}, seen); err != nil {
		t.Errorf("valid packages rejected: %v", err)
	}

	tamper := []struct {
		name   string
		mutate func(*ComposerPackage)
		seen   map[string]bool
	}{
		{"dist key present", func(p *ComposerPackage) {
			p.Metadata = composerTestMetadata(t, "acme/app", "1.2.0", "1.2.0.0", map[string]any{"dist": map[string]any{"url": "https://evil.example"}})
		}, seen},
		{"source key present", func(p *ComposerPackage) {
			p.Metadata = composerTestMetadata(t, "acme/app", "1.2.0", "1.2.0.0", map[string]any{"source": map[string]any{"url": "ssh://leak"}})
		}, seen},
		{"metadata name mismatch", func(p *ComposerPackage) {
			p.Metadata = composerTestMetadata(t, "acme/other", "1.2.0", "1.2.0.0", nil)
		}, seen},
		{"metadata normalized mismatch", func(p *ComposerPackage) {
			p.Metadata = composerTestMetadata(t, "acme/app", "1.2.0", "9.9.9.9", nil)
		}, seen},
		{"metadata not an object", func(p *ComposerPackage) { p.Metadata = json.RawMessage(`"hi"`) }, seen},
		{"metadata null", func(p *ComposerPackage) { p.Metadata = json.RawMessage(`null`) }, seen},
		{"non-canonical path", func(p *ComposerPackage) { p.Path = "composer/dist/acme/app/app.zip" }, map[string]bool{"composer/dist/acme/app/app.zip": true}},
		{"path not in seen", func(_ *ComposerPackage) {}, map[string]bool{}},
		{"bad normalized version", func(p *ComposerPackage) { p.VersionNormalized = "../1" }, seen},
		{"bad name", func(p *ComposerPackage) { p.Name = "Acme/app" }, seen},
		{"empty version", func(p *ComposerPackage) { p.Version = "" }, seen},
	}
	for _, tt := range tamper {
		p := good()
		tt.mutate(&p)
		if err := validateComposerPackages([]ComposerPackage{p}, tt.seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration: collect with dependency closure
// -----------------------------------------------------------------------------

// TestCollectComposerClosure resolves a package whose require chain spans two
// more packages, skipping platform packages and a dev-constrained edge, and
// checks the packed manifest records carry pruned metadata.
func TestCollectComposerClosure(t *testing.T) {
	repo := newComposerTestRepo(t)
	repo.add("acme/app", "2.0.0-beta1", "2.0.0.0-beta1", map[string]any{"acme/lib": "^9"})
	repo.add("acme/app", "1.2.0", "1.2.0.0", map[string]any{
		"acme/lib": "^1.0", "php": ">=8.0", "ext-json": "*", "lib-icu": "*",
		"composer-plugin-api": "^2.2", "composer-runtime-api": "^2",
		"acme/devtool": "2.0.x-dev",
	})
	repo.add("acme/lib", "2.0.0", "2.0.0.0", map[string]any{"acme/core": "^9"})
	repo.add("acme/lib", "1.1.0", "1.1.0.0", map[string]any{"acme/core": "~1.1.0"})
	repo.add("acme/lib", "1.0.0", "1.0.0.0", nil)
	repo.add("acme/core", "1.2.0", "1.2.0.0", nil)
	repo.add("acme/core", "1.1.9-RC1", "1.1.9.0-RC1", nil)
	repo.add("acme/core", "1.1.5", "1.1.5.0", map[string]any{"php": ">=7.4"})

	ls, _ := newComposerLowServer(t, repo.srv.URL)
	res, err := ls.CollectComposer(context.Background(), ComposerCollectRequest{Packages: []string{"acme/app"}})
	if err != nil {
		t.Fatalf("CollectComposer: %v", err)
	}
	if res.BundleID != "composer-bundle-000001" || res.ExportedModules != 3 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	if len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected failures: %+v", res.SkippedModules)
	}

	m := composerManifestFromExport(t, ls, res.BundleID)
	got := map[string]string{}
	for _, p := range m.Composer.Packages {
		got[p.Name] = p.VersionNormalized
		if p.Path != composerDistRel(p.Name, p.VersionNormalized) {
			t.Errorf("%s stored at %s", p.Name, p.Path)
		}
	}
	// The stable app release (not the newer beta), the constraint-satisfying
	// lib (not the newer 2.0.0), and core's newest stable inside ~1.1.0.
	want := map[string]string{"acme/app": "1.2.0.0", "acme/lib": "1.1.0.0", "acme/core": "1.1.5.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved %v, want %v", got, want)
	}

	var meta map[string]any
	for _, p := range m.Composer.Packages {
		if p.Name == "acme/app" {
			if err := json.Unmarshal(p.Metadata, &meta); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, ok := meta["dist"]; ok {
		t.Errorf("app metadata still carries dist: %v", meta)
	}
	if _, ok := meta["source"]; ok {
		t.Errorf("app metadata still carries source: %v", meta)
	}
	req, _ := meta["require"].(map[string]any)
	if req["acme/lib"] != "^1.0" {
		t.Errorf("app metadata lost its require map: %v", meta)
	}
}

// TestCollectComposerFailures exercises the skip-and-report paths: an
// unsupported constraint, a missing dependency, a dependency with no stable
// release, no_deps/force, a missing pinned version, and a non-http dist.
func TestCollectComposerFailures(t *testing.T) {
	repo := newComposerTestRepo(t)
	repo.add("acme/rangey", "1.0.0", "1.0.0.0", map[string]any{"acme/two": "1.0 - 2.0"})
	repo.add("acme/two", "1.5.0", "1.5.0.0", nil)
	repo.add("acme/four", "1.0.0", "1.0.0.0", map[string]any{"acme/ghost": "^1.0"})
	repo.add("acme/five", "1.0.0", "1.0.0.0", map[string]any{"acme/beta": "^1.0"})
	repo.add("acme/beta", "1.2.0-beta1", "1.2.0.0-beta1", nil)
	repo.add("acme/bad", "1.0.0", "1.0.0.0", nil)
	repo.pkgs["acme/bad"][0]["dist"] = map[string]any{"type": "zip", "url": "ftp://evil.example/x.zip"}
	ls, _ := newComposerLowServer(t, repo.srv.URL)
	ctx := context.Background()

	res, err := ls.CollectComposer(ctx, ComposerCollectRequest{Packages: []string{"acme/rangey"}})
	if err != nil || res.ExportedModules != 1 {
		t.Fatalf("rangey collect: %+v, %v", res, err)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "acme/two" ||
		!strings.Contains(res.SkippedModules[0].Error, "unsupported") {
		t.Fatalf("expected acme/two skipped for an unsupported constraint, got %+v", res.SkippedModules)
	}

	res, err = ls.CollectComposer(ctx, ComposerCollectRequest{Packages: []string{"acme/four"}})
	if err != nil || res.ExportedModules != 1 || len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "acme/ghost" {
		t.Fatalf("ghost dep should be reported: %+v, %v", res, err)
	}

	res, err = ls.CollectComposer(ctx, ComposerCollectRequest{Packages: []string{"acme/five"}})
	if err != nil || len(res.SkippedModules) != 1 || !strings.Contains(res.SkippedModules[0].Error, "no stable version") {
		t.Fatalf("beta-only dep should be reported: %+v, %v", res, err)
	}

	// no_deps skips the closure entirely (force: the zip was already packed).
	res, err = ls.CollectComposer(ctx, ComposerCollectRequest{Packages: []string{"acme/four"}, NoDeps: true, Force: true})
	if err != nil || res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("no_deps collect: %+v, %v", res, err)
	}

	if _, err := ls.CollectComposer(ctx, ComposerCollectRequest{Packages: []string{"acme/four:9.9.9"}}); err == nil {
		t.Fatal("a sole missing pinned version should fail the collect")
	}
	if _, err := ls.CollectComposer(ctx, ComposerCollectRequest{Packages: []string{"acme/bad"}}); err == nil ||
		!strings.Contains(err.Error(), "http") {
		t.Fatalf("non-http dist should fail the collect, got %v", err)
	}
	if _, err := ls.CollectComposer(ctx, ComposerCollectRequest{}); err == nil {
		t.Fatal("empty request should fail")
	}
}

// TestHandleComposerCollect drives the admin handler directly (the route is
// wired by the registry at registration time).
func TestHandleComposerCollect(t *testing.T) {
	repo := newComposerTestRepo(t)
	repo.add("acme/solo", "1.0.0", "1.0.0.0", nil)
	ls, _ := newComposerLowServer(t, repo.srv.URL)
	ctx := context.Background()

	r := httptest.NewRequest(http.MethodPost, "/admin/composer/collect", strings.NewReader(`{"packages":["acme/solo"]}`))
	res, err := ls.HandleComposerCollect(ctx, r)
	if err != nil || res.BundleID != "composer-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("handler collect: %+v, %v", res, err)
	}

	r = httptest.NewRequest(http.MethodPost, "/admin/composer/collect", strings.NewReader("not json"))
	if _, err := ls.HandleComposerCollect(ctx, r); err == nil {
		t.Error("invalid JSON body should error")
	}
	r = httptest.NewRequest(http.MethodPost, "/admin/composer/collect", strings.NewReader(`{}`))
	if _, err := ls.HandleComposerCollect(ctx, r); err == nil {
		t.Error("empty request should error")
	}
}

// -----------------------------------------------------------------------------
// Integration: low -> high pipeline and on-the-fly p2 rendering
// -----------------------------------------------------------------------------

// TestComposerLowToHighPipeline collects a package and its dependency into a
// signed bundle, verifies the signature and content records like the importer
// does, lands the byte-verified files on a high server, publishes, and checks
// the regenerated Composer v2 API end to end.
func TestComposerLowToHighPipeline(t *testing.T) {
	repo := newComposerTestRepo(t)
	appZip := repo.add("acme/app", "1.2.0", "1.2.0.0", map[string]any{"acme/lib": "^1.0", "php": ">=8.0"})
	libZip := repo.add("acme/lib", "v1.1.0", "1.1.0.0", nil)
	oldLibZip := repo.add("acme/lib", "v1.0.0", "1.0.0.0", nil)

	ls, priv := newComposerLowServer(t, repo.srv.URL)
	res, err := ls.CollectComposer(context.Background(), ComposerCollectRequest{Packages: []string{"acme/app"}})
	if err != nil {
		t.Fatalf("CollectComposer: %v", err)
	}
	if res.BundleID != "composer-bundle-000001" || res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	importComposerBundle(t, ls, hs, pub, res.BundleID)

	// A second bundle accumulates an older lib release next to the first.
	res2, err := ls.CollectComposer(context.Background(), ComposerCollectRequest{Packages: []string{"acme/lib:1.0.0.0"}})
	if err != nil || res2.BundleID != "composer-bundle-000002" {
		t.Fatalf("second collect: %+v, %v", res2, err)
	}
	importComposerBundle(t, ls, hs, pub, res2.BundleID)

	assertComposerRoot(t, hs)
	assertComposerP2App(t, hs, appZip)

	// The dependency accumulated both releases, newest first.
	code, body := composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/p2/acme/lib.json")
	if code != http.StatusOK {
		t.Fatalf("lib p2 status %d: %s", code, body)
	}
	libVersions := composerP2Versions(t, body, "acme/lib")
	if len(libVersions) != 2 ||
		composerString(libVersions[0], "version_normalized") != "1.1.0.0" ||
		composerString(libVersions[1], "version_normalized") != "1.0.0.0" {
		t.Fatalf("lib versions out of order: %s", body)
	}

	// ~dev is answered with an empty (truthful) list for known packages.
	code, body = composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/p2/acme/app~dev.json")
	if code != http.StatusOK || !strings.Contains(body, `"acme/app": []`) {
		t.Fatalf("~dev = %d %s", code, body)
	}
	if code, _ := composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/p2/acme/ghost.json"); code != http.StatusNotFound {
		t.Errorf("unknown package p2 status %d, want 404", code)
	}
	if code, _ := composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/p2/acme/ghost~dev.json"); code != http.StatusNotFound {
		t.Errorf("unknown package ~dev status %d, want 404", code)
	}

	// The dist download serves the exact collected bytes.
	code, got := composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/dist/acme/app/1.2.0.0.zip")
	if code != http.StatusOK || got != string(appZip) {
		t.Errorf("dist download: status %d, %d bytes (want %d)", code, len(got), len(appZip))
	}
	_ = libZip

	// Serving is gated on the zip being present: removing one release's zip
	// drops exactly that version from the rendered metadata.
	if err := os.Remove(filepath.Join(hs.downloadDir, "composer", "dist", "acme", "lib", "1.0.0.0.zip")); err != nil {
		t.Fatal(err)
	}
	_, body = composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/p2/acme/lib.json")
	if vs := composerP2Versions(t, body, "acme/lib"); len(vs) != 1 || composerString(vs[0], "version_normalized") != "1.1.0.0" {
		t.Errorf("zip gating failed: %s", body)
	}
	_ = oldLibZip
}

// importComposerBundle verifies a bundle's signature and records, then lands
// its byte-verified files on the high server and publishes them — the same
// steps the importer runs once the ecosystem is registered.
func importComposerBundle(t *testing.T, ls *LowServer, hs *HighServer, pub ed25519.PublicKey, bundleID string) {
	t.Helper()
	manifestBytes, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	sigB64, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	sigText := strings.TrimSpace(string(sigB64))
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sigText, manifestSignaturePHPrefix))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(manifestBytes)
	if err := ed25519.VerifyWithOptions(pub, digest[:], sig, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		t.Fatalf("bundle manifest signature does not verify: %v", err)
	}
	var m BundleManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateComposerPackages(m.Composer.Packages, seen); err != nil {
		t.Fatalf("importer content validation rejected the bundle: %v", err)
	}
	if err := extractAndVerifyTarGz(filepath.Join(ls.cfg.ExportDir, bundleID+".tar.gz"), hs.downloadDir, m.Files); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if err := hs.publishComposer(m.Composer); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// assertComposerRoot checks packages.json: the metadata-url template and the
// sorted available-packages list.
func assertComposerRoot(t *testing.T, hs *HighServer) {
	t.Helper()
	code, body := composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/packages.json")
	if code != http.StatusOK {
		t.Fatalf("packages.json status %d: %s", code, body)
	}
	var root struct {
		MetadataURL string   `json:"metadata-url"`
		Available   []string `json:"available-packages"`
	}
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatalf("packages.json is not JSON: %v\n%s", err, body)
	}
	if root.MetadataURL != "/composer/p2/%package%.json" {
		t.Errorf("metadata-url = %q", root.MetadataURL)
	}
	if !reflect.DeepEqual(root.Available, []string{"acme/app", "acme/lib"}) {
		t.Errorf("available-packages = %v", root.Available)
	}
}

// assertComposerP2App checks the app's rendered p2 file: full objects (no
// minified key), the injected dist with the recomputed SHA-1, and no leaked
// source section.
func assertComposerP2App(t *testing.T, hs *HighServer, appZip []byte) {
	t.Helper()
	code, body := composerServe(t, hs, http.MethodGet, "http://mirror.example/composer/p2/acme/app.json")
	if code != http.StatusOK {
		t.Fatalf("app p2 status %d: %s", code, body)
	}
	if strings.Contains(body, `"minified"`) {
		t.Errorf("p2 output claims to be minified: %s", body)
	}
	versions := composerP2Versions(t, body, "acme/app")
	if len(versions) != 1 {
		t.Fatalf("app p2 lists %d versions, want 1: %s", len(versions), body)
	}
	obj := versions[0]
	if composerString(obj, "name") != "acme/app" || composerString(obj, "version") != "1.2.0" ||
		composerString(obj, "version_normalized") != "1.2.0.0" {
		t.Errorf("app identity wrong: %v", obj)
	}
	if _, ok := obj["source"]; ok {
		t.Errorf("served object leaks the source section: %v", obj)
	}
	req, _ := obj["require"].(map[string]any)
	if req["acme/lib"] != "^1.0" {
		t.Errorf("served object lost require: %v", obj)
	}
	dist, _ := obj["dist"].(map[string]any)
	if dist == nil {
		t.Fatalf("served object has no dist: %v", obj)
	}
	wantURL := "http://mirror.example/composer/dist/acme/app/1.2.0.0.zip"
	if dist["url"] != wantURL || dist["type"] != "zip" {
		t.Errorf("dist = %v, want url %s type zip", dist, wantURL)
	}
	if dist["shasum"] != composerTestSHA1(appZip) {
		t.Errorf("dist.shasum = %v, want %s", dist["shasum"], composerTestSHA1(appZip))
	}
}

// composerP2Versions decodes one package's version list from a p2 response.
func composerP2Versions(t *testing.T, body, name string) []map[string]any {
	t.Helper()
	var doc struct {
		Packages map[string][]map[string]any `json:"packages"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("p2 response is not JSON: %v\n%s", err, body)
	}
	return doc.Packages[name]
}

// -----------------------------------------------------------------------------
// Serving hardening and publish rejections
// -----------------------------------------------------------------------------

func TestComposerServeHardening(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	composerTestPublish(t, hs, "acme/app", "1.0.0", "1.0.0.0", []byte("zip"), nil)

	// Non-composer paths are not claimed.
	w := httptest.NewRecorder()
	if hs.serveComposer(w, httptest.NewRequest(http.MethodGet, "http://x/composers", nil)) {
		t.Error("serveComposer claimed a foreign path")
	}

	if code, _ := composerServe(t, hs, http.MethodPost, "http://x/composer/packages.json"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST status %d, want 405", code)
	}
	notFound := []string{
		"http://x/composer",
		"http://x/composer/",
		"http://x/composer/metadata/acme/app/1.0.0.0.json", // private store
		"http://x/composer/p2/acme.json",                   // not vendor/project
		"http://x/composer/p2/acme/app.yaml",
		"http://x/composer/dist/acme/app/1.0.0.0.txt",
		"http://x/composer/dist/acme/app/extra/1.0.0.0.zip",
		"http://x/composer/dist/../../import-state.json",
		"http://x/composer/dist/acme/app/..%2f..%2fsecret.zip",
	}
	for _, target := range notFound {
		if code, _ := composerServe(t, hs, http.MethodGet, target); code == http.StatusOK {
			t.Errorf("GET %s succeeded, want rejection", target)
		}
	}
	// The valid shape still serves.
	if code, _ := composerServe(t, hs, http.MethodGet, "http://x/composer/dist/acme/app/1.0.0.0.zip"); code != http.StatusOK {
		t.Errorf("valid dist path status %d", code)
	}
}

// TestComposerPublishRejectsBadRecords proves a tampered or incomplete record
// is logged and skipped at publish — its version 404s — without failing the
// rest of the bundle.
func TestComposerPublishRejectsBadRecords(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	composerTestPublish(t, hs, "acme/good", "1.0.0", "1.0.0.0", []byte("good zip"), nil)

	zipRel := composerDistRel("acme/tampered", "1.0.0.0")
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(zipRel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, []byte("zip"))

	bad := []ComposerPackage{
		{ // metadata smuggles a dist section
			Name: "acme/tampered", Version: "1.0.0", VersionNormalized: "1.0.0.0", Path: zipRel,
			Metadata: composerTestMetadata(t, "acme/tampered", "1.0.0", "1.0.0.0", map[string]any{"dist": map[string]any{"url": "https://evil"}}),
		},
		{ // zip missing
			Name: "acme/missing", Version: "1.0.0", VersionNormalized: "1.0.0.0",
			Path:     composerDistRel("acme/missing", "1.0.0.0"),
			Metadata: composerTestMetadata(t, "acme/missing", "1.0.0", "1.0.0.0", nil),
		},
		{ // non-canonical path
			Name: "acme/stray", Version: "1.0.0", VersionNormalized: "1.0.0.0", Path: "composer/dist/acme/stray/x.zip",
			Metadata: composerTestMetadata(t, "acme/stray", "1.0.0", "1.0.0.0", nil),
		},
	}
	if err := hs.publishComposer(&ComposerManifest{Packages: bad}); err != nil {
		t.Fatalf("publish must skip bad records, not fail: %v", err)
	}
	for _, name := range []string{"acme/tampered", "acme/missing", "acme/stray"} {
		if objs, err := hs.composerVersionObjects("http://x", name); err != nil || len(objs) != 0 {
			t.Errorf("%s should not be served, got %d objects (%v)", name, len(objs), err)
		}
	}
	if objs, err := hs.composerVersionObjects("http://x", "acme/good"); err != nil || len(objs) != 1 {
		t.Errorf("good package lost: %d objects (%v)", len(objs), err)
	}
}

// -----------------------------------------------------------------------------
// Dashboard tree/detail and registry descriptor
// -----------------------------------------------------------------------------

func TestComposerTreeAndDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	zip := []byte("zip bytes for detail")
	composerTestPublish(t, hs, "acme/app", "1.0.0", "1.0.0.0", []byte("old zip"), nil)
	composerTestPublish(t, hs, "acme/app", "v1.2.0", "1.2.0.0", zip, map[string]any{
		"license": []any{"MIT"}, "description": "does things", "require": map[string]any{"acme/lib": "^1.0"},
	})

	mods, err := hs.listComposerPackages()
	if err != nil || len(mods) != 1 || mods[0].Module != "acme/app" {
		t.Fatalf("listComposerPackages = %+v, %v", mods, err)
	}
	if !reflect.DeepEqual(mods[0].Versions, []string{"1.0.0", "v1.2.0"}) {
		t.Errorf("versions = %v, want pretty versions oldest first", mods[0].Versions)
	}

	d, err := hs.composerDetail("acme/app@1.2.0.0")
	if err != nil {
		t.Fatalf("composerDetail: %v", err)
	}
	if d.Title != "acme/app" || d.Subtitle != "v1.2.0" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	fields := map[string]string{}
	for _, f := range d.Fields {
		fields[f.Label] = f.Value
	}
	if fields["License"] != "MIT" || fields["Description"] != "does things" || fields["Require"] != "1 dependencies" {
		t.Errorf("detail fields = %v", fields)
	}
	if fields["Normalized"] != "1.2.0.0" || fields["SHA-256"] != helmTestSHA256(zip) {
		t.Errorf("detail identity fields = %v", fields)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/composer/dist/acme/app/1.2.0.0.zip" {
		t.Errorf("detail downloads = %+v", d.Downloads)
	}

	// The pretty version the dashboard tree lists resolves too.
	if d, err := hs.composerDetail("acme/app@v1.2.0"); err != nil || d.Subtitle != "v1.2.0" {
		t.Errorf("pretty-version detail = %+v, %v", d, err)
	}
	for _, spec := range []string{"acme/app@9.9.9", "acme/app", "nope@1.0", "@1.0", "acme/app@"} {
		if _, err := hs.composerDetail(spec); err == nil {
			t.Errorf("composerDetail(%q) = nil, want error", spec)
		}
	}
}

// TestComposerEcosystemDescriptor pins the registry descriptor's wiring so
// central registration only has to append the constructor.
func TestComposerEcosystemDescriptor(t *testing.T) {
	eco := composerEcosystem()
	if eco.stream != streamComposer || eco.label != "Composer" || eco.title == "" || eco.contentDesc == "" {
		t.Errorf("descriptor identity: %+v", eco)
	}
	if eco.collect == nil || eco.watchCollect == nil || eco.publish == nil ||
		eco.serve == nil || eco.scanTree == nil || eco.detail == nil {
		t.Error("descriptor is missing hooks")
	}

	if eco.manifestContent(BundleManifest{}) {
		t.Error("empty manifest reported as composer content")
	}
	if eco.manifestContent(BundleManifest{Composer: &ComposerManifest{}}) {
		t.Error("packageless manifest reported as composer content")
	}
	withPkg := BundleManifest{Composer: &ComposerManifest{Packages: []ComposerPackage{{Name: "acme/app"}}}}
	if !eco.manifestContent(withPkg) {
		t.Error("manifest with packages not reported as composer content")
	}
	if err := eco.validateContent(withPkg, map[string]bool{}); err == nil {
		t.Error("validateContent accepted an invalid record")
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cfg LowConfig
	eco.flags(fs, &cfg)
	if err := fs.Parse([]string{"-composer-repo", "https://mirror.example"}); err != nil {
		t.Fatal(err)
	}
	if cfg.ComposerRepoURL != "https://mirror.example" {
		t.Errorf("composer-repo flag not wired: %q", cfg.ComposerRepoURL)
	}
}
