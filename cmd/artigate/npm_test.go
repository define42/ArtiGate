package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // asserting the legacy npm dist.shasum field
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateNpmName(t *testing.T) {
	valid := []string{"lodash", "@types/node", "JSONStream", "d3-color", "es5-ext", "@artigate/x.y_z"}
	invalid := []string{
		"", "..", ".hidden", "-flag", "_private",
		"a/b", "@scope", "@scope/", "@/pkg", "@scope/../etc", "@scope/.dot",
		"a b", strings.Repeat("x", 215),
	}
	for _, name := range valid {
		if err := validateNpmName(name); err != nil {
			t.Errorf("validateNpmName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range invalid {
		if err := validateNpmName(name); err == nil {
			t.Errorf("validateNpmName(%q) = nil, want error", name)
		}
	}
}

func TestValidateNpmVersion(t *testing.T) {
	valid := []string{"1.0.0", "4.17.21", "1.0.0-beta.1", "2.0.0-rc.1+build.5"}
	invalid := []string{"", "latest", "-1.0", "^1.0.0", "1.0.0/..", "..", "v1.0.0"}
	for _, v := range valid {
		if err := validateNpmVersion(v); err != nil {
			t.Errorf("validateNpmVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalid {
		if err := validateNpmVersion(v); err == nil {
			t.Errorf("validateNpmVersion(%q) = nil, want error", v)
		}
	}
}

func TestNpmTarballFilename(t *testing.T) {
	tests := []struct{ name, version, want string }{
		{"lodash", "4.17.21", "lodash-4.17.21.tgz"},
		{"@types/node", "20.11.5", "node-20.11.5.tgz"},
	}
	for _, tt := range tests {
		if got := npmTarballFilename(tt.name, tt.version); got != tt.want {
			t.Errorf("npmTarballFilename(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
}

func TestValidateNpmSpecArg(t *testing.T) {
	valid := []string{"lodash", "lodash@4.17.21", "react@^18.2", "@types/node@latest", "left-pad@>=1.0.0"}
	invalid := []string{"", "--registry=http://attacker.example", "-g", "lodash 4.17", "pkg\nname"}
	for _, s := range valid {
		if err := validateNpmSpecArg(s); err != nil {
			t.Errorf("validateNpmSpecArg(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateNpmSpecArg(s); err == nil {
			t.Errorf("validateNpmSpecArg(%q) = nil, want error", s)
		}
	}
}

func TestSplitNpmPackagePath(t *testing.T) {
	tests := []struct {
		rest, name, version string
		ok                  bool
	}{
		{"lodash", "lodash", "", true},
		{"@scope/pkg", "@scope/pkg", "", true},
		{"lodash/4.17.21", "lodash", "4.17.21", true},
		{"@scope/pkg/1.0.0", "@scope/pkg", "1.0.0", true},
		{"a/b/c", "", "", false},
		{"@s/a/b/c", "", "", false},
	}
	for _, tt := range tests {
		name, version, ok := splitNpmPackagePath(tt.rest)
		if name != tt.name || version != tt.version || ok != tt.ok {
			t.Errorf("splitNpmPackagePath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.rest, name, version, ok, tt.name, tt.version, tt.ok)
		}
	}
}

func TestNpmLatestVersion(t *testing.T) {
	tests := []struct {
		versions []string
		want     string
	}{
		{[]string{"1.0.0", "2.0.0", "1.9.9"}, "2.0.0"},
		{[]string{"1.0.0", "2.0.0-beta.1"}, "1.0.0"}, // release beats newer prerelease
		{[]string{"2.0.0-beta.1", "2.0.0-beta.2"}, "2.0.0-beta.2"},
	}
	for _, tt := range tests {
		if got := npmLatestVersion(tt.versions); got != tt.want {
			t.Errorf("npmLatestVersion(%v) = %q, want %q", tt.versions, got, tt.want)
		}
	}
}

func sriFor(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestSRIVerifier(t *testing.T) {
	data := []byte("tarball-bytes")

	v, err := newSRIVerifier(sriFor(data))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = v.Write(data)
	if err := v.verify(); err != nil {
		t.Errorf("matching sha512 integrity rejected: %v", err)
	}

	v, err = newSRIVerifier(sriFor([]byte("other")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = v.Write(data)
	if err := v.verify(); err == nil {
		t.Error("mismatched integrity accepted")
	}

	// The strongest of several entries wins (sha512 over sha1).
	sum := sha1.Sum(data) //nolint:gosec // legacy integrity format under test
	multi := "sha1-" + base64.StdEncoding.EncodeToString(sum[:]) + " " + sriFor(data)
	v, err = newSRIVerifier(multi)
	if err != nil {
		t.Fatal(err)
	}
	if v.algo != "sha512" {
		t.Errorf("picked %q, want sha512", v.algo)
	}

	if v, err := newSRIVerifier(""); err != nil || v != nil {
		t.Errorf("empty integrity should verify nothing: %v, %v", v, err)
	}
	if _, err := newSRIVerifier("md5-abcd"); err == nil {
		t.Error("unsupported algorithm accepted")
	}
	if _, err := newSRIVerifier("sha512-!!not-base64!!"); err == nil {
		t.Error("invalid base64 accepted")
	}
}

func TestParseNpmLock(t *testing.T) {
	lock := `{
	  "name": "artigate-collect", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "artigate-collect", "version": "0.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.example/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-aaaa"},
	    "node_modules/@scope/pkg": {"version": "1.0.0", "resolved": "https://registry.example/@scope/pkg/-/pkg-1.0.0.tgz", "integrity": "sha512-bbbb"},
	    "node_modules/a/node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.example/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-aaaa"},
	    "node_modules/alias": {"name": "real-name", "version": "2.0.0", "resolved": "https://registry.example/real-name/-/real-name-2.0.0.tgz", "integrity": "sha512-cccc"},
	    "node_modules/linked": {"link": true, "resolved": "../somewhere"},
	    "node_modules/bundled": {"version": "1.0.0", "inBundle": true},
	    "node_modules/gitdep": {"version": "3.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"},
	    "node_modules/nointegrity": {"version": "9.9.9", "resolved": "https://registry.example/nointegrity/-/nointegrity-9.9.9.tgz"},
	    "packages/workspace-app": {"version": "0.1.0"}
	  }
	}`
	entries, skipped, err := parseNpmLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]npmLockEntry{}
	for _, e := range entries {
		got[e.Name+"@"+e.Version] = e
	}
	for _, want := range []string{"lodash@4.17.21", "@scope/pkg@1.0.0", "real-name@2.0.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing lock entry %s (got %v)", want, entries)
		}
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 deduplicated entries, got %d: %v", len(entries), entries)
	}
	// A git dependency (unsupported URL) and a registry entry with no integrity
	// hash (unverifiable) are both skipped and reported, never forwarded.
	skippedErr := map[string]string{}
	for _, s := range skipped {
		skippedErr[s.Module] = s.Error
	}
	if len(skipped) != 2 {
		t.Errorf("expected 2 skipped deps, got %d: %v", len(skipped), skipped)
	}
	if _, ok := skippedErr["gitdep"]; !ok {
		t.Errorf("expected gitdep skipped, got %v", skipped)
	}
	if msg, ok := skippedErr["nointegrity"]; !ok || !strings.Contains(msg, "integrity") {
		t.Errorf("expected nointegrity skipped for missing integrity, got %v", skipped)
	}

	if _, _, err := parseNpmLock([]byte(`{"lockfileVersion":1,"dependencies":{}}`)); err == nil {
		t.Error("v1 lockfile without packages map should error")
	}
	if _, _, err := parseNpmLock([]byte("not json")); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestValidateNpmRequest(t *testing.T) {
	valid := []NpmCollectRequest{
		{Packages: []string{"lodash"}},
		{PackageJSON: `{"name":"x"}`},
		{PackageJSON: `{"name":"x"}`, PackageLock: `{"lockfileVersion":3}`},
	}
	invalid := []NpmCollectRequest{
		{},
		{Packages: []string{"--registry=http://x"}},
		{PackageJSON: "not json"},
		{PackageJSON: `{"name":"x"}`, PackageLock: "not json"},
		{PackageLock: `{"lockfileVersion":3}`}, // lock without package.json
	}
	for i, req := range valid {
		if err := validateNpmRequest(req); err != nil {
			t.Errorf("valid request %d rejected: %v", i, err)
		}
	}
	for i, req := range invalid {
		if err := validateNpmRequest(req); err == nil {
			t.Errorf("invalid request %d accepted", i)
		}
	}
}

func TestValidateNpmPackages(t *testing.T) {
	seen := map[string]bool{"npm/packages/lodash/lodash-4.17.21.tgz": true}
	good := []NpmPackage{{
		Name: "lodash", Version: "4.17.21", Filename: "lodash-4.17.21.tgz",
		Path: "npm/packages/lodash/lodash-4.17.21.tgz", SHA256: strings.Repeat("a", 64),
	}}
	if err := validateNpmPackages(good, seen); err != nil {
		t.Errorf("valid packages rejected: %v", err)
	}

	bad := []struct {
		name string
		pkgs []NpmPackage
	}{
		{"missing name", []NpmPackage{{Version: "1.0.0", Path: "npm/packages/x/x-1.0.0.tgz"}}},
		{"bad version", []NpmPackage{{Name: "x", Version: "../..", Path: "npm/packages/x/x-1.tgz"}}},
		{"outside npm tree", []NpmPackage{{Name: "x", Version: "1.0.0", Path: "python/packages/x.tgz"}}},
		{"unlisted file", []NpmPackage{{Name: "x", Version: "1.0.0", Path: "npm/packages/x/x-1.0.0.tgz"}}},
	}
	for _, tt := range bad {
		if err := validateNpmPackages(tt.pkgs, seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// makeNpmTgz builds a registry-shaped npm tarball whose embedded package.json
// carries the given name/version, under the given top-level directory
// ("package" by convention, but npm accepts any single directory).
func makeNpmTgz(t *testing.T, topDir, name, version string) []byte {
	t.Helper()
	manifest := fmt.Sprintf(`{"name":%q,"version":%q,"description":"test package for %s","license":"MIT","dependencies":{"left-pad":"^1.0.0"},"scripts":{"postinstall":"echo hi"}}`, name, version, name)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{
		{topDir + "/package.json", manifest},
		{topDir + "/index.js", "module.exports = 42;\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
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

func TestExtractNpmPackageJSON(t *testing.T) {
	dir := t.TempDir()

	// Non-"package" top directory still works (npm strips one component).
	p := filepath.Join(dir, "custom.tgz")
	writeFile(t, p, makeNpmTgz(t, "custom-root", "weird", "1.0.0"))
	b, err := extractNpmPackageJSON(p)
	if err != nil {
		t.Fatalf("extractNpmPackageJSON: %v", err)
	}
	if !strings.Contains(string(b), `"weird"`) {
		t.Errorf("unexpected manifest: %s", b)
	}

	// A tarball without package.json errors.
	empty := filepath.Join(dir, "empty.tgz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "package/readme.md", Mode: 0o644, Size: 2})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	_ = gz.Close()
	writeFile(t, empty, buf.Bytes())
	if _, err := extractNpmPackageJSON(empty); err == nil {
		t.Error("tarball without package.json accepted")
	}

	// Not a gzip stream at all.
	corrupt := filepath.Join(dir, "corrupt.tgz")
	writeFile(t, corrupt, []byte("not a tarball"))
	if _, err := extractNpmPackageJSON(corrupt); err == nil {
		t.Error("corrupt tarball accepted")
	}
}

// newNpmRegistry serves the given tarballs at registry-convention paths
// (/<name>/-/<file>.tgz) and returns the server.
func newNpmRegistry(t *testing.T, tarballs map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := tarballs[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeFakeNpm writes a stand-in npm binary that emits the given
// package-lock.json into the working directory, mimicking
// `npm install --package-lock-only`.
func writeFakeNpm(t *testing.T, lockJSON string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake npm shell script is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for fake npm script")
	}
	script := "#!/usr/bin/env bash\nset -eu\ncat > package-lock.json <<'ARTIGATE_LOCK'\n" + lockJSON + "\nARTIGATE_LOCK\n"
	p := filepath.Join(t.TempDir(), "npm")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// npmTestFixture is a low server wired to a fake registry serving lodash and a
// scoped package, with a fake npm that resolves to exactly those two.
type npmTestFixture struct {
	ls     *LowServer
	priv   ed25519.PrivateKey
	lodash []byte
	scoped []byte
}

func newNpmFixture(t *testing.T) npmTestFixture {
	t.Helper()
	lodash := makeNpmTgz(t, "package", "lodash", "4.17.21")
	scoped := makeNpmTgz(t, "package", "@artigate/scoped", "1.0.0")
	registry := newNpmRegistry(t, map[string][]byte{
		"/lodash/-/lodash-4.17.21.tgz":         lodash,
		"/@artigate/scoped/-/scoped-1.0.0.tgz": scoped,
	})
	lock := fmt.Sprintf(`{
	  "name": "artigate-collect", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "artigate-collect", "version": "0.0.0"},
	    "node_modules/lodash": {"version": "4.17.21", "resolved": "%s/lodash/-/lodash-4.17.21.tgz", "integrity": "%s"},
	    "node_modules/@artigate/scoped": {"version": "1.0.0", "resolved": "%s/@artigate/scoped/-/scoped-1.0.0.tgz", "integrity": "%s"}
	  }
	}`, registry.URL, sriFor(lodash), registry.URL, sriFor(scoped))

	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:      t.TempDir(),
		ExportDir: filepath.Join(t.TempDir(), "out"),
		NpmBinary: writeFakeNpm(t, lock),
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return npmTestFixture{ls: ls, priv: priv, lodash: lodash, scoped: scoped}
}

func TestLowServerNpmCollectAdmin(t *testing.T) {
	fx := newNpmFixture(t)
	srv := httptest.NewServer(fx.ls)
	defer srv.Close()

	body := strings.NewReader(`{"packages":["lodash"]}`)
	resp, err := http.Post(srv.URL+"/admin/npm/collect", "application/json", body) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect admin status = %d, want 200: %s", resp.StatusCode, b)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "npm-bundle-000001" || res.ExportedModules != 2 {
		t.Errorf("unexpected collect result: %+v", res)
	}

	// An empty request is rejected with 400.
	bad, err := http.Post(srv.URL+"/admin/npm/collect", "application/json", strings.NewReader(`{}`)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("empty collect status = %d, want 400", bad.StatusCode)
	}
}

func TestCollectNpmRejectsFlagInjection(t *testing.T) {
	fx := newNpmFixture(t)
	_, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{
		Packages: []string{"--registry=http://attacker.example", "evilpkg"},
	})
	if err == nil {
		t.Fatal("CollectNpm accepted a flag-like spec")
	}
	if !strings.Contains(err.Error(), "'-'") {
		t.Errorf("error should explain the flag rejection, got: %v", err)
	}
}

func TestCollectNpmVerifiesIntegrity(t *testing.T) {
	// A registry that serves different bytes than the lockfile pinned.
	tampered := makeNpmTgz(t, "package", "lodash", "4.17.21")
	registry := newNpmRegistry(t, map[string][]byte{"/lodash/-/lodash-4.17.21.tgz": tampered})
	lock := fmt.Sprintf(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "artigate-collect"},
	    "node_modules/lodash": {"version": "4.17.21", "resolved": "%s/lodash/-/lodash-4.17.21.tgz", "integrity": "%s"}
	  }
	}`, registry.URL, sriFor([]byte("the real bytes")))

	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), NpmBinary: writeFakeNpm(t, lock)}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ls.Close() }()

	_, err = ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
		t.Fatalf("tampered tarball should fail the collect with an integrity error, got: %v", err)
	}
	// The failed collect must not have burned a sequence number.
	if seq := ls.peekSequence(streamNpm); seq != 1 {
		t.Errorf("sequence advanced to %d after failed collect, want 1", seq)
	}
}

func TestLowToHighNpmPipeline(t *testing.T) {
	fx := newNpmFixture(t)
	res, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err != nil {
		t.Fatalf("CollectNpm: %v", err)
	}
	if res.BundleID != "npm-bundle-000001" || res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	// Deliver the low-produced bundle to a high server and import it.
	pub := fx.priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range bundleSuffixes() {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(fx.ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of npm bundle failed: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	assertNpmPackument(t, srv.URL, fx.lodash)
	assertNpmScopedAndVersion(t, srv.URL, fx.scoped)

	// Unknown package and traversal 404/400.
	if code, _ := httpGet(t, srv.URL+"/npm/nope"); code != http.StatusNotFound {
		t.Errorf("unknown package status %d, want 404", code)
	}
	if code, _ := httpGet(t, srv.URL+"/npm/lodash/-/..%2f..%2fsecret.tgz"); code == http.StatusOK {
		t.Error("traversal tarball path should not succeed")
	}
}

// assertNpmPackument checks the lodash packument: dist-tags, dist section, and
// that the advertised tarball URL serves the exact collected bytes.
func assertNpmPackument(t *testing.T, base string, wantTarball []byte) {
	t.Helper()
	code, body := httpGet(t, base+"/npm/lodash")
	if code != http.StatusOK {
		t.Fatalf("packument status %d: %s", code, body)
	}
	var doc struct {
		Name     string            `json:"name"`
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Version string `json:"version"`
			Dist    struct {
				Tarball   string `json:"tarball"`
				Shasum    string `json:"shasum"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
			HasInstallScript bool `json:"hasInstallScript"`
		} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("packument is not JSON: %v\n%s", err, body)
	}
	if doc.Name != "lodash" || doc.DistTags["latest"] != "4.17.21" {
		t.Errorf("packument identity wrong: %+v", doc)
	}
	v, ok := doc.Versions["4.17.21"]
	if !ok {
		t.Fatalf("packument missing version 4.17.21: %s", body)
	}
	wantURL := base + "/npm/lodash/-/lodash-4.17.21.tgz"
	if v.Dist.Tarball != wantURL {
		t.Errorf("dist.tarball = %q, want %q", v.Dist.Tarball, wantURL)
	}
	if v.Dist.Integrity != sriFor(wantTarball) {
		t.Errorf("dist.integrity = %q, want %q", v.Dist.Integrity, sriFor(wantTarball))
	}
	sum := sha1.Sum(wantTarball) //nolint:gosec // asserting the legacy shasum field
	if v.Dist.Shasum != hex.EncodeToString(sum[:]) {
		t.Errorf("dist.shasum = %q, want %q", v.Dist.Shasum, hex.EncodeToString(sum[:]))
	}
	if !v.HasInstallScript {
		t.Error("hasInstallScript not set despite a postinstall script")
	}

	code, got := httpGet(t, wantURL)
	if code != http.StatusOK || got != string(wantTarball) {
		t.Errorf("tarball download: status %d, %d bytes (want %d)", code, len(got), len(wantTarball))
	}
}

// assertNpmScopedAndVersion checks the scoped package via both the literal and
// URL-encoded name forms, and the single-version manifest route.
func assertNpmScopedAndVersion(t *testing.T, base string, wantTarball []byte) {
	t.Helper()
	for _, p := range []string{"/npm/@artigate/scoped", "/npm/@artigate%2fscoped"} {
		code, body := httpGet(t, base+p)
		if code != http.StatusOK || !strings.Contains(body, `"1.0.0"`) {
			t.Errorf("GET %s: status %d body %q", p, code, body)
		}
	}
	code, body := httpGet(t, base+"/npm/@artigate/scoped/1.0.0")
	if code != http.StatusOK {
		t.Fatalf("version manifest status %d", code)
	}
	var v struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		License string `json:"license"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("version manifest not JSON: %v", err)
	}
	if v.Name != "@artigate/scoped" || v.Version != "1.0.0" || v.License != "MIT" {
		t.Errorf("unexpected version manifest: %+v", v)
	}
	code, got := httpGet(t, base+"/npm/@artigate/scoped/-/scoped-1.0.0.tgz")
	if code != http.StatusOK || got != string(wantTarball) {
		t.Errorf("scoped tarball download: status %d, %d bytes (want %d)", code, len(got), len(wantTarball))
	}
}

// writeSignedNpmBundle builds a signed npm bundle in landing from raw tarball
// bytes, reusing the production tar/sign helpers.
func writeSignedNpmBundle(t *testing.T, landing string, priv ed25519.PrivateKey, seq int64, tarballs map[string][]byte) {
	t.Helper()
	src := t.TempDir()
	var files []ManifestFile
	var pkgs []NpmPackage
	for spec, content := range tarballs {
		name, version, _ := strings.Cut(spec, "@@")
		rel := "npm/packages/" + name + "/" + npmTarballFilename(name, version)
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
		pkgs = append(pkgs, NpmPackage{Name: name, Version: version, Filename: npmTarballFilename(name, version), Path: rel, SHA256: mf.SHA256})
	}

	bundleID := bundleIDFor(streamNpm, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamNpm,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Ecosystems:       []string{"npm"},
		Npm:              &NpmManifest{Packages: pkgs},
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

// TestNpmImportSkipsCorruptTarball proves that one unparseable tarball in a
// bundle is skipped (its version 404s) while the rest of the bundle imports
// and serves — a bad artifact must never wedge the stream.
func TestNpmImportSkipsCorruptTarball(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	good := makeNpmTgz(t, "package", "good", "1.0.0")
	writeSignedNpmBundle(t, hs.cfg.Landing, priv, 1, map[string][]byte{
		"good@@1.0.0":   good,
		"broken@@1.0.0": []byte("not a tarball at all"),
	})

	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import with a corrupt member failed entirely: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	if code, _ := httpGet(t, srv.URL+"/npm/good"); code != http.StatusOK {
		t.Errorf("good package should serve, got %d", code)
	}
	if code, _ := httpGet(t, srv.URL+"/npm/broken"); code != http.StatusNotFound {
		t.Errorf("broken package should 404, got %d", code)
	}
}

func TestNpmTreeAndDetail(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedNpmBundle(t, hs.cfg.Landing, priv, 1, map[string][]byte{
		"lodash@@4.17.21": makeNpmTgz(t, "package", "lodash", "4.17.21"),
	})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/ui/api/tree?eco=npm&path=")
	if code != http.StatusOK || !strings.Contains(body, `"lodash"`) {
		t.Fatalf("npm tree root: status %d body %q", code, body)
	}
	code, body = httpGet(t, srv.URL+"/ui/api/tree?eco=npm&path=lodash")
	if code != http.StatusOK || !strings.Contains(body, `"lodash@4.17.21"`) {
		t.Fatalf("npm tree versions: status %d body %q", code, body)
	}
	code, body = httpGet(t, srv.URL+"/ui/api/detail?eco=npm&path=lodash@4.17.21")
	if code != http.StatusOK || !strings.Contains(body, "Integrity") || !strings.Contains(body, "MIT") {
		t.Fatalf("npm detail: status %d body %q", code, body)
	}
	var d UIDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/npm/lodash/-/lodash-4.17.21.tgz" || d.Downloads[0].Label != "lodash-4.17.21.tgz" {
		t.Errorf("npm detail downloads = %+v", d.Downloads)
	}
	if code, _ := httpGet(t, srv.URL+"/ui/api/detail?eco=npm&path=lodash@9.9.9"); code != http.StatusNotFound {
		t.Errorf("missing version detail should 404, got %d", code)
	}
}

// TestNpmUIWiring asserts both dashboards expose the NPM ecosystem.
func TestNpmUIWiring(t *testing.T) {
	for _, want := range []string{`data-view="npm"`, `id="view-npm"`, "collectNpm", "scheduleNpm", `/admin/npm/collect`} {
		if !strings.Contains(lowUIHTML, want) {
			t.Errorf("low-side UI missing %s", want)
		}
	}
	for _, want := range []string{`data-view="npm"`} {
		if !strings.Contains(uiIndexHTML, want) {
			t.Errorf("high-side UI missing %s", want)
		}
	}
	for _, want := range []string{"npmGuideSection", `npm: "NPM packages"`} {
		if !strings.Contains(uiAppJS, want) {
			t.Errorf("high-side app.js missing %s", want)
		}
	}
}

// -----------------------------------------------------------------------------
// Dist-tags: collection, validation, and serving
// -----------------------------------------------------------------------------

func TestNpmRegistryBaseFor(t *testing.T) {
	for _, tt := range []struct{ name, resolved, want string }{
		{"lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "https://registry.npmjs.org"},
		{"@scope/pkg", "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", "https://registry.npmjs.org"},
		{"left-pad", "https://nexus.corp/repository/npm-proxy/left-pad/-/left-pad-1.3.0.tgz", "https://nexus.corp/repository/npm-proxy"},
		{"lodash", "https://cdn.example/other/path.tgz", ""},
	} {
		if got := npmRegistryBaseFor(tt.name, tt.resolved); got != tt.want {
			t.Errorf("npmRegistryBaseFor(%q, %q) = %q, want %q", tt.name, tt.resolved, got, tt.want)
		}
	}
}

func TestValidateNpmDistTags(t *testing.T) {
	good := map[string]map[string]string{
		"lodash":     {"latest": "4.17.21", "next": "5.0.0-beta.1"},
		"@scope/pkg": {"v2-latest": "2.0.0"},
	}
	if err := validateNpmDistTags(good); err != nil {
		t.Fatalf("valid dist-tags rejected: %v", err)
	}
	for name, bad := range map[string]map[string]map[string]string{
		"bad package name": {"../etc": {"latest": "1.0.0"}},
		"bad tag name":     {"lodash": {".hidden": "1.0.0"}},
		"tag with slash":   {"lodash": {"a/b": "1.0.0"}},
		"bad version":      {"lodash": {"latest": "not-a-version"}},
	} {
		if err := validateNpmDistTags(bad); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestNpmFetchDistTags exercises the best-effort tag fetch: a registry
// serving tags (with junk entries to drop), a package whose packument 404s,
// and a package with an unusable resolved URL.
func TestNpmFetchDistTags(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/lodash", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != npmAbbreviatedType {
			t.Errorf("packument fetched without the abbreviated media type: %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"4.17.21","next":"5.0.0-beta.1","bad tag":"1.0.0","broken":"not_a_version"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	entries := []npmLockEntry{
		{Name: "lodash", Resolved: srv.URL + "/lodash/-/lodash-4.17.21.tgz"},
		{Name: "gone", Resolved: srv.URL + "/gone/-/gone-1.0.0.tgz"},
		{Name: "weird", Resolved: "https://cdn.example/blob.tgz"},
	}
	tags := fetchNpmDistTags(context.Background(), entries)
	if len(tags) != 1 || tags["lodash"] == nil {
		t.Fatalf("fetchNpmDistTags = %+v, want lodash only", tags)
	}
	want := map[string]string{"latest": "4.17.21", "next": "5.0.0-beta.1"}
	if len(tags["lodash"]) != len(want) || tags["lodash"]["latest"] != want["latest"] || tags["lodash"]["next"] != want["next"] {
		t.Errorf("lodash tags = %+v, want %+v (junk dropped)", tags["lodash"], want)
	}
}

// TestNpmDistTagsServing publishes two versions plus an upstream tag
// snapshot and asserts the packument's dist-tags honor mirrored upstream
// tags, filter tags whose target is absent, and regenerate latest; the
// GET /npm/<name>/<tag> route resolves served tags only.
func TestNpmDistTagsServing(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	for _, v := range []string{"1.0.0", "1.1.0"} {
		tgz := makeNpmTgz(t, "package", "tagpkg", v)
		rel := "npm/packages/tagpkg/tagpkg-" + v + ".tgz"
		abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, tgz)
		if err := hs.publishNpmPackage(NpmPackage{Name: "tagpkg", Version: v, Path: rel}); err != nil {
			t.Fatalf("publishNpmPackage %s: %v", v, err)
		}
	}
	// Upstream pinned latest at the OLDER release and tags a beta this mirror
	// does not hold.
	err := hs.publishNpmDistTags("tagpkg", map[string]string{
		"latest": "1.0.0",
		"stable": "1.1.0",
		"beta":   "2.0.0-beta.1",
	})
	if err != nil {
		t.Fatalf("publishNpmDistTags: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/npm/tagpkg")
	if code != http.StatusOK {
		t.Fatalf("packument status %d", code)
	}
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"latest": "1.0.0", "stable": "1.1.0"}
	if len(doc.DistTags) != len(want) || doc.DistTags["latest"] != want["latest"] || doc.DistTags["stable"] != want["stable"] {
		t.Errorf("dist-tags = %+v, want %+v (upstream latest honored, absent beta dropped)", doc.DistTags, want)
	}

	// The tag route serves the tagged version manifest; unknown and absent
	// tags 404.
	assertServed(t, srv.URL+"/npm/tagpkg/stable", `"version": "1.1.0"`)
	for _, p := range []string{"/npm/tagpkg/beta", "/npm/tagpkg/nosuch"} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}

	// Dropping the stored snapshot falls back to the regenerated latest.
	if err := os.Remove(filepath.Join(hs.npmMetadataDir(), "tagpkg", "_tags.json")); err != nil {
		t.Fatal(err)
	}
	_, body = httpGet(t, srv.URL+"/npm/tagpkg")
	if !strings.Contains(body, `"latest": "1.1.0"`) {
		t.Errorf("packument without stored tags lost the computed latest:\n%s", body)
	}
}

// TestNpmDistTagsImportRejection proves import-time validation rejects a
// manifest whose dist-tags are malformed.
func TestNpmDistTagsImportRejection(t *testing.T) {
	eco, ok := ecosystemFor(streamNpm)
	if !ok {
		t.Fatal("npm ecosystem not registered")
	}
	m := BundleManifest{Npm: &NpmManifest{
		Packages: []NpmPackage{{Name: "a", Version: "1.0.0", Path: "npm/packages/a/a-1.0.0.tgz"}},
		DistTags: map[string]map[string]string{"a": {"latest": "../evil"}},
	}}
	seen := map[string]bool{"npm/packages/a/a-1.0.0.tgz": true}
	if err := eco.validateContent(m, seen); err == nil {
		t.Fatal("malformed dist-tag version accepted at import")
	}
}
