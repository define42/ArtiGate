package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// covP2Write writes b to p, creating parent directories first.
func covP2Write(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, b)
}

// =============================================================================
// apt.go
// =============================================================================

// TestCovP2_ValidateAptMirrorConfig drives every arm of the collect-side config
// validator: the rejects, the defaulting, and the accept.
func TestCovP2_ValidateAptMirrorConfig(t *testing.T) {
	if _, err := validateAptMirrorConfig(aptMirrorConfig{}); err == nil {
		t.Error("empty URI should be rejected")
	}
	if _, err := validateAptMirrorConfig(aptMirrorConfig{URI: "ftp://x/y", Suites: []string{"s"}}); err == nil {
		t.Error("non-http scheme should be rejected")
	}
	if _, err := validateAptMirrorConfig(aptMirrorConfig{URI: "https://x/y"}); err == nil {
		t.Error("missing suites should be rejected")
	}
	if _, err := validateAptMirrorConfig(aptMirrorConfig{URI: "https://x/y", Suites: []string{"s"}, Name: "a/b"}); err == nil {
		t.Error("mirror name with a slash should be rejected")
	}
	if _, err := validateAptMirrorConfig(aptMirrorConfig{URI: "https://x/y", Suites: []string{"bad token"}}); err == nil {
		t.Error("suite token with a space should be rejected")
	}

	// Accept: components/architectures default in, and the name derives from URI.
	got, err := validateAptMirrorConfig(aptMirrorConfig{URI: "https://packages.example/repo", Suites: []string{"stable"}})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(got.Components) != 1 || got.Components[0] != "main" ||
		len(got.Architectures) != 1 || got.Architectures[0] != "amd64" || got.Name == "" {
		t.Fatalf("defaulting wrong: %+v", got)
	}
}

// TestCovP2_ValidateAptMirrorImport covers the import-side mirror/package
// validators, one rejection per branch plus the accept.
func TestCovP2_ValidateAptMirrorImport(t *testing.T) {
	seen := map[string]bool{"apt/m/pool/main/c/code_1_amd64.deb": true}
	suite := AptSuite{Name: "stable", Components: []string{"main"}, Architectures: []string{"amd64"}}
	pkg := AptPackage{
		Package: "code", Version: "1", Architecture: "amd64", Suite: "stable", Component: "main",
		Filename: "pool/main/c/code_1_amd64.deb", SHA256: strings.Repeat("a", 64), Size: 1,
	}

	good := AptMirror{Name: "m", Suites: []AptSuite{suite}, Packages: []AptPackage{pkg}}
	if err := validateAptMirrors([]AptMirror{good}, seen); err != nil {
		t.Fatalf("valid mirror rejected: %v", err)
	}

	bad := []AptMirror{
		{Name: "", Suites: []AptSuite{suite}},             // missing name
		{Name: "a/b", Suites: []AptSuite{suite}},          // slash in name
		{Name: "m", Suites: []AptSuite{{Name: "stable"}}}, // suite missing components/arch
		{Name: "m", Suites: []AptSuite{{Name: "bad tok", Components: []string{"main"}, Architectures: []string{"amd64"}}}}, // bad token
	}
	for i, m := range bad {
		if err := validateAptMirror(m, seen); err == nil {
			t.Errorf("bad mirror %d accepted", i)
		}
	}

	// Package-level rejections.
	noFile := AptPackage{Package: "code", Suite: "stable"}
	if err := validateAptPackage("m", noFile, map[string]bool{"stable": true}, seen); err == nil {
		t.Error("package missing filename/sha256 accepted")
	}
	wrongSuite := pkg
	wrongSuite.Suite = "other"
	if err := validateAptPackage("m", wrongSuite, map[string]bool{"stable": true}, seen); err == nil {
		t.Error("package with unknown suite accepted")
	}
	unlisted := pkg
	unlisted.Filename = "pool/main/c/absent.deb"
	if err := validateAptPackage("m", unlisted, map[string]bool{"stable": true}, seen); err == nil {
		t.Error("package referencing an unlisted file accepted")
	}
}

// TestCovP2_AptDetail drives the dashboard detail resolver for one package,
// covering each error arm and the success path off a written index.json.
func TestCovP2_AptDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	for _, spec := range []string{"noatsign", "@1.0", "code@", "a/b/c@1", "../x/y/z@1"} {
		if _, err := hs.aptDetail(spec); err == nil {
			t.Errorf("aptDetail(%q) accepted a malformed spec", spec)
		}
	}
	if _, err := hs.aptDetail("missing/stable/main/code@1.0"); err == nil {
		t.Error("aptDetail on an absent mirror should error")
	}

	// Write an index and query a present and an absent version.
	mirror := AptMirror{
		Name:   "m",
		Suites: []AptSuite{{Name: "stable", Components: []string{"main"}, Architectures: []string{"amd64"}}},
		Packages: []AptPackage{{
			Package: "code", Version: "1.0", Architecture: "amd64", Suite: "stable", Component: "main",
			Filename: "pool/main/c/code_1.0_amd64.deb", SHA256: strings.Repeat("b", 64), Size: 10,
		}},
	}
	b, _ := json.MarshalIndent(mirror, "", "  ")
	covP2Write(t, filepath.Join(hs.aptDir(), "m", "index.json"), b)

	if _, err := hs.aptDetail("m/stable/main/code@9.9"); err == nil {
		t.Error("aptDetail for an absent version should error")
	}
	d, err := hs.aptDetail("m/stable/main/code@1.0")
	if err != nil || d.Subtitle != "1.0" {
		t.Fatalf("aptDetail = %+v, %v", d, err)
	}
}

// TestCovP2_ServeAptMethodAndEmpty covers serveApt's non-static branches.
func TestCovP2_ServeAptMethodAndEmpty(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Bare /apt with no relative path is a 404.
	if code, _ := httpGet(t, srv.URL+"/apt"); code != http.StatusNotFound {
		t.Errorf("GET /apt = %d, want 404", code)
	}
	// A write method is rejected.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/apt/x", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /apt/x = %d, want 405", resp.StatusCode)
	}
}

// TestCovP2_AptRepoListSigned exercises the signed-mirror branch of aptRepoList
// (an InRelease present for every suite) and the empty-tree short-circuit.
func TestCovP2_AptRepoListSigned(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	if repos, err := hs.aptRepoList(); err != nil || repos != nil {
		t.Fatalf("aptRepoList on empty tree = %v, %v; want nil, nil", repos, err)
	}

	mirror := AptMirror{Name: "m", Suites: []AptSuite{{Name: "stable", Components: []string{"main"}, Architectures: []string{"amd64"}}}}
	b, _ := json.MarshalIndent(mirror, "", "  ")
	covP2Write(t, filepath.Join(hs.aptDir(), "m", "index.json"), b)
	// Also drop a non-directory entry beside it to hit the !IsDir skip.
	covP2Write(t, filepath.Join(hs.aptDir(), "stray.txt"), []byte("x"))
	covP2Write(t, filepath.Join(hs.aptDir(), "m", "dists", "stable", "InRelease"), []byte("signed"))

	repos, err := hs.aptRepoList()
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || !repos[0].Signed {
		t.Fatalf("aptRepoList = %+v, want one signed repo", repos)
	}
}

// TestCovP2_FetchAptPackagesIndex covers each outcome of the index fetcher:
// no advertised index, a fetch error, a checksum mismatch, a decompress
// failure, and the gzip success path.
func TestCovP2_FetchAptPackagesIndex(t *testing.T) {
	ls, _ := newAptLowServer(t)
	ctx := context.Background()

	packages := []byte("Package: code\nVersion: 1.0\nArchitecture: amd64\n" +
		"Filename: pool/main/c/code_1.0_amd64.deb\nSize: 3\nSHA256: " + strings.Repeat("a", 64) + "\n\n")
	gz, err := gzipBytes(packages)
	if err != nil {
		t.Fatal(err)
	}
	dir := "main/binary-amd64"

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/"+dir+"/Packages.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz) })
	// A "Packages" file whose bytes are not gzip but whose declared checksum matches.
	notGz := []byte("this is not gzip but its checksum will match")
	mux.HandleFunc("/dists/stable/"+dir+"/Packages", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(notGz) })
	up := httptest.NewServer(mux)
	defer up.Close()
	distBase := up.URL + "/dists/stable"

	// No index advertised in Release checksums.
	if _, err := ls.fetchAptPackagesIndex(ctx, distBase, "stable", "main", "amd64", map[string]aptChecksum{}); err == nil {
		t.Error("empty checksums should yield a no-index error")
	}
	// Advertised but the served body's checksum disagrees.
	badSum := map[string]aptChecksum{dir + "/Packages.gz": {sha256: strings.Repeat("0", 64), size: int64(len(gz))}}
	if _, err := ls.fetchAptPackagesIndex(ctx, distBase, "stable", "main", "amd64", badSum); err == nil || !strings.Contains(err.Error(), "index") {
		t.Errorf("checksum mismatch = %v, want an index error", err)
	}
	// Advertised gzip path missing on the server (fetch error).
	miss := map[string]aptChecksum{dir + "/Packages.gz": {sha256: aptSHA256(gz)}}
	if _, err := ls.fetchAptPackagesIndex(context.Background(), up.URL+"/dists/absent", "stable", "main", "amd64", miss); err == nil {
		t.Error("a missing index file should surface a fetch error")
	}
	// A plain "Packages" whose checksum matches but body is not gzip: gunzip is
	// not applied to Packages, so this actually parses (zero stanzas). Instead
	// verify the decompress-failure path via a Packages.gz that is not gzip.
	corrupt := map[string]aptChecksum{dir + "/Packages.gz": {sha256: aptSHA256(notGz), size: int64(len(notGz))}}
	mux.HandleFunc("/dists/bad/"+dir+"/Packages.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(notGz) })
	if _, err := ls.fetchAptPackagesIndex(ctx, up.URL+"/dists/bad", "bad", "main", "amd64", corrupt); err == nil || !strings.Contains(err.Error(), "decompress") {
		t.Errorf("non-gzip Packages.gz = %v, want a decompress error", err)
	}

	// Success from the real gzip.
	okSum := map[string]aptChecksum{dir + "/Packages.gz": {sha256: aptSHA256(gz), size: int64(len(gz))}}
	pkgs, err := ls.fetchAptPackagesIndex(ctx, distBase, "stable", "main", "amd64", okSum)
	if err != nil || len(pkgs) != 1 || pkgs[0].Package != "code" {
		t.Fatalf("fetchAptPackagesIndex = %+v, %v", pkgs, err)
	}
}

// TestCovP2_HttpGetBytes covers the cap-exceeded, HTTP-error, and success arms.
func TestCovP2_HttpGetBytes(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 200)
	mux := http.NewServeMux()
	mux.HandleFunc("/data", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	up := httptest.NewServer(mux)
	defer up.Close()

	if _, err := httpGetBytes(context.Background(), up.URL+"/data", 10); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("small cap = %v, want a cap error", err)
	}
	if _, err := httpGetBytes(context.Background(), up.URL+"/missing", 1000); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("404 = %v, want an HTTP 404 error", err)
	}
	got, err := httpGetBytes(context.Background(), up.URL+"/data", 1000)
	if err != nil || len(got) != len(body) {
		t.Fatalf("httpGetBytes = %d bytes, %v", len(got), err)
	}
}

// TestCovP2_PruneAptDists covers the no-dists short-circuit and the prune of a
// stale suite directory.
func TestCovP2_PruneAptDists(t *testing.T) {
	root := t.TempDir()
	// No dists directory yet: a no-op success.
	if err := pruneAptDists(root, []string{"stable"}); err != nil {
		t.Fatalf("pruneAptDists with no dists dir = %v, want nil", err)
	}
	keep := filepath.Join(root, "dists", "stable")
	junk := filepath.Join(root, "dists", "junk")
	covP2Write(t, filepath.Join(keep, "Release"), []byte("keep"))
	covP2Write(t, filepath.Join(junk, "Release"), []byte("stale"))
	if err := pruneAptDists(root, []string{"stable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Errorf("stale dists/junk not pruned, stat = %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("dists/stable should survive, stat = %v", err)
	}
}

// TestCovP2_MergeAptMirror covers the second-import update path and the
// corrupt-index error branch.
func TestCovP2_MergeAptMirror(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	mk := func(version string) AptMirror {
		return AptMirror{
			Name:   "m",
			URI:    "https://ex/repo",
			Suites: []AptSuite{{Name: "stable", Components: []string{"main"}, Architectures: []string{"amd64"}}},
			Packages: []AptPackage{{
				Package: "code", Version: version, Architecture: "amd64", Suite: "stable", Component: "main",
				Filename: "pool/main/c/code.deb", SHA256: strings.Repeat("c", 64), Size: 1,
			}},
		}
	}
	if _, err := hs.mergeAptMirror(mk("1.0")); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	// Re-importing the same (suite, filename) key updates in place, not appends.
	merged, err := hs.mergeAptMirror(mk("2.0"))
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if len(merged.Packages) != 1 || merged.Packages[0].Version != "2.0" {
		t.Fatalf("merge did not update in place: %+v", merged.Packages)
	}

	// A corrupt on-disk index surfaces the unmarshal error.
	covP2Write(t, filepath.Join(hs.aptDir(), "m", "index.json"), []byte("{not json"))
	if _, err := hs.mergeAptMirror(mk("3.0")); err == nil {
		t.Error("mergeAptMirror with a corrupt index should error")
	}
}

// =============================================================================
// rpm.go
// =============================================================================

// TestCovP2_ValidateRpmMirrorConfigAndImport covers both RPM validators.
func TestCovP2_ValidateRpmMirrorConfigAndImport(t *testing.T) {
	// Collect-side config validator.
	if _, err := validateRpmMirrorConfig(rpmMirrorConfig{}); err == nil {
		t.Error("empty base_url accepted")
	}
	if _, err := validateRpmMirrorConfig(rpmMirrorConfig{BaseURL: "https://ex/$releasever/os"}); err == nil {
		t.Error("$-variable base_url accepted")
	}
	if _, err := validateRpmMirrorConfig(rpmMirrorConfig{BaseURL: "ftp://ex/repo"}); err == nil {
		t.Error("non-http base_url accepted")
	}
	if _, err := validateRpmMirrorConfig(rpmMirrorConfig{BaseURL: "https://ex/repo", Name: "a/b"}); err == nil {
		t.Error("mirror name with a slash accepted")
	}
	got, err := validateRpmMirrorConfig(rpmMirrorConfig{BaseURL: "https://dl.example/os"})
	if err != nil || got.Name == "" {
		t.Fatalf("valid config = %+v, %v", got, err)
	}

	// Import-side validator.
	seen := map[string]bool{
		"rpm/m/repodata/primary.xml.gz":      true,
		"rpm/m/Packages/code-1-1.x86_64.rpm": true,
	}
	good := RpmMirror{
		Name: "m", BaseURL: "https://ex/repo",
		Repodata: []RpmData{{Type: "primary", Href: "repodata/primary.xml.gz"}},
		Packages: []RpmPackage{{Name: "code", Version: "1", Location: "Packages/code-1-1.x86_64.rpm"}},
	}
	if err := validateRpmMirrors([]RpmMirror{good}, seen); err != nil {
		t.Fatalf("valid rpm mirror rejected: %v", err)
	}
	bad := []RpmMirror{
		{Name: "", BaseURL: "https://ex/repo"},                                       // missing name/baseurl
		{Name: "a/b", BaseURL: "https://ex/repo", Repodata: good.Repodata},           // slash
		{Name: "m", BaseURL: "https://ex/repo"},                                      // no repodata
		{Name: "m", BaseURL: "https://ex/repo", Repodata: []RpmData{{Href: "x.gz"}}}, // metadata not in files
		{
			Name: "m", BaseURL: "https://ex/repo", Repodata: good.Repodata,
			Packages: []RpmPackage{{Name: "z", Location: "Packages/absent.rpm"}},
		}, // pkg not in files
	}
	for i, m := range bad {
		if err := validateRpmMirror(m, seen); err == nil {
			t.Errorf("bad rpm mirror %d accepted", i)
		}
	}
}

// TestCovP2_RpmDetail covers the RPM detail resolver's error arms and success.
func TestCovP2_RpmDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	for _, spec := range []string{"noat", "@1", "code@", "noslash@1", "../m/code@1"} {
		if _, err := hs.rpmDetail(spec); err == nil {
			t.Errorf("rpmDetail(%q) accepted a malformed spec", spec)
		}
	}
	if _, err := hs.rpmDetail("missing/code@1"); err == nil {
		t.Error("rpmDetail on an absent mirror should error")
	}

	mirror := RpmMirror{
		Name: "m", BaseURL: "https://ex/repo",
		Packages: []RpmPackage{{
			Name: "code", Version: "1.0-1", Arch: "x86_64",
			Location: "Packages/code-1.0-1.x86_64.rpm", SHA256: strings.Repeat("d", 64), Size: 5,
		}},
	}
	b, _ := json.MarshalIndent(mirror, "", "  ")
	covP2Write(t, filepath.Join(hs.rpmDir(), "m", "index.json"), b)

	if _, err := hs.rpmDetail("m/code@9.9"); err == nil {
		t.Error("rpmDetail for an absent version should error")
	}
	d, err := hs.rpmDetail("m/code@1.0-1")
	if err != nil || d.Subtitle != "1.0-1" {
		t.Fatalf("rpmDetail = %+v, %v", d, err)
	}
}

// TestCovP2_ServeRpmMethodAndEmpty covers serveRpm's non-static branches, and
// rpmRepoList's signed branch.
func TestCovP2_ServeRpmMethodAndEmpty(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	if code, _ := httpGet(t, srv.URL+"/rpm"); code != http.StatusNotFound {
		t.Errorf("GET /rpm = %d, want 404", code)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/rpm/x", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /rpm/x = %d, want 405", resp.StatusCode)
	}

	// rpmRepoList reports Signed when a repomd.xml.asc is present.
	mirror := RpmMirror{Name: "m", BaseURL: "https://ex/repo", Repodata: []RpmData{{Type: "primary", Href: "repodata/primary.xml.gz"}}}
	b, _ := json.MarshalIndent(mirror, "", "  ")
	covP2Write(t, filepath.Join(hs.rpmDir(), "m", "index.json"), b)
	covP2Write(t, filepath.Join(hs.rpmDir(), "m", "repodata", "repomd.xml.asc"), []byte("sig"))
	repos, err := hs.rpmRepoList()
	if err != nil || len(repos) != 1 || !repos[0].Signed {
		t.Fatalf("rpmRepoList = %+v, %v; want one signed repo", repos, err)
	}
}

// TestCovP2_RpmCmpSegmentAlphaVsNumeric pins the cross-class comparison in
// rpmCmpSegment (an alpha run against a numeric run, both orders).
func TestCovP2_RpmCmpSegmentAlphaVsNumeric(t *testing.T) {
	if got := rpmVerCmp("a", "1"); got != -1 { // numeric beats alpha
		t.Errorf(`rpmVerCmp("a","1") = %d, want -1`, got)
	}
	if got := rpmVerCmp("1", "a"); got != 1 {
		t.Errorf(`rpmVerCmp("1","a") = %d, want 1`, got)
	}
}

// TestCovP2_RunXZError drives runXZ's nonzero-exit branch (garbage input).
func TestCovP2_RunXZError(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz not installed")
	}
	if _, err := runXZ([]byte("definitely not xz-compressed data"), 1<<20, "--decompress", "--stdout"); err == nil {
		t.Error("runXZ on garbage input should fail")
	}
}

// TestCovP2_MirrorRpmRepoErrors covers mirrorRpmRepo's early error arms with
// crafted fake upstreams (fetch failure, bad XML, and a repomd with no primary).
func TestCovP2_MirrorRpmRepoErrors(t *testing.T) {
	ls, _ := newRpmLowServer(t)
	ctx := context.Background()
	stage := t.TempDir()
	prior := func(string, string) bool { return false }
	arches := []string{"x86_64"}

	// No repomd on the server: fetchRepomd fails.
	empty := httptest.NewServer(http.NewServeMux())
	defer empty.Close()
	if _, _, err := ls.mirrorRpmRepo(ctx, rpmMirrorConfig{Name: "m", BaseURL: empty.URL}, stage, arches, true, prior); err == nil {
		t.Error("missing repomd should fail the mirror")
	}

	// Malformed repomd XML: xml.Unmarshal error.
	badMux := http.NewServeMux()
	badMux.HandleFunc("/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<repomd <<not xml")) })
	bad := httptest.NewServer(badMux)
	defer bad.Close()
	if _, _, err := ls.mirrorRpmRepo(ctx, rpmMirrorConfig{Name: "m", BaseURL: bad.URL}, stage, arches, true, prior); err == nil || !strings.Contains(err.Error(), "repomd") {
		t.Errorf("malformed repomd = %v, want a parse error", err)
	}

	// A well-formed repomd carrying no <data>: "no primary metadata".
	noPrimMux := http.NewServeMux()
	noPrimMux.HandleFunc("/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"></repomd>`))
	})
	noPrim := httptest.NewServer(noPrimMux)
	defer noPrim.Close()
	if _, _, err := ls.mirrorRpmRepo(ctx, rpmMirrorConfig{Name: "m", BaseURL: noPrim.URL}, stage, arches, true, prior); err == nil || !strings.Contains(err.Error(), "primary") {
		t.Errorf("no-primary repomd = %v, want a primary error", err)
	}
}

// =============================================================================
// java.go
// =============================================================================

// TestCovP2_ValidatePomDependency exercises each dependency-validation arm
// directly (the transitive/post-resolution constructs the pom-upload test only
// reaches through sanitizeUploadedPom).
func TestCovP2_ValidatePomDependency(t *testing.T) {
	props := map[string]string{"v": "1.2.3"}

	// Accept: property interpolation, allowed scope, valid exclusion.
	ok, err := validatePomDependency(pomDependency{
		GroupID: "org.x", ArtifactID: "y", Version: "${v}", Scope: "runtime",
		Exclusions: []pomExclusion{{GroupID: "*", ArtifactID: "*"}},
	}, props, false)
	if err != nil || ok.Version != "1.2.3" {
		t.Fatalf("valid dependency rejected: %+v, %v", ok, err)
	}

	bad := []struct {
		name string
		d    pomDependency
		mgmt bool
	}{
		{"systemPath", pomDependency{GroupID: "a", ArtifactID: "b", Version: "1", SystemPath: "/etc/passwd"}, false},
		{"bad groupId", pomDependency{GroupID: "a/b", ArtifactID: "b", Version: "1"}, false},
		{"bad artifactId", pomDependency{GroupID: "a", ArtifactID: "b/c", Version: "1"}, false},
		{"unresolvable prop", pomDependency{GroupID: "a", ArtifactID: "b", Version: "${nope}"}, false},
		{"bad exclusion", pomDependency{GroupID: "a", ArtifactID: "b", Version: "1", Exclusions: []pomExclusion{{GroupID: "bad/x", ArtifactID: "y"}}}, false},
	}
	for _, tc := range bad {
		if _, err := validatePomDependency(tc.d, props, tc.mgmt); err == nil {
			t.Errorf("%s: accepted an invalid dependency", tc.name)
		}
	}
}

// TestCovP2_ValidatePomScopeFieldsVersion covers the scope, field, and version
// sub-validators directly.
func TestCovP2_ValidatePomScopeFieldsVersion(t *testing.T) {
	base := pomDependency{GroupID: "a", ArtifactID: "b"}

	// Scope rules.
	if err := validatePomScope(pomDependency{Scope: "system"}, "a:b", false); err == nil {
		t.Error("system scope accepted")
	}
	if err := validatePomScope(pomDependency{Scope: "import"}, "a:b", false); err == nil {
		t.Error("import outside dependencyManagement accepted")
	}
	if err := validatePomScope(pomDependency{Scope: "import"}, "a:b", true); err == nil {
		t.Error("import BOM without <type>pom</type> accepted")
	}
	if err := validatePomScope(pomDependency{Scope: "import", Type: "pom"}, "a:b", true); err != nil {
		t.Errorf("valid import BOM rejected: %v", err)
	}
	if err := validatePomScope(pomDependency{Scope: "weird"}, "a:b", false); err == nil {
		t.Error("unsupported scope accepted")
	}

	// Field rules.
	for _, d := range []pomDependency{{Type: "bad type"}, {Classifier: "bad classifier"}, {Optional: "maybe"}} {
		if err := validatePomDependencyFields(d, "a:b"); err == nil {
			t.Errorf("invalid fields accepted: %+v", d)
		}
	}
	if err := validatePomDependencyFields(pomDependency{Type: "jar", Classifier: "sources", Optional: "true"}, "a:b"); err != nil {
		t.Errorf("valid fields rejected: %v", err)
	}

	// Version rules.
	mgmt := base
	if err := validatePomVersion(mgmt, "a:b", true); err == nil {
		t.Error("management entry without a version accepted")
	}
	if err := validatePomVersion(base, "a:b", false); err != nil {
		t.Errorf("versionless plain dep rejected: %v", err)
	}
	badVer := base
	badVer.Version = "1.0-SNAPSHOT"
	if err := validatePomVersion(badVer, "a:b", false); err == nil {
		t.Error("SNAPSHOT version accepted")
	}
}

// TestCovP2_ParentAsBOMImport covers the parent-to-BOM conversion arms.
func TestCovP2_ParentAsBOMImport(t *testing.T) {
	props := map[string]string{"pv": "2.0.0"}
	d, err := parentAsBOMImport(pomParent{GroupID: "org.x", ArtifactID: "parent", Version: "${pv}"}, props)
	if err != nil || d.Version != "2.0.0" || d.Type != "pom" || d.Scope != "import" {
		t.Fatalf("valid parent = %+v, %v", d, err)
	}
	if _, err := parentAsBOMImport(pomParent{GroupID: "a/b", ArtifactID: "p", Version: "1"}, props); err == nil {
		t.Error("bad parent coordinate accepted")
	}
	if _, err := parentAsBOMImport(pomParent{GroupID: "a", ArtifactID: "p", Version: "1-SNAPSHOT"}, props); err == nil {
		t.Error("SNAPSHOT parent version accepted")
	}
	if _, err := parentAsBOMImport(pomParent{GroupID: "${nope}", ArtifactID: "p", Version: "1"}, props); err == nil {
		t.Error("unresolvable parent property accepted")
	}
}

// TestCovP2_SkipMavenFile covers each bookkeeping-file class plus a real
// artifact (kept).
func TestCovP2_SkipMavenFile(t *testing.T) {
	skip := []string{
		"_remote.repositories", "maven-metadata-central.xml", "resolver-status.properties",
		"slf4j-api-2.0.16.jar.lastUpdated", "part.download.part", "download.tmp",
	}
	for _, n := range skip {
		if !skipMavenFile(n) {
			t.Errorf("skipMavenFile(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"slf4j-api-2.0.16.jar", "slf4j-api-2.0.16.pom"} {
		if skipMavenFile(n) {
			t.Errorf("skipMavenFile(%q) = true, want false", n)
		}
	}
}

// TestCovP2_ValidateMavenArtifacts covers the import-side artifact validator.
func TestCovP2_ValidateMavenArtifacts(t *testing.T) {
	seen := map[string]bool{"maven/org/x/y/1.0/y-1.0.jar": true}
	good := []MavenArtifact{{GroupID: "org.x", ArtifactID: "y", Version: "1.0", Files: []string{"maven/org/x/y/1.0/y-1.0.jar"}}}
	if err := validateMavenArtifacts(good, seen); err != nil {
		t.Fatalf("valid artifacts rejected: %v", err)
	}
	bad := [][]MavenArtifact{
		{{ArtifactID: "y", Version: "1.0", Files: []string{"x"}}},                                  // missing group
		{{GroupID: "org.x", ArtifactID: "y", Version: "1.0"}},                                      // no files
		{{GroupID: "org.x", ArtifactID: "y", Version: "1.0", Files: []string{"maven/absent.jar"}}}, // file not in seen
	}
	for i, arts := range bad {
		if err := validateMavenArtifacts(arts, seen); err == nil {
			t.Errorf("bad artifact set %d accepted", i)
		}
	}
}

// TestCovP2_CollectMavenRepo walks a synthetic local repo and confirms the
// bookkeeping/too-shallow files are dropped while real GAV files are grouped.
func TestCovP2_CollectMavenRepo(t *testing.T) {
	repo := t.TempDir()
	// A real artifact laid out in Maven 2 layout.
	gav := filepath.Join(repo, "org", "slf4j", "slf4j-api", "2.0.16")
	covP2Write(t, filepath.Join(gav, "slf4j-api-2.0.16.jar"), []byte("JAR"))
	covP2Write(t, filepath.Join(gav, "slf4j-api-2.0.16.pom"), []byte("<project/>"))
	// Bookkeeping beside it: skipped by skipMavenFile.
	covP2Write(t, filepath.Join(gav, "_remote.repositories"), []byte(""))
	covP2Write(t, filepath.Join(gav, "maven-metadata-central.xml"), []byte("<metadata/>"))
	// A file too shallow to be a GAV member: ignored (len(segs) < 4).
	covP2Write(t, filepath.Join(repo, "toplevel.txt"), []byte("x"))

	files, artifacts, err := collectMavenRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || len(artifacts) != 1 {
		t.Fatalf("collectMavenRepo files=%d artifacts=%d, want 2 files / 1 artifact", len(files), len(artifacts))
	}
	a := artifacts[0]
	if a.GroupID != "org.slf4j" || a.ArtifactID != "slf4j-api" || a.Version != "2.0.16" || len(a.Files) != 2 {
		t.Fatalf("unexpected artifact: %+v", a)
	}
}

// TestCovP2_MavenDetail covers mavenDetail's error arms and the success path.
func TestCovP2_MavenDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	for _, spec := range []string{"noat", "@1", "org/x@", "../x@1", "org/x@1/../2"} {
		if _, err := hs.mavenDetail(spec); err == nil {
			t.Errorf("mavenDetail(%q) accepted a malformed spec", spec)
		}
	}
	if _, err := hs.mavenDetail("org/example/absent@1.0"); err == nil {
		t.Error("mavenDetail on an absent artifact should error")
	}

	dir := filepath.Join(hs.mavenDir(), "com", "example", "lib", "1.0.0")
	covP2Write(t, filepath.Join(dir, "lib-1.0.0.jar"), []byte("JARBYTES"))
	covP2Write(t, filepath.Join(dir, "lib-1.0.0.pom"), []byte("<project/>"))
	covP2Write(t, filepath.Join(dir, "lib-1.0.0.jar.sha1"), []byte("deadbeef")) // checksum: skipped in the field loop
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {       // a directory entry: skipped
		t.Fatal(err)
	}
	d, err := hs.mavenDetail("com/example/lib@1.0.0")
	if err != nil {
		t.Fatalf("mavenDetail: %v", err)
	}
	if d.Title != "com.example:lib" || d.Subtitle != "1.0.0" {
		t.Fatalf("unexpected detail: %+v", d)
	}
	var hasJarSum bool
	for _, f := range d.Fields {
		if f.Label == "JAR SHA-256" {
			hasJarSum = true
		}
	}
	if !hasJarSum {
		t.Errorf("detail missing the JAR SHA-256 field: %+v", d.Fields)
	}
}

// TestCovP2_ListMavenArtifactsEmpty covers the not-yet-created-tree short
// circuit of the walker.
func TestCovP2_ListMavenArtifactsEmpty(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	mods, err := hs.listMavenArtifacts()
	if err != nil || len(mods) != 0 {
		t.Fatalf("listMavenArtifacts on empty tree = %+v, %v", mods, err)
	}
}

// TestCovP2_ServeMavenEmpty covers serveMaven's empty-rel 404.
func TestCovP2_ServeMavenEmpty(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	if code, _ := httpGet(t, srv.URL+"/maven"); code != http.StatusNotFound {
		t.Errorf("GET /maven = %d, want 404", code)
	}
}

// TestCovP2_CollectMavenRejectsBadCoord confirms CollectMaven surfaces the
// coordinate-parse error before mvn runs.
func TestCovP2_CollectMavenRejectsBadCoord(t *testing.T) {
	ls, _ := newMavenLowServer(t)
	if _, err := ls.CollectMaven(context.Background(), MavenCollectRequest{Coordinates: []string{"not-a-coordinate"}}); err == nil {
		t.Error("CollectMaven with a malformed coordinate should error")
	}
}

// =============================================================================
// npm.go
// =============================================================================

// TestCovP2_ReadNpmStoredManifest covers each rejection of the stored-manifest
// loader plus the success path.
func TestCovP2_ReadNpmStoredManifest(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// Missing file.
	if _, err := hs.readNpmStoredManifest("lodash", "1.0.0"); err == nil {
		t.Error("missing manifest accepted")
	}
	metaDir := filepath.Join(hs.npmMetadataDir(), "lodash")
	// Bad JSON.
	covP2Write(t, filepath.Join(metaDir, "1.0.0.json"), []byte("{not json"))
	if _, err := hs.readNpmStoredManifest("lodash", "1.0.0"); err == nil {
		t.Error("corrupt manifest accepted")
	}
	// Empty filename.
	covP2Write(t, filepath.Join(metaDir, "1.0.1.json"), []byte(`{"filename":""}`))
	if _, err := hs.readNpmStoredManifest("lodash", "1.0.1"); err == nil {
		t.Error("manifest with empty filename accepted")
	}
	// Tarball absent on disk.
	covP2Write(t, filepath.Join(metaDir, "1.0.2.json"), []byte(`{"filename":"lodash-1.0.2.tgz"}`))
	if _, err := hs.readNpmStoredManifest("lodash", "1.0.2"); err == nil {
		t.Error("manifest whose tarball is missing accepted")
	}
	// Success: filename resolves to a present tarball.
	covP2Write(t, filepath.Join(metaDir, "1.0.3.json"), []byte(`{"filename":"lodash-1.0.3.tgz"}`))
	covP2Write(t, filepath.Join(hs.npmPackagesDir(), "lodash", "lodash-1.0.3.tgz"), []byte("tgz"))
	if st, err := hs.readNpmStoredManifest("lodash", "1.0.3"); err != nil || st.Filename != "lodash-1.0.3.tgz" {
		t.Fatalf("readNpmStoredManifest = %+v, %v", st, err)
	}
}

// TestCovP2_PublishNpmPackageErrors covers publishNpmPackage's rejection arms.
func TestCovP2_PublishNpmPackageErrors(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	if err := hs.publishNpmPackage(NpmPackage{Name: "-bad", Version: "1.0.0", Path: "npm/packages/x/x.tgz"}); err == nil {
		t.Error("invalid name accepted")
	}
	if err := hs.publishNpmPackage(NpmPackage{Name: "ok", Version: "not a version", Path: "npm/packages/ok/ok.tgz"}); err == nil {
		t.Error("invalid version accepted")
	}
	if err := hs.publishNpmPackage(NpmPackage{Name: "ok", Version: "1.0.0", Path: "python/x.tgz"}); err == nil {
		t.Error("path outside npm/packages accepted")
	}
	// Valid coordinates but the tarball is not a valid gzip: extract fails.
	rel := "npm/packages/ok/ok-1.0.0.tgz"
	covP2Write(t, filepath.Join(hs.downloadDir, filepath.FromSlash(rel)), []byte("not a tarball"))
	if err := hs.publishNpmPackage(NpmPackage{Name: "ok", Version: "1.0.0", Path: rel}); err == nil {
		t.Error("unreadable tarball accepted")
	}
}

// TestCovP2_ExtractNpmPackageJSONExtra covers the open-error and invalid-JSON
// branches the existing test does not reach.
func TestCovP2_ExtractNpmPackageJSONExtra(t *testing.T) {
	if _, err := extractNpmPackageJSON(filepath.Join(t.TempDir(), "nope.tgz")); err == nil {
		t.Error("extract of a missing file accepted")
	}
	// A tarball whose package.json is present but not valid JSON.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := "{not valid json"
	if err := tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	p := filepath.Join(t.TempDir(), "badjson.tgz")
	writeFile(t, p, buf.Bytes())
	if _, err := extractNpmPackageJSON(p); err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("invalid embedded package.json = %v, want a JSON error", err)
	}
}

// TestCovP2_ListNpmPackages covers the metadata-tree grouping, including the
// non-.json entry it must ignore, and the empty-tree short circuit.
func TestCovP2_ListNpmPackages(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	if mods, err := hs.listNpmPackages(); err != nil || len(mods) != 0 {
		t.Fatalf("listNpmPackages on empty tree = %+v, %v", mods, err)
	}

	dir := filepath.Join(hs.npmMetadataDir(), "lodash")
	covP2Write(t, filepath.Join(dir, "1.0.0.json"), []byte(`{"filename":"lodash-1.0.0.tgz"}`))
	covP2Write(t, filepath.Join(dir, "2.0.0.json"), []byte(`{"filename":"lodash-2.0.0.tgz"}`))
	covP2Write(t, filepath.Join(dir, "notes.txt"), []byte("ignored")) // non-.json: skipped

	mods, err := hs.listNpmPackages()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Module != "lodash" || len(mods[0].Versions) != 2 {
		t.Fatalf("listNpmPackages = %+v, want lodash with 2 versions", mods)
	}
}

// TestCovP2_DownloadNpmTarball covers each outcome of the tarball downloader:
// success, HTTP error, integrity mismatch, an unparseable integrity string, and
// the O_EXCL refusal when the destination already exists.
func TestCovP2_DownloadNpmTarball(t *testing.T) {
	data := makeNpmTgz(t, "package", "lodash", "4.17.21")
	reg := newNpmRegistry(t, map[string][]byte{"/lodash/-/lodash-4.17.21.tgz": data})
	ctx := context.Background()
	url := reg.URL + "/lodash/-/lodash-4.17.21.tgz"

	// Success.
	dest := filepath.Join(t.TempDir(), "ok.tgz")
	if err := downloadNpmTarball(ctx, url, sriFor(data), dest); err != nil {
		t.Fatalf("downloadNpmTarball success = %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != string(data) {
		t.Error("downloaded bytes differ from served bytes")
	}
	// The destination now exists: O_EXCL refuses to overwrite it.
	if err := downloadNpmTarball(ctx, url, sriFor(data), dest); err == nil {
		t.Error("downloadNpmTarball overwrote an existing destination")
	}

	// HTTP error.
	if err := downloadNpmTarball(ctx, reg.URL+"/missing/-/x.tgz", "", filepath.Join(t.TempDir(), "a.tgz")); err == nil {
		t.Error("404 tarball accepted")
	}
	// Integrity mismatch: the partial file is removed.
	mm := filepath.Join(t.TempDir(), "mm.tgz")
	if err := downloadNpmTarball(ctx, url, sriFor([]byte("other")), mm); err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
		t.Errorf("integrity mismatch = %v, want a mismatch error", err)
	}
	if _, err := os.Stat(mm); !os.IsNotExist(err) {
		t.Errorf("rejected download left a file, stat = %v", err)
	}
	// Unparseable integrity string.
	if err := downloadNpmTarball(ctx, url, "sha512-!!not-base64!!", filepath.Join(t.TempDir(), "b.tgz")); err == nil {
		t.Error("invalid integrity string accepted")
	}
}

// covP2NpmBin writes a stand-in npm binary running the given shell body,
// skipping on platforms without a POSIX shell.
func covP2NpmBin(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell npm stand-in is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	p := filepath.Join(t.TempDir(), "npm")
	if err := os.WriteFile(p, []byte("#!/usr/bin/env bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// covP2NpmLowServer builds a low server wired to a specific npm stand-in.
func covP2NpmLowServer(t *testing.T, npmBin string) *LowServer {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), NpmBinary: npmBin}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls
}

// TestCovP2_ResolveNpmLock covers resolveNpmLock's two failure arms: the npm
// run failing, and npm producing no lockfile.
func TestCovP2_ResolveNpmLock(t *testing.T) {
	req := NpmCollectRequest{Packages: []string{"lodash"}}

	// npm exits nonzero: runNpm surfaces the error.
	failLS := covP2NpmLowServer(t, covP2NpmBin(t, "exit 1\n"))
	if _, _, err := failLS.resolveNpmLock(context.Background(), t.TempDir(), req); err == nil {
		t.Error("resolveNpmLock should fail when npm exits nonzero")
	}

	// npm succeeds but writes no package-lock.json.
	noLockLS := covP2NpmLowServer(t, covP2NpmBin(t, "exit 0\n"))
	if _, _, err := noLockLS.resolveNpmLock(context.Background(), t.TempDir(), req); err == nil || !strings.Contains(err.Error(), "package-lock.json") {
		t.Errorf("resolveNpmLock with no lock = %v, want a lockfile error", err)
	}
}

// TestCovP2_CollectNpmAllFail drives CollectNpm through the path where every
// resolved tarball fails to download, hitting the "no npm packages" branch and
// downloadNpmPackages' per-entry failure accounting.
func TestCovP2_CollectNpmAllFail(t *testing.T) {
	// A registry that serves nothing: every tarball 404s.
	reg := newNpmRegistry(t, map[string][]byte{})
	lock := `{"lockfileVersion":3,"packages":{` +
		`"":{"name":"artigate-collect"},` +
		`"node_modules/lodash":{"version":"4.17.21","resolved":"` + reg.URL + `/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-x"}}}`
	body := "set -eu\ncat > package-lock.json <<'LOCK'\n" + lock + "\nLOCK\n"
	ls := covP2NpmLowServer(t, covP2NpmBin(t, body))

	_, err := ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err == nil || !strings.Contains(err.Error(), "no npm packages") {
		t.Fatalf("CollectNpm all-fail = %v, want a no-packages error", err)
	}
}
