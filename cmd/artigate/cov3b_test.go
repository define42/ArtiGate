package main

// cov3b_test.go drives the remaining uncovered error/edge branches of the four
// package-ecosystem adapters (apt.go, rpm.go, java.go, npm.go): upstream HTTP
// failures, checksum/size mismatches, malformed indexes/metadata, empty
// results, host-tool failures (gpg/gpgv/xz, guarded by exec.LookPath), and a
// few filesystem fault injections (skipped as root, restored in cleanup). All
// helpers/fixtures already defined in the package's other _test.go files are
// reused; new helpers/types are prefixed cov3B and tests TestCov3B_.

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// cov3BskipAsRoot skips a filesystem-permission fault-injection test when the
// process is root, since root bypasses the 0o500 mode that would block writes.
func cov3BskipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses filesystem permissions")
	}
}

// cov3BnoPrior is a prior-file check that always reports "not forwarded", so a
// direct downloadAptDeb call always attempts the download.
func cov3BnoPrior(string, string) bool { return false }

// -----------------------------------------------------------------------------
// apt.go — HTTP + hashing helpers
// -----------------------------------------------------------------------------

func TestCov3B_HttpGetBytesErrors(t *testing.T) {
	ctx := context.Background()
	big := strings.Repeat("A", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	// Response larger than the cap is refused.
	if _, err := httpGetBytes(ctx, srv.URL, 10); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("over-cap httpGetBytes = %v, want cap error", err)
	}
	// A dial failure surfaces as a transport error.
	if _, err := httpGetBytes(ctx, "http://127.0.0.1:1/nope", 1<<20); err == nil {
		t.Error("dial to a closed port should error")
	}
	// A malformed URL fails at request construction.
	if _, err := httpGetBytes(ctx, "http://\x7f/bad", 1<<20); err == nil {
		t.Error("control character in URL should fail NewRequest")
	}
}

func TestCov3B_CheckDownloadResultCap(t *testing.T) {
	// wantSize<=0 with the byte count over the cap is the streamed-file backstop.
	if err := checkDownloadResult(100, 0, 50, sha256.New(), "sha256", "irrelevant"); err == nil ||
		!strings.Contains(err.Error(), "cap") {
		t.Errorf("over-cap checkDownloadResult = %v, want cap error", err)
	}
}

func TestCov3B_NewRepoHash(t *testing.T) {
	for _, algo := range []string{"sha256", "", "sha512", "sha1", "sha"} {
		if _, err := newRepoHash(algo); err != nil {
			t.Errorf("newRepoHash(%q) = %v, want nil", algo, err)
		}
	}
	if _, err := newRepoHash("crc32"); err == nil {
		t.Error("newRepoHash(crc32) should be unsupported")
	}
}

func TestCov3B_VerifySHA256AndGunzip(t *testing.T) {
	if err := verifySHA256([]byte("data"), "not-the-hash"); err == nil {
		t.Error("verifySHA256 with a wrong digest should error")
	}
	if _, err := gunzip([]byte("this is not gzip"), 1<<20); err == nil {
		t.Error("gunzip of non-gzip bytes should error")
	}
}

func TestCov3B_DownloadVerifiedFileFSErrors(t *testing.T) {
	cov3BskipAsRoot(t)
	ctx := context.Background()
	payload := []byte("streamed body")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	dir := t.TempDir()

	// MkdirAll fails when a parent path component is a regular file.
	blocker := filepath.Join(dir, "blocker")
	writeFile(t, blocker, []byte("x"))
	if _, _, err := downloadVerifiedFile(ctx, srv.URL, filepath.Join(blocker, "sub", "f"), 0, "sha256", aptSHA256(payload)); err == nil {
		t.Error("download into a path under a file should fail MkdirAll")
	}

	// OpenFile fails when the destination is itself a directory.
	if _, _, err := downloadVerifiedFile(ctx, srv.URL, dir, 0, "sha256", aptSHA256(payload)); err == nil {
		t.Error("download onto a directory should fail OpenFile")
	}
}

// -----------------------------------------------------------------------------
// apt.go — parsing + config resolution
// -----------------------------------------------------------------------------

func TestCov3B_ParseAptPackagesSkips(t *testing.T) {
	// A stanza missing Filename/SHA256 is dropped; a blank block is ignored.
	data := []byte("Package: nofile\nVersion: 1\n\n\n" +
		"Package: ok\nVersion: 2\nFilename: pool/o/ok.deb\nSHA256: " + strings.Repeat("a", 64) + "\nSize: 3\n")
	pkgs := parseAptPackages(data, "stable", "main")
	if len(pkgs) != 1 || pkgs[0].Package != "ok" {
		t.Fatalf("parseAptPackages = %+v, want only the complete stanza", pkgs)
	}
}

func TestCov3B_ParseAptSourcesEdge(t *testing.T) {
	// A block with neither URIs nor Suites is skipped; with none left it errors.
	if _, err := parseAptSources("Comment: just a note\n"); err == nil {
		t.Error("a non-source stanza should yield no deb sources")
	}
}

func TestCov3B_ResolveAptMirrorsErrors(t *testing.T) {
	// A source_list that parses to no stanzas propagates the parse error.
	if _, err := resolveAptMirrors(AptCollectRequest{SourceList: "Comment: x\n"}); err == nil {
		t.Error("empty source_list should error")
	}
	// Two same-URI stanzas derive the same name and collide.
	dup := "Types: deb\nURIs: https://x.example/repo\nSuites: stable\n\n" +
		"Types: deb\nURIs: https://x.example/repo\nSuites: noble\n"
	if _, err := resolveAptMirrors(AptCollectRequest{SourceList: dup}); err == nil ||
		!strings.Contains(err.Error(), "duplicate mirror name") {
		t.Errorf("duplicate mirror = %v, want duplicate mirror name error", err)
	}
}

func TestCov3B_ValidateAptMirrorConfig(t *testing.T) {
	bad := []aptMirrorConfig{
		{URI: "ftp://x/y", Suites: []string{"s"}},                // wrong scheme
		{URI: "https://x/y"},                                     // no suites
		{URI: "https://x/y", Suites: []string{"s"}, Name: "a/b"}, // slash in name
		{URI: "https://x/y", Suites: []string{"bad token"}},      // invalid suite token
	}
	for i, cfg := range bad {
		if _, err := validateAptMirrorConfig(cfg); err == nil {
			t.Errorf("case %d: validateAptMirrorConfig(%+v) = nil, want error", i, cfg)
		}
	}
	// Components/architectures default when unset.
	got, err := validateAptMirrorConfig(aptMirrorConfig{URI: "https://x/y", Suites: []string{"stable"}})
	if err != nil || len(got.Components) == 0 || len(got.Architectures) == 0 {
		t.Fatalf("defaults not filled: %+v, %v", got, err)
	}
}

// -----------------------------------------------------------------------------
// apt.go — collect flow error branches (fake upstreams)
// -----------------------------------------------------------------------------

func TestCov3B_FetchAptReleaseFallback(t *testing.T) {
	// InRelease is absent, Release is present, but a keyring is configured and
	// Release.gpg is absent — the fetch fails before any gpg call.
	release := "Origin: Test\nSuite: stable\nSHA256:\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/Release", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(release)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ls, _ := newAptLowServer(t)
	if _, err := ls.fetchAptRelease(context.Background(), srv.URL+"/dists/stable", "/nonexistent/keyring.gpg", nil); err == nil ||
		!strings.Contains(err.Error(), "Release.gpg") {
		t.Errorf("fetchAptRelease = %v, want a Release.gpg fetch error", err)
	}
}

func TestCov3B_FetchAptPackagesIndex(t *testing.T) {
	ctx := context.Background()
	ls, _ := newAptLowServer(t)

	// No index referenced in the Release checksums at all.
	if _, err := ls.fetchAptPackagesIndex(ctx, "http://127.0.0.1:1/dists/stable", "stable", "main", "amd64", map[string]aptChecksum{}, nil); err == nil ||
		!strings.Contains(err.Error(), "no Packages index") {
		t.Errorf("empty checksums = %v, want no-index error", err)
	}

	plain := []byte("Package: ok\nFilename: pool/o/ok.deb\nSHA256: " + strings.Repeat("a", 64) + "\n\n")
	gz, err := gzipBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz) })
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("plain-served")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	distBase := srv.URL + "/dists/stable"

	// Checksum mismatch against the signed Release.
	badSums := map[string]aptChecksum{"main/binary-amd64/Packages.gz": {sha256: strings.Repeat("0", 64), size: int64(len(gz))}}
	if _, err := ls.fetchAptPackagesIndex(ctx, distBase, "stable", "main", "amd64", badSums, nil); err == nil ||
		!strings.Contains(err.Error(), "index") {
		t.Errorf("checksum mismatch = %v, want index error", err)
	}

	// A .gz index whose bytes are actually plain (not gzip) fails to decompress.
	plainAsGz := map[string]aptChecksum{"main/binary-amd64/Packages": {sha256: aptSHA256([]byte("plain-served")), size: 12}}
	if _, err := ls.fetchAptPackagesIndex(ctx, distBase, "stable", "main", "amd64", plainAsGz, nil); err != nil {
		t.Errorf("plain Packages index should parse: %v", err)
	}

	// A referenced index that 404s propagates the HTTP error.
	miss := map[string]aptChecksum{"main/binary-amd64/Packages.gz": {sha256: aptSHA256(gz), size: int64(len(gz))}}
	mux2 := http.NewServeMux() // serves nothing
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	if _, err := ls.fetchAptPackagesIndex(ctx, srv2.URL+"/dists/stable", "stable", "main", "amd64", miss, nil); err == nil {
		t.Error("missing index should error")
	}
}

func TestCov3B_DownloadAptDebUnsafe(t *testing.T) {
	ls, _ := newAptLowServer(t)
	pkg := AptPackage{Package: "evil", Filename: "../escape.deb", SHA256: strings.Repeat("a", 64), Size: 1}
	if _, err := ls.downloadAptDeb(context.Background(), aptMirrorConfig{Name: "mirror", URI: "http://127.0.0.1:1"}, pkg, t.TempDir(), cov3BnoPrior); err == nil ||
		!strings.Contains(err.Error(), "unsafe") {
		t.Errorf("downloadAptDeb with traversal Filename = %v, want unsafe error", err)
	}
}

// cov3BEmptyAptUpstream serves a valid Release whose Packages index has zero
// stanzas, so a collect resolves no packages.
func cov3BEmptyAptUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	packages := []byte("")
	gz, err := gzipBytes(packages)
	if err != nil {
		t.Fatal(err)
	}
	release := "Origin: Test\nLabel: t\nSuite: stable\nCodename: stable\nComponents: main\nArchitectures: amd64\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 UTC\nSHA256:\n" +
		" " + aptSHA256(gz) + " " + strconv.Itoa(len(gz)) + " main/binary-amd64/Packages.gz\n" +
		" " + aptSHA256(packages) + " 0 main/binary-amd64/Packages\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(release)) })
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz) })
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(packages) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCov3B_CollectAptNoPackages(t *testing.T) {
	up := cov3BEmptyAptUpstream(t)
	ls, _ := newAptLowServer(t)
	_, err := ls.CollectApt(context.Background(), AptCollectRequest{
		Name: "empty", URI: up.URL, Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
	})
	if err == nil || !strings.Contains(err.Error(), "no packages") {
		t.Fatalf("CollectApt on an empty index = %v, want 'no packages' error", err)
	}
}

func TestCov3B_CollectAptReleaseErrors(t *testing.T) {
	ls, _ := newAptLowServer(t)
	// Nothing is served: InRelease and Release both 404.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := ls.CollectApt(context.Background(), AptCollectRequest{
		Name: "gone", URI: srv.URL, Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
	}); err == nil {
		t.Error("CollectApt against an empty upstream should error")
	}

	// An empty Release body has no stanzas.
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(nil) })
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	if _, err := ls.CollectApt(context.Background(), AptCollectRequest{
		Name: "emptyrel", URI: srv2.URL, Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
	}); err == nil || !strings.Contains(err.Error(), "empty Release") {
		t.Errorf("CollectApt with an empty Release = %v, want empty Release error", err)
	}
}

func TestCov3B_CollectAptStagingBlocked(t *testing.T) {
	ls, _ := newAptLowServer(t)
	// A regular file where the apt/ staging tree must be created blocks MkdirAll.
	aptPath := filepath.Join(ls.cfg.Root, "apt")
	_ = os.RemoveAll(aptPath)
	writeFile(t, aptPath, []byte("not a dir"))
	if _, err := ls.CollectApt(context.Background(), AptCollectRequest{
		Name: "x", URI: "https://x.example/repo", Suites: []string{"stable"},
	}); err == nil {
		t.Error("CollectApt should fail when the staging directory cannot be created")
	}
}

// -----------------------------------------------------------------------------
// apt.go — high-side publish/list/serve error branches
// -----------------------------------------------------------------------------

func TestCov3B_ServeAptMethodNotAllowed(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/apt/x", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /apt/x = %d, want 405", resp.StatusCode)
	}
}

func TestCov3B_AptRepoListEdge(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// No apt dir yet: returns no repos and no error.
	if repos, err := hs.aptRepoList(); err != nil || repos != nil {
		t.Fatalf("aptRepoList on empty tree = %v, %v", repos, err)
	}

	aptRoot := filepath.Join(hs.downloadDir, "apt")
	if err := os.MkdirAll(aptRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// A stray file (not a directory) is ignored.
	writeFile(t, filepath.Join(aptRoot, "stray.txt"), []byte("x"))
	// A directory without an index.json is skipped.
	if err := os.MkdirAll(filepath.Join(aptRoot, "noindex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if repos, err := hs.aptRepoList(); err != nil || len(repos) != 0 {
		t.Fatalf("aptRepoList ignoring junk = %v, %v", repos, err)
	}
}

func TestCov3B_MergeAndPublishAptBadIndex(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	name := "brokenmirror"
	idx := filepath.Join(hs.downloadDir, "apt", name, "index.json")
	if err := os.MkdirAll(filepath.Dir(idx), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, idx, []byte("{ this is not json"))

	mirror := AptMirror{Name: name, URI: "https://x/y", Suites: []AptSuite{{Name: "stable", Components: []string{"main"}, Architectures: []string{"amd64"}}}}
	if _, err := hs.mergeAptMirror(mirror); err == nil {
		t.Error("mergeAptMirror over a corrupt index should error")
	}
	if err := hs.publishAptMirror(mirror); err == nil {
		t.Error("publishAptMirror over a corrupt index should error")
	}
}

func TestCov3B_PresentAptStanzas(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	mirrorRoot := t.TempDir()
	pkgs := []AptPackage{
		{Package: "wrongsuite", Suite: "other", Component: "main", Architecture: "amd64", Filename: "pool/w.deb"},
		{Package: "missingfile", Suite: "stable", Component: "main", Architecture: "amd64", Filename: "pool/missing.deb"},
	}
	if got := hs.presentAptStanzas(mirrorRoot, pkgs, "stable", "main", "amd64"); len(got) != 0 {
		t.Errorf("presentAptStanzas = %v, want none (mismatched suite + absent file)", got)
	}
}

func TestCov3B_CollectAptVersionsAndPrune(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// loadAptIndex error path: no index for this name is a silent skip.
	byKey := map[string]map[string]bool{}
	hs.collectAptVersions("noindex", byKey)
	if len(byKey) != 0 {
		t.Errorf("collectAptVersions without an index recorded %v", byKey)
	}

	// A package whose .deb is absent on disk is not recorded.
	name := "m1"
	idx := filepath.Join(hs.downloadDir, "apt", name, "index.json")
	if err := os.MkdirAll(filepath.Dir(idx), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, idx, []byte(`{"name":"m1","packages":[{"package":"p","version":"1","suite":"stable","component":"main","filename":"pool/absent.deb"}]}`))
	hs.collectAptVersions(name, byKey)
	if len(byKey) != 0 {
		t.Errorf("collectAptVersions recorded a package with no file: %v", byKey)
	}

	// pruneAptDists on a mirror with no dists/ tree is a no-op.
	if err := pruneAptDists(t.TempDir(), []string{"stable"}); err != nil {
		t.Errorf("pruneAptDists on an empty mirror = %v", err)
	}
}

func TestCov3B_SignAptReleaseGPGFails(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	hs.cfg.AptGPGKey = "artigate-nonexistent-signing-key"
	distDir := t.TempDir()
	writeFile(t, filepath.Join(distDir, "Release"), []byte("Origin: Test\n"))
	if err := hs.signAptRelease(distDir); err == nil {
		t.Error("signAptRelease with an unknown key should fail")
	}
}

func TestCov3B_RunGPGVerifyFails(t *testing.T) {
	if _, err := exec.LookPath("gpgv"); err != nil {
		t.Skip("gpgv not installed")
	}
	if err := runGPGVerify(context.Background(), "/nonexistent/keyring.gpg", []byte("data"), nil); err == nil {
		t.Error("runGPGVerify with a missing keyring should fail")
	}
}

// -----------------------------------------------------------------------------
// rpm.go
// -----------------------------------------------------------------------------

func TestCov3B_PrimaryPkgid(t *testing.T) {
	if id := primaryPkgid(`<package><name>x</name></package>`); id != "" {
		t.Errorf("primaryPkgid without pkgid = %q, want empty", id)
	}
	// pkgid marker present but the checksum element is truncated.
	if id := primaryPkgid(`<checksum pkgid="YES"`); id != "" {
		t.Errorf("primaryPkgid on a truncated block = %q, want empty", id)
	}
	if id := primaryPkgid(`<checksum pkgid="YES">`); id != "" {
		t.Errorf("primaryPkgid with no closing tag = %q, want empty", id)
	}
	if id := primaryPkgid(`<checksum type="sha256" pkgid="YES">ABC123</checksum>`); id != "abc123" {
		t.Errorf("primaryPkgid = %q, want lowercased abc123", id)
	}
}

func TestCov3B_RestagePrimaryZchunk(t *testing.T) {
	// A zchunk primary cannot be recompressed after filtering.
	err := restagePrimary(t.TempDir(), "mirror", "repodata/primary.xml.zck", []byte("<metadata/>"), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "zchunk") {
		t.Errorf("restagePrimary(.zck) = %v, want a zchunk error", err)
	}
}

func TestCov3B_ResolveRpmMirrors(t *testing.T) {
	// A repo file with no [section] errors.
	if _, err := resolveRpmMirrors(RpmCollectRequest{RepoFile: "baseurl=https://x/y\n"}); err == nil {
		t.Error("repo file without a [section] should error")
	}
	// An explicit GPGKey is applied to every parsed section.
	cfgs, err := resolveRpmMirrors(RpmCollectRequest{
		RepoFile: "[a]\nbaseurl=https://a.example/repo\n", GPGKey: "/keys/a.gpg",
	})
	if err != nil || len(cfgs) != 1 || cfgs[0].GPGKey != "/keys/a.gpg" {
		t.Fatalf("resolveRpmMirrors GPGKey override = %+v, %v", cfgs, err)
	}
}

func TestCov3B_RpmRepoListEdge(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if repos, err := hs.rpmRepoList(); err != nil || repos != nil {
		t.Fatalf("rpmRepoList on empty tree = %v, %v", repos, err)
	}
	rpmRoot := filepath.Join(hs.downloadDir, "rpm")
	if err := os.MkdirAll(filepath.Join(rpmRoot, "noindex"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(rpmRoot, "stray.txt"), []byte("x"))
	if repos, err := hs.rpmRepoList(); err != nil || len(repos) != 0 {
		t.Fatalf("rpmRepoList ignoring junk = %v, %v", repos, err)
	}
}

func TestCov3B_CollectRpmErrors(t *testing.T) {
	ls, _ := newRpmLowServer(t)

	// Bad repomd.xml: served but not parseable.
	mux := http.NewServeMux()
	mux.HandleFunc("/r/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<<not xml")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "m", BaseURL: srv.URL + "/r"}); err == nil ||
		!strings.Contains(err.Error(), "repomd") {
		t.Errorf("CollectRpm with a malformed repomd = %v, want a repomd error", err)
	}

	// repomd with no primary metadata entry.
	repomd := `<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>` +
		`<data type="other"><checksum type="sha256">` + aptSHA256([]byte("x")) + `</checksum>` +
		`<location href="repodata/other.xml"/><size>1</size></data></repomd>`
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/r/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(repomd)) })
	mux2.HandleFunc("/r/repodata/other.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("x")) })
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	if _, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "m2", BaseURL: srv2.URL + "/r"}); err == nil ||
		!strings.Contains(err.Error(), "primary") {
		t.Errorf("CollectRpm with no primary = %v, want a primary error", err)
	}
}

func TestCov3B_CollectRpmStagingBlocked(t *testing.T) {
	ls, _ := newRpmLowServer(t)
	rpmPath := filepath.Join(ls.cfg.Root, "rpm")
	_ = os.RemoveAll(rpmPath)
	writeFile(t, rpmPath, []byte("not a dir"))
	if _, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "m", BaseURL: "https://x.example/repo"}); err == nil {
		t.Error("CollectRpm should fail when the staging directory cannot be created")
	}
}

func TestCov3B_RunXZWaitError(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz not installed")
	}
	// Non-xz input makes xz exit non-zero, so Wait reports the failure.
	if _, err := runXZ([]byte("definitely not xz data"), 1<<20, "--decompress", "--stdout"); err == nil {
		t.Error("runXZ decompressing garbage should fail")
	}
}

// -----------------------------------------------------------------------------
// java.go
// -----------------------------------------------------------------------------

func TestCov3B_CollectMavenToolFailures(t *testing.T) {
	falseBin, err := exec.LookPath("false")
	if err != nil {
		t.Skip("false not available")
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true not available")
	}
	_, priv := newTestKeys(t)

	// mvn exits non-zero: runMaven surfaces the failure.
	cfgFail := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), MavenBinary: falseBin}
	lsFail, err := NewLowServer(cfgFail, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lsFail.Close() }()
	if _, err := lsFail.CollectMaven(context.Background(), MavenCollectRequest{Coordinates: []string{"org.slf4j:slf4j-api:2.0.16"}}); err == nil {
		t.Error("CollectMaven should fail when mvn exits non-zero")
	}

	// mvn succeeds but resolves nothing: the empty local repo is rejected.
	cfgEmpty := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), MavenBinary: trueBin}
	lsEmpty, err := NewLowServer(cfgEmpty, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lsEmpty.Close() }()
	if _, err := lsEmpty.CollectMaven(context.Background(), MavenCollectRequest{Coordinates: []string{"org.slf4j:slf4j-api:2.0.16"}}); err == nil ||
		!strings.Contains(err.Error(), "no artifacts") {
		t.Errorf("CollectMaven with an empty resolution = %v, want a 'no artifacts' error", err)
	}
}

func TestCov3B_CollectMavenBadCoordinate(t *testing.T) {
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true not available")
	}
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), MavenBinary: trueBin}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ls.Close() }()
	if _, err := ls.CollectMaven(context.Background(), MavenCollectRequest{Coordinates: []string{"not-a-coordinate"}}); err == nil {
		t.Error("CollectMaven with an invalid coordinate should fail before mvn runs")
	}
}

func TestCov3B_CollectMavenParseError(t *testing.T) {
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true not available")
	}
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), MavenBinary: trueBin}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ls.Close() }()
	req := httptest.NewRequest(http.MethodPost, "/admin/maven/collect", strings.NewReader("{not json"))
	if _, err := ls.HandleMavenCollect(context.Background(), req); err == nil {
		t.Error("HandleMavenCollect should reject a malformed JSON body")
	}
}

func TestCov3B_CollectMavenRepoEdges(t *testing.T) {
	// Walking a non-existent repo root propagates the walk error.
	if _, _, err := collectMavenRepo(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("collectMavenRepo of a missing root should error")
	}

	// A file too shallow to carry a Maven coordinate is skipped; a proper one is
	// collected.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "toplevel.txt"), []byte("x"))
	deep := filepath.Join(root, "org", "slf4j", "slf4j-api", "2.0.16")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(deep, "slf4j-api-2.0.16.jar"), []byte("JAR"))
	files, arts, err := collectMavenRepo(root)
	if err != nil || len(files) != 1 || len(arts) != 1 {
		t.Fatalf("collectMavenRepo = %d files, %d artifacts, %v", len(files), len(arts), err)
	}
}

func TestCov3B_BuildMavenMetadataMissingDir(t *testing.T) {
	if _, ok := buildMavenMetadata("org/x", filepath.Join(t.TempDir(), "absent")); ok {
		t.Error("buildMavenMetadata for a missing directory should report not-ok")
	}
}

func TestCov3B_ListMavenArtifactsEmpty(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// The maven dir does not exist yet: the walk tolerates that and returns none.
	if mods, err := hs.listMavenArtifacts(); err != nil || len(mods) != 0 {
		t.Fatalf("listMavenArtifacts on empty tree = %v, %v", mods, err)
	}
}

func TestCov3B_MavenDetailErrors(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	for _, spec := range []string{
		"no-at-sign",           // missing @
		"org/x@1/2",            // version contains a slash
		"org/x@..",             // version contains ..
		"org/slf4j/absent@9.9", // artifact directory does not exist
	} {
		if _, err := hs.mavenDetail(spec); err == nil {
			t.Errorf("mavenDetail(%q) = nil error, want error", spec)
		}
	}
}

func TestCov3B_ServeMavenEdges(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Non-GET/HEAD is rejected.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/maven/x", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /maven/x = %d, want 405", resp.StatusCode)
	}

	// maven-metadata.xml for a group/artifact with no versions is a 404.
	if code, _ := httpGet(t, srv.URL+"/maven/org/none/maven-metadata.xml"); code != http.StatusNotFound {
		t.Errorf("metadata for an unknown artifact = %d, want 404", code)
	}
}

func TestCov3B_SanitizeUploadedPomScopeAndFields(t *testing.T) {
	// A dependency exercising provided scope plus type/classifier/optional fields
	// takes the branches a plain compile dep does not.
	pom := `<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>t</artifactId><version>1.0</version>` +
		`<dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version>` +
		`<scope>provided</scope><type>jar</type><classifier>sources</classifier><optional>true</optional></dependency></dependencies></project>`
	out, err := sanitizeUploadedPom(pom)
	if err != nil {
		t.Fatalf("sanitizeUploadedPom = %v", err)
	}
	if !strings.Contains(out, "<scope>provided</scope>") || !strings.Contains(out, "<classifier>sources</classifier>") {
		t.Errorf("sanitized pom lost provided-scope fields:\n%s", out)
	}

	// An invalid <optional> value is rejected.
	badOpt := strings.Replace(pom, "<optional>true</optional>", "<optional>maybe</optional>", 1)
	if _, err := sanitizeUploadedPom(badOpt); err == nil || !strings.Contains(err.Error(), "optional") {
		t.Errorf("bad <optional> = %v, want an optional error", err)
	}

	// A parent whose version is a SNAPSHOT fails the BOM-import conversion.
	parentSnap := `<project><modelVersion>4.0.0</modelVersion>` +
		`<parent><groupId>g</groupId><artifactId>p</artifactId><version>1-SNAPSHOT</version></parent>` +
		`<artifactId>t</artifactId>` +
		`<dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version></dependency></dependencies></project>`
	if _, err := sanitizeUploadedPom(parentSnap); err == nil || !strings.Contains(err.Error(), "SNAPSHOT") {
		t.Errorf("parent SNAPSHOT = %v, want a SNAPSHOT rejection", err)
	}
}

func TestCov3B_DecodePomPropertiesTruncated(t *testing.T) {
	// A pom that ends inside <properties> makes the property reader hit EOF.
	if _, err := parseUploadedPom(`<project><properties><a>1</a>`); err == nil {
		t.Error("a pom truncated inside <properties> should error")
	}
}

// -----------------------------------------------------------------------------
// npm.go
// -----------------------------------------------------------------------------

func TestCov3B_NpmBaseURLForwardedProto(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/npm/lodash", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := npmBaseURL(r); !strings.HasPrefix(got, "https://") {
		t.Errorf("npmBaseURL with X-Forwarded-Proto=https = %q, want https", got)
	}
}

func TestCov3B_NpmHasInstallScript(t *testing.T) {
	if npmHasInstallScript(map[string]any{"scripts": "not a map"}) {
		t.Error("non-map scripts should report no install script")
	}
	if npmHasInstallScript(map[string]any{"scripts": map[string]any{"build": "x"}}) {
		t.Error("scripts without an install hook should report false")
	}
	if !npmHasInstallScript(map[string]any{"scripts": map[string]any{"postinstall": "x"}}) {
		t.Error("a postinstall hook should report true")
	}
}

func TestCov3B_PublishNpmPackageRejects(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	bad := []NpmPackage{
		{Name: "Bad Name", Version: "1.0.0", Path: "npm/packages/x/x-1.0.0.tgz"},
		{Name: "lodash", Version: "not-a-version", Path: "npm/packages/lodash/lodash.tgz"},
		{Name: "lodash", Version: "1.0.0", Path: "python/packages/x.tgz"}, // outside npm/packages
	}
	for _, p := range bad {
		if err := hs.publishNpmPackage(p); err == nil {
			t.Errorf("publishNpmPackage(%+v) = nil, want error", p)
		}
	}
}

func TestCov3B_HandleNpmTarball404(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	// A tarball request whose filename is not a .tgz is a 404.
	if code, _ := httpGet(t, srv.URL+"/npm/lodash/-/lodash-4.17.21.zip"); code != http.StatusNotFound {
		t.Errorf("non-.tgz tarball request = %d, want 404", code)
	}
}

func TestCov3B_ListNpmPackagesEdge(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// Metadata dir absent: the walk tolerates it and returns none.
	if mods, err := hs.listNpmPackages(); err != nil || len(mods) != 0 {
		t.Fatalf("listNpmPackages on empty tree = %v, %v", mods, err)
	}

	metaRoot := hs.npmMetadataDir()
	if err := os.MkdirAll(filepath.Join(metaRoot, "lodash"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(metaRoot, "lodash", "4.17.21.json"), []byte("{}"))
	// A stray non-json file is skipped.
	writeFile(t, filepath.Join(metaRoot, "lodash", "notes.txt"), []byte("x"))
	// A json directly at the root has no package name and is skipped.
	writeFile(t, filepath.Join(metaRoot, "orphan.json"), []byte("{}"))
	// A json under an invalid package name is skipped.
	if err := os.MkdirAll(filepath.Join(metaRoot, "-badname"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(metaRoot, "-badname", "1.0.0.json"), []byte("{}"))

	mods, err := hs.listNpmPackages()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Module != "lodash" {
		t.Fatalf("listNpmPackages = %+v, want just lodash", mods)
	}
}

func TestCov3B_DownloadNpmTarballErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	body := []byte("tarball-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing.tgz" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Unsupported integrity algorithm is rejected after a successful GET.
	if err := downloadNpmTarball(ctx, srv.URL+"/ok.tgz", "md5-abcd", filepath.Join(dir, "a.tgz")); err == nil {
		t.Error("unsupported integrity should fail the download")
	}
	// A transport error (closed port).
	if err := downloadNpmTarball(ctx, "http://127.0.0.1:1/x.tgz", "", filepath.Join(dir, "b.tgz")); err == nil {
		t.Error("dial failure should error")
	}
	// A 404 response.
	if err := downloadNpmTarball(ctx, srv.URL+"/missing.tgz", "", filepath.Join(dir, "c.tgz")); err == nil ||
		!strings.Contains(err.Error(), "404") {
		t.Errorf("404 download = %v, want an HTTP 404 error", err)
	}
	// The destination already exists: O_EXCL open fails.
	existing := filepath.Join(dir, "d.tgz")
	writeFile(t, existing, []byte("present"))
	if err := downloadNpmTarball(ctx, srv.URL+"/ok.tgz", sriFor(body), existing); err == nil {
		t.Error("download onto an existing file should fail the exclusive open")
	}
}

func TestCov3B_CollectNpmStagingBlocked(t *testing.T) {
	fx := newNpmFixture(t)
	npmPath := filepath.Join(fx.ls.cfg.Root, "npm")
	_ = os.RemoveAll(npmPath)
	writeFile(t, npmPath, []byte("not a dir"))
	if _, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}}); err == nil {
		t.Error("CollectNpm should fail when the staging directory cannot be created")
	}
}

func TestCov3B_CollectNpmAllDownloadsFail(t *testing.T) {
	// The registry serves nothing, so every resolved tarball 404s and no package
	// can be fetched.
	registry := newNpmRegistry(t, map[string][]byte{})
	body := makeNpmTgz(t, "package", "lodash", "4.17.21")
	lock := `{
	  "name": "artigate-collect", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "artigate-collect"},
	    "node_modules/lodash": {"version": "4.17.21", "resolved": "` + registry.URL + `/lodash/-/lodash-4.17.21.tgz", "integrity": "` + sriFor(body) + `"}
	  }
	}`
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), NpmBinary: writeFakeNpm(t, lock)}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ls.Close() }()
	if _, err := ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}}); err == nil ||
		!strings.Contains(err.Error(), "no npm packages could be fetched") {
		t.Errorf("CollectNpm with all downloads failing = %v, want a 'no packages fetched' error", err)
	}
}
