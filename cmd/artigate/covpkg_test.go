package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// covPkgGPGKey generates an ephemeral ed25519 signing key inside an isolated
// GNUPGHOME (via t.Setenv) so gpg/gpgv invocations in the package under test use
// it, and returns the user id usable as a --local-user selector. It skips the
// test when gpg is unavailable or key generation fails (e.g. no entropy source).
func covPkgGPGKey(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	home := filepath.Join(t.TempDir(), "gnupg")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", home)
	uid := "artigate-cov-test"
	cmd := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", uid, "ed25519", "sign", "0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("gpg key generation unavailable: %v\n%s", err, out)
	}
	return uid
}

// covPkgKeyring exports the public key of the current GNUPGHOME to a keyring
// file usable as gpgv's --keyring argument.
func covPkgKeyring(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("gpg", "--export").Output()
	if err != nil {
		t.Fatalf("gpg --export: %v", err)
	}
	kr := filepath.Join(t.TempDir(), "keyring.gpg")
	writeFile(t, kr, out)
	return kr
}

// covPkgGPGSign signs data with the current GNUPGHOME key. When clearsign is
// true it produces a clearsigned document; otherwise a detached binary
// signature.
func covPkgGPGSign(t *testing.T, data []byte, clearsign bool) []byte {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	out := filepath.Join(dir, "out")
	writeFile(t, in, data)
	mode := "--detach-sign"
	if clearsign {
		mode = "--clearsign"
	}
	cmd := exec.Command("gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
		mode, "--output", out, in)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg %s: %v\n%s", mode, err, o)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCovPkg_HandleCollectHandlers drives the HTTP request wrappers that decode
// a JSON collect request body and delegate to CollectApt / CollectRpm.
func TestCovPkg_HandleCollectHandlers(t *testing.T) {
	// APT: a well-formed request body mirrors the fake upstream.
	up, _ := fakeAptUpstream(t, false)
	ls, _ := newAptLowServer(t)
	body, err := json.Marshal(AptCollectRequest{
		Name: "microsoft-code", URI: up.URL + "/repos/code",
		Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/collect/apt", strings.NewReader(string(body)))
	res, err := ls.HandleAptCollect(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleAptCollect: %v", err)
	}
	if res.BundleID != "apt-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("HandleAptCollect result = %+v", res)
	}
	// Empty body → empty request → CollectApt rejects it.
	if _, err := ls.HandleAptCollect(context.Background(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))); err == nil {
		t.Error("HandleAptCollect with empty body should error")
	}
	// Malformed JSON is reported as a parse error.
	if _, err := ls.HandleAptCollect(context.Background(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{not json"))); err == nil || !strings.Contains(err.Error(), "parse apt collect request") {
		t.Errorf("HandleAptCollect with bad JSON = %v, want parse error", err)
	}

	// RPM: mirror the fake upstream through the HTTP wrapper.
	rup, _ := fakeRpmUpstream(t, false)
	rls, _ := newRpmLowServer(t)
	rbody, err := json.Marshal(RpmCollectRequest{Name: "vscode", BaseURL: rup.URL + "/yumrepos/vscode"})
	if err != nil {
		t.Fatal(err)
	}
	rres, err := rls.HandleRpmCollect(context.Background(), httptest.NewRequest(http.MethodPost, "/collect/rpm", strings.NewReader(string(rbody))))
	if err != nil {
		t.Fatalf("HandleRpmCollect: %v", err)
	}
	if rres.BundleID != "rpm-bundle-000001" || rres.ExportedModules != 1 {
		t.Fatalf("HandleRpmCollect result = %+v", rres)
	}
	if _, err := rls.HandleRpmCollect(context.Background(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))); err == nil {
		t.Error("HandleRpmCollect with empty body should error")
	}
	if _, err := rls.HandleRpmCollect(context.Background(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))); err == nil || !strings.Contains(err.Error(), "parse rpm collect request") {
		t.Errorf("HandleRpmCollect with bad JSON = %v, want parse error", err)
	}
}

// TestCovPkg_FetchAptReleaseUnsigned exercises the InRelease→Release fallback
// and the both-missing error path with no keyring (no gpg required).
func TestCovPkg_FetchAptReleaseUnsigned(t *testing.T) {
	release := []byte("Origin: Test\nSuite: stable\nComponents: main\nSHA256:\n")
	mux := http.NewServeMux()
	// No InRelease is served, so fetchAptRelease falls back to Release.
	mux.HandleFunc("/dists/stable/Release", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(release) })
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, _ := newAptLowServer(t)
	got, err := ls.fetchAptRelease(context.Background(), up.URL+"/dists/stable", "", nil)
	if err != nil {
		t.Fatalf("fetchAptRelease (Release fallback): %v", err)
	}
	if string(got) != string(release) {
		t.Errorf("fetchAptRelease returned %q, want the Release body", got)
	}

	// Neither InRelease nor Release present: a fetch error is surfaced.
	empty := httptest.NewServer(http.NewServeMux())
	defer empty.Close()
	if _, err := ls.fetchAptRelease(context.Background(), empty.URL+"/dists/stable", "", nil); err == nil || !strings.Contains(err.Error(), "fetch InRelease/Release") {
		t.Errorf("fetchAptRelease with no metadata = %v, want fetch error", err)
	}
}

// TestCovPkg_FetchRepomdUnsigned exercises fetchRepomd without a signing key,
// plus the missing-repomd error.
func TestCovPkg_FetchRepomdUnsigned(t *testing.T) {
	repomd := []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo"></repomd>`)
	mux := http.NewServeMux()
	mux.HandleFunc("/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(repomd) })
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, _ := newRpmLowServer(t)
	got, err := ls.fetchRepomd(context.Background(), up.URL, "", nil)
	if err != nil {
		t.Fatalf("fetchRepomd: %v", err)
	}
	if string(got) != string(repomd) {
		t.Errorf("fetchRepomd returned %q, want the repomd body", got)
	}
	empty := httptest.NewServer(http.NewServeMux())
	defer empty.Close()
	if _, err := ls.fetchRepomd(context.Background(), empty.URL, "", nil); err == nil || !strings.Contains(err.Error(), "fetch repomd.xml") {
		t.Errorf("fetchRepomd with no repomd = %v, want fetch error", err)
	}
}

// TestCovPkg_DecompressCompressByExt covers extension-driven (de)compression:
// gzip via the stdlib, xz via the binary (skipped if absent), zchunk rejection,
// and the plain passthrough.
func TestCovPkg_DecompressCompressByExt(t *testing.T) {
	plain := []byte("index payload for extension dispatch")

	// gzip round-trip through compressByExt/decompressByExt.
	gz, err := compressByExt("primary.xml.gz", plain)
	if err != nil {
		t.Fatalf("compressByExt gz: %v", err)
	}
	back, err := decompressByExt("primary.xml.gz", gz)
	if err != nil || string(back) != string(plain) {
		t.Fatalf("gz round-trip = %q, %v", back, err)
	}

	// Plain passthrough (no recognized extension).
	if out, err := compressByExt("primary.xml", plain); err != nil || string(out) != string(plain) {
		t.Fatalf("compressByExt plain = %q, %v", out, err)
	}
	if out, err := decompressByExt("primary.xml", plain); err != nil || string(out) != string(plain) {
		t.Fatalf("decompressByExt plain = %q, %v", out, err)
	}

	// zchunk cannot be produced or parsed.
	if _, err := compressByExt("primary.xml.zck", plain); err == nil || !strings.Contains(err.Error(), "zchunk") {
		t.Errorf("compressByExt zck = %v, want zchunk error", err)
	}
	if _, err := decompressByExt("primary.xml.zck", plain); err == nil || !strings.Contains(err.Error(), "zchunk") {
		t.Errorf("decompressByExt zck = %v, want zchunk error", err)
	}

	// xz round-trip via the binary, exercising xzDecompress.
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz not installed; skipping xz round-trip")
	}
	xz, err := compressByExt("primary.xml.xz", plain)
	if err != nil {
		t.Fatalf("compressByExt xz: %v", err)
	}
	xback, err := decompressByExt("primary.xml.xz", xz)
	if err != nil || string(xback) != string(plain) {
		t.Fatalf("xz round-trip = %q, %v", xback, err)
	}
}

// TestCovPkg_RpmRepoListEndpoint imports an RPM bundle and confirms the "Set me
// up" repo list surfaces the mirror through rpmRepoList (unsigned by default).
func TestCovPkg_RpmRepoListEndpoint(t *testing.T) {
	hs, _, _ := collectAndImportRpm(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/ui/api/repos?eco=rpm")
	if code != http.StatusOK {
		t.Fatalf("repos endpoint status %d", code)
	}
	var repos UIReposResponse
	if err := json.Unmarshal([]byte(body), &repos); err != nil {
		t.Fatalf("decode repos: %v (%s)", err, body)
	}
	if len(repos.Repos) != 1 || repos.Repos[0].Name != "vscode" {
		t.Fatalf("rpm repo list = %+v, want one 'vscode' repo", repos.Repos)
	}
	if repos.Repos[0].Signed {
		t.Error("rpm repo should be unsigned without a high-side RPM key")
	}

	// The direct call also returns nil when the rpm tree does not yet exist.
	fresh := newTestHighServer(t, hs.publicKey)
	if got, err := fresh.rpmRepoList(); err != nil || got != nil {
		t.Errorf("rpmRepoList on empty tree = %v, %v; want nil, nil", got, err)
	}
}

// TestCovPkg_SignNoKeyRemovesStale confirms that, without a high-side signing
// key, publishing removes any stale APT/RPM signatures and reports success.
func TestCovPkg_SignNoKeyRemovesStale(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub) // no AptGPGKey / RpmGPGKey configured

	distDir := t.TempDir()
	writeFile(t, filepath.Join(distDir, "InRelease"), []byte("stale clearsign"))
	writeFile(t, filepath.Join(distDir, "Release.gpg"), []byte("stale detached"))
	if err := hs.signAptRelease(distDir); err != nil {
		t.Fatalf("signAptRelease (no key): %v", err)
	}
	for _, name := range []string{"InRelease", "Release.gpg"} {
		if _, err := os.Stat(filepath.Join(distDir, name)); !os.IsNotExist(err) {
			t.Errorf("stale %s should have been removed, stat = %v", name, err)
		}
	}

	repodata := t.TempDir()
	sig := filepath.Join(repodata, "repomd.xml.asc")
	writeFile(t, sig, []byte("stale asc"))
	if err := hs.signRpmRepomd(repodata); err != nil {
		t.Fatalf("signRpmRepomd (no key): %v", err)
	}
	if _, err := os.Stat(sig); !os.IsNotExist(err) {
		t.Errorf("stale repomd.xml.asc should have been removed, stat = %v", err)
	}
}

// TestCovPkg_RpmVerCmpSeparatorEdges pins the caret-at-end (post-release) branch
// of rpmCmpCaret and the release-less split of splitRpmVerRel.
func TestCovPkg_RpmVerCmpSeparatorEdges(t *testing.T) {
	if got := rpmVerCmp("1.0^", "1.0"); got != 1 { // trailing caret is newer
		t.Errorf(`rpmVerCmp("1.0^","1.0") = %d, want 1`, got)
	}
	if got := rpmVerCmp("1.0", "1.0^"); got != -1 {
		t.Errorf(`rpmVerCmp("1.0","1.0^") = %d, want -1`, got)
	}
	// A caret facing a non-caret character in range: the non-caret side wins.
	if got := rpmVerCmp("1.0a", "1.0^"); got != 1 {
		t.Errorf(`rpmVerCmp("1.0a","1.0^") = %d, want 1`, got)
	}
	if got := rpmVerCmp("1.0^", "1.0a"); got != -1 {
		t.Errorf(`rpmVerCmp("1.0^","1.0a") = %d, want -1`, got)
	}
	// Matching carets on both sides advance to compare the trailing segment.
	if got := rpmVerCmp("1.0^2", "1.0^3"); got != -1 {
		t.Errorf(`rpmVerCmp("1.0^2","1.0^3") = %d, want -1`, got)
	}
	if ver, rel := splitRpmVerRel("1.2.3"); ver != "1.2.3" || rel != "" {
		t.Errorf(`splitRpmVerRel("1.2.3") = %q, %q; want "1.2.3", ""`, ver, rel)
	}
	if ver, rel := splitRpmVerRel("1.2.3-4"); ver != "1.2.3" || rel != "4" {
		t.Errorf(`splitRpmVerRel("1.2.3-4") = %q, %q; want "1.2.3", "4"`, ver, rel)
	}
}

// TestCovPkg_GPGVerifyAndSign is a real gpg round-trip (skipped without gpg):
// it drives runGPGVerify through both the clearsigned and detached fetch paths,
// and exercises the high-side signAptRelease / signRpmRepomd key branches.
func TestCovPkg_GPGVerifyAndSign(t *testing.T) {
	uid := covPkgGPGKey(t)
	keyring := covPkgKeyring(t)
	ctx := context.Background()

	// --- fetchAptRelease with a clearsigned InRelease (gpgVerifyClearsigned) ---
	release := []byte("Origin: Test\nSuite: stable\nComponents: main\nSHA256:\n")
	inrelease := covPkgGPGSign(t, release, true)
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(inrelease) })
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, _ := newAptLowServer(t)
	got, err := ls.fetchAptRelease(ctx, up.URL+"/dists/stable", keyring, nil)
	if err != nil {
		t.Fatalf("fetchAptRelease (signed InRelease): %v", err)
	}
	if !strings.Contains(string(got), "Origin: Test") {
		t.Errorf("verified InRelease body = %q", got)
	}
	// A wrong keyring makes verification fail.
	empty := filepath.Join(t.TempDir(), "empty.gpg")
	writeFile(t, empty, nil)
	if _, err := ls.fetchAptRelease(ctx, up.URL+"/dists/stable", empty, nil); err == nil || !strings.Contains(err.Error(), "verify InRelease") {
		t.Errorf("fetchAptRelease with wrong keyring = %v, want verify error", err)
	}

	// --- fetchAptRelease detached fallback (gpgVerifyDetached) ---
	relSig := covPkgGPGSign(t, release, false)
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/dists/stable/Release", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(release) })
	mux2.HandleFunc("/dists/stable/Release.gpg", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(relSig) })
	up2 := httptest.NewServer(mux2)
	defer up2.Close()
	if _, err := ls.fetchAptRelease(ctx, up2.URL+"/dists/stable", keyring, nil); err != nil {
		t.Fatalf("fetchAptRelease (detached Release.gpg): %v", err)
	}

	// --- fetchRepomd with a detached repomd.xml.asc ---
	repomd := []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo"></repomd>`)
	repomdSig := covPkgGPGSign(t, repomd, false)
	mux3 := http.NewServeMux()
	mux3.HandleFunc("/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(repomd) })
	mux3.HandleFunc("/repodata/repomd.xml.asc", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(repomdSig) })
	up3 := httptest.NewServer(mux3)
	defer up3.Close()
	rls, _ := newRpmLowServer(t)
	if _, err := rls.fetchRepomd(ctx, up3.URL, keyring, nil); err != nil {
		t.Fatalf("fetchRepomd (signed): %v", err)
	}

	// runGPGVerify directly: tampered data is rejected.
	if err := runGPGVerify(ctx, keyring, []byte("tampered"), relSig); err == nil {
		t.Error("runGPGVerify should reject a mismatched detached signature")
	}

	// --- signAptRelease / signRpmRepomd with a real key ---
	cfg := HighConfig{Root: t.TempDir(), Landing: t.TempDir(), ImportInterval: 0, AptGPGKey: uid, RpmGPGKey: uid}
	pub := ls.privateKey.Public().(ed25519.PublicKey)
	hs, err := NewHighServer(cfg, pub)
	if err != nil {
		t.Fatal(err)
	}

	distDir := t.TempDir()
	writeFile(t, filepath.Join(distDir, "Release"), release)
	if err := hs.signAptRelease(distDir); err != nil {
		t.Fatalf("signAptRelease (with key): %v", err)
	}
	inrel, err := os.ReadFile(filepath.Join(distDir, "InRelease"))
	if err != nil {
		t.Fatalf("InRelease not written: %v", err)
	}
	if err := runGPGVerify(ctx, keyring, inrel, nil); err != nil {
		t.Errorf("gpgv could not verify signAptRelease's InRelease: %v", err)
	}
	relSigned, err := os.ReadFile(filepath.Join(distDir, "Release.gpg"))
	if err != nil {
		t.Fatalf("Release.gpg not written: %v", err)
	}
	if err := runGPGVerify(ctx, keyring, release, relSigned); err != nil {
		t.Errorf("gpgv could not verify signAptRelease's Release.gpg: %v", err)
	}

	repodata := t.TempDir()
	writeFile(t, filepath.Join(repodata, "repomd.xml"), repomd)
	if err := hs.signRpmRepomd(repodata); err != nil {
		t.Fatalf("signRpmRepomd (with key): %v", err)
	}
	asc, err := os.ReadFile(filepath.Join(repodata, "repomd.xml.asc"))
	if err != nil {
		t.Fatalf("repomd.xml.asc not written: %v", err)
	}
	if err := runGPGVerify(ctx, keyring, repomd, asc); err != nil {
		t.Errorf("gpgv could not verify signRpmRepomd's repomd.xml.asc: %v", err)
	}
}
