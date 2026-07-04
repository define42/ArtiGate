package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func aptSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// registerAptRepo serves a minimal but valid APT repository (Release + Packages
// + one .deb) for one package at prefix on mux, with a correctly chaining
// SHA256 so the collector verifies without GPG. tamper corrupts the served .deb.
// It returns the .deb body.
func registerAptRepo(t *testing.T, mux *http.ServeMux, prefix, pkg, version string, tamper bool) string {
	t.Helper()
	deb := []byte("FAKE-DEB-" + pkg + "-" + version)
	debRel := fmt.Sprintf("pool/main/%s/%s/%s_%s_amd64.deb", pkg[:1], pkg, pkg, version)
	stanza := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\n"+
		"Maintainer: Test <t@example.com>\nFilename: %s\nSize: %d\nSHA256: %s\n"+
		"Description: test package\n", pkg, version, debRel, len(deb), aptSHA256(deb))
	packages := []byte(stanza + "\n")
	packagesGz, err := gzipBytes(packages)
	if err != nil {
		t.Fatal(err)
	}
	release := "Origin: Test\nLabel: test\nSuite: stable\nCodename: stable\n" +
		"Components: main\nArchitectures: amd64\nDate: Mon, 01 Jan 2024 00:00:00 UTC\nSHA256:\n" +
		fmt.Sprintf(" %s %d main/binary-amd64/Packages.gz\n", aptSHA256(packagesGz), len(packagesGz)) +
		fmt.Sprintf(" %s %d main/binary-amd64/Packages\n", aptSHA256(packages), len(packages))
	served := deb
	if tamper {
		served = []byte("CORRUPTED-DIFFERENT-BYTES")
	}
	mux.HandleFunc(prefix+"/dists/stable/InRelease", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(release)) })
	mux.HandleFunc(prefix+"/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(packagesGz) })
	mux.HandleFunc(prefix+"/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(packages) })
	mux.HandleFunc(prefix+"/"+debRel, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(served) })
	return string(deb)
}

// fakeAptUpstream serves a single-package APT repository at /repos/code.
func fakeAptUpstream(t *testing.T, tamper bool) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	deb := registerAptRepo(t, mux, "/repos/code", "code", "1.101.2", tamper)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, deb
}

func newAptLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

func TestParseAptSource(t *testing.T) {
	src := "Types: deb\n" +
		"URIs: https://packages.microsoft.com/repos/code\n" +
		"Suites: stable\n" +
		"Components: main\n" +
		"Architectures: amd64\n" +
		"Signed-By: /usr/share/keyrings/microsoft.gpg\n"
	cfgs, err := parseAptSources(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("parseAptSources returned %d stanzas, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.URI != "https://packages.microsoft.com/repos/code" || cfg.Suite != "stable" ||
		len(cfg.Components) != 1 || cfg.Components[0] != "main" ||
		len(cfg.Architectures) != 1 || cfg.Architectures[0] != "amd64" ||
		cfg.SignedBy != "/usr/share/keyrings/microsoft.gpg" {
		t.Fatalf("parseAptSources = %+v", cfg)
	}
	// A non-deb source type is rejected.
	if _, err := parseAptSources("Types: deb-src\nURIs: https://x/y\nSuites: s\n"); err == nil {
		t.Error("deb-src source should be rejected")
	}
	// A multi-stanza .sources file yields one config per repository.
	multi := "Types: deb\nURIs: https://a.example/repo\nSuites: stable\nComponents: main\nArchitectures: amd64\n\n" +
		"Types: deb\nURIs: https://b.example/repo\nSuites: noble\nComponents: main\nArchitectures: arm64\n"
	got, err := parseAptSources(multi)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].URI != "https://a.example/repo" || got[1].Suite != "noble" {
		t.Fatalf("multi-stanza parse = %+v", got)
	}
}

func TestReleaseIndexChecksums(t *testing.T) {
	release := map[string]string{"SHA256": "\n abc123 42 main/binary-amd64/Packages.gz\n def456 7 main/binary-amd64/Packages"}
	sums := releaseIndexChecksums(release)
	if c := sums["main/binary-amd64/Packages.gz"]; c.sha256 != "abc123" || c.size != 42 {
		t.Errorf("Packages.gz checksum = %+v", c)
	}
	if c := sums["main/binary-amd64/Packages"]; c.sha256 != "def456" || c.size != 7 {
		t.Errorf("Packages checksum = %+v", c)
	}
}

// collectAndImportApt mirrors the fake upstream on a low server, transfers the
// bundle to a fresh high server, and imports it.
func collectAndImportApt(t *testing.T) (*HighServer, ExportResult, string) {
	t.Helper()
	up, debBody := fakeAptUpstream(t, false)
	ls, priv := newAptLowServer(t)
	res, err := ls.CollectApt(context.Background(), AptCollectRequest{
		Name:  "microsoft-code",
		URI:   up.URL + "/repos/code",
		Suite: "stable", Components: []string{"main"}, Architectures: []string{"amd64"},
	})
	if err != nil {
		t.Fatalf("CollectApt: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of apt bundle failed: %v", err)
	}
	return hs, res, debBody
}

// TestLowToHighAptPipeline is the full round-trip: mirror a fake upstream APT
// repo on the low side, transfer the signed bundle, import it, and confirm the
// high side regenerated the APT metadata and serves the repository.
func TestLowToHighAptPipeline(t *testing.T) {
	hs, res, debBody := collectAndImportApt(t)
	if res.BundleID != "apt-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	base := srv.URL + "/apt/microsoft-code"
	// The .deb is served from the pool with intact bytes.
	assertServed(t, base+"/pool/main/c/code/code_1.101.2_amd64.deb", debBody)
	// Packages/Packages.gz and Release were regenerated from the imported stanza.
	assertServed(t, base+"/dists/stable/main/binary-amd64/Packages", "Package: code")
	assertServed(t, base+"/dists/stable/main/binary-amd64/Packages", "Filename: pool/main/c/code/code_1.101.2_amd64.deb")
	assertServed(t, base+"/dists/stable/main/binary-amd64/Packages.gz", "")
	assertServed(t, base+"/dists/stable/Release", "SHA256:")
	assertServed(t, base+"/dists/stable/Release", "main/binary-amd64/Packages.gz")

	// Unsigned by default (no --apt-gpg-key), so InRelease is absent.
	if code, _ := httpGet(t, base+"/dists/stable/InRelease"); code == http.StatusOK {
		t.Error("InRelease should be absent without a high-side signing key")
	}
}

// TestCollectAptMultipleRepos mirrors two repositories in one deb822 source
// list and confirms they are kept in separate namespaces (not mixed into one
// index) on the high side.
func TestCollectAptMultipleRepos(t *testing.T) {
	mux := http.NewServeMux()
	registerAptRepo(t, mux, "/repos/code", "code", "1.101.2", false)
	registerAptRepo(t, mux, "/repos/tools", "tool", "2.0.0", false)
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, priv := newAptLowServer(t)
	src := "Types: deb\nURIs: " + up.URL + "/repos/code\nSuites: stable\nComponents: main\nArchitectures: amd64\n\n" +
		"Types: deb\nURIs: " + up.URL + "/repos/tools\nSuites: stable\nComponents: main\nArchitectures: amd64\n"
	res, err := ls.CollectApt(context.Background(), AptCollectRequest{SourceList: src})
	if err != nil {
		t.Fatalf("CollectApt (two repos): %v", err)
	}
	// One bundle carrying both repositories' packages.
	if res.BundleID != "apt-bundle-000001" || res.ExportedModules != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	nCode := aptMirrorName(up.URL + "/repos/code")
	nTools := aptMirrorName(up.URL + "/repos/tools")
	if nCode == nTools {
		t.Fatal("distinct repos must derive distinct mirror names")
	}
	// Each repo is served under its own namespace with its own Packages.
	assertServed(t, srv.URL+"/apt/"+nCode+"/dists/stable/main/binary-amd64/Packages", "Package: code")
	assertServed(t, srv.URL+"/apt/"+nTools+"/dists/stable/main/binary-amd64/Packages", "Package: tool")

	// The repos are NOT mixed: code's index must not contain tool and vice versa.
	if _, body := httpGet(t, srv.URL+"/apt/"+nCode+"/dists/stable/main/binary-amd64/Packages"); strings.Contains(body, "Package: tool") {
		t.Error("code's index contains tool — repositories were mixed")
	}
}

func TestCollectAptRejectsBadDebHash(t *testing.T) {
	up, _ := fakeAptUpstream(t, true) // tampered .deb
	ls, _ := newAptLowServer(t)
	_, err := ls.CollectApt(context.Background(), AptCollectRequest{
		Name: "microsoft-code", URI: up.URL + "/repos/code",
		Suite: "stable", Components: []string{"main"}, Architectures: []string{"amd64"},
	})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("CollectApt with tampered .deb = %v, want a sha256 mismatch", err)
	}
}

func TestCollectAptEmptyRequest(t *testing.T) {
	ls, _ := newAptLowServer(t)
	if _, err := ls.CollectApt(context.Background(), AptCollectRequest{}); err == nil {
		t.Error("empty CollectApt should error")
	}
}

// TestHighServerUIAptTree confirms the dashboard exposes the imported APT
// packages through the tree and detail APIs.
func TestHighServerUIAptTree(t *testing.T) {
	hs, _, _ := collectAndImportApt(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Tree root is the mirror name; expanding it yields the package.
	if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=apt&path="); !strings.Contains(body, `"microsoft-code"`) {
		t.Errorf("apt tree root missing mirror: %s", body)
	}
	if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=apt&path=microsoft-code"); !strings.Contains(body, `"code"`) {
		t.Errorf("apt tree missing package: %s", body)
	}
	// Detail shows the coordinate.
	assertServed(t, srv.URL+"/ui/api/detail?eco=apt&path=microsoft-code/code@1.101.2", "1.101.2")
}

func TestServeAptRejectsTraversal(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	for _, p := range []string{"/apt/../import-state.json", "/apt/..%2f..%2fimport-state.json"} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("traversal %s returned 200, want rejection", p)
		}
	}
}
