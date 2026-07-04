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

// fakeAptUpstream serves a minimal but valid APT repository (Release + Packages
// + one .deb) whose checksums chain correctly, so the collector's SHA256
// verification passes without needing GPG. tamper corrupts the served .deb so
// the SHA256 check fails.
func fakeAptUpstream(t *testing.T, tamper bool) (*httptest.Server, string) {
	t.Helper()
	deb := []byte("FAKE-DEB-BYTES-code-1.101.2")
	debRel := "pool/main/c/code/code_1.101.2_amd64.deb"
	debSHA := aptSHA256(deb)

	stanza := fmt.Sprintf("Package: code\nVersion: 1.101.2\nArchitecture: amd64\n"+
		"Maintainer: Test <t@example.com>\nFilename: %s\nSize: %d\nSHA256: %s\n"+
		"Description: test package\n", debRel, len(deb), debSHA)
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

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/code/dists/stable/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(release))
	})
	mux.HandleFunc("/repos/code/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(packagesGz)
	})
	mux.HandleFunc("/repos/code/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(packages)
	})
	mux.HandleFunc("/repos/code/"+debRel, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(served)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, string(deb)
}

func newAptLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	return ls, priv
}

func TestParseAptSource(t *testing.T) {
	src := "Types: deb\n" +
		"URIs: https://packages.microsoft.com/repos/code\n" +
		"Suites: stable\n" +
		"Components: main\n" +
		"Architectures: amd64\n" +
		"Signed-By: /usr/share/keyrings/microsoft.gpg\n"
	cfg, err := parseAptSource(src)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URI != "https://packages.microsoft.com/repos/code" || cfg.Suite != "stable" ||
		len(cfg.Components) != 1 || cfg.Components[0] != "main" ||
		len(cfg.Architectures) != 1 || cfg.Architectures[0] != "amd64" ||
		cfg.SignedBy != "/usr/share/keyrings/microsoft.gpg" {
		t.Fatalf("parseAptSource = %+v", cfg)
	}
	// A non-deb source type is rejected.
	if _, err := parseAptSource("Types: deb-src\nURIs: https://x/y\nSuites: s\n"); err == nil {
		t.Error("deb-src source should be rejected")
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
	if res.BundleID != "go-bundle-000001" || res.ExportedModules != 1 {
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
