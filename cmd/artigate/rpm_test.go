package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// registerRpmRepo serves a full-metadata YUM/DNF repository (repomd.xml with
// primary + filelists + updateinfo, plus one .rpm) for one package at prefix on
// mux, with correctly chaining SHA256s so the collector verifies without GPG.
// tamper corrupts the served .rpm. It returns the .rpm body.
func registerRpmRepo(t *testing.T, mux *http.ServeMux, prefix, pkg, ver, rel string, tamper bool) string {
	t.Helper()
	rpmBytes := []byte("FAKE-RPM-" + pkg + "-" + ver + "-" + rel)
	rpmSHA := aptSHA256(rpmBytes)
	loc := fmt.Sprintf("Packages/%s-%s-%s.x86_64.rpm", pkg, ver, rel)

	primary := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">`+"\n"+
		`<package type="rpm"><name>%s</name><arch>x86_64</arch><version epoch="0" ver="%s" rel="%s"/>`+
		`<checksum type="sha256" pkgid="YES">%s</checksum><size package="%d"/><location href="%s"/></package>`+"\n"+
		`</metadata>`+"\n", pkg, ver, rel, rpmSHA, len(rpmBytes), loc))
	filelists := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="1">`+"\n"+
		`<package pkgid="%s" name="%s" arch="x86_64"><version epoch="0" ver="%s" rel="%s"/></package>`+"\n"+
		`</filelists>`+"\n", rpmSHA, pkg, ver, rel))
	updateinfo := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n<updates></updates>\n")

	// data serves one metadata file (gzipped) and returns its repomd <data> block.
	data := func(typ string, plain []byte) string {
		gz, err := gzipBytes(plain)
		if err != nil {
			t.Fatal(err)
		}
		href := "repodata/" + typ + ".xml.gz"
		mux.HandleFunc("/"+strings.TrimLeft(prefix+"/"+href, "/"), func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz) })
		return fmt.Sprintf(`  <data type="%s">`+"\n"+
			`    <checksum type="sha256">%s</checksum>`+"\n"+
			`    <open-checksum type="sha256">%s</open-checksum>`+"\n"+
			`    <location href="%s"/>`+"\n"+
			`    <size>%d</size>`+"\n"+
			`    <open-size>%d</open-size>`+"\n"+
			`  </data>`+"\n", typ, aptSHA256(gz), aptSHA256(plain), href, len(gz), len(plain))
	}
	repomd := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<repomd xmlns="http://linux.duke.edu/metadata/repo">` + "\n  <revision>1</revision>\n" +
		data("primary", primary) + data("filelists", filelists) + data("updateinfo", updateinfo) +
		`</repomd>` + "\n"
	mux.HandleFunc(prefix+"/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(repomd)) })

	served := rpmBytes
	if tamper {
		served = []byte("CORRUPTED-DIFFERENT-BYTES")
	}
	mux.HandleFunc(prefix+"/"+loc, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(served) })
	return string(rpmBytes)
}

func fakeRpmUpstream(t *testing.T, tamper bool) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	body := registerRpmRepo(t, mux, "/yumrepos/vscode", "code", "1.101.2", "1", tamper)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, body
}

func newRpmLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
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

func TestParseRepoFile(t *testing.T) {
	repo := "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc\n"
	cfgs, err := parseRepoFile(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 || cfgs[0].Name != "code" || cfgs[0].BaseURL != "https://packages.microsoft.com/yumrepos/vscode" {
		t.Fatalf("parseRepoFile = %+v", cfgs)
	}
	if cfgs[0].GPGKey != "" {
		t.Errorf("remote gpgkey should not become a keyring path, got %q", cfgs[0].GPGKey)
	}
	multi := "[a]\nbaseurl=https://a.example/repo\n\n[b]\nbaseurl=https://b.example/repo\n"
	got, err := parseRepoFile(multi)
	if err != nil || len(got) != 2 || got[0].Name != "a" || got[1].BaseURL != "https://b.example/repo" {
		t.Fatalf("multi-section parse = %+v, err %v", got, err)
	}
}

func TestValidateRpmMirrorConfigRejectsVariables(t *testing.T) {
	if _, err := validateRpmMirrorConfig(rpmMirrorConfig{Name: "x", BaseURL: "https://ex/$releasever/os"}); err == nil {
		t.Error("baseurl with $releasever should be rejected")
	}
}

// collectAndImportRpm mirrors the "vscode" fake upstream and imports it.
func collectAndImportRpm(t *testing.T) (*HighServer, ExportResult, string) {
	t.Helper()
	up, rpmBody := fakeRpmUpstream(t, false)
	ls, priv := newRpmLowServer(t)
	res, err := ls.CollectRpm(context.Background(), RpmCollectRequest{
		Name: "vscode", BaseURL: up.URL + "/yumrepos/vscode",
	})
	if err != nil {
		t.Fatalf("CollectRpm: %v", err)
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
		t.Fatalf("high import of rpm bundle failed: %v", err)
	}
	return hs, res, rpmBody
}

// TestLowToHighRpmPipeline is the full round-trip: mirror a full-metadata fake
// upstream, transfer the bundle, import it, and confirm the high side carries
// every metadata type and regenerates a repomd that lists them all.
func TestLowToHighRpmPipeline(t *testing.T) {
	hs, res, rpmBody := collectAndImportRpm(t)
	if res.BundleID != "rpm-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	base := srv.URL + "/rpm/vscode"
	assertServed(t, base+"/Packages/code-1.101.2-1.x86_64.rpm", rpmBody)

	// Every metadata file is served, including filelists and updateinfo — the
	// types a createrepo_c-only regeneration would drop.
	assertServed(t, base+"/repodata/primary.xml.gz", "")
	assertServed(t, base+"/repodata/filelists.xml.gz", "")
	assertServed(t, base+"/repodata/updateinfo.xml.gz", "")

	// The regenerated repomd lists all three types.
	for _, want := range []string{`type="primary"`, `type="filelists"`, `type="updateinfo"`, "sha256"} {
		assertServed(t, base+"/repodata/repomd.xml", want)
	}
	// Unsigned by default: repomd.xml.asc absent.
	if code, _ := httpGet(t, base+"/repodata/repomd.xml.asc"); code == http.StatusOK {
		t.Error("repomd.xml.asc should be absent without a high-side signing key")
	}
	// The served primary lists the package (carried verbatim from upstream).
	_, body := httpGet(t, base+"/repodata/primary.xml.gz")
	plain, err := gunzip([]byte(body))
	if err != nil {
		t.Fatalf("gunzip primary: %v", err)
	}
	if !strings.Contains(string(plain), "<name>code</name>") {
		t.Errorf("served primary missing package: %s", plain)
	}
}

// TestCollectRpmMultipleRepos mirrors two repos and confirms they stay in
// separate namespaces (not mixed).
func TestCollectRpmMultipleRepos(t *testing.T) {
	mux := http.NewServeMux()
	registerRpmRepo(t, mux, "/repos/code", "code", "1.0", "1", false)
	registerRpmRepo(t, mux, "/repos/tools", "tool", "2.0", "1", false)
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, priv := newRpmLowServer(t)
	repo := "[code]\nbaseurl=" + up.URL + "/repos/code\n\n[tools]\nbaseurl=" + up.URL + "/repos/tools\n"
	res, err := ls.CollectRpm(context.Background(), RpmCollectRequest{RepoFile: repo})
	if err != nil {
		t.Fatalf("CollectRpm (two repos): %v", err)
	}
	if res.ExportedModules != 2 {
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
	assertServed(t, srv.URL+"/rpm/code/Packages/code-1.0-1.x86_64.rpm", "FAKE-RPM-code")
	assertServed(t, srv.URL+"/rpm/tools/Packages/tool-2.0-1.x86_64.rpm", "FAKE-RPM-tool")

	_, body := httpGet(t, srv.URL+"/rpm/code/repodata/primary.xml.gz")
	plain, err := gunzip([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "<name>tool</name>") {
		t.Error("code's repodata contains tool — repositories were mixed")
	}
}

func TestCollectRpmRejectsBadHash(t *testing.T) {
	up, _ := fakeRpmUpstream(t, true) // tampered .rpm
	ls, _ := newRpmLowServer(t)
	_, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "vscode", BaseURL: up.URL + "/yumrepos/vscode"})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("CollectRpm with tampered .rpm = %v, want a sha256 mismatch", err)
	}
}

func TestCollectRpmEmptyRequest(t *testing.T) {
	ls, _ := newRpmLowServer(t)
	if _, err := ls.CollectRpm(context.Background(), RpmCollectRequest{}); err == nil {
		t.Error("empty CollectRpm should error")
	}
}

func TestServeRpmRejectsTraversal(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	for _, p := range []string{"/rpm/../import-state.json", "/rpm/..%2f..%2fimport-state.json"} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("traversal %s returned 200, want rejection", p)
		}
	}
}

func TestHighServerUIRpmTree(t *testing.T) {
	hs, _, _ := collectAndImportRpm(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=rpm&path="); !strings.Contains(body, `"vscode"`) {
		t.Errorf("rpm tree root missing mirror: %s", body)
	}
	if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=rpm&path=vscode"); !strings.Contains(body, `"code"`) {
		t.Errorf("rpm tree missing package: %s", body)
	}
	assertServed(t, srv.URL+"/ui/api/detail?eco=rpm&path=vscode/code@1.101.2-1", "1.101.2-1")
}
