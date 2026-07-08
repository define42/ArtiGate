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

func TestRpmVerCmp(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.10", "1.9", 1}, // numeric, not lexical
		{"1.0", "1.0.1", -1},
		{"2.0", "1.0", 1},
		{"1.0", "1.0a", -1},    // longer (alpha-suffixed) wins
		{"fc38", "fc39", -1},   // alpha then numeric segment
		{"1.0~rc1", "1.0", -1}, // tilde sorts before
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0^20240101", -1}, // caret sorts after (post-release)
		{"1.0^a", "1.0", 1},
		{"01", "1", 0}, // leading zeros
	}
	for _, tt := range tests {
		if got := rpmVerCmp(tt.a, tt.b); got != tt.want {
			t.Errorf("rpmVerCmp(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := rpmVerCmp(tt.b, tt.a); got != -tt.want { // antisymmetry
			t.Errorf("rpmVerCmp(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestFilterNewestRpm(t *testing.T) {
	pkgs := []RpmPackage{
		{Name: "code", Version: "1.100.0-1", Arch: "x86_64", Location: "Packages/code-1.100.0-1.rpm"},
		{Name: "code", Version: "1.101.2-1", Arch: "x86_64", Location: "Packages/code-1.101.2-1.rpm"},
		{Name: "code", Epoch: "1", Version: "1.0.0-1", Arch: "x86_64", Location: "Packages/code-1.0.0-1.rpm"},
		{Name: "code", Version: "1.101.2-1", Arch: "aarch64", Location: "Packages/code-1.101.2-1.aarch64.rpm"},
	}
	got := filterNewestRpm(pkgs)
	if len(got) != 2 { // newest x86_64 + newest aarch64
		t.Fatalf("kept %d packages, want 2: %+v", len(got), got)
	}
	for _, p := range got {
		// The epoch-1 build is newest for x86_64 despite its lower version number.
		if p.Arch == "x86_64" && p.Epoch != "1" {
			t.Errorf("x86_64 newest should be the epoch-1 build, got %+v", p)
		}
	}
}

func TestFilterPrimaryXML(t *testing.T) {
	primary := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">` + "\n" +
		`<package type="rpm"><name>code</name><arch>x86_64</arch><version epoch="0" ver="1.100.0" rel="1"/>` +
		`<checksum type="sha256" pkgid="YES">aaa111</checksum><location href="Packages/code-1.100.0-1.x86_64.rpm"/></package>` + "\n" +
		`<package type="rpm"><name>code</name><arch>x86_64</arch><version epoch="0" ver="1.101.2" rel="1"/>` +
		`<checksum type="sha256" pkgid="YES">bbb222</checksum><location href="Packages/code-1.101.2-1.x86_64.rpm"/></package>` + "\n" +
		`</metadata>` + "\n"
	got := string(filterPrimaryXML([]byte(primary), map[string]bool{"bbb222": true}))
	if strings.Contains(got, "aaa111") || strings.Contains(got, "1.100.0") {
		t.Errorf("filtered primary still contains the dropped version:\n%s", got)
	}
	if !strings.Contains(got, "bbb222") || !strings.Contains(got, "1.101.2") {
		t.Errorf("filtered primary missing the kept version:\n%s", got)
	}
	if !strings.Contains(got, `packages="1"`) {
		t.Errorf("packages count not updated to 1:\n%s", got)
	}
	if !strings.Contains(got, "</metadata>") {
		t.Errorf("footer lost:\n%s", got)
	}
}

// registerRpmRepoVersions serves a repo whose primary lists several versions of
// one package, each with its own .rpm — for newest-only tests.
func registerRpmRepoVersions(t *testing.T, mux *http.ServeMux, prefix, pkg string, vers [][2]string) {
	t.Helper()
	var pkgBlocks, flBlocks []string
	for _, vr := range vers {
		ver, rel := vr[0], vr[1]
		body := []byte("FAKE-RPM-" + pkg + "-" + ver + "-" + rel)
		sha := aptSHA256(body)
		loc := fmt.Sprintf("Packages/%s-%s-%s.x86_64.rpm", pkg, ver, rel)
		pkgBlocks = append(pkgBlocks, fmt.Sprintf(`<package type="rpm"><name>%s</name><arch>x86_64</arch>`+
			`<version epoch="0" ver="%s" rel="%s"/><checksum type="sha256" pkgid="YES">%s</checksum>`+
			`<size package="%d"/><location href="%s"/></package>`, pkg, ver, rel, sha, len(body), loc))
		flBlocks = append(flBlocks, fmt.Sprintf(`<package pkgid="%s" name="%s" arch="x86_64"><version epoch="0" ver="%s" rel="%s"/></package>`, sha, pkg, ver, rel))
		mux.HandleFunc(prefix+"/"+loc, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	serveRpmRepodata(t, mux, prefix, len(vers), pkgBlocks, flBlocks)
}

// serveRpmRepodata assembles primary/filelists XML from per-package blocks and
// serves them (gzipped) with a matching repomd.xml under prefix/repodata.
func serveRpmRepodata(t *testing.T, mux *http.ServeMux, prefix string, n int, pkgBlocks, flBlocks []string) {
	t.Helper()
	primary := []byte(fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
			"<metadata xmlns=\"http://linux.duke.edu/metadata/common\" packages=\"%d\">\n%s\n</metadata>\n",
		n, strings.Join(pkgBlocks, "\n")))
	filelists := []byte(fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
			"<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"%d\">\n%s\n</filelists>\n",
		n, strings.Join(flBlocks, "\n")))
	data := func(typ string, plain []byte) string {
		gz, err := gzipBytes(plain)
		if err != nil {
			t.Fatal(err)
		}
		href := "repodata/" + typ + ".xml.gz"
		mux.HandleFunc(prefix+"/"+href, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz) })
		return fmt.Sprintf("  <data type=%q>\n    <checksum type=\"sha256\">%s</checksum>\n"+
			"    <open-checksum type=\"sha256\">%s</open-checksum>\n    <location href=%q/>\n"+
			"    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n",
			typ, aptSHA256(gz), aptSHA256(plain), href, len(gz), len(plain))
	}
	repomd := `<?xml version="1.0" encoding="UTF-8"?>` + "\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\n  <revision>1</revision>\n" +
		data("primary", primary) + data("filelists", filelists) + "</repomd>\n"
	mux.HandleFunc(prefix+"/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(repomd)) })
}

// registerRpmRepoArches serves a repo whose primary lists one build of a
// package per architecture — for architecture-filter tests.
func registerRpmRepoArches(t *testing.T, mux *http.ServeMux, prefix, pkg string, arches []string) {
	t.Helper()
	var pkgBlocks, flBlocks []string
	for _, arch := range arches {
		body := []byte("FAKE-RPM-" + pkg + "-" + arch)
		sha := aptSHA256(body)
		loc := fmt.Sprintf("Packages/%s-1.0-1.%s.rpm", pkg, arch)
		pkgBlocks = append(pkgBlocks, fmt.Sprintf(`<package type="rpm"><name>%s</name><arch>%s</arch>`+
			`<version epoch="0" ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">%s</checksum>`+
			`<size package="%d"/><location href="%s"/></package>`, pkg, arch, sha, len(body), loc))
		flBlocks = append(flBlocks, fmt.Sprintf(`<package pkgid="%s" name="%s" arch="%s"><version epoch="0" ver="1.0" rel="1"/></package>`, sha, pkg, arch))
		mux.HandleFunc(prefix+"/"+loc, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	serveRpmRepodata(t, mux, prefix, len(arches), pkgBlocks, flBlocks)
}

// TestCollectRpmNewestOnly mirrors a repo that lists two versions of one package
// with newest-only (the default): only the newest .rpm is bundled, and the
// high side serves a primary index that advertises just that version. Importing
// the bundle also validates that the rewritten primary's checksums match the
// manifest.
func TestCollectRpmNewestOnly(t *testing.T) {
	mux := http.NewServeMux()
	registerRpmRepoVersions(t, mux, "/yumrepos/vscode", "code", [][2]string{{"1.100.0", "1"}, {"1.101.2", "1"}})
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, priv := newRpmLowServer(t)
	res, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "vscode", BaseURL: up.URL + "/yumrepos/vscode"})
	if err != nil {
		t.Fatalf("CollectRpm: %v", err)
	}
	if res.ExportedModules != 1 { // only the newest .rpm
		t.Fatalf("newest-only bundled %d packages, want 1", res.ExportedModules)
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
		t.Fatalf("import of newest-only rpm bundle failed (rewritten primary checksums must match manifest): %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	base := srv.URL + "/rpm/vscode"
	// The served (regenerated) primary advertises only the newest version.
	assertServed(t, base+"/repodata/primary.xml.gz", "")
	assertServed(t, base+"/Packages/code-1.101.2-1.x86_64.rpm", "FAKE-RPM-code-1.101.2-1")
	if code, _ := httpGet(t, base+"/Packages/code-1.100.0-1.x86_64.rpm"); code == http.StatusOK {
		t.Error("old version should not be mirrored under newest-only")
	}

	// With newest-only disabled, every version is mirrored.
	no := false
	all, err := ls.CollectRpm(context.Background(), RpmCollectRequest{
		Name: "vscode", BaseURL: up.URL + "/yumrepos/vscode", NewestOnly: &no,
	})
	if err != nil {
		t.Fatal(err)
	}
	if all.ExportedModules != 2 {
		t.Errorf("all-versions bundled %d packages, want 2", all.ExportedModules)
	}
}

// TestCollectRpmArchFilter mirrors a repo listing x86_64, noarch, and i686
// builds: the default filter keeps x86_64 + noarch and rewrites the served
// primary so i686 is neither downloaded nor advertised; an explicit
// architectures list overrides the default.
func TestCollectRpmArchFilter(t *testing.T) {
	mux := http.NewServeMux()
	registerRpmRepoArches(t, mux, "/yumrepos/tools", "tool", []string{"x86_64", "noarch", "i686"})
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, priv := newRpmLowServer(t)
	res, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "tools", BaseURL: up.URL + "/yumrepos/tools"})
	if err != nil {
		t.Fatalf("CollectRpm: %v", err)
	}
	if res.ExportedModules != 2 { // x86_64 + noarch; i686 dropped
		t.Fatalf("default arch filter bundled %d packages, want 2", res.ExportedModules)
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
		t.Fatalf("import failed (rewritten primary checksums must match manifest): %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	base := srv.URL + "/rpm/tools"
	assertServed(t, base+"/Packages/tool-1.0-1.x86_64.rpm", "FAKE-RPM-tool-x86_64")
	assertServed(t, base+"/Packages/tool-1.0-1.noarch.rpm", "FAKE-RPM-tool-noarch")
	if code, _ := httpGet(t, base+"/Packages/tool-1.0-1.i686.rpm"); code == http.StatusOK {
		t.Error("i686 package should not be mirrored by the default filter")
	}

	// An explicit list overrides the default: strictly x86_64, no noarch.
	only, err := ls.CollectRpm(context.Background(), RpmCollectRequest{
		Name: "tools", BaseURL: up.URL + "/yumrepos/tools", Architectures: []string{"x86_64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if only.ExportedModules != 1 {
		t.Errorf("explicit x86_64 filter bundled %d packages, want 1", only.ExportedModules)
	}
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
