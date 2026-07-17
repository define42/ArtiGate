package main

import (
	"context"
	"crypto/ed25519"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"example.com/artigate/buildin"
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
		// Same length as the real .rpm: the streaming download enforces the
		// index-declared size first, so only same-length corruption proves the
		// SHA256 check itself.
		served = []byte(strings.Repeat("X", len(rpmBytes)))
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

// TestCollectRpmPrivateUpstream exercises HTTP Basic against a repo that
// demands a login on every request (repomd, metadata, and .rpms alike).
func TestCollectRpmPrivateUpstream(t *testing.T) {
	mux := http.NewServeMux()
	registerRpmRepo(t, mux, "/yumrepos/vscode", "code", "1.0.1", "1", false)
	srv := httptest.NewServer(basicAuthGate(mux, testBasicAuth("bot", "hunter2")))
	t.Cleanup(srv.Close)
	ls, _ := newRpmLowServer(t)
	ctx := context.Background()
	base := srv.URL + "/yumrepos/vscode"

	// Anonymous mirrors fail with guidance naming both supply paths.
	_, err := ls.CollectRpm(ctx, RpmCollectRequest{Name: "vscode", BaseURL: base})
	if err == nil || !strings.Contains(err.Error(), upstreamAuthEnv) {
		t.Fatalf("anonymous collect error = %v", err)
	}

	// A wrong login is reported as rejected — and never echoed.
	_, err = ls.CollectRpm(ctx, RpmCollectRequest{
		Name: "vscode", BaseURL: base,
		Auth: &HostCollectAuth{Username: "bot", Password: "nope"},
	})
	if err == nil || !strings.Contains(err.Error(), "were not accepted") || strings.Contains(err.Error(), "nope") {
		t.Fatalf("wrong-login error = %v", err)
	}

	// The per-collect login mirrors the repo.
	if _, err := ls.CollectRpm(ctx, RpmCollectRequest{
		Name: "vscode", BaseURL: base,
		Auth: &HostCollectAuth{Username: "bot", Password: "hunter2"},
	}); err != nil {
		t.Fatalf("authenticated collect: %v", err)
	}

	// Standing ARTIGATE_UPSTREAM_AUTH credentials work without request auth —
	// the only credential source scheduled collects have.
	t.Setenv(upstreamAuthEnv, strings.TrimPrefix(srv.URL, "http://")+"=bot:hunter2")
	if _, err := ls.CollectRpm(ctx, RpmCollectRequest{Name: "vscode", BaseURL: base, Force: true}); err != nil {
		t.Fatalf("env-authenticated collect: %v", err)
	}

	// A base_url that smuggles the login as userinfo is rejected without
	// echoing it.
	_, err = ls.CollectRpm(ctx, RpmCollectRequest{
		Name:    "vscode",
		BaseURL: "http://bot:hunter2@" + strings.TrimPrefix(base, "http://"),
	})
	if err == nil || !strings.Contains(err.Error(), "must not embed credentials") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("userinfo base_url error = %v", err)
	}
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
	got := string(filterIndexXML([]byte(primary), map[string]bool{"bbb222": true}, primaryPkgid))
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

// TestFilterPkgidIndexXML covers the filelists/other shape, where the pkgid is
// an attribute of <package> rather than a checksum element: dropped packages
// must lose their (multi-line) blocks and the root count must follow.
func TestFilterPkgidIndexXML(t *testing.T) {
	docs := map[string]string{
		"filelists": `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
			`<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="2">` + "\n" +
			`<package pkgid="aaa111" name="code" arch="x86_64"><version epoch="0" ver="1.100.0" rel="1"/>` + "\n" +
			`  <file>/usr/bin/code</file>` + "\n</package>\n" +
			`<package pkgid="bbb222" name="code" arch="x86_64"><version epoch="0" ver="1.101.2" rel="1"/>` + "\n" +
			`  <file>/usr/bin/code</file>` + "\n</package>\n" +
			`</filelists>` + "\n",
		"other": `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
			`<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="2">` + "\n" +
			`<package pkgid="aaa111" name="code" arch="x86_64"><version epoch="0" ver="1.100.0" rel="1"/>` +
			`<changelog author="dev">old fix</changelog></package>` + "\n" +
			`<package pkgid="bbb222" name="code" arch="x86_64"><version epoch="0" ver="1.101.2" rel="1"/>` +
			`<changelog author="dev">new fix</changelog></package>` + "\n" +
			`</otherdata>` + "\n",
	}
	for typ, doc := range docs {
		got := string(filterIndexXML([]byte(doc), map[string]bool{"bbb222": true}, listPkgid))
		if strings.Contains(got, "aaa111") || strings.Contains(got, "1.100.0") {
			t.Errorf("filtered %s still contains the dropped package:\n%s", typ, got)
		}
		if !strings.Contains(got, "bbb222") {
			t.Errorf("filtered %s missing the kept package:\n%s", typ, got)
		}
		if !strings.Contains(got, `packages="1"`) {
			t.Errorf("%s packages count not updated to 1:\n%s", typ, got)
		}
	}
	if !isRpmPkgidIndex("filelists") || !isRpmPkgidIndex("filelists_ext") || !isRpmPkgidIndex("other") {
		t.Error("filelists/filelists_ext/other must be recognized as pkgid-keyed indexes")
	}
	// updateinfo/comps/zchunk variants are not pkgid-keyed <package> lists and
	// must be left verbatim (the zchunk ones could not be recompressed anyway).
	for _, typ := range []string{"updateinfo", "group", "primary", "filelists_zck", "other_db"} {
		if isRpmPkgidIndex(typ) {
			t.Errorf("%s must not be rewritten as a pkgid-keyed index", typ)
		}
	}
}

// rpmPkgidBlocks renders the filelists and other <package> blocks for one
// package, keyed by its pkgid like createrepo_c writes them.
func rpmPkgidBlocks(sha, pkg, arch, ver, rel string) (fl, ol string) {
	fl = fmt.Sprintf(`<package pkgid="%s" name="%s" arch="%s"><version epoch="0" ver="%s" rel="%s"/>`+
		`<file>/usr/bin/%s</file></package>`, sha, pkg, arch, ver, rel, pkg)
	ol = fmt.Sprintf(`<package pkgid="%s" name="%s" arch="%s"><version epoch="0" ver="%s" rel="%s"/>`+
		`<changelog author="dev">- update to %s-%s</changelog></package>`, sha, pkg, arch, ver, rel, ver, rel)
	return fl, ol
}

// registerRpmRepoVersions serves a repo whose primary lists several versions of
// one package, each with its own .rpm — for newest-only tests.
func registerRpmRepoVersions(t *testing.T, mux *http.ServeMux, prefix, pkg string, vers [][2]string) {
	t.Helper()
	var pkgBlocks, flBlocks, olBlocks []string
	for _, vr := range vers {
		ver, rel := vr[0], vr[1]
		body := []byte("FAKE-RPM-" + pkg + "-" + ver + "-" + rel)
		sha := aptSHA256(body)
		loc := fmt.Sprintf("Packages/%s-%s-%s.x86_64.rpm", pkg, ver, rel)
		pkgBlocks = append(pkgBlocks, fmt.Sprintf(`<package type="rpm"><name>%s</name><arch>x86_64</arch>`+
			`<version epoch="0" ver="%s" rel="%s"/><checksum type="sha256" pkgid="YES">%s</checksum>`+
			`<size package="%d"/><location href="%s"/></package>`, pkg, ver, rel, sha, len(body), loc))
		fl, ol := rpmPkgidBlocks(sha, pkg, "x86_64", ver, rel)
		flBlocks = append(flBlocks, fl)
		olBlocks = append(olBlocks, ol)
		mux.HandleFunc(prefix+"/"+loc, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	serveRpmRepodata(t, mux, prefix, len(vers), pkgBlocks, flBlocks, olBlocks)
}

// serveRpmRepodata assembles primary/filelists/other XML from per-package
// blocks and serves them (gzipped) with a matching repomd.xml under
// prefix/repodata.
func serveRpmRepodata(t *testing.T, mux *http.ServeMux, prefix string, n int, pkgBlocks, flBlocks, olBlocks []string) {
	t.Helper()
	serveRpmRepodataExt(t, mux, prefix, n, pkgBlocks, flBlocks, olBlocks, "gz", gzipBytes)
}

// serveRpmRepodataExt is serveRpmRepodata with a caller-chosen index
// compression (file extension + compressor), so a test can publish .gz or .zst
// metadata through the same assembly — .zst being the form Docker CE's EL9
// repos ship.
func serveRpmRepodataExt(t *testing.T, mux *http.ServeMux, prefix string, n int, pkgBlocks, flBlocks, olBlocks []string, ext string, compress func([]byte) ([]byte, error)) {
	t.Helper()
	primary := []byte(fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
			"<metadata xmlns=\"http://linux.duke.edu/metadata/common\" packages=\"%d\">\n%s\n</metadata>\n",
		n, strings.Join(pkgBlocks, "\n")))
	filelists := []byte(fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
			"<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"%d\">\n%s\n</filelists>\n",
		n, strings.Join(flBlocks, "\n")))
	other := []byte(fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
			"<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"%d\">\n%s\n</otherdata>\n",
		n, strings.Join(olBlocks, "\n")))
	data := func(typ string, plain []byte) string {
		comp, err := compress(plain)
		if err != nil {
			t.Fatal(err)
		}
		href := "repodata/" + typ + ".xml." + ext
		mux.HandleFunc(prefix+"/"+href, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(comp) })
		return fmt.Sprintf("  <data type=%q>\n    <checksum type=\"sha256\">%s</checksum>\n"+
			"    <open-checksum type=\"sha256\">%s</open-checksum>\n    <location href=%q/>\n"+
			"    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n",
			typ, aptSHA256(comp), aptSHA256(plain), href, len(comp), len(plain))
	}
	repomd := `<?xml version="1.0" encoding="UTF-8"?>` + "\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\n  <revision>1</revision>\n" +
		data("primary", primary) + data("filelists", filelists) + data("other", other) + "</repomd>\n"
	mux.HandleFunc(prefix+"/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(repomd)) })
}

// registerRpmRepoArches serves a repo whose primary lists one build of a
// package per architecture — for architecture-filter tests.
func registerRpmRepoArches(t *testing.T, mux *http.ServeMux, prefix, pkg string, arches []string) {
	t.Helper()
	var pkgBlocks, flBlocks, olBlocks []string
	for _, arch := range arches {
		body := []byte("FAKE-RPM-" + pkg + "-" + arch)
		sha := aptSHA256(body)
		loc := fmt.Sprintf("Packages/%s-1.0-1.%s.rpm", pkg, arch)
		pkgBlocks = append(pkgBlocks, fmt.Sprintf(`<package type="rpm"><name>%s</name><arch>%s</arch>`+
			`<version epoch="0" ver="1.0" rel="1"/><checksum type="sha256" pkgid="YES">%s</checksum>`+
			`<size package="%d"/><location href="%s"/></package>`, pkg, arch, sha, len(body), loc))
		fl, ol := rpmPkgidBlocks(sha, pkg, arch, "1.0", "1")
		flBlocks = append(flBlocks, fl)
		olBlocks = append(olBlocks, ol)
		mux.HandleFunc(prefix+"/"+loc, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	serveRpmRepodata(t, mux, prefix, len(arches), pkgBlocks, flBlocks, olBlocks)
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

	// The pkgid-keyed indexes were rewritten alongside primary: filelists and
	// other must not keep orphan entries (or a stale count) for the dropped
	// build, and the regenerated repomd must advertise the rewritten files'
	// checksums or dnf would reject them.
	droppedSHA := aptSHA256([]byte("FAKE-RPM-code-1.100.0-1"))
	keptSHA := aptSHA256([]byte("FAKE-RPM-code-1.101.2-1"))
	_, repomd := httpGet(t, base+"/repodata/repomd.xml")
	for _, typ := range []string{"primary", "filelists", "other"} {
		_, gz := httpGet(t, base+"/repodata/"+typ+".xml.gz")
		plain, err := gunzip([]byte(gz), maxIndexPlainBytes)
		if err != nil {
			t.Fatalf("gunzip %s: %v", typ, err)
		}
		if strings.Contains(string(plain), droppedSHA) {
			t.Errorf("served %s still lists the dropped build's pkgid", typ)
		}
		if !strings.Contains(string(plain), keptSHA) {
			t.Errorf("served %s is missing the kept build's pkgid:\n%s", typ, plain)
		}
		if !strings.Contains(string(plain), `packages="1"`) {
			t.Errorf("served %s packages count was not rewritten to 1:\n%s", typ, plain)
		}
		for _, sum := range []string{aptSHA256([]byte(gz)), aptSHA256(plain)} {
			if !strings.Contains(repomd, sum) {
				t.Errorf("repomd.xml does not carry the rewritten %s checksum %s:\n%s", typ, sum, repomd)
			}
		}
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

// TestCollectRpmZstdMetadata mirrors a repo whose primary/filelists/other
// indexes are zstd-compressed (.zst) — the exact shape Docker CE's EL9 repos
// ship. Before .zst support the collect failed at parse time with
// "parse primary.xml: XML syntax error on line 1: invalid UTF-8". It also
// exercises the recompress path: newest-only rewrites the .zst primary and the
// pkgid-keyed .zst indexes, and the high side must serve the survivor.
func TestCollectRpmZstdMetadata(t *testing.T) {
	mux := http.NewServeMux()
	var pkgBlocks, flBlocks, olBlocks []string
	for _, vr := range [][2]string{{"1.100.0", "1"}, {"1.101.2", "1"}} {
		ver, rel := vr[0], vr[1]
		body := []byte("FAKE-RPM-code-" + ver + "-" + rel)
		sha := aptSHA256(body)
		loc := fmt.Sprintf("Packages/code-%s-%s.x86_64.rpm", ver, rel)
		pkgBlocks = append(pkgBlocks, fmt.Sprintf(`<package type="rpm"><name>code</name><arch>x86_64</arch>`+
			`<version epoch="0" ver="%s" rel="%s"/><checksum type="sha256" pkgid="YES">%s</checksum>`+
			`<size package="%d"/><location href="%s"/></package>`, ver, rel, sha, len(body), loc))
		fl, ol := rpmPkgidBlocks(sha, "code", "x86_64", ver, rel)
		flBlocks = append(flBlocks, fl)
		olBlocks = append(olBlocks, ol)
		mux.HandleFunc("/yumrepos/docker/"+loc, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	serveRpmRepodataExt(t, mux, "/yumrepos/docker", 2, pkgBlocks, flBlocks, olBlocks, "zst", zstdCompress)
	up := httptest.NewServer(mux)
	defer up.Close()

	ls, priv := newRpmLowServer(t)
	res, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "docker", BaseURL: up.URL + "/yumrepos/docker"})
	if err != nil {
		t.Fatalf("CollectRpm with .zst metadata: %v", err)
	}
	if res.ExportedModules != 1 { // newest-only rewrote & recompressed the .zst primary
		t.Fatalf("newest-only bundled %d packages, want 1", res.ExportedModules)
	}

	// Import and confirm the high side serves the newest .rpm, the old build is
	// gone, and the rewritten .zst indexes decompress back to the survivor.
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
		t.Fatalf("import of .zst rpm bundle failed (rewritten .zst checksums must match manifest): %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	base := srv.URL + "/rpm/docker"
	assertServed(t, base+"/Packages/code-1.101.2-1.x86_64.rpm", "FAKE-RPM-code-1.101.2-1")
	if code, _ := httpGet(t, base+"/Packages/code-1.100.0-1.x86_64.rpm"); code == http.StatusOK {
		t.Error("old version should not be mirrored under newest-only")
	}
	keptSHA := aptSHA256([]byte("FAKE-RPM-code-1.101.2-1"))
	droppedSHA := aptSHA256([]byte("FAKE-RPM-code-1.100.0-1"))
	for _, typ := range []string{"primary", "filelists", "other"} {
		_, zst := httpGet(t, base+"/repodata/"+typ+".xml.zst")
		plain, err := zstdDecompress([]byte(zst), maxIndexPlainBytes)
		if err != nil {
			t.Fatalf("zstd decompress served %s: %v", typ, err)
		}
		if !strings.Contains(string(plain), keptSHA) {
			t.Errorf("served %s is missing the kept build's pkgid:\n%s", typ, plain)
		}
		if strings.Contains(string(plain), droppedSHA) {
			t.Errorf("served %s still lists the dropped build's pkgid", typ)
		}
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
	// The [section] header is structural only; the name derives from baseurl.
	if len(cfgs) != 1 || cfgs[0].Name != "" || cfgs[0].BaseURL != "https://packages.microsoft.com/yumrepos/vscode" {
		t.Fatalf("parseRepoFile = %+v", cfgs)
	}
	if cfgs[0].GPGKey != "" {
		t.Errorf("remote gpgkey should not become a keyring path, got %q", cfgs[0].GPGKey)
	}
	multi := "[a]\nbaseurl=https://a.example/repo\n\n[b]\nbaseurl=https://b.example/repo\n"
	got, err := parseRepoFile(multi)
	if err != nil || len(got) != 2 || got[0].Name != "" || got[1].BaseURL != "https://b.example/repo" {
		t.Fatalf("multi-section parse = %+v, err %v", got, err)
	}
}

// TestResolveRpmMirrorsNames pins the APT-style naming: repo_file mirrors are
// always named by their baseurl slug (generic [baseos] sections from different
// distros never collide), and two sections with the same baseurl are rejected.
func TestResolveRpmMirrorsNames(t *testing.T) {
	rocky9 := "[baseos]\nname=Rocky Linux 9 - BaseOS\nbaseurl=http://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/\n\n" +
		"[baseos-10]\nname=Rocky Linux 10 - BaseOS\nbaseurl=http://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/\n"
	cfgs, err := resolveRpmMirrors(RpmCollectRequest{RepoFile: rocky9})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 ||
		cfgs[0].Name != "dl-rockylinux-org-pub-rocky-9-BaseOS-x86-64-os" ||
		cfgs[1].Name != "dl-rockylinux-org-pub-rocky-10-BaseOS-x86-64-os" {
		t.Fatalf("derived names = %q, %q", cfgs[0].Name, cfgs[1].Name)
	}
	// Same baseurl twice derives the same name and is rejected.
	dup := "[a]\nbaseurl=https://x.example/repo\n\n[b]\nbaseurl=https://x.example/repo\n"
	if _, err := resolveRpmMirrors(RpmCollectRequest{RepoFile: dup}); err == nil ||
		!strings.Contains(err.Error(), "duplicate mirror name") {
		t.Fatalf("duplicate baseurl = %v, want duplicate mirror name error", err)
	}
	// The explicit fields form still allows a hand-picked name.
	named, err := resolveRpmMirrors(RpmCollectRequest{Name: "rocky9-baseos", BaseURL: "https://x.example/repo"})
	if err != nil || len(named) != 1 || named[0].Name != "rocky9-baseos" {
		t.Fatalf("explicit name = %+v, err %v", named, err)
	}
}

// TestBuiltinRpmReposCollectable pins every built-in .repo shipped for the
// dashboard picker to content the collector actually accepts: each file must
// resolve to at least one mirror, and its remote gpgkey URL must not resolve
// to a local keyring path — one the low host does not have would fail every
// collect.
func TestBuiltinRpmReposCollectable(t *testing.T) {
	src, err := buildin.Sources()
	if err != nil {
		t.Fatal(err)
	}
	if len(src["rpm"]) == 0 {
		t.Fatal("no built-in rpm repo definitions shipped")
	}
	for _, e := range src["rpm"] {
		cfgs, err := resolveRpmMirrors(RpmCollectRequest{RepoFile: e.Content})
		if err != nil {
			t.Errorf("built-in %s does not resolve: %v", e.File, err)
			continue
		}
		for _, c := range cfgs {
			if c.GPGKey != "" {
				t.Errorf("built-in %s resolves gpgkey to local path %q; built-ins must not assume a keyring on the low host", e.File, c.GPGKey)
			}
		}
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
	plain, err := gunzip([]byte(body), maxIndexPlainBytes)
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
	// Mirror names derive from each baseurl, not from the [section] headers.
	nCode := aptMirrorName(up.URL + "/repos/code")
	nTools := aptMirrorName(up.URL + "/repos/tools")
	if nCode == nTools {
		t.Fatal("distinct baseurls must derive distinct mirror names")
	}
	assertServed(t, srv.URL+"/rpm/"+nCode+"/Packages/code-1.0-1.x86_64.rpm", "FAKE-RPM-code")
	assertServed(t, srv.URL+"/rpm/"+nTools+"/Packages/tool-2.0-1.x86_64.rpm", "FAKE-RPM-tool")

	_, body := httpGet(t, srv.URL+"/rpm/"+nCode+"/repodata/primary.xml.gz")
	plain, err := gunzip([]byte(body), maxIndexPlainBytes)
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

// TestRunXZOutputCap proves the xz pipe kills a decompression bomb at the
// output cap instead of buffering it, while normal payloads round-trip.
func TestRunXZOutputCap(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz not installed")
	}
	comp, err := xzCompress(make([]byte, 1<<20)) // 1 MiB of zeros compresses tiny
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runXZ(comp, 64<<10, "--decompress", "--stdout"); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("runXZ(bomb) = %v, want cap error", err)
	}
	if out, err := runXZ(comp, 2<<20, "--decompress", "--stdout"); err != nil || len(out) != 1<<20 {
		t.Fatalf("runXZ roundtrip = %d bytes, %v", len(out), err)
	}
}

// TestWriteRepomdDataEscapesHostileFields is a regression test: repomd <data>
// fields are copied verbatim from the upstream repomd.xml (which the low side
// may fetch without verifying a signature, e.g. a remote gpgkey= URL), so a
// hostile value must not inject markup into the repomd.xml the high side
// re-signs and serves.
func TestWriteRepomdDataEscapesHostileFields(t *testing.T) {
	var b strings.Builder
	b.WriteString("<repomd>\n")
	writeRepomdData(&b, RpmData{
		Type:      `primary"></data><data type="evil`,
		Href:      `repodata/primary.xml.gz"/><injected x="`,
		Checksum:  `<script>&`,
		Timestamp: `1<2&3`,
	})
	b.WriteString("</repomd>\n")
	out := b.String()

	// Must be well-formed XML with exactly one <data> element: the injection
	// must neither break parsing nor forge a second element.
	var doc struct {
		Data []struct {
			Type string `xml:"type,attr"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("regenerated repomd is not well-formed XML: %v\n%s", err, out)
	}
	if len(doc.Data) != 1 {
		t.Fatalf("repomd has %d <data> elements, want 1 (XML injection):\n%s", len(doc.Data), out)
	}
	if doc.Data[0].Type != `primary"></data><data type="evil` {
		t.Errorf("type attribute did not round-trip: %q", doc.Data[0].Type)
	}
	// None of the raw payloads may appear unescaped in the document.
	for _, raw := range []string{"</data><data", "<injected", "<script>"} {
		if strings.Contains(out, raw) {
			t.Errorf("unescaped %q present in regenerated repomd:\n%s", raw, out)
		}
	}
}
