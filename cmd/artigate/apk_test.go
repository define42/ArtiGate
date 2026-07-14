package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // sha1 is the checksum apk's index format mandates
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixture builders (all helpers here are apkTest*/fakeApkMirror-prefixed).
// -----------------------------------------------------------------------------

// apkTestPkg is one fixture package: the assembled .apk file plus the
// compressed control segment its index C: checksum covers.
type apkTestPkg struct {
	name    string
	version string
	apk     []byte
	control []byte
}

// apkTestBuildPkg assembles a structurally faithful .apk: a cut control
// segment holding .PKGINFO, then a data segment — two concatenated gzip
// streams — optionally preceded by a cut .SIGN.RSA signature segment.
func apkTestBuildPkg(t *testing.T, name, version string, signed bool) apkTestPkg {
	t.Helper()
	control, err := apkTarGzSegment([]apkTarFile{
		{name: ".PKGINFO", data: []byte("pkgname = " + name + "\npkgver = " + version + "\n")},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := apkTarGzSegment([]apkTarFile{
		{name: "usr/bin/" + name, data: []byte("BIN-" + name + "-" + version)},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	var apk []byte
	if signed {
		sig, err := apkTarGzSegment([]apkTarFile{
			{name: ".SIGN.RSA.test", data: []byte("upstream-signature-blob-" + name)},
		}, true)
		if err != nil {
			t.Fatal(err)
		}
		apk = append(apk, sig...)
	}
	apk = append(apk, control...)
	apk = append(apk, data...)
	return apkTestPkg{name: name, version: version, apk: apk, control: control}
}

// apkTestQ1 renders an index C: pull checksum: "Q1" + base64(SHA-1 of b).
func apkTestQ1(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // apk's index format mandates SHA-1
	return "Q1" + base64.StdEncoding.EncodeToString(sum[:])
}

func (p apkTestPkg) checksum() string { return apkTestQ1(p.control) }

func (p apkTestPkg) filename() string { return p.name + "-" + p.version + ".apk" }

// stanza renders the package's APKINDEX entry with the correct checksum and
// size; stanzaWith substitutes lies for the negative tests.
func (p apkTestPkg) stanza() string {
	return p.stanzaWith(p.checksum(), int64(len(p.apk)))
}

func (p apkTestPkg) stanzaWith(checksum string, size int64) string {
	return fmt.Sprintf("C:%s\nP:%s\nV:%s\nA:x86_64\nS:%d\nT:test package %s",
		checksum, p.name, p.version, size, p.name)
}

// apkTestIndexArchive renders an upstream-style APKINDEX.tar.gz holding the
// given stanzas.
func apkTestIndexArchive(t *testing.T, stanzas ...string) []byte {
	t.Helper()
	var idx strings.Builder
	for _, st := range stanzas {
		idx.WriteString(st)
		idx.WriteString("\n\n")
	}
	arch, err := apkTarGzSegment([]apkTarFile{
		{name: "APKINDEX", data: []byte(idx.String())},
		{name: "DESCRIPTION", data: []byte("test")},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	return arch
}

// fakeApkMirror is a mutable fake Alpine mirror; tests update its files to
// simulate upstream index changes between collects.
type fakeApkMirror struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
}

func newFakeApkMirror(t *testing.T) *fakeApkMirror {
	t.Helper()
	m := &fakeApkMirror{files: map[string][]byte{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		b, ok := m.files[r.URL.Path]
		m.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *fakeApkMirror) set(path string, b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = b
}

// apkTestRepoPath is the branch/repo/arch tree every fixture serves.
const apkTestRepoPath = "/v3.22/main/x86_64/"

// apkTestFixture wires a fake mirror serving foo 1.0-r0, foo 0.9-r0, and a
// signed-variant bar 2.0-r0 under v3.22/main/x86_64, plus a low server ready
// to collect it.
type apkTestFixture struct {
	mirror *fakeApkMirror
	ls     *LowServer
	priv   ed25519.PrivateKey
	foo10  apkTestPkg
	foo09  apkTestPkg
	bar    apkTestPkg
}

func newApkTestFixture(t *testing.T) *apkTestFixture {
	t.Helper()
	fx := &apkTestFixture{
		mirror: newFakeApkMirror(t),
		foo10:  apkTestBuildPkg(t, "foo", "1.0-r0", false),
		foo09:  apkTestBuildPkg(t, "foo", "0.9-r0", false),
		bar:    apkTestBuildPkg(t, "bar", "2.0-r0", true),
	}
	fx.ls, fx.priv = newAptLowServer(t)
	fx.setPkg(fx.foo10)
	fx.setPkg(fx.foo09)
	fx.setPkg(fx.bar)
	fx.setIndex(t, fx.foo10.stanza(), fx.foo09.stanza(), fx.bar.stanza())
	return fx
}

func (fx *apkTestFixture) setPkg(p apkTestPkg) {
	fx.mirror.set(apkTestRepoPath+p.filename(), p.apk)
}

func (fx *apkTestFixture) setIndex(t *testing.T, stanzas ...string) {
	t.Helper()
	fx.mirror.set(apkTestRepoPath+"APKINDEX.tar.gz", apkTestIndexArchive(t, stanzas...))
}

// collect runs CollectApk against the fixture mirror, defaulting the URI and
// branch selection to the fixture tree.
func (fx *apkTestFixture) collect(t *testing.T, req ApkCollectRequest) ExportResult {
	t.Helper()
	if req.URI == "" {
		req.URI = fx.mirror.srv.URL
	}
	if len(req.Branches) == 0 {
		req.Branches = []string{"v3.22"}
	}
	res, err := fx.ls.CollectApk(context.Background(), req)
	if err != nil {
		t.Fatalf("CollectApk: %v", err)
	}
	return res
}

// apkTestManifest decodes the signed bundle manifest a collect wrote into the
// low export dir.
func apkTestManifest(t *testing.T, ls *LowServer, bundleID string) BundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// apkTestMirrorName extracts the collected mirror's name (derived from the
// fake upstream's URL) from the exported manifest.
func apkTestMirrorName(t *testing.T, ls *LowServer, bundleID string) string {
	t.Helper()
	m := apkTestManifest(t, ls, bundleID)
	if m.Apk == nil || len(m.Apk.Mirrors) != 1 {
		t.Fatalf("bundle manifest carries no apk mirror: %+v", m.Apk)
	}
	return m.Apk.Mirrors[0].Name
}

// apkTestImport transfers one exported bundle into the high server's landing
// dir and imports it.
func apkTestImport(t *testing.T, ls *LowServer, hs *HighServer, bundleID string) {
	t.Helper()
	transferAptBundle(t, ls, hs, bundleID)
	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("high import of %s failed: %v", bundleID, err)
	}
	if !res.Imported {
		t.Fatalf("bundle %s was not imported: %+v", bundleID, res)
	}
}

// apkTestFetchIndex downloads a regenerated APKINDEX.tar.gz and returns its
// parsed stanzas.
func apkTestFetchIndex(t *testing.T, url string) []apkStanza {
	t.Helper()
	code, body := httpGet(t, url)
	if code != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, code)
	}
	text, err := apkIndexFromArchive([]byte(body), 1<<20)
	if err != nil {
		t.Fatalf("regenerated index unreadable: %v", err)
	}
	return parseApkIndex(text)
}

// apkTestRSAKeyFile writes a fresh PKCS#1 PEM RSA index signing key to disk.
func apkTestRSAKeyFile(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "apk-index.rsa")
	writeFile(t, p, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return p, key
}

// apkTestSplitLeadingSegment reads an archive's first gzip stream, returning
// its first tar member's name and content plus the remaining raw bytes (the
// start of the next gzip stream, i.e. the signed segment of a signed index).
func apkTestSplitLeadingSegment(t *testing.T, archive []byte) (member string, content, remainder []byte) {
	t.Helper()
	cbr := &countingByteReader{r: bufio.NewReader(bytes.NewReader(archive))}
	gz, err := gzip.NewReader(cbr)
	if err != nil {
		t.Fatal(err)
	}
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	content, err = io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return hdr.Name, content, archive[cbr.n:]
}

// -----------------------------------------------------------------------------
// Version comparison
// -----------------------------------------------------------------------------

func TestApkVersionCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-r0", "1.0-r0", 0},
		{"1.2.3_beta2", "1.2.3_beta2", 0},
		{"1.0", "1.0.1", -1},
		{"1.0", "1.0.0", -1}, // more components wins when the prefix ties
		{"1.0-r0", "1.0-r1", -1},
		{"1.0", "1.0-r1", -1},
		{"2.9-r5", "2.14-r0", -1}, // numeric, not lexical
		{"1.0.2", "1.0.10", -1},
		{"3.2", "3.19", -1},
		{"1.05", "1.5", -1},  // leading zero compares as a fraction
		{"1.5", "1.50", -1},  // no leading zero stays numeric
		{"1.05", "1.050", 0}, // fractional trailing zeros are equal
		{"1.2", "1.2a", -1},  // trailing letter beats end-of-string
		{"1.2a", "1.2b", -1},
		{"apple", "banana", -1},          // unparsable falls back to lexical
		{"1.0_weird1", "1.0_weird2", -1}, // unknown suffix falls back too
		{"1.0", "1.0_weird1", -1},        // either side unparsable means lexical
	}
	for _, tt := range tests {
		if got := apkVersionCompare(tt.a, tt.b); got != tt.want {
			t.Errorf("apkVersionCompare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := apkVersionCompare(tt.b, tt.a); got != -tt.want { // antisymmetry
			t.Errorf("apkVersionCompare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
	// The full suffix ladder: alpha < beta < pre < rc < release < cvs < svn <
	// git < hg < p.
	ladder := []string{
		"1.2_alpha1", "1.2_beta1", "1.2_pre1", "1.2_rc1", "1.2",
		"1.2_cvs1", "1.2_svn1", "1.2_git1", "1.2_hg1", "1.2_p1",
	}
	for i := 0; i+1 < len(ladder); i++ {
		if got := apkVersionCompare(ladder[i], ladder[i+1]); got >= 0 {
			t.Errorf("apkVersionCompare(%q, %q) = %d, want < 0", ladder[i], ladder[i+1], got)
		}
	}
}

func TestApkParseVersion(t *testing.T) {
	v := parseApkVersion("1.2.3b_beta2_p1-r5")
	if !v.ok || strings.Join(v.nums, ".") != "1.2.3" || v.letter != 'b' || v.rel != 5 {
		t.Fatalf("parseApkVersion = %+v", v)
	}
	if len(v.suffixes) != 2 ||
		v.suffixes[0] != (apkVersionSuffix{rank: -4, num: 2}) ||
		v.suffixes[1] != (apkVersionSuffix{rank: 5, num: 1}) {
		t.Fatalf("suffixes = %+v", v.suffixes)
	}
	for _, bad := range []string{"", "abc", "1.0_bogus1", "-r1", "1.0-r", "1.0.x"} {
		if parseApkVersion(bad).ok {
			t.Errorf("parseApkVersion(%q).ok = true, want false", bad)
		}
	}
}

// -----------------------------------------------------------------------------
// Index parsing and validation
// -----------------------------------------------------------------------------

func TestApkParseIndex(t *testing.T) {
	foo := "C:Q1abcdef\nP:foo\nV:1.0-r0\nA:x86_64\nS:123\nT:the foo tool\nU:https://foo.example"
	bar := "C:Q1ghijkl\nP:bar\nV:2.0-r1\nA:aarch64\nS:456\nT:bar"
	noName := "V:9.9\nS:1"                // dropped: carries no P
	badSize := "P:qux\nV:1\nS:notanumber" // kept, unparsable S ignored
	index := strings.Join([]string{foo, bar, noName, badSize}, "\n\n") + "\n\n"

	got := parseApkIndex(index)
	if len(got) != 3 {
		t.Fatalf("parseApkIndex returned %d stanzas, want 3: %+v", len(got), got)
	}
	if got[0].Text != foo || got[1].Text != bar { // verbatim text survives
		t.Errorf("stanza text not verbatim:\n%q\n%q", got[0].Text, got[1].Text)
	}
	if got[0].Name != "foo" || got[0].Version != "1.0-r0" || got[0].Arch != "x86_64" ||
		got[0].Checksum != "Q1abcdef" || got[0].Size != 123 {
		t.Errorf("foo stanza = %+v", got[0])
	}
	if got[1].Name != "bar" || got[1].Version != "2.0-r1" || got[1].Arch != "aarch64" ||
		got[1].Checksum != "Q1ghijkl" || got[1].Size != 456 {
		t.Errorf("bar stanza = %+v", got[1])
	}
	if got[2].Name != "qux" || got[2].Size != 0 {
		t.Errorf("qux stanza = %+v", got[2])
	}
	if n := len(parseApkIndex("")); n != 0 {
		t.Errorf("empty index parsed to %d stanzas", n)
	}

	// apkStanzaField pulls single fields for the dashboard detail panel.
	if v := apkStanzaField(foo, "T"); v != "the foo tool" {
		t.Errorf("apkStanzaField(T) = %q", v)
	}
	if v := apkStanzaField(foo, "Z"); v != "" {
		t.Errorf("apkStanzaField(Z) = %q, want empty", v)
	}
}

func TestApkValidateStanza(t *testing.T) {
	valid := []string{
		"P:foo\nV:1.0-r0",
		"C:Q1x\nP:a\nV:1\nT:desc with spaces",
		"P:a\nV:1\n\n\n", // trailing newlines are tolerated
	}
	for _, st := range valid {
		if err := validateApkStanza(st); err != nil {
			t.Errorf("validateApkStanza(%q) = %v, want nil", st, err)
		}
	}
	invalid := []string{
		"",
		"\n\n",
		"P:a\n\nP:evil", // embedded blank line would forge an extra index entry
		"P:a\nnot a field line",
		"P:a\n:x", // missing field letter
		"1:x",     // digit field key
		"P",       // too short
	}
	for _, st := range invalid {
		if err := validateApkStanza(st); err == nil {
			t.Errorf("validateApkStanza(%q) = nil, want error", st)
		}
	}
}

func TestApkFilterNewest(t *testing.T) {
	stanzas := []apkStanza{
		{Name: "foo", Version: "1.0-r0"},
		{Name: "bar", Version: "2.0-r0"},
		{Name: "foo", Version: "1.0-r1"},
		{Name: "foo", Version: "0.9-r5"},
	}
	got := filterNewestApk(stanzas)
	if len(got) != 2 {
		t.Fatalf("kept %d stanzas, want 2: %+v", len(got), got)
	}
	// First-seen order is preserved; each name keeps its highest version.
	if got[0].Name != "foo" || got[0].Version != "1.0-r1" {
		t.Errorf("foo kept %+v", got[0])
	}
	if got[1].Name != "bar" || got[1].Version != "2.0-r0" {
		t.Errorf("bar kept %+v", got[1])
	}
}

func TestApkIndexFromArchive(t *testing.T) {
	arch := apkTestIndexArchive(t, "C:Q1x\nP:foo\nV:1.0-r0")
	text, err := apkIndexFromArchive(arch, 1<<20)
	if err != nil || !strings.Contains(text, "P:foo") {
		t.Fatalf("apkIndexFromArchive = %q, %v", text, err)
	}
	if _, err := apkIndexFromArchive(arch, 4); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("oversized index = %v, want cap error", err)
	}
	noIndex, err := apkTarGzSegment([]apkTarFile{{name: "DESCRIPTION", data: []byte("x")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apkIndexFromArchive(noIndex, 1<<20); err == nil || !strings.Contains(err.Error(), "no APKINDEX member") {
		t.Errorf("missing member = %v, want no-APKINDEX error", err)
	}
	if _, err := apkIndexFromArchive([]byte("not gzip"), 1<<20); err == nil {
		t.Error("non-gzip archive accepted")
	}
}

func TestApkNameAndVersionValidation(t *testing.T) {
	validNames := []string{"foo", "libstdc++", "openssl3.5", "py3-pip", "A1", "gcc_bootstrap"}
	invalidNames := []string{"", "..", ".hidden", "-flag", "+x", "_p", "a b", "a/b"}
	for _, n := range validNames {
		if err := validateApkName(n); err != nil {
			t.Errorf("validateApkName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateApkName(n); err == nil {
			t.Errorf("validateApkName(%q) = nil, want error", n)
		}
	}
	validVersions := []string{"1.0-r0", "1.2.3_alpha1", "20240101", "1.0e", "3.5+dfsg"}
	invalidVersions := []string{"", "x1", "-r1", "1.0/..", "1 0", "..1"}
	for _, v := range validVersions {
		if err := validateApkVersion(v); err != nil {
			t.Errorf("validateApkVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVersions {
		if err := validateApkVersion(v); err == nil {
			t.Errorf("validateApkVersion(%q) = nil, want error", v)
		}
	}
}

// apkTestValidMirror is a baseline mirror record that passes import
// validation; the negative cases each break one property.
func apkTestValidMirror() (ApkMirror, map[string]bool) {
	pkg := ApkPackage{
		Name: "foo", Version: "1.0-r0", Arch: "x86_64", Branch: "v3.22", Repository: "main",
		Filename: "foo-1.0-r0.apk", SHA256: strings.Repeat("a", 64), Size: 10,
		Stanza: "C:Q1abc\nP:foo\nV:1.0-r0\nA:x86_64\nS:10\nT:foo",
	}
	m := ApkMirror{
		Name: "alpine", URI: "https://mirror.example/alpine",
		Branches: []ApkBranch{{Name: "v3.22", Repositories: []string{"main"}, Architectures: []string{"x86_64"}}},
		Packages: []ApkPackage{pkg},
	}
	seen := map[string]bool{"apk/alpine/v3.22/main/x86_64/foo-1.0-r0.apk": true}
	return m, seen
}

func TestApkValidateMirrors(t *testing.T) {
	m, seen := apkTestValidMirror()
	if err := validateApkMirrors([]ApkMirror{m}, seen); err != nil {
		t.Fatalf("valid mirror rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ApkMirror)
		want   string
	}{
		{"branch outside mirror set", func(m *ApkMirror) { m.Packages[0].Branch = "v9.99" }, "outside the mirror's set"},
		{"arch outside mirror set", func(m *ApkMirror) { m.Packages[0].Arch = "riscv64" }, "outside the mirror's set"},
		{"stanza P mismatch", func(m *ApkMirror) { m.Packages[0].Stanza = "P:evil\nV:1.0-r0" }, "stanza names"},
		{"stanza V mismatch", func(m *ApkMirror) { m.Packages[0].Stanza = "P:foo\nV:9.9-r9" }, "stanza names"},
		{"non-canonical filename", func(m *ApkMirror) { m.Packages[0].Filename = "foo.apk" }, "non-canonical filename"},
		{"stanza with blank line", func(m *ApkMirror) { m.Packages[0].Stanza = "P:foo\nV:1.0-r0\n\nP:evil\nV:1" }, "malformed stanza"},
		{"bad package name", func(m *ApkMirror) { m.Packages[0].Name = "-flag" }, "invalid apk package name"},
		{"bad version", func(m *ApkMirror) { m.Packages[0].Version = "x.1" }, "invalid apk version"},
		{"missing uri", func(m *ApkMirror) { m.URI = "" }, "missing uri or branches"},
		{"no branches", func(m *ApkMirror) { m.Branches = nil }, "missing uri or branches"},
		{"invalid branch token", func(m *ApkMirror) { m.Branches[0].Name = ".." }, "invalid branch selection"},
		{"invalid arch token", func(m *ApkMirror) { m.Branches[0].Architectures = []string{"x86_64/.."} }, "invalid repository/architecture"},
		{"bad mirror name", func(m *ApkMirror) { m.Name = "../up" }, "invalid mirror name"},
	}
	for _, tt := range tests {
		m, seen := apkTestValidMirror()
		tt.mutate(&m)
		err := validateApkMirrors([]ApkMirror{m}, seen)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}

	// A package whose .apk is not in the manifest's file set is refused.
	m, _ = apkTestValidMirror()
	err := validateApkMirrors([]ApkMirror{m}, map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "not listed in manifest.files") {
		t.Errorf("unlisted file: err = %v", err)
	}
}

// -----------------------------------------------------------------------------
// Control checksum verification
// -----------------------------------------------------------------------------

func TestApkVerifyControlChecksum(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		writeFile(t, p, b)
		return p
	}
	unsigned := apkTestBuildPkg(t, "foo", "1.0-r0", false)
	signed := apkTestBuildPkg(t, "bar", "2.0-r0", true)
	unsignedPath := write("foo.apk", unsigned.apk)
	signedPath := write("bar.apk", signed.apk)

	// The correct control checksum verifies for both layouts.
	if err := apkVerifyControlChecksum(unsignedPath, unsigned.checksum()); err != nil {
		t.Errorf("unsigned .apk with correct C: rejected: %v", err)
	}
	if err := apkVerifyControlChecksum(signedPath, signed.checksum()); err != nil {
		t.Errorf("signed .apk with correct C: rejected: %v", err)
	}

	// A checksum over anything but the control segment fails: other content,
	// or the whole file (proving the check is control-segment-scoped).
	if err := apkVerifyControlChecksum(unsignedPath, apkTestQ1([]byte("other bytes"))); err == nil ||
		!strings.Contains(err.Error(), "mismatch") {
		t.Errorf("wrong checksum = %v, want mismatch", err)
	}
	if err := apkVerifyControlChecksum(signedPath, apkTestQ1(signed.apk)); err == nil ||
		!strings.Contains(err.Error(), "mismatch") {
		t.Errorf("whole-file checksum = %v, want mismatch", err)
	}

	// Tampered file content fails the original checksum.
	tampered := append([]byte(nil), unsigned.apk...)
	tampered[10] ^= 0xff
	if err := apkVerifyControlChecksum(write("tampered.apk", tampered), unsigned.checksum()); err == nil {
		t.Error("tampered control segment accepted")
	}

	// Only Q1 (SHA-1) pull checksums are supported; garbage base64 is refused.
	if err := apkVerifyControlChecksum(unsignedPath, "Q2deadbeef"); err == nil ||
		!strings.Contains(err.Error(), "unsupported checksum") {
		t.Errorf("Q2 checksum = %v, want unsupported", err)
	}
	if err := apkVerifyControlChecksum(unsignedPath, "Q1!!!not-base64!!!"); err == nil ||
		!strings.Contains(err.Error(), "invalid checksum") {
		t.Errorf("bad base64 = %v, want invalid checksum", err)
	}

	// A file whose leading member is neither .PKGINFO nor .SIGN.* is not an apk.
	junk, err := apkTarGzSegment([]apkTarFile{{name: "readme.txt", data: []byte("hi")}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := apkVerifyControlChecksum(write("junk.apk", junk), unsigned.checksum()); err == nil ||
		!strings.Contains(err.Error(), "unexpected leading segment") {
		t.Errorf("non-apk = %v, want unexpected leading segment", err)
	}

	// Two signature segments and no control segment anywhere.
	sig1, err := apkTarGzSegment([]apkTarFile{{name: ".SIGN.RSA.a", data: []byte("s1")}}, true)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := apkTarGzSegment([]apkTarFile{{name: ".SIGN.RSA.b", data: []byte("s2")}}, true)
	if err != nil {
		t.Fatal(err)
	}
	noCtl := write("noctl.apk", append(append([]byte(nil), sig1...), sig2...))
	if err := apkVerifyControlChecksum(noCtl, unsigned.checksum()); err == nil ||
		!strings.Contains(err.Error(), "no control segment") {
		t.Errorf("apk without control segment = %v, want no-control-segment error", err)
	}

	// A missing file errors rather than passing.
	if err := apkVerifyControlChecksum(filepath.Join(dir, "absent.apk"), unsigned.checksum()); err == nil {
		t.Error("missing file accepted")
	}
}

// -----------------------------------------------------------------------------
// Repositories-file parsing and collect request resolution
// -----------------------------------------------------------------------------

func TestApkParseRepositoriesFile(t *testing.T) {
	text := "# main mirror\n" +
		"\n" +
		"https://mirror.example/alpine/v3.22/main\n" +
		"https://mirror.example/alpine/v3.22/community\n" +
		"@testing https://mirror.example/alpine/edge/testing\n" +
		"https://mirror.example/alpine/v3.22/main\n" // duplicate collapses
	uri, branchRepos, err := parseApkRepositoriesFile(text)
	if err != nil {
		t.Fatal(err)
	}
	if uri != "https://mirror.example/alpine" {
		t.Errorf("uri = %q", uri)
	}
	if len(branchRepos) != 2 ||
		strings.Join(branchRepos["v3.22"], " ") != "main community" ||
		strings.Join(branchRepos["edge"], " ") != "testing" {
		t.Errorf("branchRepos = %+v", branchRepos)
	}

	// Lines naming two different mirror bases are rejected.
	mixed := "https://a.example/alpine/v3.22/main\nhttps://b.example/alpine/v3.22/main\n"
	if _, _, err := parseApkRepositoriesFile(mixed); err == nil || !strings.Contains(err.Error(), "different mirrors") {
		t.Errorf("mixed mirrors = %v, want different-mirrors error", err)
	}
	// Comment-only input lists nothing.
	if _, _, err := parseApkRepositoriesFile("# nothing\n\n"); err == nil {
		t.Error("empty repositories file accepted")
	}
	// A non-http(s) line fails.
	if _, _, err := parseApkRepositoriesFile("ftp://mirror.example/alpine/v3.22/main"); err == nil {
		t.Error("non-http repository accepted")
	}
}

func TestApkSplitRepoURL(t *testing.T) {
	tests := []struct{ line, base, branch, repo string }{
		{"https://mirror.example/alpine/v3.20/main", "https://mirror.example/alpine", "v3.20", "main"},
		{"https://mirror.example/alpine/v3.20/main/", "https://mirror.example/alpine", "v3.20", "main"}, // trailing slash
		{"http://mirror.example/v3.20/community", "http://mirror.example", "v3.20", "community"},
		{"https://mirror.example/alpine/edge/testing?x=1#frag", "https://mirror.example/alpine", "edge", "testing"},
	}
	for _, tt := range tests {
		base, branch, repo, err := splitApkRepoURL(tt.line)
		if err != nil || base != tt.base || branch != tt.branch || repo != tt.repo {
			t.Errorf("splitApkRepoURL(%q) = (%q, %q, %q, %v), want (%q, %q, %q)",
				tt.line, base, branch, repo, err, tt.base, tt.branch, tt.repo)
		}
	}
	for _, bad := range []string{"https://mirror.example/main", "ftp://x/a/b", "not a url", ""} {
		if _, _, _, err := splitApkRepoURL(bad); err == nil {
			t.Errorf("splitApkRepoURL(%q) accepted", bad)
		}
	}
}

func TestApkResolveRequest(t *testing.T) {
	// Structured fields: repo/arch defaults fill in, tokens dedupe, URI trims.
	plan, err := resolveApkRequest(ApkCollectRequest{
		URI:      " https://mirror.example/alpine/ ",
		Branches: []string{"v3.22", "v3.22"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.uri != "https://mirror.example/alpine" || plan.name != "mirror-example-alpine" || !plan.newestOnly {
		t.Errorf("plan = %+v", plan)
	}
	if len(plan.branches) != 1 ||
		plan.branches[0].Name != "v3.22" ||
		strings.Join(plan.branches[0].Repositories, " ") != "main" ||
		strings.Join(plan.branches[0].Architectures, " ") != "x86_64" {
		t.Errorf("branches = %+v", plan.branches)
	}

	// A pasted repositories file drives the plan; branches come out sorted and
	// the explicit name and architectures apply.
	no := false
	plan, err = resolveApkRequest(ApkCollectRequest{
		Name:             "alp",
		Architectures:    []string{"aarch64"},
		NewestOnly:       &no,
		RepositoriesFile: "https://m.example/alpine/v3.22/main\n@t https://m.example/alpine/edge/testing\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.uri != "https://m.example/alpine" || plan.name != "alp" || plan.newestOnly {
		t.Errorf("file-driven plan = %+v", plan)
	}
	if len(plan.branches) != 2 ||
		plan.branches[0].Name != "edge" || plan.branches[1].Name != "v3.22" ||
		strings.Join(plan.branches[0].Architectures, " ") != "aarch64" {
		t.Errorf("file-driven branches = %+v", plan.branches)
	}

	bad := []ApkCollectRequest{
		{},                            // nothing provided
		{URI: "https://x"},            // no branches
		{Branches: []string{"v3.22"}}, // no uri
		{URI: "ftp://x", Branches: []string{"v3.22"}},
		{URI: "https://x", Branches: []string{"../evil"}},
		{URI: "https://x", Branches: []string{"v3.22"}, Repositories: []string{"a/b"}},
		{URI: "https://x", Branches: []string{"v3.22"}, Name: ".."},
	}
	for i, req := range bad {
		if _, err := resolveApkRequest(req); err == nil {
			t.Errorf("bad request %d accepted: %+v", i, req)
		}
	}
}

// -----------------------------------------------------------------------------
// High-side merge units
// -----------------------------------------------------------------------------

func TestApkMergeMirrors(t *testing.T) {
	prev := ApkMirror{
		Name:     "alpine",
		Branches: []ApkBranch{{Name: "v3.21", Repositories: []string{"main"}, Architectures: []string{"x86_64"}}},
		Packages: []ApkPackage{
			{Name: "foo", Version: "1.0-r0", Branch: "v3.21", Repository: "main", Arch: "x86_64", Filename: "foo-1.0-r0.apk", Stanza: "old"},
			{Name: "gone", Version: "1", Branch: "v3.21", Repository: "main", Arch: "x86_64", Filename: "gone-1.apk", Stanza: "keep"},
		},
	}
	next := ApkMirror{
		Name: "alpine",
		Branches: []ApkBranch{
			{Name: "v3.21", Repositories: []string{"community"}, Architectures: []string{"aarch64"}},
			{Name: "v3.22", Repositories: []string{"main"}, Architectures: []string{"x86_64"}},
		},
		Packages: []ApkPackage{
			{Name: "foo", Version: "1.0-r0", Branch: "v3.21", Repository: "main", Arch: "x86_64", Filename: "foo-1.0-r0.apk", Stanza: "new"},
		},
	}
	got := mergeApkMirrors(prev, next)

	// Branch selections union per branch name and come out name-sorted.
	if len(got.Branches) != 2 || got.Branches[0].Name != "v3.21" || got.Branches[1].Name != "v3.22" {
		t.Fatalf("merged branches = %+v", got.Branches)
	}
	if strings.Join(got.Branches[0].Repositories, " ") != "community main" ||
		strings.Join(got.Branches[0].Architectures, " ") != "aarch64 x86_64" {
		t.Errorf("v3.21 union = %+v", got.Branches[0])
	}

	// Same-key package: the newer bundle's record wins; prev-only packages stay.
	if len(got.Packages) != 2 {
		t.Fatalf("merged packages = %+v", got.Packages)
	}
	if got.Packages[0].Name != "foo" || got.Packages[0].Stanza != "new" {
		t.Errorf("foo record = %+v, want the newer stanza", got.Packages[0])
	}
	if got.Packages[1].Name != "gone" || got.Packages[1].Stanza != "keep" {
		t.Errorf("prev-only record = %+v", got.Packages[1])
	}
}

// -----------------------------------------------------------------------------
// RSA key loading
// -----------------------------------------------------------------------------

func TestApkLoadRSAKey(t *testing.T) {
	keyPath, key := apkTestRSAKeyFile(t)
	dir := t.TempDir()

	got, err := loadApkRSAKey(keyPath) // PKCS#1
	if err != nil || !got.Equal(key) {
		t.Errorf("PKCS#1 load = %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := filepath.Join(dir, "pkcs8.pem")
	writeFile(t, pkcs8, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	got, err = loadApkRSAKey(pkcs8)
	if err != nil || !got.Equal(key) {
		t.Errorf("PKCS#8 load = %v", err)
	}

	notPEM := filepath.Join(dir, "junk")
	writeFile(t, notPEM, []byte("not a pem"))
	if _, err := loadApkRSAKey(notPEM); err == nil {
		t.Error("non-PEM file accepted")
	}

	_, edPriv := newTestKeys(t)
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	edPath := filepath.Join(dir, "ed.pem")
	writeFile(t, edPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER}))
	if _, err := loadApkRSAKey(edPath); err == nil || !strings.Contains(err.Error(), "not an RSA private key") {
		t.Errorf("ed25519 key = %v, want not-RSA error", err)
	}

	if _, err := loadApkRSAKey(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing key file accepted")
	}
}

// -----------------------------------------------------------------------------
// Low-to-high integration
// -----------------------------------------------------------------------------

// TestApkLowToHighPipeline is the full round-trip: mirror a fake Alpine
// upstream (newest-only by default), transfer the signed bundle, import it,
// and confirm the high side regenerates the APKINDEX from the verbatim
// stanzas and serves the exact package bytes.
func TestApkLowToHighPipeline(t *testing.T) {
	fx := newApkTestFixture(t)
	res := fx.collect(t, ApkCollectRequest{
		Repositories:  []string{"main"},
		Architectures: []string{"x86_64"},
	})
	if res.BundleID != "apk-bundle-000001" || res.Sequence != 1 || res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	manifest := apkTestManifest(t, fx.ls, res.BundleID)
	if manifest.Stream != streamApk || manifest.Apk == nil || len(manifest.Apk.Mirrors) != 1 {
		t.Fatalf("manifest = stream %q apk %+v", manifest.Stream, manifest.Apk)
	}
	mirror := manifest.Apk.Mirrors[0]
	if mirror.URI != fx.mirror.srv.URL || len(mirror.Packages) != 2 {
		t.Fatalf("mirror = %+v", mirror)
	}
	// Newest-only kept foo 1.0-r0 (not 0.9-r0) plus bar.
	versions := map[string]string{}
	for _, p := range mirror.Packages {
		versions[p.Name] = p.Version
	}
	if versions["foo"] != "1.0-r0" || versions["bar"] != "2.0-r0" {
		t.Fatalf("collected versions = %v", versions)
	}
	for _, f := range manifest.Files {
		if !strings.HasPrefix(f.Path, "apk/"+mirror.Name+"/v3.22/main/x86_64/") {
			t.Errorf("manifest file outside the mirror tree: %s", f.Path)
		}
	}

	pub := fx.priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	apkTestImport(t, fx.ls, hs, res.BundleID)

	srv := httptest.NewServer(hs)
	defer srv.Close()
	base := srv.URL + "/apk/" + mirror.Name + "/v3.22/main/x86_64"

	// The regenerated APKINDEX carries both stanzas verbatim.
	stanzas := apkTestFetchIndex(t, base+"/APKINDEX.tar.gz")
	texts := map[string]string{}
	for _, st := range stanzas {
		texts[st.Name] = st.Text
	}
	if len(stanzas) != 2 || texts["foo"] != fx.foo10.stanza() || texts["bar"] != fx.bar.stanza() {
		t.Errorf("regenerated stanzas = %+v", texts)
	}

	// The packages serve byte-for-byte.
	for _, p := range []apkTestPkg{fx.foo10, fx.bar} {
		code, body := httpGet(t, base+"/"+p.filename())
		if code != http.StatusOK || body != string(p.apk) {
			t.Errorf("GET %s: status %d, %d bytes (want %d)", p.filename(), code, len(body), len(p.apk))
		}
	}
	// The version newest-only filtered out was never collected.
	if code, _ := httpGet(t, base+"/foo-0.9-r0.apk"); code != http.StatusNotFound {
		t.Errorf("filtered version served with status %d, want 404", code)
	}

	// Dashboard wiring: tree root, package detail, and the "Set me up" list.
	if _, tree := httpGet(t, srv.URL+"/ui/api/tree?eco=apk&path="); !strings.Contains(tree, `"`+mirror.Name+`"`) {
		t.Errorf("apk tree root missing mirror: %s", tree)
	}
	detailURL := srv.URL + "/ui/api/detail?eco=apk&path=" + mirror.Name + "/v3.22/main/x86_64/foo@1.0-r0"
	if code, detail := httpGet(t, detailURL); code != http.StatusOK || !strings.Contains(detail, "test package foo") {
		t.Errorf("apk detail: status %d body %s", code, detail)
	}
	for _, bad := range []string{
		mirror.Name + "/v3.22/main/x86_64/foo@9.9-r9", // unknown version
		mirror.Name + "/v3.22/main/x86_64/foo",        // no version at all
		"ghost/v3.22/main/x86_64/foo@1.0-r0",          // unknown mirror
	} {
		if code, _ := httpGet(t, srv.URL+"/ui/api/detail?eco=apk&path="+bad); code == http.StatusOK {
			t.Errorf("apk detail for %q should not be found", bad)
		}
	}
	// A nil apk manifest section is a no-op on publish.
	if err := hs.publishApk(nil); err != nil {
		t.Errorf("publishApk(nil) = %v", err)
	}
	if _, repos := httpGet(t, srv.URL+"/ui/api/repos?eco=apk"); !strings.Contains(repos, `"`+mirror.Name+`"`) ||
		!strings.Contains(repos, `"v3.22"`) {
		t.Errorf("apk repo list = %s", repos)
	}
}

// TestApkCollectAllVersions turns newest-only off and mirrors every listed
// version.
func TestApkCollectAllVersions(t *testing.T) {
	fx := newApkTestFixture(t)
	no := false
	res := fx.collect(t, ApkCollectRequest{NewestOnly: &no})
	if res.ExportedModules != 3 || len(res.SkippedModules) != 0 {
		t.Fatalf("collect with newest-only off = %+v, want 3 packages", res)
	}
	m := apkTestManifest(t, fx.ls, res.BundleID)
	fooVersions := 0
	for _, p := range m.Apk.Mirrors[0].Packages {
		if p.Name == "foo" {
			fooVersions++
		}
	}
	if fooVersions != 2 {
		t.Errorf("foo versions bundled = %d, want 2", fooVersions)
	}
}

// TestApkCollectSizeMismatch proves an index stanza lying about the package
// size skips that package (reported, not fatal) while the rest still exports.
func TestApkCollectSizeMismatch(t *testing.T) {
	fx := newApkTestFixture(t)
	lie := fx.foo10.stanzaWith(fx.foo10.checksum(), int64(len(fx.foo10.apk))+1)
	fx.setIndex(t, lie, fx.bar.stanza())

	res := fx.collect(t, ApkCollectRequest{})
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 {
		t.Fatalf("collect = %+v, want 1 exported + 1 skipped", res)
	}
	sk := res.SkippedModules[0]
	if sk.Module != "foo" || sk.Version != "1.0-r0" || !strings.Contains(sk.Error, "size mismatch") {
		t.Errorf("skipped = %+v", sk)
	}
}

// TestApkCollectChecksumMismatch proves a wrong C: control checksum skips the
// package likewise.
func TestApkCollectChecksumMismatch(t *testing.T) {
	fx := newApkTestFixture(t)
	lie := fx.foo10.stanzaWith(apkTestQ1([]byte("not the control segment")), int64(len(fx.foo10.apk)))
	fx.setIndex(t, lie, fx.bar.stanza())

	res := fx.collect(t, ApkCollectRequest{})
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 {
		t.Fatalf("collect = %+v, want 1 exported + 1 skipped", res)
	}
	sk := res.SkippedModules[0]
	if sk.Module != "foo" || !strings.Contains(sk.Error, "checksum mismatch") {
		t.Errorf("skipped = %+v", sk)
	}
}

// TestApkCollectFailures covers the fatal collect errors: an unreachable
// index fails the collect outright, and a collect where every package fails
// verification produces no bundle and burns no sequence number.
func TestApkCollectFailures(t *testing.T) {
	fx := newApkTestFixture(t)

	// The selected branch has no APKINDEX upstream: a selection error the
	// operator must see, not a silent empty bundle.
	_, err := fx.ls.CollectApk(context.Background(), ApkCollectRequest{
		URI: fx.mirror.srv.URL, Branches: []string{"v9.99"},
	})
	if err == nil {
		t.Error("collect of a branch without an index should fail")
	}

	// Every listed package fails its size check: nothing to bundle.
	fx.setIndex(t,
		fx.foo10.stanzaWith(fx.foo10.checksum(), 1),
		fx.bar.stanzaWith(fx.bar.checksum(), 1),
	)
	_, err = fx.ls.CollectApk(context.Background(), ApkCollectRequest{
		URI: fx.mirror.srv.URL, Branches: []string{"v3.22"},
	})
	if err == nil || !strings.Contains(err.Error(), "no apk packages could be fetched") {
		t.Errorf("all-failed collect = %v, want no-packages error", err)
	}
	// The failed collects must not have burned a sequence number.
	if seq := fx.ls.peekSequence(streamApk); seq != 1 {
		t.Errorf("sequence advanced to %d after failed collects, want 1", seq)
	}
}

// TestApkSignedIndexRegeneration configures a high-side RSA index signing key
// and verifies the regenerated APKINDEX.tar.gz the way apk itself does: the
// leading gzip stream carries .SIGN.RSA.<keyname>, and its RSA PKCS#1 v1.5
// signature covers the SHA-1 of the remaining bytes (the index segment). The
// matching public key is served under /apk/keys/.
func TestApkSignedIndexRegeneration(t *testing.T) {
	fx := newApkTestFixture(t)
	res := fx.collect(t, ApkCollectRequest{})
	name := apkTestMirrorName(t, fx.ls, res.BundleID)

	keyPath, key := apkTestRSAKeyFile(t)
	pub := fx.priv.Public().(ed25519.PublicKey)
	cfg := HighConfig{
		Root: t.TempDir(), Landing: t.TempDir(), ImportInterval: 0,
		ApkRSAKey: keyPath, ApkKeyName: "test.rsa.pub",
	}
	hs, err := NewHighServer(cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	apkTestImport(t, fx.ls, hs, res.BundleID)

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/apk/"+name+"/v3.22/main/x86_64/APKINDEX.tar.gz")
	if code != http.StatusOK {
		t.Fatalf("signed index status %d", code)
	}
	archive := []byte(body)

	member, sig, signedSegment := apkTestSplitLeadingSegment(t, archive)
	if member != ".SIGN.RSA.test.rsa.pub" {
		t.Fatalf("leading member = %q, want .SIGN.RSA.test.rsa.pub", member)
	}
	if len(signedSegment) == 0 {
		t.Fatal("no index segment follows the signature stream")
	}
	digest := sha1.Sum(signedSegment) //nolint:gosec // apk's .SIGN.RSA format mandates SHA-1
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, digest[:], sig); err != nil {
		t.Errorf("index signature does not verify over the index segment: %v", err)
	}

	// The signed archive still parses as an index (the signature is a leading
	// concatenated gzip stream apk walks straight through).
	text, err := apkIndexFromArchive(archive, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseApkIndex(text); len(got) != 2 {
		t.Errorf("signed index stanzas = %d, want 2", len(got))
	}

	// The matching public key is served for /etc/apk/keys/<name>.
	code, keyBody := httpGet(t, srv.URL+"/apk/keys/test.rsa.pub")
	if code != http.StatusOK {
		t.Fatalf("public key status %d", code)
	}
	block, _ := pem.Decode([]byte(keyBody))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public key is not a PEM PUBLIC KEY: %q", keyBody)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok || !rsaPub.Equal(&key.PublicKey) {
		t.Error("served public key does not match the signing key")
	}

	// The "Set me up" guide reports the repository as signed.
	if _, repos := httpGet(t, srv.URL+"/ui/api/repos?eco=apk"); !strings.Contains(repos, `"signed": true`) {
		t.Errorf("apk repo list not marked signed: %s", repos)
	}
}

// TestApkRouteHardening locks down the /apk/ URL space: traversal, off-shape
// paths, and writes are all refused while the legitimate route keeps working.
func TestApkRouteHardening(t *testing.T) {
	fx := newApkTestFixture(t)
	res := fx.collect(t, ApkCollectRequest{})
	name := apkTestMirrorName(t, fx.ls, res.BundleID)
	pub := fx.priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	apkTestImport(t, fx.ls, hs, res.BundleID)

	srv := httptest.NewServer(hs)
	defer srv.Close()

	for _, p := range []string{
		"/apk/" + name + "/../x",
		"/apk/" + name + "/..%2f..%2fimport-state.json",
		"/apk/../import-state.json",
		"/apk/" + name + "/v3.22/main/x86_64/other.txt", // not an index or .apk
		"/apk/" + name + "/v3.22/main/x86_64",           // wrong depth
		"/apk/" + name + "/v3.22/main/x86_64/absent-1.0-r0.apk",
		"/apk/keys/test.rsa.pub", // no signing key configured
		"/apk",
	} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", p, code)
		}
	}

	// Writes are refused with 405.
	target := srv.URL + "/apk/" + name + "/v3.22/main/x86_64/APKINDEX.tar.gz"
	resp, err := http.Post(target, "text/plain", strings.NewReader("x")) //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status %d, want 405", resp.StatusCode)
	}

	// The legitimate index still serves after all that.
	assertServed(t, target, "")
}

// TestApkSecondBundleAccumulates imports a delta bundle (upstream gained one
// package) and confirms the persistent merge: the regenerated index covers
// old and new packages, and prior content keeps serving.
func TestApkSecondBundleAccumulates(t *testing.T) {
	fx := newApkTestFixture(t)
	pub := fx.priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)

	first := fx.collect(t, ApkCollectRequest{})
	apkTestImport(t, fx.ls, hs, first.BundleID)

	// Upstream gains baz; foo and bar are unchanged, so the second bundle is a
	// delta carrying only baz's bytes (foo and bar ride along as prior files).
	baz := apkTestBuildPkg(t, "baz", "3.0-r0", false)
	fx.setPkg(baz)
	fx.setIndex(t, fx.foo10.stanza(), fx.bar.stanza(), baz.stanza())

	second := fx.collect(t, ApkCollectRequest{})
	if second.BundleID != "apk-bundle-000002" || second.ExportedModules != 3 || second.PriorFiles != 2 {
		t.Fatalf("second collect = %+v, want bundle 2 with 3 packages and 2 prior files", second)
	}
	apkTestImport(t, fx.ls, hs, second.BundleID)

	srv := httptest.NewServer(hs)
	defer srv.Close()
	name := apkTestMirrorName(t, fx.ls, second.BundleID)
	base := srv.URL + "/apk/" + name + "/v3.22/main/x86_64"

	stanzas := apkTestFetchIndex(t, base+"/APKINDEX.tar.gz")
	names := map[string]bool{}
	for _, st := range stanzas {
		names[st.Name] = true
	}
	if len(stanzas) != 3 || !names["foo"] || !names["bar"] || !names["baz"] {
		t.Errorf("accumulated index names = %v, want foo+bar+baz", names)
	}
	// Content from both bundles serves byte-for-byte.
	for _, p := range []apkTestPkg{fx.foo10, fx.bar, baz} {
		code, body := httpGet(t, base+"/"+p.filename())
		if code != http.StatusOK || body != string(p.apk) {
			t.Errorf("GET %s after delta import: status %d, %d bytes (want %d)",
				p.filename(), code, len(body), len(p.apk))
		}
	}
}

// TestApkAdminCollect drives the low-side admin endpoint end to end and
// checks its error mapping.
func TestApkAdminCollect(t *testing.T) {
	fx := newApkTestFixture(t)
	srv := httptest.NewServer(fx.ls)
	defer srv.Close()

	body := fmt.Sprintf(`{"uri":%q,"branches":["v3.22"],"repositories":["main"],"architectures":["x86_64"]}`,
		fx.mirror.srv.URL)
	resp, err := http.Post(srv.URL+"/admin/apk/collect", "application/json", strings.NewReader(body)) //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect status %d, want 200: %s", resp.StatusCode, b)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "apk-bundle-000001" || res.ExportedModules != 2 {
		t.Errorf("admin collect result = %+v", res)
	}

	// Bad JSON and an empty selection are both 400s.
	for _, bad := range []string{"{not json", "{}"} {
		resp, err := http.Post(srv.URL+"/admin/apk/collect", "application/json", strings.NewReader(bad)) //nolint:noctx // short-lived test request
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("collect %q status = %d, want 400", bad, resp.StatusCode)
		}
	}
}
