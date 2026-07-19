package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

// snapTestStoreKey is the fake store signing key digest the fixture
// assertions reference.
const snapTestStoreKey = "BWDEoaqyr25nF5SNCvEv2v7QnM9QsfCc0PBMYD_i2NGSQ32EF2d4D0hqUel3m8ul"

// snapTestSHA3 returns the hex and base64url SHA3-384 of some bytes.
func snapTestSHA3(b []byte) (hexDigest, b64 string) {
	sum := sha3.Sum384(b)
	return hex.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:])
}

// snapTestAssertion renders one store assertion in wire format: ordered
// headers, a blank line, an optional length-declared body followed by a blank
// line, and a fake signature block.
func snapTestAssertion(headers [][2]string, body string) []byte {
	var b strings.Builder
	for _, kv := range headers {
		b.WriteString(kv[0] + ": " + kv[1] + "\n")
	}
	if body != "" {
		b.WriteString("body-length: " + strconv.Itoa(len(body)) + "\n")
	}
	b.WriteString("\n")
	if body != "" {
		b.WriteString(body + "\n\n")
	}
	b.WriteString("AcLBUgQfakeSignatureBase64\n")
	return []byte(b.String())
}

// snapTestRevisionAssertion is the snap-revision assertion for some snap bytes.
func snapTestRevisionAssertion(snapID string, revision int, data []byte) []byte {
	_, b64 := snapTestSHA3(data)
	return snapTestAssertion([][2]string{
		{"type", "snap-revision"},
		{"authority-id", "canonical"},
		{"snap-sha3-384", b64},
		{"developer-id", "pubacct"},
		{"snap-id", snapID},
		{"snap-revision", strconv.Itoa(revision)},
		{"snap-size", strconv.Itoa(len(data))},
		{"sign-key-sha3-384", snapTestStoreKey},
	}, "")
}

// snapTestDeclarationAssertion is the snap-declaration binding a snap-id to a
// name.
func snapTestDeclarationAssertion(snapID, name string) []byte {
	return snapTestAssertion([][2]string{
		{"type", "snap-declaration"},
		{"authority-id", "canonical"},
		{"series", "16"},
		{"snap-id", snapID},
		{"publisher-id", "pubacct"},
		{"snap-name", name},
		{"sign-key-sha3-384", snapTestStoreKey},
	}, "")
}

func snapTestAccountAssertion() []byte {
	return snapTestAssertion([][2]string{
		{"type", "account"},
		{"authority-id", "canonical"},
		{"account-id", "pubacct"},
		{"username", "pub"},
		{"validation", "verified"},
		{"sign-key-sha3-384", "rootKeyDigest"},
	}, "")
}

func snapTestAccountKeyAssertion() []byte {
	return snapTestAssertion([][2]string{
		{"type", "account-key"},
		{"authority-id", "canonical"},
		{"public-key-sha3-384", snapTestStoreKey},
		{"account-id", "canonical"},
		{"name", "store"},
		{"since", "2016-04-01T00:00:00.0Z"},
		{"sign-key-sha3-384", "rootKeyDigest"},
	}, "openpgp FAKEKEYMATERIAL")
}

// snapTestAssertFile composes the .assert document the low side would write
// for some snap bytes.
func snapTestAssertFile(snapID, name string, revision int, data []byte) []byte {
	return composeSnapAssertions([][]byte{
		snapTestAccountKeyAssertion(),
		snapTestAccountAssertion(),
		snapTestDeclarationAssertion(snapID, name),
		snapTestRevisionAssertion(snapID, revision, data),
	})
}

// snapTestSnap describes one snap a fake store publishes on latest/stable for
// amd64. revisionDoc/declarationDoc override the assertion endpoints' answers
// for failure-path tests; nil serves the consistent default.
type snapTestSnap struct {
	name, snapID, version, base string
	revision                    int
	data                        []byte
	revisionDoc, declarationDoc []byte
}

// fakeSnapStore serves the Snap Store API subset ArtiGate reads: snap info,
// downloads, and the four assertion endpoints.
func fakeSnapStore(t *testing.T, snaps []snapTestSnap) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for _, sn := range snaps {
		fakeSnapStoreSnap(t, mux, srv, sn)
	}
	serveAssert := func(doc []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", snapAssertionAccept)
			_, _ = w.Write(doc)
		}
	}
	mux.HandleFunc("/v2/assertions/account/pubacct", serveAssert(snapTestAccountAssertion()))
	mux.HandleFunc("/v2/assertions/account-key/"+snapTestStoreKey, serveAssert(snapTestAccountKeyAssertion()))
	return srv
}

// fakeSnapStoreSnap registers one snap's info, download, and per-snap
// assertion routes.
func fakeSnapStoreSnap(t *testing.T, mux *http.ServeMux, srv *httptest.Server, sn snapTestSnap) {
	t.Helper()
	hexDigest, b64 := snapTestSHA3(sn.data)
	file := fmt.Sprintf("%s_%d.snap", sn.name, sn.revision)
	data := sn.data
	mux.HandleFunc("/download/"+file, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
	doc, err := json.Marshal(map[string]any{
		"channel-map": []map[string]any{{
			"channel":     map[string]any{"architecture": "amd64", "name": "stable", "risk": "stable", "track": "latest"},
			"download":    map[string]any{"sha3-384": hexDigest, "size": len(sn.data), "url": srv.URL + "/download/" + file},
			"revision":    sn.revision,
			"version":     sn.version,
			"base":        sn.base,
			"confinement": "strict",
			"type":        "app",
		}},
		"name":    sn.name,
		"snap-id": sn.snapID,
		"snap": map[string]any{
			"publisher": map[string]any{"display-name": "Pub", "username": "pub"},
			"summary":   "Summary of " + sn.name,
			"title":     sn.name,
			"license":   "MIT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/v2/snaps/info/"+sn.name, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Snap-Device-Series") != "16" {
			http.Error(w, "missing Snap-Device-Series", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(doc)
	})
	serveAssert := func(doc []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(doc) }
	}
	revDoc := sn.revisionDoc
	if revDoc == nil {
		revDoc = snapTestRevisionAssertion(sn.snapID, sn.revision, sn.data)
	}
	declDoc := sn.declarationDoc
	if declDoc == nil {
		declDoc = snapTestDeclarationAssertion(sn.snapID, sn.name)
	}
	mux.HandleFunc("/v2/assertions/snap-revision/"+b64, serveAssert(revDoc))
	mux.HandleFunc("/v2/assertions/snap-declaration/16/"+sn.snapID, serveAssert(declDoc))
}

func newSnapLowServer(t *testing.T, storeURL string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{
		Root:         t.TempDir(),
		ExportDir:    filepath.Join(t.TempDir(), "out"),
		SnapStoreURL: storeURL,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// snapTestFixtures returns the two-snap fixture (an app and the base it
// declares) used across the collect tests.
func snapTestFixtures() []snapTestSnap {
	hello := append([]byte("hsqs"), bytes.Repeat([]byte{0xAB}, 2048)...)
	core := append([]byte("hsqs"), bytes.Repeat([]byte{0xCD}, 1024)...)
	return []snapTestSnap{
		{name: "hello", snapID: "helloSnapIDhelloSnapID12", version: "2.10", base: "core22", revision: 42, data: hello},
		{name: "core22", snapID: "core22SnapIDcore22Snap34", version: "20240823", base: "", revision: 1380, data: core},
	}
}

// -----------------------------------------------------------------------------
// Unit: descriptor, naming, spec parsing, manifest validation
// -----------------------------------------------------------------------------

// TestSnapEcosystemDescriptor pins the registry descriptor's identity and
// hooks, and that its flags hook wires the store override.
func TestSnapEcosystemDescriptor(t *testing.T) {
	e := snapEcosystem()
	if e.stream != streamSnap || e.label == "" || e.title == "" || e.contentDesc == "" {
		t.Errorf("descriptor identity incomplete: %+v", e)
	}
	if e.collect == nil || e.watchCollect == nil || e.publish == nil || e.serve == nil || e.scanTree == nil || e.detail == nil || e.flags == nil {
		t.Error("descriptor is missing hooks")
	}
	if e.manifestContent(BundleManifest{}) {
		t.Error("an empty manifest must carry no snap content")
	}
	p := snapTestPackage()
	m := BundleManifest{Snap: &SnapManifest{Snaps: []SnapPackage{p}}}
	if !e.manifestContent(m) {
		t.Error("a manifest with a snap must carry snap content")
	}
	if err := e.validateContent(m, map[string]bool{p.Path: true, p.AssertPath: true}); err != nil {
		t.Errorf("validateContent rejected a canonical record: %v", err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cfg LowConfig
	e.flags(fs, &cfg)
	if err := fs.Parse([]string{"-snap-store", "https://store.example"}); err != nil {
		t.Fatal(err)
	}
	if cfg.SnapStoreURL != "https://store.example" {
		t.Errorf("-snap-store did not set SnapStoreURL: %q", cfg.SnapStoreURL)
	}
}

// snapTestPackage is a canonical manifest record for validation tests.
func snapTestPackage() SnapPackage {
	return SnapPackage{
		Name: "hello", SnapID: "helloSnapIDhelloSnapID12", Revision: 42,
		Channel: "latest/stable", Architecture: "amd64", Version: "2.10",
		Filename: "hello_42.snap", Path: "snap/files/hello/hello_42.snap",
		SHA256: strings.Repeat("a", 64), SHA3384: strings.Repeat("b", 96),
		AssertPath: "snap/files/hello/hello_42.assert",
	}
}

func TestSnapValidateNames(t *testing.T) {
	valid := []string{"hello", "core22", "0ad", "hello-world", "a1", "x", "firefox"}
	invalid := []string{"", "Hello", "0", "42", "-x", "x-", "a--b", "a_b", "a.b", "a/b", strings.Repeat("a", 41)}
	for _, n := range valid {
		if err := validateSnapName(n); err != nil {
			t.Errorf("validateSnapName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalid {
		if err := validateSnapName(n); err == nil {
			t.Errorf("validateSnapName(%q) = nil, want error", n)
		}
	}
}

func TestSnapValidateChannelsAndArch(t *testing.T) {
	for _, ch := range []string{"stable", "edge", "latest/stable", "22.04/stable", "4.1/candidate", "latest/edge/feature-x"} {
		if err := validateSnapChannel(ch); err != nil {
			t.Errorf("validateSnapChannel(%q) = %v, want nil", ch, err)
		}
	}
	for _, ch := range []string{"", "/stable", "stable/", "a/b/c/d", "-x", "UP", "a b", "../x"} {
		if err := validateSnapChannel(ch); err == nil {
			t.Errorf("validateSnapChannel(%q) = nil, want error", ch)
		}
	}
	for _, a := range []string{"amd64", "arm64", "armhf", "ppc64el", "s390x", "riscv64", "i386"} {
		if err := validateSnapArch(a); err != nil {
			t.Errorf("validateSnapArch(%q) = %v, want nil", a, err)
		}
	}
	for _, a := range []string{"", "x", "AMD64", "-amd64", "a/b", strings.Repeat("a", 21)} {
		if err := validateSnapArch(a); err == nil {
			t.Errorf("validateSnapArch(%q) = nil, want error", a)
		}
	}
}

func TestSnapParseSpec(t *testing.T) {
	good := []struct{ spec, name, channel string }{
		{"hello", "hello", "stable"},
		{"hello@latest", "hello", "stable"},
		{"hello@edge", "hello", "edge"},
		{"blender@4.1/stable", "blender", "4.1/stable"},
	}
	for _, tt := range good {
		name, channel, err := parseSnapSpec(tt.spec)
		if err != nil || name != tt.name || channel != tt.channel {
			t.Errorf("parseSnapSpec(%q) = (%q, %q, %v), want (%q, %q)", tt.spec, name, channel, err, tt.name, tt.channel)
		}
	}
	for _, spec := range []string{"", "Hello", "hello@/x", "hello@Bad Channel", "a..b"} {
		if _, _, err := parseSnapSpec(spec); err == nil {
			t.Errorf("parseSnapSpec(%q) = nil error, want rejection", spec)
		}
	}
}

func TestSnapValidatePackages(t *testing.T) {
	canon := snapTestPackage()
	seen := map[string]bool{canon.Path: true, canon.AssertPath: true}
	if err := validateSnapPackages([]SnapPackage{canon}, seen); err != nil {
		t.Errorf("canonical record rejected: %v", err)
	}
	badFilename := canon
	badFilename.Filename = "hello.snap"
	badPath := canon
	badPath.Path = "snap/files/other/hello_42.snap"
	badAssert := canon
	badAssert.AssertPath = "snap/files/hello/hello_42.snap.assert"
	badDigest := canon
	badDigest.SHA3384 = "zz"
	badID := canon
	badID.SnapID = "short"
	badRev := canon
	badRev.Revision = 0
	badVersion := canon
	badVersion.Version = "2.10\x00"
	for name, p := range map[string]SnapPackage{
		"bad filename": badFilename, "bad path": badPath, "bad assert path": badAssert,
		"bad digest": badDigest, "bad snap-id": badID, "bad revision": badRev, "bad version": badVersion,
	} {
		if err := validateSnapPackage(p, seen); err == nil {
			t.Errorf("%s: record accepted, want rejection", name)
		}
	}
	unlisted := map[string]bool{canon.Path: true}
	if err := validateSnapPackage(canon, unlisted); err == nil {
		t.Error("record with unlisted assert file accepted, want rejection")
	}
}

// -----------------------------------------------------------------------------
// Unit: assertion parsing
// -----------------------------------------------------------------------------

func TestSplitSnapAssertions(t *testing.T) {
	data := []byte("payload")
	stream := snapTestAssertFile("helloSnapIDhelloSnapID12", "hello", 42, data)
	as, err := splitSnapAssertions(stream)
	if err != nil {
		t.Fatalf("splitSnapAssertions: %v", err)
	}
	if len(as) != 4 {
		t.Fatalf("parsed %d assertions, want 4", len(as))
	}
	types := make([]string, 0, len(as))
	for _, a := range as {
		types = append(types, a.header("type"))
	}
	if strings.Join(types, ",") != "account-key,account,snap-declaration,snap-revision" {
		t.Errorf("assertion order = %v", types)
	}
	// The body-carrying account-key round-trips with its body intact.
	if !bytes.Contains(as[0].text, []byte("openpgp FAKEKEYMATERIAL")) {
		t.Errorf("account-key text lost its body: %q", as[0].text)
	}
	if as[3].header("snap-revision") != "42" || as[3].header("snap-size") != strconv.Itoa(len(data)) {
		t.Errorf("snap-revision headers = %v", as[3].headers)
	}
}

func TestSplitSnapAssertionsRejects(t *testing.T) {
	cases := map[string]string{
		"no separator":     "type: account\nauthority-id: canonical\n",
		"no type":          "authority-id: canonical\n\nsig\n",
		"empty signature":  "type: account\n\n\n",
		"bad body-length":  "type: account\nbody-length: nope\n\nsig\n",
		"truncated body":   "type: account\nbody-length: 100\n\nshort\n\nsig\n",
		"unmarked body":    "type: account\nbody-length: 5\n\nbodyXsig\n",
		"negative length":  "type: account\nbody-length: -1\n\nsig\n",
		"oversized length": "type: account\nbody-length: 99999999\n\nsig\n",
	}
	for name, stream := range cases {
		if _, err := splitSnapAssertions([]byte(stream)); err == nil {
			t.Errorf("%s: parsed, want error", name)
		}
	}
	if as, err := splitSnapAssertions(nil); err != nil || len(as) != 0 {
		t.Errorf("empty stream = (%v, %v), want no assertions", as, err)
	}
}

func TestParseSnapAssertionHeaders(t *testing.T) {
	h := parseSnapAssertionHeaders([]byte("type: snap-declaration\ntimestamp: 2016-07-27T01:32:10.291422Z\nplugs:\n  network:\n    allow: true\nsnap-name: hello"))
	if h["type"] != "snap-declaration" || h["snap-name"] != "hello" {
		t.Errorf("headers = %v", h)
	}
	if h["timestamp"] != "2016-07-27T01:32:10.291422Z" {
		t.Errorf("colon-carrying value mangled: %q", h["timestamp"])
	}
	if _, ok := h["  network"]; ok {
		t.Error("continuation line parsed as a header")
	}
}

func TestSnapDigestBase64(t *testing.T) {
	hexDigest, b64 := snapTestSHA3([]byte("x"))
	got, err := snapDigestBase64(hexDigest)
	if err != nil || got != b64 {
		t.Errorf("snapDigestBase64 = (%q, %v), want %q", got, err, b64)
	}
	for _, bad := range []string{"", "zz", strings.Repeat("g", 96), strings.Repeat("a", 95)} {
		if _, err := snapDigestBase64(bad); err == nil {
			t.Errorf("snapDigestBase64(%q) = nil error, want rejection", bad)
		}
	}
}

func TestSnapVerifyAssertions(t *testing.T) {
	data := []byte("snap-bytes")
	p := snapTestPackage()
	hexDigest, _ := snapTestSHA3(data)
	ok := snapTestAssertFile(p.SnapID, p.Name, p.Revision, data)
	if err := snapVerifyAssertions(ok, p, hexDigest, int64(len(data))); err != nil {
		t.Errorf("canonical assertions rejected: %v", err)
	}
	if err := snapVerifyAssertions(ok, p, hexDigest, int64(len(data))+1); err == nil {
		t.Error("size mismatch accepted")
	}
	otherDigest, _ := snapTestSHA3([]byte("tampered"))
	if err := snapVerifyAssertions(ok, p, otherDigest, int64(len(data))); err == nil {
		t.Error("digest mismatch accepted")
	}
	wrongRev := p
	wrongRev.Revision = 43
	if err := snapVerifyAssertions(ok, wrongRev, hexDigest, int64(len(data))); err == nil {
		t.Error("revision mismatch accepted")
	}
	wrongName := p
	wrongName.Name = "other"
	if err := snapVerifyAssertions(ok, wrongName, hexDigest, int64(len(data))); err == nil {
		t.Error("declaration name mismatch accepted")
	}
	incomplete := composeSnapAssertions([][]byte{
		snapTestDeclarationAssertion(p.SnapID, p.Name),
		snapTestRevisionAssertion(p.SnapID, p.Revision, data),
	})
	if err := snapVerifyAssertions(incomplete, p, hexDigest, int64(len(data))); err == nil {
		t.Error("assertions without the account chain accepted")
	}
}

// -----------------------------------------------------------------------------
// Unit: store client helpers
// -----------------------------------------------------------------------------

func TestSnapChannelSelection(t *testing.T) {
	info := &snapStoreInfo{SnapID: "helloSnapIDhelloSnapID12", Name: "hello"}
	mk := func(track, risk, name, arch string, rev int) snapChannelEntry {
		var e snapChannelEntry
		e.Channel.Track, e.Channel.Risk, e.Channel.Name, e.Channel.Architecture = track, risk, name, arch
		e.Revision = rev
		return e
	}
	info.ChannelMap = []snapChannelEntry{
		mk("latest", "stable", "stable", "amd64", 42),
		mk("latest", "edge", "edge", "amd64", 50),
		mk("4.1", "stable", "4.1/stable", "amd64", 40),
		mk("latest", "stable", "stable", "arm64", 43),
	}
	for want, rev := range map[string]int{
		"stable": 42, "latest/stable": 42, "edge": 50, "4.1/stable": 40,
	} {
		e, err := selectSnapChannel(info, want, "amd64")
		if err != nil || e.Revision != rev {
			t.Errorf("selectSnapChannel(%q) = (%v, %v), want revision %d", want, e, err, rev)
		}
	}
	if e, err := selectSnapChannel(info, "stable", "arm64"); err != nil || e.Revision != 43 {
		t.Errorf("arm64 stable = (%v, %v), want revision 43", e, err)
	}
	for _, want := range []string{"candidate", "5.0/stable", "stable/x"} {
		if _, err := selectSnapChannel(info, want, "amd64"); err == nil {
			t.Errorf("selectSnapChannel(%q) matched, want error", want)
		}
	}
	if _, err := selectSnapChannel(info, "stable", "s390x"); err == nil {
		t.Error("unknown architecture matched, want error")
	}
}

func TestValidateSnapChannelEntry(t *testing.T) {
	good := snapChannelEntry{Revision: 42, Base: "core22"}
	good.Download.SHA3384 = strings.Repeat("a", 96)
	good.Download.Size = 100
	good.Download.URL = "https://store.example/x.snap"
	if err := validateSnapChannelEntry(&good); err != nil {
		t.Errorf("valid entry rejected: %v", err)
	}
	for name, mutate := range map[string]func(*snapChannelEntry){
		"bad revision": func(e *snapChannelEntry) { e.Revision = 0 },
		"bad digest":   func(e *snapChannelEntry) { e.Download.SHA3384 = "zz" },
		"bad size":     func(e *snapChannelEntry) { e.Download.Size = 0 },
		"huge size":    func(e *snapChannelEntry) { e.Download.Size = maxMirroredFileBytes + 1 },
		"bad url":      func(e *snapChannelEntry) { e.Download.URL = "ftp://x" },
		"bad base":     func(e *snapChannelEntry) { e.Base = "NOT/safe" },
	} {
		e := good
		mutate(&e)
		if err := validateSnapChannelEntry(&e); err == nil {
			t.Errorf("%s: entry accepted, want rejection", name)
		}
	}
}

func TestSnapStoreBaseAndRequest(t *testing.T) {
	ls, _ := newSnapLowServer(t, "")
	if got := ls.snapStoreBase(); got != defaultSnapStoreURL {
		t.Errorf("default store base = %q", got)
	}
	ls.cfg.SnapStoreURL = "https://proxy.example/"
	if got := ls.snapStoreBase(); got != "https://proxy.example" {
		t.Errorf("configured store base = %q", got)
	}

	if _, err := validateSnapRequest(SnapCollectRequest{}); err == nil {
		t.Error("empty request accepted")
	}
	if _, err := validateSnapRequest(SnapCollectRequest{Snaps: []string{"BAD"}}); err == nil {
		t.Error("bad spec accepted")
	}
	if _, err := validateSnapRequest(SnapCollectRequest{Snaps: []string{"hello"}, Architecture: "X!"}); err == nil {
		t.Error("bad architecture accepted")
	}
	arch, err := validateSnapRequest(SnapCollectRequest{Snaps: []string{"hello"}})
	if err != nil || arch != snapDefaultArch {
		t.Errorf("default arch = (%q, %v), want %q", arch, err, snapDefaultArch)
	}
}

func TestSnapFetchInfoMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/snaps/info/hello", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"name":"other","snap-id":"helloSnapIDhelloSnapID12"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := snapFetchInfo(context.Background(), srv.URL, "hello", "amd64"); err == nil {
		t.Error("mismatched store identity accepted")
	}
	if _, err := snapFetchInfo(context.Background(), srv.URL, "absent", "amd64"); err == nil {
		t.Error("missing snap accepted")
	}
}

func TestOrErr(t *testing.T) {
	def := context.Canceled
	if got := orErr(nil, def); !errors.Is(got, def) {
		t.Errorf("orErr(nil, def) = %v", got)
	}
	if got := orErr(io.EOF, def); !errors.Is(got, io.EOF) {
		t.Errorf("orErr(err, def) = %v", got)
	}
}

// -----------------------------------------------------------------------------
// Collect -> transfer -> import -> serve pipeline
// -----------------------------------------------------------------------------

// TestSnapCollectPipeline mirrors a snap (and the base it declares) from a
// fake store, transfers the signed bundle, imports it — which re-verifies the
// archives against their assertions — and drives the served routes.
func TestSnapCollectPipeline(t *testing.T) {
	fixtures := snapTestFixtures()
	srv := fakeSnapStore(t, fixtures)
	ls, priv := newSnapLowServer(t, srv.URL)

	res, err := ls.CollectSnap(context.Background(), SnapCollectRequest{Snaps: []string{"hello"}})
	if err != nil {
		t.Fatalf("CollectSnap: %v", err)
	}
	if res.BundleID != "snap-bundle-000001" || res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	snapAssertManifest(t, ls, res.BundleID, fixtures)

	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}
	web := httptest.NewServer(hs)
	defer web.Close()
	snapAssertServed(t, web.URL, fixtures[0])
	snapAssertTreeAndDetail(t, hs)
	snapAssertGates(t, web.URL)

	// Export dedup: an unchanged channel exports nothing new.
	res2, err := ls.CollectSnap(context.Background(), SnapCollectRequest{Snaps: []string{"hello"}})
	if err != nil {
		t.Fatalf("re-collect: %v", err)
	}
	if !res2.Skipped {
		t.Errorf("unchanged re-collect not skipped: %+v", res2)
	}

	// Serving is gated on both files still being present: dropping the
	// .assert drops the revision from the metadata routes.
	if err := os.Remove(filepath.Join(hs.downloadDir, "snap", "files", "hello", "hello_42.assert")); err != nil {
		t.Fatal(err)
	}
	if code, _ := httpGet(t, web.URL+"/snap/info/hello"); code != http.StatusNotFound {
		t.Errorf("info for a revision missing its .assert = %d, want 404", code)
	}
}

// snapAssertManifest checks the exported bundle manifest's snap records.
func snapAssertManifest(t *testing.T, ls *LowServer, bundleID string, fixtures []snapTestSnap) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Snap == nil || len(m.Snap.Snaps) != 2 {
		t.Fatalf("manifest carries %+v, want 2 snaps", m.Snap)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateSnapPackages(m.Snap.Snaps, seen); err != nil {
		t.Fatalf("exported manifest fails high-side validation: %v", err)
	}
	byName := map[string]SnapPackage{}
	for _, p := range m.Snap.Snaps {
		byName[p.Name] = p
	}
	hello := byName["hello"]
	hexDigest, _ := snapTestSHA3(fixtures[0].data)
	if hello.Revision != 42 || hello.Channel != "latest/stable" || hello.SHA3384 != hexDigest ||
		hello.Base != "core22" || hello.Publisher != "pub" || hello.SnapID != fixtures[0].snapID {
		t.Errorf("hello record = %+v", hello)
	}
	if _, ok := byName["core22"]; !ok {
		t.Error("base snap core22 not mirrored with hello")
	}
}

// snapAssertServed drives the file and info routes for one imported snap.
func snapAssertServed(t *testing.T, base string, sn snapTestSnap) {
	t.Helper()
	code, body := httpGet(t, base+fmt.Sprintf("/snap/files/%s/%s_%d.snap", sn.name, sn.name, sn.revision))
	if code != http.StatusOK || body != string(sn.data) {
		t.Fatalf("served snap = %d (%d bytes), want the archive", code, len(body))
	}
	code, body = httpGet(t, base+fmt.Sprintf("/snap/files/%s/%s_%d.assert", sn.name, sn.name, sn.revision))
	if code != http.StatusOK || !strings.Contains(body, "type: snap-revision") || !strings.Contains(body, "type: account-key") {
		t.Fatalf("served assert = %d %q", code, body)
	}
	code, body = httpGet(t, base+"/snap/info/"+sn.name)
	if code != http.StatusOK {
		t.Fatalf("info = %d %s", code, body)
	}
	var info struct {
		Name      string `json:"name"`
		Revisions []struct {
			Revision int               `json:"revision"`
			Version  string            `json:"version"`
			Files    map[string]string `json:"files"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("info is not JSON: %v\n%s", err, body)
	}
	if info.Name != sn.name || len(info.Revisions) != 1 || info.Revisions[0].Revision != sn.revision ||
		info.Revisions[0].Version != sn.version || info.Revisions[0].Files["assert"] == "" {
		t.Errorf("info = %s", body)
	}
}

// snapAssertTreeAndDetail checks the dashboard hooks against the imported
// metadata.
func snapAssertTreeAndDetail(t *testing.T, hs *HighServer) {
	t.Helper()
	mods, err := hs.listSnapPackages()
	if err != nil || len(mods) != 2 {
		t.Fatalf("listSnapPackages = (%v, %v), want hello and core22", mods, err)
	}
	if mods[0].Module != "core22" || mods[1].Module != "hello" || mods[1].Versions[0] != "42" {
		t.Errorf("tree modules = %+v", mods)
	}
	detail, err := hs.snapDetail("hello@42")
	if err != nil {
		t.Fatalf("snapDetail: %v", err)
	}
	if detail.Title != "hello" || len(detail.Downloads) != 2 {
		t.Errorf("detail = %+v", detail)
	}
	fields := map[string]string{}
	for _, f := range detail.Fields {
		fields[f.Label] = f.Value
	}
	if fields["Channel"] != "latest/stable" || fields["Base"] != "core22" || fields["Version"] != "2.10" {
		t.Errorf("detail fields = %v", fields)
	}
	for _, spec := range []string{"hello", "hello@nope", "../x@1", "hello@0", "hello@43"} {
		if _, err := hs.snapDetail(spec); err == nil {
			t.Errorf("snapDetail(%q) = nil error, want rejection", spec)
		}
	}
}

// snapAssertGates checks the route guards: methods, unknown names, and
// non-canonical filenames.
func snapAssertGates(t *testing.T, base string) {
	t.Helper()
	resp, err := http.Post(base+"/snap/files/hello/hello_42.snap", "text/plain", strings.NewReader("x")) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", resp.StatusCode)
	}
	for path, want := range map[string]int{
		"/snap":                              http.StatusNotFound,
		"/snap/info/absent":                  http.StatusNotFound,
		"/snap/info/NotASnap":                http.StatusNotFound,
		"/snap/files/hello/other_1.snap":     http.StatusNotFound,
		"/snap/files/hello/hello_42.torrent": http.StatusNotFound,
		"/snap/files/hello/hello_1.snap":     http.StatusNotFound,
		"/snap/files/hello":                  http.StatusNotFound,
	} {
		if code, _ := httpGet(t, base+path); code != want {
			t.Errorf("GET %s = %d, want %d", path, code, want)
		}
	}
}

// TestSnapCollectNoBases pins the opt-out: only the listed snaps are
// mirrored, and failures are reported per snap without failing the batch.
func TestSnapCollectNoBases(t *testing.T) {
	srv := fakeSnapStore(t, snapTestFixtures())
	ls, _ := newSnapLowServer(t, srv.URL)
	res, err := ls.CollectSnap(context.Background(), SnapCollectRequest{Snaps: []string{"hello", "missing"}, NoBases: true})
	if err != nil {
		t.Fatalf("CollectSnap: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Errorf("exported %d snaps, want just hello: %+v", res.ExportedModules, res)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "missing" {
		t.Errorf("skipped = %+v, want the missing snap", res.SkippedModules)
	}
}

// TestSnapCollectRejectsBadStoreText pins the low-side half of the record
// validation symmetry: a store field the high side's validateSnapPackage
// would reject (control characters here) fails that one snap at collect
// time instead of being signed into a bundle the high side must then reject
// — which, on the strictly sequenced snap stream, would stall every later
// import behind the dead sequence number.
func TestSnapCollectRejectsBadStoreText(t *testing.T) {
	snaps := snapTestFixtures()
	snaps[0].version = "2.10\x01" // hello
	srv := fakeSnapStore(t, snaps)
	ls, _ := newSnapLowServer(t, srv.URL)
	res, err := ls.CollectSnap(context.Background(), SnapCollectRequest{Snaps: []string{"hello", "core22"}, NoBases: true})
	if err != nil {
		t.Fatalf("CollectSnap: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Errorf("exported %d snaps, want just core22: %+v", res.ExportedModules, res)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "hello" ||
		!strings.Contains(res.SkippedModules[0].Error, "control characters") {
		t.Errorf("skipped = %+v, want hello failing the free-text check", res.SkippedModules)
	}
}

// TestSnapCollectAllFail pins the all-failed error shape.
func TestSnapCollectAllFail(t *testing.T) {
	srv := fakeSnapStore(t, nil)
	ls, _ := newSnapLowServer(t, srv.URL)
	_, err := ls.CollectSnap(context.Background(), SnapCollectRequest{Snaps: []string{"missing"}})
	if err == nil || !strings.Contains(err.Error(), "no snaps could be fetched") {
		t.Errorf("all-failed collect = %v", err)
	}
}

// TestSnapCollectAssertionFailures pins the low side's cross-checks of the
// fetched assertion chain: a store whose assertions disagree with its channel
// map fails the snap at collect time, before anything crosses the diode.
func TestSnapCollectAssertionFailures(t *testing.T) {
	data := append([]byte("hsqs"), bytes.Repeat([]byte{0x11}, 256)...)
	base := snapTestSnap{name: "hello", snapID: "helloSnapIDhelloSnapID12", version: "1.0", revision: 7, data: data}
	badDecl := func(headers [][2]string) []byte { return snapTestAssertion(headers, "") }
	for name, tc := range map[string]struct {
		mutate func(*snapTestSnap)
		want   string
	}{
		"revision disagrees": {func(sn *snapTestSnap) {
			sn.revisionDoc = snapTestRevisionAssertion(sn.snapID, sn.revision+1, sn.data)
		}, "disagrees with the store's channel entry"},
		"declaration names another snap": {func(sn *snapTestSnap) {
			sn.declarationDoc = snapTestDeclarationAssertion(sn.snapID, "other")
		}, "snap-declaration names"},
		"unusable publisher": {func(sn *snapTestSnap) {
			sn.declarationDoc = badDecl([][2]string{
				{"type", "snap-declaration"},
				{"series", "16"},
				{"snap-id", sn.snapID},
				{"publisher-id", "bad id!"},
				{"snap-name", sn.name},
				{"sign-key-sha3-384", snapTestStoreKey},
			})
		}, "unusable publisher-id"},
		"unusable sign key": {func(sn *snapTestSnap) {
			sn.declarationDoc = badDecl([][2]string{
				{"type", "snap-declaration"},
				{"series", "16"},
				{"snap-id", sn.snapID},
				{"publisher-id", "pubacct"},
				{"snap-name", sn.name},
				{"sign-key-sha3-384", "bad key!"},
			})
		}, "unusable sign-key reference"},
		"garbage assertion response": {func(sn *snapTestSnap) {
			doc := snapTestRevisionAssertion(sn.snapID, sn.revision, sn.data)
			sn.revisionDoc = composeSnapAssertions([][]byte{doc, doc})
		}, "unusable response"},
	} {
		sn := base
		tc.mutate(&sn)
		srv := fakeSnapStore(t, []snapTestSnap{sn})
		ls, _ := newSnapLowServer(t, srv.URL)
		_, err := ls.CollectSnap(context.Background(), SnapCollectRequest{Snaps: []string{"hello"}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: collect = %v, want %q", name, err, tc.want)
		}
	}
}

// TestSnapStoreGetCaps covers the store client's response cap and status
// handling.
func TestSnapStoreGetCaps(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bytes.Repeat([]byte{'x'}, 100)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := snapStoreGet(context.Background(), srv.URL+"/big", "", 10); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("oversized response = %v, want cap error", err)
	}
	if b, err := snapStoreGet(context.Background(), srv.URL+"/big", "text/plain", 100); err != nil || len(b) != 100 {
		t.Errorf("within-cap response = (%d bytes, %v)", len(b), err)
	}
	var httpErr *upstreamHTTPError
	_, err := snapStoreGet(context.Background(), srv.URL+"/absent", "", 100)
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusNotFound {
		t.Errorf("404 response = %v, want upstreamHTTPError", err)
	}
	if _, err := snapStoreGet(context.Background(), "http://[bad", "", 100); err == nil {
		t.Error("invalid URL accepted")
	}
}

// TestHandleSnapCollect covers the admin endpoint's request parsing.
func TestHandleSnapCollect(t *testing.T) {
	ls, _ := newSnapLowServer(t, "http://127.0.0.1:0")
	req := httptest.NewRequest(http.MethodPost, "/admin/snap/collect", strings.NewReader("{bad json"))
	if _, err := ls.HandleSnapCollect(context.Background(), req); err == nil {
		t.Error("bad JSON accepted")
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/snap/collect", strings.NewReader(`{"snaps":[]}`))
	if _, err := ls.HandleSnapCollect(context.Background(), req); err == nil {
		t.Error("empty snap list accepted")
	}
}

// TestPublishSnapRejectsTampering pins the high side's independent artifact
// verification: bytes that do not match the assertion chain publish nothing.
func TestPublishSnapRejectsTampering(t *testing.T) {
	_, priv := newTestKeys(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	data := []byte("genuine snap bytes")
	p := snapTestPackage()
	place := func(snapBytes, assert []byte) {
		dir := filepath.Join(hs.downloadDir, "snap", "files", "hello")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, p.Filename), snapBytes)
		writeFile(t, filepath.Join(dir, snapAssertFilename(p.Name, p.Revision)), assert)
	}

	place(data, snapTestAssertFile(p.SnapID, p.Name, p.Revision, data))
	if err := hs.publishSnapPackage(p); err != nil {
		t.Fatalf("genuine artifact rejected: %v", err)
	}
	if _, err := hs.readSnapStored("hello", 42); err != nil {
		t.Fatalf("metadata not readable after publish: %v", err)
	}

	place([]byte("tampered bytes"), snapTestAssertFile(p.SnapID, p.Name, p.Revision, data))
	if err := hs.publishSnapPackage(p); err == nil {
		t.Fatal("tampered archive published without error")
	}
	if err := hs.publishSnap(&SnapManifest{Snaps: []SnapPackage{p}}); err != nil {
		t.Fatalf("publishSnap must skip (not fail on) a bad snap: %v", err)
	}

	unsafe := p
	unsafe.Path = "other/files/hello/hello_42.snap"
	if err := hs.publishSnapPackage(unsafe); err == nil {
		t.Error("non-snap path accepted")
	}
	absent := p
	absent.Name = "ghost"
	absent.Filename = "ghost_42.snap"
	absent.Path = "snap/files/ghost/ghost_42.snap"
	absent.AssertPath = "snap/files/ghost/ghost_42.assert"
	if err := hs.publishSnapPackage(absent); err == nil {
		t.Error("record without artifacts accepted")
	}
	if err := hs.publishSnap(nil); err != nil {
		t.Errorf("nil manifest = %v", err)
	}
}

// TestSnapComposeAndInfoShapes covers the remaining small helpers.
func TestSnapComposeAndInfoShapes(t *testing.T) {
	got := composeSnapAssertions([][]byte{[]byte("a: 1\n\nsig\n\n\n"), []byte("b: 2\n\nsig")})
	want := "a: 1\n\nsig\n\nb: 2\n\nsig\n"
	if string(got) != want {
		t.Errorf("composeSnapAssertions = %q, want %q", got, want)
	}
	if snapFilename("hello", 42) != "hello_42.snap" || snapAssertFilename("hello", 42) != "hello_42.assert" {
		t.Error("canonical filenames changed")
	}
	if snapFileRel("hello", "hello_42.snap") != "snap/files/hello/hello_42.snap" {
		t.Error("canonical path changed")
	}
}
