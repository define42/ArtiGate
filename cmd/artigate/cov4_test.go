package main

import (
	"crypto/ed25519"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This file closes the final coverage gap with focused tests over pure helpers,
// exercising all of their branches so the previously-missed error/edge arms are
// covered.

func TestCov4_ParseMavenCoord(t *testing.T) {
	if c, err := parseMavenCoord(" org.example : lib : 1.2.3 "); err != nil {
		t.Fatalf("valid coord: %v", err)
	} else if c.GroupID != "org.example" || c.ArtifactID != "lib" || c.Version != "1.2.3" {
		t.Fatalf("parsed = %+v", c)
	}
	for _, bad := range []string{"onlyone", "a:b", "a:b:c:d", "bad group:lib:1.0", "org:bad artifact:1.0", "org:lib:1.0-SNAPSHOT", "org:lib:"} {
		if _, err := parseMavenCoord(bad); err == nil {
			t.Errorf("parseMavenCoord(%q) should fail", bad)
		}
	}
}

func TestCov4_ValidateMavenVersion(t *testing.T) {
	if err := validateMavenVersion("1.4.0"); err != nil {
		t.Fatalf("valid version rejected: %v", err)
	}
	for _, bad := range []string{"", "   ", "1.0-SNAPSHOT", "LATEST", "RELEASE", "1.+", "[1.0,2.0)", "1.0.*", "bad version!"} {
		if err := validateMavenVersion(bad); err == nil {
			t.Errorf("validateMavenVersion(%q) should fail", bad)
		}
	}
}

func TestCov4_EnvIsTrue(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on", " On "} {
		if !envIsTrue(v) {
			t.Errorf("envIsTrue(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "nonsense"} {
		if envIsTrue(v) {
			t.Errorf("envIsTrue(%q) = true, want false", v)
		}
	}
}

func TestCov4_HostnameOrDefault(t *testing.T) {
	if hostnameOrDefault() == "" {
		t.Fatal("hostnameOrDefault returned empty")
	}
}

func TestCov4_ParseBundleName(t *testing.T) {
	if s, n, ok := parseBundleName("go-bundle-000042.manifest.json"); !ok || s != "go" || n != 42 {
		t.Fatalf("go bundle = %q/%d/%v", s, n, ok)
	}
	if s, n, ok := parseBundleName("apt-bundle-000001.manifest.json"); !ok || s != "apt" || n != 1 {
		t.Fatalf("apt bundle = %q/%d/%v", s, n, ok)
	}
	// Non-matching name.
	if _, _, ok := parseBundleName("not-a-bundle.txt"); ok {
		t.Error("non-bundle name should not parse")
	}
	// Regex matches the digits but the value overflows int64 → ParseInt fails.
	if _, _, ok := parseBundleName("go-bundle-99999999999999999999999.manifest.json"); ok {
		t.Error("overflowing sequence should not parse")
	}
}

func TestCov4_MergeSequenceRanges(t *testing.T) {
	if got := mergeSequenceRanges(nil); got != nil {
		t.Fatalf("empty input = %v, want nil", got)
	}
	// Overlapping + adjacent ranges collapse; a disjoint one stays separate.
	in := []SequenceRange{{5, 6}, {1, 3}, {4, 4}, {10, 12}}
	got := mergeSequenceRanges(in)
	if len(got) != 2 || got[0] != (SequenceRange{1, 6}) || got[1] != (SequenceRange{10, 12}) {
		t.Fatalf("merged = %+v", got)
	}
}

func TestCov4_MissingRanges(t *testing.T) {
	if got := missingRanges(5, 1, nil); got != nil {
		t.Fatalf("end<start = %v, want nil", got)
	}
	present := map[int64]bool{2: true, 3: true, 6: false}
	got := missingRanges(1, 5, present)
	if len(got) != 2 || got[0] != (SequenceRange{1, 1}) || got[1] != (SequenceRange{4, 5}) {
		t.Fatalf("gaps = %+v", got)
	}
	// No gaps: contiguous coverage.
	if got := missingRanges(1, 3, map[int64]bool{1: true, 2: true, 3: true}); got != nil {
		t.Fatalf("contiguous = %+v, want nil", got)
	}
	// MaxInt64 present triggers the early return.
	if got := missingRanges(math.MaxInt64-1, math.MaxInt64, map[int64]bool{math.MaxInt64: true}); len(got) != 1 {
		t.Fatalf("maxint = %+v", got)
	}
}

func TestCov4_ParseSequenceSpec(t *testing.T) {
	for _, bad := range []string{"", "   ", " , , ", "abc", "3-1", "0", "1-x"} {
		if _, err := parseSequenceSpec(bad); err == nil {
			t.Errorf("parseSequenceSpec(%q) should fail", bad)
		}
	}
	got, err := parseSequenceSpec(" 1, 3-5 , 7 ")
	if err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	if len(got) != 3 || got[0] != (SequenceRange{1, 1}) || got[1] != (SequenceRange{3, 5}) || got[2] != (SequenceRange{7, 7}) {
		t.Fatalf("spec = %+v", got)
	}
}

func TestCov4_ComparePrerelease(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"alpha", "alpha", 0},
		{"1", "2", -1},
		{"2", "1", 1},
		{"1", "alpha", -1}, // numeric ranks below alphanumeric
		{"alpha", "1", 1},
		{"alpha", "beta", -1},
		{"alpha", "alpha.1", -1}, // shorter set has lower precedence
		{"alpha.1", "alpha", 1},
	}
	for _, c := range cases {
		if got := comparePrerelease(c.a, c.b); got != c.want {
			t.Errorf("comparePrerelease(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCov4_ModuleEscFromInfoPath(t *testing.T) {
	got, err := moduleEscFromInfoPath("github.com/foo/bar/@v/v1.0.0.info")
	if err != nil || got != "github.com/foo/bar" {
		t.Fatalf("moduleEsc = %q err=%v", got, err)
	}
	if _, err := moduleEscFromInfoPath("no-at-v-segment"); err == nil {
		t.Error("path without /@v/ should error")
	}
}

func TestCov4_ShortDigest(t *testing.T) {
	if got := shortDigest("sha256:0123456789abcdef"); got != "0123456789ab" {
		t.Fatalf("long digest = %q", got)
	}
	if got := shortDigest("sha256:abcd"); got != "abcd" {
		t.Fatalf("short digest = %q", got)
	}
}

func TestCov4_NormalizeVersionConstraint(t *testing.T) {
	cases := map[string]string{
		"x":        ">= 0",
		"*":        ">= 0",
		"1.26.x":   ">= 1.26.0, < 1.27.0",
		">= 2.x.x": ">= 2.0.0",
	}
	for in, want := range cases {
		if got := normalizeVersionConstraint(in); got != want {
			t.Errorf("normalizeVersionConstraint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCov4_WildcardToRange(t *testing.T) {
	cases := map[string]string{
		"1.26.x": ">= 1.26.0, < 1.27.0",
		"1.x":    ">= 1.0.0, < 2.0.0",
		"v2.x":   ">= 2.0.0, < 3.0.0",
		"x":      ">= 0",
	}
	for in, want := range cases {
		if got := wildcardToRange(in); got != want {
			t.Errorf("wildcardToRange(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCov4_DebCharOrder(t *testing.T) {
	if debCharOrder('5') != 0 {
		t.Error("digit weight")
	}
	if debCharOrder('a') != int('a') {
		t.Error("letter weight")
	}
	if debCharOrder('~') != -1 {
		t.Error("tilde weight")
	}
	if debCharOrder('.') != int('.')+256 {
		t.Error("other weight")
	}
}

func TestCov4_FirstField(t *testing.T) {
	if firstField("   ") != "" {
		t.Error("blank should yield empty")
	}
	if firstField("  hello world ") != "hello" {
		t.Error("first token")
	}
}

func TestCov4_RpmEVRCompare(t *testing.T) {
	if rpmEVRCompare(RpmPackage{Epoch: "1", Version: "1.0-1"}, RpmPackage{Epoch: "0", Version: "9.0-1"}) <= 0 {
		t.Error("higher epoch should win")
	}
	if rpmEVRCompare(RpmPackage{Version: "1.2-1"}, RpmPackage{Version: "1.10-1"}) >= 0 {
		t.Error("1.2 < 1.10 by segment compare")
	}
	if rpmEVRCompare(RpmPackage{Version: "1.0-1"}, RpmPackage{Version: "1.0-2"}) >= 0 {
		t.Error("release should break the tie")
	}
	if rpmEVRCompare(RpmPackage{Version: "1.0-1"}, RpmPackage{Version: "1.0-1"}) != 0 {
		t.Error("equal EVR")
	}
}

func TestCov4_DiodeTokenOK(t *testing.T) {
	req := httptest.NewRequest("PUT", "/diode/x", nil)
	if !diodeTokenOK(req, "") {
		t.Error("empty token accepts any request")
	}
	req.Header.Set("Authorization", "Bearer secret")
	if !diodeTokenOK(req, "secret") {
		t.Error("matching token should pass")
	}
	if diodeTokenOK(req, "other") {
		t.Error("mismatched token should fail")
	}
}

func TestCov4_MergeSequenceLists(t *testing.T) {
	got := mergeSequenceLists([]int64{3, 1, 2}, []int64{2, 5, 4})
	want := []int64{1, 2, 3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("merged = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged = %v, want %v", got, want)
		}
	}
}

func TestCov4_BoolToInt(t *testing.T) {
	if boolToInt(true) != 1 || boolToInt(false) != 0 {
		t.Fatal("boolToInt")
	}
}

// TestCov4_RunHighBoot exercises the high-side startup wiring (flag parsing,
// key loading, server construction, catcher/import setup, and the listen call)
// by booting runHigh. It binds an OS-assigned loopback port (":0") directly so
// there is no bind-race with another listener — binding via a pre-opened,
// then-closed port would let another process claim it and make listenAndServe
// fail, which runHigh turns into a fatal exit. listenAndServe blocks, so runHigh
// runs in a goroutine; the server is torn down when the test process exits.
func TestCov4_RunHighBoot(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "high.ed25519.pub")
	if err := writeKeyFile(pubPath, pub, 0o644); err != nil {
		t.Fatal(err)
	}

	// Neutralize inherited diode/TLS env so startup uses plain defaults.
	for _, k := range []string{"ARTIGATE_DIODE_INGEST", "ARTIGATE_DIODE_TOKEN", "ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN", "ARTIGATE_TLS_MODE"} {
		t.Setenv(k, "")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runHigh([]string{
			"--public-key", pubPath,
			"--listen", "127.0.0.1:0",
			"--root", filepath.Join(dir, "root"),
			"--landing", filepath.Join(dir, "landing"),
			"--import-interval", "0",
		})
	}()

	// runHigh blocks in listenAndServe once startup succeeds; give the goroutine
	// time to execute the startup path. If startup fails, runHigh would exit the
	// process, so reaching the end of this test means the wiring came up cleanly.
	select {
	case <-done:
		t.Fatal("runHigh returned unexpectedly (startup failed)")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestCov4_MoveFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	writeFile(t, src, []byte("payload"))
	if err := moveFile(src, dst, 0o644); err != nil {
		t.Fatalf("moveFile happy path: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("source should be gone after move")
	}
	if b, _ := os.ReadFile(dst); string(b) != "payload" {
		t.Error("destination content mismatch")
	}
	// A same-filesystem rename of a missing source returns the rename error
	// (not EXDEV), exercising the error-return branch.
	if err := moveFile(filepath.Join(dir, "missing"), filepath.Join(dir, "dst2"), 0o644); err == nil {
		t.Error("moveFile of missing source should fail")
	}
}

func TestCov4_ParseProxyRequest(t *testing.T) {
	// @latest
	if r, err := parseProxyRequest("/github.com/foo/bar/@latest"); err != nil || r.Kind != proxyLatest || r.Module != "github.com/foo/bar" {
		t.Fatalf("@latest = %+v err=%v", r, err)
	}
	// list
	if r, err := parseProxyRequest("/github.com/foo/bar/@v/list"); err != nil || r.Kind != proxyList {
		t.Fatalf("list = %+v err=%v", r, err)
	}
	// version files
	for _, ext := range []string{".info", ".mod", ".zip", ".ziphash"} {
		p := "/github.com/foo/bar/@v/v1.2.3" + ext
		r, err := parseProxyRequest(p)
		if err != nil || r.Kind != proxyVersionFile || r.Ext != ext || r.Version != "v1.2.3" {
			t.Fatalf("%s = %+v err=%v", ext, r, err)
		}
	}
	// error paths
	for _, bad := range []string{
		"/",                          // empty after clean
		"//",                         // cleans to empty
		"github.com/foo/bar",         // no /@v/ and not @latest
		"github.com/foo/bar/@v/v1.x", // unknown extension
	} {
		if _, err := parseProxyRequest(bad); err == nil {
			t.Errorf("parseProxyRequest(%q) should fail", bad)
		}
	}
}

func TestCov4_ParseBearerChallenge(t *testing.T) {
	realm, params, err := parseBearerChallenge(`Bearer realm="https://auth.example.com/token",service="reg",scope="repo:pull"`)
	if err != nil {
		t.Fatalf("valid challenge: %v", err)
	}
	if realm != "https://auth.example.com/token" || params["service"] != "reg" || params["scope"] != "repo:pull" {
		t.Fatalf("parsed realm=%q params=%v", realm, params)
	}
	// Malformed comma-separated part without '=' is skipped, not fatal.
	if _, _, err := parseBearerChallenge(`Bearer realm="https://a/t", junk`); err != nil {
		t.Fatalf("challenge with junk part: %v", err)
	}
	for _, bad := range []string{
		`Basic realm="x"`,                   // unsupported scheme
		`Bearer service="reg"`,              // no realm
		`Bearer realm="://bad",service="x"`, // unparseable realm scheme
		`Bearer realm="ftp://host/t"`,       // non-http(s) scheme
	} {
		if _, _, err := parseBearerChallenge(bad); err == nil {
			t.Errorf("parseBearerChallenge(%q) should fail", bad)
		}
	}
}

func TestCov4_ValidateImageRef(t *testing.T) {
	if err := validateImageRef("docker.io/library/golang:1.26", imageRef{Registry: "docker.io", Repository: "library/golang", Tag: "1.26"}); err != nil {
		t.Fatalf("valid ref rejected: %v", err)
	}
	cases := []imageRef{
		{Registry: "reg.example.com:5000", Repository: "app", Tag: "1"}, // port not allowed
		{Registry: "bad host", Repository: "app", Tag: "1"},             // invalid host
		{Registry: "docker.io", Repository: "", Tag: "1"},               // empty repo
		{Registry: "docker.io", Repository: "app", Tag: "bad tag!"},     // invalid tag
	}
	for i, ref := range cases {
		if err := validateImageRef("spec", ref); err == nil {
			t.Errorf("case %d: validateImageRef should fail for %+v", i, ref)
		}
	}
}

func TestCov4_FirstPomIn(t *testing.T) {
	dir := t.TempDir()
	if firstPomIn(dir) != "" {
		t.Error("empty dir should yield no pom")
	}
	if firstPomIn(filepath.Join(dir, "does-not-exist")) != "" {
		t.Error("missing dir should yield empty (ReadDir error)")
	}
	writeFile(t, filepath.Join(dir, "lib-1.0.pom"), []byte("<project/>"))
	if got := firstPomIn(dir); got != filepath.Join(dir, "lib-1.0.pom") {
		t.Fatalf("firstPomIn = %q", got)
	}
}

// TestCov4_CachedListsError drives cachedTrees's error-return branch by making
// the Go module tree unreadable so listGoModules's WalkDir fails.
func TestCov4_CachedListsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	root := hs.goModuleDir()
	sub := filepath.Join(root, "example.com", "mod", "@v")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Make an intermediate directory unreadable/untraversable so WalkDir errors.
	locked := filepath.Join(root, "example.com")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	if _, err := hs.cachedTrees(); err == nil {
		t.Fatal("cachedTrees should propagate the WalkDir permission error")
	}
}

// TestCov4_TreeCacheInvalidation pins the dashboard scan cache's contract: a
// warmed cache serves the memoized scan (the mirror only changes on import or
// upload deletion), and invalidate() makes the next request re-scan so those
// mutations are visible immediately instead of after the TTL.
func TestCov4_TreeCacheInvalidation(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	uploadsDir := filepath.Join(hs.uploadsDir(), "docs")
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(uploadsDir, "a.txt"), []byte("a"))

	docsFiles := func(trees map[string]uiTree) int {
		return len(trees["uploads"].children("docs"))
	}
	first, err := hs.cachedTrees()
	if err != nil {
		t.Fatal(err)
	}
	if docsFiles(first) != 1 {
		t.Fatalf("uploads docs folder = %d file(s), want 1", docsFiles(first))
	}

	// A direct disk write is invisible while the cache is warm…
	writeFile(t, filepath.Join(uploadsDir, "b.txt"), []byte("b"))
	cached, err := hs.cachedTrees()
	if err != nil {
		t.Fatal(err)
	}
	if docsFiles(cached) != 1 {
		t.Fatalf("cached uploads docs folder = %d file(s), want the memoized 1", docsFiles(cached))
	}

	// …and visible immediately after the mutation paths invalidate the cache.
	hs.tree.invalidate()
	fresh, err := hs.cachedTrees()
	if err != nil {
		t.Fatal(err)
	}
	if docsFiles(fresh) != 2 {
		t.Fatalf("invalidated uploads docs folder = %d file(s), want 2", docsFiles(fresh))
	}
}
