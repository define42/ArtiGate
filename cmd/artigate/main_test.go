package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseSemverAndValid(t *testing.T) {
	tests := []struct {
		in    string
		ok    bool
		major int64
		minor int64
		patch int64
		pre   string
	}{
		{"v1.2.3", true, 1, 2, 3, ""},
		{"v0.0.0", true, 0, 0, 0, ""},
		{"v10.20.30", true, 10, 20, 30, ""},
		{"v1.2.3-rc.1", true, 1, 2, 3, "rc.1"},
		{"v2.0.0+incompatible", true, 2, 0, 0, ""},
		{"v1.2.3-beta+incompatible", true, 1, 2, 3, "beta"},
		{"1.2.3", false, 0, 0, 0, ""}, // missing leading v
		{"v1.2", false, 0, 0, 0, ""},  // not enough components
		{"v1.2.3.4", false, 0, 0, 0, ""},
		{"vabc", false, 0, 0, 0, ""},
		{"", false, 0, 0, 0, ""},
	}
	for _, tt := range tests {
		got := parseSemver(tt.in)
		if got.ok != tt.ok {
			t.Errorf("parseSemver(%q).ok = %v, want %v", tt.in, got.ok, tt.ok)
			continue
		}
		if isValidSemver(tt.in) != tt.ok {
			t.Errorf("isValidSemver(%q) = %v, want %v", tt.in, isValidSemver(tt.in), tt.ok)
		}
		if !tt.ok {
			continue
		}
		if got.major != tt.major || got.minor != tt.minor || got.patch != tt.patch || got.pre != tt.pre {
			t.Errorf("parseSemver(%q) = %+v, want {%d %d %d %q}", tt.in, got, tt.major, tt.minor, tt.patch, tt.pre)
		}
	}
}

func TestIsPseudoVersion(t *testing.T) {
	pseudo := []string{
		"v0.0.0-20191109021931-daa7c04131f5",
		"v1.2.3-0.20200101000000-abcdef1234567",
		"v0.0.0-20060102150405-0123456789ab",
	}
	notPseudo := []string{
		"v1.2.3",
		"v1.2.3-rc.1",
		"v2.0.0+incompatible",
		"v0.0.0-20191109021931", // no hash suffix
	}
	for _, v := range pseudo {
		if !isPseudoVersion(v) {
			t.Errorf("isPseudoVersion(%q) = false, want true", v)
		}
	}
	for _, v := range notPseudo {
		if isPseudoVersion(v) {
			t.Errorf("isPseudoVersion(%q) = true, want false", v)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.3.0", "v1.2.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.2.3-rc.1", "v1.2.3", -1}, // pre-release < release
		{"v1.2.3", "v1.2.3-rc.1", 1},
		{"v1.2.3-rc.1", "v1.2.3-rc.2", -1},
		{"v1.2.3-rc.2", "v1.2.3-rc.10", -1}, // numeric compare, not lexical
		{"v1.2.3-alpha", "v1.2.3-beta", -1},
		{"v1.2.3-rc.1", "v1.2.3-rc.1.1", -1}, // shorter set < longer
		{"v1.2.3-1", "v1.2.3-alpha", -1},     // numeric < alphanumeric
		// invalid versions sort below valid ones, and compare lexically among themselves
		{"garbage", "v1.0.0", -1},
		{"v1.0.0", "garbage", 1},
		{"aaa", "bbb", -1},
	}
	for _, tt := range tests {
		if got := sign(compareVersions(tt.a, tt.b)); got != tt.want {
			t.Errorf("compareVersions(%q, %q) sign = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		// Antisymmetry: reversing arguments negates the sign.
		if got := sign(compareVersions(tt.b, tt.a)); got != -tt.want {
			t.Errorf("compareVersions(%q, %q) sign = %d, want %d (antisymmetry)", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestSortVersionsAsc(t *testing.T) {
	in := []string{"v1.2.0", "v1.0.0", "v1.10.0", "v1.2.0-rc.1", "v1.0.0-alpha"}
	sortVersionsAsc(in)
	want := []string{"v1.0.0-alpha", "v1.0.0", "v1.2.0-rc.1", "v1.2.0", "v1.10.0"}
	if !reflect.DeepEqual(in, want) {
		t.Errorf("sortVersionsAsc = %v, want %v", in, want)
	}
}

func TestFilterNonPseudoValid(t *testing.T) {
	in := []string{
		"v1.2.3",
		"v1.2.3", // duplicate removed
		"garbage",
		"v0.0.0-20191109021931-daa7c04131f5", // pseudo removed
		"v2.0.0-rc.1",
	}
	got := filterNonPseudoValid(in)
	want := []string{"v1.2.3", "v2.0.0-rc.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterNonPseudoValid = %v, want %v", got, want)
	}
}

func mustModuleInfo(t *testing.T, v, ts string) ModuleInfo {
	t.Helper()
	var tm time.Time
	if ts != "" {
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t.Fatalf("bad time %q: %v", ts, err)
		}
		tm = parsed
	}
	return ModuleInfo{Version: v, Time: tm}
}

func TestChooseLatestSelects(t *testing.T) {
	tests := []struct {
		name  string
		infos []ModuleInfo
		want  string
	}{
		{
			"prefers highest release",
			[]ModuleInfo{mustModuleInfo(t, "v1.0.0", ""), mustModuleInfo(t, "v1.2.0", ""), mustModuleInfo(t, "v1.1.5-rc.1", "")},
			"v1.2.0",
		},
		{
			"falls back to prerelease",
			[]ModuleInfo{mustModuleInfo(t, "v1.0.0-alpha", ""), mustModuleInfo(t, "v1.0.0-beta", "")},
			"v1.0.0-beta",
		},
		{
			"falls back to newest pseudo by time",
			[]ModuleInfo{
				mustModuleInfo(t, "v0.0.0-20200101000000-aaaaaaaaaaaa", "2020-01-01T00:00:00Z"),
				mustModuleInfo(t, "v0.0.0-20210101000000-bbbbbbbbbbbb", "2021-01-01T00:00:00Z"),
			},
			"v0.0.0-20210101000000-bbbbbbbbbbbb",
		},
	}
	for _, tt := range tests {
		got, ok := chooseLatest(tt.infos)
		if !ok || got.Version != tt.want {
			t.Errorf("%s: chooseLatest = %q (ok=%v), want %q", tt.name, got.Version, ok, tt.want)
		}
	}
}

func TestChooseLatestEmpty(t *testing.T) {
	if _, ok := chooseLatest(nil); ok {
		t.Error("chooseLatest(nil) ok = true, want false")
	}
	if _, ok := chooseLatest([]ModuleInfo{{Version: "garbage"}}); ok {
		t.Error("chooseLatest(garbage) ok = true, want false")
	}
}

func TestEscapeUnescapeBangRoundTrip(t *testing.T) {
	cases := []struct {
		unescaped string
		escaped   string
	}{
		{"github.com/foo/bar", "github.com/foo/bar"},
		{"github.com/Azure/azure-sdk", "github.com/!azure/azure-sdk"},
		{"github.com/BurntSushi/toml", "github.com/!burnt!sushi/toml"},
		{"ALLCAPS", "!a!l!l!c!a!p!s"},
	}
	for _, c := range cases {
		if got := escapeBang(c.unescaped); got != c.escaped {
			t.Errorf("escapeBang(%q) = %q, want %q", c.unescaped, got, c.escaped)
		}
		got, err := unescapeBang(c.escaped)
		if err != nil {
			t.Errorf("unescapeBang(%q) error: %v", c.escaped, err)
			continue
		}
		if got != c.unescaped {
			t.Errorf("unescapeBang(%q) = %q, want %q", c.escaped, got, c.unescaped)
		}
	}
}

func TestUnescapeBangErrors(t *testing.T) {
	bad := []string{
		"trailing!", // trailing bang
		"foo!Bar",   // uppercase after bang is invalid
		"foo!1",     // non-letter after bang
	}
	for _, in := range bad {
		if _, err := unescapeBang(in); err == nil {
			t.Errorf("unescapeBang(%q) error = nil, want error", in)
		}
	}
}

func TestValidateRelPath(t *testing.T) {
	valid := []string{
		"github.com/foo/bar/@v/list",
		"a/b/c.info",
		"single",
	}
	invalid := []string{
		"",
		"/absolute",
		"../escape",
		"a/../b",
		"a/../../etc",
		`a\b`, // backslash
		"..",
	}
	for _, p := range valid {
		if err := validateRelPath(p); err != nil {
			t.Errorf("validateRelPath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range invalid {
		if err := validateRelPath(p); err == nil {
			t.Errorf("validateRelPath(%q) = nil, want error", p)
		}
	}
}

func TestParseProxyRequestParses(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		kind    proxyKind
		module  string
		version string
		ext     string
	}{
		{"list", "/github.com/foo/bar/@v/list", proxyList, "github.com/foo/bar", "", ""},
		{"latest", "/github.com/foo/bar/@latest", proxyLatest, "github.com/foo/bar", "", ""},
		{"version file with escape", "/github.com/!azure/foo/@v/v1.0.0.info", proxyVersionFile, "github.com/Azure/foo", "v1.0.0", ".info"},
	}
	for _, tt := range tests {
		req, err := parseProxyRequest(tt.path)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tt.name, err)
			continue
		}
		if req.Kind != tt.kind || req.Module != tt.module || req.Version != tt.version || req.Ext != tt.ext {
			t.Errorf("%s: parseProxyRequest(%q) = %+v", tt.name, tt.path, req)
		}
	}
}

func TestParseProxyRequestExtensions(t *testing.T) {
	for _, ext := range []string{".info", ".mod", ".zip", ".ziphash"} {
		req, err := parseProxyRequest("/m/@v/v1.0.0" + ext)
		if err != nil {
			t.Errorf("ext %s: %v", ext, err)
			continue
		}
		if req.Ext != ext {
			t.Errorf("ext = %q, want %q", req.Ext, ext)
		}
	}
}

func TestParseProxyRequestErrors(t *testing.T) {
	bad := []string{
		"/",
		"",
		"/github.com/foo/bar", // no /@v/ segment
		"/m/@v/v1.0.0.txt",    // unknown extension
	}
	for _, p := range bad {
		if _, err := parseProxyRequest(p); err == nil {
			t.Errorf("parseProxyRequest(%q) = nil error, want error", p)
		}
	}
}

func TestSequenceRangeString(t *testing.T) {
	tests := []struct {
		r    SequenceRange
		want string
	}{
		{SequenceRange{Start: 5, End: 5}, "5"},
		{SequenceRange{Start: 42, End: 47}, "42-47"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestParseSequenceSpec(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		got, err := parseSequenceSpec("42,45-47")
		if err != nil {
			t.Fatal(err)
		}
		want := []SequenceRange{{Start: 42, End: 42}, {Start: 45, End: 47}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("merges and sorts", func(t *testing.T) {
		got, err := parseSequenceSpec("5-7, 1, 6-9")
		if err != nil {
			t.Fatal(err)
		}
		want := []SequenceRange{{Start: 1, End: 1}, {Start: 5, End: 9}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("errors", func(t *testing.T) {
		bad := []string{"", "  ", "0", "-1", "abc", "5-3", "1-x", "x-1"}
		for _, s := range bad {
			if _, err := parseSequenceSpec(s); err == nil {
				t.Errorf("parseSequenceSpec(%q) = nil error, want error", s)
			}
		}
	})
}

func TestMergeSequenceRanges(t *testing.T) {
	tests := []struct {
		name string
		in   []SequenceRange
		want []SequenceRange
	}{
		{"empty", nil, nil},
		{
			"adjacent merge",
			[]SequenceRange{{1, 3}, {4, 6}},
			[]SequenceRange{{1, 6}},
		},
		{
			"overlap merge",
			[]SequenceRange{{1, 5}, {3, 8}},
			[]SequenceRange{{1, 8}},
		},
		{
			"disjoint stays split",
			[]SequenceRange{{1, 2}, {5, 6}},
			[]SequenceRange{{1, 2}, {5, 6}},
		},
		{
			"unsorted input",
			[]SequenceRange{{5, 6}, {1, 2}, {2, 3}},
			[]SequenceRange{{1, 3}, {5, 6}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeSequenceRanges(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeSequenceRanges = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandSequenceRanges(t *testing.T) {
	ranges := []SequenceRange{{1, 3}, {10, 11}}
	if got := expandSequenceRanges(ranges, 0); !reflect.DeepEqual(got, []int64{1, 2, 3, 10, 11}) {
		t.Errorf("expand unbounded = %v", got)
	}
	if got := expandSequenceRanges(ranges, 4); !reflect.DeepEqual(got, []int64{1, 2, 3, 10}) {
		t.Errorf("expand capped = %v, want [1 2 3 10]", got)
	}
}

func TestMissingRanges(t *testing.T) {
	present := map[int64]bool{42: true, 44: true, 47: true}
	got := missingRanges(41, 47, present)
	want := []SequenceRange{{Start: 41, End: 41}, {Start: 43, End: 43}, {Start: 45, End: 46}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("missingRanges = %v, want %v", got, want)
	}

	if got := missingRanges(5, 4, nil); got != nil {
		t.Errorf("missingRanges with end<start = %v, want nil", got)
	}

	allPresent := map[int64]bool{1: true, 2: true, 3: true}
	if got := missingRanges(1, 3, allPresent); got != nil {
		t.Errorf("missingRanges all present = %v, want nil", got)
	}
}

func TestRangesToStrings(t *testing.T) {
	got := rangesToStrings([]SequenceRange{{1, 1}, {5, 9}})
	want := []string{"1", "5-9"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rangesToStrings = %v, want %v", got, want)
	}
}

func TestBundleIDAndParse(t *testing.T) {
	if got := bundleIDForSequence(42); got != "go-bundle-000042" {
		t.Errorf("bundleIDForSequence(42) = %q", got)
	}
	if got := bundleIDForSequence(123456); got != "go-bundle-123456" {
		t.Errorf("bundleIDForSequence(123456) = %q", got)
	}

	seq, ok := parseBundleSeqFromManifestName("go-bundle-000042.manifest.json")
	if !ok || seq != 42 {
		t.Errorf("parseBundleSeqFromManifestName = %d, %v; want 42, true", seq, ok)
	}

	badNames := []string{
		"go-bundle-000042.tar.gz",
		"go-bundle-42.manifest.json", // wrong digit count
		"go-bundle-000042.manifest.json.sig",
		"random.json",
	}
	for _, n := range badNames {
		if _, ok := parseBundleSeqFromManifestName(n); ok {
			t.Errorf("parseBundleSeqFromManifestName(%q) ok = true, want false", n)
		}
	}
}

func TestFindBundleSequencesAndComplete(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Bundle 1 is complete; bundle 2 is missing its signature.
	write("go-bundle-000001.tar.gz")
	write("go-bundle-000001.manifest.json")
	write("go-bundle-000001.manifest.json.sig")
	write("go-bundle-000002.tar.gz")
	write("go-bundle-000002.manifest.json")
	write("unrelated.txt")

	seqs, err := findBundleSequences(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seqs, []int64{1, 2}) {
		t.Errorf("findBundleSequences = %v, want [1 2]", seqs)
	}

	complete := filterCompleteSequences(dir, seqs)
	if !reflect.DeepEqual(complete, []int64{1}) {
		t.Errorf("filterCompleteSequences = %v, want [1]", complete)
	}

	if !bundleCompleteInDir(dir, "go-bundle-000001") {
		t.Error("bundle 1 should be complete")
	}
	if bundleCompleteInDir(dir, "go-bundle-000002") {
		t.Error("bundle 2 should be incomplete")
	}
}

func TestFindBundleSequencesMissingDir(t *testing.T) {
	seqs, err := findBundleSequences(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if seqs != nil {
		t.Errorf("expected nil seqs for missing dir, got %v", seqs)
	}
}
