package main

import (
	"context"
	"crypto/md5" //nolint:gosec // recomputes the compact-index /versions MD5 fingerprint independently of the code under test
	"encoding/hex"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// -----------------------------------------------------------------------------
// Descriptor
// -----------------------------------------------------------------------------

// TestRubyGemsEcosystemDescriptor pins the registry descriptor: identity,
// the hook set, and the upstream-override flag — mirroring what
// TestEcosystemRegistryWiring enforces once the ecosystem is registered.
func TestRubyGemsEcosystemDescriptor(t *testing.T) {
	e := rubygemsEcosystem()
	if e.stream != streamRubyGems || e.label != "RubyGems" || e.title != "Ruby gems" || e.contentDesc != "gems" {
		t.Errorf("descriptor identity = %q %q %q %q", e.stream, e.label, e.title, e.contentDesc)
	}
	if e.collect == nil || e.watchCollect == nil || e.manifestContent == nil || e.validateContent == nil ||
		e.publish == nil || e.serve == nil || e.scanTree == nil || e.detail == nil {
		t.Error("descriptor is missing a dispatch hook")
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cfg LowConfig
	e.flags(fs, &cfg)
	if fs.Lookup("rubygems-url") == nil {
		t.Error("flags hook must register -rubygems-url")
	}
	m := BundleManifest{RubyGems: &RubyGemsManifest{Gems: []GemVersion{{Name: "a"}}}}
	if !e.manifestContent(m) || e.manifestContent(BundleManifest{}) {
		t.Error("manifestContent must key on the manifest's gem records")
	}
}

// -----------------------------------------------------------------------------
// Unit: naming/version validation
// -----------------------------------------------------------------------------

func TestRubyGemsValidateNames(t *testing.T) {
	validNames := []string{"rake", "rack-test", "a", "A0", "gem.name", "gem_name", "6to4"}
	invalidNames := []string{"", ".", "..", "-flag", "_private", ".hidden", "a/b", "a b", "café", strings.Repeat("x", 129)}
	for _, n := range validNames {
		if err := validateGemName(n); err != nil {
			t.Errorf("validateGemName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateGemName(n); err == nil {
			t.Errorf("validateGemName(%q) = nil, want error", n)
		}
	}

	validVersions := []string{"1", "13.2.1", "1.0.0.beta.2", "0.4.11", "1.0.0.rc1"}
	invalidVersions := []string{"", "v1.0.0", "1.0.0-x86", "-1", ".1", "1 .0", "1.0\n", "latest", strings.Repeat("1", 65)}
	for _, v := range validVersions {
		if err := validateGemVersion(v); err != nil {
			t.Errorf("validateGemVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVersions {
		if err := validateGemVersion(v); err == nil {
			t.Errorf("validateGemVersion(%q) = nil, want error", v)
		}
	}

	validPlatforms := []string{"x86_64-linux", "java", "arm64-darwin", "x64-mingw-ucrt", "universal-darwin-19"}
	invalidPlatforms := []string{"", "-linux", ".hidden", "a/b", "a b", strings.Repeat("p", 65)}
	for _, p := range validPlatforms {
		if err := validateGemPlatform(p); err != nil {
			t.Errorf("validateGemPlatform(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range invalidPlatforms {
		if err := validateGemPlatform(p); err == nil {
			t.Errorf("validateGemPlatform(%q) = nil, want error", p)
		}
	}

	if gemFilename("nokogiri", "1.16.0", "x86_64-linux") != "nokogiri-1.16.0-x86_64-linux.gem" ||
		gemFilename("rake", "13.2.1", "") != "rake-13.2.1.gem" {
		t.Error("gemFilename is not canonical")
	}
	if gemFileRel("rake-13.2.1.gem") != "rubygems/gems/rake-13.2.1.gem" {
		t.Errorf("gemFileRel = %q", gemFileRel("rake-13.2.1.gem"))
	}
}

// -----------------------------------------------------------------------------
// Unit: info-line parsing
// -----------------------------------------------------------------------------

func TestGemInfoLineParsing(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		raw  string
		want gemInfoLine
	}{
		{
			"no deps",
			"0.4.11 |checksum:" + sum + ",ruby:> 0.0.0,created_at:2009-07-25T18:01:32Z",
			gemInfoLine{Version: "0.4.11", Checksum: sum, Ruby: "> 0.0.0"},
		},
		{
			"deps with &-joined constraints",
			"4.0.0 dep1:>= 1.0&< 2.a,dep2:~> 3.0|checksum:" + sum + ",ruby:>= 2.2,rubygems:>= 1.8.11",
			gemInfoLine{
				Version: "4.0.0",
				Deps: []gemDep{
					{Name: "dep1", Reqs: []string{">= 1.0", "< 2.a"}},
					{Name: "dep2", Reqs: []string{"~> 3.0"}},
				},
				Checksum: sum, Ruby: ">= 2.2", RubyGems: ">= 1.8.11",
			},
		},
		{
			"platform variant with a dep",
			"1.2.3-x86_64-linux racc:~> 1.4|checksum:" + sum,
			gemInfoLine{
				Version: "1.2.3", Platform: "x86_64-linux",
				Deps:     []gemDep{{Name: "racc", Reqs: []string{"~> 1.4"}}},
				Checksum: sum,
			},
		},
		{
			"&-joined ruby requirement",
			"1.16.0 |checksum:" + sum + ",ruby:< 3.4.dev&>= 3.0,rubygems:> 1.3.1",
			gemInfoLine{Version: "1.16.0", Checksum: sum, Ruby: "< 3.4.dev&>= 3.0", RubyGems: "> 1.3.1"},
		},
	}
	for _, tt := range tests {
		got, err := parseGemInfoLine(tt.raw)
		if err != nil {
			t.Errorf("%s: parseGemInfoLine: %v", tt.name, err)
			continue
		}
		tt.want.Raw = tt.raw
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: parseGemInfoLine = %+v, want %+v", tt.name, got, tt.want)
		}
	}

	bad := []string{
		"",
		"---",
		"1.0.0 no requirement section",
		"1.0.0 |ruby:>= 2.0",                 // no checksum
		"1.0.0 |checksum:deadbeef",           // not a sha256
		"-flag |checksum:" + sum,             // invalid version token
		"1.0.0--bad |checksum:" + sum,        // invalid platform
		"1.0.0 ../evil:>= 1|checksum:" + sum, // invalid dependency name
		"1.0.0 nocolondep|checksum:" + sum,   // dependency without a requirement
	}
	for _, raw := range bad {
		if _, err := parseGemInfoLine(raw); err == nil {
			t.Errorf("parseGemInfoLine(%q) = nil error, want error", raw)
		}
	}

	// A whole info file: the "---" header and unparsable lines are skipped,
	// the rest is kept in file order.
	lines, err := parseGemInfoFile([]byte("---\n0.9.0 |checksum:" + sum + "\ngarbage\n1.0.0 |checksum:" + sum + "\n"))
	if err != nil || len(lines) != 2 || lines[0].Version != "0.9.0" || lines[1].Version != "1.0.0" {
		t.Errorf("parseGemInfoFile = %+v, %v", lines, err)
	}
	if _, err := parseGemInfoFile([]byte("---\n")); err == nil {
		t.Error("info file without valid releases should error")
	}
}

// -----------------------------------------------------------------------------
// Unit: Gem::Version ordering and Gem::Requirement matching
// -----------------------------------------------------------------------------

func TestGemCompareVersions(t *testing.T) {
	ordered := []string{"0.9.9", "1.0.0.a", "1.0.0.beta.2", "1.0.0.beta.10", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		if gemCompareVersions(a, b) >= 0 || gemCompareVersions(b, a) <= 0 {
			t.Errorf("want %s < %s", a, b)
		}
	}
	// Missing segments count as zero; alphabetic segments sort before numeric.
	if gemCompareVersions("1.0", "1.0.0") != 0 || gemCompareVersions("1", "1.0.0") != 0 {
		t.Error("missing segments must compare as zero")
	}
	if gemCompareVersions("1.0.a", "1.0.0") >= 0 || gemCompareVersions("1.0.a", "1.0") >= 0 {
		t.Error("want 1.0.a < 1.0.0 (alphabetic before numeric)")
	}
	// Numeric segments compare numerically, not lexically.
	if gemCompareVersions("1.10.0", "1.9.0") <= 0 {
		t.Error("want 1.10.0 > 1.9.0")
	}

	for v, want := range map[string]bool{
		"1.0.0": false, "13.2.1": false, "1.1.0.beta.1": true, "1.0.0.a": true, "0.9.0.rc1": true,
	} {
		if got := gemIsPrerelease(v); got != want {
			t.Errorf("gemIsPrerelease(%s) = %v, want %v", v, got, want)
		}
	}

	// Token ordering: versions ascending, the pure-ruby release before its
	// platform variants.
	tokens := []string{"1.0.0-java", "0.9.0", "1.0.0", "1.0.0-x86_64-linux"}
	sort.Slice(tokens, func(i, j int) bool { return gemTokenLess(tokens[i], tokens[j]) })
	if got := strings.Join(tokens, " "); got != "0.9.0 1.0.0 1.0.0-java 1.0.0-x86_64-linux" {
		t.Errorf("token order = %q", got)
	}
}

func TestGemReqSatisfied(t *testing.T) {
	tests := []struct {
		req, version string
		want         bool
	}{
		{"= 1.2.3", "1.2.3", true},
		{"= 1.2.3", "1.2.4", false},
		{"= 1.2", "1.2.0", true},
		{"!= 1.2.3", "1.2.3", false},
		{"!= 1.2.3", "1.2.4", true},
		{"> 1.0", "1.0.1", true},
		{"> 1.0", "1.0", false},
		{"< 2", "1.9.9", true},
		{"< 2", "2.0.0", false},
		{">= 1.0", "1.0.0", true},
		{">= 1.0", "0.9.9", false},
		{"<= 1.0", "1.0.0", true},
		{"<= 1.0", "1.0.1", false},
		// "~> 3.0" is >= 3.0 and < 4; "~> 3.0.3" is >= 3.0.3 and < 3.1.
		{"~> 3.0", "3.0.0", true},
		{"~> 3.0", "3.9.9", true},
		{"~> 3.0", "4.0.0", false},
		{"~> 3.0", "2.9.9", false},
		{"~> 3.0.3", "3.0.3", true},
		{"~> 3.0.3", "3.0.9", true},
		{"~> 3.0.3", "3.1.0", false},
		{"~> 3.0.3", "3.0.2", false},
		{"~> 3", "3.5.0", true},
		{"~> 3", "4.0.0", false},
		// ">= 0" is the default requirement and accepts anything — even a
		// prerelease like 0.0.a that compares below "0".
		{">= 0", "0.0.a", true},
		{">= 0", "9.9.9", true},
		// A bare version means "=".
		{"1.2", "1.2.0", true},
		{"1.2", "1.3", false},
		// Prerelease bounds compare with Gem::Version rules.
		{">= 1.0.0.beta.2", "1.0.0.beta.10", true},
		{"< 2.a", "1.9.9", true},
		{"< 2.a", "2.0.0", false},
		// An invalid or uncomputable bound never matches.
		{"~> alpha", "1.0.0", false},
		{">= not-a-version", "1.0.0", false},
	}
	for _, tt := range tests {
		if got := gemReqSatisfied(tt.req, tt.version); got != tt.want {
			t.Errorf("gemReqSatisfied(%q, %s) = %v, want %v", tt.req, tt.version, got, tt.want)
		}
	}
	if !gemReqsSatisfied([]string{">= 1.0", "< 2.a"}, "1.5.0") ||
		gemReqsSatisfied([]string{">= 1.0", "< 2.a"}, "2.0.0") {
		t.Error("gemReqsSatisfied must AND the &-joined constraints")
	}
}

// -----------------------------------------------------------------------------
// Unit: import-side manifest validation
// -----------------------------------------------------------------------------

func TestRubyGemsValidateRecords(t *testing.T) {
	payload := []byte("gem bytes")
	sum := aptSHA256(payload)
	line := func(token, checksum string) string {
		return token + " |checksum:" + checksum + ",ruby:>= 2.0"
	}
	rel := gemFileRel("mylib-1.0.0.gem")
	good := GemVersion{
		Name: "mylib", Version: "1.0.0", Filename: "mylib-1.0.0.gem",
		Path: rel, SHA256: sum, InfoLine: line("1.0.0", sum),
	}
	seen := map[string]bool{rel: true}
	files := []ManifestFile{{Path: rel, SHA256: sum, Size: int64(len(payload))}}

	if err := validateRubyGems(nil, nil, nil); err != nil {
		t.Errorf("empty gem list = %v, want nil", err)
	}
	if err := validateRubyGems([]GemVersion{good}, seen, files); err != nil {
		t.Errorf("valid record rejected: %v", err)
	}

	// A platform variant's canonical shape carries the platform in the
	// filename, the path, and the info line's version token.
	prel := gemFileRel("mylib-1.0.0-java.gem")
	variant := GemVersion{
		Name: "mylib", Version: "1.0.0", Platform: "java", Filename: "mylib-1.0.0-java.gem",
		Path: prel, SHA256: sum, InfoLine: line("1.0.0-java", sum),
	}
	if err := validateRubyGems([]GemVersion{variant}, map[string]bool{prel: true},
		[]ManifestFile{{Path: prel, SHA256: sum}}); err != nil {
		t.Errorf("valid platform record rejected: %v", err)
	}
	// Checksums compare case-insensitively, like hex digests should.
	upper := good
	upper.InfoLine = line("1.0.0", strings.ToUpper(sum))
	if err := validateRubyGems([]GemVersion{upper}, seen, files); err != nil {
		t.Errorf("uppercase checksum rejected: %v", err)
	}

	mutate := func(f func(*GemVersion)) GemVersion {
		g := good
		f(&g)
		return g
	}
	other := aptSHA256([]byte("other bytes"))
	bad := []struct {
		name string
		g    GemVersion
		seen map[string]bool
	}{
		{"invalid name", mutate(func(g *GemVersion) { g.Name = "../evil" }), seen},
		{"invalid version", mutate(func(g *GemVersion) { g.Version = "1.0.0/.." }), seen},
		{"invalid platform", mutate(func(g *GemVersion) { g.Platform = "../x" }), seen},
		{"non-canonical filename", mutate(func(g *GemVersion) { g.Filename = "mylib.gem" }), seen},
		{"non-canonical path", mutate(func(g *GemVersion) { g.Path = "rubygems/gems/sub/mylib-1.0.0.gem" }), seen},
		{"path outside rubygems tree", mutate(func(g *GemVersion) { g.Path = "npm/mylib-1.0.0.gem" }), seen},
		{"file not listed in manifest", good, map[string]bool{}},
		{"multi-line info line", mutate(func(g *GemVersion) {
			g.InfoLine = line("1.0.0", sum) + "\n2.0.0 |checksum:" + sum
		}), seen},
		{"unparsable info line", mutate(func(g *GemVersion) { g.InfoLine = "not an info line" }), seen},
		{"info line names another version", mutate(func(g *GemVersion) { g.InfoLine = line("2.0.0", sum) }), seen},
		{"info line names a platform variant", mutate(func(g *GemVersion) { g.InfoLine = line("1.0.0-java", sum) }), seen},
		{"info checksum mismatch", mutate(func(g *GemVersion) { g.InfoLine = line("1.0.0", other) }), seen},
		{"empty sha256", mutate(func(g *GemVersion) { g.SHA256 = "" }), seen},
		// The record's own claim must also match the byte-verified
		// manifest.files hash for its path.
		{"record sha disagrees with manifest.files", mutate(func(g *GemVersion) {
			g.SHA256 = other
			g.InfoLine = line("1.0.0", other)
		}), seen},
	}
	for _, tt := range bad {
		if err := validateRubyGems([]GemVersion{tt.g}, tt.seen, files); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Fixtures: fake compact-index upstream
// -----------------------------------------------------------------------------

// gemTestPayload is the deterministic fake .gem body for a release, so every
// assertion can recompute the expected bytes and SHA-256 (the low side never
// parses gem contents, only hashes them).
func gemTestPayload(name, token string) []byte {
	return []byte("fake-gem " + name + " " + token)
}

// fakeGemUpstream is an httptest compact-index server: per-gem /info files
// assembled line by line plus /gems/<file> payloads, with every request
// counted so tests can assert what was (not) fetched.
type fakeGemUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	info  map[string]string // gem name -> info lines (without the "---" header)
	gems  map[string][]byte // filename -> payload
	lines map[string]string // name + " " + token -> the exact upstream line
}

func newFakeGemUpstream(t *testing.T) *fakeGemUpstream {
	t.Helper()
	f := &fakeGemUpstream{hits: map[string]int{}, info: map[string]string{}, gems: map[string][]byte{}, lines: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		infoContent, okInfo := "", false
		if name, ok := strings.CutPrefix(r.URL.Path, "/info/"); ok {
			infoContent, okInfo = f.info[name]
		}
		var body []byte
		okGem := false
		if fn, ok := strings.CutPrefix(r.URL.Path, "/gems/"); ok {
			body, okGem = f.gems[fn]
		}
		f.mu.Unlock()
		switch {
		case okInfo:
			_, _ = io.WriteString(w, "---\n"+infoContent)
		case okGem:
			_, _ = w.Write(body)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// add registers one release: an info line whose checksum is the real SHA-256
// of the deterministic payload, plus the payload on the download route. deps
// is the raw dependency field ("dep1:>= 0.1&< 0.2,dep2:~> 1.0"), "" for none.
func (f *fakeGemUpstream) add(name, token, deps string) {
	payload := gemTestPayload(name, token)
	line := token + " " + deps + "|checksum:" + aptSHA256(payload) + ",ruby:>= 2.0,created_at:2024-01-01T00:00:00Z"
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info[name] += line + "\n"
	f.gems[name+"-"+token+".gem"] = payload
	f.lines[name+" "+token] = line
}

// tamper makes one download serve different bytes than its info line's
// checksum declares.
func (f *fakeGemUpstream) tamper(name, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gems[name+"-"+token+".gem"] = []byte("tampered bytes")
}

func (f *fakeGemUpstream) count(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[p]
}

// line returns the exact upstream info line registered for one release.
func (f *fakeGemUpstream) line(t *testing.T, name, token string) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.lines[name+" "+token]
	if !ok {
		t.Fatalf("no fixture line for %s %s", name, token)
	}
	return l
}

// rubygemsTestSetup stands up the fake upstream (mylib with a prerelease,
// platform variants, and a small dependency chain ending in a
// prerelease-only gem) plus a low server resolving against it.
func rubygemsTestSetup(t *testing.T) (*fakeGemUpstream, *LowServer) {
	t.Helper()
	reg := newFakeGemUpstream(t)
	reg.add("mylib", "0.9.0", "")
	reg.add("mylib", "1.0.0", "dep1:>= 0.1&< 0.2")
	reg.add("mylib", "1.0.0-x86_64-linux", "dep1:>= 0.1&< 0.2")
	reg.add("mylib", "1.0.0-java", "")
	reg.add("mylib", "1.1.0.beta.1", "")
	reg.add("dep1", "0.1.5", "dep2:>= 0")
	reg.add("dep1", "0.2.0", "")
	reg.add("dep2", "1.0.0.a", "")

	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), RubyGemsURL: reg.srv.URL}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return reg, ls
}

// rubygemsInstallBundle runs a collected bundle through the import-side
// hooks: it re-validates the manifest exactly like the importer does, places
// the artifacts at their manifest paths, and publishes the records. (The
// signature/extract half of the pipeline is shared machinery covered by the
// other streams' import tests; the rubygems stream is dispatched through it
// once the ecosystem is registered.)
func rubygemsInstallBundle(t *testing.T, ls *LowServer, hs *HighServer, bundleID string) *RubyGemsManifest {
	t.Helper()
	m := readBundleManifest(t, ls, bundleID)
	if m.RubyGems == nil {
		t.Fatalf("bundle %s carries no rubygems content", bundleID)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateRubyGems(m.RubyGems.Gems, seen, m.Files); err != nil {
		t.Fatalf("collected manifest fails import validation: %v", err)
	}
	for _, g := range m.RubyGems.Gems {
		abs := filepath.Join(hs.downloadDir, filepath.FromSlash(g.Path))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, gemTestPayload(g.Name, gemVersionFull(g.Version, g.Platform)))
	}
	if err := hs.publishRubyGems(m.RubyGems); err != nil {
		t.Fatalf("publishRubyGems: %v", err)
	}
	return m.RubyGems
}

// rubygemsTestServer wraps the serveRubyGems hook the way the high server's
// registry dispatch does, answering 418 for unclaimed paths so tests can
// tell "not mine" from "mine, but 404".
func rubygemsTestServer(t *testing.T, hs *HighServer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hs.serveRubyGems(w, r) {
			http.Error(w, "unclaimed", http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// rubygemsFetchVersions GETs the served /versions file and returns its
// per-gem entries as name -> [comma-joined tokens, md5].
func rubygemsFetchVersions(t *testing.T, base string) map[string][2]string {
	t.Helper()
	code, body := httpGet(t, base+"/rubygems/versions")
	if code != http.StatusOK {
		t.Fatalf("GET /rubygems/versions = %d: %s", code, body)
	}
	if !strings.HasPrefix(body, "created_at: ") {
		t.Fatalf("/versions missing created_at header: %q", body)
	}
	_, list, ok := strings.Cut(body, "---\n")
	if !ok {
		t.Fatalf("/versions missing --- separator: %q", body)
	}
	out := map[string][2]string{}
	for _, line := range strings.Split(strings.TrimSuffix(list, "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			t.Fatalf("/versions line %q is not 'name tokens md5'", line)
		}
		out[parts[0]] = [2]string{parts[1], parts[2]}
	}
	return out
}

// -----------------------------------------------------------------------------
// Integration: low -> high pipeline
// -----------------------------------------------------------------------------

// rubygemsAssertBundleManifest checks the first collect's exported manifest:
// the dependency closure with canonical paths, real hashes, and verbatim
// upstream info lines — and that the import-side validator accepts exactly
// what the collector produced.
func rubygemsAssertBundleManifest(t *testing.T, reg *fakeGemUpstream, ls *LowServer, bundleID string) {
	t.Helper()
	m := readBundleManifest(t, ls, bundleID)
	if m.RubyGems == nil || len(m.RubyGems.Gems) != 4 || len(m.Files) != 4 {
		t.Fatalf("bundle manifest = %+v files %+v, want 4 gems", m.RubyGems, m.Files)
	}
	// Records sort by name then path, which puts mylib's platform variant
	// ("...-x86..." < "....gem") ahead of the pure-ruby gem.
	wants := []struct{ name, version, platform string }{
		{"dep1", "0.1.5", ""},
		{"dep2", "1.0.0.a", ""},
		{"mylib", "1.0.0", "x86_64-linux"},
		{"mylib", "1.0.0", ""},
	}
	for i, want := range wants {
		g := m.RubyGems.Gems[i]
		token := gemVersionFull(want.version, want.platform)
		payload := gemTestPayload(want.name, token)
		filename := want.name + "-" + token + ".gem"
		if g.Name != want.name || g.Version != want.version || g.Platform != want.platform ||
			g.Filename != filename || g.Path != "rubygems/gems/"+filename || g.SHA256 != aptSHA256(payload) {
			t.Errorf("gem record %d = %+v, want %s@%s", i, g, want.name, token)
		}
		if g.InfoLine != reg.line(t, want.name, token) {
			t.Errorf("gem record %d info line %q is not the verbatim upstream line", i, g.InfoLine)
		}
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateRubyGems(m.RubyGems.Gems, seen, m.Files); err != nil {
		t.Errorf("collector output fails import validation: %v", err)
	}
}

// TestRubyGemsLowToHighPipeline is the full round-trip: greedy resolution
// against a fake compact index (dependency closure, a requested platform
// variant, prerelease rules), checksum-verified downloads into a signed
// bundle, import-side validation and publish, and the regenerated compact
// index the high side serves.
func TestRubyGemsLowToHighPipeline(t *testing.T) {
	reg, ls := rubygemsTestSetup(t)
	ctx := context.Background()

	res, err := ls.CollectRubyGems(ctx, RubyGemsCollectRequest{
		Gems: []string{"mylib"}, Platforms: []string{"x86_64-linux"},
	})
	if err != nil {
		t.Fatalf("CollectRubyGems: %v", err)
	}
	if res.BundleID != "rubygems-bundle-000001" || res.ExportedModules != 4 || res.Skipped || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	// The resolver fetched only what it selected: the newest release (not
	// the prerelease), the requested platform variant (not java), dep1's
	// release satisfying both &-joined constraints (not 0.2.0), and dep2's
	// prerelease fallback. Each /info file was fetched exactly once.
	for _, p := range []string{
		"/gems/mylib-0.9.0.gem",
		"/gems/mylib-1.1.0.beta.1.gem",
		"/gems/mylib-1.0.0-java.gem",
		"/gems/dep1-0.2.0.gem",
	} {
		if n := reg.count(p); n != 0 {
			t.Errorf("upstream %s fetched %d time(s), want 0", p, n)
		}
	}
	for _, p := range []string{"/info/mylib", "/info/dep1", "/info/dep2"} {
		if n := reg.count(p); n != 1 {
			t.Errorf("upstream %s fetched %d time(s), want 1", p, n)
		}
	}
	rubygemsAssertBundleManifest(t, reg, ls, res.BundleID)

	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rubygemsInstallBundle(t, ls, hs, res.BundleID)
	srv := rubygemsTestServer(t, hs)

	// /info/mylib carries the verbatim upstream lines under the "---"
	// header, the pure-ruby release before its platform variant.
	code, body := httpGet(t, srv.URL+"/rubygems/info/mylib")
	wantInfo := "---\n" + reg.line(t, "mylib", "1.0.0") + "\n" + reg.line(t, "mylib", "1.0.0-x86_64-linux") + "\n"
	if code != http.StatusOK || body != wantInfo {
		t.Errorf("GET /rubygems/info/mylib = %d %q, want %q", code, body, wantInfo)
	}
	versions := rubygemsFetchVersions(t, srv.URL)
	if len(versions) != 3 || versions["mylib"][0] != "1.0.0,1.0.0-x86_64-linux" ||
		versions["dep1"][0] != "0.1.5" || versions["dep2"][0] != "1.0.0.a" {
		t.Errorf("versions entries = %v", versions)
	}
	// The listed MD5 is the real MD5 of the served info file content (which
	// bundler re-checks), recomputed here independently from the fetched
	// bytes.
	sum := md5.Sum([]byte(body)) //nolint:gosec // independent recomputation of the served fingerprint
	if got := versions["mylib"][1]; got != hex.EncodeToString(sum[:]) {
		t.Errorf("mylib md5 = %s, want %s", got, hex.EncodeToString(sum[:]))
	}
	code, body = httpGet(t, srv.URL+"/rubygems/names")
	if code != http.StatusOK || body != "---\ndep1\ndep2\nmylib\n" {
		t.Errorf("GET /rubygems/names = %d %q", code, body)
	}
	// The .gem downloads round-trip byte-identically.
	code, body = httpGet(t, srv.URL+"/rubygems/gems/mylib-1.0.0-x86_64-linux.gem")
	if code != http.StatusOK || body != string(gemTestPayload("mylib", "1.0.0-x86_64-linux")) {
		t.Errorf("gem download = %d, %d byte(s)", code, len(body))
	}

	// A second bundle upserts into the same info file: earlier versions are
	// kept and the new one slots in ascending order.
	res2, err := ls.CollectRubyGems(ctx, RubyGemsCollectRequest{Gems: []string{"mylib@0.9.0"}, NoDeps: true})
	if err != nil {
		t.Fatalf("second CollectRubyGems: %v", err)
	}
	if res2.BundleID != "rubygems-bundle-000002" || res2.ExportedModules != 1 {
		t.Fatalf("second collect result: %+v", res2)
	}
	gems2 := rubygemsInstallBundle(t, ls, hs, res2.BundleID)
	code, body = httpGet(t, srv.URL+"/rubygems/info/mylib")
	wantInfo = "---\n" + reg.line(t, "mylib", "0.9.0") + "\n" + reg.line(t, "mylib", "1.0.0") + "\n" +
		reg.line(t, "mylib", "1.0.0-x86_64-linux") + "\n"
	if code != http.StatusOK || body != wantInfo {
		t.Errorf("info file after second import = %q, want earlier lines kept: %q", body, wantInfo)
	}
	if got := rubygemsFetchVersions(t, srv.URL)["mylib"][0]; got != "0.9.0,1.0.0,1.0.0-x86_64-linux" {
		t.Errorf("mylib tokens after second import = %q", got)
	}

	// Everything already forwarded: the collect skips and burns no sequence.
	res3, err := ls.CollectRubyGems(ctx, RubyGemsCollectRequest{Gems: []string{"mylib@0.9.0"}, NoDeps: true})
	if err != nil {
		t.Fatalf("third CollectRubyGems: %v", err)
	}
	if !res3.Skipped || res3.BundleID != "" {
		t.Fatalf("all-prior collect = %+v, want skipped", res3)
	}
	if seq := ls.peekSequence(streamRubyGems); seq != 3 {
		t.Errorf("next sequence = %d, want 3 (a skip must not burn a number)", seq)
	}

	// Index regeneration is gated on artifact presence: with artifacts
	// removed, the next publish drops their lines — and delists a gem whose
	// last artifact is gone, removing its stale info file.
	for _, f := range []string{"mylib-1.0.0-x86_64-linux.gem", "dep2-1.0.0.a.gem"} {
		if err := os.Remove(filepath.Join(hs.rubygemsGemsDir(), f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := hs.publishRubyGems(gems2); err != nil {
		t.Fatalf("republish after removal: %v", err)
	}
	code, body = httpGet(t, srv.URL+"/rubygems/info/mylib")
	if code != http.StatusOK || strings.Contains(body, "x86_64-linux") {
		t.Errorf("removed platform variant still listed: %q", body)
	}
	versions = rubygemsFetchVersions(t, srv.URL)
	if got := versions["mylib"][0]; got != "0.9.0,1.0.0" {
		t.Errorf("mylib tokens after artifact removal = %q", got)
	}
	if _, ok := versions["dep2"]; ok {
		t.Error("dep2 must be delisted once its only artifact is gone")
	}
	if code, _ := httpGet(t, srv.URL+"/rubygems/info/dep2"); code != http.StatusNotFound {
		t.Errorf("stale info file for dep2 should be gone, got %d", code)
	}
	code, body = httpGet(t, srv.URL+"/rubygems/names")
	if code != http.StatusOK || body != "---\ndep1\nmylib\n" {
		t.Errorf("names after artifact removal = %d %q", code, body)
	}
}

// TestRubyGemsCollectFailures covers the per-item failure paths: an
// unresolvable dependency is reported and skipped, unknown gems and missing
// pins fail hard, a checksum-tampering upstream is caught, and malformed
// requests are rejected before touching the network.
func TestRubyGemsCollectFailures(t *testing.T) {
	reg, ls := rubygemsTestSetup(t)
	ctx := context.Background()

	// A dependency whose /info file the upstream does not know is reported
	// and skipped; the rest of the batch still exports.
	reg.add("app", "1.0.0", "ghost:>= 1.0")
	res, err := ls.CollectRubyGems(ctx, RubyGemsCollectRequest{Gems: []string{"app"}})
	if err != nil {
		t.Fatalf("CollectRubyGems: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "ghost" {
		t.Fatalf("collect result = %+v, want app exported and ghost skipped", res)
	}

	// An unknown root gem leaves nothing to export: hard failure.
	if _, err := ls.CollectRubyGems(ctx, RubyGemsCollectRequest{Gems: []string{"nosuchgem"}}); err == nil ||
		!strings.Contains(err.Error(), "no gems could be fetched") {
		t.Fatalf("unknown gem collect = %v, want 'no gems could be fetched'", err)
	}

	// A pinned version the index does not list fails the same way.
	if _, err := ls.CollectRubyGems(ctx, RubyGemsCollectRequest{Gems: []string{"mylib@9.9.9"}}); err == nil {
		t.Fatal("missing pinned version should fail the collect")
	}

	// An upstream serving different bytes than its line's checksum declares
	// is caught by the streaming verification.
	reg.add("evil", "1.0.0", "")
	reg.tamper("evil", "1.0.0")
	_, err = ls.CollectRubyGems(ctx, RubyGemsCollectRequest{Gems: []string{"evil"}})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("tampered gem collect = %v, want a sha256 mismatch", err)
	}

	// Request validation rejects malformed specs and platforms.
	for _, req := range []RubyGemsCollectRequest{
		{},
		{Gems: []string{"../evil"}},
		{Gems: []string{"ok@bad-version"}},
		{Gems: []string{"mylib"}, Platforms: []string{"x/86"}},
		{Gems: []string{"mylib"}, Platforms: []string{"java", "java"}},
	} {
		if _, err := ls.CollectRubyGems(ctx, req); err == nil {
			t.Errorf("request %+v should be rejected", req)
		}
	}
}

// TestRubyGemsHandleCollectAdmin drives the admin JSON handler directly and
// confirms the empty/malformed request rejections.
func TestRubyGemsHandleCollectAdmin(t *testing.T) {
	_, ls := rubygemsTestSetup(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/rubygems/collect",
		strings.NewReader(`{"gems":["mylib"],"no_deps":true}`))
	res, err := ls.HandleRubyGemsCollect(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRubyGemsCollect: %v", err)
	}
	if res.BundleID != "rubygems-bundle-000001" || res.ExportedModules != 1 {
		t.Errorf("unexpected collect result: %+v", res)
	}
	for _, body := range []string{`{}`, `not json`, ``} {
		bad := httptest.NewRequest(http.MethodPost, "/admin/rubygems/collect", strings.NewReader(body))
		if _, err := ls.HandleRubyGemsCollect(context.Background(), bad); err == nil {
			t.Errorf("collect body %q should error", body)
		}
	}
}

// -----------------------------------------------------------------------------
// High side: publish hardening, serving hardening, dashboard
// -----------------------------------------------------------------------------

// rubygemsPublishOne installs one fake release into the high server's
// repository and publishes its record, regenerating the served index.
func rubygemsPublishOne(t *testing.T, hs *HighServer, name, version, platform string) {
	t.Helper()
	token := gemVersionFull(version, platform)
	payload := gemTestPayload(name, token)
	rel := gemFileRel(gemFilename(name, version, platform))
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, payload)
	m := &RubyGemsManifest{Gems: []GemVersion{{
		Name: name, Version: version, Platform: platform,
		Filename: gemFilename(name, version, platform), Path: rel,
		SHA256: aptSHA256(payload), InfoLine: token + " |checksum:" + aptSHA256(payload) + ",ruby:>= 2.0",
	}}}
	if err := hs.publishRubyGems(m); err != nil {
		t.Fatalf("publishRubyGems: %v", err)
	}
}

// TestRubyGemsPublishSkipsUnverifiedRecord proves the publish-side
// re-verification: a record whose installed artifact does not hash to its
// info line's checksum — or whose path escapes the gems tree — is logged and
// skipped, and never enters the served index.
func TestRubyGemsPublishSkipsUnverifiedRecord(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rubygemsPublishOne(t, hs, "good", "1.0.0", "")

	wrong := aptSHA256([]byte("something else"))
	rel := gemFileRel("bad-1.0.0.gem")
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, []byte("not the checksummed bytes"))
	records := []GemVersion{
		{
			Name: "bad", Version: "1.0.0", Filename: "bad-1.0.0.gem", Path: rel,
			SHA256: wrong, InfoLine: "1.0.0 |checksum:" + wrong + ",ruby:>= 2.0",
		},
		{
			Name: "sneaky", Version: "1.0.0", Filename: "sneaky-1.0.0.gem",
			Path:   "rubygems/gems/../../import-state.json",
			SHA256: wrong, InfoLine: "1.0.0 |checksum:" + wrong,
		},
		{
			Name: "shifty", Version: "1.0.0", Filename: "shifty-1.0.0.gem",
			Path:   gemFileRel("shifty-1.0.0.gem"),
			SHA256: wrong, InfoLine: "2.0.0 |checksum:" + wrong, // names another version
		},
	}
	if err := hs.publishRubyGems(&RubyGemsManifest{Gems: records}); err != nil {
		t.Fatalf("publish with skippable records: %v", err)
	}

	srv := rubygemsTestServer(t, hs)
	for _, name := range []string{"bad", "sneaky", "shifty"} {
		if code, _ := httpGet(t, srv.URL+"/rubygems/info/"+name); code != http.StatusNotFound {
			t.Errorf("unverified record %s must stay out of the index, got %d", name, code)
		}
	}
	code, body := httpGet(t, srv.URL+"/rubygems/names")
	if code != http.StatusOK || body != "---\ngood\n" {
		t.Errorf("names = %d %q, want only the verified gem", code, body)
	}
}

// TestRubyGemsServeHardening checks the /rubygems/ routes: the compact index
// and .gem downloads are served, everything else — the legacy Marshal-index
// endpoints, the private metadata store, the internal index layout,
// traversal shapes, and non-read methods — is rejected.
func TestRubyGemsServeHardening(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rubygemsPublishOne(t, hs, "mylib", "1.0.0", "")
	srv := rubygemsTestServer(t, hs)

	// Paths outside /rubygems are not claimed (the registry passes them on).
	if code, _ := httpGet(t, srv.URL+"/crates/index/config.json"); code != http.StatusTeapot {
		t.Errorf("foreign path claimed: %d", code)
	}

	for _, p := range []string{"/rubygems/versions", "/rubygems/names", "/rubygems/info/mylib", "/rubygems/gems/mylib-1.0.0.gem"} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, code)
		}
	}

	for _, p := range []string{
		"/rubygems",
		"/rubygems/",
		"/rubygems/specs.4.8.gz",        // legacy Marshal index: deliberately not served
		"/rubygems/api/v1/dependencies", // legacy dependency API: deliberately not served
		"/rubygems/quick/Marshal.4.8/mylib-1.0.0.gemspec.rz",
		"/rubygems/metadata/mylib.json", // private metadata store
		"/rubygems/index/versions",      // internal index layout stays hidden
		"/rubygems/index/info/mylib",
		"/rubygems/info/mylib/extra",
		"/rubygems/info/-flag",
		"/rubygems/info/nosuchgem",
		"/rubygems/gems/mylib-1.0.0", // not a .gem
		"/rubygems/gems/noversion.gem",
		"/rubygems/gems/-flag-1.0.0.gem",
		"/rubygems/gems/..%2f..%2fimport-state.json",
		"/rubygems/info/..%2f..%2fmetadata%2fmylib.json",
		"/rubygems/gems/mylib-1.0.0.gem%2f..%2f..%2fx",
	} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("GET %s = 200, want rejection", p)
		}
	}

	resp, err := http.Post(srv.URL+"/rubygems/versions", "text/plain", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /rubygems/versions = %d, want 405", resp.StatusCode)
	}
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/rubygems/gems/mylib-1.0.0.gem", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE gem = %d, want 405", resp.StatusCode)
	}
}

// TestRubyGemsDashboardListAndDetail covers the high-side dashboard helpers:
// gem/version listing (junk filtered, artifact-gated) and the per-release
// detail panel for both the pure-ruby gem and a platform variant.
func TestRubyGemsDashboardListAndDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rubygemsPublishOne(t, hs, "mylib", "1.0.0", "")
	rubygemsPublishOne(t, hs, "mylib", "1.0.0", "x86_64-linux")
	rubygemsPublishOne(t, hs, "mylib", "0.9.0", "")
	rubygemsPublishOne(t, hs, "alib", "2.0.0", "")

	// Junk in the metadata store is filtered out of the listings.
	writeFile(t, filepath.Join(hs.rubygemsMetadataDir(), "README.txt"), []byte("junk"))
	writeFile(t, filepath.Join(hs.rubygemsMetadataDir(), "-flag.json"), []byte(`{"lines":{}}`))

	mods, err := hs.listRubyGems()
	if err != nil {
		t.Fatalf("listRubyGems: %v", err)
	}
	if len(mods) != 2 || mods[0].Module != "alib" || mods[1].Module != "mylib" {
		t.Fatalf("listRubyGems = %+v, want alib and mylib", mods)
	}
	if got := strings.Join(mods[1].Versions, " "); got != "0.9.0 1.0.0 1.0.0-x86_64-linux" {
		t.Errorf("mylib versions = %q", got)
	}

	det, err := hs.rubygemsDetail("mylib@1.0.0-x86_64-linux")
	if err != nil {
		t.Fatalf("rubygemsDetail: %v", err)
	}
	if det.Title != "mylib" || det.Subtitle != "1.0.0-x86_64-linux" {
		t.Errorf("detail identity = %q %q", det.Title, det.Subtitle)
	}
	fields := map[string]string{}
	for _, f := range det.Fields {
		fields[f.Label] = f.Value
	}
	payload := gemTestPayload("mylib", "1.0.0-x86_64-linux")
	if fields["Gem"] != "mylib" || fields["Version"] != "1.0.0" || fields["Platform"] != "x86_64-linux" ||
		fields["SHA-256"] != aptSHA256(payload) || fields["Requires ruby"] != ">= 2.0" ||
		fields["Dependencies"] != "0" || fields["Registry path"] != "/rubygems/gems/mylib-1.0.0-x86_64-linux.gem" {
		t.Errorf("detail fields = %+v", fields)
	}
	if len(det.Downloads) != 1 || det.Downloads[0].URL != "/rubygems/gems/mylib-1.0.0-x86_64-linux.gem" ||
		det.Downloads[0].Label != "mylib-1.0.0-x86_64-linux.gem" {
		t.Errorf("detail downloads = %+v", det.Downloads)
	}

	// A release whose artifact vanished is hidden from list and detail.
	if err := os.Remove(filepath.Join(hs.rubygemsGemsDir(), "alib-2.0.0.gem")); err != nil {
		t.Fatal(err)
	}
	mods, err = hs.listRubyGems()
	if err != nil || len(mods) != 1 || mods[0].Module != "mylib" {
		t.Fatalf("listRubyGems after removal = %+v, %v", mods, err)
	}
	for _, spec := range []string{"alib@2.0.0", "mylib@9.9.9", "nope", "..@1.0.0", "mylib@../etc", "mylib@1.0.0-b@d"} {
		if _, err := hs.rubygemsDetail(spec); err == nil {
			t.Errorf("rubygemsDetail(%q) = nil error, want error", spec)
		}
	}
}
