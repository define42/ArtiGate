package main

// Tests for the NuGet ecosystem adapter (nuget.go): version normalization,
// comparison and range semantics, minimum-version dependency selection,
// manifest validation, nuspec parsing, and the full low->high pipeline against
// a fake NuGet v3 upstream, including the regenerated v3 feed the high side
// serves.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Unit: version normalization and comparison.
// -----------------------------------------------------------------------------

func TestNugetNormalizeVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.0", "1.0.0"},
		{"1", "1.0.0"},
		{"1.01.3", "1.1.3"},              // leading zeros removed
		{"1.2.3.0", "1.2.3"},             // zero legacy fourth part dropped
		{"1.2.3.4", "1.2.3.4"},           // non-zero fourth part kept
		{"1.2.3+meta", "1.2.3"},          // build metadata dropped
		{"1.2.3-Beta.1", "1.2.3-Beta.1"}, // pre-release casing preserved
		{"1.0.0-beta.1+sha.5", "1.0.0-beta.1"},
		{" 1.0 ", "1.0.0"},
		{"garbage", "garbage"},     // unparsable is returned unchanged
		{"1.2.3.4.5", "1.2.3.4.5"}, // too many parts: unchanged
	}
	for _, tt := range tests {
		if got := nugetNormalizeVersion(tt.in); got != tt.want {
			t.Errorf("nugetNormalizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func nugetTestParseVer(t *testing.T, s string) nugetVer {
	t.Helper()
	v, err := parseNugetVer(s)
	if err != nil {
		t.Fatalf("parseNugetVer(%q): %v", s, err)
	}
	return v
}

func TestNugetCompareVer(t *testing.T) {
	equal := [][2]string{
		{"1.0.0-ALPHA", "1.0.0-alpha"}, // pre-release ranks case-insensitively
		{"1.0", "1.0.0"},
		{"1.2.3+build.1", "1.2.3+build.2"}, // build metadata ignored
	}
	for _, p := range equal {
		if c := compareNugetVer(nugetTestParseVer(t, p[0]), nugetTestParseVer(t, p[1])); c != 0 {
			t.Errorf("compareNugetVer(%q, %q) = %d, want 0", p[0], p[1], c)
		}
	}
	less := [][2]string{
		{"1.0.0-alpha", "1.0.0"}, // release outranks any pre-release
		{"1.0.0-rc.99", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-beta"},
		{"1.0.0-beta.2", "1.0.0-beta.11"}, // numeric pre-release identifiers
		{"1.0.0-ALPHA", "1.0.0-beta"},     // ordering is case-insensitive too
		{"1.9.0", "1.10.0"},
		{"2.0.0", "10.0.0"},
		{"1.2.3", "1.2.3.4"}, // legacy fourth part outranks its absence
		{"1.2.3.4", "1.2.3.5"},
	}
	for _, p := range less {
		a, b := nugetTestParseVer(t, p[0]), nugetTestParseVer(t, p[1])
		if c := compareNugetVer(a, b); c >= 0 {
			t.Errorf("compareNugetVer(%q, %q) = %d, want < 0", p[0], p[1], c)
		}
		if c := compareNugetVer(b, a); c <= 0 { // antisymmetry
			t.Errorf("compareNugetVer(%q, %q) = %d, want > 0", p[1], p[0], c)
		}
	}
	// The string-level comparator falls back to lexical order only when a side
	// does not parse.
	if !nugetVersionLess("1.2.0", "1.10.0") {
		t.Error("nugetVersionLess(1.2.0, 1.10.0) = false, want numeric ordering")
	}
	if nugetVersionLess("junk", "1.0.0") {
		t.Error(`nugetVersionLess("junk", "1.0.0") = true, want lexical fallback`)
	}
}

// -----------------------------------------------------------------------------
// Unit: dependency ranges.
// -----------------------------------------------------------------------------

func nugetTestRange(t *testing.T, s string) nugetRange {
	t.Helper()
	r, err := parseNugetRange(s)
	if err != nil {
		t.Fatalf("parseNugetRange(%q): %v", s, err)
	}
	return r
}

func TestNugetParseRangeMatches(t *testing.T) {
	tests := []struct {
		rng, ver string
		want     bool
	}{
		{"1.0.0", "1.0.0", true}, // bare version: inclusive minimum, no maximum
		{"1.0.0", "9.0.0", true},
		{"1.0.0", "0.9.9", false},
		{"[1.0.0]", "1.0.0", true}, // exact pin
		{"[1.0.0]", "1.0", true},   // compares by value, not text
		{"[1.0.0]", "1.0.1", false},
		{"[1.0,2.0)", "1.0.0", true},
		{"[1.0,2.0)", "1.9.9", true},
		{"[1.0,2.0)", "2.0.0", false}, // exclusive maximum
		{"(1.0,2.0]", "1.0.0", false}, // exclusive minimum
		{"(1.0,2.0]", "1.0.1", true},
		{"(1.0,2.0]", "2.0.0", true},
		{"(,2.0]", "0.0.1", true}, // no minimum
		{"(,2.0]", "2.0.0", true},
		{"(,2.0]", "2.0.1", false},
		{"", "0.0.1", true}, // empty range accepts anything
		{"", "99.99.99", true},
		{"[1.5.0, )", "1.5.0", true}, // whitespace and an empty upper bound
		{"[1.5.0, )", "1.4.9", false},
		{"[1.0,2.0)", "2.0.0-alpha", true}, // a pre-release sorts below its release
		{"[1.0.0-alpha,)", "1.0.0-beta", true},
	}
	for _, tt := range tests {
		got := nugetTestRange(t, tt.rng).matches(nugetTestParseVer(t, tt.ver))
		if got != tt.want {
			t.Errorf("range %q matches %q = %v, want %v", tt.rng, tt.ver, got, tt.want)
		}
	}

	invalid := []string{"[a,b]", "[1.0", "(1.0)", "1.0,2.0)", "[]", "[1.0,2.0,3.0]", "*"}
	for _, s := range invalid {
		if _, err := parseNugetRange(s); err == nil {
			t.Errorf("parseNugetRange(%q) = nil error, want error", s)
		}
	}

	pre := []struct {
		rng  string
		want bool
	}{
		{"[1.0.0-alpha,)", true},
		{"(,2.0-rc]", true},
		{"[1.0,2.0)", false},
		{"1.0.0", false},
		{"", false},
	}
	for _, tt := range pre {
		if got := nugetTestRange(t, tt.rng).allowsPrerelease(); got != tt.want {
			t.Errorf("range %q allowsPrerelease = %v, want %v", tt.rng, got, tt.want)
		}
	}
}

func TestNugetPickMinimumAndLatest(t *testing.T) {
	asc := []string{"1.0.0-alpha", "1.0.0", "1.5.0", "2.0.0-beta.1", "2.0.0"}

	picks := []struct {
		rng, want string
	}{
		{"[1.2.0, )", "1.5.0"},             // lowest satisfying wins, not the newest
		{"", "1.0.0"},                      // stable preferred over an older pre-release
		{"[1.0.0-alpha, )", "1.0.0-alpha"}, // the range naming a pre-release admits them
	}
	for _, tt := range picks {
		got, err := pickNugetMinimum(asc, nugetTestRange(t, tt.rng))
		if err != nil || got != tt.want {
			t.Errorf("pickNugetMinimum(%q) = %q, %v, want %q", tt.rng, got, err, tt.want)
		}
	}
	// Only pre-releases satisfy: fall back to them even without a pre-release bound.
	got, err := pickNugetMinimum([]string{"2.0.0-beta.1"}, nugetTestRange(t, "[1.0, )"))
	if err != nil || got != "2.0.0-beta.1" {
		t.Errorf("pickNugetMinimum(prerelease only) = %q, %v", got, err)
	}
	if _, err := pickNugetMinimum(asc, nugetTestRange(t, "[3.0, )")); err == nil {
		t.Error("unsatisfiable range should error")
	}

	latest := []struct {
		versions []string
		want     string
	}{
		{asc, "2.0.0"}, // highest stable, ignoring the newer pre-release
		{[]string{"1.0.0", "2.0.0-beta.1"}, "1.0.0"},
		{[]string{"1.0.0-alpha", "2.0.0-beta.1"}, "2.0.0-beta.1"}, // pre-release fallback
	}
	for _, tt := range latest {
		got, err := pickNugetLatest(tt.versions)
		if err != nil || got != tt.want {
			t.Errorf("pickNugetLatest(%v) = %q, %v, want %q", tt.versions, got, err, tt.want)
		}
	}
	if _, err := pickNugetLatest(nil); err == nil {
		t.Error("pickNugetLatest(nil) should error")
	}
}

// -----------------------------------------------------------------------------
// Unit: naming, specs, and manifest validation.
// -----------------------------------------------------------------------------

func TestNugetValidateIDAndVersion(t *testing.T) {
	validIDs := []string{"Newtonsoft.Json", "a", "A1", "Serilog.Sinks.Console", "x_y-z.9"}
	invalidIDs := []string{"", "..", ".hidden", "-flag", "_x", "a/b", "a b", "@scope", strings.Repeat("x", 101)}
	for _, id := range validIDs {
		if err := validateNugetID(id); err != nil {
			t.Errorf("validateNugetID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range invalidIDs {
		if err := validateNugetID(id); err == nil {
			t.Errorf("validateNugetID(%q) = nil, want error", id)
		}
	}

	validVers := []string{"1.0.0", "13.0.3", "1.0.0-beta.1", "1.2.3.4", "1.0.0+meta"}
	invalidVers := []string{"", "latest", "v1.0", "-1.0", "1.0/..", "..", "1.0 beta"}
	for _, v := range validVers {
		if err := validateNugetVersion(v); err != nil {
			t.Errorf("validateNugetVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVers {
		if err := validateNugetVersion(v); err == nil {
			t.Errorf("validateNugetVersion(%q) = nil, want error", v)
		}
	}
}

func TestNugetParseSpecAndRequest(t *testing.T) {
	tests := []struct{ spec, id, version string }{
		{"Newtonsoft.Json", "Newtonsoft.Json", ""},
		{"Newtonsoft.Json@13.0.3", "Newtonsoft.Json", "13.0.3"},
		{"Foo@1.0", "Foo", "1.0.0"}, // pins are normalized
		{"Foo@1.2.3.0", "Foo", "1.2.3"},
		{"Foo@latest", "Foo", ""},
	}
	for _, tt := range tests {
		id, version, err := parseNugetSpec(tt.spec)
		if err != nil || id != tt.id || version != tt.version {
			t.Errorf("parseNugetSpec(%q) = (%q, %q, %v), want (%q, %q, nil)",
				tt.spec, id, version, err, tt.id, tt.version)
		}
	}
	for _, spec := range []string{"", "@1.0", "-flag@1.0", "Foo@^1.0", "Foo@..", "a b@1.0"} {
		if _, _, err := parseNugetSpec(spec); err == nil {
			t.Errorf("parseNugetSpec(%q) = nil error, want error", spec)
		}
	}

	if err := validateNugetRequest(NugetCollectRequest{}); err == nil {
		t.Error("empty collect request accepted")
	}
	if err := validateNugetRequest(NugetCollectRequest{Packages: []string{"ok.pkg", "bad name"}}); err == nil {
		t.Error("collect request with an invalid spec accepted")
	}
	if err := validateNugetRequest(NugetCollectRequest{Packages: []string{"Newtonsoft.Json@13.0.3"}}); err != nil {
		t.Errorf("valid collect request rejected: %v", err)
	}
}

func TestNugetValidatePackages(t *testing.T) {
	rel := nugetPackageRel("Foo.Bar", "1.2.3")
	if rel != "nuget/packages/foo.bar/1.2.3/foo.bar.1.2.3.nupkg" {
		t.Fatalf("nugetPackageRel = %q", rel)
	}
	seen := map[string]bool{rel: true}
	good := []NugetPackage{{ID: "Foo.Bar", Version: "1.2.3", Path: rel, SHA256: strings.Repeat("a", 64)}}
	if err := validateNugetPackages(good, seen); err != nil {
		t.Errorf("valid packages rejected: %v", err)
	}

	bad := []struct {
		name string
		pkg  NugetPackage
	}{
		{"traversal id", NugetPackage{ID: "..", Version: "1.2.3", Path: rel}},
		{"leading-dot id", NugetPackage{ID: ".hidden", Version: "1.2.3", Path: rel}},
		{"invalid version", NugetPackage{ID: "Foo.Bar", Version: "v1", Path: rel}},
		{"non-normalized version", NugetPackage{
			ID: "Foo.Bar", Version: "1.2.3.0",
			Path: "nuget/packages/foo.bar/1.2.3.0/foo.bar.1.2.3.0.nupkg",
		}},
		{"non-canonical path", NugetPackage{ID: "Foo.Bar", Version: "1.2.3", Path: "nuget/packages/foo.bar/1.2.3/other.nupkg"}},
		{"path outside the nuget tree", NugetPackage{ID: "Foo.Bar", Version: "1.2.3", Path: "npm/packages/foo.bar/1.2.3/foo.bar.1.2.3.nupkg"}},
		{"unlisted file", NugetPackage{ID: "Dep.One", Version: "2.0.0", Path: nugetPackageRel("Dep.One", "2.0.0")}},
	}
	for _, tt := range bad {
		if err := validateNugetPackages([]NugetPackage{tt.pkg}, seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Fixtures: nuspec / nupkg builders.
// -----------------------------------------------------------------------------

// nugetTestDep is one dependency edge written into a test nuspec.
type nugetTestDep struct {
	id  string
	rng string
}

// nugetTestNuspec renders the nuspec XML embedded in test packages; deps go
// into a single net8.0 dependency group.
func nugetTestNuspec(id, version string, deps ...nugetTestDep) []byte {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	sb.WriteString(`<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>`)
	fmt.Fprintf(&sb, "<id>%s</id><version>%s</version>", id, version)
	fmt.Fprintf(&sb, "<description>test package %s</description><authors>artigate tests</authors>", id)
	if len(deps) > 0 {
		sb.WriteString(`<dependencies><group targetFramework="net8.0">`)
		for _, d := range deps {
			fmt.Fprintf(&sb, "<dependency id=%q version=%q />", d.id, d.rng)
		}
		sb.WriteString(`</group></dependencies>`)
	}
	sb.WriteString(`</metadata></package>`)
	return []byte(sb.String())
}

type nugetTestZipEntry struct {
	name string
	body []byte
}

func nugetTestZip(t *testing.T, entries ...nugetTestZipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		fw, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// nugetTestNupkg builds a .nupkg archive whose root-level nuspec carries the
// given identity and dependencies, plus payload entries (a root-level
// non-nuspec file and a nested one) that nuspec extraction must skip over.
func nugetTestNupkg(t *testing.T, id, version string, deps ...nugetTestDep) []byte {
	t.Helper()
	return nugetTestZip(t,
		nugetTestZipEntry{"readme.txt", []byte("root-level non-nuspec entry")},
		nugetTestZipEntry{id + ".nuspec", nugetTestNuspec(id, version, deps...)},
		nugetTestZipEntry{"lib/net8.0/" + strings.ToLower(id) + ".dll", []byte("fake assembly bytes for " + id)},
	)
}

// -----------------------------------------------------------------------------
// Unit: nuspec parsing and extraction.
// -----------------------------------------------------------------------------

func TestNugetNuspecParsing(t *testing.T) {
	raw := nugetTestNuspec("Foo.Bar", "1.2.3", nugetTestDep{"Dep.One", "[2.0.0, 3.0.0)"})
	spec, err := parseNuspec(raw)
	if err != nil {
		t.Fatalf("parseNuspec: %v", err)
	}
	if spec.Metadata.ID != "Foo.Bar" || spec.Metadata.Version != "1.2.3" {
		t.Errorf("parsed identity = %s@%s", spec.Metadata.ID, spec.Metadata.Version)
	}
	groups := nuspecDepGroups(spec)
	if len(groups) != 1 || groups[0].TargetFramework != "net8.0" ||
		len(groups[0].Dependencies) != 1 ||
		groups[0].Dependencies[0] != (nugetDepRef{ID: "Dep.One", Range: "[2.0.0, 3.0.0)"}) {
		t.Errorf("nuspecDepGroups = %+v", groups)
	}

	// The legacy ungrouped <dependency> form maps to a group with no target
	// framework, and a dependency with a path-hostile id is dropped.
	legacy := []byte(`<package><metadata><id>Old.Pkg</id><version>1.0</version>` +
		`<dependencies><dependency id="Dep.One" version="1.0"/><dependency id="../evil" version="1.0"/></dependencies>` +
		`</metadata></package>`)
	spec, err = parseNuspec(legacy)
	if err != nil {
		t.Fatalf("parseNuspec(legacy): %v", err)
	}
	groups = nuspecDepGroups(spec)
	if len(groups) != 1 || groups[0].TargetFramework != "" ||
		len(groups[0].Dependencies) != 1 || groups[0].Dependencies[0].ID != "Dep.One" {
		t.Errorf("legacy nuspecDepGroups = %+v", groups)
	}

	if _, err := parseNuspec([]byte(`<package><metadata><id>x</id></metadata></package>`)); err == nil {
		t.Error("nuspec without a version accepted")
	}
	if _, err := parseNuspec([]byte("not xml at all <<<")); err == nil {
		t.Error("malformed XML accepted")
	}
}

func TestNugetExtractNuspec(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.nupkg")
	writeFile(t, good, nugetTestNupkg(t, "Foo.Bar", "1.2.3"))
	raw, spec, err := extractNuspec(good)
	if err != nil {
		t.Fatalf("extractNuspec: %v", err)
	}
	if spec.Metadata.ID != "Foo.Bar" || !bytes.Equal(raw, nugetTestNuspec("Foo.Bar", "1.2.3")) {
		t.Errorf("extracted nuspec = %s: %s", spec.Metadata.ID, raw)
	}

	// A nuspec below the archive root does not count.
	nested := filepath.Join(dir, "nested.nupkg")
	writeFile(t, nested, nugetTestZip(t, nugetTestZipEntry{"sub/Foo.Bar.nuspec", nugetTestNuspec("Foo.Bar", "1.2.3")}))
	if _, _, err := extractNuspec(nested); err == nil {
		t.Error("nupkg with only a nested nuspec accepted")
	}

	junk := filepath.Join(dir, "junk.nupkg")
	writeFile(t, junk, []byte("not a zip archive"))
	if _, _, err := extractNuspec(junk); err == nil {
		t.Error("non-zip nupkg accepted")
	}
}

// -----------------------------------------------------------------------------
// Fixtures: fake NuGet v3 upstream and low/high servers.
// -----------------------------------------------------------------------------

// fakeNugetUpstream is a minimal NuGet v3 source: a service index at
// /v3/index.json, a flat container under /flat/ serving canned version lists
// and .nupkg bytes, and registration leaves whose catalog documents publish
// each package's SHA-512 — the digest chain nuget.org serves.
type fakeNugetUpstream struct {
	srv      *httptest.Server
	versions map[string][]string // lowercase id -> published version strings
	nupkgs   map[string][]byte   // "<id>/<version>" (lowercase) -> archive bytes

	tamperHash bool // serve wrong catalog hashes to drive verification failures
	noHashes   bool // pretend the feed publishes no registration/catalog data
}

func fakeNugetService(t *testing.T) *fakeNugetUpstream {
	t.Helper()
	f := &fakeNugetUpstream{versions: map[string][]string{}, nupkgs: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/index.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"version": "3.0.0",
			"resources": []map[string]string{
				// A non-http PackageBaseAddress must be skipped in favor of the
				// usable one below it.
				{"@id": "ftp://mirror.invalid/flat/", "@type": "PackageBaseAddress/3.0.0"},
				{"@id": "http://" + r.Host + "/v3/registration/", "@type": "RegistrationsBaseUrl"},
				{"@id": "http://" + r.Host + "/flat/", "@type": "PackageBaseAddress/3.0.0"},
			},
		})
	})
	mux.HandleFunc("/v3/bare.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"version": "3.0.0", "resources": []map[string]string{}})
	})
	mux.HandleFunc("/v3/badjson.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not a service index"))
	})
	mux.HandleFunc("/flat/", f.handleFlat)
	mux.HandleFunc("/v3/registration/", f.handleRegistration)
	mux.HandleFunc("/v3/catalog/", f.handleCatalog)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// url returns the service index URL a LowServer should be configured with.
func (f *fakeNugetUpstream) url() string { return f.srv.URL + "/v3/index.json" }

// add publishes one package version with the given archive bytes.
func (f *fakeNugetUpstream) add(id, version string, nupkg []byte) {
	idl := strings.ToLower(id)
	f.versions[idl] = append(f.versions[idl], version)
	f.nupkgs[idl+"/"+strings.ToLower(version)] = nupkg
}

func (f *fakeNugetUpstream) handleFlat(w http.ResponseWriter, r *http.Request) {
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/flat/"), "/")
	switch {
	case len(segs) == 2 && segs[1] == "index.json" && f.versions[segs[0]] != nil:
		writeJSON(w, map[string]any{"versions": f.versions[segs[0]]})
	case len(segs) == 3 && segs[2] == segs[0]+"."+segs[1]+".nupkg" && f.nupkgs[segs[0]+"/"+segs[1]] != nil:
		_, _ = w.Write(f.nupkgs[segs[0]+"/"+segs[1]])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// leafKey maps a registration/catalog "<id>/<version>.json" path suffix to
// the published nupkgs key.
func (f *fakeNugetUpstream) leafKey(rest string) (string, bool) {
	key, ok := strings.CutSuffix(rest, ".json")
	if !ok || f.noHashes || f.nupkgs[key] == nil {
		return "", false
	}
	return key, true
}

// handleRegistration serves per-version registration leaves whose
// catalogEntry is the URL of the catalog document, like nuget.org's.
func (f *fakeNugetUpstream) handleRegistration(w http.ResponseWriter, r *http.Request) {
	key, ok := f.leafKey(strings.TrimPrefix(r.URL.Path, "/v3/registration/"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"catalogEntry": "http://" + r.Host + "/v3/catalog/" + key + ".json"})
}

// handleCatalog serves the catalog document carrying the package hash.
func (f *fakeNugetUpstream) handleCatalog(w http.ResponseWriter, r *http.Request) {
	key, ok := f.leafKey(strings.TrimPrefix(r.URL.Path, "/v3/catalog/"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sum := sha512.Sum512(f.nupkgs[key])
	if f.tamperHash {
		sum[0] ^= 0xff
	}
	writeJSON(w, map[string]any{
		"packageHash":          base64.StdEncoding.EncodeToString(sum[:]),
		"packageHashAlgorithm": "SHA512",
	})
}

// fakeNugetStandardUpstream publishes Root.Pkg 2.0.0 (depending on Dep.One
// "[1.5.0, )") and Dep.One 1.0.0/1.5.0/2.0.0, returning the upstream plus the
// Root.Pkg and Dep.One 1.5.0 archive bytes.
func fakeNugetStandardUpstream(t *testing.T) (*fakeNugetUpstream, []byte, []byte) {
	t.Helper()
	up := fakeNugetService(t)
	root := nugetTestNupkg(t, "Root.Pkg", "2.0.0", nugetTestDep{"Dep.One", "[1.5.0, )"})
	dep := nugetTestNupkg(t, "Dep.One", "1.5.0")
	up.add("Root.Pkg", "2.0.0", root)
	up.add("Dep.One", "1.0.0", nugetTestNupkg(t, "Dep.One", "1.0.0"))
	up.add("Dep.One", "1.5.0", dep)
	up.add("Dep.One", "2.0.0", nugetTestNupkg(t, "Dep.One", "2.0.0"))
	// An unparsable upstream version entry is dropped, never fatal.
	up.versions["dep.one"] = append(up.versions["dep.one"], "not!a!version")
	return up, root, dep
}

func nugetTestLowServer(t *testing.T, source string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), NugetSource: source}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// nugetTestCollectImport runs one collect on a fresh low server wired to the
// upstream, transfers the bundle, and imports it into a fresh high server.
func nugetTestCollectImport(t *testing.T, up *fakeNugetUpstream, req NugetCollectRequest) (*HighServer, ExportResult) {
	t.Helper()
	ls, priv := nugetTestLowServer(t, up.url())
	res, err := ls.CollectNuget(context.Background(), req)
	if err != nil {
		t.Fatalf("CollectNuget: %v", err)
	}
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of nuget bundle failed: %v", err)
	}
	return hs, res
}

// -----------------------------------------------------------------------------
// Feed assertion helpers.
// -----------------------------------------------------------------------------

func nugetTestAssertServiceIndex(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/nuget/v3/index.json")
	if code != http.StatusOK {
		t.Fatalf("service index status %d: %s", code, body)
	}
	var idx struct {
		Version   string `json:"version"`
		Resources []struct {
			ID   string `json:"@id"`
			Type string `json:"@type"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatalf("service index is not JSON: %v", err)
	}
	got := map[string]string{}
	for _, res := range idx.Resources {
		got[res.Type] = res.ID
	}
	want := map[string]string{
		"PackageBaseAddress/3.0.0":    base + "/nuget/v3-flatcontainer/",
		"RegistrationsBaseUrl":        base + "/nuget/v3/registration/",
		"RegistrationsBaseUrl/3.6.0":  base + "/nuget/v3/registration/",
		"SearchQueryService":          base + "/nuget/v3/search",
		"SearchQueryService/3.0.0-rc": base + "/nuget/v3/search",
	}
	for typ, wantURL := range want {
		if got[typ] != wantURL {
			t.Errorf("service index resource %s = %q, want %q", typ, got[typ], wantURL)
		}
	}
}

// nugetTestAssertVersions checks the flat-container versions list for id.
func nugetTestAssertVersions(t *testing.T, base, id string, want []string) {
	t.Helper()
	code, body := httpGet(t, base+"/nuget/v3-flatcontainer/"+id+"/index.json")
	if code != http.StatusOK {
		t.Fatalf("versions list for %s: status %d: %s", id, code, body)
	}
	var doc struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("versions list for %s is not JSON: %v", id, err)
	}
	if strings.Join(doc.Versions, " ") != strings.Join(want, " ") {
		t.Errorf("versions for %s = %v, want %v", id, doc.Versions, want)
	}
}

// nugetTestSearchHits queries the search route, returning totalHits and the
// first hit as "id@version".
func nugetTestSearchHits(t *testing.T, base, q string) (int, string) {
	t.Helper()
	code, body := httpGet(t, base+"/nuget/v3/search?q="+q)
	if code != http.StatusOK {
		t.Fatalf("search %q status %d: %s", q, code, body)
	}
	var doc struct {
		TotalHits int `json:"totalHits"`
		Data      []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("search response is not JSON: %v", err)
	}
	if doc.TotalHits != len(doc.Data) {
		t.Errorf("search %q: totalHits %d != len(data) %d", q, doc.TotalHits, len(doc.Data))
	}
	first := ""
	if len(doc.Data) > 0 {
		first = doc.Data[0].ID + "@" + doc.Data[0].Version
	}
	return doc.TotalHits, first
}

// nugetTestRegIndex mirrors the registration index response shape.
type nugetTestRegIndex struct {
	Count int `json:"count"`
	Items []struct {
		Count int    `json:"count"`
		Lower string `json:"lower"`
		Upper string `json:"upper"`
		Items []struct {
			CatalogEntry struct {
				ID               string `json:"id"`
				Version          string `json:"version"`
				Listed           bool   `json:"listed"`
				Description      string `json:"description"`
				Authors          string `json:"authors"`
				PackageContent   string `json:"packageContent"`
				DependencyGroups []struct {
					TargetFramework string `json:"targetFramework"`
					Dependencies    []struct {
						ID    string `json:"id"`
						Range string `json:"range"`
					} `json:"dependencies"`
				} `json:"dependencyGroups"`
			} `json:"catalogEntry"`
			PackageContent string `json:"packageContent"`
		} `json:"items"`
	} `json:"items"`
}

// -----------------------------------------------------------------------------
// Integration: full low -> high pipeline.
// -----------------------------------------------------------------------------

// TestNugetLowToHighPipeline is the full round-trip: resolve a package and its
// dependency graph against a fake v3 upstream (minimum-version selection),
// transfer the signed bundle, import it, and confirm the high side regenerated
// the whole v3 feed from the embedded nuspecs. It then re-collects with Force
// and proves re-importing identical content is idempotent.
func TestNugetLowToHighPipeline(t *testing.T) {
	up, rootNupkg, depNupkg := fakeNugetStandardUpstream(t)
	ls, priv := nugetTestLowServer(t, up.url())

	res, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Root.Pkg"}})
	if err != nil {
		t.Fatalf("CollectNuget: %v", err)
	}
	if res.BundleID != "nuget-bundle-000001" || res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	transferAptBundle(t, ls, hs, res.BundleID)
	imp, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("high import of nuget bundle failed: %v", err)
	}
	if len(imp.ImportedBundles) != 1 || imp.ImportedBundles[0] != res.BundleID {
		t.Fatalf("imported bundles = %+v", imp.ImportedBundles)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	nugetTestAssertServiceIndex(t, srv.URL)
	// Dependency resolution picked the minimum version satisfying "[1.5.0, )",
	// not the newest published one.
	nugetTestAssertVersions(t, srv.URL, "root.pkg", []string{"2.0.0"})
	nugetTestAssertVersions(t, srv.URL, "dep.one", []string{"1.5.0"})

	nugetTestAssertPipelineFlat(t, srv.URL, rootNupkg, depNupkg)
	nugetTestAssertPipelineRegistration(t, srv.URL)
	nugetTestAssertPipelineSearch(t, srv.URL)
	nugetTestAssertPipelineDashboard(t, srv.URL)

	// A forced re-collect packs the same content again on the next sequence;
	// re-importing it is idempotent (immutable files with identical bytes).
	res2, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Root.Pkg"}, Force: true})
	if err != nil {
		t.Fatalf("forced re-collect: %v", err)
	}
	if res2.BundleID != "nuget-bundle-000002" || res2.Sequence != 2 || res2.ExportedModules != 2 {
		t.Fatalf("unexpected forced collect result: %+v", res2)
	}
	transferAptBundle(t, ls, hs, res2.BundleID)
	imp2, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("re-import of identical content failed: %v", err)
	}
	if len(imp2.ImportedBundles) != 1 || imp2.ImportedBundles[0] != res2.BundleID {
		t.Fatalf("re-import bundles = %+v", imp2.ImportedBundles)
	}
	nugetTestAssertVersions(t, srv.URL, "root.pkg", []string{"2.0.0"})
	if code, got := httpGet(t, srv.URL+"/nuget/v3-flatcontainer/root.pkg/2.0.0/root.pkg.2.0.0.nupkg"); code != http.StatusOK || got != string(rootNupkg) {
		t.Errorf("nupkg after re-import: status %d, %d bytes (want %d)", code, len(got), len(rootNupkg))
	}

	// A version whose archive disappears stops being served everywhere — the
	// regenerated metadata alone must never resurrect it.
	if err := os.Remove(filepath.Join(hs.downloadDir, filepath.FromSlash(nugetPackageRel("Dep.One", "1.5.0")))); err != nil {
		t.Fatal(err)
	}
	if code, _ := httpGet(t, srv.URL+"/nuget/v3-flatcontainer/dep.one/index.json"); code != http.StatusNotFound {
		t.Errorf("versions list for a missing archive = %d, want 404", code)
	}
	if code, _ := httpGet(t, srv.URL+"/nuget/v3/registration/dep.one/index.json"); code != http.StatusNotFound {
		t.Errorf("registration for a missing archive = %d, want 404", code)
	}
	if hits, _ := nugetTestSearchHits(t, srv.URL, ""); hits != 1 {
		t.Errorf("search hits after archive removal = %d, want 1", hits)
	}
}

// nugetTestAssertPipelineFlat checks the flat-container downloads: exact
// archive bytes, the re-extracted nuspec, and case-insensitive routing.
func nugetTestAssertPipelineFlat(t *testing.T, base string, rootNupkg, depNupkg []byte) {
	t.Helper()
	code, got := httpGet(t, base+"/nuget/v3-flatcontainer/root.pkg/2.0.0/root.pkg.2.0.0.nupkg")
	if code != http.StatusOK || got != string(rootNupkg) {
		t.Errorf("root.pkg nupkg download: status %d, %d bytes (want %d)", code, len(got), len(rootNupkg))
	}
	code, got = httpGet(t, base+"/nuget/v3-flatcontainer/dep.one/1.5.0/dep.one.1.5.0.nupkg")
	if code != http.StatusOK || got != string(depNupkg) {
		t.Errorf("dep.one nupkg download: status %d, %d bytes (want %d)", code, len(got), len(depNupkg))
	}
	wantNuspec := nugetTestNuspec("Root.Pkg", "2.0.0", nugetTestDep{"Dep.One", "[1.5.0, )"})
	code, got = httpGet(t, base+"/nuget/v3-flatcontainer/root.pkg/2.0.0/root.pkg.nuspec")
	if code != http.StatusOK || got != string(wantNuspec) {
		t.Errorf("nuspec route: status %d body %q", code, got)
	}
	// Mixed-case route segments resolve case-insensitively.
	if code, _ := httpGet(t, base+"/nuget/v3-flatcontainer/Root.Pkg/index.json"); code != http.StatusOK {
		t.Errorf("mixed-case versions list = %d, want 200", code)
	}
	if code, _ := httpGet(t, base+"/nuget/v3-flatcontainer/ROOT.PKG/2.0.0/ROOT.PKG.2.0.0.nupkg"); code != http.StatusOK {
		t.Errorf("mixed-case nupkg download = %d, want 200", code)
	}
}

// nugetTestAssertPipelineRegistration checks the regenerated registration
// index: one inlined page whose catalog entry carries the canonical identity
// and the dependency groups from the embedded nuspec.
func nugetTestAssertPipelineRegistration(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/nuget/v3/registration/root.pkg/index.json")
	if code != http.StatusOK {
		t.Fatalf("registration status %d: %s", code, body)
	}
	var reg nugetTestRegIndex
	if err := json.Unmarshal([]byte(body), &reg); err != nil {
		t.Fatalf("registration is not JSON: %v", err)
	}
	if reg.Count != 1 || len(reg.Items) != 1 {
		t.Fatalf("registration pages = %+v", reg)
	}
	page := reg.Items[0]
	if page.Count != 1 || page.Lower != "2.0.0" || page.Upper != "2.0.0" || len(page.Items) != 1 {
		t.Fatalf("registration page = %+v", page)
	}
	entry := page.Items[0].CatalogEntry
	if entry.ID != "Root.Pkg" || entry.Version != "2.0.0" || !entry.Listed {
		t.Errorf("catalog entry identity = %+v", entry)
	}
	if entry.Description == "" || entry.Authors == "" {
		t.Errorf("catalog entry lost nuspec description/authors: %+v", entry)
	}
	wantContent := base + "/nuget/v3-flatcontainer/root.pkg/2.0.0/root.pkg.2.0.0.nupkg"
	if entry.PackageContent != wantContent || page.Items[0].PackageContent != wantContent {
		t.Errorf("packageContent = %q / %q, want %q", entry.PackageContent, page.Items[0].PackageContent, wantContent)
	}
	if len(entry.DependencyGroups) != 1 || entry.DependencyGroups[0].TargetFramework != "net8.0" {
		t.Fatalf("dependencyGroups = %+v", entry.DependencyGroups)
	}
	deps := entry.DependencyGroups[0].Dependencies
	if len(deps) != 1 || deps[0].ID != "Dep.One" || deps[0].Range != "[1.5.0, )" {
		t.Errorf("dependencies = %+v", deps)
	}
	// The registration route is case-insensitive too.
	if code, _ := httpGet(t, base+"/nuget/v3/registration/DEP.ONE/index.json"); code != http.StatusOK {
		t.Errorf("mixed-case registration = %d, want 200", code)
	}
	nugetTestAssertRegistrationLeaf(t, base)
}

// nugetTestAssertRegistrationLeaf follows the leaf URL the index items and the
// search results advertise as their "@id" — clients open version metadata
// through it, so it must resolve to a leaf document carrying the inlined
// catalog entry, the listed flag, and the backlink to the registration index.
func nugetTestAssertRegistrationLeaf(t *testing.T, base string) {
	t.Helper()
	leafURL := base + "/nuget/v3/registration/root.pkg/2.0.0.json"
	code, body := httpGet(t, leafURL)
	if code != http.StatusOK {
		t.Fatalf("registration leaf status %d: %s", code, body)
	}
	var leaf struct {
		ID           string `json:"@id"`
		Listed       bool   `json:"listed"`
		Registration string `json:"registration"`
		Content      string `json:"packageContent"`
		CatalogEntry struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"catalogEntry"`
	}
	if err := json.Unmarshal([]byte(body), &leaf); err != nil {
		t.Fatalf("registration leaf is not JSON: %v", err)
	}
	if leaf.ID != leafURL || !leaf.Listed {
		t.Errorf("leaf identity = %+v, want @id %q and listed", leaf, leafURL)
	}
	if leaf.Registration != base+"/nuget/v3/registration/root.pkg/index.json" {
		t.Errorf("leaf registration backlink = %q", leaf.Registration)
	}
	if want := base + "/nuget/v3-flatcontainer/root.pkg/2.0.0/root.pkg.2.0.0.nupkg"; leaf.Content != want {
		t.Errorf("leaf packageContent = %q, want %q", leaf.Content, want)
	}
	if leaf.CatalogEntry.ID != "Root.Pkg" || leaf.CatalogEntry.Version != "2.0.0" {
		t.Errorf("leaf catalog entry = %+v", leaf.CatalogEntry)
	}
	// Mixed case and non-normalized version spellings resolve to the same
	// leaf; an unmirrored version 404s.
	if code, _ := httpGet(t, base+"/nuget/v3/registration/ROOT.PKG/2.0.0.0.json"); code != http.StatusOK {
		t.Errorf("mixed-case/non-normalized leaf = %d, want 200", code)
	}
	if code, _ := httpGet(t, base+"/nuget/v3/registration/root.pkg/9.9.9.json"); code != http.StatusNotFound {
		t.Errorf("unmirrored version leaf = %d, want 404", code)
	}
}

func nugetTestAssertPipelineSearch(t *testing.T, base string) {
	t.Helper()
	if hits, first := nugetTestSearchHits(t, base, "root"); hits != 1 || first != "Root.Pkg@2.0.0" {
		t.Errorf("search q=root = %d hits, first %q", hits, first)
	}
	if hits, _ := nugetTestSearchHits(t, base, "nomatch"); hits != 0 {
		t.Errorf("search q=nomatch = %d hits, want 0", hits)
	}
	if hits, _ := nugetTestSearchHits(t, base, ""); hits != 2 {
		t.Errorf("search without q = %d hits, want 2", hits)
	}
}

// nugetTestAssertPipelineDashboard checks the mirrored packages appear in the
// dashboard tree and detail APIs.
func nugetTestAssertPipelineDashboard(t *testing.T, base string) {
	t.Helper()
	_, body := httpGet(t, base+"/ui/api/tree?eco=nuget&path=")
	if !strings.Contains(body, `"Root.Pkg"`) || !strings.Contains(body, `"Dep.One"`) {
		t.Errorf("nuget tree root missing packages: %s", body)
	}
	_, body = httpGet(t, base+"/ui/api/tree?eco=nuget&path=Root.Pkg")
	if !strings.Contains(body, `"Root.Pkg@2.0.0"`) {
		t.Errorf("nuget tree versions missing leaf: %s", body)
	}
	code, body := httpGet(t, base+"/ui/api/detail?eco=nuget&path=Root.Pkg@2.0.0")
	if code != http.StatusOK {
		t.Fatalf("nuget detail status %d: %s", code, body)
	}
	var d UIDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	if d.Title != "Root.Pkg" || d.Subtitle != "2.0.0" {
		t.Errorf("detail identity = %q %q", d.Title, d.Subtitle)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/nuget/v3-flatcontainer/root.pkg/2.0.0/root.pkg.2.0.0.nupkg" ||
		d.Downloads[0].Label != "root.pkg.2.0.0.nupkg" {
		t.Errorf("detail downloads = %+v", d.Downloads)
	}
	if code, _ := httpGet(t, base+"/ui/api/detail?eco=nuget&path=Root.Pkg@9.9.9"); code != http.StatusNotFound {
		t.Errorf("missing version detail = %d, want 404", code)
	}
	if code, _ := httpGet(t, base+"/ui/api/detail?eco=nuget&path=NoVersionSpec"); code != http.StatusNotFound {
		t.Errorf("invalid detail spec = %d, want 404", code)
	}
}

// -----------------------------------------------------------------------------
// Integration: collect variants.
// -----------------------------------------------------------------------------

// TestNugetCollectResolveDepsOff proves ResolveDeps=false mirrors only the
// listed packages, leaving the dependency unfetched.
func TestNugetCollectResolveDepsOff(t *testing.T) {
	up, _, _ := fakeNugetStandardUpstream(t)
	off := false
	hs, res := nugetTestCollectImport(t, up, NugetCollectRequest{Packages: []string{"Root.Pkg"}, ResolveDeps: &off})
	if res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()
	nugetTestAssertVersions(t, srv.URL, "root.pkg", []string{"2.0.0"})
	if code, _ := httpGet(t, srv.URL+"/nuget/v3-flatcontainer/dep.one/index.json"); code != http.StatusNotFound {
		t.Errorf("dep.one mirrored despite resolve_deps=false, status %d", code)
	}
}

// TestNugetCollectSharedDependency proves a dependency range already
// satisfied by an earlier pick is not resolved again, while an explicit pin of
// another version still mirrors both versions side by side.
func TestNugetCollectSharedDependency(t *testing.T) {
	up, _, _ := fakeNugetStandardUpstream(t)
	up.add("Second.Pkg", "1.0.0", nugetTestNupkg(t, "Second.Pkg", "1.0.0", nugetTestDep{"Dep.One", "[1.0.0, )"}))

	hs, res := nugetTestCollectImport(t, up, NugetCollectRequest{
		Packages: []string{"Root.Pkg", "Second.Pkg", "Dep.One@1.0.0"},
	})
	// Root.Pkg + Second.Pkg + the pinned Dep.One 1.0.0 + Dep.One 1.5.0 for
	// Root.Pkg's "[1.5.0, )". Second.Pkg's "[1.0.0, )" is already satisfied by
	// the pinned 1.0.0, so no third Dep.One version appears.
	if res.ExportedModules != 4 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()
	nugetTestAssertVersions(t, srv.URL, "dep.one", []string{"1.0.0", "1.5.0"})
	// The search entry describes the newest mirrored version.
	if hits, first := nugetTestSearchHits(t, srv.URL, "dep"); hits != 1 || first != "Dep.One@1.5.0" {
		t.Errorf("search q=dep = %d hits, first %q", hits, first)
	}
}

// TestNugetCollectUnresolvableDep proves dependencies that cannot be resolved
// (an unpublished package, an unparsable range) are skipped and reported while
// their parent still ships.
func TestNugetCollectUnresolvableDep(t *testing.T) {
	up := fakeNugetService(t)
	up.add("Lonely.Pkg", "1.0.0", nugetTestNupkg(t, "Lonely.Pkg", "1.0.0",
		nugetTestDep{"Ghost.Pkg", "[1.0.0, )"}, nugetTestDep{"Weird.Pkg", "[not-a-range"}))
	ls, _ := nugetTestLowServer(t, up.url())

	res, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Lonely.Pkg"}})
	if err != nil {
		t.Fatalf("CollectNuget: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	skipped := map[string]string{}
	for _, s := range res.SkippedModules {
		skipped[s.Module] = s.Version
	}
	if v, ok := skipped["Ghost.Pkg"]; !ok || v != "[1.0.0, )" {
		t.Errorf("Ghost.Pkg skip record = %+v", res.SkippedModules)
	}
	if v, ok := skipped["Weird.Pkg"]; !ok || v != "[not-a-range" {
		t.Errorf("Weird.Pkg skip record = %+v", res.SkippedModules)
	}
}

func TestNugetCollectAdminEndpoint(t *testing.T) {
	up, _, _ := fakeNugetStandardUpstream(t)
	ls, _ := nugetTestLowServer(t, up.url())
	srv := httptest.NewServer(ls)
	defer srv.Close()

	body := strings.NewReader(`{"packages":["Root.Pkg"],"resolve_deps":false}`)
	resp, err := http.Post(srv.URL+"/admin/nuget/collect", "application/json", body) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect admin status = %d, want 200: %s", resp.StatusCode, b)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "nuget-bundle-000001" || res.ExportedModules != 1 {
		t.Errorf("unexpected collect result: %+v", res)
	}

	// An empty request and a malformed body are rejected with 400.
	for name, payload := range map[string]string{"empty": `{}`, "malformed": `{"packages":`} {
		bad, err := http.Post(srv.URL+"/admin/nuget/collect", "application/json", strings.NewReader(payload)) //nolint:noctx // test request
		if err != nil {
			t.Fatal(err)
		}
		_ = bad.Body.Close()
		if bad.StatusCode != http.StatusBadRequest {
			t.Errorf("%s collect status = %d, want 400", name, bad.StatusCode)
		}
	}
}

// TestNugetCollectPinnedPrerelease pins a pre-release version with different
// casing than upstream publishes: the pin matches case-insensitively, the flat
// container lowercases the served version, and the catalog entry keeps the
// canonical casing from the nuspec.
func TestNugetCollectPinnedPrerelease(t *testing.T) {
	up := fakeNugetService(t)
	pre := nugetTestNupkg(t, "Pre.Pkg", "1.0.0-Beta.1")
	up.add("Pre.Pkg", "1.0.0-Beta.1", pre)

	hs, res := nugetTestCollectImport(t, up, NugetCollectRequest{Packages: []string{"Pre.Pkg@1.0.0-beta.1"}})
	if res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	nugetTestAssertVersions(t, srv.URL, "pre.pkg", []string{"1.0.0-beta.1"})
	code, got := httpGet(t, srv.URL+"/nuget/v3-flatcontainer/pre.pkg/1.0.0-beta.1/pre.pkg.1.0.0-beta.1.nupkg")
	if code != http.StatusOK || got != string(pre) {
		t.Errorf("prerelease nupkg download: status %d, %d bytes (want %d)", code, len(got), len(pre))
	}
	code, body := httpGet(t, srv.URL+"/nuget/v3/registration/pre.pkg/index.json")
	if code != http.StatusOK || !strings.Contains(body, `"1.0.0-Beta.1"`) {
		t.Errorf("registration should keep the canonical version casing: status %d body %s", code, body)
	}
}

// TestNugetCollectNuspecIdentityMismatch proves a package whose embedded
// nuspec names a different identity than requested is never bundled: alone it
// fails the collect, in a batch it is skipped and reported.
func TestNugetCollectNuspecIdentityMismatch(t *testing.T) {
	up := fakeNugetService(t)
	up.add("Evil.Pkg", "1.0.0", nugetTestNupkg(t, "Other.Pkg", "1.0.0")) // lies about its id
	up.add("Ver.Pkg", "1.0.0", nugetTestNupkg(t, "Ver.Pkg", "9.9.9"))    // lies about its version
	up.add("Good.Pkg", "1.0.0", nugetTestNupkg(t, "Good.Pkg", "1.0.0"))
	ls, _ := nugetTestLowServer(t, up.url())

	// As the only requested package, the mismatch fails the whole collect...
	_, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Evil.Pkg"}})
	if err == nil || !strings.Contains(err.Error(), "identifies as") {
		t.Fatalf("collect of only a lying package = %v, want an identity error", err)
	}
	// ...without burning a sequence number.
	if seq := ls.peekSequence(streamNuget); seq != 1 {
		t.Errorf("sequence advanced to %d after failed collect, want 1", seq)
	}

	// In a batch, lying packages are skipped and reported; the honest one ships.
	res, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Evil.Pkg", "Ver.Pkg", "Good.Pkg"}})
	if err != nil {
		t.Fatalf("batch collect: %v", err)
	}
	if res.BundleID != "nuget-bundle-000001" || res.ExportedModules != 1 || len(res.SkippedModules) != 2 {
		t.Fatalf("unexpected batch result: %+v", res)
	}
	skipped := map[string]string{}
	for _, s := range res.SkippedModules {
		skipped[s.Module] = s.Error
	}
	for _, id := range []string{"Evil.Pkg", "Ver.Pkg"} {
		if msg, ok := skipped[id]; !ok || !strings.Contains(msg, "identifies as") {
			t.Errorf("%s not skipped with an identity error: %v", id, res.SkippedModules)
		}
	}
}

func TestNugetCollectUpstreamErrors(t *testing.T) {
	up := fakeNugetService(t)
	up.add("Real.Pkg", "1.0.0", nugetTestNupkg(t, "Real.Pkg", "1.0.0"))

	// A service index without a usable PackageBaseAddress fails the collect.
	ls, _ := nugetTestLowServer(t, up.srv.URL+"/v3/bare.json")
	_, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Real.Pkg"}})
	if err == nil || !strings.Contains(err.Error(), "PackageBaseAddress") {
		t.Fatalf("collect against a bare service index = %v, want a PackageBaseAddress error", err)
	}

	// A service index that is not JSON, or missing altogether, fails too.
	lsBadJSON, _ := nugetTestLowServer(t, up.srv.URL+"/v3/badjson.json")
	_, err = lsBadJSON.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Real.Pkg"}})
	if err == nil || !strings.Contains(err.Error(), "parse service index") {
		t.Fatalf("collect against a non-JSON service index = %v", err)
	}
	lsMissing, _ := nugetTestLowServer(t, up.srv.URL+"/v3/missing.json")
	_, err = lsMissing.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Real.Pkg"}})
	if err == nil || !strings.Contains(err.Error(), "service index") {
		t.Fatalf("collect against a missing service index = %v", err)
	}

	// An id the upstream never published (404 on the versions list) and a pin
	// to an unpublished version both fail without burning a sequence number.
	ls2, _ := nugetTestLowServer(t, up.url())
	_, err = ls2.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"No.Such.Pkg"}})
	if err == nil || !strings.Contains(err.Error(), "no nuget packages could be fetched") {
		t.Fatalf("collect of unknown package = %v", err)
	}
	_, err = ls2.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Real.Pkg@2.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "not found upstream") {
		t.Fatalf("collect of unknown pinned version = %v", err)
	}
	if _, err := ls2.CollectNuget(context.Background(), NugetCollectRequest{}); err == nil {
		t.Error("collect with no packages accepted")
	}
	if seq := ls2.peekSequence(streamNuget); seq != 1 {
		t.Errorf("sequence advanced to %d after failed collects, want 1", seq)
	}

	// Without an explicit source, collection targets the public v3 endpoint.
	if got := ls2.nugetSource(); got != up.url() {
		t.Errorf("configured nugetSource = %q, want %q", got, up.url())
	}
	lsDefault, _ := nugetTestLowServer(t, "")
	if got := lsDefault.nugetSource(); got != defaultNugetSource {
		t.Errorf("default nugetSource = %q, want %q", got, defaultNugetSource)
	}
}

// TestNugetResourceURLOK pins the service-index resource gate: only absolute
// http(s) URLs with a host and no embedded login are usable fetch bases (the
// old prefix check accepted anything starting with "http", httpfoo:// schemes
// and credentialed URLs included).
func TestNugetResourceURLOK(t *testing.T) {
	for _, u := range []string{"http://host.example/flat/", "https://host.example/v3/registration/"} {
		if !nugetResourceURLOK(u) {
			t.Errorf("nugetResourceURLOK(%q) = false, want true", u)
		}
	}
	bad := []string{
		"", "httpfoo://host.example/flat/", "ftp://host.example/flat/", "http://",
		"/v3/flat/", "http://user:pw@host.example/flat/", "http://ho st.example/flat/",
	}
	for _, u := range bad {
		if nugetResourceURLOK(u) {
			t.Errorf("nugetResourceURLOK(%q) = true, want false", u)
		}
	}
}

// TestNugetUpstreamDigestPinning drives the registration/catalog digest path:
// a catalog hash that does not match the served .nupkg fails the package (and
// with every package failing, the whole collect), while a feed publishing no
// hashes still collects with integrity resting on TLS.
func TestNugetUpstreamDigestPinning(t *testing.T) {
	up, _, _ := fakeNugetStandardUpstream(t)
	up.tamperHash = true
	ls, _ := nugetTestLowServer(t, up.url())
	_, err := ls.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Root.Pkg@2.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "sha512 mismatch") {
		t.Fatalf("collect with a tampered catalog hash = %v, want a sha512 mismatch", err)
	}

	up.tamperHash, up.noHashes = false, true
	lsPlain, _ := nugetTestLowServer(t, up.url())
	if _, err := lsPlain.CollectNuget(context.Background(), NugetCollectRequest{Packages: []string{"Root.Pkg@2.0.0"}}); err != nil {
		t.Fatalf("collect against a hashless feed = %v, want success", err)
	}
}

// TestNugetCatalogEntryShapes covers the two catalogEntry encodings — the
// entry object inlined in the leaf, and the URL of a catalog document — plus
// the refusals that fall back to TLS-only integrity.
func TestNugetCatalogEntryShapes(t *testing.T) {
	ctx := context.Background()
	sum := sha256.Sum256([]byte("nupkg bytes"))
	b64 := base64.StdEncoding.EncodeToString(sum[:])

	inline := json.RawMessage(`{"packageHash":"` + b64 + `","packageHashAlgorithm":"SHA256"}`)
	entry, ok := fetchNugetCatalogEntry(ctx, inline)
	if !ok {
		t.Fatal("inline catalogEntry rejected")
	}
	if typ, digest := nugetEntryDigest(entry); typ != "sha256" || digest != hex.EncodeToString(sum[:]) {
		t.Errorf("inline entry digest = %q %q", typ, digest)
	}

	// The catalogEntry-as-URL shape fetches the catalog document.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"packageHash": b64, "packageHashAlgorithm": "SHA256"})
	}))
	defer srv.Close()
	entry, ok = fetchNugetCatalogEntry(ctx, json.RawMessage(`"`+srv.URL+`/entry.json"`))
	if !ok || entry.PackageHash != b64 {
		t.Errorf("catalog-document entry = %+v ok=%v", entry, ok)
	}

	// Junk shapes and unfetchable/unsafe catalog URLs report no entry.
	for _, raw := range []string{"", `42`, `"ftp://host.invalid/entry.json"`, `"http://user:pw@host.invalid/entry.json"`, `{"packageHash":""}`} {
		if _, ok := fetchNugetCatalogEntry(ctx, json.RawMessage(raw)); ok {
			t.Errorf("catalogEntry %q accepted", raw)
		}
	}

	// Unknown algorithms, wrong-length hashes, and undecodable hashes yield no
	// digest (TLS-only fallback), never a bogus verification input.
	for _, e := range []nugetCatalogEntry{
		{PackageHash: b64, PackageHashAlgorithm: "MD5"},
		{PackageHash: b64, PackageHashAlgorithm: "SHA512"}, // 32 bytes, not 64
		{PackageHash: "!!!not base64!!!", PackageHashAlgorithm: "SHA256"},
		{PackageHash: "", PackageHashAlgorithm: "SHA256"},
	} {
		if typ, digest := nugetEntryDigest(e); typ != "" || digest != "" {
			t.Errorf("nugetEntryDigest(%+v) = %q %q, want empty", e, typ, digest)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration: high-side hardening and resilience.
// -----------------------------------------------------------------------------

func TestNugetHighRouteHardening(t *testing.T) {
	up := fakeNugetService(t)
	up.add("Solo.Pkg", "1.0.0", nugetTestNupkg(t, "Solo.Pkg", "1.0.0"))
	hs, _ := nugetTestCollectImport(t, up, NugetCollectRequest{Packages: []string{"Solo.Pkg"}})
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Wrong or hostile paths 404 instead of touching anything outside the tree.
	for _, p := range []string{
		"/nuget/v3-flatcontainer/../x/index.json",
		"/nuget/v3-flatcontainer/..%2f..%2fimport-state.json",
		"/nuget/v3-flatcontainer/solo.pkg/1.0.0/other.name.nupkg", // wrong filename
		"/nuget/v3-flatcontainer/solo.pkg/1.0.0/solo.pkg.nuspec.bak",
		"/nuget/v3-flatcontainer/solo.pkg/1.0.0", // missing filename segment
		"/nuget/v3-flatcontainer/missing.pkg/index.json",
		"/nuget/v3-flatcontainer/solo.pkg/9.9.9/solo.pkg.9.9.9.nupkg", // unknown version
		"/nuget/v3-flatcontainer/solo.pkg/9.9.9/solo.pkg.nuspec",      // nuspec of an unknown version
		"/nuget/v3/registration/../solo.pkg/index.json",
		"/nuget/v3/registration/missing.pkg/index.json",
		"/nuget/v3/registration/solo.pkg/extra/index.json",
		"/nuget/v3/registration/solo.pkg/..%2f1.0.0.json", // hostile leaf version
		"/nuget/v3/registration/solo.pkg/notaversion.json",
		"/nuget/v3/registration/solo.pkg/1.0.0.json.bak",
		"/nuget/v3/registration/missing.pkg/1.0.0.json",
		"/nuget/v3/nope",
	} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}

	// Only read methods are allowed anywhere under /nuget/.
	for _, p := range []string{"/nuget/v3/index.json", "/nuget/v3-flatcontainer/solo.pkg/index.json"} {
		resp, err := http.Post(srv.URL+p, "application/json", strings.NewReader("{}")) //nolint:noctx // test request
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", p, resp.StatusCode)
		}
	}
}

// nugetTestWriteSignedBundle builds a signed nuget bundle in landing from raw
// archive bytes (spec keys are "Id@Version"), reusing the production tar/sign
// helpers, so high-side behavior can be probed with content the low side would
// never produce.
func nugetTestWriteSignedBundle(t *testing.T, landing string, priv ed25519.PrivateKey, seq int64, nupkgs map[string][]byte) {
	t.Helper()
	src := t.TempDir()
	var files []ManifestFile
	var pkgs []NugetPackage
	for spec, content := range nupkgs {
		id, version, _ := strings.Cut(spec, "@")
		rel := nugetPackageRel(id, version)
		abs := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, content)
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, mf)
		pkgs = append(pkgs, NugetPackage{ID: id, Version: version, Path: rel, SHA256: mf.SHA256})
	}
	bundleID := bundleIDFor(streamNuget, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamNuget,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Ecosystems:       []string{"nuget"},
		Nuget:            &NugetManifest{Packages: pkgs},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestBytes)
	if err := createTarGzAtomic(context.Background(), filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json"), manifestBytes)
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
}

// TestNugetImportSkipsCorruptNupkg proves one unparseable archive in a bundle
// is skipped (its version 404s) while the rest of the bundle imports and
// serves — a bad artifact must never wedge the stream.
func TestNugetImportSkipsCorruptNupkg(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	nugetTestWriteSignedBundle(t, hs.cfg.Landing, priv, 1, map[string][]byte{
		"Good.Pkg@1.0.0":   nugetTestNupkg(t, "Good.Pkg", "1.0.0"),
		"Broken.Pkg@1.0.0": []byte("not a zip archive at all"),
	})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import with a corrupt member failed entirely: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	nugetTestAssertVersions(t, srv.URL, "good.pkg", []string{"1.0.0"})
	if code, _ := httpGet(t, srv.URL+"/nuget/v3-flatcontainer/broken.pkg/index.json"); code != http.StatusNotFound {
		t.Errorf("broken package should 404, got %d", code)
	}
	if hits, _ := nugetTestSearchHits(t, srv.URL, ""); hits != 1 {
		t.Errorf("search hits = %d, want 1", hits)
	}

	// A bundle without a nuget section publishes nothing and is a no-op.
	if err := hs.publishNuget(nil); err != nil {
		t.Errorf("publishNuget(nil) = %v, want nil", err)
	}
}

// TestNugetPublishPackageRejections exercises the high side's per-package
// re-verification directly: the served metadata is regenerated only when the
// archive's embedded nuspec agrees with the manifest record.
func TestNugetPublishPackageRejections(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rel := nugetPackageRel("Foo.Bar", "1.2.3")
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, nugetTestNupkg(t, "Foo.Bar", "1.2.3"))

	if err := hs.publishNugetPackage(NugetPackage{ID: "Foo.Bar", Version: "1.2.3", Path: rel}); err != nil {
		t.Fatalf("publish of a consistent package: %v", err)
	}
	// The id comparison is case-insensitive: casing differences are fine.
	if err := hs.publishNugetPackage(NugetPackage{ID: "FOO.BAR", Version: "1.2.3", Path: rel}); err != nil {
		t.Errorf("publish with different id casing: %v", err)
	}

	bad := []struct {
		name string
		pkg  NugetPackage
	}{
		{"invalid id", NugetPackage{ID: "..", Version: "1.2.3", Path: rel}},
		{"invalid version", NugetPackage{ID: "Foo.Bar", Version: "v1", Path: rel}},
		{"path outside the nuget tree", NugetPackage{ID: "Foo.Bar", Version: "1.2.3", Path: "go/foo.nupkg"}},
		{"nuspec id mismatch", NugetPackage{ID: "Other.Pkg", Version: "1.2.3", Path: rel}},
		{"nuspec version mismatch", NugetPackage{ID: "Foo.Bar", Version: "9.9.9", Path: rel}},
		{"missing archive", NugetPackage{ID: "Foo.Bar", Version: "1.2.4", Path: nugetPackageRel("Foo.Bar", "1.2.4")}},
	}
	for _, tt := range bad {
		if err := hs.publishNugetPackage(tt.pkg); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// TestNugetImportRejectsNonNormalizedManifest proves the high side re-checks
// manifest package records at import time: a non-normalized version is
// rejected outright (moved aside), never installed.
func TestNugetImportRejectsNonNormalizedManifest(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	nugetTestWriteSignedBundle(t, hs.cfg.Landing, priv, 1, map[string][]byte{
		"Bad.Pkg@1.0": nugetTestNupkg(t, "Bad.Pkg", "1.0"),
	})
	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if res.Imported || len(res.RejectedBundles) != 1 || res.RejectedBundles[0] != "nuget-bundle-000001" {
		t.Fatalf("bundle with a non-normalized version should be rejected: %+v", res)
	}
}

// TestNugetUIWiring asserts both dashboards expose the NuGet ecosystem.
func TestNugetUIWiring(t *testing.T) {
	for _, want := range []string{`data-view="nuget"`, `id="view-nuget"`, "collectNuget", "scheduleNuget", `/admin/nuget/collect`} {
		if !strings.Contains(lowUIHTML, want) {
			t.Errorf("low-side UI missing %s", want)
		}
	}
	if !strings.Contains(uiIndexHTML, `data-view="nuget"`) {
		t.Error(`high-side UI missing data-view="nuget"`)
	}
	for _, want := range []string{"nugetGuideSection", `nuget: "NuGet packages"`} {
		if !strings.Contains(uiAppJS, want) {
			t.Errorf("high-side app.js missing %s", want)
		}
	}
}
