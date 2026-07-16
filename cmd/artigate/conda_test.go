package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

// condaTestPkg describes one package file a fake channel serves.
type condaTestPkg struct {
	subdir  string
	name    string
	version string
	build   string
	num     int64
	depends []string
	ext     string // ".conda" or ".tar.bz2"
	noSHA   bool   // omit the sha256 field from the entry
	badSHA  bool   // declare a sha256 that does not match the payload
}

func (p condaTestPkg) filename() string { return p.name + "-" + p.version + "-" + p.build + p.ext }

// condaTestPayload is the deterministic fake package payload for a filename,
// so every assertion can recompute the expected bytes and SHA-256. The low
// side never parses package contents, so arbitrary bytes work.
func condaTestPayload(filename string) []byte { return []byte("conda-pkg " + filename) }

// condaTestEntryJSON renders one repodata entry for a fake package, with the
// real SHA-256 of its payload unless the fixture says otherwise.
func condaTestEntryJSON(p condaTestPkg) string {
	deps, _ := json.Marshal(append([]string{}, p.depends...))
	entry := fmt.Sprintf(`{"build":%q,"build_number":%d,"depends":%s,"license":"MIT","name":%q,"size":%d,"subdir":%q,"version":%q`,
		p.build, p.num, deps, p.name, len(condaTestPayload(p.filename())), p.subdir, p.version)
	switch {
	case p.noSHA:
	case p.badSHA:
		entry += fmt.Sprintf(`,"sha256":%q`, strings.Repeat("ab", 32))
	default:
		entry += fmt.Sprintf(`,"sha256":%q`, aptSHA256(condaTestPayload(p.filename())))
	}
	return entry + "}"
}

// condaTestRepodataJSON assembles one subdir's repodata document from its
// fixture packages.
func condaTestRepodataJSON(subdir string, pkgs []condaTestPkg) string {
	var tarbz, condas []string
	for _, p := range pkgs {
		kv := fmt.Sprintf("%q:%s", p.filename(), condaTestEntryJSON(p))
		if p.ext == ".conda" {
			condas = append(condas, kv)
		} else {
			tarbz = append(tarbz, kv)
		}
	}
	return fmt.Sprintf(`{"info":{"subdir":%q},"packages":{%s},"packages.conda":{%s},"repodata_version":1}`,
		subdir, strings.Join(tarbz, ","), strings.Join(condas, ","))
}

// fakeCondaChannel serves an upstream conda channel: per-subdir plain
// repodata.json (the .zst/.bz2 forms 404, exercising the fetch fallback) and
// the package payloads. Every request is counted so tests can assert what
// was (not) fetched. A noarch document always exists, like on real channel
// hosts.
type fakeCondaChannel struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int
	docs map[string]string
	pkgs map[string][]byte
	// requireAuth, when set before the first request, is the exact
	// Authorization value every request must carry; anything else gets a 401
	// Basic challenge (a private channel).
	requireAuth string
}

func newFakeCondaChannel(t *testing.T, pkgs []condaTestPkg) *fakeCondaChannel {
	t.Helper()
	f := &fakeCondaChannel{hits: map[string]int{}, docs: map[string]string{}, pkgs: map[string][]byte{}}
	bySubdir := map[string][]condaTestPkg{"noarch": nil}
	for _, p := range pkgs {
		bySubdir[p.subdir] = append(bySubdir[p.subdir], p)
	}
	for subdir, list := range bySubdir {
		f.docs["/"+subdir+"/repodata.json"] = condaTestRepodataJSON(subdir, list)
		for _, p := range list {
			f.pkgs["/"+subdir+"/"+p.filename()] = condaTestPayload(p.filename())
		}
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCondaChannel) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	doc, okDoc := f.docs[r.URL.Path]
	body, okPkg := f.pkgs[r.URL.Path]
	auth := f.requireAuth
	f.mu.Unlock()
	if auth != "" && r.Header.Get("Authorization") != auth {
		w.Header().Set("Www-Authenticate", `Basic realm="channel"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case okDoc:
		_, _ = w.Write([]byte(doc))
	case okPkg:
		_, _ = w.Write(body)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *fakeCondaChannel) count(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[p]
}

func newCondaLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// condaTestRecord renders the manifest record a real collect would produce
// for one fixture package under a mirror.
func condaTestRecord(mirror string, p condaTestPkg) CondaPackage {
	fn := p.filename()
	return CondaPackage{
		Subdir:        p.subdir,
		Filename:      fn,
		Path:          condaFileRel(mirror, p.subdir, fn),
		SHA256:        aptSHA256(condaTestPayload(fn)),
		RepodataEntry: json.RawMessage(condaTestEntryJSON(p)),
	}
}

// condaPlaceArtifact writes one package payload where the bundle importer
// installs verified files, so the publish/serve hooks can be driven
// directly.
func condaPlaceArtifact(t *testing.T, hs *HighServer, rec CondaPackage) {
	t.Helper()
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rec.Path))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, condaTestPayload(rec.Filename))
}

// condaServeHandler wraps the serve hook with a fallthrough 404 so an
// httptest server exercises routing exactly as the high-side handler chain
// would.
func condaServeHandler(hs *HighServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hs.serveConda(w, r) {
			http.NotFound(w, r)
		}
	})
}

// condaReadServedRepodata fetches and parses one regenerated repodata.json.
func condaReadServedRepodata(t *testing.T, base, mirror, subdir string) condaRepodata {
	t.Helper()
	code, body := httpGet(t, base+"/conda/"+mirror+"/"+subdir+"/repodata.json")
	if code != http.StatusOK {
		t.Fatalf("repodata.json %s/%s status %d: %s", mirror, subdir, code, body)
	}
	var doc condaRepodata
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("repodata.json %s/%s is not JSON: %v\n%s", mirror, subdir, err, body)
	}
	return doc
}

// -----------------------------------------------------------------------------
// Unit: registry descriptor
// -----------------------------------------------------------------------------

// TestCondaEcosystemDescriptor pins the registry entry's identity and hook
// wiring (TestEcosystemRegistryWiring covers a descriptor only once it is
// appended to ecosystems()).
func TestCondaEcosystemDescriptor(t *testing.T) {
	e := condaEcosystem()
	if e.stream != streamConda || e.label != "Conda" || e.title != "Conda packages" || e.contentDesc != "conda packages" {
		t.Errorf("descriptor identity = %q/%q/%q/%q", e.stream, e.label, e.title, e.contentDesc)
	}
	if e.collect == nil || e.watchCollect == nil || e.manifestContent == nil || e.validateContent == nil ||
		e.publish == nil || e.serve == nil || e.scanTree == nil || e.detail == nil {
		t.Error("descriptor is missing hooks the dispatch sites dereference")
	}
	if e.manifestContent(BundleManifest{}) {
		t.Error("manifestContent claims an empty manifest carries conda content")
	}
	withConda := BundleManifest{Conda: &CondaManifest{Channels: []CondaChannel{{Name: "chan"}}}}
	if !e.manifestContent(withConda) {
		t.Error("manifestContent misses conda content")
	}

	fs := flag.NewFlagSet("conda", flag.ContinueOnError)
	var cfg LowConfig
	e.flags(fs, &cfg)
	if err := fs.Parse([]string{"-conda-channel-base", "https://mirror.example"}); err != nil {
		t.Fatal(err)
	}
	if cfg.CondaChannelBase != "https://mirror.example" {
		t.Errorf("conda-channel-base flag wired to %q", cfg.CondaChannelBase)
	}
}

// -----------------------------------------------------------------------------
// Unit: naming, filenames, versions
// -----------------------------------------------------------------------------

func TestCondaValidateNamesAndFilenames(t *testing.T) {
	validNames := []string{"numpy", "font-ttf-dejavu-sans-mono", "_libgcc_mutex", "zlib", "x264", "py.test"}
	invalidNames := []string{"", "Numpy", ".hidden", "-flag", "a/b", "a b", "café", ".."}
	for _, n := range validNames {
		if err := validateCondaPackageName(n); err != nil {
			t.Errorf("validateCondaPackageName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateCondaPackageName(n); err == nil {
			t.Errorf("validateCondaPackageName(%q) = nil, want error", n)
		}
	}

	validSubdirs := []string{"noarch", "linux-64", "osx-arm64", "win-64", "linux-aarch64"}
	invalidSubdirs := []string{"", "Linux-64", "../x", "-x", ".hidden", "a/b", ".."}
	for _, sd := range validSubdirs {
		if err := validateCondaSubdir(sd); err != nil {
			t.Errorf("validateCondaSubdir(%q) = %v, want nil", sd, err)
		}
	}
	for _, sd := range invalidSubdirs {
		if err := validateCondaSubdir(sd); err == nil {
			t.Errorf("validateCondaSubdir(%q) = nil, want error", sd)
		}
	}

	validFiles := []string{"numpy-1.26.4-py312h2b4c86e_0.conda", "font-ttf-dejavu-sans-mono-2.37-hab24e00_0.tar.bz2", "zlib-1.2.13-h5eee18b_1.conda"}
	invalidFiles := []string{"", ".conda", "-x.conda", ".hidden.conda", "numpy-1.0.tar.gz", "numpy-1.0.zip", "a/b.conda", "numpy-1.0-h1_0.CONDA"}
	for _, fn := range validFiles {
		if !condaFilenameRE.MatchString(fn) {
			t.Errorf("condaFilenameRE rejects %q", fn)
		}
	}
	for _, fn := range invalidFiles {
		if condaFilenameRE.MatchString(fn) {
			t.Errorf("condaFilenameRE accepts %q", fn)
		}
	}

	if stem, ok := condaFilenameStem("numpy-1.26.4-py312_0.conda"); !ok || stem != "numpy-1.26.4-py312_0" {
		t.Errorf("condaFilenameStem(.conda) = %q, %v", stem, ok)
	}
	if stem, ok := condaFilenameStem("numpy-1.26.4-py312_0.tar.bz2"); !ok || stem != "numpy-1.26.4-py312_0" {
		t.Errorf("condaFilenameStem(.tar.bz2) = %q, %v", stem, ok)
	}
	if _, ok := condaFilenameStem("numpy-1.26.4-py312_0.zip"); ok {
		t.Error("condaFilenameStem accepted a foreign extension")
	}
	if got := condaFileRel("chan", "noarch", "a-1-0.conda"); got != "conda/chan/noarch/a-1-0.conda" {
		t.Errorf("condaFileRel = %q", got)
	}
}

// TestCondaCompareVersions pins the pragmatic VersionOrder subset: epochs
// first, dotted/underscored/dashed segments, alpha runs before numbers, and
// "dev" before other tags.
func TestCondaCompareVersions(t *testing.T) {
	ordered := []string{
		"0.4", "0.4.1.rc", "0.4.1", "0.5a1", "0.5b3", "0.5C1", "0.5",
		"0.9.6", "0.960923", "1.0", "1.1dev1", "1.1a1", "1.1.0rc1", "1.1.0",
		"1996.07.12", "1!0.4.1", "2!0.4.1",
	}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		if condaCompareVersions(a, b) >= 0 || condaCompareVersions(b, a) <= 0 {
			t.Errorf("want %s < %s", a, b)
		}
	}
	equal := [][2]string{
		{"1.2", "1.2.0"},
		{"1.2.3", "1.2_3"},
		{"1.2.3", "1.2-3"},
		{"0.5C1", "0.5c1"},
		{"1!1.0", "1!1.0.0"},
		{"01.1", "1.1"},
	}
	for _, pair := range equal {
		if condaCompareVersions(pair[0], pair[1]) != 0 {
			t.Errorf("want %s == %s", pair[0], pair[1])
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: spec, constraint, and dependency parsing
// -----------------------------------------------------------------------------

func TestCondaSpecParsingAndMatching(t *testing.T) {
	tests := []struct {
		spec    string
		version string
		want    bool
	}{
		{"pkga", "1.0.0", true}, // bare name matches anything
		{"pkga==1.2.3", "1.2.3", true},
		{"pkga==1.2.3", "1.2.4", false},
		{"pkga==1.2", "1.2.0", true}, // exact compares by version order
		{"pkga=1.2", "1.2.4", true},  // "=" is a prefix match
		{"pkga=1.2", "1.2", true},
		{"pkga=1.2", "1.20.0", false},
		{"pkga>=1.2", "1.2", true},
		{"pkga>=1.2", "1.1.9", false},
		{"pkga>=1.2,<2.0", "1.9.9", true}, // comma is AND
		{"pkga>=1.2,<2.0", "2.0", false},
		{"pkga>=1.19,<2.0a0", "1.26.4", true},
		{"pkga>=1.19,<2.0a0", "2.0", false}, // 2.0a0 sorts before 2.0
		{"pkga!=1.5", "1.5.0", false},
		{"pkga!=1.5", "1.5.1", true},
		{"pkga<=1.5", "1.5", true},
		{"pkga<1.5", "1.5", false},
		{"pkga>1!1.0", "2.0", false}, // epochs dominate
		{"pkga>1!1.0", "1!1.1", true},
	}
	for _, tt := range tests {
		name, cs, err := condaParseSpec(tt.spec)
		if err != nil || name != "pkga" {
			t.Errorf("condaParseSpec(%q) = %q, %v", tt.spec, name, err)
			continue
		}
		if got := condaConstraintsMatch(cs, tt.version); got != tt.want {
			t.Errorf("spec %q matching %s = %v, want %v", tt.spec, tt.version, got, tt.want)
		}
	}

	for _, bad := range []string{"", "PkgA", "pkga==1.2|2.0", "pkga==", "pkga>=1.2,", "==1.2", "pkga@1.0", "a b"} {
		if _, _, err := condaParseSpec(bad); err == nil {
			t.Errorf("condaParseSpec(%q) = nil error, want error", bad)
		}
	}
}

func TestCondaParseDepend(t *testing.T) {
	tests := []struct {
		dep     string
		name    string
		build   string
		match   string
		wantHit bool
	}{
		{"pkgb", "pkgb", "", "9.9", true},
		{"pkgb >=0.1", "pkgb", "", "0.1", true},
		{"pkgb >=0.1,<0.2", "pkgb", "", "0.3", false},
		{"pkgb 1.2.*", "pkgb", "", "1.2.7", true},
		{"pkgb 1.2", "pkgb", "", "1.2.7", true}, // bare dependency version is a prefix
		{"pkgb 1.2", "pkgb", "", "1.3.0", false},
		{"pkgb 2.7*", "pkgb", "", "2.7.18", true},
		{"pkgb *", "pkgb", "", "0.0.1", true},
		{"pkgb >=1.0 h1_0", "pkgb", "h1_0", "1.5", true},
		{"pkgb >=1.0 *_0", "pkgb", "", "1.5", true}, // wildcard build is ignored
	}
	for _, tt := range tests {
		name, cs, build, err := condaParseDepend(tt.dep)
		if err != nil || name != tt.name || build != tt.build {
			t.Errorf("condaParseDepend(%q) = %q, %q, %v; want %q, %q", tt.dep, name, build, err, tt.name, tt.build)
			continue
		}
		if got := condaConstraintsMatch(cs, tt.match); got != tt.wantHit {
			t.Errorf("dependency %q matching %s = %v, want %v", tt.dep, tt.match, got, tt.wantHit)
		}
	}

	for _, bad := range []string{"", "PkgB 1.0", "pkgb 1.0 h1_0 extra", "pkgb 2.7*|>=3.6", "pkgb >="} {
		if _, _, _, err := condaParseDepend(bad); err == nil {
			t.Errorf("condaParseDepend(%q) = nil error, want error", bad)
		}
	}
}

func TestCondaChannelURLAndSubdirs(t *testing.T) {
	if got, err := condaChannelURL("conda-forge", "https://base.example"); err != nil || got != "https://base.example/conda-forge" {
		t.Errorf("bare channel = %q, %v", got, err)
	}
	if got, err := condaChannelURL("https://host.example/chan/", "https://base.example"); err != nil || got != "https://host.example/chan" {
		t.Errorf("url channel = %q, %v", got, err)
	}
	for _, bad := range []string{"", "ftp://host/chan", "../evil", "a b"} {
		if _, err := condaChannelURL(bad, "https://base.example"); err == nil {
			t.Errorf("condaChannelURL(%q) = nil error, want error", bad)
		}
	}
	// A login embedded in the channel URL would cross to the high side inside
	// the signed manifest and progress text; it is refused without ever
	// echoing the secret back.
	if _, err := condaChannelURL("https://user:token@host.example/chan", "https://base.example"); err == nil {
		t.Error("channel URL with userinfo accepted")
	} else if strings.Contains(err.Error(), "token") {
		t.Errorf("channel userinfo error echoes the secret: %v", err)
	}

	if got, err := condaRequestSubdirs(nil); err != nil || len(got) != 1 || got[0] != "noarch" {
		t.Errorf("default subdirs = %v, %v; want [noarch]", got, err)
	}
	got, err := condaRequestSubdirs([]string{"linux-64", "noarch", "linux-64"})
	if err != nil || len(got) != 2 || got[0] != "linux-64" || got[1] != "noarch" {
		t.Errorf("subdirs = %v, %v; want [linux-64 noarch]", got, err)
	}
	if _, err := condaRequestSubdirs([]string{"Linux-64"}); err == nil {
		t.Error("invalid subdir accepted")
	}

	ls, _ := newCondaLowServer(t)
	if got := ls.condaChannelBase(); got != defaultCondaChannelBase {
		t.Errorf("default channel base = %q", got)
	}
	ls.cfg.CondaChannelBase = "https://mirror.example/base/"
	if got := ls.condaChannelBase(); got != "https://mirror.example/base" {
		t.Errorf("configured channel base = %q", got)
	}
}

// -----------------------------------------------------------------------------
// Unit: repodata fetching (compression fallback chain)
// -----------------------------------------------------------------------------

// TestCondaFetchRepodataFallback exercises the .zst -> .bz2 -> plain chain:
// each compressed form is produced with the matching system tool when
// present (skipping that leg otherwise, like the APT xz/lz4 tests do), and a
// channel with none of the three fails loudly.
func TestCondaFetchRepodataFallback(t *testing.T) {
	plain := []byte(`{"info":{"subdir":"noarch"},"packages":{},"packages.conda":{},"repodata_version":1}`)
	serve := func(t *testing.T, files map[string][]byte) string {
		t.Helper()
		mux := http.NewServeMux()
		for rel, body := range files {
			mux.HandleFunc("/noarch/"+rel, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
		}
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		return srv.URL + "/noarch"
	}

	t.Run("plain", func(t *testing.T) {
		url := serve(t, map[string][]byte{"repodata.json": plain})
		got, err := condaFetchRepodata(context.Background(), url, nil)
		if err != nil || string(got) != string(plain) {
			t.Fatalf("plain fallback = %q, %v", got, err)
		}
	})
	t.Run("bz2", func(t *testing.T) {
		if _, err := exec.LookPath("bzip2"); err != nil {
			t.Skip("bzip2 not installed")
		}
		comp, err := runFilterCmd("bzip2", plain, 1<<20, "-z", "-c")
		if err != nil {
			t.Fatal(err)
		}
		url := serve(t, map[string][]byte{"repodata.json.bz2": comp})
		got, err := condaFetchRepodata(context.Background(), url, nil)
		if err != nil || string(got) != string(plain) {
			t.Fatalf("bz2 fetch = %q, %v", got, err)
		}
		// The decompression cap fails a bomb instead of buffering it.
		if _, err := condaBunzip2Capped(comp, 8); err == nil || !strings.Contains(err.Error(), "cap") {
			t.Errorf("condaBunzip2Capped over limit = %v, want cap error", err)
		}
	})
	t.Run("zst", func(t *testing.T) {
		if _, err := exec.LookPath("zstd"); err != nil {
			t.Skip("zstd not installed")
		}
		comp, err := runFilterCmd("zstd", plain, 1<<20, "-c")
		if err != nil {
			t.Fatal(err)
		}
		url := serve(t, map[string][]byte{"repodata.json.zst": comp})
		got, err := condaFetchRepodata(context.Background(), url, nil)
		if err != nil || string(got) != string(plain) {
			t.Fatalf("zst fetch = %q, %v", got, err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		url := serve(t, map[string][]byte{})
		if _, err := condaFetchRepodata(context.Background(), url, nil); err == nil || !strings.Contains(err.Error(), "repodata unavailable") {
			t.Fatalf("missing repodata = %v, want 'repodata unavailable'", err)
		}
	})
}

// -----------------------------------------------------------------------------
// Unit: greedy resolution
// -----------------------------------------------------------------------------

// condaTestIndex builds an in-memory package index from fixture packages.
func condaTestIndex(t *testing.T, pkgs []condaTestPkg) condaPackageIndex {
	t.Helper()
	bySubdir := map[string][]condaTestPkg{}
	for _, p := range pkgs {
		bySubdir[p.subdir] = append(bySubdir[p.subdir], p)
	}
	idx := condaPackageIndex{}
	for subdir, list := range bySubdir {
		if err := condaIndexRepodata(idx, subdir, []byte(condaTestRepodataJSON(subdir, list))); err != nil {
			t.Fatal(err)
		}
	}
	return idx
}

func condaResolveTestPkgs() []condaTestPkg {
	return []condaTestPkg{
		{subdir: "noarch", name: "pkgx", version: "1.0.0", build: "h1_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgx", version: "2.0.0", build: "h1_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgx", version: "2.0.0", build: "h1_1", num: 1, ext: ".conda"},
		{subdir: "noarch", name: "pkgx", version: "2.0.0", build: "h1_1", num: 1, ext: ".tar.bz2"}, // duplicate identity: .conda wins
		{subdir: "noarch", name: "pkgy", version: "1.2.9", build: "h0_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgy", version: "1.20.0", build: "h0_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgv", version: "1.0", build: "h7_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgv", version: "1.0", build: "h7_1", num: 1, ext: ".conda"},
		{
			subdir: "linux-64", name: "pkgq", version: "1.0.0", build: "h5_0", ext: ".conda",
			depends: []string{"pkgv >=1.0 h7_0", "pkgz >=1.0", "__glibc >=2.17"},
		},
		{subdir: "noarch", name: "pkgz", version: "0.9", build: "h9_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgdev", version: "1.0.0", build: "h2_0", ext: ".conda", noSHA: true},
	}
}

// condaTestResolve runs one resolution against the shared fixture index.
func condaTestResolve(t *testing.T, noDeps bool, specs ...string) ([]condaCandidate, []FailedModule) {
	t.Helper()
	r := &condaResolver{idx: condaTestIndex(t, condaResolveTestPkgs()), noDeps: noDeps, byName: map[string]bool{}}
	return r.resolve(context.Background(), specs)
}

func condaSelectionFilenames(selected []condaCandidate) []string {
	out := make([]string, 0, len(selected))
	for _, s := range selected {
		out = append(out, s.filename)
	}
	return out
}

func TestCondaResolve(t *testing.T) {
	// Newest version wins, higher build number breaks the tie, and the
	// .conda form shadows the identical .tar.bz2.
	selected, failed := condaTestResolve(t, false, "pkgx")
	if len(failed) != 0 || len(selected) != 1 || selected[0].filename != "pkgx-2.0.0-h1_1.conda" {
		t.Fatalf("pkgx resolve = %v, %+v", condaSelectionFilenames(selected), failed)
	}

	// Constraints narrow the pick; prefix matching never crosses a segment.
	if sel, _ := condaTestResolve(t, false, "pkgx<2.0"); len(sel) != 1 || sel[0].filename != "pkgx-1.0.0-h1_0.conda" {
		t.Errorf("pkgx<2.0 = %v", condaSelectionFilenames(sel))
	}
	if sel, _ := condaTestResolve(t, false, "pkgy=1.2"); len(sel) != 1 || sel[0].filename != "pkgy-1.2.9-h0_0.conda" {
		t.Errorf("pkgy=1.2 = %v", condaSelectionFilenames(sel))
	}

	// The dependency walk: an exact build pin beats the higher build number,
	// the virtual __glibc edge is skipped, and the unsatisfiable pkgz>=1.0
	// is reported without sinking the batch.
	selected, failed = condaTestResolve(t, false, "pkgq")
	got := strings.Join(condaSelectionFilenames(selected), " ")
	if len(selected) != 2 || !strings.Contains(got, "pkgq-1.0.0-h5_0.conda") || !strings.Contains(got, "pkgv-1.0-h7_0.conda") {
		t.Errorf("pkgq closure = %v", condaSelectionFilenames(selected))
	}
	if len(failed) != 1 || failed[0].Module != "pkgz" {
		t.Errorf("pkgq failures = %+v, want one for pkgz", failed)
	}

	// NoDeps mirrors only the listed package.
	if sel, fail := condaTestResolve(t, true, "pkgq"); len(sel) != 1 || len(fail) != 0 {
		t.Errorf("no_deps resolve = %v, %+v", condaSelectionFilenames(sel), fail)
	}

	// First selection wins: a second demand for an already-selected name is
	// silently satisfied, like a shared dependency.
	if sel, fail := condaTestResolve(t, false, "pkgx==1.0.0", "pkgx"); len(sel) != 1 || sel[0].filename != "pkgx-1.0.0-h1_0.conda" || len(fail) != 0 {
		t.Errorf("first-wins resolve = %v, %+v", condaSelectionFilenames(sel), fail)
	}

	// An entry without sha256 is never mirrored, only reported.
	if sel, fail := condaTestResolve(t, false, "pkgdev"); len(sel) != 0 || len(fail) != 1 || !strings.Contains(fail[0].Error, "sha256") {
		t.Errorf("sha-less resolve = %v, %+v", condaSelectionFilenames(sel), fail)
	}

	// Unknown names are reported.
	if _, fail := condaTestResolve(t, false, "nosuchpkg"); len(fail) != 1 || fail[0].Module != "nosuchpkg" {
		t.Errorf("unknown package failures = %+v", fail)
	}
}

// -----------------------------------------------------------------------------
// Unit: import-side manifest validation
// -----------------------------------------------------------------------------

func TestCondaValidateChannels(t *testing.T) {
	good := condaTestRecord("chan", condaTestPkg{subdir: "noarch", name: "pkga", version: "1.0.0", build: "h1_0", ext: ".conda"})
	seen := map[string]bool{good.Path: true}
	files := []ManifestFile{{Path: good.Path, SHA256: good.SHA256, Size: 1}}
	channel := func(pkgs ...CondaPackage) []CondaChannel {
		return []CondaChannel{{Name: "chan", URL: "https://up.example/chan", Packages: pkgs}}
	}

	if err := validateCondaChannels(channel(good), seen, files); err != nil {
		t.Errorf("valid channel rejected: %v", err)
	}

	mutate := func(f func(*CondaPackage)) CondaPackage {
		c := good
		f(&c)
		return c
	}
	otherSHA := aptSHA256([]byte("other bytes"))
	bad := []struct {
		name     string
		channels []CondaChannel
		seen     map[string]bool
		files    []ManifestFile
	}{
		{"bad mirror name", []CondaChannel{{Name: "../x", URL: "u", Packages: []CondaPackage{good}}}, seen, files},
		{"no url", []CondaChannel{{Name: "chan", Packages: []CondaPackage{good}}}, seen, files},
		{"no packages", []CondaChannel{{Name: "chan", URL: "u"}}, seen, files},
		{"bad subdir", channel(mutate(func(c *CondaPackage) { c.Subdir = "../x" })), seen, files},
		{"foreign extension", channel(mutate(func(c *CondaPackage) { c.Filename = "pkga-1.0.0-h1_0.zip" })), seen, files},
		{"filename/entry mismatch", channel(mutate(func(c *CondaPackage) { c.Filename = "pkga-1.0.1-h1_0.conda" })), seen, files},
		{"unparsable entry", channel(mutate(func(c *CondaPackage) { c.RepodataEntry = json.RawMessage("not json") })), seen, files},
		{"entry name not lowercase", channel(condaTestRecord("chan", condaTestPkg{subdir: "noarch", name: "PkgA", version: "1.0.0", build: "h1_0", ext: ".conda"})), map[string]bool{"conda/chan/noarch/PkgA-1.0.0-h1_0.conda": true}, files},
		{"non-canonical path", channel(mutate(func(c *CondaPackage) { c.Path = "conda/other/noarch/" + c.Filename })), map[string]bool{"conda/other/noarch/pkga-1.0.0-h1_0.conda": true}, files},
		{"path not in seen", channel(good), map[string]bool{}, files},
		{"entry sha disagrees with record", channel(mutate(func(c *CondaPackage) { c.SHA256 = otherSHA })), seen, files},
		{"empty record sha", channel(mutate(func(c *CondaPackage) { c.SHA256 = "" })), seen, files},
		{"record sha disagrees with manifest.files", channel(good), seen, []ManifestFile{{Path: good.Path, SHA256: otherSHA, Size: 1}}},
	}
	for _, tt := range bad {
		if err := validateCondaChannels(tt.channels, tt.seen, tt.files); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}

	// An uppercase upstream sha256 still matches the lowercase artifact hash.
	upper := good
	upper.RepodataEntry = json.RawMessage(strings.Replace(string(good.RepodataEntry),
		`"sha256":"`+good.SHA256+`"`, `"sha256":"`+strings.ToUpper(good.SHA256)+`"`, 1))
	if err := validateCondaChannels(channel(upper), seen, files); err != nil {
		t.Errorf("uppercase entry sha rejected: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Integration: collect -> validate -> publish -> serve
// -----------------------------------------------------------------------------

// condaPipelinePkgs is the fixture channel for the round-trip tests: a
// noarch package with one dependency (plus a virtual one), an unrequested
// bystander, and a linux-64 package that exists in both archive formats.
func condaPipelinePkgs() []condaTestPkg {
	return []condaTestPkg{
		{
			subdir: "noarch", name: "pkga", version: "1.0.0", build: "h1_0", ext: ".conda",
			depends: []string{"pkgb >=0.1", "__glibc >=2.17"},
		},
		{subdir: "noarch", name: "pkgb", version: "0.1.5", build: "h2_0", ext: ".tar.bz2"},
		{subdir: "noarch", name: "pkgc", version: "3.0.0", build: "h3_0", ext: ".conda"},
		{subdir: "linux-64", name: "pkgd", version: "2.0.0", build: "h4_0", ext: ".conda"},
		{subdir: "linux-64", name: "pkgd", version: "2.0.0", build: "h4_0", ext: ".tar.bz2"},
	}
}

// TestCondaCollectAndPublishPipeline is the full round trip: resolve against
// a fake channel, download with sha256 verification, export a signed bundle,
// validate the manifest the way the importer would, publish, and serve the
// regenerated channel. (The import-side hooks are driven directly, against
// artifacts laid out exactly as the importer installs them.)
func TestCondaCollectAndPublishPipeline(t *testing.T) {
	up := newFakeCondaChannel(t, condaPipelinePkgs())
	ls, _ := newCondaLowServer(t)
	ctx := context.Background()

	req := CondaCollectRequest{
		Channel: up.srv.URL, Name: "chan", Subdirs: []string{"linux-64"},
		Packages: []string{"pkga", "pkgd==2.0.0"},
	}
	res, err := ls.CollectConda(ctx, req)
	if err != nil {
		t.Fatalf("CollectConda: %v", err)
	}
	if res.BundleID != "conda-bundle-000001" || res.ExportedModules != 3 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	// Only the selected files were fetched: not the bystander, and not the
	// .tar.bz2 twin of a package that also ships as .conda.
	for _, p := range []string{"/noarch/pkgc-3.0.0-h3_0.conda", "/linux-64/pkgd-2.0.0-h4_0.tar.bz2"} {
		if n := up.count(p); n != 0 {
			t.Errorf("upstream %s fetched %d time(s), want 0", p, n)
		}
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if m.Conda == nil || len(m.Conda.Channels) != 1 || len(m.Conda.Channels[0].Packages) != 3 {
		t.Fatalf("bundle manifest conda content = %+v", m.Conda)
	}
	ch := m.Conda.Channels[0]
	if ch.Name != "chan" || ch.URL != up.srv.URL {
		t.Errorf("channel identity = %s %s", ch.Name, ch.URL)
	}
	wantPaths := []string{
		"conda/chan/linux-64/pkgd-2.0.0-h4_0.conda",
		"conda/chan/noarch/pkga-1.0.0-h1_0.conda",
		"conda/chan/noarch/pkgb-0.1.5-h2_0.tar.bz2",
	}
	for i, want := range wantPaths {
		p := ch.Packages[i]
		if p.Path != want || p.SHA256 != aptSHA256(condaTestPayload(p.Filename)) {
			t.Errorf("package record %d = %+v, want path %s", i, p, want)
		}
		if m.Files[i].Path != want || m.Files[i].SHA256 != p.SHA256 {
			t.Errorf("bundle file %d = %+v, want %s", i, m.Files[i], want)
		}
	}

	// The manifest passes exactly the check the importer runs.
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateCondaChannels(m.Conda.Channels, seen, m.Files); err != nil {
		t.Fatalf("collected manifest fails import validation: %v", err)
	}

	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	for _, p := range ch.Packages {
		condaPlaceArtifact(t, hs, p)
	}
	if err := hs.publishConda(m.Conda); err != nil {
		t.Fatalf("publishConda: %v", err)
	}

	srv := httptest.NewServer(condaServeHandler(hs))
	defer srv.Close()
	condaAssertPipelineServing(t, srv.URL)

	// A second bundle merges: pkgc joins the regenerated noarch document,
	// while pkgb drops out once its artifact is pruned (presence gating).
	second := &CondaManifest{Channels: []CondaChannel{{Name: "chan", URL: up.srv.URL, Packages: []CondaPackage{
		condaTestRecord("chan", condaPipelinePkgs()[2]),
	}}}}
	condaPlaceArtifact(t, hs, second.Channels[0].Packages[0])
	if err := os.Remove(filepath.Join(hs.downloadDir, "conda", "chan", "noarch", "pkgb-0.1.5-h2_0.tar.bz2")); err != nil {
		t.Fatal(err)
	}
	if err := hs.publishConda(second); err != nil {
		t.Fatalf("second publishConda: %v", err)
	}
	doc := condaReadServedRepodata(t, srv.URL, "chan", "noarch")
	if _, ok := doc.PackagesConda["pkgc-3.0.0-h3_0.conda"]; !ok {
		t.Errorf("second publish did not merge pkgc: %v", doc.PackagesConda)
	}
	if _, ok := doc.PackagesConda["pkga-1.0.0-h1_0.conda"]; !ok {
		t.Errorf("second publish clobbered pkga: %v", doc.PackagesConda)
	}
	if _, ok := doc.Packages["pkgb-0.1.5-h2_0.tar.bz2"]; ok {
		t.Error("pruned pkgb still listed in repodata.json")
	}

	// Everything already forwarded: the collect skips, burning no sequence.
	res2, err := ls.CollectConda(ctx, req)
	if err != nil {
		t.Fatalf("dedup CollectConda: %v", err)
	}
	if !res2.Skipped || res2.BundleID != "" {
		t.Fatalf("all-prior collect = %+v, want skipped", res2)
	}
	if seq := ls.peekSequence(streamConda); seq != 2 {
		t.Errorf("next sequence = %d, want 2 (a skip must not burn a number)", seq)
	}
}

// condaAssertPipelineServing checks the regenerated documents and the
// serving hardening after the pipeline's first publish.
func condaAssertPipelineServing(t *testing.T, base string) {
	t.Helper()
	doc := condaReadServedRepodata(t, base, "chan", "noarch")
	if doc.Info.Subdir != "noarch" || doc.RepodataVersion != 1 {
		t.Errorf("noarch repodata identity = %+v", doc.Info)
	}
	rawA, okA := doc.PackagesConda["pkga-1.0.0-h1_0.conda"]
	if _, okB := doc.Packages["pkgb-0.1.5-h2_0.tar.bz2"]; !okA || !okB {
		t.Fatalf("noarch repodata misses mirrored packages: %v / %v", doc.PackagesConda, doc.Packages)
	}
	if _, ok := doc.PackagesConda["pkgc-3.0.0-h3_0.conda"]; ok {
		t.Error("unmirrored pkgc listed in repodata.json")
	}
	entry, err := condaEntryForFilename("pkga-1.0.0-h1_0.conda", rawA)
	if err != nil || strings.ToLower(entry.SHA256) != aptSHA256(condaTestPayload("pkga-1.0.0-h1_0.conda")) {
		t.Errorf("served pkga entry = %+v, %v", entry, err)
	}
	lin := condaReadServedRepodata(t, base, "chan", "linux-64")
	if _, ok := lin.PackagesConda["pkgd-2.0.0-h4_0.conda"]; !ok {
		t.Errorf("linux-64 repodata misses pkgd: %v", lin.PackagesConda)
	}

	// Package files round-trip byte-identically, with the JSON content type
	// on index documents.
	resp, err := http.Get(base + "/conda/chan/noarch/repodata.json") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("repodata.json content type = %q", ct)
	}
	code, body := httpGet(t, base+"/conda/chan/noarch/pkga-1.0.0-h1_0.conda")
	if code != http.StatusOK || body != string(condaTestPayload("pkga-1.0.0-h1_0.conda")) {
		t.Errorf("package download status %d, %d byte(s)", code, len(body))
	}

	// The private metadata store is never served; traversal and non-read
	// methods are rejected; anything but the two servable shapes 404s.
	for _, p := range []string{
		"/conda/chan/metadata/noarch/pkga-1.0.0-h1_0.conda.json",
		"/conda/..%2f..%2fimport-state.json",
		"/conda/chan/noarch/..%2f..%2fmetadata%2fnoarch%2fpkga-1.0.0-h1_0.conda.json",
		"/conda/chan/noarch/pkga-1.0.0-h1_0.conda/extra",
		"/conda/chan/noarch",
		"/conda/chan",
	} {
		if code, _ := httpGet(t, base+p); code == http.StatusOK {
			t.Errorf("GET %s returned 200, want rejection", p)
		}
	}
	post, err := http.Post(base+"/conda/chan/noarch/repodata.json", "application/json", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST repodata.json status %d, want 405", post.StatusCode)
	}
}

// TestCondaPublishNoarchSkeleton proves a platform-only mirror still answers
// the noarch half conda clients unconditionally request, and that a tampered
// artifact is kept out of the regenerated index (while import-verified bytes
// would still be served).
func TestCondaPublishNoarchSkeleton(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rec := condaTestRecord("lchan", condaTestPkg{subdir: "linux-64", name: "pkgd", version: "2.0.0", build: "h4_0", ext: ".conda"})
	tampered := condaTestRecord("lchan", condaTestPkg{subdir: "linux-64", name: "pkge", version: "1.0.0", build: "h0_0", ext: ".conda"})
	m := &CondaManifest{Channels: []CondaChannel{{Name: "lchan", URL: "https://up.example", Packages: []CondaPackage{rec, tampered}}}}
	condaPlaceArtifact(t, hs, rec)
	tamperedAbs := filepath.Join(hs.downloadDir, filepath.FromSlash(tampered.Path))
	if err := os.MkdirAll(filepath.Dir(tamperedAbs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, tamperedAbs, []byte("not the packaged bytes"))
	if err := hs.publishConda(m); err != nil {
		t.Fatalf("publishConda: %v", err)
	}

	srv := httptest.NewServer(condaServeHandler(hs))
	defer srv.Close()
	noarch := condaReadServedRepodata(t, srv.URL, "lchan", "noarch")
	if noarch.Info.Subdir != "noarch" || len(noarch.Packages) != 0 || len(noarch.PackagesConda) != 0 {
		t.Errorf("noarch skeleton = %+v", noarch)
	}
	lin := condaReadServedRepodata(t, srv.URL, "lchan", "linux-64")
	if _, ok := lin.PackagesConda["pkgd-2.0.0-h4_0.conda"]; !ok {
		t.Errorf("linux-64 repodata misses pkgd: %v", lin.PackagesConda)
	}
	if _, ok := lin.PackagesConda["pkge-1.0.0-h0_0.conda"]; ok {
		t.Error("tampered pkge listed in repodata.json")
	}
}

// -----------------------------------------------------------------------------
// Dashboard tree/detail
// -----------------------------------------------------------------------------

func TestCondaTreeAndDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	pkgs := []condaTestPkg{
		{subdir: "noarch", name: "pkga", version: "1.0.0", build: "h1_0", ext: ".conda", depends: []string{"pkgb >=0.1"}},
		{subdir: "noarch", name: "pkga", version: "2.0.0", build: "h1_0", ext: ".conda"},
		{subdir: "noarch", name: "pkgb", version: "0.1.5", build: "h2_0", ext: ".tar.bz2"},
	}
	records := make([]CondaPackage, 0, len(pkgs))
	for _, p := range pkgs {
		records = append(records, condaTestRecord("chan", p))
	}
	m := &CondaManifest{Channels: []CondaChannel{{Name: "chan", URL: "https://up.example", Packages: records}}}
	for _, rec := range records {
		condaPlaceArtifact(t, hs, rec)
	}
	if err := hs.publishConda(m); err != nil {
		t.Fatalf("publishConda: %v", err)
	}

	mods, err := hs.listCondaPackages()
	if err != nil || len(mods) != 2 {
		t.Fatalf("listCondaPackages = %+v, %v", mods, err)
	}
	if mods[0].Module != "chan/pkga" || strings.Join(mods[0].Versions, " ") != "1.0.0-h1_0 2.0.0-h1_0" {
		t.Errorf("pkga tree entry = %+v", mods[0])
	}
	if mods[1].Module != "chan/pkgb" || strings.Join(mods[1].Versions, " ") != "0.1.5-h2_0" {
		t.Errorf("pkgb tree entry = %+v", mods[1])
	}

	d, err := hs.condaDetail("chan/pkga@1.0.0-h1_0")
	if err != nil {
		t.Fatalf("condaDetail: %v", err)
	}
	if d.Title != "pkga" || d.Subtitle != "1.0.0-h1_0" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/conda/chan/noarch/pkga-1.0.0-h1_0.conda" {
		t.Errorf("detail downloads = %+v", d.Downloads)
	}
	byLabel := map[string]string{}
	for _, f := range d.Fields {
		byLabel[f.Label] = f.Value
	}
	if byLabel["License"] != "MIT" || byLabel["Subdir"] != "noarch" || byLabel["Depends"] == "" || byLabel["SHA-256"] == "" {
		t.Errorf("detail fields = %+v", d.Fields)
	}

	for _, bad := range []string{"chan/pkga@9.9.9-h1_0", "chan/pkga", "pkga@1.0.0-h1_0", "chan/pkga@1.0.0", "../x/pkga@1.0.0-h1_0"} {
		if _, err := hs.condaDetail(bad); err == nil {
			t.Errorf("condaDetail(%q) = nil error, want error", bad)
		}
	}
}

// -----------------------------------------------------------------------------
// Admin handler
// -----------------------------------------------------------------------------

// TestCondaHandleCollect drives the collect handler directly: malformed JSON
// and empty requests are rejected, and a well-formed request runs the full
// collection.
func TestCondaHandleCollect(t *testing.T) {
	ls, _ := newCondaLowServer(t)
	ctx := context.Background()

	r := httptest.NewRequest(http.MethodPost, "/admin/conda/collect", strings.NewReader("{not json"))
	if _, err := ls.HandleCondaCollect(ctx, r); err == nil {
		t.Error("malformed JSON accepted")
	}
	r = httptest.NewRequest(http.MethodPost, "/admin/conda/collect", strings.NewReader(""))
	if _, err := ls.HandleCondaCollect(ctx, r); err == nil {
		t.Error("empty request accepted")
	}

	up := newFakeCondaChannel(t, []condaTestPkg{{subdir: "noarch", name: "pkga", version: "1.0.0", build: "h1_0", ext: ".conda"}})
	body := fmt.Sprintf(`{"channel":%q,"name":"chan","packages":["pkga"]}`, up.srv.URL)
	r = httptest.NewRequest(http.MethodPost, "/admin/conda/collect", strings.NewReader(body))
	res, err := ls.HandleCondaCollect(ctx, r)
	if err != nil || res.BundleID != "conda-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("HandleCondaCollect = %+v, %v", res, err)
	}

	// A subdir the channel does not carry fails the collect loudly.
	if _, err := ls.CollectConda(ctx, CondaCollectRequest{
		Channel: up.srv.URL, Name: "chan", Subdirs: []string{"osx-64"}, Packages: []string{"pkga"},
	}); err == nil || !strings.Contains(err.Error(), "osx-64") {
		t.Errorf("missing subdir collect = %v, want subdir named in the error", err)
	}
	// A batch where nothing resolves fails loudly too.
	if _, err := ls.CollectConda(ctx, CondaCollectRequest{
		Channel: up.srv.URL, Packages: []string{"nosuchpkg"},
	}); err == nil || !strings.Contains(err.Error(), "no conda packages could be resolved") {
		t.Errorf("unresolvable collect = %v", err)
	}
}

// TestCondaCollectShaTamper proves a channel whose declared sha256 does not
// match the served bytes is skipped (and reported), and that a sole tampered
// package fails the whole collect.
func TestCondaCollectShaTamper(t *testing.T) {
	up := newFakeCondaChannel(t, []condaTestPkg{
		{subdir: "noarch", name: "pkga", version: "1.0.0", build: "h1_0", ext: ".conda", badSHA: true},
		{subdir: "noarch", name: "pkgb", version: "0.1.5", build: "h2_0", ext: ".conda"},
	})
	ls, _ := newCondaLowServer(t)
	ctx := context.Background()

	res, err := ls.CollectConda(ctx, CondaCollectRequest{
		Channel: up.srv.URL, Name: "chan", Packages: []string{"pkga", "pkgb"},
	})
	if err != nil {
		t.Fatalf("collect with one good package should succeed: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "pkga" {
		t.Fatalf("unexpected tamper result: %+v", res)
	}
	if !strings.Contains(res.SkippedModules[0].Error, "sha256") {
		t.Errorf("skip reason should mention sha256, got %q", res.SkippedModules[0].Error)
	}

	if _, err := ls.CollectConda(ctx, CondaCollectRequest{
		Channel: up.srv.URL, Name: "chan", Packages: []string{"pkga"},
	}); err == nil {
		t.Fatal("a tampered sole package should fail the collect")
	}
}

// TestCollectCondaPrivateUpstream exercises HTTP Basic against a channel that
// demands a login on every request (repodata and packages alike).
func TestCollectCondaPrivateUpstream(t *testing.T) {
	up := newFakeCondaChannel(t, []condaTestPkg{{subdir: "noarch", name: "pkga", version: "1.0.0", build: "h1_0", ext: ".conda"}})
	up.requireAuth = testBasicAuth("bot", "hunter2")
	ls, _ := newCondaLowServer(t)
	ctx := context.Background()
	req := CondaCollectRequest{Channel: up.srv.URL, Name: "chan", Packages: []string{"pkga"}}

	// Anonymous collects fail at the repodata fetch with guidance naming both
	// supply paths.
	_, err := ls.CollectConda(ctx, req)
	if err == nil || !strings.Contains(err.Error(), upstreamAuthEnv) {
		t.Fatalf("anonymous collect error = %v", err)
	}

	// A wrong login is reported as rejected — and never echoed.
	wrong := req
	wrong.Auth = &HostCollectAuth{Username: "bot", Password: "nope"}
	_, err = ls.CollectConda(ctx, wrong)
	if err == nil || !strings.Contains(err.Error(), "were not accepted") || strings.Contains(err.Error(), "nope") {
		t.Fatalf("wrong-login error = %v", err)
	}

	// The per-collect login mirrors the channel — the repodata and the package
	// downloads all authenticate.
	good := req
	good.Auth = &HostCollectAuth{Username: "bot", Password: "hunter2"}
	if _, err := ls.CollectConda(ctx, good); err != nil {
		t.Fatalf("authenticated collect: %v", err)
	}

	// Standing ARTIGATE_UPSTREAM_AUTH credentials work without request auth —
	// the only credential source scheduled collects have.
	t.Setenv(upstreamAuthEnv, strings.TrimPrefix(up.srv.URL, "http://")+"=bot:hunter2")
	force := req
	force.Force = true
	if _, err := ls.CollectConda(ctx, force); err != nil {
		t.Fatalf("env-authenticated collect: %v", err)
	}

	// A channel URL that smuggles the login as userinfo is rejected without
	// echoing it (the URL would cross the diode inside the signed manifest).
	userinfo := req
	userinfo.Channel = "http://bot:hunter2@" + strings.TrimPrefix(up.srv.URL, "http://")
	_, err = ls.CollectConda(ctx, userinfo)
	if err == nil || !strings.Contains(err.Error(), "must not embed credentials") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("userinfo channel error = %v", err)
	}
}

// TestCondaCandidateOrdering pins the tie-breaking rules the greedy resolver
// selects by: version, then build number, then subdir (platform-specific
// beats noarch on ties), then filename (.conda beats .tar.bz2).
func TestCondaCandidateOrdering(t *testing.T) {
	mk := func(version string, buildNumber int64, subdir, filename string) condaCandidate {
		return condaCandidate{
			entry:    condaRepodataEntry{Name: "pkg", Version: version, Build: "0", BuildNumber: buildNumber},
			subdir:   subdir,
			filename: filename,
		}
	}
	for name, tt := range map[string]struct {
		a, b condaCandidate
		less bool
	}{
		"older version":       {mk("1.0", 5, "noarch", "a"), mk("1.1", 0, "noarch", "a"), true},
		"lower build number":  {mk("1.0", 1, "noarch", "a"), mk("1.0", 2, "noarch", "a"), true},
		"noarch under linux":  {mk("1.0", 1, "noarch", "a"), mk("1.0", 1, "linux-64", "a"), true},
		"tar.bz2 under conda": {mk("1.0", 1, "noarch", "pkg-1.0-0.tar.bz2"), mk("1.0", 1, "noarch", "pkg-1.0-0.conda"), true},
		"equal is not less":   {mk("1.0", 1, "noarch", "a"), mk("1.0", 1, "noarch", "a"), false},
	} {
		if got := condaCandidateLess(tt.a, tt.b); got != tt.less {
			t.Errorf("%s: condaCandidateLess = %v, want %v", name, got, tt.less)
		}
	}
}

// TestCondaMirrorNameDefaults pins the default mirror naming: a bare channel
// name is its own mirror name (the high side serves /conda/conda-forge for a
// "conda-forge" collect), while a full URL falls back to the URL slug, and an
// explicit name always wins.
func TestCondaMirrorNameDefaults(t *testing.T) {
	ls, _ := newCondaLowServer(t)
	base := func(req CondaCollectRequest) string {
		t.Helper()
		req.Packages = []string{"pkg"}
		mirror, _, _, err := ls.validateCondaRequest(req)
		if err != nil {
			t.Fatalf("validateCondaRequest(%+v): %v", req, err)
		}
		return mirror
	}
	if got := base(CondaCollectRequest{Channel: "conda-forge"}); got != "conda-forge" {
		t.Errorf("bare channel mirror = %q, want conda-forge", got)
	}
	if got := base(CondaCollectRequest{Channel: "conda-forge", Name: "sci"}); got != "sci" {
		t.Errorf("explicit name mirror = %q, want sci", got)
	}
	if got := base(CondaCollectRequest{Channel: "https://repo.example/stack"}); got == "" || strings.Contains(got, "/") {
		t.Errorf("URL channel mirror = %q, want a path-safe slug", got)
	}
}
