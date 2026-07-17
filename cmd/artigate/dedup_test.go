package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// newBareLowServer makes a low server with only a working root and export dir —
// enough to exercise the exported-content index directly, no fetch tools.
func newBareLowServer(t *testing.T) *LowServer {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls
}

func mf(path, hashChar string) ManifestFile {
	return ManifestFile{Path: path, SHA256: strings.Repeat(hashChar, 64), Size: 1}
}

// priorFlags renders which files are marked prior, for compact assertions.
func priorFlags(files []ManifestFile) []bool {
	out := make([]bool, len(files))
	for i, f := range files {
		out[i] = f.Prior
	}
	return out
}

// TestForwardedIndex covers the dedup primitives: nothing is marked on an
// empty index, recorded files come back prior, the rows are path-qualified
// (the same content at a new path is new) and per-stream, and recording is
// idempotent.
func TestForwardedIndex(t *testing.T) {
	ls := newBareLowServer(t)
	files := []ManifestFile{mf("npm/packages/a.tgz", "a"), mf("npm/packages/b.tgz", "b")}

	ls.markPriorFiles(streamNpm, files)
	if files[0].Prior || files[1].Prior {
		t.Error("nothing recorded yet, nothing may be marked prior")
	}

	ls.recordForwarded(streamNpm, files)
	marked := []ManifestFile{mf("npm/packages/a.tgz", "a"), mf("npm/packages/b.tgz", "b"), mf("npm/packages/c.tgz", "c")}
	ls.markPriorFiles(streamNpm, marked)
	if got := priorFlags(marked); !got[0] || !got[1] || got[2] {
		t.Errorf("prior flags = %v, want [true true false]", got)
	}

	// The index is path-qualified: known content at a new path is new again
	// (a prior reference must name a path the high side really holds).
	moved := []ManifestFile{mf("npm/packages/renamed.tgz", "a")}
	ls.markPriorFiles(streamNpm, moved)
	if moved[0].Prior {
		t.Error("same content at a new path must not be prior")
	}

	// And per-stream: the same files on another stream are unseen.
	other := []ManifestFile{mf("npm/packages/a.tgz", "a")}
	ls.markPriorFiles(streamPython, other)
	if other[0].Prior {
		t.Error("the index must be per-stream")
	}

	if ok, err := ls.exported.IsForwarded(streamNpm, "npm/packages/a.tgz", strings.Repeat("a", 64)); err != nil || !ok {
		t.Errorf("IsForwarded(recorded) = %v, %v; want true", ok, err)
	}
	if ok, err := ls.exported.IsForwarded(streamNpm, "npm/packages/a.tgz", strings.Repeat("f", 64)); err != nil || ok {
		t.Errorf("IsForwarded(unknown hash) = %v, %v; want false", ok, err)
	}

	// Recording again is a no-op set insert.
	ls.recordForwarded(streamNpm, files)
	n, err := ls.exported.Count(streamNpm)
	if err != nil || n != 2 {
		t.Errorf("index should hold exactly 2 hashes, got %d (err %v)", n, err)
	}
}

// TestLegacyExportedMigration proves an index written by the hash-only schema
// still suppresses re-sending: its rows migrate with an empty path (matching
// any path with that hash), the legacy table is dropped, and the next record
// adds path-qualified rows.
func TestLegacyExportedMigration(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "exported.db")
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	for _, stmt := range []string{
		`CREATE TABLE exported_content (stream TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY (stream, sha256)) WITHOUT ROWID`,
		`INSERT INTO exported_content (stream, sha256) VALUES ('npm', '` + sha + `')`,
	} {
		if _, err := legacy.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenExportedStore(dbPath)
	if err != nil {
		t.Fatalf("open store over legacy db: %v", err)
	}
	defer store.Close()

	// A legacy row matches the hash under any path.
	if ok, err := store.IsForwarded(streamNpm, "npm/packages/whatever.tgz", sha); err != nil || !ok {
		t.Errorf("legacy row should match any path, got %v, %v", ok, err)
	}
	if n, err := store.Count(streamNpm); err != nil || n != 1 {
		t.Errorf("Count = %d, %v; want 1", n, err)
	}

	// The legacy table is gone and re-recording path-qualifies the content.
	var name string
	err = store.db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exported_content'`).Scan(&name)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("legacy table should be dropped, got %q, %v", name, err)
	}
	if err := store.Record(streamNpm, []ManifestFile{{Path: "npm/packages/a.tgz", SHA256: sha, Size: 1}}); err != nil {
		t.Fatal(err)
	}
	if n, err := store.Count(streamNpm); err != nil || n != 1 {
		t.Errorf("Count after re-record = %d, %v; want 1 (same content)", n, err)
	}
}

// TestExportedIndexFailsSafe proves a store error never suppresses content:
// markPriorFiles marks nothing (export everything) and the pre-download check
// says "not forwarded" (download it).
func TestExportedIndexFailsSafe(t *testing.T) {
	ls := newBareLowServer(t)
	files := []ManifestFile{mf("npm/packages/a.tgz", "a")}
	ls.recordForwarded(streamNpm, files)

	// Close the store out from under the collector: every query now errors.
	if err := ls.exported.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := []ManifestFile{mf("npm/packages/a.tgz", "a")}
	ls.markPriorFiles(streamNpm, fresh)
	if fresh[0].Prior {
		t.Error("a store error must fail safe (export, not skip)")
	}
	if ls.priorFileCheck(streamNpm, false)("npm/packages/a.tgz", strings.Repeat("a", 64)) {
		t.Error("a store error must fail safe (download, not skip)")
	}
}

// stageTestFile writes one file under stage and returns its manifest entry.
func stageTestFile(t *testing.T, stage, rel, content string) ManifestFile {
	t.Helper()
	abs := filepath.Join(stage, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return ManifestFile{Path: rel, SHA256: aptSHA256([]byte(content)), Size: int64(len(content))}
}

// listArchiveEntries returns the sorted file names inside a bundle's tar.gz.
func listArchiveEntries(t *testing.T, dir, bundleID string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, bundleID+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	sort.Strings(names)
	return names
}

// TestExportDeltaBundle drives exportIfNew with real staged files through the
// four export shapes: a first full bundle, a delta whose archive carries only
// the new file, an all-prior skip, and a forced full re-export.
func TestExportDeltaBundle(t *testing.T) {
	ls := newBareLowServer(t)
	ctx := context.Background()
	stage := t.TempDir()
	a := stageTestFile(t, stage, "data/a.bin", "content-a")
	b := stageTestFile(t, stage, "data/b.bin", "content-b")
	c := stageTestFile(t, stage, "data/c.bin", "content-c")

	export := func(files []ManifestFile, force bool) (ExportResult, error) {
		return ls.exportIfNew(ctx, streamNpm, stage, files, force, func(seq int64) (ExportResult, error) {
			id := bundleIDFor(streamNpm, seq)
			if err := ls.writeBundleArtifacts(ctx, id, stage, []byte("{}"), files); err != nil {
				return ExportResult{}, err
			}
			return ExportResult{Stream: streamNpm, Sequence: seq, BundleID: id}, nil
		})
	}

	// First export: everything is new and packed.
	files1 := []ManifestFile{a, b}
	res1, err := export(files1, false)
	if err != nil {
		t.Fatal(err)
	}
	if res1.PriorFiles != 0 {
		t.Errorf("first export PriorFiles = %d, want 0", res1.PriorFiles)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, res1.BundleID); len(got) != 2 {
		t.Errorf("first archive = %v, want a and b", got)
	}

	// Second export: only c is new; a and b become prior manifest entries.
	files2 := []ManifestFile{a, b, c}
	res2, err := export(files2, false)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Skipped || res2.PriorFiles != 2 {
		t.Fatalf("delta export = %+v, want PriorFiles 2", res2)
	}
	if got := priorFlags(files2); !got[0] || !got[1] || got[2] {
		t.Errorf("prior flags = %v, want [true true false]", got)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, res2.BundleID); len(got) != 1 || got[0] != "data/c.bin" {
		t.Errorf("delta archive = %v, want only data/c.bin", got)
	}

	// Third export: nothing new — skipped, no sequence burned.
	res3, err := export([]ManifestFile{a, b, c}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res3.Skipped || res3.BundleID != "" {
		t.Fatalf("all-prior export should skip, got %+v", res3)
	}
	if seq := ls.peekSequence(streamNpm); seq != 3 {
		t.Errorf("next sequence = %d, want 3 (a skip must not burn a number)", seq)
	}

	// Forced export: full self-contained bundle despite everything forwarded.
	res4, err := export([]ManifestFile{a, b, c}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res4.Skipped || res4.PriorFiles != 0 {
		t.Fatalf("forced export = %+v, want a full bundle", res4)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, res4.BundleID); len(got) != 3 {
		t.Errorf("forced archive = %v, want all three files", got)
	}
}

// TestNpmCollectSkipsUnchanged drives the whole collector: a second identical
// collect produces no bundle and burns no sequence number, while the first
// still exported normally. (The complementary path — new content still exports
// and advances the sequence — is covered by TestLowServerExportSkipsUnfetchableModule,
// whose second collect adds a fresh module through the same exportIfNew gate.)
func TestNpmCollectSkipsUnchanged(t *testing.T) {
	fx := newNpmFixture(t)

	res1, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err != nil {
		t.Fatalf("first CollectNpm: %v", err)
	}
	if res1.Skipped || res1.BundleID != "npm-bundle-000001" || res1.ExportedModules != 2 {
		t.Fatalf("first collect should export a bundle, got %+v", res1)
	}

	res2, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err != nil {
		t.Fatalf("second CollectNpm: %v", err)
	}
	if !res2.Skipped || res2.BundleID != "" {
		t.Fatalf("second identical collect should skip with no bundle, got %+v", res2)
	}

	// No sequence burned and no second bundle written to the diode.
	if seq := fx.ls.peekSequence(streamNpm); seq != 2 {
		t.Errorf("next sequence = %d, want 2 (a skip must not burn a number)", seq)
	}
	if bundleCompleteInDir(fx.ls.cfg.ExportDir, "npm-bundle-000002") {
		t.Error("a skipped collect must not write a second bundle")
	}
}

// -----------------------------------------------------------------------------
// Download-skip pipelines (APT, RPM, containers, Hugging Face)
// -----------------------------------------------------------------------------

// countingHandler wraps a handler, counting requests per URL path.
type countingHandler struct {
	next http.Handler
	mu   sync.Mutex
	hits map[string]int
}

func newCountingHandler(next http.Handler) *countingHandler {
	return &countingHandler{next: next, hits: map[string]int{}}
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.hits[r.URL.Path]++
	c.mu.Unlock()
	c.next.ServeHTTP(w, r)
}

func (c *countingHandler) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[path]
}

type aptTestPkg struct {
	name, version string
	deb           []byte
}

func (p aptTestPkg) rel() string {
	return fmt.Sprintf("pool/main/%s/%s/%s_%s_amd64.deb", p.name[:1], p.name, p.name, p.version)
}

// serveAptPkgs registers an APT suite carrying the given packages on mux (the
// multi-package sibling of registerAptRepo).
func serveAptPkgs(t *testing.T, mux *http.ServeMux, prefix, suite string, pkgs []aptTestPkg) {
	t.Helper()
	var stanzas strings.Builder
	for _, p := range pkgs {
		stanzas.WriteString(fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\n"+
			"Maintainer: Test <t@example.com>\nFilename: %s\nSize: %d\nSHA256: %s\n"+
			"Description: test package\n\n", p.name, p.version, p.rel(), len(p.deb), aptSHA256(p.deb)))
	}
	packages := []byte(stanzas.String())
	packagesGz, err := gzipBytes(packages)
	if err != nil {
		t.Fatal(err)
	}
	release := fmt.Sprintf("Origin: Test\nLabel: test\nSuite: %s\nCodename: %s\n", suite, suite) +
		"Components: main\nArchitectures: amd64\nDate: Mon, 01 Jan 2024 00:00:00 UTC\nSHA256:\n" +
		fmt.Sprintf(" %s %d main/binary-amd64/Packages.gz\n", aptSHA256(packagesGz), len(packagesGz)) +
		fmt.Sprintf(" %s %d main/binary-amd64/Packages\n", aptSHA256(packages), len(packages))
	distBase := prefix + "/dists/" + suite
	mux.HandleFunc(distBase+"/InRelease", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(release)) })
	mux.HandleFunc(distBase+"/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(packagesGz) })
	mux.HandleFunc(distBase+"/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(packages) })
	for _, p := range pkgs {
		deb := p.deb
		mux.HandleFunc(prefix+"/"+p.rel(), func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(deb) })
	}
}

// TestAptDeltaPipeline is the full delta round-trip: mirror one package, then
// re-mirror after the upstream gained a second one. The unchanged .deb must
// not be downloaded again nor re-packed, the delta bundle must import cleanly
// on a high side that holds the first bundle, fail loudly when the prior
// content is missing, and a forced collect must produce a full bundle again.
func TestAptDeltaPipeline(t *testing.T) {
	alpha := aptTestPkg{name: "alpha", version: "1.0", deb: []byte("DEB-ALPHA-1.0")}
	beta := aptTestPkg{name: "beta", version: "2.0", deb: []byte("DEB-BETA-2.0")}

	mux1 := http.NewServeMux()
	serveAptPkgs(t, mux1, "/repo", "stable", []aptTestPkg{alpha})
	up1 := httptest.NewServer(mux1)
	t.Cleanup(up1.Close)
	mux2 := http.NewServeMux()
	serveAptPkgs(t, mux2, "/repo", "stable", []aptTestPkg{alpha, beta})
	counting := newCountingHandler(mux2)
	up2 := httptest.NewServer(counting)
	t.Cleanup(up2.Close)

	ls, priv := newAptLowServer(t)
	req := AptCollectRequest{
		Name: "m", URI: up1.URL + "/repo",
		Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
	}
	res1, err := ls.CollectApt(context.Background(), req)
	if err != nil {
		t.Fatalf("first CollectApt: %v", err)
	}
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	transferAptBundle(t, ls, hs, res1.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import first bundle: %v", err)
	}

	// Same mirror, grown upstream: alpha must not be fetched or packed again.
	req.URI = up2.URL + "/repo"
	res2, err := ls.CollectApt(context.Background(), req)
	if err != nil {
		t.Fatalf("second CollectApt: %v", err)
	}
	if res2.Skipped || res2.PriorFiles != 1 {
		t.Fatalf("delta collect = %+v, want PriorFiles 1", res2)
	}
	if n := counting.count("/repo/" + alpha.rel()); n != 0 {
		t.Errorf("alpha.deb was downloaded %d time(s); the index download-skip should have prevented that", n)
	}
	if n := counting.count("/repo/" + beta.rel()); n != 1 {
		t.Errorf("beta.deb downloaded %d time(s), want 1", n)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, res2.BundleID); len(got) != 1 || got[0] != "apt/m/"+beta.rel() {
		t.Errorf("delta archive = %v, want only beta's .deb", got)
	}
	m2 := readBundleManifest(t, ls, res2.BundleID)
	for _, f := range m2.Files {
		if want := f.Path == "apt/m/"+alpha.rel(); f.Prior != want {
			t.Errorf("manifest prior flag for %s = %v, want %v", f.Path, f.Prior, want)
		}
	}

	// A high side missing the prior content refuses the delta with a clear
	// error, and imports fine once the content is back.
	transferAptBundle(t, ls, hs, res2.BundleID)
	alphaInstalled := filepath.Join(hs.downloadDir, filepath.FromSlash("apt/m/"+alpha.rel()))
	if err := os.Remove(alphaInstalled); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.ImportNext(); err == nil || !strings.Contains(err.Error(), "prior file") {
		t.Fatalf("import without prior content = %v, want a 'prior file' error", err)
	}
	writeFile(t, alphaInstalled, alpha.deb)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import delta bundle: %v", err)
	}

	// The merged repository serves both packages.
	srv := httptest.NewServer(hs)
	defer srv.Close()
	assertServed(t, srv.URL+"/apt/m/"+alpha.rel(), string(alpha.deb))
	assertServed(t, srv.URL+"/apt/m/"+beta.rel(), string(beta.deb))
	assertServed(t, srv.URL+"/apt/m/dists/stable/main/binary-amd64/Packages", "Package: alpha")
	assertServed(t, srv.URL+"/apt/m/dists/stable/main/binary-amd64/Packages", "Package: beta")

	// force re-sends everything: full archive, alpha fetched after all.
	req.Force = true
	res3, err := ls.CollectApt(context.Background(), req)
	if err != nil {
		t.Fatalf("forced CollectApt: %v", err)
	}
	if res3.Skipped || res3.PriorFiles != 0 {
		t.Fatalf("forced collect = %+v, want a full bundle", res3)
	}
	if n := counting.count("/repo/" + alpha.rel()); n != 1 {
		t.Errorf("forced collect fetched alpha.deb %d time(s), want 1", n)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, res3.BundleID); len(got) != 2 {
		t.Errorf("forced archive = %v, want both .debs", got)
	}
}

type rpmTestPkg struct {
	name, ver, rel string
	rpm            []byte
}

func (p rpmTestPkg) loc() string {
	return fmt.Sprintf("Packages/%s-%s-%s.x86_64.rpm", p.name, p.ver, p.rel)
}

// serveRpmPkgs registers a YUM/DNF repository carrying the given packages on
// mux (the multi-package sibling of registerRpmRepo).
func serveRpmPkgs(t *testing.T, mux *http.ServeMux, prefix string, pkgs []rpmTestPkg) {
	t.Helper()
	var pkgXML strings.Builder
	for _, p := range pkgs {
		pkgXML.WriteString(fmt.Sprintf(`<package type="rpm"><name>%s</name><arch>x86_64</arch><version epoch="0" ver="%s" rel="%s"/>`+
			`<checksum type="sha256" pkgid="YES">%s</checksum><size package="%d"/><location href="%s"/></package>`+"\n",
			p.name, p.ver, p.rel, aptSHA256(p.rpm), len(p.rpm), p.loc()))
	}
	primary := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		fmt.Sprintf(`<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="%d">`, len(pkgs)) + "\n" +
		pkgXML.String() + `</metadata>` + "\n")
	filelists := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="0"></filelists>` + "\n")
	data := func(typ string, plain []byte) string {
		gz, err := gzipBytes(plain)
		if err != nil {
			t.Fatal(err)
		}
		href := "repodata/" + typ + ".xml.gz"
		mux.HandleFunc(prefix+"/"+href, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz) })
		return fmt.Sprintf("  <data type=%q>\n    <checksum type=\"sha256\">%s</checksum>\n    <open-checksum type=\"sha256\">%s</open-checksum>\n    <location href=%q/>\n    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n",
			typ, aptSHA256(gz), aptSHA256(plain), href, len(gz), len(plain))
	}
	repomd := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<repomd xmlns="http://linux.duke.edu/metadata/repo">` + "\n  <revision>1</revision>\n" +
		data("primary", primary) + data("filelists", filelists) +
		`</repomd>` + "\n"
	mux.HandleFunc(prefix+"/repodata/repomd.xml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(repomd)) })
	for _, p := range pkgs {
		rpm := p.rpm
		mux.HandleFunc(prefix+"/"+p.loc(), func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(rpm) })
	}
}

// TestRpmDeltaCollectSkipsDownload re-mirrors an RPM repo after it gained a
// package: the unchanged .rpm is neither downloaded nor packed again, while
// the (changed) metadata files still are.
func TestRpmDeltaCollectSkipsDownload(t *testing.T) {
	alpha := rpmTestPkg{name: "alpha", ver: "1.0", rel: "1", rpm: []byte("RPM-ALPHA-1.0")}
	beta := rpmTestPkg{name: "beta", ver: "2.0", rel: "1", rpm: []byte("RPM-BETA-2.0")}

	mux1 := http.NewServeMux()
	serveRpmPkgs(t, mux1, "/yum", []rpmTestPkg{alpha})
	up1 := httptest.NewServer(mux1)
	t.Cleanup(up1.Close)
	mux2 := http.NewServeMux()
	serveRpmPkgs(t, mux2, "/yum", []rpmTestPkg{alpha, beta})
	counting := newCountingHandler(mux2)
	up2 := httptest.NewServer(counting)
	t.Cleanup(up2.Close)

	ls, _ := newRpmLowServer(t)
	res1, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "m", BaseURL: up1.URL + "/yum"})
	if err != nil {
		t.Fatalf("first CollectRpm: %v", err)
	}
	if res1.Skipped || res1.PriorFiles != 0 {
		t.Fatalf("first collect = %+v", res1)
	}

	res2, err := ls.CollectRpm(context.Background(), RpmCollectRequest{Name: "m", BaseURL: up2.URL + "/yum"})
	if err != nil {
		t.Fatalf("second CollectRpm: %v", err)
	}
	// Prior: alpha.rpm (download skipped) and the byte-identical filelists
	// (downloaded for parsing, then deduped after hashing).
	if res2.Skipped || res2.PriorFiles != 2 {
		t.Fatalf("delta collect = %+v, want PriorFiles 2 (alpha.rpm + unchanged filelists)", res2)
	}
	if n := counting.count("/yum/" + alpha.loc()); n != 0 {
		t.Errorf("alpha.rpm was downloaded %d time(s); the index download-skip should have prevented that", n)
	}
	got := listArchiveEntries(t, ls.cfg.ExportDir, res2.BundleID)
	for _, name := range got {
		if name == "rpm/m/"+alpha.loc() {
			t.Errorf("delta archive re-packs alpha.rpm: %v", got)
		}
	}
	// The changed primary index plus beta's .rpm are delivered.
	if len(got) != 2 {
		t.Errorf("delta archive = %v, want new primary + beta.rpm", got)
	}
}

// fakeImageVariant builds a single-layer image like makeFakeImage, but with a
// caller-marked config so two variants can share a layer while differing in
// config and manifest.
func fakeImageVariant(layerContent, marker string) fakeImage {
	img := fakeImage{
		layer: []byte(layerContent),
		config: []byte(`{"architecture":"amd64","os":"linux","history":[` +
			`{"created_by":"/bin/sh -c #(nop) ADD file:abc123 in / "},` +
			`{"created_by":"/bin/sh -c #(nop)  CMD [\"` + marker + `\"]","empty_layer":true}` +
			`]}`),
	}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerManifest,
		"config": map[string]any{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"digest":    containerSHA(img.config),
			"size":      len(img.config),
		},
		"layers": []map[string]any{{
			"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
			"digest":    containerSHA(img.layer),
			"size":      len(img.layer),
		}},
	}
	img.manifest, _ = json.Marshal(manifest)
	img.manifestDigest = containerSHA(img.manifest)
	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerList,
		"manifests": []map[string]any{{
			"mediaType": mtDockerManifest,
			"digest":    img.manifestDigest,
			"size":      len(img.manifest),
			"platform":  map[string]string{"architecture": "amd64", "os": "linux"},
		}},
	}
	img.index, _ = json.Marshal(index)
	return img
}

// registerSharedLayerImage registers a tag whose layer blob another image on
// the mux already serves — Go's ServeMux rejects duplicate patterns, so only
// the tag index, manifest, and config blob are added.
func registerSharedLayerImage(mux *http.ServeMux, repo, tag string, img fakeImage, requireToken func(*http.Request) bool) {
	serve := func(body []byte, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !requireToken(r) {
				w.Header().Set("Www-Authenticate", `Bearer realm="/token-not-set",service="test"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(body)
		}
	}
	mux.HandleFunc("/v2/"+repo+"/manifests/"+tag, serve(img.index, mtDockerList))
	mux.HandleFunc("/v2/"+repo+"/manifests/"+img.manifestDigest, serve(img.manifest, mtDockerManifest))
	mux.HandleFunc("/v2/"+repo+"/blobs/"+containerSHA(img.config), serve(img.config, "application/octet-stream"))
}

// TestContainerDeltaSharedLayerSkipped collects two tags sharing a layer in
// two separate collects: the second collect must not download the shared
// layer again, and its bundle must carry only the new config, manifest, and
// index.
func TestContainerDeltaSharedLayerSkipped(t *testing.T) {
	v1 := fakeImageVariant("layer-shared-bytes", "/v1")
	v2 := fakeImageVariant("layer-shared-bytes", "/v2")

	const token = "fake-pull-token"
	mux := http.NewServeMux()
	requireToken := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+token }
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"token": token})
	})
	registerFakeImage(mux, "library/app", "v1", v1, requireToken)
	registerSharedLayerImage(mux, "library/app", "v2", v2, requireToken)
	counting := newCountingHandler(mux)
	var srv *httptest.Server
	srv = httptest.NewServer(rewriteChallengeRealm(counting, func() string { return srv.URL }))
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": srv.URL})
	if _, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"app:v1"}}); err != nil {
		t.Fatalf("first CollectContainers: %v", err)
	}
	res2, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"app:v2"}})
	if err != nil {
		t.Fatalf("second CollectContainers: %v", err)
	}
	if res2.Skipped || res2.PriorFiles != 1 {
		t.Fatalf("delta collect = %+v, want PriorFiles 1 (the shared layer)", res2)
	}
	layerBlobPath := "/v2/library/app/blobs/" + containerSHA(v1.layer)
	if n := counting.count(layerBlobPath); n != 1 {
		t.Errorf("shared layer downloaded %d time(s) across both collects, want 1", n)
	}
	got := listArchiveEntries(t, ls.cfg.ExportDir, res2.BundleID)
	want := []string{
		containerBlobRel(containerSHA(v2.config)),
		containerBlobRel(v2.manifestDigest),
		containerBlobRel(containerSHA(v2.index)),
	}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("delta archive = %v, want %v", got, want)
	}
}

// TestHFDeltaSharedBlobSkipped collects two GGUF variants of one model in two
// collects: the template blob they share becomes a prior reference in the
// second bundle and only the new gguf, config, and manifest are packed.
func TestHFDeltaSharedBlobSkipped(t *testing.T) {
	q4 := makeFakeHFModel("Q4_0", "gguf-bytes-q4")
	q5 := makeFakeHFModel("Q5_K", "gguf-bytes-q5")
	hub := fakeHFHub(t, map[string]fakeHFModel{
		"unsloth/tiny-GGUF:Q4_0": q4,
		"unsloth/tiny-GGUF:Q5_K": q5,
	}, nil, "")
	ls, _ := newHFLowServer(t, hub.URL)

	if _, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"hf.co/unsloth/tiny-GGUF:Q4_0"}}); err != nil {
		t.Fatalf("first CollectHF: %v", err)
	}
	res2, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"hf.co/unsloth/tiny-GGUF:Q5_K"}})
	if err != nil {
		t.Fatalf("second CollectHF: %v", err)
	}
	if res2.Skipped || res2.PriorFiles != 1 {
		t.Fatalf("delta collect = %+v, want PriorFiles 1 (the shared template)", res2)
	}
	got := listArchiveEntries(t, ls.cfg.ExportDir, res2.BundleID)
	if len(got) != 3 {
		t.Errorf("delta archive = %v, want gguf + config + manifest", got)
	}
	templateRel := hfBlobRel(containerSHA(q5.template))
	for _, name := range got {
		if name == templateRel {
			t.Errorf("delta archive re-packs the shared template blob: %v", got)
		}
	}
	m2 := readBundleManifest(t, ls, res2.BundleID)
	for _, f := range m2.Files {
		if want := f.Path == templateRel; f.Prior != want {
			t.Errorf("manifest prior flag for %s = %v, want %v", f.Path, f.Prior, want)
		}
	}
}

// -----------------------------------------------------------------------------
// Automatic bundle splitting (oversized collects)
// -----------------------------------------------------------------------------

// splitTestBudget fits two 100-byte staged files per bundle but not three,
// so five files split into three sequenced bundles.
const splitTestBudget = int64(8500)

func stageSplitFiles(t *testing.T, stage string) []ManifestFile {
	t.Helper()
	files := make([]ManifestFile, 0, 5)
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		files = append(files, stageTestFile(t, stage, "data/"+name+".bin", strings.Repeat(name, 100)))
	}
	return files
}

// splitExport drives exportIfNew the way a collector does, with a minimal
// final-bundle writer over the shared files slice.
func splitExport(t *testing.T, ls *LowServer, stage string, files []ManifestFile) (ExportResult, error) {
	t.Helper()
	return ls.exportIfNew(context.Background(), streamNpm, stage, files, false, func(seq int64) (ExportResult, error) {
		id := bundleIDFor(streamNpm, seq)
		if err := ls.writeBundleArtifacts(context.Background(), id, stage, []byte("{}"), files); err != nil {
			return ExportResult{}, err
		}
		return ExportResult{Stream: streamNpm, Sequence: seq, BundleID: id}, nil
	})
}

// TestExportSplitBundles drives an oversized collect end to end on the low
// side: the content ships as two content parts plus the final bundle, each
// within budget, all committed and recorded.
func TestExportSplitBundles(t *testing.T) {
	ls := newBareLowServer(t)
	ls.splitBudget = splitTestBudget
	stage := t.TempDir()
	files := stageSplitFiles(t, stage)

	res, err := splitExport(t, ls, stage, files)
	if err != nil {
		t.Fatal(err)
	}
	wantBundles := []string{"npm-bundle-000001", "npm-bundle-000002", "npm-bundle-000003"}
	if fmt.Sprint(res.Bundles) != fmt.Sprint(wantBundles) || res.BundleID != wantBundles[2] || res.Sequence != 3 {
		t.Fatalf("split result = %+v, want bundles %v", res, wantBundles)
	}
	if res.PriorFiles != 0 {
		t.Errorf("PriorFiles = %d, want 0 (nothing was forwarded before this collect)", res.PriorFiles)
	}

	wantArchives := [][]string{
		{"data/a.bin", "data/b.bin"},
		{"data/c.bin", "data/d.bin"},
		{"data/e.bin"},
	}
	for i, id := range wantBundles {
		if got := listArchiveEntries(t, ls.cfg.ExportDir, id); fmt.Sprint(got) != fmt.Sprint(wantArchives[i]) {
			t.Errorf("archive %s = %v, want %v", id, got, wantArchives[i])
		}
	}

	// Content parts carry the part marker, their slice of files (none prior),
	// and no ecosystem metadata; both pass the high side's completeness check.
	for i, id := range wantBundles[:2] {
		m := readBundleManifest(t, ls, id)
		if m.Part == nil || m.Part.Index != i+1 || m.Part.Count != 3 {
			t.Fatalf("%s part marker = %+v, want %d of 3", id, m.Part, i+1)
		}
		if len(m.Files) != 2 || m.Files[0].Prior || m.Files[1].Prior {
			t.Errorf("%s files = %+v, want 2 delivered", id, m.Files)
		}
		if err := validateManifestCompleteness(m); err != nil {
			t.Errorf("content part %s fails completeness: %v", id, err)
		}
	}

	// The final write saw the parts' files flagged prior on the shared slice.
	if got := priorFlags(files); fmt.Sprint(got) != fmt.Sprint([]bool{true, true, true, true, false}) {
		t.Errorf("prior flags after split = %v", got)
	}
	if seq := ls.peekSequence(streamNpm); seq != 4 {
		t.Errorf("next sequence = %d, want 4", seq)
	}

	// Every part was recorded as forwarded, so re-collecting the same set
	// skips without burning a sequence.
	again := stageSplitFiles(t, stage)
	res2, err := splitExport(t, ls, stage, again)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Skipped {
		t.Fatalf("re-export of a fully split collect = %+v, want skipped", res2)
	}
}

// TestExportSplitOversizedFile checks the fail-fast: a single file that no
// bundle can carry aborts the collect before any sequence is allocated —
// exporting it would produce a bundle the high side rejects, wedging the
// stream.
func TestExportSplitOversizedFile(t *testing.T) {
	ls := newBareLowServer(t)
	ls.splitBudget = splitTestBudget
	stage := t.TempDir()
	files := []ManifestFile{stageTestFile(t, stage, "data/huge.bin", strings.Repeat("x", 4096))}

	_, err := splitExport(t, ls, stage, files)
	if err == nil || !strings.Contains(err.Error(), "does not fit a bundle") {
		t.Fatalf("oversized file export = %v, want a does-not-fit error", err)
	}
	if seq := ls.peekSequence(streamNpm); seq != 1 {
		t.Errorf("next sequence = %d, want 1 (no number burned)", seq)
	}
	if entries, _ := os.ReadDir(ls.cfg.ExportDir); len(entries) != 0 {
		t.Errorf("export dir not empty after a refused collect")
	}
}

// TestExportSplitPartFailureIsResumable checks that a split failing midway
// loses nothing: the committed parts stay durable on the stream, the error
// says so, and a retry collect skips their content and continues.
func TestExportSplitPartFailureIsResumable(t *testing.T) {
	ls := newBareLowServer(t)
	ls.splitBudget = splitTestBudget
	stage := t.TempDir()
	files := stageSplitFiles(t, stage)

	// Crash residue at sequence 2 makes the second part's allocation fail
	// after part one has committed.
	if err := os.MkdirAll(ls.cfg.ExportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(ls.cfg.ExportDir, "npm-bundle-000002.tar.gz")
	if err := os.WriteFile(residue, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := splitExport(t, ls, stage, files)
	if err == nil || !strings.Contains(err.Error(), "1 of 3 bundle(s) already exported and committed (npm-bundle-000001)") {
		t.Fatalf("mid-split failure = %v, want it to name the committed part", err)
	}
	if !bundleCompleteInDir(ls.cfg.ExportDir, "npm-bundle-000001") {
		t.Fatal("part one should be complete and transferable")
	}

	// Clear the residue and retry: the first part's files are already
	// forwarded, so the remaining content ships as two more bundles.
	if err := os.Remove(residue); err != nil {
		t.Fatal(err)
	}
	retry := stageSplitFiles(t, stage)
	res, err := splitExport(t, ls, stage, retry)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(res.Bundles) != fmt.Sprint([]string{"npm-bundle-000002", "npm-bundle-000003"}) || res.PriorFiles != 2 {
		t.Fatalf("retry result = %+v, want bundles 2-3 with 2 prior files", res)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, "npm-bundle-000002"); fmt.Sprint(got) != fmt.Sprint([]string{"data/c.bin", "data/d.bin"}) {
		t.Errorf("retry part archive = %v", got)
	}
}

func TestSplitDeliveredFiles(t *testing.T) {
	sized := func(path string, size int64, prior bool) ManifestFile {
		return ManifestFile{Path: path, SHA256: strings.Repeat("a", 64), Size: size, Prior: prior}
	}
	budget := int64(bundlePackBaseOverheadBytes) + 2*estimatedPackedBytes(100)

	t.Run("fits one bundle", func(t *testing.T) {
		chunks, err := splitDeliveredFiles([]ManifestFile{sized("b", 100, false), sized("a", 100, false)}, budget)
		if err != nil || len(chunks) != 1 || len(chunks[0]) != 2 {
			t.Fatalf("chunks = %v, %v", chunks, err)
		}
	})

	t.Run("splits in path order, skipping prior", func(t *testing.T) {
		files := []ManifestFile{
			sized("d", 100, false), sized("b", 100, true),
			sized("c", 100, false), sized("a", 100, false),
		}
		chunks, err := splitDeliveredFiles(files, budget)
		if err != nil {
			t.Fatal(err)
		}
		// Delivered files in path order are a, c, d -> [a c] [d].
		if len(chunks) != 2 || fmt.Sprint(chunks[0]) != fmt.Sprint([]int{3, 2}) || fmt.Sprint(chunks[1]) != fmt.Sprint([]int{0}) {
			t.Fatalf("chunks = %v", chunks)
		}
	})

	t.Run("single oversized file", func(t *testing.T) {
		if _, err := splitDeliveredFiles([]ManifestFile{sized("big", budget, false)}, budget); err == nil {
			t.Fatal("oversized file passed the partition")
		}
	})
}

func TestValidateBundlePart(t *testing.T) {
	delivered := []ManifestFile{mf("data/x", "a")}
	prior := []ManifestFile{{Path: "data/x", SHA256: strings.Repeat("a", 64), Size: 1, Prior: true}}
	for _, tc := range []struct {
		name  string
		part  BundlePartInfo
		files []ManifestFile
		ok    bool
	}{
		{"valid middle part", BundlePartInfo{Index: 1, Count: 3}, delivered, true},
		{"index below one", BundlePartInfo{Index: 0, Count: 3}, delivered, false},
		{"index beyond count", BundlePartInfo{Index: 4, Count: 3}, delivered, false},
		{"count below two", BundlePartInfo{Index: 1, Count: 1}, delivered, false},
		{"no delivered files", BundlePartInfo{Index: 1, Count: 2}, prior, false},
	} {
		err := validateBundlePart(&tc.part, tc.files)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}

	// A manifest whose only section is the part marker passes completeness;
	// one with neither still reads as empty.
	m := BundleManifest{Part: &BundlePartInfo{Index: 1, Count: 2}, Files: delivered}
	if err := validateManifestCompleteness(m); err != nil {
		t.Errorf("part-only manifest rejected: %v", err)
	}
	if err := validateManifestCompleteness(BundleManifest{Files: delivered}); err == nil || !strings.Contains(err.Error(), "content-part") {
		t.Errorf("empty manifest error = %v, want it to mention content parts", err)
	}
}

// withTestPitcherPlan attaches a socketless pitcher (plan only) so the budget
// logic sees a wire geometry, detaching it before cleanup so ls.Close never
// touches the missing socket.
func withTestPitcherPlan(t *testing.T, ls *LowServer, mtu, dataShards, parityShards int) diodePlan {
	t.Helper()
	pl, err := newDiodePlan(mtu, dataShards, parityShards)
	if err != nil {
		t.Fatal(err)
	}
	ls.pitcher = &diodePitcher{plan: pl}
	t.Cleanup(func() { ls.pitcher = nil })
	return pl
}

// TestBundleSplitBudgetRespectsWireLimit pins the budget arithmetic: without
// a pitcher the archive cap rules; with one, the wire's block-count bound
// clamps it whenever the block geometry cannot carry a full-size archive.
func TestBundleSplitBudgetRespectsWireLimit(t *testing.T) {
	ls := newBareLowServer(t)
	if got := ls.bundleSplitBudget(); got != diodeMaxArchiveBytes {
		t.Fatalf("budget without a pitcher = %d, want the archive cap %d", got, int64(diodeMaxArchiveBytes))
	}

	small := withTestPitcherPlan(t, ls, 1500, 8, 3) // 9824-byte blocks: caps a transfer below 64 GiB
	if want := int64(small.blockDataSize()) * diodeMaxBlockCount; ls.bundleSplitBudget() != want {
		t.Fatalf("budget with a small-geometry pitcher = %d, want the wire cap %d", ls.bundleSplitBudget(), want)
	}

	withTestPitcherPlan(t, ls, 9000, 200, 8) // blocks big enough that the archive cap rules again
	if got := ls.bundleSplitBudget(); got != diodeMaxArchiveBytes {
		t.Fatalf("budget with a big-geometry pitcher = %d, want the archive cap %d", got, int64(diodeMaxArchiveBytes))
	}

	ls.splitBudget = 123 // the test override stays absolute
	if got := ls.bundleSplitBudget(); got != 123 {
		t.Fatalf("budget with an override = %d, want 123", got)
	}
}

// TestExportRefusesWireUntransmittableFile is the sequence-wedge guard for
// the UDP transport: a file below the archive cap but beyond what the
// pitcher's block geometry can send must refuse the collect up front — not
// commit a bundle whose send then fails, leaving the high side waiting on a
// sequence that cannot cross until the pitcher is reconfigured.
func TestExportRefusesWireUntransmittableFile(t *testing.T) {
	ls := newBareLowServer(t)
	withTestPitcherPlan(t, ls, 1500, 8, 3) // wire cap ≈ 38 GiB, well under the 64 GiB archive cap
	files := []ManifestFile{{Path: "data/model.safetensors", SHA256: strings.Repeat("a", 64), Size: 48 << 30}}

	_, err := splitExport(t, ls, t.TempDir(), files)
	if err == nil || !strings.Contains(err.Error(), "does not fit a bundle") || !strings.Contains(err.Error(), "ARTIGATE_PITCHER_MTU") {
		t.Fatalf("wire-untransmittable export = %v, want a refusal naming the pitcher knobs", err)
	}
	if seq := ls.peekSequence(streamNpm); seq != 1 {
		t.Errorf("next sequence = %d, want 1 (no number burned)", seq)
	}
	if entries, _ := os.ReadDir(ls.cfg.ExportDir); len(entries) != 0 {
		t.Errorf("export dir not empty after a refused collect")
	}
}
