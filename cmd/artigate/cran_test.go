package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/md5" //nolint:gosec // fixtures mirror CRAN's MD5-only index
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

// cranTestTarGz builds a source package archive containing
// "<name>/DESCRIPTION" with the given extra DCF fields.
func cranTestTarGz(t *testing.T, name, version string, extra map[string]string) []byte {
	t.Helper()
	desc := fmt.Sprintf("Package: %s\nVersion: %s\nLicense: MIT\nTitle: Test package %s\n", name, version, name)
	for k, v := range extra {
		desc += k + ": " + v + "\n"
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := []struct{ name, body string }{
		{name + "/DESCRIPTION", desc},
		{name + "/NAMESPACE", "exportPattern(\"^[[:alpha:]]+\")\n"},
	}
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cranTestMD5(b []byte) string {
	h := md5.Sum(b) //nolint:gosec // fixture checksum matching CRAN's index format
	return hex.EncodeToString(h[:])
}

// cranTestEntry describes one package the fake mirror serves: its current
// index record and tarball, plus optional archived versions.
type cranTestEntry struct {
	name     string
	version  string
	deps     map[string]string // PACKAGES dependency fields, e.g. "Imports": "pkgB"
	body     []byte
	noMD5    bool
	archived map[string][]byte // version -> tarball bytes under Archive/<name>/
}

// fakeCRANRepo serves src/contrib/PACKAGES (plain only — exercising the .gz
// fallback), the current tarballs, and the Archive tree.
func fakeCRANRepo(t *testing.T, entries []cranTestEntry) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var idx strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&idx, "Package: %s\nVersion: %s\n", e.name, e.version)
		for k, v := range e.deps {
			fmt.Fprintf(&idx, "%s: %s\n", k, v)
		}
		if !e.noMD5 {
			fmt.Fprintf(&idx, "MD5sum: %s\n", cranTestMD5(e.body))
		}
		idx.WriteString("\n")
		body := e.body
		mux.HandleFunc("/src/contrib/"+cranFilename(e.name, e.version), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		})
		for v, b := range e.archived {
			old := b
			mux.HandleFunc("/src/contrib/Archive/"+e.name+"/"+cranFilename(e.name, v), func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(old)
			})
		}
	}
	mux.HandleFunc("/src/contrib/PACKAGES", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(idx.String()))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newCRANLowServer(t *testing.T, mirror string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), CRANMirror: mirror}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// -----------------------------------------------------------------------------
// Unit: naming, DCF, versions, specs
// -----------------------------------------------------------------------------

func TestCRANValidateNames(t *testing.T) {
	for _, n := range []string{"jsonlite", "data.table", "R6", "praise", "Matrix"} {
		if err := validateCRANName(n); err != nil {
			t.Errorf("validateCRANName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range []string{"", "1pkg", ".hidden", "-flag", "a_b", "a/b", "a b", strings.Repeat("x", 129)} {
		if err := validateCRANName(n); err == nil {
			t.Errorf("validateCRANName(%q) = nil, want error", n)
		}
	}
	for _, v := range []string{"1.0", "1.0-2", "0.5.0.9000", "2024.1"} {
		if err := validateCRANVersion(v); err != nil {
			t.Errorf("validateCRANVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range []string{"", "v1.0", "1.0a", "-1", "1/0", "1 0"} {
		if err := validateCRANVersion(v); err == nil {
			t.Errorf("validateCRANVersion(%q) = nil, want error", v)
		}
	}
}

func TestCRANParseDCFRecords(t *testing.T) {
	in := "Package: a\nVersion: 1.0\nDepends: R (>= 3.5),\n jsonlite (>= 1.7),\n\tmethods\n\nPackage: b\nVersion: 2.0-1\nNoColonLineIgnored\n"
	recs := parseDCFRecords([]byte(in))
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(recs), recs)
	}
	if recs[0]["Package"] != "a" || recs[1]["Package"] != "b" {
		t.Errorf("record names = %q, %q", recs[0]["Package"], recs[1]["Package"])
	}
	// Folded continuation lines join with single spaces.
	if got := recs[0]["Depends"]; got != "R (>= 3.5), jsonlite (>= 1.7), methods" {
		t.Errorf("folded Depends = %q", got)
	}
	if got := cranDepNames(recs[0]["Depends"]); len(got) != 2 || got[0] != "jsonlite" || got[1] != "methods" {
		t.Errorf("cranDepNames = %v, want [jsonlite methods]", got)
	}
}

func TestCRANVersionCompare(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		less bool
	}{
		{"1.0", "1.0.1", true},
		{"1.0-1", "1.0-2", true},
		{"1.9", "1.10", true},
		{"2.0", "1.9.9", false},
		{"1.0", "1.0", false},
		{"1.0-2", "1.0.2", false}, // separators are equivalent
	} {
		if got := cranVersionLess(tt.a, tt.b); got != tt.less {
			t.Errorf("cranVersionLess(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.less)
		}
	}
}

func TestCRANSpecParse(t *testing.T) {
	name, version, err := parseCRANSpec("jsonlite@1.8.8")
	if err != nil || name != "jsonlite" || version != "1.8.8" {
		t.Errorf("parseCRANSpec pinned = %q, %q, %v", name, version, err)
	}
	name, version, err = parseCRANSpec(" praise ")
	if err != nil || name != "praise" || version != "" {
		t.Errorf("parseCRANSpec bare = %q, %q, %v", name, version, err)
	}
	if _, _, err := parseCRANSpec("bad_name"); err == nil {
		t.Error("parseCRANSpec accepted an invalid name")
	}
	if _, _, err := parseCRANSpec("ok@not-a-version!"); err == nil {
		t.Error("parseCRANSpec accepted an invalid version")
	}
}

func TestCRANBasePackages(t *testing.T) {
	if !isCRANBasePackage("stats") || !isCRANBasePackage("utils") {
		t.Error("base packages not recognized")
	}
	if isCRANBasePackage("jsonlite") {
		t.Error("jsonlite misclassified as base")
	}
}

// -----------------------------------------------------------------------------
// Integration: low -> high pipeline
// -----------------------------------------------------------------------------

// TestCRANLowToHighPipeline mirrors a package whose dependency closure spans
// Depends and Imports (plus base packages to skip and one unresolvable dep),
// transfers the signed bundle, imports it, and checks the regenerated
// PACKAGES index, tarball serving (flat and Archive form), and hardening.
func TestCRANLowToHighPipeline(t *testing.T) {
	pkgA := cranTestTarGz(t, "pkgA", "1.2-3", map[string]string{"Depends": "R (>= 3.5), pkgB", "Imports": "pkgC, stats"})
	pkgB := cranTestTarGz(t, "pkgB", "0.9", map[string]string{"NeedsCompilation": "no"})
	pkgC := cranTestTarGz(t, "pkgC", "2.0", nil)
	repo := fakeCRANRepo(t, []cranTestEntry{
		{name: "pkgA", version: "1.2-3", deps: map[string]string{"Depends": "R (>= 3.5), pkgB", "Imports": "pkgC, stats, ghostdep"}, body: pkgA},
		{name: "pkgB", version: "0.9", body: pkgB, noMD5: true}, // no MD5 -> unverified download path
		{name: "pkgC", version: "2.0", body: pkgC},
	})

	ls, priv := newCRANLowServer(t, repo.URL)
	res, err := ls.CollectCRAN(context.Background(), CRANCollectRequest{Packages: []string{"pkgA"}})
	if err != nil {
		t.Fatalf("CollectCRAN: %v", err)
	}
	if res.BundleID != "cran-bundle-000001" || res.ExportedModules != 3 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	// ghostdep is not in the index and must be reported, not fatal.
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "ghostdep" {
		t.Fatalf("skipped = %+v, want ghostdep", res.SkippedModules)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/cran/src/contrib/PACKAGES")
	if code != http.StatusOK {
		t.Fatalf("PACKAGES status %d: %s", code, body)
	}
	recs := parseDCFRecords([]byte(body))
	if len(recs) != 3 {
		t.Fatalf("PACKAGES lists %d packages, want 3:\n%s", len(recs), body)
	}
	byName := map[string]map[string]string{}
	for _, r := range recs {
		byName[r["Package"]] = r
	}
	// The index is regenerated from the embedded DESCRIPTION (which omits
	// ghostdep), never from the transferred upstream index (which had it).
	if got := byName["pkgA"]["Imports"]; got != "pkgC, stats" {
		t.Errorf("pkgA Imports = %q, want the DESCRIPTION's own value", got)
	}
	if got := byName["pkgA"]["MD5sum"]; got != cranTestMD5(pkgA) {
		t.Errorf("pkgA MD5sum = %q, want recomputed %q", got, cranTestMD5(pkgA))
	}
	if byName["pkgB"]["NeedsCompilation"] != "no" {
		t.Errorf("pkgB NeedsCompilation missing: %+v", byName["pkgB"])
	}

	// PACKAGES.gz decompresses to the same index.
	code, gzBody := httpGet(t, srv.URL+"/cran/src/contrib/PACKAGES.gz")
	if code != http.StatusOK {
		t.Fatalf("PACKAGES.gz status %d", code)
	}
	plain, err := gunzipCapped([]byte(gzBody), 1<<20)
	if err != nil || string(plain) != body {
		t.Errorf("PACKAGES.gz mismatch (err %v)", err)
	}

	// Tarballs serve the exact collected bytes, flat and via Archive/.
	if code, got := httpGet(t, srv.URL+"/cran/src/contrib/pkgA_1.2-3.tar.gz"); code != http.StatusOK || got != string(pkgA) {
		t.Errorf("flat tarball: status %d, %d bytes (want %d)", code, len(got), len(pkgA))
	}
	if code, got := httpGet(t, srv.URL+"/cran/src/contrib/Archive/pkgA/pkgA_1.2-3.tar.gz"); code != http.StatusOK || got != string(pkgA) {
		t.Errorf("Archive tarball: status %d, %d bytes", code, len(got))
	}

	// The private metadata store is never served; traversal and writes bounce.
	if code, _ := httpGet(t, srv.URL+"/cran/metadata/pkgA_1.2-3.json"); code != http.StatusNotFound {
		t.Errorf("metadata store must 404, got %d", code)
	}
	if code, _ := httpGet(t, srv.URL+"/cran/src/contrib/..%2f..%2fimport-state.json"); code == http.StatusOK {
		t.Error("traversal returned 200")
	}
	resp, err := http.Post(srv.URL+"/cran/src/contrib/PACKAGES", "text/plain", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST PACKAGES status %d, want 405", resp.StatusCode)
	}

	// Dashboard detail reads the stored metadata.
	det, err := hs.cranDetail("pkgA@1.2-3")
	if err != nil || det.Title != "pkgA" || det.Subtitle != "1.2-3" {
		t.Fatalf("cranDetail = %+v, %v", det, err)
	}
	if len(det.Downloads) != 1 || det.Downloads[0].URL != "/cran/src/contrib/pkgA_1.2-3.tar.gz" {
		t.Errorf("detail downloads = %+v", det.Downloads)
	}
	mods, err := hs.listCRANPackages()
	if err != nil || len(mods) != 3 {
		t.Fatalf("listCRANPackages = %+v, %v", mods, err)
	}
}

// TestCRANPinnedArchiveVersion pins a version the index has superseded: the
// tarball comes from the mirror's Archive tree, and the archived release's
// own DESCRIPTION — not the index's record of the current release — supplies
// the dependency closure (old pkgA needs pkgOld, which today's pkgA dropped).
func TestCRANPinnedArchiveVersion(t *testing.T) {
	current := cranTestTarGz(t, "pkgA", "2.0", map[string]string{"Imports": "pkgNew"})
	old := cranTestTarGz(t, "pkgA", "1.0", map[string]string{"Imports": "pkgOld, stats"})
	pkgOld := cranTestTarGz(t, "pkgOld", "0.5", nil)
	repo := fakeCRANRepo(t, []cranTestEntry{
		{name: "pkgA", version: "2.0", deps: map[string]string{"Imports": "pkgNew"}, body: current, archived: map[string][]byte{"1.0": old}},
		{name: "pkgOld", version: "0.5", body: pkgOld},
	})
	ls, _ := newCRANLowServer(t, repo.URL)
	res, err := ls.CollectCRAN(context.Background(), CRANCollectRequest{Packages: []string{"pkgA@1.0"}})
	if err != nil {
		t.Fatalf("CollectCRAN: %v", err)
	}
	// The archived pkgA plus its own dependency pkgOld — and NOT the current
	// release's pkgNew (absent from the fake index, it would have been a
	// skipped module if queued).
	if res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("expected the archived release plus its own dependency, got %+v", res)
	}
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, res.BundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"pkgA"`, `"1.0"`, `"pkgOld"`, `"0.5"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("manifest missing %s: %s", want, b)
		}
	}
	if strings.Contains(string(b), "pkgA_2.0") {
		t.Errorf("pinned collect also mirrored the current release: %s", b)
	}
}

// TestCRANCollectMD5Tamper proves an index-declared MD5 that does not match
// the served tarball fails that package (and a sole tampered package fails
// the collect).
func TestCRANCollectMD5Tamper(t *testing.T) {
	body := cranTestTarGz(t, "pkgA", "1.0", nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/src/contrib/PACKAGES", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "Package: pkgA\nVersion: 1.0\nMD5sum: %s\n\n", strings.Repeat("0", 32))
	})
	mux.HandleFunc("/src/contrib/pkgA_1.0.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newCRANLowServer(t, srv.URL)
	if _, err := ls.CollectCRAN(context.Background(), CRANCollectRequest{Packages: []string{"pkgA"}}); err == nil {
		t.Fatal("tampered MD5 did not fail the collect")
	}
}

// TestCRANValidateContent covers the import-time manifest checks.
func TestCRANValidateContent(t *testing.T) {
	good := CRANPackage{Name: "pkgA", Version: "1.0", Filename: "pkgA_1.0.tar.gz", Path: "cran/src/contrib/pkgA_1.0.tar.gz", SHA256: strings.Repeat("a", 64)}
	seen := map[string]bool{good.Path: true}
	if err := validateCRANPackages([]CRANPackage{good}, seen); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	for name, bad := range map[string]CRANPackage{
		"bad name":          {Name: "no_good", Version: "1.0", Filename: "no_good_1.0.tar.gz", Path: "cran/src/contrib/no_good_1.0.tar.gz"},
		"bad version":       {Name: "pkgA", Version: "v1", Filename: "pkgA_v1.tar.gz", Path: "cran/src/contrib/pkgA_v1.tar.gz"},
		"wrong filename":    {Name: "pkgA", Version: "1.0", Filename: "pkgA-1.0.tar.gz", Path: "cran/src/contrib/pkgA-1.0.tar.gz"},
		"path outside tree": {Name: "pkgA", Version: "1.0", Filename: "pkgA_1.0.tar.gz", Path: "cran/pkgA_1.0.tar.gz"},
		"file not listed":   {Name: "pkgB", Version: "1.0", Filename: "pkgB_1.0.tar.gz", Path: "cran/src/contrib/pkgB_1.0.tar.gz"},
	} {
		if err := validateCRANPackages([]CRANPackage{bad}, seen); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestCRANPublishRejectsForgedIdentity proves the embedded DESCRIPTION is the
// authority: a tarball whose DESCRIPTION disagrees with the manifest record
// is not published.
func TestCRANPublishRejectsForgedIdentity(t *testing.T) {
	_, priv := newTestKeys(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	forged := cranTestTarGz(t, "pkgA", "9.9", nil) // embedded version disagrees
	abs := filepath.Join(hs.downloadDir, "cran", "src", "contrib", "pkgA_1.0.tar.gz")
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, forged, 0o644); err != nil {
		t.Fatal(err)
	}
	p := CRANPackage{Name: "pkgA", Version: "1.0", Filename: "pkgA_1.0.tar.gz", Path: "cran/src/contrib/pkgA_1.0.tar.gz"}
	if err := hs.publishCRANPackage(p); err == nil {
		t.Fatal("forged DESCRIPTION accepted")
	}
	// The tarball parses but names another version, so nothing may be listed.
	if err := hs.regenerateCRANIndex(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(hs.cranContribDir(), "PACKAGES"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "pkgA") {
		t.Errorf("unpublished package leaked into PACKAGES: %s", b)
	}
}

// TestCRANIndexNewestOnly proves PACKAGES lists only the newest present
// release of a package while older tarballs stay downloadable.
func TestCRANIndexNewestOnly(t *testing.T) {
	_, priv := newTestKeys(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	for _, v := range []string{"1.0", "1.2"} {
		body := cranTestTarGz(t, "pkgA", v, nil)
		abs := filepath.Join(hs.cranContribDir(), cranFilename("pkgA", v))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, body, 0o644); err != nil {
			t.Fatal(err)
		}
		p := CRANPackage{Name: "pkgA", Version: v, Filename: cranFilename("pkgA", v), Path: cranFileRel(cranFilename("pkgA", v))}
		if err := hs.publishCRANPackage(p); err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
	}
	if err := hs.regenerateCRANIndex(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(hs.cranContribDir(), "PACKAGES"))
	if err != nil {
		t.Fatal(err)
	}
	recs := parseDCFRecords(b)
	if len(recs) != 1 || recs[0]["Version"] != "1.2" {
		t.Fatalf("PACKAGES = %+v, want only 1.2", recs)
	}
}

// TestCRANHandleCollect drives the admin endpoint wrapper: a valid JSON body
// reaches the collector (which then fails on the unreachable mirror), a
// malformed body is rejected before any network traffic, and an empty body
// falls through to request validation.
func TestCRANHandleCollect(t *testing.T) {
	ls, _ := newCRANLowServer(t, "http://127.0.0.1:1")
	req := httptest.NewRequest(http.MethodPost, "/admin/cran/collect", strings.NewReader(`{"packages":["praise"]}`))
	if _, err := ls.HandleCRANCollect(context.Background(), req); err == nil {
		t.Fatal("collect against an unreachable mirror succeeded")
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/cran/collect", strings.NewReader(`{not json`))
	if _, err := ls.HandleCRANCollect(context.Background(), req); err == nil || !strings.Contains(err.Error(), "parse cran collect request") {
		t.Fatalf("malformed body error = %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/cran/collect", strings.NewReader(""))
	if _, err := ls.HandleCRANCollect(context.Background(), req); err == nil || !strings.Contains(err.Error(), "no r packages") {
		t.Fatalf("empty body error = %v", err)
	}
}

// TestCRANRequestValidation covers the request validator's rejections.
func TestCRANRequestValidation(t *testing.T) {
	if err := validateCRANRequest(CRANCollectRequest{}); err == nil {
		t.Error("empty request accepted")
	}
	if err := validateCRANRequest(CRANCollectRequest{Packages: []string{"ok", "bad_name"}}); err == nil {
		t.Error("invalid spec accepted")
	}
	if err := validateCRANRequest(CRANCollectRequest{Packages: []string{"jsonlite@1.8.8"}}); err != nil {
		t.Errorf("valid request rejected: %v", err)
	}
}

// TestCRANStoredMetadataHardening covers readCRANStored's rejection branches:
// unparsable JSON, a forged filename, a bad embedded identity, and a stem
// that escapes the metadata tree.
func TestCRANStoredMetadataHardening(t *testing.T) {
	_, priv := newTestKeys(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	metaDir := hs.cranMetadataDir()
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(metaDir, "pkgA_1.0.json"), []byte("{not json"))
	if _, err := hs.readCRANStored("pkgA_1.0"); err == nil {
		t.Error("unparsable stored metadata accepted")
	}
	writeFile(t, filepath.Join(metaDir, "pkgB_1.0.json"), []byte(`{"filename":"../../evil.tar.gz","fields":{"Package":"pkgB","Version":"1.0"}}`))
	if _, err := hs.readCRANStored("pkgB_1.0"); err == nil {
		t.Error("forged stored filename accepted")
	}
	writeFile(t, filepath.Join(metaDir, "pkgC_1.0.json"), []byte(`{"filename":"pkgC_1.0.tar.gz","fields":{"Package":"1bad","Version":"1.0"}}`))
	if _, err := hs.readCRANStored("pkgC_1.0"); err == nil {
		t.Error("invalid embedded identity accepted")
	}
	if _, err := hs.readCRANStored("../escape"); err == nil {
		t.Error("stem traversal accepted")
	}
	// Valid metadata whose tarball is absent is not servable either.
	writeFile(t, filepath.Join(metaDir, "pkgD_1.0.json"), []byte(`{"filename":"pkgD_1.0.tar.gz","fields":{"Package":"pkgD","Version":"1.0"}}`))
	if _, err := hs.readCRANStored("pkgD_1.0"); err == nil {
		t.Error("metadata without its tarball accepted")
	}
}

// TestCRANPublishPathHardening covers publishCRANPackage's identity and path
// gates ahead of any archive parsing.
func TestCRANPublishPathHardening(t *testing.T) {
	_, priv := newTestKeys(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	for name, p := range map[string]CRANPackage{
		"bad name":     {Name: "1bad", Version: "1.0", Filename: "x", Path: "cran/src/contrib/x"},
		"bad version":  {Name: "pkgA", Version: "v1", Filename: "x", Path: "cran/src/contrib/x"},
		"outside tree": {Name: "pkgA", Version: "1.0", Filename: "pkgA_1.0.tar.gz", Path: "python/packages/pkgA_1.0.tar.gz"},
		"missing file": {Name: "pkgA", Version: "1.0", Filename: "pkgA_1.0.tar.gz", Path: "cran/src/contrib/pkgA_1.0.tar.gz"},
	} {
		if err := hs.publishCRANPackage(p); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestCRANServablePathTable pins the served-tree gate.
func TestCRANServablePathTable(t *testing.T) {
	for rel, want := range map[string]string{
		"src/contrib/PACKAGES":                       "PACKAGES",
		"src/contrib/PACKAGES.gz":                    "PACKAGES.gz",
		"src/contrib/pkgA_1.0.tar.gz":                "pkgA_1.0.tar.gz",
		"src/contrib/Archive/pkgA/pkgA_1.0.tar.gz":   "pkgA_1.0.tar.gz",
		"src/contrib/PACKAGES.rds":                   "",
		"src/contrib/Archive/1bad/pkgA_1.0.tar.gz":   "",
		"src/contrib/Archive/pkgA/other_1.0.tar.gz2": "",
		"metadata/pkgA_1.0.json":                     "",
		"src/contrib":                                "",
		"src/contrib/pkgA-1.0.tar.gz":                "",
	} {
		got, ok := cranServableFile(rel)
		if (want == "") == ok || got != want {
			t.Errorf("cranServableFile(%q) = %q, %v; want %q", rel, got, ok, want)
		}
	}
}
