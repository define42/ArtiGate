package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// covM2 helpers (do not collide with existing package helpers).
// -----------------------------------------------------------------------------

// covM2WriteFileMF writes content under dir at the slash rel path and returns
// its hashed ManifestFile.
func covM2WriteFileMF(t *testing.T, dir, rel string, content []byte) ManifestFile {
	t.Helper()
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, content)
	f, err := hashManifestFile(abs, rel)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// covM2BuildBundle builds a manifest plus its canonical bytes over real module
// files written under src, returning the src dir so callers can pack from it.
func covM2BuildBundle(t *testing.T, seq int64, mods []moduleSpec) (src string, files []ManifestFile, manifestBytes []byte) {
	t.Helper()
	src = t.TempDir()
	var manifestMods []ManifestMod
	for _, m := range mods {
		mod, mfs := buildModuleFiles(t, src, m)
		manifestMods = append(manifestMods, mod)
		files = append(files, mfs...)
	}
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "covM2",
		BundleID:         bundleIDForSequence(seq),
		Modules:          manifestMods,
		Files:            files,
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return src, files, b
}

// -----------------------------------------------------------------------------
// NewLowServer / NewHighServer error branches
// -----------------------------------------------------------------------------

func TestCovM2_NewLowServerErrors(t *testing.T) {
	_, priv := newTestKeys(t)

	t.Run("root is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "not-a-dir")
		writeFile(t, f, []byte("x"))
		if _, err := NewLowServer(LowConfig{Root: f, ExportDir: filepath.Join(t.TempDir(), "out")}, priv); err == nil {
			t.Fatal("expected error when root is a regular file")
		}
	})

	t.Run("watch store open fails", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "watches.db"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewLowServer(LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out")}, priv); err == nil {
			t.Fatal("expected error when watches.db is a directory")
		}
	})

	t.Run("exported store open fails", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "exported.db"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewLowServer(LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out")}, priv); err == nil {
			t.Fatal("expected error when exported.db is a directory")
		}
	})
}

func TestCovM2_NewHighServerErrors(t *testing.T) {
	pub, _ := newTestKeys(t)

	t.Run("root is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "not-a-dir")
		writeFile(t, f, []byte("x"))
		if _, err := NewHighServer(HighConfig{Root: f, Landing: t.TempDir()}, pub); err == nil {
			t.Fatal("expected error when root is a regular file")
		}
	})

	t.Run("landing is a file", func(t *testing.T) {
		landing := filepath.Join(t.TempDir(), "landing-file")
		writeFile(t, landing, []byte("x"))
		if _, err := NewHighServer(HighConfig{Root: t.TempDir(), Landing: landing}, pub); err == nil {
			t.Fatal("expected error when landing is a regular file")
		}
	})

	t.Run("default quarantine dir", func(t *testing.T) {
		root := t.TempDir()
		hs, err := NewHighServer(HighConfig{Root: root, Landing: t.TempDir()}, pub)
		if err != nil {
			t.Fatal(err)
		}
		if hs.cfg.Quarantine != filepath.Join(root, "quarantine") {
			t.Errorf("Quarantine = %q, want default under root", hs.cfg.Quarantine)
		}
	})
}

// -----------------------------------------------------------------------------
// serveLowAdmin / serveLowCollect
// -----------------------------------------------------------------------------

func TestCovM2_ServeLowAdmin(t *testing.T) {
	ls := newBareLowServer(t)

	// healthz.
	rec, req := httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil)
	if !ls.serveLowAdmin(rec, req) || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}

	// /admin/bundles GET returns JSON.
	rec, req = httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/bundles", nil)
	if !ls.serveLowAdmin(rec, req) || rec.Code != http.StatusOK {
		t.Errorf("admin/bundles = %d", rec.Code)
	}

	// /admin/reexport POST with no sequences → 400 from the request parser.
	rec, req = httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/reexport", nil)
	if !ls.serveLowAdmin(rec, req) || rec.Code != http.StatusBadRequest {
		t.Errorf("admin/reexport (no spec) = %d, want 400", rec.Code)
	}

	// An unknown /admin/ path is a 404.
	rec, req = httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/nope", nil)
	if !ls.serveLowAdmin(rec, req) || rec.Code != http.StatusNotFound {
		t.Errorf("admin/nope = %d, want 404", rec.Code)
	}

	// A non-admin path is not handled.
	rec, req = httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/something-else", nil)
	if ls.serveLowAdmin(rec, req) {
		t.Error("serveLowAdmin claimed a non-admin path")
	}
}

func TestCovM2_ServeLowCollectRouting(t *testing.T) {
	ls := newBareLowServer(t)

	// Non-POST is never handled.
	rec, req := httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/go/collect", nil)
	if ls.serveLowCollect(rec, req) {
		t.Error("GET collect should not be handled")
	}

	// A POST to an unmatched path falls through.
	rec, req = httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/unknown/collect", nil)
	if ls.serveLowCollect(rec, req) {
		t.Error("unknown collect path should not be handled")
	}

	// A buffered POST is handled; the empty request errors (no modules) → 400.
	rec, req = httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/go/collect", strings.NewReader("{}"))
	if !ls.serveLowCollect(rec, req) || rec.Code != http.StatusBadRequest {
		t.Errorf("buffered go collect = %d, want 400", rec.Code)
	}
}

func TestCovM2_ServeLowCollectStreaming(t *testing.T) {
	ls := newBareLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	// ?stream=1 drives the NDJSON streaming path; the empty go collect resolves
	// no modules and streams a terminal error event with a 200 status.
	resp, err := http.Post(srv.URL+"/admin/go/collect?stream=1", "application/json", strings.NewReader("{}")) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("streaming collect status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
		t.Errorf("streaming content-type = %q", ct)
	}
}

// -----------------------------------------------------------------------------
// goEnv / fetchVersion / goLatest / resolveGoModGraph
// -----------------------------------------------------------------------------

func TestCovM2_GoEnvOptionalVars(t *testing.T) {
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:        t.TempDir(),
		ExportDir:   filepath.Join(t.TempDir(), "out"),
		GoToolchain: "local",
		GOPRIVATE:   "example.com/private",
		GONOSUMDB:   "example.com/nosum",
		GONOPROXY:   "example.com/noproxy",
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	env := ls.goEnv(context.Background())
	want := []string{
		"GOTOOLCHAIN=local",
		"GOPRIVATE=example.com/private",
		"GONOSUMDB=example.com/nosum",
		"GONOPROXY=example.com/noproxy",
	}
	joined := strings.Join(env, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("goEnv missing %q", w)
		}
	}
}

func TestCovM2_FetchVersionValidation(t *testing.T) {
	ls := newBareLowServer(t)
	ctx := context.Background()
	cases := []struct{ mod, ver string }{
		{"", "v1.0.0"},              // empty module
		{"example.com/m", ""},       // empty version
		{"example.com/m", "latest"}, // non-concrete
		{"-bad", "v1.0.0"},          // module fails validation
		{"example.com/m", "-bad"},   // version fails validation
	}
	for _, c := range cases {
		if err := ls.fetchVersion(ctx, c.mod, c.ver); err == nil {
			t.Errorf("fetchVersion(%q,%q) should error", c.mod, c.ver)
		}
	}
}

func TestCovM2_GoLatestRejectsBadModule(t *testing.T) {
	ls := newBareLowServer(t)
	if _, err := ls.goLatest(context.Background(), "-flag-like"); err == nil {
		t.Fatal("goLatest should reject a flag-like module path before running go")
	}
}

func TestCovM2_ResolveGoModGraphWithSum(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	goMod := "module artigate-project\n\ngo 1.16\n\nrequire example.com/foo/bar v1.0.0\n"
	records, err := ls.resolveGoModGraph(context.Background(), goMod, "example.com/foo/bar v1.0.0/go.mod h1:abc=\n")
	if err != nil {
		t.Fatal(err)
	}
	// The fake `go mod download -json all` emits the required module plus a
	// synthetic transitive dep.
	found := map[string]bool{}
	for _, r := range records {
		found[r.Module] = true
	}
	if !found["example.com/foo/bar"] || !found["example.com/dep"] {
		t.Errorf("resolved records = %+v, want the required module and its dep", records)
	}
}

// -----------------------------------------------------------------------------
// writeBundleArtifacts / createTarGzAtomic / addFileToTar
// -----------------------------------------------------------------------------

func TestCovM2_WriteBundleArtifacts(t *testing.T) {
	ls := newBareLowServer(t)
	ctx := context.Background()
	src, files, manifestBytes := covM2BuildBundle(t, 1, []moduleSpec{{"example.com/foo/bar", "v1.0.0"}})
	bundleID := bundleIDForSequence(1)

	if err := ls.writeBundleArtifacts(ctx, bundleID, src, manifestBytes, files); err != nil {
		t.Fatalf("first writeBundleArtifacts: %v", err)
	}
	// The three artifacts landed in the export dir.
	for _, suffix := range bundleSuffixes() {
		if !fileExists(filepath.Join(ls.cfg.ExportDir, bundleID+suffix)) {
			t.Errorf("missing artifact %s%s", bundleID, suffix)
		}
	}
	// A second write with the same id refuses to clobber the produced bundle.
	if err := ls.writeBundleArtifacts(ctx, bundleID, src, manifestBytes, files); err == nil {
		t.Fatal("expected writeBundleArtifacts to refuse overwriting an existing bundle")
	}
}

func TestCovM2_CreateTarGzAtomicErrors(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "b.tar.gz")

	// A cancelled context aborts before packing the first file.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := t.TempDir()
	f := covM2WriteFileMF(t, src, "a.txt", []byte("hello"))
	if err := createTarGzAtomic(ctx, dst, src, []ManifestFile{f}); err == nil || !strings.Contains(err.Error(), "packing stopped") {
		t.Fatalf("cancelled pack err = %v, want 'packing stopped'", err)
	}

	// An invalid manifest path is rejected by addFileToTar.
	if err := createTarGzAtomic(context.Background(), dst, src, []ManifestFile{{Path: "../evil", Size: 1}}); err == nil {
		t.Fatal("expected an invalid-path error")
	}

	// A manifest file that does not exist on disk fails the stat.
	if err := createTarGzAtomic(context.Background(), dst, src, []ManifestFile{{Path: "missing.txt", Size: 1}}); err == nil {
		t.Fatal("expected a stat error for a missing file")
	}
}

// -----------------------------------------------------------------------------
// extractAndVerifyTarGz / copyFileAtomic / writeBytesAtomic
// -----------------------------------------------------------------------------

func TestCovM2_ExtractAndVerifyTarGzErrors(t *testing.T) {
	// Missing archive.
	if err := extractAndVerifyTarGz(filepath.Join(t.TempDir(), "nope.tar.gz"), t.TempDir(), nil); err == nil {
		t.Error("expected error opening a missing archive")
	}

	// Not a gzip stream.
	notGz := filepath.Join(t.TempDir(), "plain.tar.gz")
	writeFile(t, notGz, []byte("this is not gzip"))
	if err := extractAndVerifyTarGz(notGz, t.TempDir(), nil); err == nil {
		t.Error("expected a gzip-reader error")
	}

	// A valid archive that is missing an expected (non-prior) file.
	src := t.TempDir()
	present := covM2WriteFileMF(t, src, "a.txt", []byte("present"))
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := createTarGzAtomic(context.Background(), archive, src, []ManifestFile{present}); err != nil {
		t.Fatal(err)
	}
	absent := ManifestFile{Path: "b.txt", SHA256: strings.Repeat("0", 64), Size: 3}
	if err := extractAndVerifyTarGz(archive, t.TempDir(), []ManifestFile{present, absent}); err == nil ||
		!strings.Contains(err.Error(), "missing file") {
		t.Fatalf("err = %v, want 'archive missing file'", err)
	}
}

func TestCovM2_CopyFileAtomicMissingSrc(t *testing.T) {
	dir := t.TempDir()
	if err := copyFileAtomic(filepath.Join(dir, "nope"), filepath.Join(dir, "dst"), 0o644); err == nil {
		t.Fatal("copyFileAtomic of a missing source should fail")
	}
}

func TestCovM2_WriteBytesAtomicMkdirError(t *testing.T) {
	// A regular file cannot become a parent directory.
	f := filepath.Join(t.TempDir(), "blocker")
	writeFile(t, f, []byte("x"))
	if err := writeBytesAtomic(filepath.Join(f, "sub", "file.txt"), []byte("y"), 0o644); err == nil {
		t.Fatal("writeBytesAtomic should fail when a parent path is a file")
	}
}

// -----------------------------------------------------------------------------
// installVerifiedFile / requirePriorFile / installVerifiedBundle
// -----------------------------------------------------------------------------

func TestCovM2_InstallVerifiedFile(t *testing.T) {
	staging := t.TempDir()
	base := t.TempDir()

	// Fresh install.
	f := covM2WriteFileMF(t, staging, "pkg/a.txt", []byte("content-a"))
	if err := installVerifiedFile(staging, base, f); err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(base, "pkg", "a.txt")); string(got) != "content-a" {
		t.Fatalf("installed content = %q", got)
	}

	// Re-install identical content is an idempotent no-op.
	if err := installVerifiedFile(staging, base, f); err != nil {
		t.Fatalf("idempotent re-install: %v", err)
	}

	// Unsafe destination.
	if err := installVerifiedFile(staging, base, ManifestFile{Path: "../escape", SHA256: f.SHA256, Size: f.Size}); err == nil {
		t.Error("unsafe destination should error")
	}

	// Immutable conflict: same path, different content, non-uploads subtree.
	conflict := ManifestFile{Path: "pkg/a.txt", SHA256: strings.Repeat("b", 64), Size: 5}
	if err := installVerifiedFile(staging, base, conflict); err == nil ||
		!strings.Contains(err.Error(), "immutable file conflict") {
		t.Errorf("immutable conflict err = %v", err)
	}

	// The uploads/ subtree is mutable: a new content replaces the old.
	up1 := covM2WriteFileMF(t, staging, "uploads/x.txt", []byte("v1"))
	if err := installVerifiedFile(staging, base, up1); err != nil {
		t.Fatalf("uploads install v1: %v", err)
	}
	up2 := covM2WriteFileMF(t, staging, "uploads/x.txt", []byte("v2-different"))
	if err := installVerifiedFile(staging, base, up2); err != nil {
		t.Fatalf("uploads replace v2: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(base, "uploads", "x.txt")); string(got) != "v2-different" {
		t.Errorf("uploads content after replace = %q", got)
	}
}

func TestCovM2_RequirePriorFile(t *testing.T) {
	staging := t.TempDir()
	base := t.TempDir()

	// Prior file absent from the accumulated repository.
	prior := ManifestFile{Path: "pkg/p.txt", SHA256: strings.Repeat("c", 64), Size: 4, Prior: true}
	if err := installVerifiedFile(staging, base, prior); err == nil ||
		!strings.Contains(err.Error(), "not in the repository") {
		t.Errorf("missing prior err = %v", err)
	}

	// Prior present but the size disagrees with the manifest.
	if err := os.MkdirAll(filepath.Join(base, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "pkg", "p.txt"), []byte("hi")) // size 2, not 4
	if err := installVerifiedFile(staging, base, prior); err == nil ||
		!strings.Contains(err.Error(), "does not match manifest size") {
		t.Errorf("prior size mismatch err = %v", err)
	}

	// Prior present with the right size is accepted.
	good := ManifestFile{Path: "pkg/p.txt", SHA256: strings.Repeat("c", 64), Size: 2, Prior: true}
	if err := installVerifiedFile(staging, base, good); err != nil {
		t.Errorf("valid prior file rejected: %v", err)
	}
}

func TestCovM2_InstallVerifiedBundleCompleteMarkerError(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// A module whose info path lacks the "/@v/" segment makes writeCompleteMarkers
	// fail deriving the module path — with no files, apt/rpm/npm/hf are all nil.
	manifest := BundleManifest{
		Modules: []ManifestMod{{
			Module:  "m",
			Version: "v1.0.0",
			Files:   map[string]ManifestFile{"info": {Path: "badinfo"}},
		}},
	}
	if err := hs.installVerifiedBundle(t.TempDir(), manifest); err == nil {
		t.Fatal("expected installVerifiedBundle to fail writing complete markers for a malformed info path")
	}
}

// -----------------------------------------------------------------------------
// importBundleFromDirLocked
// -----------------------------------------------------------------------------

func TestCovM2_ImportBundleFromDirLockedIncomplete(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// An empty directory has none of the three required artifacts.
	_, err := hs.importBundleFromDirLocked(t.TempDir(), streamGo, bundleIDForSequence(1), 1)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err = %v, want an 'incomplete' bundle error", err)
	}
}

// -----------------------------------------------------------------------------
// rejectInvalidQuarantineLocked (via ImportStatus → quarantineFutureBundlesLocked)
// -----------------------------------------------------------------------------

func TestCovM2_RejectInvalidQuarantine(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	q := hs.cfg.Quarantine

	// Unsupported stream: always rejected.
	writeSignedStreamBundle(t, q, priv, "xstream", 1, 0)
	// Known stream, far beyond the allowed gap: rejected.
	farSeq := maxFutureSequenceGap + 5
	writeSignedStreamBundle(t, q, priv, streamGo, farSeq, farSeq-1)
	// Known stream, a legitimate near-future bundle: left in quarantine.
	writeSignedStreamBundle(t, q, priv, streamGo, 5, 4)

	if _, err := hs.ImportStatus(); err != nil {
		t.Fatalf("ImportStatus: %v", err)
	}

	rejected := filepath.Join(hs.cfg.Root, "rejected")
	for _, id := range []string{bundleIDFor("xstream", 1), bundleIDFor(streamGo, farSeq)} {
		if !bundleCompleteInDir(rejected, id) {
			t.Errorf("%s was not moved to rejected/", id)
		}
	}
	// The near-future go bundle stays in quarantine for a later import.
	if !bundleCompleteInDir(q, bundleIDFor(streamGo, 5)) {
		t.Error("near-future go bundle should remain in quarantine")
	}
}

// -----------------------------------------------------------------------------
// completeInfos / handleHighLatest
// -----------------------------------------------------------------------------

func TestCovM2_CompleteInfosSkipsJunk(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(hs.goModuleDir(), "github.com/foo/bar", "@v")
	// A subdirectory is skipped (IsDir).
	if err := os.MkdirAll(filepath.Join(base, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A non-.info file is skipped (suffix).
	writeFile(t, filepath.Join(base, "extra.txt"), []byte("junk"))
	// An incomplete version (info only, no .complete/.mod/.zip) is skipped.
	writeFile(t, filepath.Join(base, "v2.0.0.info"), []byte(`{"Version":"v2.0.0"}`))
	// A complete but corrupt-JSON info is skipped after the completeness check.
	for _, ext := range []string{".info", ".mod", ".zip", completeExt} {
		content := []byte("not json")
		if ext == ".complete" {
			content = []byte("2020-01-01T00:00:00Z\n")
		}
		writeFile(t, filepath.Join(base, "v3.0.0"+ext), content)
	}

	infos, err := hs.completeInfos("github.com/foo/bar")
	if err != nil {
		t.Fatalf("completeInfos: %v", err)
	}
	if len(infos) != 1 || infos[0].Version != "v1.0.0" {
		t.Fatalf("completeInfos = %+v, want only v1.0.0", infos)
	}

	// A module whose directory does not exist returns an error.
	if _, err := hs.completeInfos("no/such/module"); err == nil {
		t.Error("completeInfos on a missing module should error")
	}
}

func TestCovM2_HandleHighLatest(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// A known module resolves its latest version as JSON.
	code, body := httpGet(t, srv.URL+"/go/github.com/foo/bar/@latest")
	if code != http.StatusOK || !strings.Contains(body, `"Version"`) || !strings.Contains(body, "v1.0.0") {
		t.Errorf("@latest = %d %q", code, body)
	}
	// An unknown module has no complete versions → 404.
	if code, _ := httpGet(t, srv.URL+"/go/github.com/ghost/none/@latest"); code != http.StatusNotFound {
		t.Errorf("unknown @latest = %d, want 404", code)
	}
}

// -----------------------------------------------------------------------------
// parseProxyRequest
// -----------------------------------------------------------------------------

func TestCovM2_ParseProxyRequest(t *testing.T) {
	t.Run("errors", func(t *testing.T) {
		for _, p := range []string{
			"/",                  // empty after clean
			"/foo/@v/v1.0.0.txt", // unknown extension
			"/no-proxy-path",     // no /@v/ and no /@latest
		} {
			if _, err := parseProxyRequest(p); err == nil {
				t.Errorf("parseProxyRequest(%q) should error", p)
			}
		}
	})

	t.Run("latest", func(t *testing.T) {
		req, err := parseProxyRequest("/example.com/foo/@latest")
		if err != nil || req.Kind != proxyLatest || req.Module != "example.com/foo" {
			t.Fatalf("latest req = %+v err=%v", req, err)
		}
	})

	t.Run("list", func(t *testing.T) {
		req, err := parseProxyRequest("/example.com/foo/@v/list")
		if err != nil || req.Kind != proxyList {
			t.Fatalf("list req = %+v err=%v", req, err)
		}
	})

	t.Run("version file", func(t *testing.T) {
		req, err := parseProxyRequest("/example.com/foo/@v/v1.0.0.info")
		if err != nil || req.Kind != proxyVersionFile || req.Ext != ".info" || req.Version != "v1.0.0" {
			t.Fatalf("version req = %+v err=%v", req, err)
		}
	})
}
