package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Test helpers for building signed bundles and high-side servers.
// -----------------------------------------------------------------------------

type moduleSpec struct {
	module  string
	version string
}

// writeSignedBundle builds a valid, signed bundle for the given modules and
// writes its archive, manifest, and signature into landing. It exercises
// hashManifestFile and createTarGzAtomic along the way.
func writeSignedBundle(t *testing.T, landing string, priv ed25519.PrivateKey, seq, prevSeq int64, mods []moduleSpec) {
	t.Helper()
	src := t.TempDir()
	var files []ManifestFile
	var manifestMods []ManifestMod

	for _, m := range mods {
		mod, modFiles := buildModuleFiles(t, src, m)
		files = append(files, modFiles...)
		manifestMods = append(manifestMods, mod)
	}

	bundleID := bundleIDForSequence(seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: prevSeq,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Modules:          manifestMods,
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestBytes)

	if err := os.MkdirAll(landing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createTarGzAtomic(filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json"), manifestBytes)
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
}

// buildModuleFiles writes a module's .info/.mod/.zip files under src and
// returns its manifest entry plus the corresponding ManifestFile list.
func buildModuleFiles(t *testing.T, src string, m moduleSpec) (ManifestMod, []ManifestFile) {
	t.Helper()
	modFiles := map[string]ManifestFile{}
	var files []ManifestFile
	for _, kind := range []string{"info", "mod", "zip"} {
		rel := path.Join(m.module, "@v", m.version+"."+kind)
		content := m.module + " " + m.version + " " + kind + "\n"
		if kind == "info" {
			content = `{"Version":"` + m.version + `","Time":"2020-01-01T00:00:00Z"}`
		}
		abs := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, []byte(content))
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, mf)
		modFiles[kind] = mf
	}
	return ManifestMod{Module: m.module, Version: m.version, Files: modFiles}, files
}

// writeSignedStreamBundle writes a valid signed bundle tagged for an arbitrary
// stream. The payload is a single go-module unit keyed off the bundle ID so it
// never collides across streams or sequences; the stream field, not the payload
// type, is what drives per-stream sequencing, so this is enough to exercise
// per-stream import isolation without a real adapter.
func writeSignedStreamBundle(t *testing.T, landing string, priv ed25519.PrivateKey, stream string, seq, prevSeq int64) {
	t.Helper()
	bundleID := bundleIDFor(stream, seq)
	src := t.TempDir()
	mod, files := buildModuleFiles(t, src, moduleSpec{module: "example.com/" + bundleID, version: "v1.0.0"})

	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           stream,
		Sequence:         seq,
		PreviousSequence: prevSeq,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Modules:          []ManifestMod{mod},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestBytes)

	if err := os.MkdirAll(landing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createTarGzAtomic(filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json"), manifestBytes)
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newTestHighServer(t *testing.T, pub ed25519.PublicKey) *HighServer {
	t.Helper()
	cfg := HighConfig{Root: t.TempDir(), Landing: t.TempDir(), ImportInterval: 0}
	hs, err := NewHighServer(cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// -----------------------------------------------------------------------------
// High-side end-to-end: import a bundle, then serve it.
// -----------------------------------------------------------------------------

func TestHighServerImportAndServe(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})

	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if !res.Imported || len(res.ImportedBundles) != 1 || res.ImportedBundles[0] != "go-bundle-000001" {
		t.Fatalf("unexpected import result: %+v", res)
	}
	if !hs.isComplete("github.com/foo/bar", "v1.0.0") {
		t.Fatal("module should be complete after import")
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	cases := []struct {
		path    string
		wantSub string
	}{
		{"/github.com/foo/bar/@v/list", "v1.0.0"},
		{"/github.com/foo/bar/@v/v1.0.0.info", `"Version":"v1.0.0"`},
		{"/github.com/foo/bar/@v/v1.0.0.mod", "github.com/foo/bar v1.0.0 mod"},
		{"/github.com/foo/bar/@v/v1.0.0.zip", "github.com/foo/bar v1.0.0 zip"},
	}
	for _, c := range cases {
		code, body := httpGet(t, srv.URL+c.path)
		if code != http.StatusOK {
			t.Errorf("GET %s: status %d", c.path, code)
		}
		if !strings.Contains(body, c.wantSub) {
			t.Errorf("GET %s: body %q missing %q", c.path, body, c.wantSub)
		}
	}

	code, body := httpGet(t, srv.URL+"/github.com/foo/bar/@latest")
	if code != http.StatusOK {
		t.Fatalf("GET @latest: status %d", code)
	}
	var info ModuleInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("decode @latest: %v", err)
	}
	if info.Version != "v1.0.0" {
		t.Errorf("@latest version = %q, want v1.0.0", info.Version)
	}

	// Unknown module 404s rather than erroring.
	if code, _ := httpGet(t, srv.URL+"/github.com/does/notexist/@v/list"); code != http.StatusNotFound {
		t.Errorf("unknown module list: status %d, want 404", code)
	}
}

func TestHighServerQuarantineThenDrain(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// Import bundle 1, then deliver bundle 3 while 2 is still missing.
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"m", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	writeSignedBundle(t, hs.cfg.Landing, priv, 3, 2, []moduleSpec{{"m", "v3.0.0"}})

	status, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	st := status.Stream(streamGo)
	if st.BlockingMissing != 2 {
		t.Errorf("BlockingMissing = %d, want 2", st.BlockingMissing)
	}
	if len(st.QuarantinedSequences) != 1 || st.QuarantinedSequences[0] != 3 {
		t.Errorf("QuarantinedSequences = %v, want [3]", st.QuarantinedSequences)
	}
	if got := strings.Join(st.MissingRanges, ","); got != "2" {
		t.Errorf("MissingRanges = %q, want \"2\"", got)
	}

	// Deliver bundle 2: import should drain 2 and the quarantined 3.
	writeSignedBundle(t, hs.cfg.Landing, priv, 2, 1, []moduleSpec{{"m", "v2.0.0"}})
	res, err := hs.ImportNext()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Imported || res.ImportedBundles[len(res.ImportedBundles)-1] != "go-bundle-000003" {
		t.Errorf("expected drain through go-bundle-000003, got %+v", res)
	}
	for _, v := range []string{"v1.0.0", "v2.0.0", "v3.0.0"} {
		if !hs.isComplete("m", v) {
			t.Errorf("m@%s should be complete", v)
		}
	}
}

func mustImportNext(t *testing.T, hs *HighServer) ImportResult {
	t.Helper()
	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	return res
}

// assertStreamProgress checks a stream's last-imported sequence and the bundle
// it is blocked on (0 = not blocked).
func assertStreamProgress(t *testing.T, hs *HighServer, stream string, wantLast, wantBlocking int64) {
	t.Helper()
	status, err := hs.ImportStatus()
	if err != nil {
		t.Fatalf("ImportStatus: %v", err)
	}
	st := status.Stream(stream)
	if st.LastImportedSequence != wantLast {
		t.Errorf("%s last imported = %d, want %d", stream, st.LastImportedSequence, wantLast)
	}
	if st.BlockingMissing != wantBlocking {
		t.Errorf("%s blocking = %d, want %d", stream, st.BlockingMissing, wantBlocking)
	}
}

// TestHighServerPerStreamIsolation proves each ecosystem stream sequences and
// imports independently: a gap in one stream never blocks another. The go stream
// is missing bundle 1 (bundle 2 arrives early and is quarantined), yet the
// python stream imports its bundle 1 normally; filling the go gap later drains
// both go bundles (proving bundle 2 was retained in quarantine) without
// disturbing python.
func TestHighServerPerStreamIsolation(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 2, 1)     // go: gap, bundle 1 missing
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamPython, 1, 0) // python: in order

	res := mustImportNext(t, hs)
	if !res.Imported || len(res.ImportedBundles) != 1 || res.ImportedBundles[0] != "python-bundle-000001" {
		t.Fatalf("expected only python-bundle-000001 imported, got %+v", res)
	}
	// python advanced; go stays blocked on its missing bundle 1 — streams isolated.
	assertStreamProgress(t, hs, streamPython, 1, 0)
	assertStreamProgress(t, hs, streamGo, 0, 1)

	// Fill the go gap: bundles 1 and 2 drain, python is untouched.
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 1, 0)
	res = mustImportNext(t, hs)
	if len(res.ImportedBundles) != 2 {
		t.Fatalf("expected go bundles 1 and 2 to drain, got %+v", res)
	}
	assertStreamProgress(t, hs, streamGo, 2, 0)
	assertStreamProgress(t, hs, streamPython, 1, 0)
}

func TestHighServerRejectsTamperedManifest(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"m", "v1.0.0"}})

	// Corrupt the manifest so its signature no longer verifies.
	manifestPath := filepath.Join(hs.cfg.Landing, "go-bundle-000001.manifest.json")
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, manifestPath, append(b, ' '))

	if _, err := hs.ImportNext(); err == nil {
		t.Fatal("ImportNext accepted a tampered manifest")
	}
}

// -----------------------------------------------------------------------------
// Manifest validation.
// -----------------------------------------------------------------------------

func TestValidateManifestCompleteness(t *testing.T) {
	good := ManifestFile{Path: "m/@v/v1.0.0.info", SHA256: strings.Repeat("a", 64), Size: 1}
	goodMod := ManifestFile{Path: "m/@v/v1.0.0.mod", SHA256: strings.Repeat("b", 64), Size: 1}
	goodZip := ManifestFile{Path: "m/@v/v1.0.0.zip", SHA256: strings.Repeat("c", 64), Size: 1}
	fullMod := ManifestMod{Module: "m", Version: "v1.0.0", Files: map[string]ManifestFile{
		"info": good, "mod": goodMod, "zip": goodZip,
	}}

	valid := BundleManifest{Modules: []ManifestMod{fullMod}, Files: []ManifestFile{good, goodMod, goodZip}}
	if err := validateManifestCompleteness(valid); err != nil {
		t.Errorf("valid manifest rejected: %v", err)
	}

	tests := []struct {
		name string
		m    BundleManifest
	}{
		{"no modules", BundleManifest{}},
		{
			"bad sha length",
			BundleManifest{
				Modules: []ManifestMod{fullMod},
				Files:   []ManifestFile{{Path: "m/@v/v1.0.0.info", SHA256: "short", Size: 1}},
			},
		},
		{
			"traversal path",
			BundleManifest{
				Modules: []ManifestMod{fullMod},
				Files:   []ManifestFile{{Path: "../escape", SHA256: strings.Repeat("a", 64), Size: 1}},
			},
		},
		{
			"module missing zip",
			BundleManifest{
				Modules: []ManifestMod{{Module: "m", Version: "v1.0.0", Files: map[string]ManifestFile{"info": good, "mod": goodMod}}},
				Files:   []ManifestFile{good, goodMod},
			},
		},
		{
			"module references unlisted file",
			BundleManifest{
				Modules: []ManifestMod{fullMod},
				Files:   []ManifestFile{good, goodMod}, // zip not listed
			},
		},
	}
	for _, tt := range tests {
		if err := validateManifestCompleteness(tt.m); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

func TestModuleEscFromInfoPath(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"github.com/foo/bar/@v/v1.0.0.info", "github.com/foo/bar", false},
		{"m/@v/v1.0.0.info", "m", false},
		{"no-at-v-segment.info", "", true},
	}
	for _, tt := range tests {
		got, err := moduleEscFromInfoPath(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("moduleEscFromInfoPath(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("moduleEscFromInfoPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Archive round-trip and tamper detection.
// -----------------------------------------------------------------------------

func TestTarGzRoundTrip(t *testing.T) {
	src := t.TempDir()
	rel := "a/b/file.txt"
	abs := filepath.Join(src, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, []byte("hello world"))
	mf, err := hashManifestFile(abs, rel)
	if err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := createTarGzAtomic(archive, src, []ManifestFile{mf}); err != nil {
		t.Fatal(err)
	}

	staging := t.TempDir()
	if err := extractAndVerifyTarGz(archive, staging, []ManifestFile{mf}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(staging, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("extracted content = %q", got)
	}

	// A manifest claiming the wrong hash must fail verification.
	bad := mf
	bad.SHA256 = strings.Repeat("0", 64)
	if err := extractAndVerifyTarGz(archive, t.TempDir(), []ManifestFile{bad}); err == nil {
		t.Error("extract accepted a wrong hash")
	}
	// A manifest expecting an extra file must fail.
	extra := ManifestFile{Path: "missing.txt", SHA256: strings.Repeat("0", 64), Size: 1}
	if err := extractAndVerifyTarGz(archive, t.TempDir(), []ManifestFile{mf, extra}); err == nil {
		t.Error("extract accepted a manifest with a missing file")
	}
}

// -----------------------------------------------------------------------------
// Key generation and file helpers.
// -----------------------------------------------------------------------------

func TestKeygenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "low.ed25519")
	pubPath := filepath.Join(dir, "high.ed25519.pub")
	runKeygen([]string{"--private", privPath, "--public", pubPath})

	priv, err := readPrivateKey(privPath)
	if err != nil {
		t.Fatalf("readPrivateKey: %v", err)
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		t.Fatalf("readPublicKey: %v", err)
	}

	msg := []byte("attestation")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("generated keys do not verify a signature")
	}

	if _, err := readPublicKey(privPath); err == nil {
		t.Error("readPublicKey accepted a private key")
	}
}

func TestAtomicFileHelpers(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "state.json")
	if err := writeJSONAtomic(jsonPath, map[string]int{"n": 7}, 0o600); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]int
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &decoded); err != nil || decoded["n"] != 7 {
		t.Fatalf("writeJSONAtomic round-trip failed: %v %v", decoded, err)
	}

	bytesPath := filepath.Join(dir, "data.bin")
	if err := writeBytesAtomic(bytesPath, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	copyPath := filepath.Join(dir, "copy.bin")
	if err := copyFileAtomic(bytesPath, copyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("copyFileAtomic content = %q, want payload", got)
	}

	h1, err := sha256File(bytesPath)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := sha256File(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || len(h1) != 64 {
		t.Errorf("sha256File mismatch: %q vs %q", h1, h2)
	}

	if !fileExists(bytesPath) || fileExists(filepath.Join(dir, "nope")) {
		t.Error("fileExists gave the wrong answer")
	}
}

func TestMoveBundleFiles(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := filepath.Join(t.TempDir(), "dst")
	bundleID := bundleIDForSequence(1)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		writeFile(t, filepath.Join(srcDir, bundleID+suffix), []byte("x"))
	}

	if err := moveBundleFiles(srcDir, dstDir, bundleID); err != nil {
		t.Fatal(err)
	}
	if !bundleCompleteInDir(dstDir, bundleID) {
		t.Error("bundle should be complete in destination")
	}
	if bundleCompleteInDir(srcDir, bundleID) {
		t.Error("bundle files should have been moved out of source")
	}
}

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	if !safeJoin(root, filepath.Join(root, "a", "b")) {
		t.Error("safeJoin rejected a path inside root")
	}
	if safeJoin(root, filepath.Join(root, "..", "escape")) {
		t.Error("safeJoin accepted a path escaping root")
	}
}

func TestLogHTTPPassesThrough(t *testing.T) {
	called := false
	h := logHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/whatever", nil))
	if !called {
		t.Error("logHTTP did not call the wrapped handler")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestHostnameOrDefault(t *testing.T) {
	if hostnameOrDefault() == "" {
		t.Error("hostnameOrDefault returned an empty string")
	}
}

func TestEscapeApproxHelpers(t *testing.T) {
	if got := escapePathApprox("github.com/Azure/foo"); got != "github.com/!azure/foo" {
		t.Errorf("escapePathApprox = %q", got)
	}
	if got := escapeVersionApprox("v1.0.0-RC1"); got != "v1.0.0-!r!c1" {
		t.Errorf("escapeVersionApprox = %q", got)
	}
}

// -----------------------------------------------------------------------------
// Low-side pure helpers (no `go` toolchain required).
// -----------------------------------------------------------------------------

func TestReexportSpecFromRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			"query param",
			httptest.NewRequest(http.MethodPost, "/admin/reexport?sequences=42,45-47", nil),
			"42,45-47",
		},
		{
			"raw body",
			httptest.NewRequest(http.MethodPost, "/admin/reexport", strings.NewReader("1-3")),
			"1-3",
		},
		{
			"json body",
			httptest.NewRequest(http.MethodPost, "/admin/reexport", strings.NewReader(`{"sequences":"9"}`)),
			"9",
		},
	}
	for _, tt := range tests {
		_, got, err := reexportSpecFromRequest(tt.req)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestLowServerRecordAndStatus(t *testing.T) {
	_, priv := newTestKeys(t)
	root := t.TempDir()
	cfg := LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out"), AutoApprove: true}

	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}

	ls.recordRequest("github.com/foo/bar", "v1.0.0")
	ls.recordRequest("github.com/foo/bar", "v1.0.0") // duplicate collapses
	ls.recordRequest("github.com/baz/qux", "v2.0.0")
	ls.recordRequest("ignored", "latest") // never recorded

	status := ls.BundleStatus()
	if status.Stream(streamGo).NextSequence != 1 {
		t.Errorf("go NextSequence = %d, want 1", status.Stream(streamGo).NextSequence)
	}
	if status.PendingModules != 2 {
		t.Errorf("PendingModules = %d, want 2", status.PendingModules)
	}

	// A fresh server over the same root reloads persisted state.
	reloaded, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.BundleStatus().PendingModules; got != 2 {
		t.Errorf("reloaded PendingModules = %d, want 2", got)
	}
}

func TestSortRequestRecords(t *testing.T) {
	records := []RequestRecord{
		{Module: "b", Version: "v1.0.0"},
		{Module: "a", Version: "v2.0.0"},
		{Module: "a", Version: "v1.0.0"},
	}
	sortRequestRecords(records)
	got := make([]string, len(records))
	for i, r := range records {
		got[i] = r.Module + "@" + r.Version
	}
	want := []string{"a@v1.0.0", "a@v2.0.0", "b@v1.0.0"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sortRequestRecords = %v, want %v", got, want)
			break
		}
	}
}
