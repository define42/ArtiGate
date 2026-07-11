package main

import (
	"bytes"
	"context"
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
	if err := createTarGzAtomic(context.Background(), filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
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
	if err := createTarGzAtomic(context.Background(), filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
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
		{"/go/github.com/foo/bar/@v/list", "v1.0.0"},
		{"/go/github.com/foo/bar/@v/v1.0.0.info", `"Version":"v1.0.0"`},
		{"/go/github.com/foo/bar/@v/v1.0.0.mod", "github.com/foo/bar v1.0.0 mod"},
		{"/go/github.com/foo/bar/@v/v1.0.0.zip", "github.com/foo/bar v1.0.0 zip"},
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

	code, body := httpGet(t, srv.URL+"/go/github.com/foo/bar/@latest")
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
	if code, _ := httpGet(t, srv.URL+"/go/github.com/does/notexist/@v/list"); code != http.StatusNotFound {
		t.Errorf("unknown module list: status %d, want 404", code)
	}
	// Go is served only under /go/ now; the old root path is not found.
	if code, _ := httpGet(t, srv.URL+"/github.com/foo/bar/@v/list"); code == http.StatusOK {
		t.Error("Go module served at the root path; expected only under /go/")
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

// TestImportStateSaveFailureDoesNotStrandBundle forces the durable state write
// to fail after a bundle's files are installed. The in-memory counter must
// roll back to match disk: if it ran ahead, the next quarantine pass would
// file the landing bundle under duplicates/ as "already imported", and after a
// restart the stream would wait forever for a bundle it can no longer find.
func TestImportStateSaveFailureDoesNotStrandBundle(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})

	goodStatePath := hs.statePath
	// Point the state file under a path whose parent is a regular file, so the
	// atomic write fails deterministically (MkdirAll returns ENOTDIR).
	blocker := filepath.Join(hs.cfg.Root, "state-blocker")
	writeFile(t, blocker, []byte("x"))
	hs.statePath = filepath.Join(blocker, "state.json")

	// Two passes: the first fails the save, the second proves the bundle was
	// neither skipped (memory rolled back) nor mis-sorted into duplicates/.
	for i := 0; i < 2; i++ {
		if _, err := hs.ImportNext(); err == nil || !strings.Contains(err.Error(), "not persisted") {
			t.Fatalf("ImportNext #%d with failing state save = %v, want persistence error", i+1, err)
		}
		if got := hs.state.Imported[streamGo]; got != 0 {
			t.Fatalf("in-memory import state advanced to %d despite failed save", got)
		}
	}
	if !bundleCompleteInDir(hs.cfg.Landing, "go-bundle-000001") {
		t.Fatal("bundle must stay in landing while its import is not durably recorded")
	}

	// Once state can persist again, the retried import completes end to end.
	hs.statePath = goodStatePath
	res := mustImportNext(t, hs)
	if !res.Imported || len(res.ImportedBundles) != 1 || res.ImportedBundles[0] != "go-bundle-000001" {
		t.Fatalf("retried import = %+v", res)
	}
	if !hs.isComplete("github.com/foo/bar", "v1.0.0") {
		t.Fatal("module should be complete after the retried import")
	}
	if got := hs.state.Imported[streamGo]; got != 1 {
		t.Fatalf("imported sequence = %d, want 1", got)
	}
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
	if err := createTarGzAtomic(context.Background(), archive, src, []ManifestFile{mf}); err != nil {
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

// TestLowServerSequencePersists checks the status defaults (every known stream
// starts at sequence 1) and that an advanced per-stream counter survives a
// restart over the same root.
func TestLowServerSequencePersists(t *testing.T) {
	_, priv := newTestKeys(t)
	root := t.TempDir()
	cfg := LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out")}

	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := ls.BundleStatus().Stream(streamGo).NextSequence; got != 1 {
		t.Errorf("go NextSequence = %d, want 1", got)
	}

	// Advancing a stream's counter persists across a reload.
	if err := ls.commitSequence(streamGo, 1); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.BundleStatus().Stream(streamGo).NextSequence; got != 2 {
		t.Errorf("reloaded go NextSequence = %d, want 2", got)
	}
}

// TestExportStateSaveFailureDoesNotReuseSequence is the low-side mirror of
// TestImportStateSaveFailureDoesNotStrandBundle, guarding the opposite
// invariant: a sequence number must never be reused once a signed bundle for
// it was written to the export dir (it may already have crossed the diode).
// The bundle is written before the sequence claim is persisted, so a failed
// state save followed by a restart leaves low-state.json still pointing at
// the claimed number; the naive counter would hand it out again and silently
// overwrite the original signed bundle in both the export dir and the
// archive, forking the stream. Allocation must instead skip past any sequence
// whose bundle already exists on disk.
func TestExportStateSaveFailureDoesNotReuseSequence(t *testing.T) {
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:            filepath.Join(t.TempDir(), "root"),
		ExportDir:       filepath.Join(t.TempDir(), "out"),
		GoBinary:        writeFakeGo(t),
		UpstreamGOPROXY: "off",
		GOSUMDB:         "off",
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() }) // idempotent; also closed mid-test for the restart
	ctx := context.Background()
	archiveDir := filepath.Join(cfg.Root, "bundles")

	// Point the state file under a path whose parent is a regular file, so the
	// atomic write fails deterministically (MkdirAll returns ENOTDIR).
	blocker := filepath.Join(cfg.Root, "state-blocker")
	writeFile(t, blocker, []byte("x"))
	ls.statePath = filepath.Join(blocker, "low-state.json")

	// The collect writes and archives bundle 1 in full, then fails to persist
	// the claim on its sequence number.
	_, err = ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "not persisted") {
		t.Fatalf("CollectGo with failing state save = %v, want persistence error", err)
	}
	if !bundleCompleteInDir(cfg.ExportDir, "go-bundle-000001") || !bundleCompleteInDir(archiveDir, "go-bundle-000001") {
		t.Fatal("bundle 1 must be complete in the export dir and the archive despite the failed save")
	}
	// While the process lives, the in-memory counter stays ahead of disk on
	// purpose (the opposite of the high side's rollback): serving 1 again
	// in-process would overwrite the bundle that already exists.
	if got := ls.peekSequence(streamGo); got != 2 {
		t.Fatalf("in-process next sequence after failed save = %d, want 2", got)
	}

	manifest1, err := os.ReadFile(filepath.Join(cfg.ExportDir, "go-bundle-000001.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Restart over the same root: disk state never recorded the claim, so the
	// counter alone would allocate sequence 1 again.
	if err := ls.Close(); err != nil {
		t.Fatal(err)
	}
	ls2, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls2.Close() })

	// Retrying the same module must ship it under a fresh sequence: the failed
	// commit never recorded the content as forwarded, so dedup must not skip
	// it, and allocation must step past the bundle already on disk.
	res, err := ls2.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err != nil {
		t.Fatalf("retried CollectGo after restart: %v", err)
	}
	if res.Skipped || res.Sequence != 2 || res.BundleID != "go-bundle-000002" {
		t.Fatalf("retried collect = %+v, want a full export as go-bundle-000002", res)
	}
	if got, err := os.ReadFile(filepath.Join(cfg.ExportDir, "go-bundle-000001.manifest.json")); err != nil || !bytes.Equal(got, manifest1) {
		t.Fatalf("bundle 1 must survive the retry byte-for-byte (err=%v, changed=%v)", err, !bytes.Equal(got, manifest1))
	}
	if got := ls2.peekSequence(streamGo); got != 3 {
		t.Errorf("next sequence after retry = %d, want 3", got)
	}

	// Both bundles must flow through the diode: the high side imports 1 then 2
	// in order (re-installing identical content is idempotent), so nothing is
	// shelved as a duplicate and the stream never wedges on a gap.
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, id := range []string{"go-bundle-000001", "go-bundle-000002"} {
		for _, suffix := range bundleSuffixes() {
			b, err := os.ReadFile(filepath.Join(cfg.ExportDir, id+suffix))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(hs.cfg.Landing, id+suffix), b)
		}
	}
	imp, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("high-side import of both bundles: %v", err)
	}
	if len(imp.ImportedBundles) != 2 {
		t.Fatalf("imported bundles = %v, want both", imp.ImportedBundles)
	}
	if got := hs.state.Imported[streamGo]; got != 2 {
		t.Errorf("high-side imported sequence = %d, want 2", got)
	}
	if !hs.isComplete("example.com/foo/bar", "v1.0.0") {
		t.Error("module should be complete on the high side")
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

// TestCreateTarGzCancelledLeavesNothing checks that stopping a collect during
// the packing phase aborts the archive write and removes the temp file — a
// bundle is either fully produced or not at all.
func TestCreateTarGzCancelledLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "blob"), []byte("bundle-content"))
	files := []ManifestFile{{Path: "blob", SHA256: strings.Repeat("a", 64), Size: 14}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := filepath.Join(dir, "bundle.tar.gz")
	err := createTarGzAtomic(ctx, dst, src, files)
	if err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("cancelled packing = %v, want a 'stopped' error", err)
	}
	for _, p := range []string{dst, dst + ".tmp"} {
		if fileExists(p) {
			t.Errorf("%s exists after a cancelled pack", p)
		}
	}
}
