package main

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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
// covMain_* helpers (do not collide with existing package helpers).
// -----------------------------------------------------------------------------

// covMainBuildManifest builds a valid BundleManifest (with real hashed module
// files under a temp src dir) for the go stream and returns it plus its
// canonical JSON encoding. PreviousSequence is seq-1 so a fresh high server
// (Imported[go]==0) accepts sequence 1.
func covMainBuildManifest(t *testing.T, seq int64, mods []moduleSpec) (BundleManifest, []byte) {
	t.Helper()
	src := t.TempDir()
	var files []ManifestFile
	var manifestMods []ManifestMod
	for _, m := range mods {
		mod, mfs := buildModuleFiles(t, src, m)
		files = append(files, mfs...)
		manifestMods = append(manifestMods, mod)
	}
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "covmain",
		BundleID:         bundleIDForSequence(seq),
		Modules:          manifestMods,
		Files:            files,
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return manifest, b
}

// covMainWriteManifestSig writes a manifest and its signature (streaming
// Ed25519ph when prehashed, plain Ed25519 otherwise) into dir and returns the
// two paths.
func covMainWriteManifestSig(t *testing.T, dir, bundleID string, manifestBytes []byte, priv ed25519.PrivateKey, prehashed bool) (string, string) {
	t.Helper()
	mp := filepath.Join(dir, bundleID+".manifest.json")
	sp := mp + ".sig"
	writeFile(t, mp, manifestBytes)
	var sigText string
	if prehashed {
		sig, err := signManifestPH(priv, manifestBytes)
		if err != nil {
			t.Fatal(err)
		}
		sigText = manifestSignaturePHPrefix + base64.StdEncoding.EncodeToString(sig) + "\n"
	} else {
		sig := ed25519.Sign(priv, manifestBytes)
		sigText = base64.StdEncoding.EncodeToString(sig) + "\n"
	}
	writeFile(t, sp, []byte(sigText))
	return mp, sp
}

// covMainTarReaderFor writes a single regular tar entry into an in-memory
// archive and returns a reader positioned at that entry's header.
func covMainTarReaderFor(t *testing.T, name string, content []byte) (*tar.Reader, *tar.Header) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	got, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	return tr, got
}

// -----------------------------------------------------------------------------
// applyHighEnvConfig
// -----------------------------------------------------------------------------

func TestCovMain_ApplyHighEnvConfig(t *testing.T) {
	t.Run("defaults off", func(t *testing.T) {
		t.Setenv("ARTIGATE_DIODE_INGEST", "")
		t.Setenv("ARTIGATE_DIODE_TOKEN", "")
		t.Setenv("ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN", "")
		cfg := HighConfig{}
		applyHighEnvConfig(&cfg)
		if cfg.DiodeIngest || cfg.AllowRemoteAdmin || cfg.DiodeToken != "" {
			t.Fatalf("defaults not off: %+v", cfg)
		}
	})

	t.Run("ingest on with token and remote admin", func(t *testing.T) {
		token := strings.Repeat("a", minDiodeTokenBytes)
		t.Setenv("ARTIGATE_DIODE_INGEST", "on")
		t.Setenv("ARTIGATE_DIODE_TOKEN", token)
		t.Setenv("ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN", "yes")
		cfg := HighConfig{}
		applyHighEnvConfig(&cfg)
		if !cfg.DiodeIngest {
			t.Error("DiodeIngest not enabled")
		}
		if cfg.DiodeToken != token {
			t.Errorf("DiodeToken = %q", cfg.DiodeToken)
		}
		if !cfg.AllowRemoteAdmin {
			t.Error("AllowRemoteAdmin not enabled")
		}
	})
}

// -----------------------------------------------------------------------------
// LowServer.loadState and NewLowServer
// -----------------------------------------------------------------------------

func TestCovMain_LowServerLoadState(t *testing.T) {
	_, priv := newTestKeys(t)

	t.Run("legacy single-stream migration", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "low-state.json"), []byte(`{"next_sequence":5}`))
		cfg := LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out")}
		ls, err := NewLowServer(cfg, priv)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ls.Close() })
		if got := ls.state.Sequences[streamGo]; got != 5 {
			t.Errorf("migrated go sequence = %d, want 5", got)
		}
		if ls.state.NextSequence != 0 {
			t.Errorf("legacy NextSequence not cleared: %d", ls.state.NextSequence)
		}
	})

	t.Run("existing per-stream state loads", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "low-state.json"), []byte(`{"sequences":{"go":3,"python":1}}`))
		cfg := LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out")}
		ls, err := NewLowServer(cfg, priv)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ls.Close() })
		if ls.state.Sequences[streamGo] != 3 || ls.state.Sequences[streamPython] != 1 {
			t.Errorf("loaded sequences = %v", ls.state.Sequences)
		}
	})

	t.Run("invalid json errors", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "low-state.json"), []byte("not json"))
		cfg := LowConfig{Root: root, ExportDir: filepath.Join(t.TempDir(), "out")}
		if _, err := NewLowServer(cfg, priv); err == nil {
			t.Fatal("expected error for corrupt low-state.json")
		}
	})
}

func TestCovMain_NewLowServerRejectsBadRegistry(t *testing.T) {
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:                t.TempDir(),
		ExportDir:           filepath.Join(t.TempDir(), "out"),
		ContainerRegistries: "no-equals-sign",
	}
	if _, err := NewLowServer(cfg, priv); err == nil {
		t.Fatal("expected NewLowServer to reject an invalid container registry override")
	}
}

// -----------------------------------------------------------------------------
// HighServer.loadState
// -----------------------------------------------------------------------------

func TestCovMain_HighServerLoadState(t *testing.T) {
	pub, _ := newTestKeys(t)

	t.Run("legacy single-stream migration", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "import-state.json"), []byte(`{"last_imported_sequence":7}`))
		cfg := HighConfig{Root: root, Landing: t.TempDir(), ImportInterval: 0}
		hs, err := NewHighServer(cfg, pub)
		if err != nil {
			t.Fatal(err)
		}
		if got := hs.state.Imported[streamGo]; got != 7 {
			t.Errorf("migrated imported go = %d, want 7", got)
		}
		if hs.state.LastImportedSequence != 0 {
			t.Errorf("legacy field not cleared: %d", hs.state.LastImportedSequence)
		}
	})

	t.Run("invalid json errors", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "import-state.json"), []byte("{bad"))
		cfg := HighConfig{Root: root, Landing: t.TempDir(), ImportInterval: 0}
		if _, err := NewHighServer(cfg, pub); err == nil {
			t.Fatal("expected error for corrupt import-state.json")
		}
	})
}

// -----------------------------------------------------------------------------
// scanForInfoRel / findVersionFilesByScan
// -----------------------------------------------------------------------------

func covMainWriteGoCacheModule(t *testing.T, dl, modEsc, version string) {
	t.Helper()
	base := filepath.Join(dl, filepath.FromSlash(modEsc), "@v")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, version+".info"), []byte(`{"Version":"`+version+`","Time":"2020-01-01T00:00:00Z"}`))
	writeFile(t, filepath.Join(base, version+".mod"), []byte("module x\n"))
	writeFile(t, filepath.Join(base, version+".zip"), []byte("zip-bytes"))
}

func TestCovMain_FindVersionFilesByScan(t *testing.T) {
	wanted := map[string]string{"info": ".info", "mod": ".mod", "zip": ".zip"}

	t.Run("finds complete module", func(t *testing.T) {
		dl := t.TempDir()
		covMainWriteGoCacheModule(t, dl, "example.com/foo", "v1.0.0")

		rel, err := scanForInfoRel(dl, "v1.0.0", "v1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if rel != "example.com/foo/@v/v1.0.0.info" {
			t.Fatalf("scanForInfoRel = %q", rel)
		}

		matches, err := findVersionFilesByScan(dl, "example.com/foo", "v1.0.0", "v1.0.0", wanted)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 3 || matches["zip"] != "example.com/foo/@v/v1.0.0.zip" {
			t.Fatalf("matches = %v", matches)
		}
	})

	t.Run("version not present", func(t *testing.T) {
		dl := t.TempDir()
		covMainWriteGoCacheModule(t, dl, "example.com/foo", "v1.0.0")
		if _, err := findVersionFilesByScan(dl, "example.com/foo", "v9.9.9", "v9.9.9", wanted); err == nil {
			t.Fatal("expected error when the version is absent")
		}
	})

	t.Run("incomplete cache", func(t *testing.T) {
		dl := t.TempDir()
		covMainWriteGoCacheModule(t, dl, "example.com/foo", "v1.0.0")
		if err := os.Remove(filepath.Join(dl, "example.com/foo/@v/v1.0.0.zip")); err != nil {
			t.Fatal(err)
		}
		if _, err := findVersionFilesByScan(dl, "example.com/foo", "v1.0.0", "v1.0.0", wanted); err == nil {
			t.Fatal("expected incomplete-cache error")
		}
	})
}

// -----------------------------------------------------------------------------
// serveHighAdmin
// -----------------------------------------------------------------------------

func TestCovMain_ServeHighAdmin(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	if code, body := httpGet(t, srv.URL+"/healthz"); code != http.StatusOK || !strings.Contains(body, "ok") {
		t.Errorf("healthz = %d %q", code, body)
	}
	code, body := httpGet(t, srv.URL+"/admin/status")
	if code != http.StatusOK {
		t.Errorf("admin/status = %d", code)
	}
	// The status JSON identifies the serving binary, so a remote fleet check
	// can read the air-gapped high side's version and format ceiling.
	var status ImportStatus
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		t.Fatalf("decode admin/status: %v", err)
	}
	if status.Version != versionString() || status.ManifestFormat != manifestFormatCurrent {
		t.Errorf("status identity = %q format %d, want %q format %d",
			status.Version, status.ManifestFormat, versionString(), manifestFormatCurrent)
	}
	if code, _ := httpGet(t, srv.URL+"/admin/missing"); code != http.StatusOK {
		t.Errorf("admin/missing = %d", code)
	}

	resp, err := http.Post(srv.URL+"/admin/import", "text/plain", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin/import (loopback) = %d, want 200", resp.StatusCode)
	}

	// An unknown /admin/ path is a 404.
	if code, _ := httpGet(t, srv.URL+"/admin/does-not-exist"); code != http.StatusNotFound {
		t.Errorf("admin/does-not-exist = %d, want 404", code)
	}
	// An unknown /admin/uploads path routes through serveUploadsAdmin and 404s.
	if code, _ := httpGet(t, srv.URL+"/admin/uploads/nope"); code != http.StatusNotFound {
		t.Errorf("admin/uploads/nope = %d, want 404", code)
	}
}

func TestCovMain_ServeHighAdminNonAdminReturnsFalse(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/go/example.com/foo/@v/list", nil)
	if handled := hs.serveHighAdmin(rec, req); handled {
		t.Fatal("serveHighAdmin claimed a non-admin path")
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("serveHighAdmin wrote a response for an unhandled path: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestCovMain_ServeHighAdminRemoteImportForbidden(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/import", nil)
	req.RemoteAddr = "203.0.113.7:5555" // non-loopback
	if handled := hs.serveHighAdmin(rec, req); !handled {
		t.Fatal("serveHighAdmin should handle /admin/import")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("remote /admin/import = %d, want 403", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// handleHighVersionFile
// -----------------------------------------------------------------------------

func TestCovMain_HandleHighVersionFile(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Unsupported extension is rejected before any lookup.
	if code, _ := httpGet(t, srv.URL+"/go/github.com/foo/bar/@v/v1.0.0.txt"); code != http.StatusBadRequest && code != http.StatusNotFound {
		t.Errorf("unsupported ext status = %d", code)
	}
	// Known-but-absent version is a 404.
	if code, _ := httpGet(t, srv.URL+"/go/github.com/foo/bar/@v/v2.0.0.info"); code != http.StatusNotFound {
		t.Errorf("absent version = %d, want 404", code)
	}
	// Present, complete version serves the file.
	if code, body := httpGet(t, srv.URL+"/go/github.com/foo/bar/@v/v1.0.0.mod"); code != http.StatusOK || !strings.Contains(body, "github.com/foo/bar v1.0.0 mod") {
		t.Errorf("present version = %d %q", code, body)
	}
}

// -----------------------------------------------------------------------------
// importLoop
// -----------------------------------------------------------------------------

func TestCovMain_ImportLoop(t *testing.T) {
	pub, priv := newTestKeys(t)
	// importLoop has no stop channel, so the goroutine below keeps writing the
	// import-state file after the test returns. Use self-managed temp dirs whose
	// cleanup ignores errors, rather than t.TempDir, so that lingering writer can
	// never race the test framework's cleanup into a spurious "directory not
	// empty" failure.
	root, err := os.MkdirTemp("", "covmain-importloop-root")
	if err != nil {
		t.Fatal(err)
	}
	landing, err := os.MkdirTemp("", "covmain-importloop-landing")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root); _ = os.RemoveAll(landing) })

	cfg := HighConfig{Root: root, Landing: landing, ImportInterval: 5 * time.Millisecond}
	hs, err := NewHighServer(cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})

	go hs.importLoop(t.Context())

	deadline := time.Now().Add(3 * time.Second)
	for {
		if hs.isComplete("github.com/foo/bar", "v1.0.0") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("importLoop did not import the landing bundle in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// -----------------------------------------------------------------------------
// loadVerifiedManifest / checkManifestFields
// -----------------------------------------------------------------------------

func TestCovMain_LoadVerifiedManifest(t *testing.T) {
	pub, priv := newTestKeys(t)
	mods := []moduleSpec{{"github.com/foo/bar", "v1.0.0"}}
	bundleID := bundleIDForSequence(1)

	t.Run("plain signature verifies", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		_, mb := covMainBuildManifest(t, 1, mods)
		mp, sp := covMainWriteManifestSig(t, t.TempDir(), bundleID, mb, priv, false)
		got, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got.BundleID != bundleID {
			t.Errorf("bundle id = %q", got.BundleID)
		}
	})

	t.Run("prehashed signature verifies", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		_, mb := covMainBuildManifest(t, 1, mods)
		mp, sp := covMainWriteManifestSig(t, t.TempDir(), bundleID, mb, priv, true)
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err != nil {
			t.Fatalf("prehashed verify: %v", err)
		}
	})

	t.Run("tampered manifest fails prehashed verify", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		_, mb := covMainBuildManifest(t, 1, mods)
		mp, sp := covMainWriteManifestSig(t, dir, bundleID, mb, priv, true)
		writeFile(t, mp, append(mb, ' ')) // change the manifest after signing
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected verification failure for a tampered manifest")
		}
	})

	t.Run("undecodable signature", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		_, mb := covMainBuildManifest(t, 1, mods)
		mp := filepath.Join(dir, bundleID+".manifest.json")
		sp := mp + ".sig"
		writeFile(t, mp, mb)
		writeFile(t, sp, []byte("!!!not base64!!!"))
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected a signature-decode error")
		}
	})

	t.Run("wrong expected sequence", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		_, mb := covMainBuildManifest(t, 1, mods)
		mp, sp := covMainWriteManifestSig(t, t.TempDir(), bundleID, mb, priv, false)
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 2); err == nil {
			t.Fatal("expected sequence-mismatch error")
		}
	})
}

func TestCovMain_CheckManifestFields(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	good, _ := covMainBuildManifest(t, 1, []moduleSpec{{"m", "v1.0.0"}})
	bundleID := good.BundleID

	// A legacy manifest (format 0, from before the field existed) and one
	// stamped with the current format must both pass; only newer formats are
	// refused.
	if err := hs.checkManifestFields(good, streamGo, bundleID, 1); err != nil {
		t.Fatalf("valid legacy (format 0) manifest rejected: %v", err)
	}
	current := good
	current.Format = manifestFormatCurrent
	if err := hs.checkManifestFields(current, streamGo, bundleID, 1); err != nil {
		t.Fatalf("valid current-format manifest rejected: %v", err)
	}

	tests := []struct {
		name  string
		mutFn func(m *BundleManifest)
		want  string
	}{
		{"format too new", func(m *BundleManifest) { m.Format = manifestFormatCurrent + 1 }, "upgrade the ArtiGate high side"},
		{"wrong type", func(m *BundleManifest) { m.Type = "bogus" }, "wrong manifest type"},
		{"stream mismatch", func(m *BundleManifest) { m.Stream = streamPython }, "stream mismatch"},
		{"sequence mismatch", func(m *BundleManifest) { m.Sequence = 9 }, "sequence mismatch"},
		{"previous mismatch", func(m *BundleManifest) { m.PreviousSequence = 5 }, "previous sequence mismatch"},
		{"bundle id mismatch", func(m *BundleManifest) { m.BundleID = "go-bundle-000099" }, "bundle_id mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := good
			tt.mutFn(&m)
			err := hs.checkManifestFields(m, streamGo, bundleID, 1)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

// TestCovMain_TooNewManifestFormatStaysInLanding pins the fleet-upgrade
// contract: a validly signed bundle whose manifest format is newer than this
// binary is a retryable operator condition (upgrade the high side, the bundle
// then imports as-is), never a terminal rejection — a rejected bundle's only
// recovery would be a low-side re-export across the diode.
func TestCovMain_TooNewManifestFormatStaysInLanding(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	src := t.TempDir()
	bundleID := bundleIDFor(streamGo, 1)
	mod, files := buildModuleFiles(t, src, moduleSpec{module: "example.com/future", version: "v1.0.0"})
	manifest := BundleManifest{
		Type:             manifestType,
		Format:           manifestFormatCurrent + 1,
		Stream:           streamGo,
		Sequence:         1,
		PreviousSequence: 0,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "future-low-side",
		BundleID:         bundleID,
		Modules:          []ManifestMod{mod},
		Files:            files,
	}
	signAndWriteBundle(t, hs.cfg.Landing, priv, manifest, src)

	res, err := hs.ImportNext()
	if err == nil || !strings.Contains(err.Error(), "upgrade the ArtiGate high side") {
		t.Fatalf("import err = %v, want the format upgrade guidance", err)
	}
	if res.Imported || len(res.RejectedBundles) != 0 {
		t.Fatalf("result = %+v, want nothing imported and nothing rejected", res)
	}
	if !bundleCompleteInDir(hs.cfg.Landing, bundleID) {
		t.Error("bundle must stay complete in landing so the upgraded binary can import it")
	}
	if fileExists(filepath.Join(hs.cfg.Root, "rejected", bundleID+".manifest.json")) {
		t.Error("a too-new bundle must not be moved to rejected/")
	}
	if got := hs.state.Imported[streamGo]; got != 0 {
		t.Errorf("imported sequence advanced to %d on a refused bundle", got)
	}
}

// -----------------------------------------------------------------------------
// extractTarEntry
// -----------------------------------------------------------------------------

func TestCovMain_ExtractTarEntry(t *testing.T) {
	content := []byte("hello archive")
	// hashManifestFile needs a real file; build one under a temp dir.
	blobDir := t.TempDir()
	blobPath := filepath.Join(blobDir, "blob")
	writeFile(t, blobPath, content)
	goodMF, err := hashManifestFile(blobPath, "a/b.txt")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid entry extracts", func(t *testing.T) {
		staging := t.TempDir()
		tr, hdr := covMainTarReaderFor(t, "a/b.txt", content)
		if err := extractTarEntry(tr, hdr, staging, map[string]ManifestFile{"a/b.txt": goodMF}); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(staging, "a", "b.txt"))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("extracted = %q err=%v", got, err)
		}
	})

	t.Run("unexpected file", func(t *testing.T) {
		tr, hdr := covMainTarReaderFor(t, "a/b.txt", content)
		if err := extractTarEntry(tr, hdr, t.TempDir(), map[string]ManifestFile{}); err == nil || !strings.Contains(err.Error(), "unexpected file") {
			t.Fatalf("err = %v, want unexpected-file", err)
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		tr, hdr := covMainTarReaderFor(t, "a/b.txt", content)
		bad := goodMF
		bad.Size = goodMF.Size + 1
		if err := extractTarEntry(tr, hdr, t.TempDir(), map[string]ManifestFile{"a/b.txt": bad}); err == nil || !strings.Contains(err.Error(), "size mismatch") {
			t.Fatalf("err = %v, want size-mismatch", err)
		}
	})

	t.Run("sha mismatch", func(t *testing.T) {
		tr, hdr := covMainTarReaderFor(t, "a/b.txt", content)
		bad := goodMF
		bad.SHA256 = strings.Repeat("0", 64)
		if err := extractTarEntry(tr, hdr, t.TempDir(), map[string]ManifestFile{"a/b.txt": bad}); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("err = %v, want sha-mismatch", err)
		}
	})

	t.Run("non-regular file", func(t *testing.T) {
		hdr := &tar.Header{Name: "a/dir", Typeflag: tar.TypeDir}
		if err := extractTarEntry(nil, hdr, t.TempDir(), map[string]ManifestFile{}); err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("err = %v, want non-regular", err)
		}
	})
}

// -----------------------------------------------------------------------------
// recordForwarded / moveFile / must
// -----------------------------------------------------------------------------

func TestCovMain_RecordForwarded(t *testing.T) {
	ls := newBareLowServer(t)
	// Empty slice is a no-op.
	ls.recordForwarded(streamNpm, nil)

	files := []ManifestFile{mf("npm/packages/z.tgz", "z")}
	ls.recordForwarded(streamNpm, files)
	ok, err := ls.exported.IsForwarded(streamNpm, "npm/packages/z.tgz", strings.Repeat("z", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("recordForwarded did not persist the file to the exported index")
	}
}

func TestCovMain_MoveFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	writeFile(t, src, []byte("payload"))
	writeFile(t, dst, []byte("stale")) // pre-existing dst is removed first

	if err := moveFile(src, dst, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "payload" {
		t.Fatalf("dst = %q err=%v", got, err)
	}
	if fileExists(src) {
		t.Error("src should be gone after moveFile")
	}

	// A missing source is a plain (non-EXDEV) rename error.
	if err := moveFile(filepath.Join(dir, "nope"), filepath.Join(dir, "out"), 0o644); err == nil {
		t.Error("moveFile of a missing source should fail")
	}
}

func TestCovMain_MustNilDoesNotFatal(_ *testing.T) {
	must(nil) // must must not exit on a nil error
}
