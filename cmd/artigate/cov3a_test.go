package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/reedsolomon"
)

// cov3ASkipIfRoot skips chmod-based fault injection when running as root, since
// root bypasses the permission bits the tests rely on to force I/O failures.
func cov3ASkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("chmod-based fault injection is ineffective as root")
	}
}

// cov3AReadonlyDir returns a fresh directory made read-only (0o500). The mode is
// restored to 0o700 on cleanup so t.TempDir removal succeeds.
func cov3AReadonlyDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d, 0o700) })
	return d
}

// cov3ASHA returns the hex SHA-256 of b, as manifests carry it.
func cov3ASHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var errCov3ABoom = errors.New("cov3a boom")

// cov3AErrReader always fails, to drive io.Copy error branches.
type cov3AErrReader struct{}

func (cov3AErrReader) Read([]byte) (int, error) { return 0, errCov3ABoom }

// -----------------------------------------------------------------------------
// main.go: atomic write / hash helpers under filesystem faults
// -----------------------------------------------------------------------------

func TestCov3A_CopyFileAtomicFaults(t *testing.T) {
	cov3ASkipIfRoot(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	writeFile(t, src, []byte("payload"))

	// Missing source: os.Open fails.
	if err := copyFileAtomic(filepath.Join(dir, "nope"), filepath.Join(dir, "out"), 0o644); err == nil {
		t.Error("copyFileAtomic with a missing source should fail")
	}

	// Read-only destination directory: the temp file cannot be created.
	ro := cov3AReadonlyDir(t)
	if err := copyFileAtomic(src, filepath.Join(ro, "out.bin"), 0o644); err == nil {
		t.Error("copyFileAtomic into a read-only directory should fail")
	}
}

func TestCov3A_WriteBytesAtomicFaults(t *testing.T) {
	cov3ASkipIfRoot(t)
	dir := t.TempDir()

	// A regular file where a parent directory is expected (ENOTDIR from MkdirAll).
	blocker := filepath.Join(dir, "blocker")
	writeFile(t, blocker, []byte("x"))
	if err := writeBytesAtomic(filepath.Join(blocker, "sub", "f"), []byte("y"), 0o644); err == nil {
		t.Error("writeBytesAtomic under a regular-file parent should fail")
	}

	// Read-only directory: MkdirAll no-ops on the existing dir, then the temp
	// file cannot be created.
	ro := cov3AReadonlyDir(t)
	if err := writeBytesAtomic(filepath.Join(ro, "f"), []byte("y"), 0o644); err == nil {
		t.Error("writeBytesAtomic into a read-only directory should fail")
	}
}

func TestCov3A_HashManifestFileFaults(t *testing.T) {
	cov3ASkipIfRoot(t)
	dir := t.TempDir()

	// Missing file: os.Stat fails.
	if _, err := hashManifestFile(filepath.Join(dir, "nope"), "rel"); err == nil {
		t.Error("hashManifestFile on a missing file should fail")
	}

	// A directory is rejected before hashing.
	sub := filepath.Join(dir, "adir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := hashManifestFile(sub, "rel"); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("hashManifestFile on a directory = %v, want a directory error", err)
	}

	// Stat succeeds but the file cannot be opened for hashing.
	unreadable := filepath.Join(dir, "unreadable")
	writeFile(t, unreadable, []byte("secret"))
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })
	if _, err := hashManifestFile(unreadable, "rel"); err == nil {
		t.Error("hashManifestFile on an unreadable file should fail")
	}
}

func TestCov3A_CreateTarGzAndAddFileFaults(t *testing.T) {
	cov3ASkipIfRoot(t)
	ctx := context.Background()
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "real.txt"), []byte("real"))

	// Read-only destination directory: the temp archive cannot be created.
	ro := cov3AReadonlyDir(t)
	files := []ManifestFile{{Path: "real.txt", SHA256: cov3ASHA([]byte("real")), Size: 4}}
	if err := createTarGzAtomic(ctx, filepath.Join(ro, "b.tar.gz"), base, files); err == nil {
		t.Error("createTarGzAtomic into a read-only directory should fail")
	}

	// addFileToTar rejects an unsafe manifest path.
	dst := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := createTarGzAtomic(ctx, dst, base, []ManifestFile{{Path: "../escape", SHA256: strings.Repeat("a", 64), Size: 1}}); err == nil {
		t.Error("createTarGzAtomic with an unsafe path should fail")
	}

	// addFileToTar cannot stat a manifest file that is absent on disk.
	if err := createTarGzAtomic(ctx, dst, base, []ManifestFile{{Path: "ghost.txt", SHA256: strings.Repeat("a", 64), Size: 1}}); err == nil {
		t.Error("createTarGzAtomic with a missing source file should fail")
	}

	// addFileToTar cannot open a stat-able but unreadable file.
	unreadable := filepath.Join(base, "unreadable.txt")
	writeFile(t, unreadable, []byte("x"))
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })
	if err := createTarGzAtomic(ctx, dst, base, []ManifestFile{{Path: "unreadable.txt", SHA256: strings.Repeat("a", 64), Size: 1}}); err == nil {
		t.Error("createTarGzAtomic with an unreadable source file should fail")
	}
}

// -----------------------------------------------------------------------------
// main.go: writeBundleArtifacts guard rails
// -----------------------------------------------------------------------------

func TestCov3A_WriteBundleArtifactsFaults(t *testing.T) {
	ctx := context.Background()

	t.Run("refuses to overwrite existing artifacts", func(t *testing.T) {
		ls := newBareLowServer(t)
		id := bundleIDFor(streamGo, 7)
		if err := os.MkdirAll(ls.cfg.ExportDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(ls.cfg.ExportDir, id+".tar.gz"), []byte("residue"))
		err := ls.writeBundleArtifacts(ctx, id, t.TempDir(), []byte("{}"), []ManifestFile{{Path: "x", SHA256: strings.Repeat("a", 64), Size: 1}})
		if err == nil || !strings.Contains(err.Error(), "already has artifacts") {
			t.Fatalf("writeBundleArtifacts over existing artifacts = %v, want an already-has-artifacts error", err)
		}
	})

	t.Run("propagates a packing failure", func(t *testing.T) {
		ls := newBareLowServer(t)
		id := bundleIDFor(streamGo, 8)
		// The manifest references a file that is not on disk, so createTarGzAtomic
		// fails while packing.
		err := ls.writeBundleArtifacts(ctx, id, t.TempDir(), []byte("{}"), []ManifestFile{{Path: "ghost.info", SHA256: strings.Repeat("a", 64), Size: 1}})
		if err == nil {
			t.Fatal("writeBundleArtifacts should fail when packing fails")
		}
	})
}

// -----------------------------------------------------------------------------
// main.go: loadVerifiedManifest error branches
// -----------------------------------------------------------------------------

func TestCov3A_LoadVerifiedManifestErrors(t *testing.T) {
	pub, priv := newTestKeys(t)
	mods := []moduleSpec{{"github.com/foo/bar", "v1.0.0"}}
	bundleID := bundleIDForSequence(1)

	t.Run("missing signature file", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		_, mb := covMainBuildManifest(t, 1, mods)
		mp := filepath.Join(dir, bundleID+".manifest.json")
		writeFile(t, mp, mb)
		sp := mp + ".sig" // never created
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected an error for a missing signature file")
		}
	})

	t.Run("plain sig then missing manifest", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		mp := filepath.Join(dir, bundleID+".manifest.json") // never created
		sp := mp + ".sig"
		writeFile(t, sp, []byte(base64.StdEncoding.EncodeToString([]byte("x"))+"\n"))
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected an error when the manifest file is missing")
		}
	})

	t.Run("prehashed sig then missing manifest", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		mp := filepath.Join(dir, bundleID+".manifest.json") // never created
		sp := mp + ".sig"
		writeFile(t, sp, []byte(manifestSignaturePHPrefix+base64.StdEncoding.EncodeToString([]byte("x"))+"\n"))
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected an error when hashing a missing manifest")
		}
	})

	t.Run("prehashed sig from the wrong key", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		_, otherPriv := newTestKeys(t)
		dir := t.TempDir()
		_, mb := covMainBuildManifest(t, 1, mods)
		mp := filepath.Join(dir, bundleID+".manifest.json")
		sp := mp + ".sig"
		writeFile(t, mp, mb)
		sig, err := signManifestPH(otherPriv, mb)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, sp, []byte(manifestSignaturePHPrefix+base64.StdEncoding.EncodeToString(sig)+"\n"))
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected verification to fail for a wrong-key prehashed signature")
		}
	})

	t.Run("plain sig over non-JSON manifest", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		garbage := []byte("this is not json")
		mp := filepath.Join(dir, bundleID+".manifest.json")
		sp := mp + ".sig"
		writeFile(t, mp, garbage)
		sig := ed25519.Sign(priv, garbage)
		writeFile(t, sp, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
		if _, err := hs.loadVerifiedManifest(mp, sp, streamGo, bundleID, 1); err == nil {
			t.Fatal("expected a JSON decode error for a non-JSON manifest")
		}
	})
}

// -----------------------------------------------------------------------------
// main.go: install path error branches
// -----------------------------------------------------------------------------

func TestCov3A_InstallVerifiedBundleUnsafePath(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	manifest := BundleManifest{Files: []ManifestFile{{Path: "../escape", SHA256: strings.Repeat("a", 64), Size: 1}}}
	if err := hs.installVerifiedBundle(t.TempDir(), manifest); err == nil || !strings.Contains(err.Error(), "unsafe destination") {
		t.Fatalf("installVerifiedBundle with an unsafe path = %v, want an unsafe-destination error", err)
	}
}

func TestCov3A_InstallVerifiedFileBranches(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	base := hs.downloadDir
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()

	// Immutable conflict: an existing file with different content, not under
	// uploads/, cannot be replaced.
	writeFile(t, filepath.Join(base, "conf.txt"), []byte("aaa"))
	conflict := ManifestFile{Path: "conf.txt", SHA256: cov3ASHA([]byte("bbb")), Size: 3}
	if err := installVerifiedFile(staging, base, conflict); err == nil || !strings.Contains(err.Error(), "immutable file conflict") {
		t.Fatalf("installVerifiedFile conflict = %v, want an immutable-conflict error", err)
	}

	// Idempotent: an existing file whose content already matches is a no-op.
	writeFile(t, filepath.Join(base, "same.txt"), []byte("data"))
	same := ManifestFile{Path: "same.txt", SHA256: cov3ASHA([]byte("data")), Size: 4}
	if err := installVerifiedFile(staging, base, same); err != nil {
		t.Fatalf("installVerifiedFile idempotent = %v, want nil", err)
	}

	// Prior file that is not in the repository.
	missing := ManifestFile{Path: "prior-missing.txt", SHA256: strings.Repeat("a", 64), Size: 3, Prior: true}
	if err := installVerifiedFile(staging, base, missing); err == nil || !strings.Contains(err.Error(), "not in the repository") {
		t.Fatalf("installVerifiedFile missing prior = %v, want a not-in-repository error", err)
	}

	// Prior file with a size that disagrees with the manifest.
	writeFile(t, filepath.Join(base, "prior-sz.txt"), []byte("12345"))
	sizeBad := ManifestFile{Path: "prior-sz.txt", SHA256: strings.Repeat("a", 64), Size: 6, Prior: true}
	if err := installVerifiedFile(staging, base, sizeBad); err == nil || !strings.Contains(err.Error(), "does not match manifest size") {
		t.Fatalf("installVerifiedFile prior size = %v, want a size-mismatch error", err)
	}

	// Prior file present with a matching size.
	writeFile(t, filepath.Join(base, "prior-ok.txt"), []byte("12345"))
	priorOK := ManifestFile{Path: "prior-ok.txt", SHA256: strings.Repeat("a", 64), Size: 5, Prior: true}
	if err := installVerifiedFile(staging, base, priorOK); err != nil {
		t.Fatalf("installVerifiedFile prior ok = %v, want nil", err)
	}
}

// -----------------------------------------------------------------------------
// main.go: extractTarEntry filesystem faults
// -----------------------------------------------------------------------------

func TestCov3A_ExtractTarEntryFaults(t *testing.T) {
	content := []byte("archive bytes")

	t.Run("unsafe archive path", func(t *testing.T) {
		tr, hdr := covMainTarReaderFor(t, "a/../../escape", content)
		expected := map[string]ManifestFile{"a/../../escape": {Path: "a/../../escape", SHA256: cov3ASHA(content), Size: int64(len(content))}}
		if err := extractTarEntry(tr, hdr, t.TempDir(), expected); err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
			t.Fatalf("extractTarEntry unsafe path = %v, want an unsafe-path error", err)
		}
	})

	t.Run("destination already exists", func(t *testing.T) {
		staging := t.TempDir()
		if err := os.MkdirAll(filepath.Join(staging, "a"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(staging, "a", "b.txt"), []byte("old"))
		tr, hdr := covMainTarReaderFor(t, "a/b.txt", content)
		expected := map[string]ManifestFile{"a/b.txt": {Path: "a/b.txt", SHA256: cov3ASHA(content), Size: int64(len(content))}}
		if err := extractTarEntry(tr, hdr, staging, expected); err == nil {
			t.Fatal("extractTarEntry over an existing file should fail (O_EXCL)")
		}
	})

	t.Run("parent is a regular file", func(t *testing.T) {
		staging := t.TempDir()
		writeFile(t, filepath.Join(staging, "a"), []byte("iam a file"))
		tr, hdr := covMainTarReaderFor(t, "a/b.txt", content)
		expected := map[string]ManifestFile{"a/b.txt": {Path: "a/b.txt", SHA256: cov3ASHA(content), Size: int64(len(content))}}
		if err := extractTarEntry(tr, hdr, staging, expected); err == nil {
			t.Fatal("extractTarEntry under a regular-file parent should fail")
		}
	})
}

// -----------------------------------------------------------------------------
// main.go: metadata hashing / key reading limits
// -----------------------------------------------------------------------------

func TestCov3A_HashFileLimitSHA512(t *testing.T) {
	dir := t.TempDir()
	if _, err := hashFileLimitSHA512(filepath.Join(dir, "nope"), 16); err == nil {
		t.Error("hashFileLimitSHA512 on a missing file should fail")
	}
	big := filepath.Join(dir, "big")
	writeFile(t, big, []byte("123456789"))
	if _, err := hashFileLimitSHA512(big, 8); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("hashFileLimitSHA512 oversize = %v, want an exceeds error", err)
	}
}

func TestCov3A_ReadPrivateKeyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := readPrivateKey(filepath.Join(dir, "nope")); err == nil {
		t.Error("readPrivateKey on a missing file should fail")
	}
	short := filepath.Join(dir, "short.key")
	writeFile(t, short, []byte(base64.StdEncoding.EncodeToString([]byte("too short"))+"\n"))
	if _, err := readPrivateKey(short); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("readPrivateKey wrong length = %v, want a length error", err)
	}
}

// -----------------------------------------------------------------------------
// main.go: parseGoModDownload edge cases
// -----------------------------------------------------------------------------

func TestCov3A_ParseGoModDownload(t *testing.T) {
	if _, err := parseGoModDownload([]byte("{not json")); err == nil {
		t.Error("parseGoModDownload on garbage should fail")
	}
	if _, err := parseGoModDownload([]byte(`{"Path":"m","Version":"v1","Error":"nope"}`)); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("parseGoModDownload with an entry error = %v, want the entry error", err)
	}
	// An empty-version entry is skipped; the concrete one is returned.
	recs, err := parseGoModDownload([]byte(`{"Path":"m","Version":""}` + "\n" + `{"Path":"m2","Version":"v2.0.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Module != "m2" || recs[0].Version != "v2.0.0" {
		t.Errorf("parseGoModDownload = %+v, want only m2@v2.0.0", recs)
	}
}

// -----------------------------------------------------------------------------
// main.go: goLatest / fetchVersion error branches (fake `go`)
// -----------------------------------------------------------------------------

const cov3AGoLatestScript = `#!/usr/bin/env bash
case "$*" in
  *failmod*) echo "boom" >&2; exit 1 ;;
  *errmod*) printf '{"Error":"latest boom"}' ;;
  *emptymod*) printf '{}' ;;
  *) printf 'not json' ;;
esac
`

func TestCov3A_GoLatestErrors(t *testing.T) {
	ls, _ := newFakeLowServerWithGo(t, writeFakeGoWith(t, cov3AGoLatestScript))
	ctx := context.Background()

	if _, err := ls.goLatest(ctx, "-badflag"); err == nil {
		t.Error("goLatest with a flag-like module path should fail validation")
	}
	if _, err := ls.goLatest(ctx, "example.com/failmod"); err == nil {
		t.Error("goLatest with a failing go command should fail")
	}
	if _, err := ls.goLatest(ctx, "example.com/errmod"); err == nil || !strings.Contains(err.Error(), "latest boom") {
		t.Errorf("goLatest with an Error field = %v, want the reported error", err)
	}
	if _, err := ls.goLatest(ctx, "example.com/emptymod"); err == nil || !strings.Contains(err.Error(), "did not return a version") {
		t.Errorf("goLatest with an empty version = %v, want a no-version error", err)
	}
	if _, err := ls.goLatest(ctx, "example.com/garbage"); err == nil || !strings.Contains(err.Error(), "parse go latest") {
		t.Errorf("goLatest with garbage output = %v, want a parse error", err)
	}
}

const cov3AFetchScript = `#!/usr/bin/env bash
case "$*" in
  *errmod*) printf '{"Error":"dl boom"}' ;;
  *incompletemod*) printf '{"Path":"x","Version":"v1.0.0"}' ;;
  *) printf 'not json' ;;
esac
`

func TestCov3A_FetchVersionErrors(t *testing.T) {
	ls, _ := newFakeLowServerWithGo(t, writeFakeGoWith(t, cov3AFetchScript))
	ctx := context.Background()

	// Pure validation branches that never shell out.
	if err := ls.fetchVersion(ctx, "", "v1.0.0"); err == nil {
		t.Error("fetchVersion with an empty module should fail")
	}
	if err := ls.fetchVersion(ctx, "m", "latest"); err == nil {
		t.Error("fetchVersion with a non-concrete version should fail")
	}
	if err := ls.fetchVersion(ctx, "-badflag", "v1.0.0"); err == nil {
		t.Error("fetchVersion with a flag-like module should fail")
	}
	if err := ls.fetchVersion(ctx, "example.com/m", "-badver"); err == nil {
		t.Error("fetchVersion with a flag-like version should fail")
	}

	// Script-driven download failures.
	if err := ls.fetchVersion(ctx, "example.com/errmod", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "dl boom") {
		t.Errorf("fetchVersion with an Error field = %v, want the reported error", err)
	}
	if err := ls.fetchVersion(ctx, "example.com/incompletemod", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "did not produce complete files") {
		t.Errorf("fetchVersion with an incomplete result = %v, want an incomplete error", err)
	}
	if err := ls.fetchVersion(ctx, "example.com/garbage", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "parse go mod download") {
		t.Errorf("fetchVersion with garbage output = %v, want a parse error", err)
	}
}

// -----------------------------------------------------------------------------
// main.go: high-side serving / status error branches
// -----------------------------------------------------------------------------

func TestCov3A_HandleHighVersionFileZiphash(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"github.com/foo/bar", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// A .ziphash is an accepted extension but the file is absent, so this walks
	// the isComplete + safeJoin + serveFile path to a 404.
	if code, _ := httpGet(t, srv.URL+"/go/github.com/foo/bar/@v/v1.0.0.ziphash"); code != http.StatusNotFound {
		t.Errorf("ziphash request = %d, want 404", code)
	}
}

func TestCov3A_ImportStatusFindStreamsError(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// Point quarantine at a regular file so importStatusLocked's scan of it fails,
	// while landing stays a valid directory (quarantineFutureBundlesLocked scans
	// only landing and still succeeds).
	blocker := filepath.Join(t.TempDir(), "quarantine-file")
	writeFile(t, blocker, []byte("x"))
	hs.cfg.Quarantine = blocker
	if _, err := hs.ImportStatus(); err == nil {
		t.Fatal("ImportStatus should fail when the quarantine path is not a directory")
	}
}

func TestCov3A_ImportBundleFromDirLockedFaults(t *testing.T) {
	pub, priv := newTestKeys(t)

	t.Run("incomplete bundle", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		id := bundleIDFor(streamGo, 1)
		writeFile(t, filepath.Join(dir, id+".tar.gz"), []byte("only the archive"))
		if _, err := hs.importBundleFromDirLocked(dir, streamGo, id, 1); err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("importBundleFromDirLocked incomplete = %v, want an incomplete error", err)
		}
	})

	t.Run("oversized signature artifact", func(t *testing.T) {
		hs := newTestHighServer(t, pub)
		dir := t.TempDir()
		id := bundleIDFor(streamGo, 1)
		// Build a valid manifest+archive, then bloat the signature past its limit.
		writeSignedBundle(t, dir, priv, 1, 0, []moduleSpec{{"m", "v1.0.0"}})
		sig := filepath.Join(dir, id+".manifest.json.sig")
		writeFile(t, sig, bytes.Repeat([]byte("A"), int(diodeMaxSignatureBytes)+1))
		if _, err := hs.importBundleFromDirLocked(dir, streamGo, id, 1); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("importBundleFromDirLocked oversized sig = %v, want an exceeds error", err)
		}
	})
}

// -----------------------------------------------------------------------------
// diodewire.go: send side
// -----------------------------------------------------------------------------

func TestCov3A_SendDiodeFileErrors(t *testing.T) {
	pl := testDiodePlan(t)
	enc, err := reedsolomon.New(pl.dataShards, pl.parityShards)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newDiodeTransferID()
	if err != nil {
		t.Fatal(err)
	}
	noop := func([]byte) error { return nil }

	// An empty file is refused up front.
	empty := diodeFileMeta{TransferID: id, Name: "go-bundle-000001.tar.gz", FileSize: 0}
	if err := sendDiodeFile(bytes.NewReader(nil), empty, pl, enc, noop); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("sendDiodeFile empty = %v, want an empty-file error", err)
	}

	// A reader shorter than the declared size fails at io.ReadFull.
	short := diodeFileMeta{TransferID: id, Name: "go-bundle-000001.tar.gz", FileSize: int64(pl.blockDataSize()) + 100}
	if err := sendDiodeFile(bytes.NewReader([]byte("tiny")), short, pl, enc, noop); err == nil || !strings.Contains(err.Error(), "read") {
		t.Errorf("sendDiodeFile short read = %v, want a read error", err)
	}

	// emit failures propagate.
	content := make([]byte, pl.blockDataSize())
	meta := diodeFileMeta{TransferID: id, Name: "go-bundle-000001.tar.gz", FileSize: int64(len(content))}
	if err := sendDiodeFile(bytes.NewReader(content), meta, pl, enc, func([]byte) error { return errCov3ABoom }); !errors.Is(err, errCov3ABoom) {
		t.Errorf("sendDiodeFile emit error = %v, want the emit error", err)
	}

	// An empty name cannot be marshalled into a datagram.
	badName := diodeFileMeta{TransferID: id, Name: "", FileSize: int64(len(content))}
	if err := sendDiodeFile(bytes.NewReader(content), badName, pl, enc, noop); err == nil {
		t.Error("sendDiodeFile with an empty name should fail to marshal")
	}
}

// -----------------------------------------------------------------------------
// diodewire.go: receive side
// -----------------------------------------------------------------------------

func TestCov3A_LandFileRenameFails(t *testing.T) {
	const name = "go-bundle-000001.tar.gz"
	content := []byte("the reassembled bundle bytes")
	sha := sha256.Sum256(content)

	asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
	// A directory sitting at the final landing name makes the atomic rename fail.
	if err := os.MkdirAll(filepath.Join(asm.dir, name), 0o755); err != nil {
		t.Fatal(err)
	}
	tr := covLangTransfer(t, asm, 1, name, content, sha, int64(len(content)))
	if err := asm.landFile(tr); err == nil {
		t.Fatal("landFile should fail when the destination name is a directory")
	}
}

func TestCov3A_TransferForFaults(t *testing.T) {
	cov3ASkipIfRoot(t)
	validPacket := func() *diodePacket {
		return &diodePacket{Name: "go-bundle-000001.tar.gz", FileSize: 100, BlockCount: 1}
	}
	now := time.Now()

	t.Run("too many transfers in flight", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		for i := 0; i < diodeMaxTransfers; i++ {
			var tid [16]byte
			tid[0] = byte(i + 1)
			asm.active[tid] = &diodeTransfer{}
		}
		if _, err := asm.transferFor(validPacket(), now); err == nil || !strings.Contains(err.Error(), "transfers in flight") {
			t.Fatalf("transferFor over the transfer cap = %v, want a too-many error", err)
		}
	})

	t.Run("quota measurement error", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		asm.measureStored = func() (int64, error) { return 0, errCov3ABoom }
		if _, err := asm.transferFor(validPacket(), now); err == nil || !strings.Contains(err.Error(), "measure landing quota") {
			t.Fatalf("transferFor with a measure error = %v, want a measure-quota error", err)
		}
	})

	t.Run("unverified quota exceeded", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		asm.measureStored = func() (int64, error) { return diodeMaxUnverifiedBytes, nil }
		if _, err := asm.transferFor(validPacket(), now); err == nil || !strings.Contains(err.Error(), "quota") {
			t.Fatalf("transferFor over quota = %v, want a quota error", err)
		}
	})

	t.Run("landing temp file cannot be created", func(t *testing.T) {
		ro := cov3AReadonlyDir(t)
		asm := newDiodeAssembler(ro, validBundleFileName, nil)
		asm.measureStored = func() (int64, error) { return 0, nil }
		if _, err := asm.transferFor(validPacket(), now); err == nil {
			t.Fatal("transferFor into a read-only landing dir should fail")
		}
	})
}

func TestCov3A_BlockForFaults(t *testing.T) {
	t.Run("shard geometry mismatch within a block", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		tx := &diodeTransfer{name: "go-bundle-000001.tar.gz", blocks: map[uint32]*diodeBlock{}}
		p1 := &diodePacket{BlockIndex: 0, DataShards: 4, ParityShards: 2, ShardSize: 100, BlockLen: 400, BlockOffset: 0}
		if _, err := asm.blockFor(tx, p1); err != nil {
			t.Fatal(err)
		}
		p2 := &diodePacket{BlockIndex: 0, DataShards: 5, ParityShards: 2, ShardSize: 100, BlockLen: 400, BlockOffset: 0}
		if _, err := asm.blockFor(tx, p2); err == nil || !strings.Contains(err.Error(), "geometry mismatch") {
			t.Fatalf("blockFor geometry mismatch = %v, want a geometry-mismatch error", err)
		}
	})

	t.Run("per-transfer reassembly budget", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		tx := &diodeTransfer{name: "go-bundle-000001.tar.gz", blocks: map[uint32]*diodeBlock{}}
		var bounded bool
		for bi := 0; bi < 64; bi++ {
			p := &diodePacket{
				BlockIndex: uint32(bi), DataShards: 255, ParityShards: 1,
				ShardSize: diodeMaxShardSize, BlockLen: 255 * diodeMaxShardSize, BlockOffset: 0,
			}
			if _, err := asm.blockFor(tx, p); err != nil {
				if !strings.Contains(err.Error(), "reassembly budget") {
					t.Fatalf("blockFor failed for the wrong bound: %v", err)
				}
				bounded = true
				break
			}
		}
		if !bounded {
			t.Fatal("blockFor never reached the per-transfer reassembly budget")
		}
	})
}

// -----------------------------------------------------------------------------
// diode.go: streaming upload / storage helpers
// -----------------------------------------------------------------------------

func TestCov3A_WriteStreamAtomicLimitFaults(t *testing.T) {
	cov3ASkipIfRoot(t)
	dir := t.TempDir()

	// Read-only directory: the temp file cannot be created.
	ro := cov3AReadonlyDir(t)
	if _, err := writeStreamAtomicLimit(filepath.Join(ro, "f.tar.gz"), strings.NewReader("data"), 100); err == nil {
		t.Error("writeStreamAtomicLimit into a read-only dir should fail")
	}

	// Regular-file parent: MkdirAll fails.
	blocker := filepath.Join(dir, "blocker")
	writeFile(t, blocker, []byte("x"))
	if _, err := writeStreamAtomicLimit(filepath.Join(blocker, "sub", "f"), strings.NewReader("data"), 100); err == nil {
		t.Error("writeStreamAtomicLimit under a regular-file parent should fail")
	}

	// A failing reader is surfaced.
	if _, err := writeStreamAtomicLimit(filepath.Join(dir, "reader-fail"), cov3AErrReader{}, 100); err == nil {
		t.Error("writeStreamAtomicLimit with a failing reader should fail")
	}

	// The final rename fails when the destination name is an existing directory.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := writeStreamAtomicLimit(target, strings.NewReader("data"), 100); err == nil {
		t.Error("writeStreamAtomicLimit renaming over a directory should fail")
	}
}

func TestCov3A_StoreDiodeUploadStatusHelpers(t *testing.T) {
	tooBig := &http.MaxBytesError{Limit: 5}
	if got := diodeStoreErrorStatus(tooBig, 5, 10); got != http.StatusInsufficientStorage {
		t.Errorf("diodeStoreErrorStatus quota = %d, want 507", got)
	}
	if got := diodeStoreErrorStatus(&http.MaxBytesError{Limit: 10}, 10, 10); got != http.StatusRequestEntityTooLarge {
		t.Errorf("diodeStoreErrorStatus size = %d, want 413", got)
	}
	if got := diodeStoreErrorStatus(errCov3ABoom, 1, 1); got != http.StatusInternalServerError {
		t.Errorf("diodeStoreErrorStatus generic = %d, want 500", got)
	}

	if err := diodeStoreError("f", tooBig, 5, 10); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Errorf("diodeStoreError quota = %v, want a quota error", err)
	}
	if err := diodeStoreError("f", &http.MaxBytesError{Limit: 10}, 10, 10); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("diodeStoreError size = %v, want an exceeds error", err)
	}
	if err := diodeStoreError("f", errCov3ABoom, 1, 1); err == nil || !strings.Contains(err.Error(), "store f") {
		t.Errorf("diodeStoreError generic = %v, want a store error", err)
	}
}

// TestCov3A_StoreDiodeUploadPartialQuota drives storeDiodeUpload's branch where
// the remaining quota is smaller than the per-suffix limit and the body would
// exceed it.
func TestCov3A_StoreDiodeUploadPartialQuota(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	hs.cfg.DiodeIngest = true
	hs.cfg.DiodeToken = "diode-secret"

	// Fill the rejected area so only a little unverified quota remains.
	rejected := filepath.Join(hs.cfg.Root, "rejected")
	if err := os.MkdirAll(rejected, 0o755); err != nil {
		t.Fatal(err)
	}
	filler := filepath.Join(rejected, "retained.bin")
	if err := os.WriteFile(filler, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filler, diodeMaxUnverifiedBytes-100); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPut, "/diode/go-bundle-000001.tar.gz", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+hs.cfg.DiodeToken)
	req.ContentLength = 200 // more than the ~100 bytes of remaining quota
	rec := httptest.NewRecorder()
	hs.ServeHTTP(rec, req)
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("partial-quota upload = %d, want 507", rec.Code)
	}
}

func TestCov3A_DirectoryRegularFileBytesExceptError(t *testing.T) {
	// A regular file where a directory is expected yields a (non-not-exist) error.
	f := filepath.Join(t.TempDir(), "not-a-dir")
	writeFile(t, f, []byte("x"))
	if _, err := directoryRegularFileBytesExcept(f, nil); err == nil {
		t.Error("directoryRegularFileBytesExcept on a regular file should fail")
	}
}

func TestCov3A_UploadDiodeFileErrors(t *testing.T) {
	ls := newBareLowServer(t)
	if err := os.MkdirAll(ls.cfg.ExportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Missing source file: os.Open fails.
	if err := ls.uploadDiodeFile(ctx, "http://127.0.0.1:1", "go-bundle-000099.tar.gz"); err == nil {
		t.Error("uploadDiodeFile of a missing file should fail")
	}

	// Present file but an unreachable endpoint: the HTTP request fails.
	name := "go-bundle-000042.tar.gz"
	writeFile(t, filepath.Join(ls.cfg.ExportDir, name), []byte("bundle"))
	if err := ls.uploadDiodeFile(ctx, "http://127.0.0.1:1", name); err == nil || !strings.Contains(err.Error(), "PUT") {
		t.Errorf("uploadDiodeFile to an unreachable endpoint = %v, want a PUT error", err)
	}
}

func TestCov3A_TrivialDiodeHelpers(t *testing.T) {
	if err := validateDiodeURL(""); err != nil {
		t.Errorf("validateDiodeURL empty = %v, want nil", err)
	}
	if err := validateDiodeURL("http://example.com/diode"); err != nil {
		t.Errorf("validateDiodeURL valid = %v, want nil", err)
	}
	for _, bad := range []string{"ftp://example.com", "http://", "not a url"} {
		if err := validateDiodeURL(bad); err == nil {
			t.Errorf("validateDiodeURL(%q) = nil, want an error", bad)
		}
	}

	if got := diodeTokenStatus(""); !strings.Contains(got, "open to the network") {
		t.Errorf("diodeTokenStatus empty = %q", got)
	}
	if got := diodeTokenStatus("tok"); !strings.Contains(got, "bearer token") {
		t.Errorf("diodeTokenStatus set = %q", got)
	}
}
