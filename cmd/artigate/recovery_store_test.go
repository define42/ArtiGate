package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func recoveryWriteTestFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, name, data)
}

func recoveryTestSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	recoveryWriteTestFile(t, filepath.Join(root, "import-state.json"), []byte(`{"imported":{"go":7}}`))
	recoveryWriteTestFile(t, filepath.Join(root, "cache/download/a/file"), []byte("first artifact"))
	recoveryWriteTestFile(t, filepath.Join(root, "cache/download/a.txt"), []byte("second artifact"))
	return root
}

func recoveryTestManifest() recoveryManifest {
	return recoveryManifest{Kind: "backup", Role: "high", Streams: map[string]int64{streamGo: 7}}
}

func TestRecoveryStoreSplitRoundTrip(t *testing.T) {
	source := recoveryTestSource(t)
	payload := make([]byte, 16<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	recoveryWriteTestFile(t, filepath.Join(source, "cache/download/random"), payload)
	if err := os.Chmod(filepath.Join(source, "cache/download/random"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	artifactDir := filepath.Join(dir, "backup")
	artifact, err := writeRecoveryArtifactWithPartSize(t.Context(), source, artifactDir, recoveryTestManifest(), nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Manifest.Parts) < 20 {
		t.Fatalf("split produced only %d parts", len(artifact.Manifest.Parts))
	}
	for _, part := range artifact.Manifest.Parts {
		if part.Size > 512 {
			t.Fatalf("oversized part: %+v", part)
		}
	}
	if _, err := verifyRecoveryArtifact(t.Context(), artifactDir, nil, artifact.Digest); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restored")
	if _, err := restoreRecoveryArtifact(t.Context(), artifactDir, target, nil, artifact.Digest); err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Manifest.Files {
		original, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		restored, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(file.Path)))
		if err != nil || !bytes.Equal(original, restored) {
			t.Fatalf("restore %s mismatch: %v", file.Path, err)
		}
	}
	info, err := os.Stat(filepath.Join(target, "cache/download/random"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("executable mode not preserved: %v, %v", info, err)
	}
	for _, name := range []string{artifactDir, target} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("sensitive root mode: %v, %v", info, err)
		}
	}
}

func TestRecoveryStoreRejectsUnauthenticatedAndTamperedData(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, recoveryArtifact) string
	}{
		{"no trust", func(_ *testing.T, _ string, _ recoveryArtifact) string { return "" }},
		{"wrong digest", func(_ *testing.T, _ string, _ recoveryArtifact) string { return strings.Repeat("0", 64) }},
		{"manifest", func(t *testing.T, dir string, a recoveryArtifact) string {
			recoveryWriteTestFile(t, filepath.Join(dir, "manifest.json"), []byte(`{}`))
			return a.Digest
		}},
		{"part tamper", func(t *testing.T, dir string, a recoveryArtifact) string {
			file := filepath.Join(dir, a.Manifest.Parts[0].Path)
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)/2] ^= 0x80
			recoveryWriteTestFile(t, file, data)
			return a.Digest
		}},
		{"part missing", func(t *testing.T, dir string, a recoveryArtifact) string {
			if err := os.Remove(filepath.Join(dir, a.Manifest.Parts[0].Path)); err != nil {
				t.Fatal(err)
			}
			return a.Digest
		}},
		{"undeclared file", func(t *testing.T, dir string, a recoveryArtifact) string {
			recoveryWriteTestFile(t, filepath.Join(dir, "extra"), []byte("unexpected"))
			return a.Digest
		}},
		{"part symlink", func(t *testing.T, dir string, a recoveryArtifact) string {
			file := filepath.Join(dir, a.Manifest.Parts[0].Path)
			if err := os.Rename(file, filepath.Join(t.TempDir(), "part")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("manifest.json", file); err != nil {
				t.Fatal(err)
			}
			return a.Digest
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			artifactDir := filepath.Join(dir, "artifact")
			a, err := writeRecoveryArtifact(t.Context(), recoveryTestSource(t), artifactDir, recoveryTestManifest(), nil)
			if err != nil {
				t.Fatal(err)
			}
			digest := test.mutate(t, artifactDir, a)
			target := filepath.Join(dir, "restored")
			if _, err := restoreRecoveryArtifact(t.Context(), artifactDir, target, nil, digest); err == nil {
				t.Fatal("restore accepted bad artifact")
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed restore published target: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "artifact" {
				t.Fatalf("failed restore leaked staging files: %v, %v", entries, err)
			}
		})
	}
}

func TestRecoveryStoreCheckpointAuthentication(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "checkpoint")
	m := recoveryTestManifest()
	m.Kind = "checkpoint"
	a, err := writeRecoveryArtifact(t.Context(), recoveryTestSource(t), dir, m, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRecoveryArtifact(t.Context(), dir, pub, a.Digest); err != nil {
		t.Fatal(err)
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRecoveryArtifact(t.Context(), dir, wrong, a.Digest); err == nil {
		t.Fatal("wrong checkpoint key accepted")
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(data)
	sig, err := priv.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		t.Fatal(err)
	}
	recoveryWriteTestFile(t, filepath.Join(dir, "signature"), sig)
	if _, err := verifyRecoveryArtifact(t.Context(), dir, pub, a.Digest); err == nil {
		t.Fatal("signature without recovery context accepted")
	}
}

func TestRecoveryStoreRejectsUnsafeManifestAndTar(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*recoveryManifest, []*tar.Header)
	}{
		{"traversal", func(m *recoveryManifest, h []*tar.Header) { m.Files[0].Path = "../escaped"; h[0].Name = "../escaped" }},
		{"absolute", func(m *recoveryManifest, h []*tar.Header) {
			m.Files[0].Path = "/tmp/escaped"
			h[0].Name = "/tmp/escaped"
		}},
		{"duplicate", func(m *recoveryManifest, h []*tar.Header) { m.Files[1] = m.Files[0]; *h[1] = *h[0] }},
		{"symlink", func(_ *recoveryManifest, h []*tar.Header) {
			h[0].Typeflag = tar.TypeSymlink
			h[0].Size = 0
			h[0].Linkname = "outside"
		}},
		{"hard link", func(_ *recoveryManifest, h []*tar.Header) {
			h[0].Typeflag = tar.TypeLink
			h[0].Size = 0
			h[0].Linkname = "outside"
		}},
		{"extra tar file", func(m *recoveryManifest, _ []*tar.Header) { m.Files = m.Files[:1] }},
		{"role escape", func(m *recoveryManifest, h []*tar.Header) {
			m.Files[0].Path = "keys/private.key"
			h[0].Name = "keys/private.key"
		}},
		{"file hash", func(m *recoveryManifest, _ []*tar.Header) { m.Files[0].SHA256 = strings.Repeat("0", 64) }},
		{"size limit", func(m *recoveryManifest, _ []*tar.Header) { m.Files[0].Size = recoveryMaxFileSize + 1 }},
		{"stream", func(m *recoveryManifest, _ []*tar.Header) { m.Streams["unknown"] = 4 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifactDir, digest := recoveryTestMalformedArtifact(t, test.mutate, "")
			target := filepath.Join(t.TempDir(), "restore")
			if _, err := restoreRecoveryArtifact(t.Context(), artifactDir, target, nil, digest); err == nil {
				t.Fatal("malformed archive was accepted")
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("malformed archive published root: %v", err)
			}
		})
	}
}

func TestRecoveryStoreRejectsTrailingAndTruncatedStreams(t *testing.T) {
	for _, mode := range []string{"gzip trailing", "tar trailing", "tar truncated", "gzip truncated"} {
		t.Run(mode, func(t *testing.T) {
			dir, digest := recoveryTestMalformedArtifact(t, nil, mode)
			if _, err := verifyRecoveryArtifact(t.Context(), dir, nil, digest); err == nil {
				t.Fatal("invalid stream accepted")
			}
		})
	}
}

// Build an authenticated but structurally invalid backup to test validation
// beyond ordinary corruption of a digest-bound part or manifest.
func recoveryTestMalformedArtifact(t *testing.T, mutate func(*recoveryManifest, []*tar.Header), mode string) (string, string) {
	t.Helper()
	state := []byte(`{"imported":{"go":7}}`)
	m := recoveryTestManifest()
	m.Format, m.Created = recoveryFormat, time.Now().UTC()
	hash := sha256.Sum256(state)
	for _, name := range []string{"import-state.json", "cache/download/artifact"} {
		m.Files = append(m.Files, recoveryFile{Path: name, Mode: 0o600, Size: int64(len(state)), SHA256: hex.EncodeToString(hash[:])})
	}
	headers := make([]*tar.Header, len(m.Files))
	for i, file := range m.Files {
		headers[i] = &tar.Header{Name: file.Path, Size: file.Size, Mode: int64(file.Mode), Typeflag: tar.TypeReg}
	}
	if mutate != nil {
		mutate(&m, headers)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, header := range headers {
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size != 0 {
			if _, err := tw.Write(state); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := archive.Bytes()
	if mode == "tar truncated" {
		raw = raw[:len(raw)-1024]
	}
	if mode == "tar trailing" {
		raw = append(raw, []byte("hidden")...)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	part := compressed.Bytes()
	if mode == "gzip trailing" {
		part = append(part, []byte("hidden")...)
	}
	if mode == "gzip truncated" {
		part = part[:len(part)-4]
	}
	hash = sha256.Sum256(part)
	m.Parts = []recoveryPart{{Path: recoveryPartName(0), Size: int64(len(part)), SHA256: hex.EncodeToString(hash[:])}}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	recoveryWriteTestFile(t, filepath.Join(dir, "manifest.json"), data)
	recoveryWriteTestFile(t, filepath.Join(dir, recoveryPartName(0)), part)
	digest := sha256.Sum256(data)
	return dir, hex.EncodeToString(digest[:])
}

func TestRecoveryStoreCancellationAndNonOverwrite(t *testing.T) {
	source := recoveryTestSource(t)
	dir := t.TempDir()
	artifactDir := filepath.Join(dir, "artifact")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := writeRecoveryArtifact(ctx, source, artifactDir, recoveryTestManifest(), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write: %v", err)
	}
	a, err := writeRecoveryArtifact(t.Context(), source, artifactDir, recoveryTestManifest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeRecoveryArtifact(t.Context(), source, artifactDir, recoveryTestManifest(), nil); err == nil {
		t.Fatal("overwrote existing artifact")
	}
	target := filepath.Join(dir, "target")
	if _, err := restoreRecoveryArtifact(ctx, artifactDir, target, nil, a.Digest); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled restore: %v", err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreRecoveryArtifact(t.Context(), artifactDir, target, nil, a.Digest); err == nil {
		t.Fatal("overwrote existing root")
	}
	if _, err := writeRecoveryArtifact(t.Context(), source, filepath.Join(source, "nested"), recoveryTestManifest(), nil); err == nil {
		t.Fatal("allowed output inside source")
	}
}

type recoveryCancelWriter struct{ cancel context.CancelFunc }

func (w recoveryCancelWriter) Write(data []byte) (int, error) {
	w.cancel()
	return len(data), nil
}

func TestRecoveryCopySourceCancellationAndSymlinks(t *testing.T) {
	source := recoveryTestSource(t)
	recoveryWriteTestFile(t, filepath.Join(source, "large"), make([]byte, 256<<10))
	root, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.Stat("large")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = recoveryCopySourceFile(ctx, root, "large", info, recoveryCancelWriter{cancel: cancel})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during file copy: %v", err)
	}
	if err := os.Symlink("large", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeRecoveryArtifact(t.Context(), source, filepath.Join(t.TempDir(), "artifact"), recoveryTestManifest(), nil); err == nil {
		t.Fatal("source symlink accepted")
	}
}

func TestRecoveryRestoreRejectsStateMismatch(t *testing.T) {
	m := recoveryTestManifest()
	m.Streams[streamGo]++
	dir := filepath.Join(t.TempDir(), "artifact")
	a, err := writeRecoveryArtifact(t.Context(), recoveryTestSource(t), dir, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRecoveryArtifact(t.Context(), dir, nil, a.Digest); err == nil {
		t.Fatal("verified archive with mismatched sequence state")
	}
	target := filepath.Join(t.TempDir(), "restore")
	if _, err := restoreRecoveryArtifact(t.Context(), dir, target, nil, a.Digest); err == nil {
		t.Fatal("activated root with mismatched state")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid root published: %v", err)
	}
}

func TestRecoveryRestoreActivationFailures(t *testing.T) {
	artifactDir := filepath.Join(t.TempDir(), "artifact")
	a, err := writeRecoveryArtifact(t.Context(), recoveryTestSource(t), artifactDir, recoveryTestManifest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stage sync", "publish", "target race", "parent sync", "cancel before activation"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			target := filepath.Join(parent, "target")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fault := errors.New("injected activation failure")
			syncDir := func(name string) error {
				if (mode == "stage sync" && name != parent) || (mode == "parent sync" && name == parent) {
					return fault
				}
				if mode == "cancel before activation" {
					cancel()
				}
				return fsyncDir(name)
			}
			publish := func(stage, destination string) error {
				if mode == "publish" {
					return fault
				}
				if mode == "target race" {
					if err := os.Mkdir(destination, 0o700); err != nil {
						return err
					}
					recoveryWriteTestFile(t, filepath.Join(destination, "sentinel"), []byte("preserve existing root"))
				}
				return publishRecoveryDirectory(stage, destination)
			}
			_, err := restoreRecoveryArtifactWithOps(ctx, artifactDir, target, nil, a.Digest, syncDir, publish)
			if err == nil {
				t.Fatal("injected failure not reported")
			}
			switch mode {
			case "parent sync":
				if !strings.Contains(err.Error(), "activated but parent sync failed") {
					t.Fatalf("unclear activation result: %v", err)
				}
				if err := validateRecoveryBackupState(target, a.Manifest); err != nil {
					t.Fatalf("fully activated root was removed: %v", err)
				}
			case "target race":
				data, err := os.ReadFile(filepath.Join(target, "sentinel"))
				if err != nil || string(data) != "preserve existing root" {
					t.Fatalf("overwrote concurrent destination: %q, %v", data, err)
				}
			default:
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed operation published root: %v", err)
				}
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "target" {
					t.Fatalf("leaked staging directory %s", entry.Name())
				}
			}
		})
	}
}

func TestRecoveryRestorePrepareRunsBeforeActivation(t *testing.T) {
	artifactDir := filepath.Join(t.TempDir(), "artifact")
	a, err := writeRecoveryArtifact(t.Context(), recoveryTestSource(t), artifactDir, recoveryTestManifest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		target := filepath.Join(t.TempDir(), "restore")
		called := false
		prepare := func(_ context.Context, stage string) error {
			called = true
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("prepare ran after activation: %v", err)
			}
			if err := validateRecoveryBackupState(stage, a.Manifest); err != nil {
				t.Fatal(err)
			}
			if fail {
				return errors.New("signing failed")
			}
			return recoveryWriteFile(filepath.Join(stage, "prepared-metadata"), []byte("local signature"))
		}
		_, err := restoreRecoveryArtifactPrepared(t.Context(), artifactDir, target, nil, a.Digest, prepare)
		if !called || (err != nil) != fail {
			t.Fatalf("prepare result: called=%v, err=%v, fail=%v", called, err, fail)
		}
		if fail {
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed prepare activated root: %v", err)
			}
		} else if data, err := os.ReadFile(filepath.Join(target, "prepared-metadata")); err != nil || string(data) != "local signature" {
			t.Fatalf("prepared metadata missing: %s, %v", data, err)
		}
	}
}
