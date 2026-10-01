package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkpointTestRoot(t *testing.T, streams map[string]int64) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	checkpointTestState(t, root, streams)
	return root
}

func checkpointTestState(t *testing.T, root string, streams map[string]int64) {
	t.Helper()
	next := make(map[string]int64, len(streams))
	for stream, seq := range streams {
		next[stream] = seq + 1
	}
	if err := writeJSONAtomic(filepath.Join(root, "low-state.json"), LowState{Sequences: next}, stateFileMode); err != nil {
		t.Fatal(err)
	}
}

func checkpointTestManifest(t *testing.T, archive, stream string, seq int64) BundleManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(archive, bundleIDFor(stream, seq)+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func checkpointTestWrite(t *testing.T, archive, source string, priv ed25519.PrivateKey, manifest BundleManifest) {
	t.Helper()
	manifest.Type = manifestType
	manifest.Format = manifestFormatCurrent
	manifest.BundleID = bundleIDFor(manifest.Stream, manifest.Sequence)
	manifest.PreviousSequence = manifest.Sequence - 1
	data, err := marshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := createTarGzAtomic(t.Context(), filepath.Join(archive, manifest.BundleID+".tar.gz"), source, deliveredFiles(manifest.Files)); err != nil {
		t.Fatal(err)
	}
	checkpointTestSign(t, archive, priv, manifest.BundleID, data)
}

func checkpointTestSign(t *testing.T, archive string, priv ed25519.PrivateKey, id string, data []byte) {
	t.Helper()
	writeFile(t, filepath.Join(archive, id+".manifest.json"), data)
	sig := ed25519.Sign(priv, data)
	writeFile(t, filepath.Join(archive, id+".manifest.json.sig"), []byte(base64.StdEncoding.EncodeToString(sig)))
}

func TestRecoveryCheckpointPreservesMetadataAndNextPrior(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	root := checkpointTestRoot(t, map[string]int64{streamGo: 1, streamNpm: 1})
	archive := filepath.Join(root, "bundles")
	writeSignedBundle(t, archive, priv, 1, 0, []moduleSpec{{"example.com/checkpoint", "v1.0.0"}})
	writeSignedNpmBundle(t, archive, priv, 1, map[string][]byte{
		"checkpoint-package@@1.0.0": makeNpmTgz(t, "package", "checkpoint-package", "1.0.0"),
	})
	npm := checkpointTestManifest(t, archive, streamNpm, 1)
	npm.Npm.DistTags = map[string]map[string]string{"checkpoint-package": {"stable": "1.0.0"}}
	data, err := marshalManifest(npm)
	if err != nil {
		t.Fatal(err)
	}
	checkpointTestSign(t, archive, priv, npm.BundleID, data)
	writeFile(t, filepath.Join(root, "private.ed25519"), []byte("must never enter checkpoint"))
	output := filepath.Join(t.TempDir(), "checkpoint")
	artifact, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: root, Output: output, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Manifest.Files {
		if strings.Contains(file.Path, "private") {
			t.Fatalf("checkpoint contains secret %s", file.Path)
		}
	}
	hs, err := newCheckpointReceiver(t.Context(), t.TempDir(), output, artifact.Digest, pub)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	hs.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/checkpoint-package", nil))
	var packument struct {
		Tags map[string]string `json:"dist-tags"`
	}
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &packument)
	if rec.Code != http.StatusOK || decodeErr != nil || packument.Tags["stable"] != "1.0.0" {
		t.Fatalf("restored npm metadata: status %d: %s", rec.Code, rec.Body.String())
	}
	prior := checkpointTestManifest(t, archive, streamGo, 1)
	prior.Stream, prior.Sequence = streamGo, 2
	for i := range prior.Files {
		prior.Files[i].Prior = true
	}
	checkpointTestWrite(t, archive, t.TempDir(), priv, prior)
	if err := replayCheckpointArchives(t.Context(), hs, archive, map[string]int64{streamGo: 2, streamNpm: 1}); err != nil {
		t.Fatalf("import next delta after restore: %v", err)
	}
	if !hs.isComplete("example.com/checkpoint", "v1.0.0") {
		t.Fatal("restored Go module is not complete")
	}
	if !bundleCompleteInDir(archive, bundleIDFor(streamGo, 1)) {
		t.Fatal("checkpoint consumed original archive")
	}
}

func TestRecoveryCheckpointBaseAndMutableTail(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	root := checkpointTestRoot(t, map[string]int64{streamUploads: 1})
	archive := filepath.Join(root, "bundles")
	checkpointTestUpload(t, archive, priv, 1, "old snapshot")
	base := filepath.Join(t.TempDir(), "base")
	first, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: root, Output: base, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range bundleSuffixes() {
		if err := os.Remove(filepath.Join(archive, bundleIDFor(streamUploads, 1)+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	checkpointTestUpload(t, archive, priv, 2, "new snapshot")
	checkpointTestState(t, root, map[string]int64{streamUploads: 2})
	output := filepath.Join(t.TempDir(), "next")
	second, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{
		Root: root, Output: output, Base: base, BaseDigest: first.Digest, PrivateKey: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	hs, err := newCheckpointReceiver(t.Context(), t.TempDir(), output, second.Digest, pub)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(hs.downloadDir, "uploads", "project", "state.txt"))
	if err != nil || string(body) != "new snapshot" {
		t.Fatalf("restored mutable file = %q: %v", body, err)
	}
	if err := replayRecoveryCheckpointTail(t.Context(), base, pub, archive, map[string]int64{streamUploads: 2}); err != nil {
		t.Fatalf("base restore and tail drill: %v", err)
	}
}

func checkpointTestUpload(t *testing.T, archive string, priv ed25519.PrivateKey, seq int64, content string) {
	t.Helper()
	source := t.TempDir()
	rel := "uploads/project/state.txt"
	abs := filepath.Join(source, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, []byte(content))
	file, err := hashManifestFile(abs, rel)
	if err != nil {
		t.Fatal(err)
	}
	checkpointTestWrite(t, archive, source, priv, BundleManifest{
		Stream: streamUploads, Sequence: seq, Files: []ManifestFile{file},
		Uploads: &UploadsManifest{Files: []UploadFile{{
			Folder: "project", Name: "state.txt", Path: rel, SHA256: file.SHA256, Size: file.Size,
		}}},
	})
}

func TestRecoveryCheckpointPreservesUnpublishedPart(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	root := checkpointTestRoot(t, map[string]int64{streamGo: 1})
	archive := filepath.Join(root, "bundles")
	source := t.TempDir()
	mod, files := buildModuleFiles(t, source, moduleSpec{"example.com/parts", "v1.0.0"})
	checkpointTestWrite(t, archive, source, priv, BundleManifest{
		Stream: streamGo, Sequence: 1, Files: files, Part: &BundlePartInfo{Index: 1, Count: 2},
	})
	output := filepath.Join(t.TempDir(), "checkpoint")
	artifact, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: root, Output: output, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	hs, err := newCheckpointReceiver(t.Context(), t.TempDir(), output, artifact.Digest, pub)
	if err != nil {
		t.Fatal(err)
	}
	if hs.isComplete("example.com/parts", "v1.0.0") {
		t.Fatal("content part was published before its final metadata")
	}
	for i := range files {
		files[i].Prior = true
	}
	checkpointTestWrite(t, archive, source, priv, BundleManifest{
		Stream: streamGo, Sequence: 2, Files: files, Modules: []ManifestMod{mod},
	})
	if err := replayCheckpointArchives(t.Context(), hs, archive, map[string]int64{streamGo: 2}); err != nil {
		t.Fatal(err)
	}
	if !hs.isComplete("example.com/parts", "v1.0.0") {
		t.Fatal("final metadata could not publish restored content part")
	}
}

func TestRecoveryCheckpointRejectsIncompleteHistory(t *testing.T) {
	for _, name := range []string{"missing predecessor", "missing archive", "tampered signature", "future manifest", "wrong key"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, priv := newTestKeys(t)
			root := checkpointTestRoot(t, map[string]int64{streamGo: 2})
			archive := filepath.Join(root, "bundles")
			writeSignedBundle(t, archive, priv, 1, 0, []moduleSpec{{"example.com/first", "v1.0.0"}})
			writeSignedBundle(t, archive, priv, 2, 1, []moduleSpec{{"example.com/second", "v1.0.0"}})
			checkpointTestCorrupt(t, archive, priv, name)
			if name == "wrong key" {
				_, priv = newTestKeys(t)
			}
			output := filepath.Join(t.TempDir(), "checkpoint")
			_, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: root, Output: output, PrivateKey: priv})
			if err == nil {
				t.Fatal("checkpoint accepted incomplete or unverifiable history")
			}
			if fileExists(filepath.Join(output, "manifest.json")) {
				t.Fatal("failed replay published a checkpoint")
			}
		})
	}
}

func checkpointTestCorrupt(t *testing.T, archive string, priv ed25519.PrivateKey, name string) {
	t.Helper()
	id := bundleIDFor(streamGo, 1)
	switch name {
	case "missing predecessor":
		for _, suffix := range bundleSuffixes() {
			if err := os.Remove(filepath.Join(archive, id+suffix)); err != nil {
				t.Fatal(err)
			}
		}
	case "missing archive":
		if err := os.Remove(filepath.Join(archive, id+".tar.gz")); err != nil {
			t.Fatal(err)
		}
	case "tampered signature":
		writeFile(t, filepath.Join(archive, id+".manifest.json.sig"), []byte("invalid"))
	case "future manifest":
		manifest := checkpointTestManifest(t, archive, streamGo, 1)
		manifest.Format = manifestFormatCurrent + 1
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		checkpointTestSign(t, archive, priv, id, data)
	}
}

func TestRecoveryCheckpointRestoreRejectsMismatchedState(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	source := t.TempDir()
	if err := writeJSONAtomic(filepath.Join(source, "import-state.json"), HighState{Imported: map[string]int64{streamGo: 1}}, stateFileMode); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "checkpoint")
	artifact, err := writeRecoveryArtifact(t.Context(), source, output, recoveryManifest{
		Kind: "checkpoint", Role: "high", Streams: map[string]int64{streamGo: 2},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "receiver")
	if _, err := restoreRecoveryArtifact(t.Context(), output, target, pub, artifact.Digest); err == nil {
		t.Fatal("restore trusted a cursor that differs from the repository state")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed restore activated target: %v", err)
	}
}

func TestRecoveryCheckpointRejectsOverlapAndCancellation(t *testing.T) {
	for _, name := range []string{"nested output", "symlinked output parent", "cancelled context"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, priv := newTestKeys(t)
			root := checkpointTestRoot(t, nil)
			output := filepath.Join(t.TempDir(), "checkpoint")
			ctx := t.Context()
			switch name {
			case "nested output":
				output = filepath.Join(root, "checkpoint")
			case "symlinked output parent":
				link := filepath.Join(t.TempDir(), "low-root")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(link, "checkpoint")
			case "cancelled context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := createRecoveryCheckpoint(ctx, checkpointOptions{Root: root, Output: output, PrivateKey: priv}); err == nil {
				t.Fatal("checkpoint accepted overlapping output or cancelled work")
			}
		})
	}
}
