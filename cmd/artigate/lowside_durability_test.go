package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWriteBundleArtifactsArchivesBeforeFolderTransfer(t *testing.T) {
	t.Parallel()
	ls, priv := newFakeLowServer(t)
	id := bundleIDFor(streamGo, 1)
	src, files, manifest := covM2BuildBundle(t, 1, []moduleSpec{{"example.com/folder", "v1.0.0"}})
	landing := t.TempDir()
	archive := ls.bundleArchiveDir()
	durable := make(map[string]bool)
	var delivered []string
	carrier := func(dir string) error {
		if err := fsyncDir(dir); err != nil {
			return err
		}
		if bundleCompleteInDir(archive, id) {
			durable[dir] = true
		}
		if dir != ls.cfg.ExportDir {
			return nil
		}
		for parent := archive; ; parent = filepath.Dir(parent) {
			if !durable[parent] {
				t.Fatalf("outbound file published before archive directory %s was durable", parent)
			}
			if parent == filepath.Dir(parent) {
				break
			}
		}
		// A folder carrier may remove each final file before the next one is
		// published. Export and replay must depend only on the archive now.
		for _, suffix := range bundleSuffixes() {
			name := id + suffix
			out := filepath.Join(ls.cfg.ExportDir, name)
			if fileExists(out) {
				if err := os.Rename(out, filepath.Join(landing, name)); err != nil {
					return err
				}
				delivered = append(delivered, name)
			}
		}
		return nil
	}
	if err := ls.writeBundleArtifactsWithSync(t.Context(), id, src, manifest, files, carrier); err != nil {
		t.Fatal(err)
	}
	assertBundleSigned(t, archive, id, priv.Public().(ed25519.PublicKey))
	assertBundleSigned(t, landing, id, priv.Public().(ed25519.PublicKey))
	wantOrder := []string{id + ".tar.gz", id + ".manifest.json", id + ".manifest.json.sig"}
	if !slices.Equal(delivered, wantOrder) {
		t.Fatalf("folder delivery order = %v, want %v", delivered, wantOrder)
	}
	for _, name := range wantOrder {
		if err := os.Remove(filepath.Join(landing, name)); err != nil {
			t.Fatal(err)
		}
	}
	clear(durable)
	delivered = nil
	if _, err := ls.exportSequenceWithSync(streamGo, 1, carrier); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(delivered, wantOrder) {
		t.Fatalf("folder replay order = %v, want %v", delivered, wantOrder)
	}
	for _, name := range wantOrder {
		archived, err := os.ReadFile(filepath.Join(archive, name))
		if err != nil {
			t.Fatal(err)
		}
		landed, err := os.ReadFile(filepath.Join(landing, name))
		if err != nil || !bytes.Equal(archived, landed) {
			t.Fatalf("folder replay of %s differs from the retained archive: %v", name, err)
		}
		if fileExists(filepath.Join(ls.cfg.ExportDir, name)) {
			t.Fatalf("folder carrier did not remove %s", name)
		}
	}
}

func TestWriteBundleArtifactsArchiveSyncFailurePublishesNothing(t *testing.T) {
	for _, suffix := range bundleSuffixes() {
		t.Run(suffix, func(t *testing.T) {
			t.Parallel()
			ls, _ := newFakeLowServer(t)
			id := bundleIDFor(streamGo, 1)
			src, files, manifest := covM2BuildBundle(t, 1, []moduleSpec{{"example.com/failed", "v1.0.0"}})
			syncErr := errors.New("archive sync failed")
			err := ls.writeBundleArtifactsWithSync(t.Context(), id, src, manifest, files, func(dir string) error {
				if dir == ls.bundleArchiveDir() && fileExists(filepath.Join(dir, id+suffix)) {
					return syncErr
				}
				return fsyncDir(dir)
			})
			if !errors.Is(err, syncErr) {
				t.Fatalf("write = %v, want archive sync failure", err)
			}
			if bundleArtifactsExistInDir(ls.cfg.ExportDir, id) {
				t.Fatal("failed archive exposed outbound artifacts to the folder carrier")
			}
			if suffix == ".manifest.json.sig" {
				// A complete archive remains replayable even when its failed
				// sync prevented the fresh export from publishing any spool files.
				if _, err := ls.ExportSequence(streamGo, 1); err != nil {
					t.Fatalf("re-export complete archive after repair: %v", err)
				}
			}
		})
	}
}

func TestArchiveBundleDirectorySyncFailureRetainsSpool(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	spool := t.TempDir()
	ls := &LowServer{cfg: LowConfig{Root: root, ExportDir: spool}}
	id := bundleIDFor(streamGo, 1)
	for _, suffix := range bundleSuffixes() {
		writeFile(t, filepath.Join(spool, id+suffix), []byte(suffix))
	}
	syncErr := errors.New("archive directory sync failed")
	for attempt := 0; attempt < 2; attempt++ {
		err := ls.archiveBundleWithSync(id, func(dir string) error {
			if dir == root {
				return syncErr
			}
			return fsyncDir(dir)
		})
		if !errors.Is(err, syncErr) {
			t.Fatalf("attempt %d = %v, want sync error", attempt, err)
		}
		if !bundleCompleteInDir(spool, id) {
			t.Fatal("failed archive removed the spool copy")
		}
	}
	if err := ls.archiveBundle(id); err != nil {
		t.Fatal(err)
	}
	// The archive is now independently usable after transfer clears the spool.
	for _, suffix := range bundleSuffixes() {
		if fileExists(filepath.Join(ls.bundleArchiveDir(), id+suffix+".tmp")) {
			t.Fatalf("archive retry left a temporary hardlink for %s", suffix)
		}
		if err := os.Remove(filepath.Join(spool, id+suffix)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(ls.bundleArchiveDir(), id+suffix))
		if err != nil || string(got) != suffix {
			t.Fatalf("archived %s = %q, %v", suffix, got, err)
		}
	}
}

func TestExportSequenceRecoversArchiveSyncFailure(t *testing.T) {
	cases := []struct {
		name       string
		suffix     string
		parentSync bool
	}{
		{name: "first artifact", suffix: ".tar.gz"},
		{name: "signature", suffix: ".manifest.json.sig"},
		{name: "signature ancestor", suffix: ".manifest.json.sig", parentSync: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ls, priv := newFakeLowServer(t)
			id := bundleIDFor(streamGo, 1)
			writeSignedBundle(t, ls.cfg.ExportDir, priv, 1, 0, []moduleSpec{{"example.com/retry", "v1.0.0"}})
			original := make(map[string][]byte)
			for _, suffix := range bundleSuffixes() {
				name := id + suffix
				b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
				if err != nil {
					t.Fatal(err)
				}
				original[name] = b
			}
			archive := ls.bundleArchiveDir()
			failDir := archive
			if tc.parentSync {
				failDir = ls.cfg.Root
			}
			syncErr := errors.New("archive directory sync failed")
			err := ls.archiveBundleWithSync(id, func(dir string) error {
				if dir == failDir && fileExists(filepath.Join(archive, id+tc.suffix)) {
					return syncErr
				}
				return fsyncDir(dir)
			})
			if !errors.Is(err, syncErr) {
				t.Fatalf("archive = %v, want sync failure", err)
			}
			if complete := bundleCompleteInDir(archive, id); complete != (tc.suffix == ".manifest.json.sig") {
				t.Fatalf("unexpected archive completeness after failure: %v", complete)
			}

			receiver := &diodeReceiver{}
			diode := httptest.NewServer(receiver)
			t.Cleanup(diode.Close)
			ls.cfg.DiodeURL = diode.URL
			// Exercise the same locked re-export path as ExportSequence. A
			// persistent failure must neither send nor discard the retained spool.
			_, err = ls.exportSequenceWithSync(streamGo, 1, func(dir string) error {
				if dir == failDir {
					return syncErr
				}
				return fsyncDir(dir)
			})
			if !errors.Is(err, syncErr) {
				t.Fatalf("re-export = %v, want sync failure", err)
			}
			for name, want := range original {
				if got, _ := receiver.file(name); got != nil {
					t.Fatalf("transferred %s before the archive was durable", name)
				}
				got, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("failed re-export changed the retained spool file %s: %v", name, err)
				}
			}

			// Storage is repaired. The public operation recovers the original
			// signed bytes, sends them, and leaves a complete persistent archive.
			res, err := ls.ExportSequence(streamGo, 1)
			if err != nil || res.DiodeError != "" || res.BundleID != id {
				t.Fatalf("re-export after repair = %+v, %v", res, err)
			}
			for name, want := range original {
				got, err := os.ReadFile(filepath.Join(archive, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("recovered archive file %s differs from the signed original: %v", name, err)
				}
				if got, _ := receiver.file(name); !bytes.Equal(got, want) {
					t.Fatalf("transferred %s differs from the signed original", name)
				}
				if fileExists(filepath.Join(ls.cfg.ExportDir, name)) {
					t.Fatalf("successful transfer did not clear %s from the spool", name)
				}
			}
		})
	}
}
