package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImportDirectorySyncFailureKeepsSequenceRetryable(t *testing.T) {
	for _, failure := range []string{"artifact directory", "new ancestor"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			pub, priv := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			id := bundleIDFor(streamGo, 1)
			writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"example.com/new/module", "v1.0.0"}})
			before, err := os.ReadFile(hs.statePath)
			if err != nil {
				t.Fatal(err)
			}
			artifactDir := filepath.Join(hs.goModuleDir(), "example.com", "new", "module", "@v")
			failDir := artifactDir
			if failure == "new ancestor" {
				failDir = filepath.Join(hs.goModuleDir(), "example.com")
			}
			syncErr := errors.New("artifact directory sync failed")
			fail := func(dir string) error {
				if dir == failDir {
					return syncErr
				}
				return fsyncDir(dir)
			}
			// The second attempt sees matching artifacts left by the first one.
			// It must retry the failed directory sync before saving any progress.
			for attempt := 0; attempt < 2; attempt++ {
				_, err := hs.importBundleFromDirLockedWithSync(hs.cfg.Landing, streamGo, id, 1, fail)
				if !errors.Is(err, syncErr) {
					t.Fatalf("attempt %d = %v, want sync error", attempt, err)
				}
				if hs.importedSequence(streamGo) != 0 || !bundleCompleteInDir(hs.cfg.Landing, id) {
					t.Fatal("failed directory sync advanced sequence or consumed the bundle")
				}
				if hs.isComplete("example.com/new/module", "v1.0.0") {
					t.Fatal("complete marker published before artifact directories were durable")
				}
				after, err := os.ReadFile(hs.statePath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("durable import state changed on sync failure: %v", err)
				}
			}
			var synced []string
			_, err = hs.importBundleFromDirLockedWithSync(hs.cfg.Landing, streamGo, id, 1, func(dir string) error {
				synced = append(synced, dir)
				return fsyncDir(dir)
			})
			if err != nil {
				t.Fatal(err)
			}
			assertSyncedParents(t, synced, artifactDir)
			if hs.importedSequence(streamGo) != 1 || !hs.isComplete("example.com/new/module", "v1.0.0") {
				t.Fatal("retry did not publish the module and advance its sequence")
			}
		})
	}
}
