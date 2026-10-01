package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestMoveBundleDirectorySyncFailureRetriesMovedFiles(t *testing.T) {
	t.Parallel()
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "quarantine")
	id := bundleIDFor(streamGo, 2)
	for _, suffix := range bundleSuffixes() {
		writeFile(t, filepath.Join(src, id+suffix), []byte(suffix))
	}
	syncErr := errors.New("quarantine directory sync failed")
	// Each interrupted move may leave another artifact at its destination.
	// Once no source files remain, retry must still perform the failed sync.
	for attempt := 0; attempt <= len(bundleSuffixes()); attempt++ {
		err := moveBundleFilesWithSync(src, dst, id, func(dir string) error {
			if dir == dst {
				return syncErr
			}
			return fsyncDir(dir)
		})
		if !errors.Is(err, syncErr) {
			t.Fatalf("attempt %d = %v, want sync error", attempt, err)
		}
	}
	if !bundleCompleteInDir(dst, id) {
		t.Fatal("moved bundle missing from quarantine")
	}
	var synced []string
	if err := moveBundleFilesWithSync(src, dst, id, func(dir string) error {
		synced = append(synced, dir)
		return fsyncDir(dir)
	}); err != nil {
		t.Fatal(err)
	}
	assertSyncedParents(t, synced, dst)
}
