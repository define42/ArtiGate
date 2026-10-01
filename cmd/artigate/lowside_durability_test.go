package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
