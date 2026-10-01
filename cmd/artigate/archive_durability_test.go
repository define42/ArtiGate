package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicPublicationDirectorySyncFailure(t *testing.T) {
	cases := []struct {
		name  string
		write func(t *testing.T, src, dst string, syncDir func(string) error) error
	}{
		{name: "state and metadata", write: func(_ *testing.T, _, dst string, syncDir func(string) error) error {
			return writeBytesAtomicWithSync(dst, []byte("payload"), 0o644, syncDir)
		}},
		{name: "copy fallback", write: func(_ *testing.T, src, dst string, syncDir func(string) error) error {
			return copyFileAtomicWithSync(src, dst, 0o644, syncDir)
		}},
		{name: "archive hardlink", write: func(_ *testing.T, src, dst string, syncDir func(string) error) error {
			return linkOrCopyFileWithSync(src, dst, syncDir)
		}},
		{name: "tar archive", write: func(t *testing.T, src, dst string, syncDir func(string) error) error {
			mf, err := hashManifestFile(src, filepath.Base(src))
			if err != nil {
				t.Fatal(err)
			}
			return createTarGzAtomicWithSync(t.Context(), dst, filepath.Dir(src), []ManifestFile{mf}, syncDir)
		}},
		{name: "HTTP receiver", write: func(_ *testing.T, _, dst string, syncDir func(string) error) error {
			_, err := writeStreamAtomicLimitWithSync(dst, bytes.NewBufferString("payload"), 100, syncDir)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			src := filepath.Join(root, "source")
			writeFile(t, src, []byte("payload"))
			dst := filepath.Join(root, "new", "nested", "destination")
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			syncErr := errors.New("directory sync failed")
			fail := func(dir string) error {
				if !fileExists(dst) {
					t.Fatal("directory synced before publishing destination")
				}
				if dir == root {
					return syncErr
				}
				return fsyncDir(dir)
			}
			if err := tc.write(t, src, dst, fail); !errors.Is(err, syncErr) {
				t.Fatalf("write = %v, want directory sync error", err)
			}
			// Rename succeeded, but this must still be an error to the caller.
			// Retrying must persist existing ancestors as well as the leaf.
			var synced []string
			if err := tc.write(t, src, dst, func(dir string) error {
				synced = append(synced, dir)
				return fsyncDir(dir)
			}); err != nil {
				t.Fatal(err)
			}
			assertSyncedParents(t, synced, filepath.Dir(dst))
		})
	}
}

func TestSyncDirectoriesDeduplicatesAncestors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	left := filepath.Join(root, "new", "left")
	right := filepath.Join(root, "new", "right")
	var synced []string
	if err := syncDirectories(func(dir string) error {
		synced = append(synced, dir)
		return nil
	}, left, right, left); err != nil {
		t.Fatal(err)
	}
	assertSyncedParents(t, synced, left)
	assertSyncedParents(t, synced, right)
}

func assertSyncedParents(t *testing.T, synced []string, leaf string) {
	t.Helper()
	positions := make(map[string]int, len(synced))
	for i, dir := range synced {
		if _, exists := positions[dir]; exists {
			t.Fatalf("directory %s synced more than once: %v", dir, synced)
		}
		positions[dir] = i
	}
	last := -1
	for dir := leaf; ; dir = filepath.Dir(dir) {
		position, ok := positions[dir]
		if !ok || position <= last {
			t.Fatalf("directory %s must be synced after its children: %v", dir, synced)
		}
		last = position
		if dir == filepath.Dir(dir) {
			break
		}
	}
}

func TestFsyncDirReportsOpenFailure(t *testing.T) {
	t.Parallel()
	if err := fsyncDir(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fsyncDir = %v, want missing directory error", err)
	}
}
