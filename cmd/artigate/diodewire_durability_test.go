package main

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDiodeLandingDirectorySyncFailure(t *testing.T) {
	t.Parallel()
	asm := newDiodeAssembler(filepath.Join(t.TempDir(), "new", "landing"), validBundleFileName, nil)
	const name = "go-bundle-000001.tar.gz"
	content := []byte("verified transfer bytes")
	digest := sha256.Sum256(content)
	transfer := covLangTransfer(t, asm, 1, name, content, digest, int64(len(content)))
	syncErr := errors.New("UDP landing directory sync failed")
	err := asm.landFileWithSync(transfer, func(dir string) error {
		if dir == filepath.Dir(asm.dir) {
			return syncErr
		}
		return fsyncDir(dir)
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("landFile = %v, want sync error", err)
	}
	// A retransmission safely replaces the file left by the failed sync.
	transfer = covLangTransfer(t, asm, 2, name, content, digest, int64(len(content)))
	var synced []string
	if err := asm.landFileWithSync(transfer, func(dir string) error {
		synced = append(synced, dir)
		return fsyncDir(dir)
	}); err != nil {
		t.Fatal(err)
	}
	assertSyncedParents(t, synced, asm.dir)
	got, err := os.ReadFile(filepath.Join(asm.dir, name))
	if err != nil || string(got) != string(content) {
		t.Fatalf("landed content = %q, %v", got, err)
	}
}
