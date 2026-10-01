package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSFTPPublishDirectorySyncFailureRetriesCompleteBundle(t *testing.T) {
	t.Parallel()
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	id := bundleIDFor(streamGo, 1)
	for _, suffix := range bundleSuffixes() {
		writeFile(t, filepath.Join(hs.cfg.Landing, "."+id+suffix), []byte(suffix))
	}
	syncErr := errors.New("landing directory sync failed")
	fail := func(dir string) error {
		if dir == hs.cfg.Landing {
			return syncErr
		}
		return fsyncDir(dir)
	}
	if err := hs.publishSFTPBundleWithSync(id, fail); !errors.Is(err, syncErr) {
		t.Fatalf("publish = %v, want sync error", err)
	}
	if !bundleCompleteInDir(hs.cfg.Landing, id) {
		t.Fatal("test requires the failed publication to leave all destination files")
	}
	if present, err := hs.sftpBundlePresentLockedWithSync(id, fail); !present || !errors.Is(err, syncErr) {
		t.Fatalf("retry presence = %v, %v; must retry failed sync", present, err)
	}
	var synced []string
	present, err := hs.sftpBundlePresentLockedWithSync(id, func(dir string) error {
		synced = append(synced, dir)
		return fsyncDir(dir)
	})
	if err != nil || !present {
		t.Fatalf("retry presence = %v, %v", present, err)
	}
	assertSyncedParents(t, synced, hs.cfg.Landing)
}
