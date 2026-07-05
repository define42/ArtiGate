package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// newBareLowServer makes a low server with only a working root and export dir —
// enough to exercise the exported-content index directly, no fetch tools.
func newBareLowServer(t *testing.T) *LowServer {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls
}

func mf(path, hashChar string) ManifestFile {
	return ManifestFile{Path: path, SHA256: strings.Repeat(hashChar, 64), Size: 1}
}

// TestExportedContentIndex covers the Tier-1 dedup primitives: the empty/unseen
// cases never skip, a recorded set is reported forwarded, one new file defeats
// the all-or-nothing skip, the index is per-stream, and it persists as a set.
func TestExportedContentIndex(t *testing.T) {
	ls := newBareLowServer(t)
	files := []ManifestFile{mf("npm/packages/a.tgz", "a"), mf("npm/packages/b.tgz", "b")}

	if ls.allForwarded(streamNpm, nil) {
		t.Error("an empty file set must never skip")
	}
	if ls.allForwarded(streamNpm, files) {
		t.Error("nothing recorded yet, must not skip")
	}

	ls.recordForwarded(streamNpm, files)
	if !ls.allForwarded(streamNpm, files) {
		t.Error("recorded files should all be forwarded")
	}

	// Tier-1 is all-or-nothing: one new file among forwarded ones defeats the skip.
	withNew := append([]ManifestFile{mf("npm/packages/c.tgz", "c")}, files...)
	if ls.allForwarded(streamNpm, withNew) {
		t.Error("a new file must prevent the skip")
	}

	// The index is per-stream: the same hashes on another stream are unseen.
	if ls.allForwarded(streamPython, files) {
		t.Error("the index must be per-stream")
	}

	// It persists as a set (recording the same files again is a no-op).
	ls.recordForwarded(streamNpm, files)
	n, err := ls.exported.Count(streamNpm)
	if err != nil || n != 2 {
		t.Errorf("index should hold exactly 2 hashes, got %d (err %v)", n, err)
	}
}

// TestExportedContentIndexFailsSafe proves a store error never suppresses a
// collect: allForwarded returns false (export anyway) rather than skipping.
func TestExportedContentIndexFailsSafe(t *testing.T) {
	ls := newBareLowServer(t)
	files := []ManifestFile{mf("npm/packages/a.tgz", "a")}
	ls.recordForwarded(streamNpm, files)
	if !ls.allForwarded(streamNpm, files) {
		t.Fatal("precondition: file should be recorded")
	}
	// Close the store out from under the collector: every query now errors.
	if err := ls.exported.Close(); err != nil {
		t.Fatal(err)
	}
	if ls.allForwarded(streamNpm, files) {
		t.Error("a store error must fail safe (export, not skip)")
	}
}

// TestNpmCollectSkipsUnchanged drives the whole collector: a second identical
// collect produces no bundle and burns no sequence number, while the first
// still exported normally. (The complementary path — new content still exports
// and advances the sequence — is covered by TestLowServerExportSkipsUnfetchableModule,
// whose second collect adds a fresh module through the same exportIfNew gate.)
func TestNpmCollectSkipsUnchanged(t *testing.T) {
	fx := newNpmFixture(t)

	res1, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err != nil {
		t.Fatalf("first CollectNpm: %v", err)
	}
	if res1.Skipped || res1.BundleID != "npm-bundle-000001" || res1.ExportedModules != 2 {
		t.Fatalf("first collect should export a bundle, got %+v", res1)
	}

	res2, err := fx.ls.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err != nil {
		t.Fatalf("second CollectNpm: %v", err)
	}
	if !res2.Skipped || res2.BundleID != "" {
		t.Fatalf("second identical collect should skip with no bundle, got %+v", res2)
	}

	// No sequence burned and no second bundle written to the diode.
	if seq := fx.ls.peekSequence(streamNpm); seq != 2 {
		t.Errorf("next sequence = %d, want 2 (a skip must not burn a number)", seq)
	}
	if bundleCompleteInDir(fx.ls.cfg.ExportDir, "npm-bundle-000002") {
		t.Error("a skipped collect must not write a second bundle")
	}
}
