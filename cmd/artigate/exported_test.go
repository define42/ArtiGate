package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func assertMetadataChanged(t *testing.T, store *ExportedStore, stream string, metadata []ExportMetadata, want bool) {
	t.Helper()
	if got, err := store.MetadataChanged(stream, metadata); err != nil || got != want {
		t.Fatalf("MetadataChanged(%s, %+v) = %v, %v; want %v", stream, metadata, got, err, want)
	}
}

func TestExportedMetadataLatestValue(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "exported.db")
	store, err := OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	a := ExportMetadata{Key: "container/review/stable", SHA256: strings.Repeat("a", 64)}
	b := ExportMetadata{Key: a.Key, SHA256: strings.Repeat("b", 64)}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{a}, true)
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{a}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{a}, false)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{b}, true)
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{b}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{a}, true)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{b}, false)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{a}, true)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{b}, false)
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{a}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{a}, false)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{b}, true)
}

func TestExportedMetadataIndependentKeysAndStreams(t *testing.T) {
	store, err := OpenExportedStore(filepath.Join(t.TempDir(), "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	v1 := ExportMetadata{Key: "container/review/v1", SHA256: strings.Repeat("a", 64)}
	stable := ExportMetadata{Key: "container/review/stable", SHA256: v1.SHA256}
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{v1}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{v1, stable}, true)
	assertMetadataChanged(t, store, streamNpm, []ExportMetadata{v1}, true)
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{stable}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{v1, stable}, false)
	replaced := ExportMetadata{Key: v1.Key, SHA256: strings.Repeat("b", 64)}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{stable, replaced}, true)
	if err := store.RecordMetadata(streamNpm, []ExportMetadata{replaced}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{v1, stable}, false)
	assertMetadataChanged(t, store, streamNpm, []ExportMetadata{replaced}, false)
	assertMetadataChanged(t, store, streamNpm, []ExportMetadata{v1}, true)
}

func TestExportedMetadataRecordOrder(t *testing.T) {
	store, err := OpenExportedStore(filepath.Join(t.TempDir(), "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	a := ExportMetadata{Key: "container/review/stable", SHA256: strings.Repeat("a", 64)}
	b := ExportMetadata{Key: a.Key, SHA256: strings.Repeat("b", 64)}
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{a, b, a}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{a}, false)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{b}, true)
}

func TestExportedMetadataInvalidationPersists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "exported.db")
	store, err := OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	v1 := ExportMetadata{Key: "container/review/v1", SHA256: strings.Repeat("a", 64)}
	stable := ExportMetadata{Key: "container/review/stable", SHA256: v1.SHA256}
	for _, stream := range []string{streamContainers, streamNpm} {
		if err := store.RecordMetadata(stream, []ExportMetadata{v1, stable}); err != nil {
			t.Fatal(err)
		}
	}
	replacement := ExportMetadata{Key: stable.Key, SHA256: strings.Repeat("b", 64)}
	missing := ExportMetadata{Key: "container/review/missing", SHA256: replacement.SHA256}
	if err := store.InvalidateMetadata(streamContainers, []ExportMetadata{replacement, missing}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{stable}, true)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{replacement}, true)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{v1}, false)
	assertMetadataChanged(t, store, streamNpm, []ExportMetadata{v1, stable}, false)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{stable}, true)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{v1}, false)
	assertMetadataChanged(t, store, streamNpm, []ExportMetadata{v1, stable}, false)
	if err := store.RecordMetadata(streamContainers, []ExportMetadata{replacement}); err != nil {
		t.Fatal(err)
	}
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{replacement}, false)
	assertMetadataChanged(t, store, streamContainers, []ExportMetadata{stable}, true)
}

func TestExportedMetadataClosedStore(t *testing.T) {
	store, err := OpenExportedStore(filepath.Join(t.TempDir(), "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	metadata := []ExportMetadata{{Key: "container/review/stable", SHA256: strings.Repeat("a", 64)}}
	if _, err := store.MetadataChanged(streamContainers, metadata); err == nil {
		t.Error("MetadataChanged on a closed store should fail")
	}
	if err := store.InvalidateMetadata(streamContainers, metadata); err == nil {
		t.Error("InvalidateMetadata on a closed store should fail")
	}
	if err := store.RecordMetadata(streamContainers, metadata); err == nil {
		t.Error("RecordMetadata on a closed store should fail")
	}
	assertMetadataChanged(t, store, streamContainers, nil, false)
	if err := store.InvalidateMetadata(streamContainers, nil); err != nil {
		t.Errorf("InvalidateMetadata(nil) = %v; want nil", err)
	}
	if err := store.RecordMetadata(streamContainers, nil); err != nil {
		t.Errorf("RecordMetadata(nil) = %v; want nil", err)
	}
}

func TestExportedPendingMetadataPersistsExactFiles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "exported.db")
	store, err := OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	files := []ManifestFile{
		{Path: "a", SHA256: strings.Repeat("a", 64)},
		{Path: "a", SHA256: strings.Repeat("b", 64)},
		{Path: "b", SHA256: strings.Repeat("a", 64)},
	}
	for _, stream := range []string{streamNuget, streamNpm} {
		if err := store.MarkPendingMetadata(stream, files); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ClearPendingMetadata(streamNuget, files[:1]); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, file := range files {
		got, err := store.HasPendingMetadata(streamNuget, []ManifestFile{file})
		if err != nil || got != (i != 0) {
			t.Errorf("pending NuGet file %d = %v, %v; want %v", i, got, err, i != 0)
		}
		if got, err := store.HasPendingMetadata(streamNpm, []ManifestFile{file}); err != nil || !got {
			t.Errorf("pending npm file %d = %v, %v; another stream's completion must not clear it", i, got, err)
		}
	}
}

func TestExportedPendingMetadataClosedStore(t *testing.T) {
	store, err := OpenExportedStore(filepath.Join(t.TempDir(), "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	files := []ManifestFile{{Path: "a", SHA256: strings.Repeat("a", 64)}}
	if _, err := store.HasPendingMetadata(streamNuget, files); err == nil {
		t.Error("pending lookup on closed store succeeded")
	}
	if err := store.MarkPendingMetadata(streamNuget, files); err == nil {
		t.Error("pending insertion on closed store succeeded")
	}
	if err := store.ClearPendingMetadata(streamNuget, files); err == nil {
		t.Error("pending clear on closed store succeeded")
	}
	if got, err := store.HasPendingMetadata(streamNuget, nil); got || err != nil {
		t.Errorf("empty lookup = %v, %v", got, err)
	}
	if err := store.MarkPendingMetadata(streamNuget, nil); err != nil {
		t.Errorf("empty insertion = %v", err)
	}
	if err := store.ClearPendingMetadata(streamNuget, nil); err != nil {
		t.Errorf("empty clear = %v", err)
	}
}

func TestExportedPendingMetadataUpgradeRunsOnce(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "exported.db")
	store, err := OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	files := []ManifestFile{mf("packages/a", "a"), mf("packages/b", "b")}
	if err := store.Record(streamNuget, files); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DROP TABLE pending_metadata_files"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if pending, err := store.HasPendingMetadata(streamNuget, []ManifestFile{file}); err != nil || !pending {
			t.Fatalf("upgrade omitted pending metadata for %s: %v, %v", file.Path, pending, err)
		}
	}
	if err := store.ClearPendingMetadata(streamNuget, files[:1]); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenExportedStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, file := range files {
		if pending, err := store.HasPendingMetadata(streamNuget, []ManifestFile{file}); err != nil || pending != (i == 1) {
			t.Fatalf("reopen pending %s: %v, %v; want %v", file.Path, pending, err, i == 1)
		}
	}
}
