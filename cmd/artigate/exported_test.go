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
