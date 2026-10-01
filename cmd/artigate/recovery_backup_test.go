package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryBackupHighExcludesSecretsAndKeepsState(t *testing.T) {
	root := recoveryTestSource(t)
	for _, name := range []string{"keys/private.key", "credentials.json", ".artigate.lock", "landing/pending", "tmp/scratch", "config.json"} {
		recoveryWriteTestFile(t, filepath.Join(root, name), []byte("must remain private"))
	}
	index := []byte(`{"projects":{"example":{}}}`)
	recoveryWriteTestFile(t, filepath.Join(root, "python-index.json"), index)
	original, err := os.ReadFile(filepath.Join(root, "import-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a, err := createRecoveryBackup(t.Context(), "high", root, filepath.Join(dir, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restore")
	if _, err := restoreRecoveryArtifact(t.Context(), filepath.Join(dir, "backup"), target, nil, a.Digest); err != nil {
		t.Fatal(err)
	}
	for _, file := range a.Manifest.Files {
		if !recoveryBackupPathAllowed("high", file.Path) {
			t.Fatalf("backup leaked %s", file.Path)
		}
	}
	got, err := os.ReadFile(filepath.Join(target, "python-index.json"))
	if err != nil || !bytes.Equal(got, index) {
		t.Fatalf("python index not preserved: %s, %v", got, err)
	}
	for _, base := range []string{root, target} {
		got, err := os.ReadFile(filepath.Join(base, "import-state.json"))
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("state changed: %s, %v", got, err)
		}
	}
	// A backup must contain independent bytes, not hard links to mutable source
	// content. Mutation after capture cannot alter the archived snapshot.
	recoveryWriteTestFile(t, filepath.Join(root, "cache/download/a/file"), []byte("replaced later"))
	if _, err := verifyRecoveryArtifact(t.Context(), filepath.Join(dir, "backup"), nil, a.Digest); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(target, "cache/download/a/file"))
	if err != nil || string(got) != "first artifact" {
		t.Fatalf("snapshot changed with source: %q, %v", got, err)
	}
}

func TestRecoveryBackupLowPreservesDedupSchedulesAndArchive(t *testing.T) {
	root := t.TempDir()
	exported, err := OpenExportedStore(filepath.Join(root, "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	metadata := ExportMetadata{Key: "container/example/stable", SHA256: strings.Repeat("a", 64)}
	if err := exported.RecordMetadata(streamContainers, []ExportMetadata{metadata}); err != nil {
		t.Fatal(err)
	}
	if err := exported.Close(); err != nil {
		t.Fatal(err)
	}
	watches, err := OpenWatchStore(filepath.Join(root, "watches.db"))
	if err != nil {
		t.Fatal(err)
	}
	watch, err := watches.Create(Watch{Stream: streamPython, Label: "daily dependencies", Spec: `{"requirements":["requests"]}`, IntervalSeconds: 86400, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := watches.Close(); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"sequences":{"go":8,"containers":4}}`)
	recoveryWriteTestFile(t, filepath.Join(root, "low-state.json"), state)
	recoveryWriteTestFile(t, filepath.Join(root, "bundles/go-bundle-000007.complete"), []byte("signed archive marker"))
	recoveryWriteTestFile(t, filepath.Join(root, "recovery-ledger.json"), []byte(`{"format":1,"next_sequences":{"go":8},"pruned_through":{}}`))
	journalPath := recoveryTestWriteJournal(t, root, true)
	recoveryWriteTestFile(t, filepath.Join(root, "containers/discovery.json"), []byte(`{"images":[]}`))
	recoveryWriteTestFile(t, filepath.Join(root, "gopath/pkg/mod/cache/private"), []byte("scratch"))
	recoveryWriteTestFile(t, filepath.Join(root, "keys/signing.key"), []byte("secret"))
	before, err := sha256File(filepath.Join(root, "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a, err := createRecoveryBackup(t.Context(), "low", root, filepath.Join(dir, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := sha256File(filepath.Join(root, "exported.db"))
	if err != nil || before != after {
		t.Fatalf("backup changed source SQLite bytes: %s -> %s, %v", before, after, err)
	}
	if a.Manifest.Streams[streamGo] != 7 || a.Manifest.Streams[streamContainers] != 3 {
		t.Fatalf("unexpected backup frontier: %v", a.Manifest.Streams)
	}
	target := filepath.Join(dir, "restore")
	if _, err := restoreRecoveryArtifact(t.Context(), filepath.Join(dir, "backup"), target, nil, a.Digest); err != nil {
		t.Fatal(err)
	}
	for _, file := range a.Manifest.Files {
		if !recoveryBackupPathAllowed("low", file.Path) {
			t.Fatalf("backup leaked %s", file.Path)
		}
	}
	restored, err := OpenExportedStore(filepath.Join(target, "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	assertMetadataChanged(t, restored, streamContainers, []ExportMetadata{metadata}, false)
	schedules, err := OpenWatchStore(filepath.Join(target, "watches.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer schedules.Close()
	got, err := schedules.Get(watch.ID)
	if err != nil || got.Label != watch.Label || got.Spec != watch.Spec || got.IntervalSeconds != watch.IntervalSeconds {
		t.Fatalf("restored schedule differs: %+v, %v", got, err)
	}
	for _, name := range []string{"low-state.json", "bundles/go-bundle-000007.complete", "recovery-ledger.json", journalPath, "containers/discovery.json"} {
		want, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored %s differs: %v", name, err)
		}
	}
}

func recoveryTestWriteJournal(t *testing.T, root string, complete bool) string {
	t.Helper()
	plan := recoveryRetentionPlan{Format: 1, Root: root, Tips: map[string]int64{streamGo: 7}, Cutoffs: map[string]int64{streamGo: 0}}
	id, err := retentionPlanID(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.ID = id
	data, err := json.Marshal(recoveryRetentionJournal{Format: 1, Plan: plan, Complete: complete})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join("recovery-retention", "plan-"+id+".json")
	recoveryWriteTestFile(t, filepath.Join(root, name), data)
	return name
}

func TestRecoveryBackupRefusesUnfinishedRetention(t *testing.T) {
	root := t.TempDir()
	recoveryWriteTestFile(t, filepath.Join(root, "low-state.json"), []byte(`{"sequences":{"go":8}}`))
	recoveryWriteTestFile(t, filepath.Join(root, "exported.db"), []byte("database"))
	recoveryTestWriteJournal(t, root, false)
	output := filepath.Join(t.TempDir(), "backup")
	_, err := createRecoveryBackup(t.Context(), "low", root, output)
	if err == nil || !strings.Contains(err.Error(), "unfinished") {
		t.Fatalf("unfinished retention was not refused: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup published unfinished retention: %v", err)
	}
}

func TestRecoveryBackupRefusesMissingStateAndSymlinks(t *testing.T) {
	for _, role := range []string{"low", "high"} {
		t.Run(role, func(t *testing.T) {
			if _, err := createRecoveryBackup(t.Context(), role, t.TempDir(), filepath.Join(t.TempDir(), "backup")); err == nil {
				t.Fatal("backup accepted missing sequence state")
			}
		})
	}
	root := recoveryTestSource(t)
	if err := os.Symlink(filepath.Join(t.TempDir(), "secret"), filepath.Join(root, "cache/download/leak")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := createRecoveryBackup(t.Context(), "high", root, dir); err == nil {
		t.Fatal("backup followed source symlink")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed backup published directory: %v", err)
	}
}

func TestRecoveryBackupPreservesSQLiteSidecars(t *testing.T) {
	root := t.TempDir()
	recoveryWriteTestFile(t, filepath.Join(root, "low-state.json"), []byte(`{"sequences":{"go":2}}`))
	for _, name := range []string{"exported.db", "exported.db-wal", "exported.db-journal"} {
		recoveryWriteTestFile(t, filepath.Join(root, name), []byte(name))
	}
	recoveryWriteTestFile(t, filepath.Join(root, "exported.db-shm"), []byte("transient shared memory"))
	dir := t.TempDir()
	a, err := createRecoveryBackup(t.Context(), "low", root, filepath.Join(dir, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restore")
	if _, err := restoreRecoveryArtifact(t.Context(), filepath.Join(dir, "backup"), target, nil, a.Digest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exported.db", "exported.db-wal", "exported.db-journal"} {
		got, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || string(got) != name {
			t.Fatalf("SQLite recovery file %s was lost: %q, %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "exported.db-shm")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copied transient shared memory: %v", err)
	}
}

func TestRecoveryBackupRecoversCommittedWALAfterCrash(t *testing.T) {
	root := t.TempDir()
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRecoveryBackupWALChild$", "-test.count=1")
	child.Env = append(os.Environ(), "ARTIGATE_RECOVERY_WAL_TEST_ROOT="+root)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("create stopped SQLite fixture: %s: %v", output, err)
	}
	wal := filepath.Join(root, "exported.db-wal")
	if info, err := os.Stat(wal); err != nil || info.Size() == 0 {
		t.Fatalf("fixture must leave committed data in WAL: %v, %v", info, err)
	}
	before, err := sha256File(wal)
	if err != nil {
		t.Fatal(err)
	}
	recoveryWriteTestFile(t, filepath.Join(root, "low-state.json"), []byte(`{"sequences":{"containers":2}}`))
	dir := t.TempDir()
	a, err := createRecoveryBackup(t.Context(), "low", root, filepath.Join(dir, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := sha256File(wal)
	if err != nil || before != after {
		t.Fatalf("backup changed source WAL: %s -> %s, %v", before, after, err)
	}
	target := filepath.Join(dir, "restore")
	if _, err := restoreRecoveryArtifact(t.Context(), filepath.Join(dir, "backup"), target, nil, a.Digest); err != nil {
		t.Fatal(err)
	}
	db, err := OpenExportedStore(filepath.Join(target, "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	metadata := ExportMetadata{Key: "container/crash/stable", SHA256: strings.Repeat("b", 64)}
	assertMetadataChanged(t, db, streamContainers, []ExportMetadata{metadata}, false)
}

func TestRecoveryBackupWALChild(t *testing.T) {
	root := os.Getenv("ARTIGATE_RECOVERY_WAL_TEST_ROOT")
	if root == "" {
		return
	}
	db, err := OpenExportedStore(filepath.Join(root, "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	metadata := ExportMetadata{Key: "container/crash/stable", SHA256: strings.Repeat("b", 64)}
	if err := db.RecordMetadata(streamContainers, []ExportMetadata{metadata}); err != nil {
		t.Fatal(err)
	}
	// Emulate process death without SQLite Close/checkpoint. The parent waits
	// for process exit before copying, so the backup source is truly stopped.
	os.Exit(0)
}
