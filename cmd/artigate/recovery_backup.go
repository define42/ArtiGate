package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func recoveryHighBackupPaths() []string {
	return []string{"cache/download", "import-state.json", "python-index.json"}
}

func recoveryLowBackupPaths() []string {
	return []string{
		"bundles", "low-state.json", "exported.db", "exported.db-wal", "exported.db-journal",
		"watches.db", "watches.db-wal", "watches.db-journal", "containers/discovery.json",
		"recovery-ledger.json", "recovery-retention",
	}
}

// createRecoveryBackup captures only data required to recover the chosen role.
// The caller holds the exclusive root lock and has stopped the corresponding
// process. SQLite WAL and rollback journals left by a crash travel with their
// databases; copying never opens or changes the source databases. Runtime
// configuration and credentials must be backed up separately.
func createRecoveryBackup(ctx context.Context, role, root, outputDir string) (recoveryArtifact, error) {
	var result recoveryArtifact
	if role != "low" && role != "high" {
		return result, errors.New("backup role must be low or high")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := recoveryCheckDirectory(root); err != nil {
		return result, err
	}
	if err := recoveryCheckDirectory(filepath.Dir(outputDir)); err != nil {
		return result, err
	}
	if err := recoverySeparatePaths(root, outputDir); err != nil {
		return result, err
	}
	if err := validateRecoveryBackupRoot(root, role); err != nil {
		return result, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(outputDir), ".artigate-backup-source-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(stage)
	paths := recoveryHighBackupPaths()
	if role == "low" {
		paths = recoveryLowBackupPaths()
	}
	if err := copyRecoveryPaths(ctx, root, stage, paths); err != nil {
		return result, err
	}
	streams, err := recoveryBackupStreams(stage, role)
	if err != nil {
		return result, err
	}
	return writeRecoveryArtifact(ctx, stage, outputDir, recoveryManifest{Kind: "backup", Role: role, Streams: streams}, nil)
}

// copyRecoveryPaths creates independent copies, never hard links. Sources are
// permitted to be absent, but callers must validate mandatory state afterward.
// Symlinks and special files anywhere inside a selected path are errors.
func copyRecoveryPaths(ctx context.Context, sourceRoot, stagingRoot string, paths []string) error {
	if err := recoveryPrepareCopyRoots(sourceRoot, stagingRoot); err != nil {
		return err
	}
	root, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	copier := recoveryCopier{source: sourceRoot, destination: stagingRoot, root: root}
	for _, selected := range paths {
		if err := copier.copySelection(ctx, selected); err != nil {
			return err
		}
	}
	return nil
}

func recoveryPrepareCopyRoots(sourceRoot, stagingRoot string) error {
	if err := recoverySeparatePaths(sourceRoot, stagingRoot); err != nil {
		return err
	}
	for _, directory := range []string{sourceRoot, filepath.Dir(stagingRoot)} {
		if err := recoveryCheckDirectory(directory); err != nil {
			return err
		}
	}
	if err := os.Mkdir(stagingRoot, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return recoveryCheckDirectory(stagingRoot)
}

type recoveryCopier struct {
	source      string
	destination string
	root        *os.Root
	files       int
	bytes       int64
}

func (c *recoveryCopier) copySelection(ctx context.Context, selected string) error {
	if err := recoveryValidatePath(selected); err != nil {
		return err
	}
	abs := filepath.Join(c.source, filepath.FromSlash(selected))
	if _, err := os.Lstat(abs); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := recoveryCheckDirectory(filepath.Dir(abs)); err != nil {
		return err
	}
	return filepath.WalkDir(abs, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return c.copyEntry(ctx, name, entry)
	})
}

func (c *recoveryCopier) copyEntry(ctx context.Context, name string, entry fs.DirEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(c.source, name)
	if err != nil {
		return err
	}
	destination := filepath.Join(c.destination, rel)
	if info.IsDir() {
		return os.MkdirAll(destination, 0o700)
	}
	if err := c.accountFile(info); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm()&0o755)
	if err != nil {
		return err
	}
	copyErr := recoveryCopySourceFile(ctx, c.root, filepath.ToSlash(rel), info, output)
	closeErr := output.Close()
	return firstErr(copyErr, closeErr)
}

func (c *recoveryCopier) accountFile(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup source is not a regular file: %s", info.Name())
	}
	if info.Size() < 0 || info.Size() > recoveryMaxFileSize || c.files >= recoveryMaxEntries || c.bytes > recoveryMaxTotalSize-info.Size() {
		return fmt.Errorf("backup source exceeds inventory or data limits: %s", info.Name())
	}
	c.files++
	c.bytes += info.Size()
	return nil
}

func validateRecoveryBackupManifest(m recoveryManifest) error {
	if m.Kind != "backup" || (m.Role != "high" && m.Role != "low") {
		return errors.New("invalid backup kind or role")
	}
	seen := make(map[string]bool, len(m.Files))
	for _, file := range m.Files {
		if !recoveryBackupPathAllowed(m.Role, file.Path) {
			return fmt.Errorf("backup contains a path outside its role allowlist: %s", file.Path)
		}
		seen[file.Path] = true
	}
	return validateRecoveryBackupRequiredFiles(m.Role, seen)
}

func validateRecoveryBackupRequiredFiles(role string, seen map[string]bool) error {
	if role == "high" && !seen["import-state.json"] {
		return errors.New("high backup is missing import-state.json")
	}
	if role != "low" {
		return nil
	}
	if !seen["low-state.json"] || !seen["exported.db"] {
		return errors.New("low backup is missing low-state.json or exported.db")
	}
	for _, base := range []string{"exported.db", "watches.db"} {
		if !seen[base] && (seen[base+"-wal"] || seen[base+"-journal"]) {
			return fmt.Errorf("backup contains SQLite sidecars without %s", base)
		}
	}
	return nil
}

func recoveryBackupPathAllowed(role, name string) bool {
	if role == "high" {
		return name == "import-state.json" || name == "python-index.json" || strings.HasPrefix(name, "cache/download/")
	}
	if role == "low" {
		return (slices.Contains(recoveryLowBackupPaths(), name) && name != "bundles" && name != "recovery-retention") || strings.HasPrefix(name, "bundles/") || strings.HasPrefix(name, "recovery-retention/")
	}
	return false
}

func validateRecoveryBackupState(root string, manifest recoveryManifest) error {
	streams, err := recoveryBackupStreams(root, manifest.Role)
	if err != nil {
		return err
	}
	if !maps.Equal(streams, manifest.Streams) {
		return errors.New("backup manifest frontier does not match its saved sequence state")
	}
	return nil
}

func recoveryBackupStreams(root, role string) (map[string]int64, error) {
	if err := validateRecoveryBackupRoot(root, role); err != nil {
		return nil, err
	}
	stateRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer stateRoot.Close()
	if role == "low" {
		info, err := stateRoot.Lstat("exported.db")
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("backup needs a regular exported.db file")
		}
	}
	data, err := recoveryReadRegularFile(stateRoot, recoveryStatePath(role), 1<<20)
	if err != nil {
		return nil, fmt.Errorf("backup needs matching %s: %w", recoveryStatePath(role), err)
	}
	return recoveryBackupStreamsFromState(data, role)
}

func validateRecoveryBackupRoot(root, role string) error {
	if role != "low" {
		return nil
	}
	if err := checkRecoveryRetentionIdle(root); err != nil {
		return fmt.Errorf("low backup requires completed retention: %w", err)
	}
	_, err := loadRecoveryLedger(root)
	return err
}

func recoveryStatePath(role string) string {
	if role == "low" {
		return "low-state.json"
	}
	return "import-state.json"
}

func recoveryBackupStreamsFromState(data []byte, role string) (map[string]int64, error) {
	var streams map[string]int64
	var err error
	switch role {
	case "high":
		streams, err = recoveryHighBackupStreams(data)
	case "low":
		streams, err = recoveryLowBackupStreams(data)
	default:
		return nil, errors.New("invalid recovery backup role")
	}
	if err != nil {
		return nil, err
	}
	for stream, seq := range streams {
		if !slices.Contains(knownStreams(), stream) || seq < 0 {
			return nil, fmt.Errorf("invalid backup stream frontier %q: %d", stream, seq)
		}
	}
	return streams, nil
}

func recoveryHighBackupStreams(data []byte) (map[string]int64, error) {
	var state HighState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read backup import state: %w", err)
	}
	streams := make(map[string]int64)
	maps.Copy(streams, state.Imported)
	if _, found := streams[streamGo]; !found && state.LastImportedSequence != 0 {
		streams[streamGo] = state.LastImportedSequence
	}
	return streams, nil
}

func recoveryLowBackupStreams(data []byte) (map[string]int64, error) {
	var state LowState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read backup export state: %w", err)
	}
	streams := make(map[string]int64)
	for stream, next := range state.Sequences {
		if next < 1 {
			return nil, fmt.Errorf("invalid next sequence for %s", stream)
		}
		streams[stream] = next - 1
	}
	if _, found := streams[streamGo]; !found && state.NextSequence != 0 {
		if state.NextSequence < 1 {
			return nil, errors.New("invalid legacy next sequence")
		}
		streams[streamGo] = state.NextSequence - 1
	}
	return streams, nil
}
