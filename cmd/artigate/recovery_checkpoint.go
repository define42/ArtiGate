package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type checkpointOptions struct {
	Root       string
	Output     string
	Base       string
	BaseDigest string
	PrivateKey ed25519.PrivateKey
}

const checkpointMaxStateBytes = 1 << 20

// createRecoveryCheckpoint requires the caller to hold the stopped low root's
// exclusive lock. Replay uses a private receiver and never consumes its source
// archives. A successful result has passed a complete restore drill.
func createRecoveryCheckpoint(ctx context.Context, opts checkpointOptions) (recoveryArtifact, error) {
	if err := ctx.Err(); err != nil {
		return recoveryArtifact{}, err
	}
	if len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return recoveryArtifact{}, errors.New("checkpoint requires an Ed25519 private key")
	}
	if opts.Root == "" || opts.Output == "" {
		return recoveryArtifact{}, errors.New("checkpoint requires root and output paths")
	}
	if err := checkRecoveryRetentionIdle(opts.Root); err != nil {
		return recoveryArtifact{}, err
	}
	if err := checkpointSeparatePaths(opts); err != nil {
		return recoveryArtifact{}, err
	}
	work, err := os.MkdirTemp("", "artigate-checkpoint-")
	if err != nil {
		return recoveryArtifact{}, fmt.Errorf("create checkpoint workspace: %w", err)
	}
	defer os.RemoveAll(work)
	pub := opts.PrivateKey.Public().(ed25519.PublicKey)
	hs, err := newCheckpointReceiver(ctx, work, opts.Base, opts.BaseDigest, pub)
	if err != nil {
		return recoveryArtifact{}, err
	}
	tip, err := checkpointFrontier(opts.Root, hs.state.Imported)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if err := replayCheckpointArchives(ctx, hs, filepath.Join(opts.Root, "bundles"), tip); err != nil {
		return recoveryArtifact{}, err
	}
	return finishRecoveryCheckpoint(ctx, hs, work, opts.Output, maps.Clone(hs.state.Imported), opts.PrivateKey)
}

func checkpointSeparatePaths(opts checkpointOptions) error {
	for _, directory := range []string{opts.Root, filepath.Dir(opts.Output)} {
		if err := recoveryCheckDirectory(directory); err != nil {
			return err
		}
	}
	if err := recoverySeparatePaths(opts.Root, opts.Output); err != nil {
		return err
	}
	if opts.Base != "" {
		return recoverySeparatePaths(opts.Base, opts.Output)
	}
	return nil
}

func finishRecoveryCheckpoint(ctx context.Context, hs *HighServer, work, output string,
	tip map[string]int64, priv ed25519.PrivateKey,
) (recoveryArtifact, error) {
	snapshot := filepath.Join(work, "snapshot")
	if err := os.Mkdir(snapshot, 0o700); err != nil {
		return recoveryArtifact{}, fmt.Errorf("create checkpoint snapshot directory: %w", err)
	}
	paths := []string{"cache/download", "import-state.json", "python-index.json"}
	if err := copyRecoveryPaths(ctx, hs.cfg.Root, snapshot, paths); err != nil {
		return recoveryArtifact{}, fmt.Errorf("stage checkpoint repository: %w", err)
	}
	manifest := recoveryManifest{
		Format: 1, Kind: "checkpoint", Role: "high", Created: time.Now().UTC(), Streams: tip,
	}
	artifact, err := writeRecoveryArtifact(ctx, snapshot, output, manifest, priv)
	if err != nil {
		return recoveryArtifact{}, fmt.Errorf("write checkpoint: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := newCheckpointReceiver(ctx, filepath.Join(work, "drill"), output, artifact.Digest, pub); err != nil {
		return recoveryArtifact{}, fmt.Errorf("checkpoint restore drill failed: %w", err)
	}
	return artifact, nil
}

// replayRecoveryCheckpointTail proves that a checkpoint and its retained tail
// reach tip through the normal signature, hash, publication and state commits.
func replayRecoveryCheckpointTail(ctx context.Context, checkpoint string, pub ed25519.PublicKey,
	archiveDir string, tip map[string]int64,
) error {
	work, err := os.MkdirTemp("", "artigate-recovery-drill-")
	if err != nil {
		return fmt.Errorf("create replay workspace: %w", err)
	}
	defer os.RemoveAll(work)
	hs, err := newCheckpointReceiver(ctx, work, checkpoint, "", pub)
	if err != nil {
		return err
	}
	return replayCheckpointArchives(ctx, hs, archiveDir, tip)
}

func newCheckpointReceiver(ctx context.Context, work, base, digest string, pub ed25519.PublicKey) (*HighServer, error) {
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, fmt.Errorf("create checkpoint receiver directory: %w", err)
	}
	root := filepath.Join(work, "receiver")
	if base != "" {
		if err := restoreCheckpointBase(ctx, base, root, pub, digest); err != nil {
			return nil, err
		}
	} else if digest != "" {
		return nil, errors.New("base digest requires a base checkpoint")
	}
	hs, err := NewHighServer(HighConfig{Root: root, Landing: filepath.Join(work, "landing")}, pub)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint receiver: %w", err)
	}
	return hs, nil
}

func restoreCheckpointBase(ctx context.Context, base, root string, pub ed25519.PublicKey, digest string) error {
	artifact, err := restoreRecoveryArtifact(ctx, base, root, pub, digest)
	if err != nil {
		return fmt.Errorf("restore base checkpoint: %w", err)
	}
	if err := validateCheckpointManifest(artifact.Manifest); err != nil {
		return err
	}
	return validateCheckpointState(root, artifact.Manifest.Streams)
}

func validateCheckpointManifest(manifest recoveryManifest) error {
	if manifest.Kind != "checkpoint" || manifest.Role != "high" {
		return errors.New("base artifact is not a high-side checkpoint")
	}
	hasState := false
	for _, file := range manifest.Files {
		if file.Path == "import-state.json" {
			hasState = true
			if file.Size > checkpointMaxStateBytes {
				return errors.New("checkpoint import state exceeds size limit")
			}
		}
		if file.Path != "import-state.json" && file.Path != "python-index.json" &&
			!strings.HasPrefix(file.Path, "cache/download/") {
			return fmt.Errorf("checkpoint contains unexpected repository path %q", file.Path)
		}
	}
	if !hasState {
		return errors.New("checkpoint is missing import-state.json")
	}
	return validCheckpointStreams(manifest.Streams)
}

func validateCheckpointState(root string, streams map[string]int64) error {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open checkpoint root: %w", err)
	}
	defer dir.Close()
	data, err := recoveryReadRegularFile(dir, "import-state.json", checkpointMaxStateBytes)
	if err != nil {
		return fmt.Errorf("read checkpoint import state: %w", err)
	}
	return validateCheckpointStateBytes(data, streams)
}

func validateCheckpointStateBytes(data []byte, streams map[string]int64) error {
	if len(data) > checkpointMaxStateBytes {
		return errors.New("checkpoint import state exceeds size limit")
	}
	var state HighState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode checkpoint import state: %w", err)
	}
	if state.LastImportedSequence != 0 {
		return errors.New("checkpoint import state must use per-stream sequences")
	}
	if err := validCheckpointStreams(streams); err != nil {
		return err
	}
	if !maps.Equal(state.Imported, streams) {
		return errors.New("checkpoint stream positions do not match its import state")
	}
	return nil
}

func validCheckpointStreams(streams map[string]int64) error {
	for stream, seq := range streams {
		if !isKnownStream(stream) || seq < 0 || seq == math.MaxInt64 {
			return fmt.Errorf("invalid checkpoint stream position %q: %d", stream, seq)
		}
	}
	return nil
}

func checkpointFrontier(root string, base map[string]int64) (map[string]int64, error) {
	tip, err := checkpointLowFrontier(root)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, "bundles"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read checkpoint archive: %w", err)
	}
	for _, entry := range entries {
		stream, seq, ok := checkpointArchiveName(entry.Name())
		if !ok {
			continue
		}
		if !isKnownStream(stream) || seq < 1 || seq == math.MaxInt64 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("invalid archived checkpoint input %q", entry.Name())
		}
		tip[stream] = max(tip[stream], seq)
	}
	if err := checkpointFrontierIncludes(tip, base); err != nil {
		return nil, err
	}
	return tip, nil
}

func checkpointLowFrontier(root string) (map[string]int64, error) {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint low-side root: %w", err)
	}
	defer dir.Close()
	data, err := recoveryReadRegularFile(dir, "low-state.json", checkpointMaxStateBytes)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint low-side state: %w", err)
	}
	var state LowState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode checkpoint low-side state: %w", err)
	}
	if state.Sequences == nil {
		state.Sequences = map[string]int64{}
	}
	if state.NextSequence < 0 {
		return nil, errors.New("invalid legacy low-side sequence")
	}
	if state.NextSequence > 0 && state.Sequences[streamGo] == 0 {
		state.Sequences[streamGo] = state.NextSequence
	}
	tip := make(map[string]int64, len(state.Sequences))
	if err := advanceCheckpointFrontier(tip, state.Sequences); err != nil {
		return nil, err
	}
	ledger, err := loadRecoveryLedger(root)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint recovery ledger: %w", err)
	}
	if err := advanceCheckpointFrontier(tip, ledger.NextSequences); err != nil {
		return nil, err
	}
	return tip, nil
}

func advanceCheckpointFrontier(tip, nextSequences map[string]int64) error {
	for stream, next := range nextSequences {
		if !isKnownStream(stream) || next < 1 {
			return fmt.Errorf("invalid checkpoint next sequence for %q: %d", stream, next)
		}
		if next > 1 {
			tip[stream] = max(tip[stream], next-1)
		}
	}
	return nil
}

func checkpointArchiveName(name string) (stream string, seq int64, ok bool) {
	for _, suffix := range bundleSuffixes() {
		if strings.HasSuffix(name, suffix) {
			id := strings.TrimSuffix(name, suffix)
			return parseBundleName(id + ".manifest.json")
		}
	}
	return "", 0, false
}

func checkpointFrontierIncludes(tip, base map[string]int64) error {
	if err := validCheckpointStreams(tip); err != nil {
		return err
	}
	for stream, seq := range base {
		if seq > tip[stream] {
			return fmt.Errorf("checkpoint %s sequence %d is ahead of low-side sequence %d", stream, seq, tip[stream])
		}
	}
	return nil
}

func replayCheckpointArchives(ctx context.Context, hs *HighServer, archive string, tip map[string]int64) error {
	if err := checkpointFrontierIncludes(tip, hs.state.Imported); err != nil {
		return err
	}
	for _, stream := range slices.Sorted(maps.Keys(tip)) {
		for seq := hs.importedSequence(stream) + 1; seq <= tip[stream]; seq++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := replayCheckpointBundle(hs, archive, stream, seq); err != nil {
				return fmt.Errorf("checkpoint replay %s sequence %d: %w", stream, seq, err)
			}
		}
	}
	return validateCheckpointState(hs.cfg.Root, checkpointImportedFrontier(tip, hs.state.Imported))
}

// A retention plan may include never-used streams at zero; their absent state
// entries have the same meaning. Preserve explicit zero entries from a base.
func checkpointImportedFrontier(tip, imported map[string]int64) map[string]int64 {
	frontier := maps.Clone(tip)
	if frontier == nil {
		frontier = map[string]int64{}
	}
	for stream, seq := range frontier {
		if _, exists := imported[stream]; !exists && seq == 0 {
			delete(frontier, stream)
		}
	}
	for stream, seq := range imported {
		if seq == 0 {
			frontier[stream] = 0
		}
	}
	return frontier
}

func replayCheckpointBundle(hs *HighServer, archive, stream string, seq int64) error {
	id := bundleIDFor(stream, seq)
	for _, suffix := range bundleSuffixes() {
		src := filepath.Join(archive, id+suffix)
		info, err := os.Lstat(src)
		if err != nil {
			return fmt.Errorf("read required archived bundle %s: %w", id, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archived bundle file %s is not regular", src)
		}
		if err := linkOrCopyFileWithSync(src, filepath.Join(hs.cfg.Landing, id+suffix), fsyncDir); err != nil {
			return fmt.Errorf("stage archived bundle %s: %w", id, err)
		}
	}
	if _, err := hs.importBundleFromDirLocked(hs.cfg.Landing, stream, id, seq); err != nil {
		return err
	}
	for _, suffix := range bundleSuffixes() {
		if err := os.Remove(filepath.Join(hs.cfg.Landing, "imported", id+suffix)); err != nil {
			return fmt.Errorf("remove replayed archive copy: %w", err)
		}
	}
	return nil
}
