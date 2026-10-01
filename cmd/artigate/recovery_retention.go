package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// retentionOptions describes operator-supplied recovery promises. ReceiverFloors
// is the minimum confirmed imported sequence across ALL receivers of each stream.
// A missing stream is unknown progress, unless AllowBootstrap explicitly permits
// replacing lagging receivers with one of the retained checkpoints.
type retentionOptions struct {
	Root           string
	ExportDir      string
	Checkpoints    []string
	PublicKey      ed25519.PublicKey
	ReceiverFloors map[string]int64
	AllowBootstrap bool
}

type recoveryRetentionFile struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Missing bool   `json:"missing,omitempty"`
}

type recoveryRetentionCheckpoint struct {
	Path    string           `json:"path"`
	Digest  string           `json:"digest"`
	Streams map[string]int64 `json:"streams"`
}

type recoveryRetentionPlan struct {
	Format           int                           `json:"format"`
	ID               string                        `json:"id"`
	Root             string                        `json:"root"`
	ExportDir        string                        `json:"export_dir"`
	KeyFingerprint   string                        `json:"key_fingerprint"`
	ReceiverFloors   map[string]int64              `json:"receiver_floors"`
	AllowBootstrap   bool                          `json:"allow_bootstrap"`
	Checkpoints      []recoveryRetentionCheckpoint `json:"checkpoints"`
	Tips             map[string]int64              `json:"tips"`
	Cutoffs          map[string]int64              `json:"cutoffs"`
	Blocked          map[string]string             `json:"blocked,omitempty"`
	PreviousLedger   recoveryLedger                `json:"previous_ledger"`
	Inputs           []recoveryRetentionFile       `json:"inputs"`
	Candidates       []recoveryRetentionFile       `json:"candidates"`
	ReclaimableBytes int64                         `json:"reclaimable_bytes"`
}

// recoveryLedger survives archive deletion independently of low-state.json.
// Keeping the largest known next sequence prevents a stale state restore from
// reusing a sequence whose last archive copy has been deliberately pruned.
type recoveryLedger struct {
	Format        int              `json:"format"`
	NextSequences map[string]int64 `json:"next_sequences"`
	PrunedThrough map[string]int64 `json:"pruned_through"`
}

type recoveryRetentionJournal struct {
	Format   int                   `json:"format"`
	Plan     recoveryRetentionPlan `json:"plan"`
	Complete bool                  `json:"complete"`
}

func recoveryRetentionJournalDir(root string) string {
	return filepath.Join(root, "recovery-retention")
}

func loadRecoveryLedger(root string) (recoveryLedger, error) {
	ledger, err := readRecoveryLedger(root)
	if err != nil {
		return ledger, err
	}
	return ledger, checkRetentionLedgerEvidence(root, ledger)
}

// Allocation reads only this small ledger. The full journal history is checked
// on startup by loadRecoveryLedger before its floors enter the in-memory state.
func readRecoveryLedger(root string) (recoveryLedger, error) {
	out := recoveryLedger{Format: 1, NextSequences: map[string]int64{}, PrunedThrough: map[string]int64{}}
	err := readRetentionJSON(filepath.Join(root, "recovery-ledger.json"), &out)
	if errors.Is(err, os.ErrNotExist) {
		return out, checkMissingRecoveryLedger(root)
	}
	if err != nil {
		return out, fmt.Errorf("read recovery ledger: %w", err)
	}
	return out, validateRecoveryLedger(out)
}

func checkMissingRecoveryLedger(root string) error {
	entries, err := retentionJournalEntries(root)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("recovery ledger missing while retention journals exist; restore the ledger or resume the recorded prune")
	}
	return nil
}

func validateRecoveryLedger(ledger recoveryLedger) error {
	if ledger.Format != 1 || ledger.NextSequences == nil || ledger.PrunedThrough == nil {
		return errors.New("invalid recovery ledger format")
	}
	for stream, next := range ledger.NextSequences {
		if !retentionKnownStream(stream) || next < 1 {
			return fmt.Errorf("invalid recovery ledger next sequence for %q", stream)
		}
	}
	for stream, seq := range ledger.PrunedThrough {
		if !retentionKnownStream(stream) || seq < 0 || ledger.NextSequences[stream] <= seq {
			return fmt.Errorf("invalid recovery ledger prune floor for %q", stream)
		}
	}
	return nil
}

func checkRetentionLedgerEvidence(root string, ledger recoveryLedger) error {
	entries, err := retentionJournalEntries(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var journal recoveryRetentionJournal
		if err := readRetentionJSON(filepath.Join(recoveryRetentionJournalDir(root), entry.Name()), &journal); err != nil {
			return err
		}
		if journal.Format != 1 || !validRetentionPlanID(journal.Plan) {
			return errors.New("invalid retention journal while checking sequence floor")
		}
		if err := checkRetentionJournalFloor(ledger, journal.Plan); err != nil {
			return err
		}
	}
	return nil
}

func checkRetentionJournalFloor(ledger recoveryLedger, plan recoveryRetentionPlan) error {
	for stream, tip := range plan.Tips {
		if tip == math.MaxInt64 || ledger.NextSequences[stream] <= tip || ledger.PrunedThrough[stream] < plan.Cutoffs[stream] {
			return fmt.Errorf("recovery ledger is behind retained prune evidence for %s", stream)
		}
	}
	return nil
}

func retentionKnownStream(stream string) bool {
	for _, s := range knownStreams() {
		if s == stream {
			return true
		}
	}
	return false
}

func readRetentionJSON(path string, value any) error {
	lst, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !lst.Mode().IsRegular() {
		return fmt.Errorf("retention state is not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 256<<20 {
		return fmt.Errorf("invalid retention state file %s", path)
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing data in retention state")
	}
	return nil
}

func checkRecoveryRetentionIdle(root string) error {
	entries, err := retentionJournalEntries(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "plan-") || !strings.HasSuffix(e.Name(), ".json") {
			return fmt.Errorf("unknown retention journal %q", e.Name())
		}
		var journal recoveryRetentionJournal
		if err := readRetentionJSON(filepath.Join(recoveryRetentionJournalDir(root), e.Name()), &journal); err != nil {
			return err
		}
		if journal.Format != 1 || !validRetentionPlanID(journal.Plan) {
			return fmt.Errorf("invalid retention journal %s", e.Name())
		}
		if !journal.Complete {
			return fmt.Errorf("retention plan %s is unfinished; resume it before starting the low side", journal.Plan.ID)
		}
	}
	return nil
}

// An atomic journal writer may crash before publishing its final name. Such a
// temporary file cannot authorize deletion, so it is neither a sequence claim
// nor an unfinished operation; the next identical write replaces it safely.
func retentionJournalEntries(root string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(recoveryRetentionJournalDir(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := entries[:0]
	for _, entry := range entries {
		name := entry.Name()
		base := strings.TrimSuffix(name, ".tmp")
		id := strings.TrimSuffix(strings.TrimPrefix(base, "plan-"), ".json")
		decoded, decodeErr := hex.DecodeString(id)
		if base != "plan-"+id+".json" || decodeErr != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("unknown retention journal %q", name)
		}
		if name == base {
			out = append(out, entry)
		}
	}
	return out, nil
}

func normalizeRetentionOptions(opts retentionOptions) (retentionOptions, error) {
	if opts.Root == "" || opts.ExportDir == "" || len(opts.PublicKey) != ed25519.PublicKeySize {
		return opts, errors.New("retention requires root, export directory and an Ed25519 public key")
	}
	var err error
	opts, err = normalizeRetentionPaths(opts)
	if err != nil {
		return opts, err
	}
	sort.Strings(opts.Checkpoints)
	for i := 1; i < len(opts.Checkpoints); i++ {
		if opts.Checkpoints[i] == opts.Checkpoints[i-1] {
			return opts, errors.New("duplicate retained checkpoint")
		}
	}
	if len(opts.Checkpoints) == 0 {
		return opts, errors.New("at least one complete retained checkpoint is required")
	}
	opts.ReceiverFloors = copyInt64Map(opts.ReceiverFloors)
	if opts.ReceiverFloors == nil {
		opts.ReceiverFloors = map[string]int64{}
	}
	for stream, floor := range opts.ReceiverFloors {
		if !retentionKnownStream(stream) || floor < 0 {
			return opts, fmt.Errorf("invalid receiver floor for %q", stream)
		}
	}
	return opts, nil
}

func normalizeRetentionPaths(opts retentionOptions) (retentionOptions, error) {
	var err error
	opts.Root, err = retentionCanonicalDirectory(opts.Root)
	if err != nil {
		return opts, err
	}
	opts.ExportDir, err = retentionCanonicalDirectory(opts.ExportDir)
	if err != nil {
		return opts, err
	}
	opts.Checkpoints = append([]string(nil), opts.Checkpoints...)
	for i, checkpoint := range opts.Checkpoints {
		opts.Checkpoints[i], err = retentionCanonicalDirectory(checkpoint)
		if err != nil {
			return opts, err
		}
		if retentionPathsOverlap(opts.Root, opts.Checkpoints[i]) || retentionPathsOverlap(opts.ExportDir, opts.Checkpoints[i]) {
			return opts, errors.New("retained checkpoints must be outside the low root and outbound spool")
		}
	}
	if opts.ExportDir == opts.Root || retentionPathsOverlap(filepath.Join(opts.Root, "bundles"), opts.ExportDir) {
		return opts, errors.New("outbound spool must be distinct from the low root and bundle archive")
	}
	return opts, nil
}

func retentionCanonicalDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("retention directory is not a directory: %s", path)
	}
	return resolved, nil
}

func retentionPathsOverlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// recoveryRetentionOptions reconstructs the exact inputs bound by a saved plan.
// The verification key is supplied separately and checked against its fingerprint.
func recoveryRetentionOptions(plan recoveryRetentionPlan, pub ed25519.PublicKey) (retentionOptions, error) {
	if !validRetentionPlanID(plan) {
		return retentionOptions{}, errors.New("retention plan ID does not match its contents")
	}
	keyHash := sha256.Sum256(pub)
	if hex.EncodeToString(keyHash[:]) != plan.KeyFingerprint {
		return retentionOptions{}, errors.New("public key does not match retention plan")
	}
	opts := retentionOptions{Root: plan.Root, ExportDir: plan.ExportDir, PublicKey: pub, ReceiverFloors: plan.ReceiverFloors, AllowBootstrap: plan.AllowBootstrap}
	for _, checkpoint := range plan.Checkpoints {
		opts.Checkpoints = append(opts.Checkpoints, checkpoint.Path)
	}
	return normalizeRetentionOptions(opts)
}

func planRecoveryRetention(ctx context.Context, opts retentionOptions) (recoveryRetentionPlan, error) {
	var plan recoveryRetentionPlan
	opts, err := normalizeRetentionOptions(opts)
	if err != nil {
		return plan, err
	}
	plan, err = initialRetentionPlan(opts)
	if err != nil {
		return plan, err
	}
	archiveFiles, err := retentionArchiveInputs(ctx, &plan)
	if err != nil {
		return plan, err
	}
	spoolFiles, err := retentionDirectoryFiles(ctx, opts.ExportDir)
	if err != nil {
		return plan, err
	}
	pending, err := retentionPendingMetadata(opts.Root)
	if err != nil {
		return plan, err
	}
	if err := addRetentionCheckpoints(ctx, opts, &plan); err != nil {
		return plan, err
	}
	if err := setRetentionCutoffs(&plan, pending); err != nil {
		return plan, err
	}
	if err := pinRetentionSpool(&plan, spoolFiles); err != nil {
		return plan, err
	}
	if err := checkRetentionContinuity(plan, archiveFiles); err != nil {
		return plan, err
	}
	if err := verifyRetentionReceiverTail(ctx, opts.PublicKey, plan, archiveFiles); err != nil {
		return plan, err
	}
	if err := finishRetentionPlan(ctx, &plan, archiveFiles, spoolFiles); err != nil {
		return plan, err
	}
	plan.ID, err = retentionPlanID(plan)
	return plan, err
}

func initialRetentionPlan(opts retentionOptions) (recoveryRetentionPlan, error) {
	var plan recoveryRetentionPlan
	if err := checkRecoveryRetentionIdle(opts.Root); err != nil {
		return plan, err
	}
	ledger, err := loadRecoveryLedger(opts.Root)
	if err != nil {
		return plan, err
	}
	keyHash := sha256.Sum256(opts.PublicKey)
	plan = recoveryRetentionPlan{
		Format: 1, Root: opts.Root, ExportDir: opts.ExportDir,
		KeyFingerprint: hex.EncodeToString(keyHash[:]), ReceiverFloors: opts.ReceiverFloors,
		AllowBootstrap: opts.AllowBootstrap, PreviousLedger: ledger,
		Tips: map[string]int64{}, Cutoffs: map[string]int64{}, Blocked: map[string]string{},
	}
	var state LowState
	if err := readRetentionJSON(filepath.Join(opts.Root, "low-state.json"), &state); err != nil {
		return plan, fmt.Errorf("load low state: %w", err)
	}
	if state.NextSequence < 0 {
		return plan, errors.New("invalid legacy low-side sequence")
	}
	if state.NextSequence > 0 && state.Sequences[streamGo] == 0 {
		if state.Sequences == nil {
			state.Sequences = map[string]int64{}
		}
		state.Sequences[streamGo] = state.NextSequence
	}
	for stream, next := range state.Sequences {
		if !retentionKnownStream(stream) || next < 1 {
			return plan, fmt.Errorf("invalid low sequence for %q", stream)
		}
		plan.Tips[stream] = next - 1
	}
	for stream, next := range ledger.NextSequences {
		plan.Tips[stream] = max(plan.Tips[stream], next-1)
	}
	return plan, nil
}

func retentionArchiveInputs(ctx context.Context, plan *recoveryRetentionPlan) ([]recoveryRetentionFile, error) {
	archive := filepath.Join(plan.Root, "bundles")
	files, err := retentionDirectoryFiles(ctx, archive)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		stream, seq, ok := retentionBundleFile(file.Path)
		if !ok {
			return nil, fmt.Errorf("archive has unrecognized or unfinished file %s", file.Path)
		}
		if !bundleCompleteInDir(archive, bundleIDFor(stream, seq)) {
			return nil, fmt.Errorf("archive bundle %s is incomplete", bundleIDFor(stream, seq))
		}
		plan.Tips[stream] = max(plan.Tips[stream], seq)
	}
	return files, nil
}

func addRetentionCheckpoints(ctx context.Context, opts retentionOptions, plan *recoveryRetentionPlan) error {
	for _, checkpoint := range opts.Checkpoints {
		artifact, err := verifyRecoveryArtifact(ctx, checkpoint, opts.PublicKey, "")
		if err != nil {
			return fmt.Errorf("verify retained checkpoint %s: %w", checkpoint, err)
		}
		if artifact.Manifest.Kind != "checkpoint" || artifact.Manifest.Role != "high" {
			return fmt.Errorf("%s is not a high-side checkpoint", checkpoint)
		}
		for stream, seq := range artifact.Manifest.Streams {
			if seq > plan.Tips[stream] {
				return fmt.Errorf("checkpoint %s is ahead of stream %s", checkpoint, stream)
			}
		}
		plan.Checkpoints = append(plan.Checkpoints, recoveryRetentionCheckpoint{
			Path: checkpoint, Digest: artifact.Digest, Streams: copyInt64Map(artifact.Manifest.Streams),
		})
		files, err := retentionDirectoryFiles(ctx, checkpoint)
		if err != nil {
			return err
		}
		plan.Inputs = append(plan.Inputs, files...)
		if err := replayRecoveryCheckpointTail(ctx, checkpoint, opts.PublicKey, filepath.Join(opts.Root, "bundles"), plan.Tips); err != nil {
			return fmt.Errorf("restore drill for %s: %w", checkpoint, err)
		}
	}
	return nil
}

func setRetentionCutoffs(plan *recoveryRetentionPlan, pending map[string]bool) error {
	for stream, tip := range plan.Tips {
		cutoff := tip
		for _, cp := range plan.Checkpoints {
			cutoff = min(cutoff, cp.Streams[stream])
		}
		if floor, ok := plan.ReceiverFloors[stream]; ok {
			if floor > tip {
				return fmt.Errorf("receiver floor exceeds stream %s tip", stream)
			}
			cutoff = min(cutoff, floor)
		} else if !plan.AllowBootstrap {
			cutoff = 0
			plan.Blocked[stream] = "receiver progress is unknown; provide the minimum confirmed receiver floor or explicitly allow checkpoint bootstrap"
		}
		if pending[stream] {
			cutoff = 0
			plan.Blocked[stream] = "unfinished content parts still need ecosystem metadata"
		}
		plan.Cutoffs[stream] = cutoff
	}
	return nil
}

func pinRetentionSpool(plan *recoveryRetentionPlan, files []recoveryRetentionFile) error {
	for _, file := range files {
		if filepath.Base(file.Path) == diodeHeartbeatFileName || filepath.Base(file.Path) == ".artigate.lock" {
			continue
		}
		stream, seq, ok := retentionBundleFile(file.Path)
		if !ok {
			return fmt.Errorf("outbound spool has unrecognized or unfinished file %s", file.Path)
		}
		if seq <= plan.Cutoffs[stream] {
			plan.Cutoffs[stream] = seq - 1
			plan.Blocked[stream] = "outbound bundle remains staged; transmission is not proof of receiver import"
		}
	}
	return nil
}

func finishRetentionPlan(ctx context.Context, plan *recoveryRetentionPlan, archiveFiles, spoolFiles []recoveryRetentionFile) error {
	for _, file := range archiveFiles {
		stream, seq, _ := retentionBundleFile(file.Path)
		if seq <= plan.Cutoffs[stream] {
			plan.Candidates = append(plan.Candidates, file)
			if file.Size > math.MaxInt64-plan.ReclaimableBytes {
				return errors.New("retention byte total overflows")
			}
			plan.ReclaimableBytes += file.Size
		}
	}
	plan.Inputs = append(plan.Inputs, archiveFiles...)
	plan.Inputs = append(plan.Inputs, spoolFiles...)
	for _, name := range []string{"low-state.json", "exported.db", "exported.db-wal", "exported.db-shm", "exported.db-journal", "recovery-ledger.json"} {
		file, err := retentionFingerprint(ctx, filepath.Join(plan.Root, name), true)
		if err != nil {
			return err
		}
		plan.Inputs = append(plan.Inputs, file)
	}
	sort.Slice(plan.Inputs, func(i, j int) bool { return plan.Inputs[i].Path < plan.Inputs[j].Path })
	sort.Slice(plan.Candidates, func(i, j int) bool { return plan.Candidates[i].Path < plan.Candidates[j].Path })
	return nil
}

// A checkpoint drill establishes its own replay path. A receiver floor older
// than that checkpoint also needs every intermediate bundle retained, even if
// those bundles would not otherwise participate in a checkpoint restore.
func checkRetentionContinuity(plan recoveryRetentionPlan, files []recoveryRetentionFile) error {
	sequences := map[string]map[int64]bool{}
	for _, file := range files {
		stream, seq, ok := retentionBundleFile(file.Path)
		if !ok {
			return fmt.Errorf("invalid retained archive file %s", file.Path)
		}
		if sequences[stream] == nil {
			sequences[stream] = map[int64]bool{}
		}
		sequences[stream][seq] = true
	}
	for stream, tip := range plan.Tips {
		if err := checkRetentionStreamContinuity(stream, plan.Cutoffs[stream], tip, sequences[stream]); err != nil {
			return err
		}
	}
	return nil
}

func checkRetentionStreamContinuity(stream string, baseline, tip int64, sequences map[int64]bool) error {
	seqs := make([]int64, 0, len(sequences))
	for seq := range sequences {
		if seq > baseline {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	last := baseline
	for _, seq := range seqs {
		if last == math.MaxInt64 || seq != last+1 {
			return fmt.Errorf("stream %s has a gap after sequence %d required by its retention baseline", stream, last)
		}
		last = seq
	}
	if last != tip {
		return fmt.Errorf("stream %s replay tail ends at %d, expected %d", stream, last, tip)
	}
	return nil
}

// Files between a receiver floor and the oldest checkpoint are unnecessary for
// checkpoint restore, but are still required by that receiver. Verify their
// signatures, identities, sizes and archive hashes independently. Its prior
// files are justified by the operator-confirmed imported receiver floor.
func verifyRetentionReceiverTail(ctx context.Context, pub ed25519.PublicKey, plan recoveryRetentionPlan, files []recoveryRetentionFile) error {
	work, err := os.MkdirTemp("", "artigate-retention-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	hs := &HighServer{publicKey: pub, state: HighState{Imported: map[string]int64{}}}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !retentionNeedsReceiverVerification(plan, file.Path) {
			continue
		}
		if err := verifyRetentionReceiverBundle(hs, work, file.Path); err != nil {
			return err
		}
	}
	return nil
}

func retentionNeedsReceiverVerification(plan recoveryRetentionPlan, filename string) bool {
	if !strings.HasSuffix(filename, ".manifest.json") {
		return false
	}
	stream, seq, ok := retentionBundleFile(filename)
	if !ok || seq <= plan.Cutoffs[stream] {
		return false
	}
	oldest := plan.Tips[stream]
	for _, cp := range plan.Checkpoints {
		oldest = min(oldest, cp.Streams[stream])
	}
	return seq <= oldest
}

func verifyRetentionReceiverBundle(hs *HighServer, work, filename string) error {
	stream, seq, ok := retentionBundleFile(filename)
	if !ok {
		return fmt.Errorf("invalid retained bundle manifest %s", filename)
	}
	id := bundleIDFor(stream, seq)
	archive := filepath.Join(filepath.Dir(filename), id+".tar.gz")
	sig := filename + ".sig"
	if err := validateBundleArtifactSizes(archive, filename, sig); err != nil {
		return err
	}
	hs.state.Imported[stream] = seq - 1
	manifest, err := hs.loadVerifiedManifest(filename, sig, stream, id, seq)
	if err != nil {
		return fmt.Errorf("verify retained receiver tail %s: %w", id, err)
	}
	stage := filepath.Join(work, id)
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	if err := extractAndVerifyTarGz(archive, stage, manifest.Files); err != nil {
		return fmt.Errorf("verify retained receiver archive %s: %w", id, err)
	}
	return os.RemoveAll(stage)
}

func retentionPendingMetadata(root string) (map[string]bool, error) {
	out := map[string]bool{}
	path := filepath.Join(root, "exported.db")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("read pending export state: %w", err)
	}
	u := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query("SELECT DISTINCT stream FROM pending_metadata_files")
	if err != nil {
		return nil, fmt.Errorf("read pending export metadata: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if !retentionKnownStream(s) {
			return nil, fmt.Errorf("unknown pending metadata stream %q", s)
		}
		out[s] = true
	}
	return out, rows.Err()
}

func retentionBundleFile(path string) (string, int64, bool) {
	name := filepath.Base(path)
	for _, suffix := range bundleSuffixes() {
		if strings.HasSuffix(name, suffix) {
			stream, seq, ok := parseBundleName(strings.TrimSuffix(name, suffix) + ".manifest.json")
			return stream, seq, ok && retentionKnownStream(stream) && seq > 0
		}
	}
	return "", 0, false
}

func retentionDirectoryFiles(ctx context.Context, dir string) ([]recoveryRetentionFile, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []recoveryRetentionFile
	for _, e := range entries {
		file, err := retentionFingerprint(ctx, filepath.Join(dir, e.Name()), false)
		if err != nil {
			return nil, err
		}
		out = append(out, file)
	}
	return out, nil
}

func retentionFingerprint(ctx context.Context, path string, allowMissing bool) (recoveryRetentionFile, error) {
	out := recoveryRetentionFile{Path: path}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	st, err := os.Lstat(path)
	if allowMissing && errors.Is(err, os.ErrNotExist) {
		out.Missing = true
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !st.Mode().IsRegular() {
		return out, fmt.Errorf("retention input is not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	out.Size, out.SHA256, err = hashRetentionReader(ctx, f)
	if err != nil {
		return out, err
	}
	if out.Size != st.Size() {
		return out, fmt.Errorf("retention input changed while hashing: %s", path)
	}
	return out, nil
}

func hashRetentionReader(ctx context.Context, r io.Reader) (int64, string, error) {
	hash := sha256.New()
	buf := make([]byte, 128<<10)
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return n, "", err
		}
		read, err := r.Read(buf)
		if read > 0 {
			_, _ = hash.Write(buf[:read])
			n += int64(read)
		}
		if errors.Is(err, io.EOF) {
			return n, hex.EncodeToString(hash.Sum(nil)), nil
		}
		if err != nil {
			return n, "", err
		}
	}
}

func retentionPlanID(plan recoveryRetentionPlan) (string, error) {
	plan.ID = ""
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func validRetentionPlanID(plan recoveryRetentionPlan) bool {
	id, err := retentionPlanID(plan)
	return err == nil && plan.Format == 1 && plan.ID == id
}

// applyRecoveryRetention must run with the low root and export spool exclusively
// locked. Journal and sequence floors are synced before deleting any archive
// bytes. Repeating this exact plan safely resumes interrupted deletion.
func applyRecoveryRetention(ctx context.Context, opts retentionOptions, plan recoveryRetentionPlan) error {
	opts, err := normalizeRetentionOptions(opts)
	if err != nil {
		return err
	}
	if err := matchRetentionOptions(opts, plan); err != nil {
		return err
	}
	journalPath := filepath.Join(recoveryRetentionJournalDir(opts.Root), "plan-"+plan.ID+".json")
	journal, err := prepareRetentionJournal(ctx, opts, plan, journalPath)
	if err != nil {
		return err
	}
	if journal.Complete {
		return nil
	}
	if err := persistRetentionLedger(opts.Root, plan); err != nil {
		return err
	}
	if err := deleteRetentionCandidates(ctx, plan); err != nil {
		return err
	}
	journal.Complete = true
	return writeJSONAtomic(journalPath, journal, 0o600)
}

func matchRetentionOptions(opts retentionOptions, plan recoveryRetentionPlan) error {
	if !validRetentionPlanID(plan) {
		return errors.New("retention plan ID does not match its contents")
	}
	keyHash := sha256.Sum256(opts.PublicKey)
	if plan.Root != opts.Root || plan.ExportDir != opts.ExportDir || plan.KeyFingerprint != hex.EncodeToString(keyHash[:]) || plan.AllowBootstrap != opts.AllowBootstrap || !reflect.DeepEqual(plan.ReceiverFloors, opts.ReceiverFloors) {
		return errors.New("retention options do not match the saved plan")
	}
	cpPaths := make([]string, 0, len(plan.Checkpoints))
	for _, cp := range plan.Checkpoints {
		cpPaths = append(cpPaths, cp.Path)
	}
	if !reflect.DeepEqual(cpPaths, opts.Checkpoints) {
		return errors.New("retained checkpoints differ from the saved plan")
	}
	return nil
}

func prepareRetentionJournal(ctx context.Context, opts retentionOptions, plan recoveryRetentionPlan, journalPath string) (recoveryRetentionJournal, error) {
	var journal recoveryRetentionJournal
	err := readRetentionJSON(journalPath, &journal)
	if err == nil {
		if journal.Format != 1 || !validRetentionPlanID(journal.Plan) || journal.Plan.ID != plan.ID {
			return journal, errors.New("retention journal does not match the saved plan")
		}
		if err := syncDirectories(fsyncDir, filepath.Dir(journalPath)); err != nil {
			return journal, err
		}
		if journal.Complete {
			return journal, nil
		}
		return journal, validateRetentionResume(ctx, opts, plan)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return journal, err
	}
	fresh, err := planRecoveryRetention(ctx, opts)
	if err != nil {
		return journal, err
	}
	if fresh.ID != plan.ID {
		return journal, errors.New("retention plan is stale; regenerate and review the plan")
	}
	journal = recoveryRetentionJournal{Format: 1, Plan: plan}
	if len(plan.Candidates) == 0 {
		journal.Complete = true
		return journal, nil
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		return journal, err
	}
	return journal, writeJSONAtomic(journalPath, journal, 0o600)
}

func deleteRetentionCandidates(ctx context.Context, plan recoveryRetentionPlan) error {
	for _, file := range plan.Candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := retentionFingerprint(ctx, file.Path, true)
		if err != nil {
			return err
		}
		if current.Missing {
			continue
		}
		if current != file {
			return fmt.Errorf("planned archive file changed: %s", file.Path)
		}
		if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDirectories(fsyncDir, filepath.Join(plan.Root, "bundles"))
}

func persistRetentionLedger(root string, plan recoveryRetentionPlan) error {
	ledger, err := advancedRetentionLedger(plan)
	if err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(root, "recovery-ledger.json"), ledger, 0o600)
}

func advancedRetentionLedger(plan recoveryRetentionPlan) (recoveryLedger, error) {
	ledger := recoveryLedger{Format: 1, NextSequences: copyInt64Map(plan.PreviousLedger.NextSequences), PrunedThrough: copyInt64Map(plan.PreviousLedger.PrunedThrough)}
	if ledger.NextSequences == nil || ledger.PrunedThrough == nil {
		return ledger, errors.New("retention plan has an invalid prior ledger")
	}
	for stream, tip := range plan.Tips {
		if tip == math.MaxInt64 {
			return ledger, errors.New("sequence space exhausted")
		}
		ledger.NextSequences[stream] = max(ledger.NextSequences[stream], tip+1)
	}
	for stream, cutoff := range plan.Cutoffs {
		ledger.PrunedThrough[stream] = max(ledger.PrunedThrough[stream], cutoff)
	}
	return ledger, nil
}

func validateRetentionResume(ctx context.Context, opts retentionOptions, plan recoveryRetentionPlan) error {
	expected, err := verifyRetentionResumeInputs(ctx, plan)
	if err != nil {
		return err
	}
	if err := verifyRetentionResumeLedger(ctx, plan, expected); err != nil {
		return err
	}
	if err := verifyRetentionResumeDirectories(ctx, plan, expected); err != nil {
		return err
	}
	for _, cp := range plan.Checkpoints {
		artifact, err := verifyRecoveryArtifact(ctx, cp.Path, opts.PublicKey, cp.Digest)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(artifact.Manifest.Streams, cp.Streams) {
			return errors.New("retained checkpoint cursor changed")
		}
	}
	return nil
}

func verifyRetentionResumeInputs(ctx context.Context, plan recoveryRetentionPlan) (map[string]recoveryRetentionFile, error) {
	candidates := map[string]bool{}
	expected := map[string]recoveryRetentionFile{}
	for _, f := range plan.Candidates {
		candidates[f.Path] = true
	}
	for _, f := range plan.Inputs {
		expected[f.Path] = f
	}
	ledgerPath := filepath.Join(plan.Root, "recovery-ledger.json")
	for _, before := range plan.Inputs {
		if before.Path == ledgerPath {
			continue
		}
		current, err := retentionFingerprint(ctx, before.Path, true)
		if err != nil {
			return nil, err
		}
		if current.Missing && candidates[before.Path] {
			continue
		}
		if current != before {
			return nil, fmt.Errorf("retention resume input changed: %s", before.Path)
		}
	}
	return expected, nil
}

// The only allowed new state is this plan's monotonically advanced ledger.
func verifyRetentionResumeLedger(ctx context.Context, plan recoveryRetentionPlan, expected map[string]recoveryRetentionFile) error {
	ledgerPath := filepath.Join(plan.Root, "recovery-ledger.json")
	current, err := retentionFingerprint(ctx, ledgerPath, true)
	if err != nil {
		return err
	}
	if current == expected[ledgerPath] {
		return nil
	}
	ledger, err := loadRecoveryLedger(plan.Root)
	if err != nil {
		return err
	}
	want, err := advancedRetentionLedger(plan)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(ledger, want) {
		return errors.New("retention ledger changed since this plan")
	}
	return nil
}

func verifyRetentionResumeDirectories(ctx context.Context, plan recoveryRetentionPlan, expected map[string]recoveryRetentionFile) error {
	dirs := []string{filepath.Join(plan.Root, "bundles"), plan.ExportDir}
	for _, cp := range plan.Checkpoints {
		dirs = append(dirs, cp.Path)
	}
	for _, dir := range dirs {
		files, err := retentionDirectoryFiles(ctx, dir)
		if err != nil {
			return err
		}
		for _, file := range files {
			if before, ok := expected[file.Path]; !ok || before != file {
				return fmt.Errorf("retention resume input changed: %s", file.Path)
			}
		}
	}
	return nil
}
