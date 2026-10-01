package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func retentionTestFixture(t *testing.T) (retentionOptions, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := newTestKeys(t)
	root := checkpointTestRoot(t, map[string]int64{streamGo: 1})
	store, err := OpenExportedStore(filepath.Join(root, "exported.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "bundles")
	writeSignedBundle(t, archive, priv, 1, 0, []moduleSpec{{"example.com/retention", "v1.0.0"}})
	cp := filepath.Join(t.TempDir(), "checkpoint")
	if _, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: root, Output: cp, PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	writeSignedBundle(t, archive, priv, 2, 1, []moduleSpec{{"example.com/retention", "v1.1.0"}})
	checkpointTestState(t, root, map[string]int64{streamGo: 2})
	return retentionOptions{Root: root, ExportDir: t.TempDir(), Checkpoints: []string{cp}, PublicKey: pub, AllowBootstrap: true}, priv
}

func TestRecoveryRetentionPlansPreserveRecoveryPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*testing.T, *retentionOptions, ed25519.PrivateKey)
		want   int64
	}{
		{name: "checkpoint bootstrap", want: 1},
		{name: "unknown receivers", change: func(_ *testing.T, o *retentionOptions, _ ed25519.PrivateKey) { o.AllowBootstrap = false }, want: 0},
		{name: "receiver at zero", change: func(_ *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			o.ReceiverFloors = map[string]int64{streamGo: 0}
		}, want: 0},
		{name: "confirmed receiver", change: func(_ *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			o.AllowBootstrap = false
			o.ReceiverFloors = map[string]int64{streamGo: 1}
		}, want: 1},
		{name: "oldest retained checkpoint", change: func(t *testing.T, o *retentionOptions, priv ed25519.PrivateKey) {
			cp := filepath.Join(t.TempDir(), "newer")
			if _, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: o.Root, Output: cp, PrivateKey: priv}); err != nil {
				t.Fatal(err)
			}
			o.Checkpoints = append(o.Checkpoints, cp)
		}, want: 1},
		{name: "pending outbound bundle", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			for _, suffix := range bundleSuffixes() {
				name := bundleIDFor(streamGo, 1) + suffix
				if err := copyFileAtomic(filepath.Join(o.Root, "bundles", name), filepath.Join(o.ExportDir, name), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}, want: 0},
		{name: "default heartbeat", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			writeFile(t, filepath.Join(o.ExportDir, diodeHeartbeatFileName), []byte("pinned heartbeat"))
		}, want: 1},
		{name: "pending metadata", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			store, err := OpenExportedStore(filepath.Join(o.Root, "exported.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			if err := store.MarkPendingMetadata(streamGo, []ManifestFile{{Path: "pending", SHA256: strings.Repeat("a", 64), Size: 1}}); err != nil {
				t.Fatal(err)
			}
		}, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts, priv := retentionTestFixture(t)
			if tc.change != nil {
				tc.change(t, &opts, priv)
			}
			plan, err := planRecoveryRetention(t.Context(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Cutoffs[streamGo] != tc.want {
				t.Fatalf("cutoff = %d, want %d", plan.Cutoffs[streamGo], tc.want)
			}
			if len(plan.Candidates) != int(tc.want)*3 {
				t.Fatalf("candidates = %d, want %d", len(plan.Candidates), tc.want*3)
			}
			if !validRetentionPlanID(plan) {
				t.Fatal("plan has invalid content ID")
			}
		})
	}
}

func TestRecoveryRetentionRejectsUnsafePlans(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*testing.T, *retentionOptions, ed25519.PrivateKey)
	}{
		{name: "missing checkpoint", change: func(_ *testing.T, o *retentionOptions, _ ed25519.PrivateKey) { o.Checkpoints = nil }},
		{name: "missing replay bundle", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			for _, suffix := range bundleSuffixes() {
				if err := os.Remove(filepath.Join(o.Root, "bundles", bundleIDFor(streamGo, 2)+suffix)); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "partial archive", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			if err := os.Remove(filepath.Join(o.Root, "bundles", bundleIDFor(streamGo, 2)+".tar.gz")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt retained receiver tail", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			o.ReceiverFloors = map[string]int64{streamGo: 0}
			writeFile(t, filepath.Join(o.Root, "bundles", bundleIDFor(streamGo, 1)+".tar.gz"), []byte("broken old archive"))
		}},
		{name: "wrong key", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			pub, _ := newTestKeys(t)
			o.PublicKey = pub
		}},
		{name: "future receiver", change: func(_ *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			o.ReceiverFloors = map[string]int64{streamGo: 3}
		}},
		{name: "checkpoint inside archive", change: func(t *testing.T, o *retentionOptions, _ ed25519.PrivateKey) {
			inside := filepath.Join(o.Root, "bundles", "checkpoint")
			if err := os.Mkdir(inside, 0o700); err != nil {
				t.Fatal(err)
			}
			o.Checkpoints = []string{inside}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts, priv := retentionTestFixture(t)
			tc.change(t, &opts, priv)
			if _, err := planRecoveryRetention(t.Context(), opts); err == nil {
				t.Fatal("unsafe retention plan succeeded")
			}
		})
	}
}

func TestRecoveryRetentionApplyRejectsChangedInputs(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"plan", "archive", "state", "checkpoint", "spool"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			opts, _ := retentionTestFixture(t)
			plan, err := planRecoveryRetention(t.Context(), opts)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "plan":
				plan.Cutoffs[streamGo] = 2
			case "archive":
				writeFile(t, plan.Candidates[0].Path, []byte("modified archive manifest"))
			case "state":
				checkpointTestState(t, opts.Root, map[string]int64{streamGo: 3})
			case "checkpoint":
				writeFile(t, filepath.Join(opts.Checkpoints[0], "manifest.json"), []byte("modified checkpoint"))
			case "spool":
				writeFile(t, filepath.Join(opts.ExportDir, diodeHeartbeatFileName), []byte("new heartbeat"))
			}
			if err := applyRecoveryRetention(t.Context(), opts, plan); err == nil {
				t.Fatal("changed inputs accepted")
			}
			if !bundleCompleteInDir(filepath.Join(opts.Root, "bundles"), bundleIDFor(streamGo, 1)) {
				t.Fatal("rejected apply deleted archive")
			}
		})
	}
}

func TestRecoveryRetentionApplyPersistsSequenceFloor(t *testing.T) {
	t.Parallel()
	opts, _ := retentionTestFixture(t)
	plan, err := planRecoveryRetention(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var saved recoveryRetentionPlan
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	rebound, err := recoveryRetentionOptions(saved, opts.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRecoveryRetention(t.Context(), rebound, saved); err != nil {
		t.Fatal(err)
	}
	if bundleCompleteInDir(filepath.Join(opts.Root, "bundles"), bundleIDFor(streamGo, 1)) {
		t.Fatal("old bundle not pruned")
	}
	if !bundleCompleteInDir(filepath.Join(opts.Root, "bundles"), bundleIDFor(streamGo, 2)) {
		t.Fatal("required tail pruned")
	}
	if err := applyRecoveryRetention(t.Context(), rebound, saved); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	checkpointTestState(t, opts.Root, map[string]int64{streamGo: 0})
	low := &LowServer{cfg: LowConfig{Root: opts.Root, ExportDir: opts.ExportDir}, statePath: filepath.Join(opts.Root, "low-state.json"), state: LowState{Sequences: map[string]int64{}}}
	if err := low.loadState(); err != nil {
		t.Fatal(err)
	}
	if seq, err := low.allocateSequence(streamGo); err != nil || seq != 3 {
		t.Fatalf("next sequence after stale state restore = %d, %v; want 3", seq, err)
	}
	if err := os.Remove(filepath.Join(opts.Root, "recovery-ledger.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := low.allocateSequence(streamGo); err == nil {
		t.Fatal("missing ledger permitted allocation after prune")
	}
}

func TestRecoveryRetentionResumesInterruptedDeletion(t *testing.T) {
	t.Parallel()
	for _, crash := range []string{"before journal rename", "before ledger", "after first unlink"} {
		t.Run(crash, func(t *testing.T) {
			t.Parallel()
			opts, _ := retentionTestFixture(t)
			plan, err := planRecoveryRetention(t.Context(), opts)
			if err != nil {
				t.Fatal(err)
			}
			journal := recoveryRetentionJournal{Format: 1, Plan: plan}
			dir := recoveryRetentionJournalDir(opts.Root)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(dir, "plan-"+plan.ID+".json")
			if crash == "before journal rename" {
				journalPath += ".tmp"
			}
			if err := writeJSONAtomic(journalPath, journal, 0o600); err != nil {
				t.Fatal(err)
			}
			if crash == "after first unlink" {
				if err := persistRetentionLedger(opts.Root, plan); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(plan.Candidates[0].Path); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkRecoveryRetentionIdle(opts.Root); (err != nil) != (crash != "before journal rename") {
				t.Fatalf("unfinished prune startup check = %v for %s", err, crash)
			}
			if err := applyRecoveryRetention(t.Context(), opts, plan); err != nil {
				t.Fatalf("resume failed: %v", err)
			}
			if err := checkRecoveryRetentionIdle(opts.Root); err != nil {
				t.Fatal(err)
			}
			for _, file := range plan.Candidates {
				if _, err := os.Stat(file.Path); !os.IsNotExist(err) {
					t.Fatalf("candidate remains after resume: %s: %v", file.Path, err)
				}
			}
		})
	}
}

func TestRecoveryRetentionResumeRejectsChangedTail(t *testing.T) {
	t.Parallel()
	opts, _ := retentionTestFixture(t)
	plan, err := planRecoveryRetention(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	dir := recoveryRetentionJournalDir(opts.Root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := recoveryRetentionJournal{Format: 1, Plan: plan}
	if err := writeJSONAtomic(filepath.Join(dir, "plan-"+plan.ID+".json"), journal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistRetentionLedger(opts.Root, plan); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(opts.Root, "bundles", bundleIDFor(streamGo, 2)+".tar.gz"), []byte("changed replay tail"))
	if err := applyRecoveryRetention(t.Context(), opts, plan); err == nil {
		t.Fatal("changed tail allowed interrupted deletion to resume")
	}
	if !bundleCompleteInDir(filepath.Join(opts.Root, "bundles"), bundleIDFor(streamGo, 1)) {
		t.Fatal("invalid resume deleted archive")
	}
}

func TestRecoveryRetentionLedgerRejectsCorruptionAndRollback(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"corrupt", "unknown stream", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			opts, _ := retentionTestFixture(t)
			plan, err := planRecoveryRetention(t.Context(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := applyRecoveryRetention(t.Context(), opts, plan); err != nil {
				t.Fatal(err)
			}
			ledger := recoveryLedger{Format: 1, NextSequences: map[string]int64{streamGo: 1}, PrunedThrough: map[string]int64{}}
			if kind == "unknown stream" {
				ledger.NextSequences = map[string]int64{"unknown": 3}
			}
			if err := writeJSONAtomic(filepath.Join(opts.Root, "recovery-ledger.json"), ledger, 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "corrupt" {
				writeFile(t, filepath.Join(opts.Root, "recovery-ledger.json"), []byte("broken"))
			}
			if _, err := loadRecoveryLedger(opts.Root); err == nil {
				t.Fatal("invalid ledger accepted")
			}
		})
	}
}

func TestRecoveryRetentionAdvancesCheckpointAcrossPruneCycles(t *testing.T) {
	t.Parallel()
	opts, priv := retentionTestFixture(t)
	first, err := planRecoveryRetention(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRecoveryRetention(t.Context(), opts, first); err != nil {
		t.Fatal(err)
	}
	oldCheckpoint := opts.Checkpoints[0]
	newCheckpoint := filepath.Join(t.TempDir(), "new-checkpoint")
	if _, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{
		Root: opts.Root, Output: newCheckpoint, Base: oldCheckpoint, PrivateKey: priv,
	}); err != nil {
		t.Fatal(err)
	}
	opts.Checkpoints = []string{newCheckpoint}
	second, err := planRecoveryRetention(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Cutoffs[streamGo] != 2 || len(second.Candidates) != 3 {
		t.Fatalf("second prune plan cutoff %d, candidates %d", second.Cutoffs[streamGo], len(second.Candidates))
	}
	if err := applyRecoveryRetention(t.Context(), opts, second); err != nil {
		t.Fatal(err)
	}
	ledger, err := loadRecoveryLedger(opts.Root)
	if err != nil || ledger.NextSequences[streamGo] != 3 || ledger.PrunedThrough[streamGo] != 2 {
		t.Fatalf("advanced recovery ledger = %+v: %v", ledger, err)
	}
	// The operator must not promise that a retired restore point still has
	// its replay tail once the newer recovery baseline has been applied.
	opts.Checkpoints = []string{oldCheckpoint, newCheckpoint}
	if _, err := planRecoveryRetention(t.Context(), opts); err == nil {
		t.Fatal("retired checkpoint with a pruned tail became eligible again")
	}
}
