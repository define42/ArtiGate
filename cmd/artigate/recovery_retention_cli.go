package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func recoveryRetentionPlanCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := recoveryFlags("retention plan", stderr)
	opts := retentionOptions{}
	var checkpoints, floors recoveryStringFlags
	fs.StringVar(&opts.Root, "root", "", "stopped low-side storage root (required)")
	fs.StringVar(&opts.ExportDir, "export-dir", "", "actual outbound spool (required)")
	fs.BoolVar(&opts.AllowBootstrap, "allow-bootstrap", false, "accept checkpoint bootstrap for receivers whose progress is unknown")
	fs.Var(&checkpoints, "checkpoint", "retained checkpoint directory; repeat for every supported restore point")
	fs.Var(&floors, "receiver-floor", "oldest supported receiver position as stream=sequence; repeat per stream")
	key := fs.String("public-key", "", "trusted low-side verification key (required)")
	output := fs.String("output", "", "new retention plan JSON file (required)")
	if err := parseRecoveryFlags(fs, args); err != nil {
		return err
	}
	if opts.Root == "" || opts.ExportDir == "" || *key == "" || *output == "" || len(checkpoints) == 0 {
		return errors.New("--root, --export-dir, --public-key, --checkpoint and --output are required")
	}
	if err := populateRetentionOptions(&opts, checkpoints, floors, *key); err != nil {
		return err
	}
	release, err := lockExistingRecoveryRoot(opts.Root)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	plan, err := planRecoveryRetention(ctx, opts)
	if err != nil {
		return err
	}
	if err := saveRecoveryPlan(*output, plan); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(plan)
}

func populateRetentionOptions(opts *retentionOptions, checkpoints, floors []string, key string) error {
	paths, err := recoveryAbsolutePaths(append([]string{opts.Root, opts.ExportDir}, checkpoints...))
	if err != nil {
		return err
	}
	opts.Root, opts.ExportDir, opts.Checkpoints = paths[0], paths[1], paths[2:]
	opts.ReceiverFloors, err = recoveryReceiverFloors(floors)
	if err != nil {
		return err
	}
	opts.PublicKey, err = readPublicKey(key)
	return err
}

func saveRecoveryPlan(path string, plan recoveryRetentionPlan) error {
	if err := validateRecoveryPlanOutput(path, plan); err != nil {
		return err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > 64<<20 {
		return errors.New("retention plan exceeds 64 MiB limit")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func validateRecoveryPlanOutput(path string, plan recoveryRetentionPlan) error {
	if err := recoveryCheckDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	protected := []string{plan.Root, plan.ExportDir}
	for _, checkpoint := range plan.Checkpoints {
		protected = append(protected, checkpoint.Path)
	}
	for _, input := range protected {
		if err := recoverySeparatePaths(input, path); err != nil {
			return fmt.Errorf("plan output must be outside recovery inputs: %w", err)
		}
	}
	return nil
}

func recoveryRetentionApplyCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := recoveryFlags("retention apply", stderr)
	input := fs.String("plan", "", "retention plan JSON file (required)")
	key := fs.String("public-key", "", "trusted low-side verification key (required)")
	if err := parseRecoveryFlags(fs, args); err != nil {
		return err
	}
	if *input == "" || *key == "" {
		return errors.New("--plan and --public-key are required")
	}
	plan, err := readRecoveryPlan(*input)
	if err != nil {
		return err
	}
	pub, err := readPublicKey(*key)
	if err != nil {
		return err
	}
	opts, err := recoveryRetentionOptions(plan, pub)
	if err != nil {
		return err
	}
	release, err := lockExistingRecoveryRoot(opts.Root)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	if err := applyRecoveryRetention(ctx, opts, plan); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Retention plan applied; retained recovery paths verified.")
	return err
}

func readRecoveryPlan(path string) (recoveryRetentionPlan, error) {
	data, err := readFileLimit(path, 64<<20)
	if err != nil {
		return recoveryRetentionPlan{}, err
	}
	var plan recoveryRetentionPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return recoveryRetentionPlan{}, fmt.Errorf("decode retention plan: %w", err)
	}
	return plan, nil
}
