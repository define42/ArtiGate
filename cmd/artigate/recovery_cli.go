package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func runRecovery(group string, args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(args) == 0 {
		printRecoveryUsage(stderr, group)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		printRecoveryUsage(stdout, group)
		return 0
	}
	err := executeRecoveryCommand(ctx, group, args[0], args[1:], stdout, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", group, args[0], err)
		return 1
	}
	return 0
}

func executeRecoveryCommand(ctx context.Context, group, action string, args []string, stdout, stderr io.Writer) error {
	switch {
	case group == "backup" && action == "create":
		return recoveryBackupCreateCommand(ctx, args, stdout, stderr)
	case group == "checkpoint" && action == "create":
		return recoveryCheckpointCreateCommand(ctx, args, stdout, stderr)
	case (group == "backup" || group == "checkpoint") && (action == "verify" || action == "restore"):
		return recoveryReadCommand(ctx, group, action, args, stdout, stderr)
	case group == "retention" && action == "plan":
		return recoveryRetentionPlanCommand(ctx, args, stdout, stderr)
	case group == "retention" && action == "apply":
		return recoveryRetentionApplyCommand(ctx, args, stdout, stderr)
	default:
		printRecoveryUsage(stderr, group)
		return fmt.Errorf("unknown recovery command %q", action)
	}
}

func printRecoveryUsage(w io.Writer, group string) {
	switch group {
	case "backup":
		fmt.Fprintln(w, `Usage:
  artigate backup create --role high|low --root ROOT --output BACKUP_DIR
  artigate backup verify --input BACKUP_DIR --digest SHA256
  artigate backup restore --input BACKUP_DIR --digest SHA256 --root NEW_ROOT
Stop the server first. Keep the printed manifest digest in trusted backup storage.
Low-side restore also requires --confirm-low-state-current: no later exports may exist.
Configuration, signing keys, credentials and external transport directories are managed separately.`)
	case "checkpoint":
		fmt.Fprintln(w, `Usage:
  artigate checkpoint create --root LOW_ROOT --private-key KEY --output CHECKPOINT_DIR [--base DIR --base-digest SHA256]
  artigate checkpoint verify --input CHECKPOINT_DIR --public-key KEY [--digest SHA256]
  artigate checkpoint restore --input CHECKPOINT_DIR --public-key KEY --digest SHA256 --root NEW_HIGH_ROOT
Creation requires a stopped low side. Restore requires a nonexistent destination.
Transfer the complete checkpoint directory through your file carrier before restoring.`)
	case "retention":
		fmt.Fprintln(w, `Usage:
  artigate retention plan --root LOW_ROOT --export-dir SPOOL --public-key KEY --checkpoint DIR --output PLAN.json
      [--checkpoint OTHER_DIR] [--receiver-floor STREAM=SEQUENCE] [--allow-bootstrap]
  artigate retention apply --plan PLAN.json --public-key KEY
Stop the low side first. Unknown receiver progress retains history unless --allow-bootstrap
explicitly accepts checkpoint recovery for receivers behind the retained history.
List every checkpoint that must remain replayable and the oldest supported receiver position per stream.`)
	}
}

func recoveryFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseRecoveryFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	return nil
}

func recoveryBackupCreateCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := recoveryFlags("backup create", stderr)
	root := fs.String("root", "", "stopped server storage root (required)")
	role := fs.String("role", "", "high or low (required)")
	output := fs.String("output", "", "new backup directory outside the storage root (required)")
	if err := parseRecoveryFlags(fs, args); err != nil {
		return err
	}
	if *root == "" || *output == "" || (*role != "low" && *role != "high") {
		return errors.New("--root, --output and --role high|low are required")
	}
	release, err := lockExistingRecoveryRoot(*root)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	artifact, err := createRecoveryBackup(ctx, *role, *root, *output)
	if err != nil {
		return err
	}
	return printRecoveryArtifact(stdout, *output, artifact)
}

func recoveryCheckpointCreateCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := recoveryFlags("checkpoint create", stderr)
	opts := checkpointOptions{}
	fs.StringVar(&opts.Root, "root", "", "stopped low-side storage root (required)")
	fs.StringVar(&opts.Output, "output", "", "new checkpoint directory outside the storage root (required)")
	fs.StringVar(&opts.Base, "base", "", "previous checkpoint for replay after archive retention")
	fs.StringVar(&opts.BaseDigest, "base-digest", "", "trusted SHA256 digest of the base manifest")
	key := fs.String("private-key", "", "low-side signing key (required)")
	if err := parseRecoveryFlags(fs, args); err != nil {
		return err
	}
	if opts.Root == "" || opts.Output == "" || *key == "" {
		return errors.New("--root, --output and --private-key are required")
	}
	if opts.Base != "" && opts.BaseDigest == "" {
		return errors.New("--base requires --base-digest to identify the intended recovery point")
	}
	priv, err := readPrivateKey(*key)
	if err != nil {
		return err
	}
	opts.PrivateKey = priv
	release, err := lockExistingRecoveryRoot(opts.Root)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	artifact, err := createRecoveryCheckpoint(ctx, opts)
	if err != nil {
		return err
	}
	return printRecoveryArtifact(stdout, opts.Output, artifact)
}

type recoveryReadOptions struct {
	Input, Digest, Root, Key string
	ConfirmLow               bool
	Signing                  HighConfig
}

func parseRecoveryReadOptions(group, action string, args []string, stderr io.Writer) (recoveryReadOptions, error) {
	opts := recoveryReadOptions{}
	fs := recoveryFlags(group+" "+action, stderr)
	fs.StringVar(&opts.Input, "input", "", "backup or checkpoint directory (required)")
	fs.StringVar(&opts.Digest, "digest", "", "trusted SHA256 digest of manifest.json (required for restore and backups)")
	fs.StringVar(&opts.Root, "root", "", "nonexistent destination storage root (restore only)")
	fs.StringVar(&opts.Key, "public-key", "", "trusted low-side verification key (checkpoint only)")
	fs.BoolVar(&opts.ConfirmLow, "confirm-low-state-current", false, "confirm this low-side backup contains the latest exported sequence state; no later exports exist")
	fs.StringVar(&opts.Signing.AptGPGKey, "apt-gpg-key", "", "local GPG key for restored APT metadata (checkpoint restore only)")
	fs.StringVar(&opts.Signing.RpmGPGKey, "rpm-gpg-key", "", "local GPG key for restored RPM metadata (checkpoint restore only)")
	fs.StringVar(&opts.Signing.ApkRSAKey, "apk-rsa-key", "", "local RSA private key for restored APK indexes (checkpoint restore only)")
	fs.StringVar(&opts.Signing.ApkKeyName, "apk-key-name", "artigate.rsa.pub", "APK public key filename (checkpoint restore only)")
	if err := parseRecoveryFlags(fs, args); err != nil {
		return opts, err
	}
	if opts.Input == "" || ((action == "restore" || group == "backup") && opts.Digest == "") {
		return opts, errors.New("--input and a trusted --digest are required")
	}
	if (action == "restore") != (opts.Root != "") {
		return opts, errors.New("--root is required for restore and is not accepted for verify")
	}
	if err := validateRecoverySigningFlags(fs, group, action); err != nil {
		return opts, err
	}
	return opts, nil
}

func validateRecoverySigningFlags(fs *flag.FlagSet, group, action string) error {
	if group == "checkpoint" && action == "restore" {
		return nil
	}
	var err error
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "apt-gpg-key", "rpm-gpg-key", "apk-rsa-key", "apk-key-name":
			err = errors.New("repository signing flags apply only to checkpoint restore")
		}
	})
	return err
}

func recoveryReadCommand(ctx context.Context, group, action string, args []string, stdout, stderr io.Writer) error {
	opts, err := parseRecoveryReadOptions(group, action, args, stderr)
	if err != nil {
		return err
	}
	pub, err := recoveryReadKey(group, opts.Key)
	if err != nil {
		return err
	}
	artifact, err := verifyRecoveryArtifact(ctx, opts.Input, pub, opts.Digest)
	if err != nil {
		return err
	}
	if err := validateRecoveryReadOptions(opts, group, action, artifact.Manifest); err != nil {
		return err
	}
	directory := opts.Input
	if action == "restore" {
		prepare := func(ctx context.Context, stage string) error {
			return prepareRecoveryRepository(ctx, stage, opts.Signing)
		}
		artifact, err = restoreRecoveryArtifactPrepared(ctx, opts.Input, opts.Root, pub, opts.Digest, prepare)
		if err != nil {
			return err
		}
		directory = opts.Root
	}
	return printRecoveryArtifact(stdout, directory, artifact)
}

func validateRecoveryReadOptions(opts recoveryReadOptions, group, action string, manifest recoveryManifest) error {
	if manifest.Kind != group {
		return fmt.Errorf("expected %s, received %s", group, manifest.Kind)
	}
	if action == "restore" && manifest.Role == "low" && !opts.ConfirmLow {
		return errors.New("low-side restore requires --confirm-low-state-current; an older backup can reuse already exported sequence numbers; reconcile later archives and sequence records before restoring")
	}
	if opts.ConfirmLow && (action != "restore" || manifest.Role != "low") {
		return errors.New("--confirm-low-state-current applies only to low-side backup restore")
	}
	return nil
}

func recoveryReadKey(group, key string) (ed25519.PublicKey, error) {
	if group == "checkpoint" {
		if key == "" {
			return nil, errors.New("--public-key is required for checkpoints")
		}
		return readPublicKey(key)
	}
	if key != "" {
		return nil, errors.New("backup verification uses --digest; --public-key is only for checkpoints")
	}
	return nil, nil
}

func lockExistingRecoveryRoot(root string) (func() error, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, errors.New("storage root must be an existing directory")
	}
	return acquireRecoveryRootLock(root)
}

func printRecoveryArtifact(w io.Writer, directory string, artifact recoveryArtifact) error {
	var total int64
	for _, part := range artifact.Manifest.Parts {
		total += part.Size
	}
	summary := struct {
		Directory string           `json:"directory"`
		Digest    string           `json:"manifest_sha256"`
		Kind      string           `json:"kind"`
		Role      string           `json:"role"`
		Streams   map[string]int64 `json:"streams"`
		Files     int              `json:"files"`
		Parts     int              `json:"parts"`
		Bytes     int64            `json:"bytes"`
	}{
		directory, artifact.Digest, artifact.Manifest.Kind, artifact.Manifest.Role,
		artifact.Manifest.Streams, len(artifact.Manifest.Files), len(artifact.Manifest.Parts), total,
	}
	return json.NewEncoder(w).Encode(summary)
}

type recoveryStringFlags []string

func (v *recoveryStringFlags) String() string { return strings.Join(*v, ",") }

func (v *recoveryStringFlags) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("empty value")
	}
	*v = append(*v, value)
	return nil
}

func recoveryReceiverFloors(values []string) (map[string]int64, error) {
	floors := make(map[string]int64, len(values))
	for _, value := range values {
		stream, number, ok := strings.Cut(value, "=")
		seq, err := strconv.ParseInt(number, 10, 64)
		if !ok || !isKnownStream(stream) || err != nil || seq < 0 {
			return nil, fmt.Errorf("invalid receiver floor %q; use a known stream=nonnegative-sequence", value)
		}
		if _, exists := floors[stream]; exists {
			return nil, fmt.Errorf("duplicate receiver floor for %s; provide the oldest supported receiver position", stream)
		}
		floors[stream] = seq
	}
	return floors, nil
}

func recoveryAbsolutePaths(paths []string) ([]string, error) {
	out := make([]string, len(paths))
	for i, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		out[i] = abs
	}
	return out, nil
}
