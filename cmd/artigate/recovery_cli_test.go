package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryBackupCLI(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"example.com/backup", "v1.0.0"}})
	mustImportNext(t, hs)
	backup := filepath.Join(t.TempDir(), "backup")
	args := []string{"create", "--role", "high", "--root", hs.cfg.Root, "--output", backup}
	var stdout, stderr bytes.Buffer
	release, err := acquireRecoveryRootLock(hs.cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	if code := runRecovery("backup", args, &stdout, &stderr); code == 0 {
		t.Fatal("backup succeeded while server lock was held")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runRecovery("backup", args, &stdout, &stderr); code != 0 {
		t.Fatalf("backup failed: %s", stderr.String())
	}
	var summary struct {
		Digest string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	stdout.Reset()
	stderr.Reset()
	if code := runRecovery("backup", []string{"restore", "--input", backup, "--digest", strings.Repeat("0", 64), "--root", target}, &stdout, &stderr); code == 0 {
		t.Fatal("restore accepted the wrong trusted digest")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed restore exposed a destination: %v", err)
	}
	stderr.Reset()
	if code := runRecovery("backup", []string{"restore", "--input", backup, "--digest", summary.Digest, "--root", target}, &stdout, &stderr); code != 0 {
		t.Fatalf("restore failed: %s", stderr.String())
	}
	restored, err := NewHighServer(HighConfig{Root: target, Landing: t.TempDir()}, pub)
	if err != nil {
		t.Fatal(err)
	}
	if restored.importedSequence(streamGo) != 1 || !restored.isComplete("example.com/backup", "v1.0.0") {
		t.Fatal("CLI backup did not preserve matching content and sequence state")
	}
	stderr.Reset()
	if code := runRecovery("backup", []string{"restore", "--input", backup, "--digest", summary.Digest, "--root", target}, &stdout, &stderr); code == 0 {
		t.Fatal("restore overwrote an existing receiver")
	}
}

func TestRecoveryCLIUsageAndReceiverFloors(t *testing.T) {
	for _, group := range []string{"backup", "checkpoint", "retention"} {
		var stdout, stderr bytes.Buffer
		if code := runRecovery(group, []string{"--help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("%s help failed: %s", group, stderr.String())
		}
		if code := runRecovery(group, nil, &stdout, &stderr); code != 2 {
			t.Fatalf("%s missing action exit = %d", group, code)
		}
		if code := runRecovery(group, []string{"unknown"}, &stdout, &stderr); code == 0 {
			t.Fatalf("%s accepted unknown action", group)
		}
	}
	for _, values := range [][]string{{"go=-1"}, {"unknown=1"}, {"go=1", "go=2"}, {"go"}, {"go=9223372036854775808"}} {
		if _, err := recoveryReceiverFloors(values); err == nil {
			t.Errorf("accepted invalid receiver floors %v", values)
		}
	}
	floors, err := recoveryReceiverFloors([]string{"go=0", "npm=32"})
	if err != nil || floors["go"] != 0 || floors["npm"] != 32 {
		t.Fatalf("valid receiver floors failed: %v: %v", floors, err)
	}
}

func TestRecoveryLowBackupCLIRequiresCurrentStateConfirmation(t *testing.T) {
	t.Parallel()
	_, priv := newTestKeys(t)
	root := checkpointTestRoot(t, map[string]int64{streamGo: 1})
	writeSignedBundle(t, filepath.Join(root, "bundles"), priv, 1, 0,
		[]moduleSpec{{"example.com/low-backup", "v1.0.0"}})
	// Backups preserve the database as opaque bytes, including database files
	// that need offline repair before a server can be restarted.
	database := []byte("low-side export database preserved byte for byte")
	writeFile(t, filepath.Join(root, "exported.db"), database)
	backup := filepath.Join(t.TempDir(), "low-backup")
	var stdout, stderr bytes.Buffer
	if code := runRecovery("backup", []string{
		"create", "--role", "low", "--root", root, "--output", backup,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("create low backup failed: %s", stderr.String())
	}
	var summary struct {
		Digest string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored-low")
	args := []string{"restore", "--input", backup, "--digest", summary.Digest, "--root", target}
	stdout.Reset()
	stderr.Reset()
	if code := runRecovery("backup", args, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "--confirm-low-state-current") {
		t.Fatalf("unconfirmed low restore exit = %d, stderr = %s", code, stderr.String())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("unconfirmed restore published a destination: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runRecovery("backup", append(args, "--confirm-low-state-current"), &stdout, &stderr); code != 0 {
		t.Fatalf("confirmed low restore failed: %s", stderr.String())
	}
	for _, relative := range []string{"low-state.json", "exported.db", "bundles/go-bundle-000001.manifest.json"} {
		want, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(target, relative))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("confirmed restore changed %s: %v", relative, err)
		}
	}
}

func TestRecoveryRetentionCLIPlanOutputKeepsInputsUnchanged(t *testing.T) {
	t.Parallel()
	for _, location := range []string{"root", "spool", "checkpoint", "outside"} {
		t.Run(location, func(t *testing.T) {
			t.Parallel()
			opts, _ := retentionTestFixture(t)
			key := filepath.Join(t.TempDir(), "public.key")
			if err := writeKeyFile(key, opts.PublicKey, 0o600); err != nil {
				t.Fatal(err)
			}
			outputDir := t.TempDir()
			switch location {
			case "root":
				outputDir = opts.Root
			case "spool":
				outputDir = opts.ExportDir
			case "checkpoint":
				outputDir = opts.Checkpoints[0]
			}
			output := filepath.Join(outputDir, "retention-plan.json")
			args := []string{
				"plan", "--root", opts.Root, "--export-dir", opts.ExportDir,
				"--checkpoint", opts.Checkpoints[0], "--public-key", key,
				"--allow-bootstrap", "--output", output,
			}
			var stdout, stderr bytes.Buffer
			code := runRecovery("retention", args, &stdout, &stderr)
			if location != "outside" {
				if code == 0 || !strings.Contains(stderr.String(), "outside recovery inputs") {
					t.Fatalf("overlapping plan exit = %d, stderr = %s", code, stderr.String())
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("rejected plan changed protected inputs: %v", err)
				}
				return
			}
			if code != 0 {
				t.Fatalf("external plan failed: %s", stderr.String())
			}
			info, err := os.Stat(output)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("saved plan permissions: %v, %v", info, err)
			}
			stdout.Reset()
			stderr.Reset()
			if code := runRecovery("retention", []string{"apply", "--plan", output, "--public-key", key}, &stdout, &stderr); code != 0 {
				t.Fatalf("saved external plan could not be applied: %s", stderr.String())
			}
			archive := filepath.Join(opts.Root, "bundles")
			if bundleCompleteInDir(archive, bundleIDFor(streamGo, 1)) || !bundleCompleteInDir(archive, bundleIDFor(streamGo, 2)) {
				t.Fatal("CLI apply did not preserve the checkpoint replay tail")
			}
		})
	}
}

func TestRecoveryCLIRejectsMisplacedRepositorySigningFlags(t *testing.T) {
	t.Parallel()
	commands := []struct {
		name, group string
		args        []string
		message     string
	}{
		{
			name: "backup create", group: "backup", args: []string{"create"},
			message: "flag provided but not defined",
		},
		{
			name: "backup verify", group: "backup",
			args:    []string{"verify", "--input", "unused", "--digest", strings.Repeat("0", 64)},
			message: "repository signing flags apply only to checkpoint restore",
		},
		{
			name: "backup restore", group: "backup",
			args:    []string{"restore", "--input", "unused", "--digest", strings.Repeat("0", 64), "--root", "unused-target"},
			message: "repository signing flags apply only to checkpoint restore",
		},
		{
			name: "checkpoint verify", group: "checkpoint", args: []string{"verify", "--input", "unused"},
			message: "repository signing flags apply only to checkpoint restore",
		},
	}
	for _, command := range commands {
		for _, signingFlag := range []string{"--apt-gpg-key", "--rpm-gpg-key", "--apk-rsa-key", "--apk-key-name"} {
			t.Run(command.name+"/"+signingFlag, func(t *testing.T) {
				t.Parallel()
				args := append(append([]string(nil), command.args...), signingFlag, "test-key")
				var stdout, stderr bytes.Buffer
				if code := runRecovery(command.group, args, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), command.message) {
					t.Fatalf("misplaced signing flag exit = %d, stderr = %s", code, stderr.String())
				}
			})
		}
	}
}
