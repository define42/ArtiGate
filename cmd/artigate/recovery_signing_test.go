package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryRepositoryGPGSigning(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is required to verify repository signatures")
	}
	home, err := os.MkdirTemp("", "ag-recovery-gpg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "gpg-agent").Run()
		_ = os.RemoveAll(home)
	})
	const key = "recovery-test@example.invalid"
	recoveryTestGPG(t, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", key, "ed25519", "sign", "0")
	stage := t.TempDir()
	aptDir := filepath.Join(stage, "cache", "download", "apt", "debian", "dists", "stable")
	rpmDir := filepath.Join(stage, "cache", "download", "rpm", "fedora", "repodata")
	for _, dir := range []string{aptDir, rpmDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const release = "Origin: ArtiGate\nSuite: stable\n"
	const repomd = "<?xml version=\"1.0\"?><repomd/>\n"
	writeFile(t, filepath.Join(aptDir, "Release"), []byte(release))
	writeFile(t, filepath.Join(rpmDir, "repomd.xml"), []byte(repomd))
	if err := prepareRecoveryRepository(t.Context(), stage, HighConfig{AptGPGKey: key, RpmGPGKey: key}); err != nil {
		t.Fatal(err)
	}
	recoveryTestGPG(t, "--batch", "--verify", filepath.Join(aptDir, "InRelease"))
	recoveryTestGPG(t, "--batch", "--verify", filepath.Join(aptDir, "Release.gpg"), filepath.Join(aptDir, "Release"))
	recoveryTestGPG(t, "--batch", "--verify", filepath.Join(rpmDir, "repomd.xml.asc"), filepath.Join(rpmDir, "repomd.xml"))
	for path, want := range map[string]string{filepath.Join(aptDir, "Release"): release, filepath.Join(rpmDir, "repomd.xml"): repomd} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("signing changed preserved repository metadata %s: %q, %v", path, got, err)
		}
	}
}

func recoveryTestGPG(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "gpg", args...).CombinedOutput(); err != nil {
		t.Fatalf("gpg %v: %v\n%s", args, err, output)
	}
}

func TestRecoveryRepositoryAPKSigning(t *testing.T) {
	t.Parallel()
	fx := newApkTestFixture(t)
	collected := fx.collect(t, ApkCollectRequest{})
	name := apkTestMirrorName(t, fx.ls, collected.BundleID)
	hs := newTestHighServer(t, fx.priv.Public().(ed25519.PublicKey))
	apkTestImport(t, fx.ls, hs, collected.BundleID)
	keyPath, key := apkTestRSAKeyFile(t)
	if err := prepareRecoveryRepository(t.Context(), hs.cfg.Root, HighConfig{
		ApkRSAKey: keyPath, ApkKeyName: "recovery.rsa.pub",
	}); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(hs.apkDir(), name, "v3.22", "main", "x86_64", "APKINDEX.tar.gz")
	data, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	member, signature, signed := apkTestSplitLeadingSegment(t, data)
	if member != ".SIGN.RSA.recovery.rsa.pub" {
		t.Fatalf("signature member = %q", member)
	}
	digest := sha1.Sum(signed) //nolint:gosec // APK's RSA index format requires SHA-1.
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, digest[:], signature); err != nil {
		t.Fatalf("restored APK index signature: %v", err)
	}
	text, err := apkIndexFromArchive(data, 1<<20)
	if err != nil || len(parseApkIndex(text)) != 2 {
		t.Fatalf("regenerated APK index lost packages: %v", err)
	}
}

func TestRecoveryRepositorySigningFailureDoesNotActivate(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	root := checkpointTestRoot(t, map[string]int64{streamGo: 1})
	writeSignedBundle(t, filepath.Join(root, "bundles"), priv, 1, 0,
		[]moduleSpec{{"example.com/signing", "v1.0.0"}})
	artifactDir := filepath.Join(t.TempDir(), "checkpoint")
	artifact, err := createRecoveryCheckpoint(t.Context(), checkpointOptions{Root: root, Output: artifactDir, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	keyPath, _ := apkTestRSAKeyFile(t)
	for _, test := range []struct {
		name string
		cfg  HighConfig
	}{
		{name: "missing key", cfg: HighConfig{ApkRSAKey: filepath.Join(t.TempDir(), "missing.pem")}},
		{name: "unsafe key name", cfg: HighConfig{ApkRSAKey: keyPath, ApkKeyName: "../../escaped.pub"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "receiver")
			_, err := restoreRecoveryArtifactPrepared(t.Context(), artifactDir, target, pub, artifact.Digest,
				func(ctx context.Context, stage string) error { return prepareRecoveryRepository(ctx, stage, test.cfg) })
			if err == nil {
				t.Fatal("restore accepted an unusable signing configuration")
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("signing failure activated destination: %v", err)
			}
		})
	}
}

func TestRecoveryRepositoryWithoutKeysDoesNothing(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "low-state.json"), []byte("low-side backup"))
	if err := prepareRecoveryRepository(t.Context(), root, HighConfig{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "low-state.json" {
		t.Fatalf("preparation changed low backup without signing keys: %v, %v", entries, err)
	}
}
