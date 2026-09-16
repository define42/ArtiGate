//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Canonical's dated Ubuntu 24.04 cloud image includes snapd and cloud-init.
// The 596 MiB fixture is bootstrapping, not a package cache: it contains neither
// hello nor core20. SHA256 is from that dated directory's official SHA256SUMS.
const (
	snapVMImageURL    = "https://cloud-images.ubuntu.com/releases/noble/release-20260911/ubuntu-24.04-server-cloudimg-amd64.img"
	snapVMImageSHA256 = "612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354"
	snapVMImageName   = "noble-20260911-amd64.img"
)

func prepareSnapReceiverVM(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		requiredUnavailable(t, "the pinned Snap VM fixture requires Linux amd64")
	}
	for _, tool := range []string{"qemu-system-x86_64", "qemu-img", "xorriso", "curl"} {
		requireTool(t, tool)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, "artigate-e2e", "vm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(dir, snapVMImageName)
	if snapVMImageMatches(image) {
		return image
	}
	tmp, err := os.CreateTemp(dir, ".snap-vm-*.img")
	if err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmp.Name()) })
	run(t, dir, nil, "curl", "-fL", "--retry", "3", "--output", tmp.Name(), snapVMImageURL)
	if !snapVMImageMatches(tmp.Name()) {
		t.Fatal("downloaded Snap VM does not match Canonical's pinned SHA256")
	}
	if err := os.Rename(tmp.Name(), image); err != nil {
		t.Fatal(err)
	}
	return image
}

func snapVMImageMatches(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	return err == nil && hex.EncodeToString(hash.Sum(nil)) == snapVMImageSHA256
}

func runSnapReceiverVM(t *testing.T, image, files string, packages []string) {
	t.Helper()
	dir := t.TempDir()
	disk := filepath.Join(dir, "receiver.qcow2")
	run(t, dir, nil, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, disk, "8G")
	seed := filepath.Join(dir, "seed")
	writeFile(t, filepath.Join(seed, "meta-data"), "instance-id: artigate-snap-receiver\nlocal-hostname: artigate-snap-receiver\n")
	writeFile(t, filepath.Join(seed, "network-config"), "version: 2\nethernets: {}\n")
	writeFile(t, filepath.Join(seed, "user-data"), snapVMCloudConfig(packages))
	iso := filepath.Join(dir, "seed.iso")
	run(t, dir, nil, "xorriso", "-as", "mkisofs", "-output", iso, "-volid", "cidata", "-joliet", "-rock", seed)
	accel := "tcg"
	if kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		_ = kvm.Close()
		accel = "kvm"
	}
	t.Logf("starting offline Snap VM with %s acceleration", accel)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	args := []string{
		"-accel", accel, "-m", "2048", "-smp", "2", "-nographic", "-no-reboot", "-nic", "none",
		"-drive", "file=" + disk + ",format=qcow2,if=virtio", "-drive", "file=" + iso + ",format=raw,media=cdrom,readonly=on",
		"-virtfs", "local,path=" + files + ",mount_tag=mirrored,security_model=none,readonly=on",
	}
	// No network device and no host devices, sockets, private keys, or writable
	// shared mounts. snapd and its privileged mount/AppArmor operations stay
	// entirely inside the guest kernel and its disposable QCOW2 overlay.
	cmd := exec.CommandContext(ctx, "qemu-system-x86_64", args...)
	logPath := filepath.Join(stack.WorkDir, "snap-receiver.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	err = cmd.Run()
	_ = logFile.Close()
	out, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	t.Logf("offline Snap VM console:\n%s", out)
	if err != nil || !strings.Contains(string(out), "ARTIGATE_SNAP_RESULT:0") || !strings.Contains(string(out), "Hello, world!") {
		t.Fatalf("offline snap ack/install/run failed: %v", err)
	}
}

func snapVMCloudConfig(packages []string) string {
	var script strings.Builder
	script.WriteString("#!/bin/bash\nset -euxo pipefail\n")
	script.WriteString("test \"$(ls /sys/class/net)\" = lo\nmkdir -p /mnt/mirrored\nmount -t 9p -o trans=virtio,version=9p2000.L,ro mirrored /mnt/mirrored\n")
	script.WriteString("timeout 120 snap wait system seed.loaded\n")
	for _, name := range packages {
		packageName, _, _ := strings.Cut(name, "_")
		fmt.Fprintf(&script, "if snap list '%s'; then echo 'receiver already contains mirrored snap' >&2; exit 1; fi\n", packageName)
		fmt.Fprintf(&script, "snap ack '/mnt/mirrored/%s.assert'\n", name)
	}
	for _, name := range packages {
		fmt.Fprintf(&script, "snap install '/mnt/mirrored/%s.snap'\n", name)
	}
	script.WriteString("snap list\nsnap run hello\n")
	return "#cloud-config\npackage_update: false\npackage_upgrade: false\nwrite_files:\n" +
		"  - path: /usr/local/bin/artigate-snap-receiver\n    permissions: '0755'\n    content: |\n      " +
		strings.ReplaceAll(strings.TrimSuffix(script.String(), "\n"), "\n", "\n      ") + "\n" +
		"runcmd:\n  - [bash, -c, '/usr/local/bin/artigate-snap-receiver > /dev/ttyS0 2>&1; code=$?; echo ARTIGATE_SNAP_RESULT:$code > /dev/ttyS0; poweroff -f']\n"
}
