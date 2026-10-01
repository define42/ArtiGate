//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryLockExcludesContainerRepair(t *testing.T) {
	root := t.TempDir()
	release, err := acquireRecoveryRootLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	var stdout, stderr bytes.Buffer
	if code := runContainersCheck([]string{"--root", root, "--repair"}, &stdout, &stderr); code == 0 {
		t.Fatal("container repair ran while backup or server held the root lock")
	}
}

func TestRecoveryRootLock(t *testing.T) {
	root := t.TempDir()
	release, err := acquireRecoveryRootLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := acquireRecoveryRootLock(root); err == nil {
		_ = other()
		t.Fatal("second process could acquire an occupied root")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = acquireRecoveryRootLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
}

func TestRecoveryRootLockRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".artigate.lock")); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireRecoveryRootLock(root); err == nil {
		_ = release()
		t.Fatal("accepted a symlink lock")
	}
}
