//go:build linux

package main

import "golang.org/x/sys/unix"

// A restore must never replace another root that appeared after validation.
func publishRecoveryDirectory(stage, target string) error {
	return unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
}
