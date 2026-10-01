//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import (
	"fmt"
	"os"
)

// Preserve normal server operation on platforms without recovery commands.
// Offline recovery itself refuses these platforms rather than taking no lock.
func acquireServerRootLock(string) (func() error, error) {
	return func() error { return nil }, nil
}

func openRecoveryLock(string) (*os.File, error) {
	return nil, fmt.Errorf("exclusive storage locks are unsupported on this operating system")
}
