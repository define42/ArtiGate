//go:build !linux

package main

import "fmt"

func publishRecoveryDirectory(_, _ string) error {
	return fmt.Errorf("atomic recovery directory publication currently requires Linux")
}
