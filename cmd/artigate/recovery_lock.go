package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// acquireRecoveryRootLock excludes servers and offline recovery operations.
// Keep the lock inode in place after unlocking: removing it would let another
// process lock a new inode while a waiter still holds the original one.
func acquireRecoveryRootLock(root string) (func() error, error) {
	if root == "" {
		return nil, fmt.Errorf("storage root is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	lock, err := openRecoveryLock(filepath.Join(root, ".artigate.lock"))
	if err != nil {
		return nil, fmt.Errorf("lock storage root %s (stop the server and other recovery commands first): %w", root, err)
	}
	return lock.Close, nil
}

func openLowServerRoot(cfg LowConfig) (*LowServer, func() error, error) {
	priv, err := readPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	release, err := acquireServerRootLock(cfg.Root)
	if err != nil {
		return nil, nil, err
	}
	s, err := NewLowServer(cfg, priv)
	if err != nil {
		_ = release()
		return nil, nil, err
	}
	return s, release, nil
}

func openHighServerRoot(cfg HighConfig) (*HighServer, func() error, error) {
	pub, err := readPublicKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	release, err := acquireServerRootLock(cfg.Root)
	if err != nil {
		return nil, nil, err
	}
	s, err := NewHighServer(cfg, pub)
	if err != nil {
		_ = release()
		return nil, nil, err
	}
	return s, release, nil
}
