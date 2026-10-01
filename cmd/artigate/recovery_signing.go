package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// prepareRecoveryRepository applies receiver-local repository signatures to a
// fully verified, private restore stage. The restore publishes it only after
// this preparation and the directory durability barrier both succeed.
func prepareRecoveryRepository(ctx context.Context, stage string, cfg HighConfig) error {
	if cfg.AptGPGKey == "" && cfg.RpmGPGKey == "" && cfg.ApkRSAKey == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := recoveryCheckDirectory(stage); err != nil {
		return err
	}
	cfg.Root = stage
	hs := &HighServer{cfg: cfg, downloadDir: filepath.Join(stage, "cache", "download")}
	if cfg.AptGPGKey != "" {
		if err := prepareRecoveryApt(ctx, hs); err != nil {
			return err
		}
	}
	if cfg.RpmGPGKey != "" {
		if err := prepareRecoveryRpm(ctx, hs); err != nil {
			return err
		}
	}
	if cfg.ApkRSAKey != "" {
		return prepareRecoveryApk(ctx, hs)
	}
	return ctx.Err()
}

func prepareRecoveryApt(ctx context.Context, hs *HighServer) error {
	return walkRecoverySigningFiles(ctx, hs.aptDir(), func(name, relative string) error {
		parts := strings.Split(relative, "/")
		if len(parts) != 4 || parts[1] != "dists" || parts[3] != "Release" {
			return nil
		}
		dir := filepath.Dir(name)
		if err := hs.signAptRelease(dir); err != nil {
			return fmt.Errorf("sign restored APT repository %s: %w", relative, err)
		}
		return syncRecoverySigningFiles(ctx, filepath.Join(dir, "InRelease"), filepath.Join(dir, "Release.gpg"))
	})
}

func prepareRecoveryRpm(ctx context.Context, hs *HighServer) error {
	return walkRecoverySigningFiles(ctx, hs.rpmDir(), func(name, relative string) error {
		parts := strings.Split(relative, "/")
		if len(parts) != 3 || parts[1] != "repodata" || parts[2] != "repomd.xml" {
			return nil
		}
		dir := filepath.Dir(name)
		if err := hs.signRpmRepomd(dir); err != nil {
			return fmt.Errorf("sign restored RPM repository %s: %w", relative, err)
		}
		return syncRecoverySigningFiles(ctx, filepath.Join(dir, "repomd.xml.asc"))
	})
}

func prepareRecoveryApk(ctx context.Context, hs *HighServer) error {
	if hs.cfg.ApkKeyName == "" {
		hs.cfg.ApkKeyName = "artigate.rsa.pub"
	}
	if err := validateUploadComponent("APK signing key filename", hs.cfg.ApkKeyName); err != nil {
		return err
	}
	if _, err := loadApkRSAKey(hs.cfg.ApkRSAKey); err != nil {
		return fmt.Errorf("load restored APK signing key: %w", err)
	}
	entries, err := os.ReadDir(hs.apkDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() {
			return fmt.Errorf("unexpected restored APK repository entry %q", entry.Name())
		}
		if err := prepareRecoveryApkMirror(hs, entry.Name()); err != nil {
			return err
		}
	}
	return walkRecoverySigningFiles(ctx, hs.apkDir(), func(name, relative string) error {
		if len(strings.Split(relative, "/")) == 5 && filepath.Base(name) == "APKINDEX.tar.gz" {
			return syncRecoverySigningFiles(ctx, name)
		}
		return nil
	})
}

func prepareRecoveryApkMirror(hs *HighServer, name string) error {
	mirror, err := hs.readApkMirrorIndex(name)
	if err != nil {
		return fmt.Errorf("read restored APK mirror %s: %w", name, err)
	}
	if mirror.Name != name {
		return fmt.Errorf("restored APK mirror %s has mismatched identity %q", name, mirror.Name)
	}
	seen := make(map[string]bool, len(mirror.Packages))
	for _, pkg := range mirror.Packages {
		rel := apkFileRel(name, pkg.Branch, pkg.Repository, pkg.Arch, pkg.Filename)
		abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
		seen[rel] = safeJoin(hs.apkDir(), abs) && fileExists(abs)
	}
	if err := validateApkMirror(mirror, seen); err != nil {
		return fmt.Errorf("validate restored APK mirror %s: %w", name, err)
	}
	return hs.publishApkMirror(mirror)
}

func walkRecoverySigningFiles(ctx context.Context, root string, visit func(string, string) error) error {
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular restored repository file %s", name)
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		return visit(name, filepath.ToSlash(rel))
	})
}

func syncRecoverySigningFiles(ctx context.Context, names ...string) error {
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := firstErr(syncErr, closeErr); err != nil {
			return fmt.Errorf("persist restored repository signature %s: %w", name, err)
		}
	}
	return nil
}
