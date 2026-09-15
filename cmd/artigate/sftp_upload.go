package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/sftp"
)

func (s *LowServer) uploadBundleToSFTP(ctx context.Context, res *ExportResult) {
	emitProgress(ctx, "Uploading %s to SFTP…", res.BundleID)
	if err := s.pushBundleToSFTP(ctx, res.BundleID); err != nil {
		log.Printf("SFTP upload %s: %v", res.BundleID, err)
		emitProgress(ctx, "  ✗ upload failed: %s", err)
		res.DiodeError = err.Error()
		return
	}
	emitProgress(ctx, "  ✓ %s uploaded", res.BundleID)
	res.DiodeError = ""
	if res.Message == "" {
		res.Message = "uploaded to SFTP"
	}
	s.clearOutboundBundle(res.BundleID)
}

// Callers already hold the stream lock, so unrelated streams and heartbeats
// remain independent. A bundle ID is immutable; retransmits use archived bytes.
func (s *LowServer) pushBundleToSFTP(ctx context.Context, bundleID string) error {
	client, closeClient, err := dialSFTP(ctx, s.cfg.SFTP)
	if err != nil {
		return err
	}
	defer closeClient()
	dir := s.cfg.SFTP.remoteDir()
	for _, suffix := range bundleSuffixes() {
		name := bundleID + suffix
		if err := stageSFTPBundleFile(client, s.cfg.ExportDir, dir, name); err != nil {
			return err
		}
	}
	// Publish the signature last, after all three complete files are staged.
	for _, suffix := range bundleSuffixes() {
		if err := promoteSFTPFile(client, path.Join(dir, bundleID+suffix)); err != nil {
			return err
		}
	}
	return nil
}

func stageSFTPBundleFile(client *sftp.Client, exportDir, remoteDir, name string) error {
	file, err := os.Open(filepath.Join(exportDir, name))
	if err != nil {
		return fmt.Errorf("open SFTP source %s: %w", name, err)
	}
	defer file.Close()
	return stageSFTPFile(client, path.Join(remoteDir, name), file)
}

func stageSFTPFile(client *sftp.Client, finalPath string, src io.Reader) error {
	temporary := finalPath + ".writing"
	// A failed attempt may have left a temporary entry. Exclusive creation
	// after removal avoids following a stale symlink during the new upload.
	if err := client.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove SFTP temporary %s: %w", path.Base(temporary), err)
	}
	file, err := client.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("create SFTP temporary %s: %w", path.Base(temporary), err)
	}
	_, copyErr := io.Copy(file, src)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("upload SFTP %s: %w", path.Base(temporary), copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close SFTP %s: %w", path.Base(temporary), closeErr)
	}
	return nil
}

func promoteSFTPFile(client *sftp.Client, finalPath string) error {
	var err error
	if _, supported := client.HasExtension("posix-rename@openssh.com"); supported {
		err = client.PosixRename(finalPath+".writing", finalPath)
	} else {
		// Standard rename may reject an existing destination. Fail safely and
		// retain the ready file instead of removing it before replacement.
		err = client.Rename(finalPath+".writing", finalPath)
	}
	if err != nil {
		return fmt.Errorf("publish SFTP %s: %w", path.Base(finalPath), err)
	}
	return nil
}

func (s *LowServer) uploadHeartbeatToSFTP(ctx context.Context, pkt []byte) error {
	s.sftpMu.Lock()
	defer s.sftpMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, diodeHeartbeatSendTimeout)
	defer cancel()
	client, closeClient, err := dialSFTP(ctx, s.cfg.SFTP)
	if err != nil {
		return err
	}
	defer closeClient()
	finalPath := path.Join(s.cfg.SFTP.remoteDir(), diodeHeartbeatFileName)
	if err := stageSFTPFile(client, finalPath, bytes.NewReader(pkt)); err != nil {
		return err
	}
	return promoteSFTPFile(client, finalPath)
}
