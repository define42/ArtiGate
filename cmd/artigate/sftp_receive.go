package main

// SFTP is a folder carrier: remote dot-prefixed and .writing files are never
// candidates. Downloads stay dot-prefixed locally until the entire bundle is
// available, then the ordinary signature/hash-verifying importer takes over.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

func (s *HighServer) startSFTPPoller(ctx context.Context) {
	if s.cfg.SFTP == nil {
		return
	}
	log.Printf("high-side SFTP: polling %s every %s", s.cfg.SFTP.URL, s.cfg.SFTP.PollInterval)
	go s.runSFTPPoller(ctx)
}

func (s *HighServer) runSFTPPoller(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		recoverWorkerPanic("SFTP poll", func() {
			if err := s.pollSFTP(ctx); err != nil && ctx.Err() == nil {
				log.Printf("SFTP poll: %v", err)
			}
		})
		timer.Reset(s.cfg.SFTP.PollInterval)
	}
}

// pollSFTP leaves remote files untouched. Durable imported sequence numbers
// and complete local/quarantined sets prevent repeated downloads after restart.
func (s *HighServer) pollSFTP(ctx context.Context) error {
	s.sftpMu.Lock()
	defer s.sftpMu.Unlock()
	client, closeClient, err := dialSFTP(ctx, s.cfg.SFTP)
	if err != nil {
		return err
	}
	defer closeClient()
	entries, err := client.ReadDirContext(ctx, s.cfg.SFTP.remoteDir())
	if err != nil {
		return fmt.Errorf("list SFTP folder: %w", err)
	}
	files := sftpReadyFiles(entries)
	var failures []error
	if info, ok := files[diodeHeartbeatFileName]; ok {
		if err := s.receiveSFTPHeartbeat(client, info); err != nil {
			failures = append(failures, err)
		}
	}
	for _, id := range sftpReadyBundles(files) {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		landed, err := s.receiveSFTPBundle(client, id, files)
		if err != nil {
			failures = append(failures, fmt.Errorf("receive %s: %w", id, err))
			continue
		}
		// Drain between bundles so a large backlog does not fill the landing
		// quota before the import timer gets an opportunity to run.
		if landed {
			if _, err := s.ImportNext(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	_, err = s.ImportNext()
	return errors.Join(append(failures, err)...)
}

func sftpReadyFiles(entries []os.FileInfo) map[string]os.FileInfo {
	files := make(map[string]os.FileInfo)
	for _, info := range entries {
		name := info.Name()
		if !info.Mode().IsRegular() || info.Size() < 0 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".writing") {
			continue
		}
		if validBundleFileName(name) || name == diodeHeartbeatFileName {
			files[name] = info
		}
	}
	return files
}

func sftpReadyBundles(files map[string]os.FileInfo) []string {
	var ids []string
	for name := range files {
		stream, seq, ok := parseBundleName(name)
		if !ok {
			continue
		}
		id := bundleIDFor(stream, seq)
		complete := true
		for _, suffix := range bundleSuffixes() {
			if _, ok := files[id+suffix]; !ok {
				complete = false
			}
		}
		if complete {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		streamI, seqI, _ := parseBundleName(ids[i] + ".manifest.json")
		streamJ, seqJ, _ := parseBundleName(ids[j] + ".manifest.json")
		if streamI != streamJ {
			return streamI < streamJ
		}
		return seqI < seqJ
	})
	return ids
}

// sftpBundlePresentLocked is called with mu held, since the importer can move
// files between the landing and quarantine directories while serving requests.
func (s *HighServer) sftpBundlePresentLocked(id string) bool {
	stream, seq, _ := parseBundleName(id + ".manifest.json")
	return seq <= s.state.Imported[stream] || bundleCompleteInDir(s.cfg.Landing, id) || bundleCompleteInDir(s.cfg.Quarantine, id)
}

func (s *HighServer) receiveSFTPBundle(client *sftp.Client, id string, files map[string]os.FileInfo) (bool, error) {
	// Share the ingest quota lock with HTTP while staging. Keep mu free
	// during network I/O so clients and the importer remain responsive.
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	s.mu.Lock()
	present := s.sftpBundlePresentLocked(id)
	s.mu.Unlock()
	if present {
		return false, nil
	}
	defer s.removeSFTPBundleTemps(id)
	for _, suffix := range bundleSuffixes() {
		name := id + suffix
		limit, _ := bundleFileSizeLimit(name)
		if err := s.stageSFTPFile(client, files[name], limit); err != nil {
			return false, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sftpBundlePresentLocked(id) {
		return false, nil
	}
	err := s.publishSFTPBundle(id)
	return err == nil, err
}

func (s *HighServer) removeSFTPBundleTemps(id string) {
	for _, suffix := range bundleSuffixes() {
		_ = os.Remove(filepath.Join(s.cfg.Landing, "."+id+suffix))
	}
}

func (s *HighServer) publishSFTPBundle(id string) error {
	// Signature is the last completeness marker. Remove an orphaned old one
	// before publishing so even a failed rename leaves an incomplete set.
	sig := filepath.Join(s.cfg.Landing, id+".manifest.json.sig")
	if err := os.Remove(sig); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, suffix := range bundleSuffixes() {
		name := id + suffix
		if err := os.Rename(filepath.Join(s.cfg.Landing, "."+name), filepath.Join(s.cfg.Landing, name)); err != nil {
			return fmt.Errorf("publish %s: %w", name, err)
		}
	}
	fsyncDir(s.cfg.Landing)
	return nil
}

func (s *HighServer) receiveSFTPHeartbeat(client *sftp.Client, info os.FileInfo) error {
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	tmp := filepath.Join(s.cfg.Landing, "."+diodeHeartbeatFileName)
	defer os.Remove(tmp)
	if err := s.stageSFTPFile(client, info, diodeMaxHeartbeatPacketBytes); err != nil {
		return fmt.Errorf("receive SFTP heartbeat: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(tmp, filepath.Join(s.cfg.Landing, diodeHeartbeatFileName)); err != nil {
		return err
	}
	fsyncDir(s.cfg.Landing)
	s.consumeLandingHeartbeat(time.Now().UTC())
	return nil
}

func (s *HighServer) stageSFTPFile(client *sftp.Client, info os.FileInfo, fileLimit int64) error {
	name := info.Name()
	if !validBundleFileName(name) && name != diodeHeartbeatFileName {
		return errors.New("invalid SFTP file name")
	}
	tmp := filepath.Join(s.cfg.Landing, "."+name)
	// A hard kill may have left this hidden file behind. Remove the directory
	// entry, then use O_EXCL below so a symlink can never redirect our writes.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	usage, err := s.unverifiedTransportBytes()
	if err != nil {
		return err
	}
	limit := min(fileLimit, diodeMaxUnverifiedBytes-usage)
	if info.Size() > limit || limit < 0 {
		return fmt.Errorf("SFTP file %s exceeds file or unverified storage limit", name)
	}
	remote, err := client.Open(path.Join(s.cfg.SFTP.remoteDir(), name))
	if err != nil {
		return err
	}
	defer remote.Close()
	actual, err := remote.Stat()
	if err != nil {
		return err
	}
	if !actual.Mode().IsRegular() || actual.Size() != info.Size() {
		return fmt.Errorf("SFTP file %s changed since listing", name)
	}
	return writeSFTPTemp(tmp, remote, info.Size())
}

// writeSFTPTemp never exposes a final name. Reading one extra byte detects a
// remote file that grows or lies about its size without exceeding the quota.
func writeSFTPTemp(tmp string, r io.Reader, size int64) error {
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(r, size+1))
	if copyErr == nil && n != size {
		copyErr = errors.New("SFTP file size changed during download")
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func isSFTPTempName(name string) bool {
	ready, ok := strings.CutPrefix(name, ".")
	return ok && (validBundleFileName(ready) || ready == diodeHeartbeatFileName)
}

func isTransportTempName(name string) bool {
	return isUDPTempName(name) || isIngestUploadTempName(name) || isSFTPTempName(name)
}
