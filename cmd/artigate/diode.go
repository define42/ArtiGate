package main

// HTTP diode transport. The folder-based flow — low side writes bundles into
// --export-dir, something carries them across, they appear in the high side's
// --landing directory — stays the default. This file adds an HTTP transport
// on both ends for diodes (or diode proxies) that speak HTTP instead of
// moving files, configured entirely through environment variables:
//
//	ARTIGATE_DIODE_URL     low side: endpoint bundles are uploaded to after
//	                       every export and re-export (PUT <url>/<file>, the
//	                       archive first). On success the export-dir copy is
//	                       removed — the export dir is the pending-transfer
//	                       spool in both transports. On failure the bundle
//	                       stays staged and archived for a re-transmit.
//	ARTIGATE_DIODE_INGEST  high side: "on" accepts bundle files at
//	                       PUT/POST /diode/<file>, streamed atomically into
//	                       the landing directory where the normal
//	                       verify-and-import pipeline picks them up.
//	ARTIGATE_DIODE_TOKEN   both sides: shared bearer token (at least 32 bytes,
//	                       required whenever HTTP transport is enabled).
//
// The transport carries zero trust: bundles are accepted from the wire
// exactly as from a landing folder, and the importer still verifies the
// Ed25519 signature, per-stream sequencing, and every file hash. The token
// only guards the high side's disk against unauthenticated uploads.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	// diodeUploadTimeout bounds one file's upload; bundle archives can be tens
	// of gigabytes.
	diodeUploadTimeout = 4 * time.Hour
	// Per-suffix limits keep manifests/signatures small enough for bounded
	// verification while still allowing large model/container archives.
	diodeMaxArchiveBytes   int64 = 64 << 30
	diodeMaxManifestBytes  int64 = 16 << 20
	diodeMaxSignatureBytes int64 = 4 << 10
	// diodeMaxUnverifiedBytes bounds aggregate pending/rejected transport data.
	diodeMaxUnverifiedBytes int64 = 128 << 30
)

// minDiodeTokenBytes prevents an enabled HTTP diode endpoint from being
// protected by an empty, default, or trivially guessable bearer token.
const minDiodeTokenBytes = 32

// bundleFileBaseRE matches a bundle's base name ("hf-bundle-000042") — the
// only names the ingest endpoint will store, so an upload can never plant an
// arbitrary file in the landing directory.
var bundleFileBaseRE = regexp.MustCompile(`^[a-z0-9]+-bundle-[0-9]{6,}$`)

// validBundleFileName accepts exactly the three files that make up one
// transferable bundle.
func validBundleFileName(name string) bool {
	for _, suffix := range bundleSuffixes() {
		if base, ok := strings.CutSuffix(name, suffix); ok {
			if !bundleFileBaseRE.MatchString(base) {
				return false
			}
			stream, seq, parsed := parseBundleName(base + ".manifest.json")
			return parsed && seq > 0 && isKnownStream(stream)
		}
	}
	return false
}

// bundleFileSizeLimit returns the maximum wire/disk size for one of the three
// supported bundle file suffixes.
func bundleFileSizeLimit(name string) (int64, bool) {
	switch {
	case strings.HasSuffix(name, ".manifest.json.sig"):
		return diodeMaxSignatureBytes, true
	case strings.HasSuffix(name, ".manifest.json"):
		return diodeMaxManifestBytes, true
	case strings.HasSuffix(name, ".tar.gz"):
		return diodeMaxArchiveBytes, true
	default:
		return 0, false
	}
}

// parseOnOff reads an on/off environment value; empty means off.
func parseOnOff(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "off", "no":
		return false, nil
	case "1", "true", "on", "yes":
		return true, nil
	default:
		return false, fmt.Errorf("invalid on/off value %q", v)
	}
}

// validateDiodeToken enforces the minimum credential required whenever the
// HTTP diode transport is enabled. Folder and UDP diode flows do not call it.
func validateDiodeToken(token string) error {
	if len(token) < minDiodeTokenBytes {
		return fmt.Errorf("ARTIGATE_DIODE_TOKEN must be at least %d bytes when HTTP diode transport is enabled", minDiodeTokenBytes)
	}
	if strings.TrimSpace(token) != token {
		return errors.New("ARTIGATE_DIODE_TOKEN must not have leading or trailing whitespace")
	}
	for _, r := range token {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("ARTIGATE_DIODE_TOKEN must not contain whitespace or control characters")
		}
	}
	return nil
}

// validateDiodeURL checks the low side's configured endpoint at startup, so a
// typo fails fast instead of failing every collect's upload.
func validateDiodeURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid ARTIGATE_DIODE_URL %q (need an http/https URL)", raw)
	}
	return nil
}

// diodeTokenStatus renders the startup-log description of the ingest
// endpoint's protection.
func diodeTokenStatus(token string) string {
	if token == "" {
		return "no token — open to the network"
	}
	return "bearer token required"
}

// diodeTokenOK compares the request's bearer token against the configured
// one in constant time. An empty configured token means the endpoint is open.
func diodeTokenOK(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// -----------------------------------------------------------------------------
// High side: ingest endpoint
// -----------------------------------------------------------------------------

// serveDiode handles PUT/POST /diode/<bundle-file>: the HTTP equivalent of a
// file landing in the --landing directory. It reports whether it wrote a
// response.
func (s *HighServer) serveDiode(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/diode" && !strings.HasPrefix(r.URL.Path, "/diode/") {
		return false
	}
	s.handleDiodeUpload(w, r)
	return true
}

func (s *HighServer) handleDiodeUpload(w http.ResponseWriter, r *http.Request) {
	name, fileLimit, ok := s.validateDiodeUpload(w, r)
	if !ok {
		return
	}
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	n, status, err := s.storeDiodeUpload(name, r, fileLimit)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	log.Printf("diode ingest: stored %s (%s)", name, formatBytes(n))
	// If this file completed its bundle, request a coalesced import instead of
	// creating one goroutine per upload.
	if bundleCompleteInDir(s.cfg.Landing, bundleBaseName(name)) {
		s.requestImport()
	}
	writeJSON(w, map[string]any{"stored": name, "size": n})
}

func (s *HighServer) validateDiodeUpload(w http.ResponseWriter, r *http.Request) (string, int64, bool) {
	if !s.cfg.DiodeIngest {
		http.Error(w, "diode ingest is disabled; set ARTIGATE_DIODE_INGEST=on", http.StatusForbidden)
		return "", 0, false
	}
	if !diodeTokenOK(r, s.cfg.DiodeToken) {
		http.Error(w, "missing or wrong diode token", http.StatusUnauthorized)
		return "", 0, false
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed; PUT the bundle file", http.StatusMethodNotAllowed)
		return "", 0, false
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/diode"), "/")
	if !validBundleFileName(name) {
		http.Error(w, "not a bundle file name (want <stream>-bundle-<seq>{.tar.gz,.manifest.json,.manifest.json.sig})", http.StatusBadRequest)
		return "", 0, false
	}
	fileLimit, _ := bundleFileSizeLimit(name)
	if r.ContentLength > fileLimit {
		http.Error(w, fmt.Sprintf("diode upload exceeds %s limit for this file type", formatBytes(fileLimit)), http.StatusRequestEntityTooLarge)
		return "", 0, false
	}
	return name, fileLimit, true
}

func (s *HighServer) storeDiodeUpload(name string, r *http.Request, fileLimit int64) (int64, int, error) {
	usage, err := s.unverifiedTransportBytes()
	if err != nil {
		return 0, http.StatusInternalServerError, fmt.Errorf("measure unverified storage: %w", err)
	}
	available := diodeMaxUnverifiedBytes - usage
	if available <= 0 {
		return 0, http.StatusInsufficientStorage, errors.New("unverified diode storage quota exhausted")
	}
	limit := min(fileLimit, available)
	if r.ContentLength > limit {
		return 0, http.StatusInsufficientStorage, errors.New("unverified diode storage quota would be exceeded")
	}
	n, err := writeStreamAtomicLimit(filepath.Join(s.cfg.Landing, name), r.Body, limit)
	if err != nil {
		return 0, diodeStoreErrorStatus(err, limit, fileLimit), diodeStoreError(name, err, limit, fileLimit)
	}
	return n, http.StatusOK, nil
}

func diodeStoreErrorStatus(err error, limit, fileLimit int64) int {
	var maxBytesErr *http.MaxBytesError
	if !errors.As(err, &maxBytesErr) {
		return http.StatusInternalServerError
	}
	if limit < fileLimit {
		return http.StatusInsufficientStorage
	}
	return http.StatusRequestEntityTooLarge
}

func diodeStoreError(name string, err error, limit, fileLimit int64) error {
	var maxBytesErr *http.MaxBytesError
	if !errors.As(err, &maxBytesErr) {
		return fmt.Errorf("store %s: %w", name, err)
	}
	if limit < fileLimit {
		return errors.New("unverified diode storage quota would be exceeded")
	}
	return fmt.Errorf("diode upload exceeds %s limit", formatBytes(maxBytesErr.Limit))
}

// writeStreamAtomicLimit streams at most limit bytes from r into dst via a temp
// file in the same directory, so a half-received upload is never visible under
// its final name (the importer's completeness check must only ever see whole
// files).
func writeStreamAtomicLimit(dst string, r io.Reader, limit int64) (int64, error) {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(dir, filepath.Base(dst)+".upload-*")
	if err != nil {
		return 0, err
	}
	tmp := f.Name()
	// Read one byte past the limit to distinguish an exact-size body from an
	// oversized one without buffering the request.
	n, copyErr := io.Copy(f, io.LimitReader(r, limit+1))
	if copyErr == nil && n == limit+1 {
		copyErr = &http.MaxBytesError{Limit: limit}
	}
	if copyErr != nil {
		closeErr := f.Close()
		_ = os.Remove(tmp)
		return n, firstErr(copyErr, closeErr)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return n, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	fsyncDir(dir)
	return n, nil
}

// directoryRegularFileBytes totals only direct regular-file children. Processed
// bundle subdirectories are intentionally excluded from the unverified quota.
func directoryRegularFileBytes(dir string) (int64, error) {
	return directoryRegularFileBytesExcept(dir, nil)
}

func directoryRegularFileBytesExcept(dir string, skip func(string) bool) (int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || (skip != nil && skip(entry.Name())) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		if info.Mode().IsRegular() {
			if info.Size() > math.MaxInt64-total {
				return 0, errors.New("unverified storage size overflow")
			}
			total += info.Size()
		}
	}
	return total, nil
}

func isUDPTempName(name string) bool {
	return strings.Contains(name, ".udp-")
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Low side: bundle upload
// -----------------------------------------------------------------------------

// uploadBundleIfConfigured hands a freshly exported (or re-exported) bundle
// to whichever diode transport is configured: the built-in UDP pitcher or the
// HTTP endpoint (they are mutually exclusive; with neither, the export dir is
// the folder-diode outbox and nothing happens here). Both transports are
// best-effort by design: the bundle is already committed and archived, so a
// failed transfer loses nothing — it is reported (result, progress, log) and
// the staged files stay in the export dir for a re-transmit from the Status
// page.
func (s *LowServer) uploadBundleIfConfigured(ctx context.Context, res *ExportResult) {
	if res.BundleID == "" {
		return
	}
	switch {
	case s.pitcher != nil:
		s.pitchBundle(ctx, res)
	case s.cfg.DiodeURL != "":
		s.uploadBundleToHTTPDiode(ctx, res)
	}
}

// uploadBundleToHTTPDiode pushes a bundle to the HTTP diode endpoint.
func (s *LowServer) uploadBundleToHTTPDiode(ctx context.Context, res *ExportResult) {
	emitProgress(ctx, "Uploading %s to the diode endpoint…", res.BundleID)
	if err := s.pushBundleToDiode(ctx, res.BundleID); err != nil {
		log.Printf("diode upload %s: %v", res.BundleID, err)
		emitProgress(ctx, "  ✗ upload failed: %s", err)
		res.DiodeError = err.Error()
		return
	}
	emitProgress(ctx, "  ✓ %s uploaded", res.BundleID)
	if res.Message == "" {
		res.Message = "uploaded to diode endpoint"
	}
	s.clearOutboundBundle(res.BundleID)
}

// clearOutboundBundle empties the outbound spool after a successful transfer,
// like a folder diode moving the files out would. The archive copy is what
// re-exports use.
func (s *LowServer) clearOutboundBundle(bundleID string) {
	for _, suffix := range bundleSuffixes() {
		if err := os.Remove(filepath.Join(s.cfg.ExportDir, bundleID+suffix)); err != nil && !os.IsNotExist(err) {
			log.Printf("diode transfer %s: clear outbound: %v", bundleID, err)
		}
	}
}

// pushBundleToDiode uploads the bundle's three files from the export dir, the
// archive first — so an interrupted transfer can never leave a manifest whose
// archive never arrives looking complete.
func (s *LowServer) pushBundleToDiode(ctx context.Context, bundleID string) error {
	base := strings.TrimRight(s.cfg.DiodeURL, "/")
	for _, suffix := range bundleSuffixes() {
		if err := s.uploadDiodeFile(ctx, base, bundleID+suffix); err != nil {
			return err
		}
	}
	return nil
}

func (s *LowServer) uploadDiodeFile(ctx context.Context, base, name string) error {
	src := filepath.Join(s.cfg.ExportDir, name)
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, diodeUploadTimeout)
	defer cancel()
	body := newProgressReader(ctx, f, "uploading "+name, st.Size())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/"+name, body)
	if err != nil {
		return err
	}
	req.ContentLength = st.Size()
	if s.cfg.DiodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.DiodeToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("PUT %s: HTTP %d: %s", name, resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	emitProgress(ctx, "  ↑ %s (%s)", name, formatBytes(st.Size()))
	return nil
}
