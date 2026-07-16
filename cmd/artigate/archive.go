package main

// Archive, hash, and atomic-file primitives shared by both sides: validation
// of untrusted relative paths (safeJoin's counterpart for containing every
// archive-driven filesystem write), SHA-256 manifest hashing, tar.gz packing,
// the verify-while-extracting unpacker the high side runs on transferred
// archives, and atomic (tmp+rename+fsync) file and JSON writes.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// tarScanMaxDecompressedBytes bounds the total decompressed bytes read while
// scanning a .tar.gz for a single metadata member (helm Chart.yaml, galaxy
// MANIFEST.json, cran DESCRIPTION). tar.Reader.Next() decompresses every skipped
// entry, so without this cap a crafted gzip bomb — the wanted member placed last,
// or absent — would inflate the whole archive. Generous enough for any real
// chart, collection, or source package; mirrors terraform's tfModuleMaxExtractBytes.
const tarScanMaxDecompressedBytes = 2 << 30

// maxRenderedBlobBytes bounds a config/metadata blob read fully into memory to
// render a dashboard detail panel (an OCI image config, an HF model config).
// Such blobs are small in practice (KB), but their size is only checked >0 at
// import, so an attacker-influenced giant "config" descriptor could OOM the high
// side when an unauthenticated GET /ui/api/detail renders it. A blob past the cap
// is treated as unreadable, so the panel simply omits those fields.
const maxRenderedBlobBytes = 32 << 20

func validateRelPath(rel string) error {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return errors.New("invalid relative path")
	}
	clean := path.Clean(rel)
	if clean == "." || clean != rel || strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return errors.New("invalid relative path")
	}
	return nil
}

// validateMirrorName checks an APT/RPM mirror name that becomes a single path
// component under the served repo root on the high side. It must be one safe
// segment — the same rule the low side enforces at collect time, re-applied on
// the untrusted import side so a signed bundle can never name a mirror ".." and
// escape the repo subtree when its metadata is (re)published or pruned.
func validateMirrorName(name string) error {
	if err := validateRelPath(name); err != nil || strings.ContainsRune(name, '/') {
		return fmt.Errorf("invalid mirror name %q", name)
	}
	return nil
}

func hashManifestFile(abs, rel string) (ManifestFile, error) {
	st, err := os.Stat(abs)
	if err != nil {
		return ManifestFile{}, err
	}
	if st.IsDir() {
		return ManifestFile{}, fmt.Errorf("%s is a directory", abs)
	}
	h, err := sha256File(abs)
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: filepath.ToSlash(rel), SHA256: h, Size: st.Size()}, nil
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// createTarGzAtomic packs the files into dst. Packing a large bundle takes
// real time (gzip over gigabytes), so it drives the dashboard's progress bar
// through the context's download sink and honors cancellation between chunks
// — a stopped collect aborts here and the temp file is removed, so a bundle
// is either fully produced or not at all.
func createTarGzAtomic(ctx context.Context, dst string, baseDir string, files []ManifestFile) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	var total int64
	for _, mf := range files {
		total += mf.Size
	}
	tracker := newProgressTracker(ctx, "packing "+filepath.Base(dst), total)
	// BestSpeed, deliberately: bundle payloads are dominated by artifacts that
	// are already compressed or high-entropy (wheels, crates, layers, jars,
	// model weights), where the default level burns ~7× the CPU for the same
	// output size, turning a large bundle's pack step into tens of minutes.
	// The small metadata files still compress fine at this level.
	gz, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	for _, mf := range files {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("packing stopped: %w", err)
		}
		if err := addFileToTar(ctx, tw, baseDir, mf, tracker); err != nil {
			return err
		}
	}
	tracker.finish()
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

// addFileToTar writes a single repository file into the tar stream with a
// deterministic header, counting its bytes toward the pack tracker.
func addFileToTar(ctx context.Context, tw *tar.Writer, baseDir string, mf ManifestFile, tracker *progressTracker) error {
	if err := validateRelPath(mf.Path); err != nil {
		return err
	}
	abs := filepath.Join(baseDir, filepath.FromSlash(mf.Path))
	st, err := os.Stat(abs)
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: mf.Path, Mode: 0o644, Size: st.Size(), ModTime: time.Unix(0, 0).UTC()}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	in, err := os.Open(abs)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(tw, &packSource{ctx: ctx, r: in, tracker: tracker})
	closeErr := in.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// packSource feeds one file into the archive, counting bytes toward the pack
// tracker and aborting between chunks when the collect is cancelled.
type packSource struct {
	ctx     context.Context
	r       io.Reader
	tracker *progressTracker
}

func (p *packSource) Read(b []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, fmt.Errorf("packing stopped: %w", err)
	}
	n, err := p.r.Read(b)
	p.tracker.add(int64(n))
	return n, err
}

// expectedArchiveFiles maps the file paths a bundle's archive must contain:
// every manifest file except prior references, which are not packed — the
// install step verifies those against the accumulated repository instead. A
// bundle whose archive carries a file it also marks prior fails extraction as
// "unexpected file", since the two claims contradict each other.
func expectedArchiveFiles(files []ManifestFile) (map[string]ManifestFile, error) {
	expected := map[string]ManifestFile{}
	for _, f := range files {
		if err := validateRelPath(f.Path); err != nil {
			return nil, err
		}
		if !f.Prior {
			expected[f.Path] = f
		}
	}
	return expected, nil
}

// stagingIOError marks a local filesystem failure while extracting a verified
// bundle into staging (for example a full disk). It is an operational fault, not
// a defect in the bundle, so the importer keeps the bundle in place to retry
// rather than rejecting a validly-signed bundle because the disk was full.
type stagingIOError struct{ err error }

func (e *stagingIOError) Error() string { return e.err.Error() }
func (e *stagingIOError) Unwrap() error { return e.err }

// stagingWriter tags a write failure to the staging file as a stagingIOError, so
// a disk-full extraction is classified operational while a read failure from the
// archive stream (a corrupt bundle) stays a content error.
type stagingWriter struct{ w io.Writer }

func (sw stagingWriter) Write(p []byte) (int, error) {
	n, err := sw.w.Write(p)
	if err != nil {
		return n, &stagingIOError{err: err}
	}
	return n, nil
}

func extractAndVerifyTarGz(archivePath, staging string, files []ManifestFile) error {
	expected, err := expectedArchiveFiles(files)
	if err != nil {
		return err
	}
	seen := map[string]bool{}

	f, err := os.Open(archivePath)
	if err != nil {
		return &stagingIOError{err: err}
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		// A repeated name is a defect in the archive. Caught here, before the
		// entry collides with its own first extraction, so it never surfaces
		// as an EEXIST tagged stagingIOError — which would misclassify the
		// bundle as retryable and wedge its stream instead of rejecting it.
		if seen[hdr.Name] {
			return fmt.Errorf("archive contains duplicate entry %s", hdr.Name)
		}
		if err := extractTarEntry(tr, hdr, staging, expected); err != nil {
			return err
		}
		seen[hdr.Name] = true
	}
	for p := range expected {
		if !seen[p] {
			return fmt.Errorf("archive missing file %s", p)
		}
	}
	return nil
}

// extractTarEntry validates one tar entry against the manifest, then writes it
// into staging while verifying its size and SHA-256.
func extractTarEntry(tr *tar.Reader, hdr *tar.Header, staging string, expected map[string]ManifestFile) error {
	if hdr.Typeflag != tar.TypeReg {
		return fmt.Errorf("archive contains non-regular file %s", hdr.Name)
	}
	mf, ok := expected[hdr.Name]
	if !ok {
		return fmt.Errorf("archive contains unexpected file %s", hdr.Name)
	}
	if hdr.Size != mf.Size {
		return fmt.Errorf("size mismatch for %s: got %d want %d", hdr.Name, hdr.Size, mf.Size)
	}
	dst := filepath.Join(staging, filepath.FromSlash(hdr.Name))
	if !safeJoin(staging, dst) {
		return fmt.Errorf("unsafe archive path %s", hdr.Name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return &stagingIOError{err: err}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return &stagingIOError{err: err}
	}
	h := sha256.New()
	// stagingWriter tags a write-side (disk) failure so it is retried, not
	// rejected; a read-side failure from tr means the archive is corrupt.
	_, copyErr := io.Copy(io.MultiWriter(stagingWriter{w: out}, h), tr)
	// fsync the staged bytes here so the install step can publish the file
	// with a bare rename — renaming an unsynced file could surface a
	// zero-length artifact at its final repository path after a crash.
	var syncErr error
	if copyErr == nil {
		syncErr = out.Sync()
	}
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return &stagingIOError{err: syncErr}
	}
	if closeErr != nil {
		return &stagingIOError{err: closeErr}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != mf.SHA256 {
		return fmt.Errorf("sha256 mismatch for %s: got %s want %s", hdr.Name, got, mf.SHA256)
	}
	return nil
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeJSONAtomic(p string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeBytesAtomic(p, b, mode)
}

func writeBytesAtomic(p string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	// fsync the contents before the rename so a crash cannot leave a truncated
	// or zero-length file where the previous good one was. This backs the state
	// files, bundle manifests, signatures, and .complete markers.
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	ok = true
	fsyncDir(dir)
	return nil
}

// fsyncDir flushes a directory so a rename into it survives a crash. It is
// best-effort: some filesystems do not support directory fsync, and a failure
// to open or sync the directory must not fail an otherwise-completed write.
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}
