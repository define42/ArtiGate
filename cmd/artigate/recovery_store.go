package main

// Recovery artifacts are immutable directories. A manifest binds a bounded
// sequence of compressed parts to a complete file inventory; checkpoints also
// authenticate that manifest with a signature distinct from bundle signatures.
// The caller must hold the source root's maintenance lock while taking a copy.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	recoveryFormat                 = 1
	recoveryPartSize         int64 = 64 << 20
	recoveryMaxManifest      int64 = 64 << 20
	recoveryMaxFileSize      int64 = 1 << 40
	recoveryMaxTotalSize     int64 = 1 << 50
	recoveryMaxEntries             = 1_000_000
	recoverySignatureContext       = "ArtiGate recovery checkpoint v1"
)

type recoveryManifest struct {
	Format         int              `json:"format"`
	Kind           string           `json:"kind"`
	Role           string           `json:"role"`
	Created        time.Time        `json:"created"`
	Streams        map[string]int64 `json:"streams"`
	KeyFingerprint string           `json:"key_fingerprint,omitempty"`
	Files          []recoveryFile   `json:"files"`
	Parts          []recoveryPart   `json:"parts"`
}

type recoveryFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type recoveryPart struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type recoveryArtifact struct {
	Manifest recoveryManifest `json:"manifest"`
	Digest   string           `json:"digest"`
}

func writeRecoveryArtifact(ctx context.Context, sourceRoot, outputDir string, manifest recoveryManifest, privateKey ed25519.PrivateKey) (recoveryArtifact, error) {
	return writeRecoveryArtifactWithPartSize(ctx, sourceRoot, outputDir, manifest, privateKey, recoveryPartSize)
}

// partSize is an argument rather than a mutable global so tests can exercise
// splitting without allocating a production-sized artifact or introducing races.
func writeRecoveryArtifactWithPartSize(ctx context.Context, sourceRoot, outputDir string, manifest recoveryManifest, privateKey ed25519.PrivateKey, partSize int64) (recoveryArtifact, error) {
	if err := ctx.Err(); err != nil {
		return recoveryArtifact{}, err
	}
	if partSize <= 0 || partSize > recoveryPartSize {
		return recoveryArtifact{}, errors.New("invalid recovery part size")
	}
	if err := recoverySeparatePaths(sourceRoot, outputDir); err != nil {
		return recoveryArtifact{}, err
	}
	if err := recoveryCheckDirectory(sourceRoot); err != nil {
		return recoveryArtifact{}, err
	}
	manifest, err := initializeRecoveryManifest(manifest, privateKey)
	if err != nil {
		return recoveryArtifact{}, err
	}
	stage, err := recoveryStageDirectory(outputDir)
	if err != nil {
		return recoveryArtifact{}, err
	}
	defer os.RemoveAll(stage)
	manifest.Files, manifest.Parts, err = archiveRecoveryDirectory(ctx, sourceRoot, stage, partSize)
	if err != nil {
		return recoveryArtifact{}, err
	}
	result, err := writeRecoveryMetadata(stage, manifest, privateKey)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return recoveryArtifact{}, err
	}
	if err := fsyncDir(stage); err != nil {
		return recoveryArtifact{}, err
	}
	if err := publishRecoveryDirectory(stage, outputDir); err != nil {
		return recoveryArtifact{}, err
	}
	if err := fsyncDir(filepath.Dir(outputDir)); err != nil {
		return result, fmt.Errorf("recovery artifact published but parent sync failed: %w", err)
	}
	return result, nil
}

func initializeRecoveryManifest(manifest recoveryManifest, privateKey ed25519.PrivateKey) (recoveryManifest, error) {
	if manifest.Format != 0 && manifest.Format != recoveryFormat {
		return manifest, errors.New("unsupported recovery format")
	}
	manifest.Format = recoveryFormat
	if manifest.Created.IsZero() {
		manifest.Created = time.Now().UTC()
	}
	manifest.Files, manifest.Parts, manifest.KeyFingerprint = nil, nil, ""
	switch manifest.Kind {
	case "checkpoint":
		if len(privateKey) != ed25519.PrivateKeySize {
			return manifest, errors.New("checkpoint requires an Ed25519 private key")
		}
		fingerprint := sha256.Sum256(privateKey.Public().(ed25519.PublicKey))
		manifest.KeyFingerprint = hex.EncodeToString(fingerprint[:])
	case "backup":
		if len(privateKey) != 0 {
			return manifest, errors.New("backup artifacts use a trusted manifest digest, not a signing key")
		}
	}
	return manifest, validateRecoveryManifestHeader(manifest)
}

func archiveRecoveryDirectory(ctx context.Context, sourceRoot, stage string, partSize int64) ([]recoveryFile, []recoveryPart, error) {
	root, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	parts := &recoveryPartWriter{dir: stage, limit: partSize}
	defer parts.abort()
	compressed := gzip.NewWriter(parts)
	archive := tar.NewWriter(compressed)
	source := recoverySourceArchive{base: sourceRoot, root: root, writer: archive}
	err = filepath.WalkDir(sourceRoot, func(abs string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return source.add(ctx, abs, entry)
	})
	if err != nil {
		return nil, nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, nil, err
	}
	if err := compressed.Close(); err != nil {
		return nil, nil, err
	}
	if err := parts.finish(); err != nil {
		return nil, nil, err
	}
	return source.files, parts.parts, nil
}

type recoverySourceArchive struct {
	base   string
	root   *os.Root
	writer *tar.Writer
	files  []recoveryFile
	total  int64
}

func (s *recoverySourceArchive) add(ctx context.Context, abs string, entry fs.DirEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if err := s.validateFile(info); err != nil {
		return err
	}
	rel, err := filepath.Rel(s.base, abs)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if err := recoveryValidatePath(rel); err != nil {
		return err
	}
	mode := uint32(info.Mode().Perm() & 0o755)
	header := &tar.Header{Name: rel, Mode: int64(mode), Size: info.Size(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := s.writer.WriteHeader(header); err != nil {
		return err
	}
	digest := sha256.New()
	if err := recoveryCopySourceFile(ctx, s.root, rel, info, io.MultiWriter(s.writer, digest)); err != nil {
		return err
	}
	s.total += info.Size()
	s.files = append(s.files, recoveryFile{Path: rel, Size: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil)), Mode: mode})
	return nil
}

func (s *recoverySourceArchive) validateFile(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("recovery source contains a non-regular file: %s", info.Name())
	}
	if len(s.files) >= recoveryMaxEntries || info.Size() < 0 || info.Size() > recoveryMaxFileSize || s.total > recoveryMaxTotalSize-info.Size() {
		return errors.New("recovery source exceeds inventory or data limits")
	}
	return nil
}

func writeRecoveryMetadata(stage string, manifest recoveryManifest, privateKey ed25519.PrivateKey) (recoveryArtifact, error) {
	if err := validateRecoveryManifest(manifest); err != nil {
		return recoveryArtifact{}, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return recoveryArtifact{}, err
	}
	data = append(data, '\n')
	if int64(len(data)) > recoveryMaxManifest {
		return recoveryArtifact{}, errors.New("recovery manifest exceeds size limit")
	}
	if err := recoveryWriteFile(filepath.Join(stage, "manifest.json"), data); err != nil {
		return recoveryArtifact{}, err
	}
	if manifest.Kind == "checkpoint" {
		if err := writeRecoverySignature(stage, data, privateKey); err != nil {
			return recoveryArtifact{}, err
		}
	}
	digest := sha256.Sum256(data)
	return recoveryArtifact{Manifest: manifest, Digest: hex.EncodeToString(digest[:])}, nil
}

func writeRecoverySignature(stage string, data []byte, privateKey ed25519.PrivateKey) error {
	digest := sha512.Sum512(data)
	signature, err := privateKey.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512, Context: recoverySignatureContext})
	if err != nil {
		return err
	}
	return recoveryWriteFile(filepath.Join(stage, "signature"), signature)
}

func verifyRecoveryArtifact(ctx context.Context, artifactDir string, publicKey ed25519.PublicKey, expectedDigest string) (recoveryArtifact, error) {
	return readRecoveryArtifact(ctx, artifactDir, "", publicKey, expectedDigest)
}

func restoreRecoveryArtifact(ctx context.Context, artifactDir, targetRoot string, publicKey ed25519.PublicKey, expectedDigest string) (recoveryArtifact, error) {
	return restoreRecoveryArtifactPrepared(ctx, artifactDir, targetRoot, publicKey, expectedDigest, nil)
}

// prepare runs after authentication and state validation, inside the private
// staging directory. It must durably write any generated metadata before it
// returns; failure prevents activation of the restored root.
func restoreRecoveryArtifactPrepared(ctx context.Context, artifactDir, targetRoot string, publicKey ed25519.PublicKey, expectedDigest string, prepare func(context.Context, string) error) (recoveryArtifact, error) {
	ops := recoveryRestoreOps{syncDir: fsyncDir, publish: publishRecoveryDirectory, prepare: prepare}
	return restoreRecoveryArtifactConfigured(ctx, artifactDir, targetRoot, publicKey, expectedDigest, ops)
}

func restoreRecoveryArtifactWithOps(ctx context.Context, artifactDir, targetRoot string, publicKey ed25519.PublicKey, expectedDigest string, syncDir func(string) error, publish func(string, string) error) (recoveryArtifact, error) {
	ops := recoveryRestoreOps{syncDir: syncDir, publish: publish}
	return restoreRecoveryArtifactConfigured(ctx, artifactDir, targetRoot, publicKey, expectedDigest, ops)
}

type recoveryRestoreOps struct {
	syncDir func(string) error
	publish func(string, string) error
	prepare func(context.Context, string) error
}

func restoreRecoveryArtifactConfigured(ctx context.Context, artifactDir, targetRoot string, publicKey ed25519.PublicKey, expectedDigest string, ops recoveryRestoreOps) (recoveryArtifact, error) {
	var result recoveryArtifact
	if err := recoverySeparatePaths(artifactDir, targetRoot); err != nil {
		return result, err
	}
	stage, err := recoveryStageDirectory(targetRoot)
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(stage)
	result, err = readRecoveryArtifact(ctx, artifactDir, stage, publicKey, expectedDigest)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if result.Manifest.Kind == "checkpoint" {
		err = validateCheckpointState(stage, result.Manifest.Streams)
	} else {
		err = validateRecoveryBackupState(stage, result.Manifest)
	}
	if err != nil {
		return recoveryArtifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return recoveryArtifact{}, err
	}
	if ops.prepare != nil {
		if err := ops.prepare(ctx, stage); err != nil {
			return recoveryArtifact{}, fmt.Errorf("prepare restored repository: %w", err)
		}
	}
	if err := recoverySyncDirectories(ctx, stage, ops.syncDir); err != nil {
		return recoveryArtifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return recoveryArtifact{}, err
	}
	if err := ops.publish(stage, targetRoot); err != nil {
		return recoveryArtifact{}, err
	}
	if err := ops.syncDir(filepath.Dir(targetRoot)); err != nil {
		return result, fmt.Errorf("recovery root activated but parent sync failed: %w", err)
	}
	return result, nil
}

func readRecoveryArtifact(ctx context.Context, artifactDir, destination string, publicKey ed25519.PublicKey, expectedDigest string) (recoveryArtifact, error) {
	if err := ctx.Err(); err != nil {
		return recoveryArtifact{}, err
	}
	if err := recoveryCheckDirectory(artifactDir); err != nil {
		return recoveryArtifact{}, err
	}
	root, err := os.OpenRoot(artifactDir)
	if err != nil {
		return recoveryArtifact{}, err
	}
	defer root.Close()
	result, err := authenticateRecoveryArtifact(root, publicKey, expectedDigest)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if err := validateRecoveryArtifactDirectory(root, result.Manifest); err != nil {
		return recoveryArtifact{}, err
	}
	if err := readRecoveryArchive(ctx, root, destination, result.Manifest); err != nil {
		return recoveryArtifact{}, err
	}
	return result, nil
}

func authenticateRecoveryArtifact(root *os.Root, publicKey ed25519.PublicKey, expectedDigest string) (recoveryArtifact, error) {
	data, err := recoveryReadRegularFile(root, "manifest.json", recoveryMaxManifest)
	if err != nil {
		return recoveryArtifact{}, err
	}
	digest := sha256.Sum256(data)
	result := recoveryArtifact{Digest: hex.EncodeToString(digest[:])}
	if expectedDigest != "" && (!recoveryValidDigest(expectedDigest) || expectedDigest != result.Digest) {
		return recoveryArtifact{}, errors.New("recovery manifest digest does not match the trusted digest")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result.Manifest); err != nil {
		return recoveryArtifact{}, fmt.Errorf("decode recovery manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return recoveryArtifact{}, errors.New("extra data after recovery manifest")
	}
	if err := validateRecoveryManifest(result.Manifest); err != nil {
		return recoveryArtifact{}, err
	}
	if result.Manifest.Kind == "checkpoint" {
		err = authenticateRecoveryCheckpoint(root, result.Manifest, data, publicKey)
	} else {
		err = authenticateRecoveryBackup(result.Manifest, expectedDigest)
	}
	if err != nil {
		return recoveryArtifact{}, err
	}
	return result, nil
}

func authenticateRecoveryCheckpoint(root *os.Root, m recoveryManifest, data []byte, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("checkpoint verification requires an Ed25519 public key")
	}
	fingerprint := sha256.Sum256(publicKey)
	if m.KeyFingerprint != hex.EncodeToString(fingerprint[:]) {
		return errors.New("checkpoint signing key fingerprint mismatch")
	}
	signature, err := recoveryReadRegularFile(root, "signature", ed25519.SignatureSize)
	if err != nil {
		return err
	}
	ph := sha512.Sum512(data)
	if err := ed25519.VerifyWithOptions(publicKey, ph[:], signature, &ed25519.Options{Hash: crypto.SHA512, Context: recoverySignatureContext}); err != nil {
		return fmt.Errorf("checkpoint signature: %w", err)
	}
	return validateCheckpointManifest(m)
}

func authenticateRecoveryBackup(m recoveryManifest, expectedDigest string) error {
	if expectedDigest == "" {
		return errors.New("backup verification requires a trusted manifest digest")
	}
	return validateRecoveryBackupManifest(m)
}

func validateRecoveryArtifactDirectory(root *os.Root, m recoveryManifest) error {
	allowed := map[string]bool{"manifest.json": true}
	if m.Kind == "checkpoint" {
		allowed["signature"] = true
	}
	for _, part := range m.Parts {
		allowed[part.Path] = true
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(len(allowed) + 1)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) != len(allowed) {
		return errors.New("recovery artifact contains missing or undeclared files")
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !allowed[entry.Name()] || !info.Mode().IsRegular() {
			return fmt.Errorf("undeclared or non-regular artifact file %q", entry.Name())
		}
	}
	return nil
}

func readRecoveryArchive(ctx context.Context, root *os.Root, destination string, m recoveryManifest) error {
	parts := &recoveryPartReader{root: root, parts: m.Parts}
	defer parts.close()
	buffered := bufio.NewReader(&recoveryContextReader{ctx: ctx, reader: parts})
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return fmt.Errorf("open recovery archive: %w", err)
	}
	defer compressed.Close()
	compressed.Multistream(false)
	var total int64
	for _, file := range m.Files {
		total += file.Size
	}
	// Bound tar extension headers as well as file data; tar.Reader consumes PAX
	// records internally, before returning a header to our inventory checks.
	bounded := &io.LimitedReader{R: compressed, N: total + int64(len(m.Files))*16384 + (1 << 20)}
	archive := tar.NewReader(bounded)
	state, err := readRecoveryFiles(ctx, archive, destination, m)
	if err != nil {
		return err
	}
	if err := finishRecoveryArchive(archive, bounded, compressed, buffered, m.Files); err != nil {
		return err
	}
	return validateRecoveryStateBytes(state, m)
}

func readRecoveryFiles(ctx context.Context, archive *tar.Reader, destination string, m recoveryManifest) ([]byte, error) {
	var state bytes.Buffer
	for _, file := range m.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if err != nil {
			return nil, fmt.Errorf("recovery file %s: %w", file.Path, err)
		}
		if err := validateRecoveryTarHeader(header, file); err != nil {
			return nil, err
		}
		var capture io.Writer
		if file.Path == recoveryStatePath(m.Role) {
			if file.Size > 1<<20 {
				return nil, errors.New("recovery sequence state exceeds 1 MiB")
			}
			capture = &state
		}
		if err := recoveryReadArchiveFile(ctx, archive, destination, file, capture); err != nil {
			return nil, err
		}
	}
	return state.Bytes(), nil
}

func validateRecoveryTarHeader(header *tar.Header, file recoveryFile) error {
	if header.Name != file.Path || header.Size != file.Size || header.Mode != int64(file.Mode) || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Format == tar.FormatGNU {
		return fmt.Errorf("recovery archive header does not match inventory for %q", file.Path)
	}
	return nil
}

func finishRecoveryArchive(archive *tar.Reader, bounded *io.LimitedReader, compressed *gzip.Reader, buffered *bufio.Reader, files []recoveryFile) error {
	beforeEnd := bounded.N
	if _, err := archive.Next(); !errors.Is(err, io.EOF) {
		return errors.New("recovery archive has extra or invalid entries")
	}
	endSize := int64(1024)
	if len(files) > 0 {
		endSize += (512 - files[len(files)-1].Size%512) % 512
	}
	if beforeEnd-bounded.N != endSize {
		return errors.New("recovery archive has a truncated or invalid tar terminator")
	}
	if bounded.N == 0 {
		return errors.New("recovery archive exceeds decompressed size limit")
	}
	var extra [1]byte
	if n, err := compressed.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("recovery archive has trailing data or an invalid gzip checksum")
	}
	if _, err := buffered.ReadByte(); !errors.Is(err, io.EOF) {
		return errors.New("recovery archive has extra compressed data or an invalid part checksum")
	}
	return nil
}

func validateRecoveryStateBytes(data []byte, m recoveryManifest) error {
	if m.Kind == "checkpoint" {
		return validateCheckpointStateBytes(data, m.Streams)
	}
	streams, err := recoveryBackupStreamsFromState(data, m.Role)
	if err != nil {
		return err
	}
	if !maps.Equal(streams, m.Streams) {
		return errors.New("backup manifest frontier does not match its saved sequence state")
	}
	return nil
}

func validateRecoveryManifestHeader(m recoveryManifest) error {
	if m.Format != recoveryFormat || (m.Kind != "checkpoint" && m.Kind != "backup") || (m.Role != "high" && m.Role != "low") || m.Created.IsZero() {
		return errors.New("unsupported or incomplete recovery manifest")
	}
	if m.Kind == "checkpoint" && (m.Role != "high" || !recoveryValidDigest(m.KeyFingerprint)) {
		return errors.New("invalid checkpoint role or signing key fingerprint")
	}
	if m.Kind == "backup" && m.KeyFingerprint != "" {
		return errors.New("backup manifest must not declare a signing key")
	}
	known := knownStreams()
	for stream, sequence := range m.Streams {
		if !slices.Contains(known, stream) || sequence < 0 {
			return fmt.Errorf("invalid recovery frontier %q: %d", stream, sequence)
		}
	}
	return nil
}

func validateRecoveryManifest(m recoveryManifest) error {
	if err := validateRecoveryManifestHeader(m); err != nil {
		return err
	}
	if len(m.Files) > recoveryMaxEntries || len(m.Parts) == 0 || len(m.Parts) > recoveryMaxEntries {
		return errors.New("recovery manifest exceeds inventory limits or has no parts")
	}
	if err := validateRecoveryFileInventory(m.Files); err != nil {
		return err
	}
	for i, part := range m.Parts {
		if part.Path != recoveryPartName(i) || part.Size <= 0 || part.Size > recoveryPartSize || !recoveryValidDigest(part.SHA256) {
			return fmt.Errorf("invalid recovery part %q", part.Path)
		}
	}
	return nil
}

func validateRecoveryFileInventory(files []recoveryFile) error {
	var total int64
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		if err := validateRecoveryFile(file); err != nil {
			return err
		}
		if seen[file.Path] || total > recoveryMaxTotalSize-file.Size {
			return fmt.Errorf("duplicate or oversized recovery inventory entry %q", file.Path)
		}
		seen[file.Path] = true
		total += file.Size
	}
	for _, file := range files {
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			if seen[parent] {
				return fmt.Errorf("recovery file %q conflicts with parent file %q", file.Path, parent)
			}
		}
	}
	return nil
}

func validateRecoveryFile(file recoveryFile) error {
	if err := recoveryValidatePath(file.Path); err != nil {
		return err
	}
	if file.Size < 0 || file.Size > recoveryMaxFileSize || !recoveryValidDigest(file.SHA256) || file.Mode&^0o755 != 0 {
		return fmt.Errorf("invalid recovery inventory entry %q", file.Path)
	}
	return nil
}

func recoveryValidDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func recoveryValidatePath(name string) error {
	if len(name) > 4096 || strings.ContainsAny(name, "\x00:\r\n") {
		return fmt.Errorf("invalid recovery path %q", name)
	}
	if err := validateRelPath(name); err != nil {
		return fmt.Errorf("invalid recovery path %q: %w", name, err)
	}
	return nil
}

func recoveryPartName(index int) string {
	return fmt.Sprintf("part-%06d.tar.gz", index+1)
}

type recoveryPartWriter struct {
	dir   string
	limit int64
	file  *os.File
	hash  hash.Hash
	size  int64
	parts []recoveryPart
}

func (w *recoveryPartWriter) Write(data []byte) (int, error) {
	var written int
	for len(data) > 0 {
		if err := w.openNext(); err != nil {
			return written, err
		}
		count := min(int64(len(data)), w.limit-w.size)
		n, err := w.file.Write(data[:count])
		_, _ = w.hash.Write(data[:n])
		w.size += int64(n)
		written += n
		data = data[n:]
		if err != nil {
			return written, err
		}
		if int64(n) != count {
			return written, io.ErrShortWrite
		}
		if err := w.finishFullPart(); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (w *recoveryPartWriter) openNext() error {
	if w.file != nil {
		return nil
	}
	if len(w.parts) >= recoveryMaxEntries {
		return errors.New("recovery artifact has too many parts")
	}
	file, err := os.OpenFile(filepath.Join(w.dir, recoveryPartName(len(w.parts))), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	w.file, w.hash, w.size = file, sha256.New(), 0
	return nil
}

func (w *recoveryPartWriter) finishFullPart() error {
	if w.size == w.limit {
		return w.finish()
	}
	return nil
}

func (w *recoveryPartWriter) finish() error {
	if w.file == nil {
		return nil
	}
	syncErr := w.file.Sync()
	closeErr := w.file.Close()
	w.file = nil
	if err := firstErr(syncErr, closeErr); err != nil {
		return err
	}
	w.parts = append(w.parts, recoveryPart{Path: recoveryPartName(len(w.parts)), Size: w.size, SHA256: hex.EncodeToString(w.hash.Sum(nil))})
	return nil
}

func (w *recoveryPartWriter) abort() {
	if w.file != nil {
		_ = w.file.Close()
	}
}

type recoveryPartReader struct {
	root  *os.Root
	parts []recoveryPart
	index int
	file  *os.File
	hash  hash.Hash
	size  int64
}

func (r *recoveryPartReader) Read(data []byte) (int, error) {
	for r.index < len(r.parts) {
		if err := r.openCurrent(); err != nil {
			return 0, err
		}
		n, err := r.file.Read(data)
		_, _ = r.hash.Write(data[:n])
		r.size += int64(n)
		if r.size > r.parts[r.index].Size {
			return n, errors.New("recovery part grew during verification")
		}
		if !errors.Is(err, io.EOF) {
			return n, err
		}
		if err := r.advance(); err != nil {
			return n, err
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, io.EOF
}

func (r *recoveryPartReader) openCurrent() error {
	if r.file != nil {
		return nil
	}
	part := r.parts[r.index]
	info, err := r.root.Lstat(part.Path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != part.Size {
		return fmt.Errorf("recovery part %q has wrong type or size", part.Path)
	}
	file, err := r.root.Open(part.Path)
	if err != nil {
		return err
	}
	r.file, r.hash, r.size = file, sha256.New(), 0
	return nil
}

func (r *recoveryPartReader) advance() error {
	part := r.parts[r.index]
	closeErr := r.file.Close()
	r.file = nil
	if closeErr != nil {
		return closeErr
	}
	if r.size != part.Size || hex.EncodeToString(r.hash.Sum(nil)) != part.SHA256 {
		return fmt.Errorf("recovery part %q checksum mismatch", part.Path)
	}
	r.index++
	return nil
}

func (r *recoveryPartReader) close() {
	if r.file != nil {
		_ = r.file.Close()
	}
}

type recoveryContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *recoveryContextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func recoveryReadRegularFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("recovery file %q has invalid type or size", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if err := firstErr(readErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("recovery file %q exceeds size limit", name)
	}
	return data, nil
}

func recoveryCopySourceFile(ctx context.Context, root *os.Root, name string, expected fs.FileInfo, destination io.Writer) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, expected) {
		return fmt.Errorf("recovery source changed: %s", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, expected) || !before.Mode().IsRegular() || before.Size() != expected.Size() || !before.ModTime().Equal(expected.ModTime()) {
		return fmt.Errorf("recovery source changed: %s", name)
	}
	written, err := io.Copy(destination, &recoveryContextReader{ctx: ctx, reader: io.LimitReader(file, expected.Size()+1)})
	if err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if written != expected.Size() || after.Size() != expected.Size() || !after.ModTime().Equal(expected.ModTime()) {
		return fmt.Errorf("recovery source changed while reading: %s", name)
	}
	return nil
}

func recoveryReadArchiveFile(ctx context.Context, archive io.Reader, destination string, entry recoveryFile, capture io.Writer) error {
	digest := sha256.New()
	var output *os.File
	var writer io.Writer = digest
	if destination != "" {
		abs := filepath.Join(destination, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return err
		}
		file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		output = file
		defer output.Close()
		writer = io.MultiWriter(output, digest)
	}
	if capture != nil {
		writer = io.MultiWriter(writer, capture)
	}
	written, err := io.Copy(writer, &recoveryContextReader{ctx: ctx, reader: archive})
	if err != nil {
		return err
	}
	if written != entry.Size || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("recovery file %q checksum or size mismatch", entry.Path)
	}
	return recoveryFinalizeRestoredFile(output, entry.Mode)
}

func recoveryFinalizeRestoredFile(output *os.File, mode uint32) error {
	if output == nil {
		return nil
	}
	if err := output.Chmod(fs.FileMode(mode)); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	return output.Close()
}

func recoveryWriteFile(name string, data []byte) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	return firstErr(writeErr, syncErr, closeErr)
}

func recoveryCheckDirectory(name string) error {
	abs, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	// Resolve every component with Lstat so selecting a symlinked root (or an
	// artifact below a symlinked parent) never silently broadens the source.
	for current := abs; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("recovery path is not a real directory: %s", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func recoverySeparatePaths(first, second string) error {
	a, err := filepath.Abs(first)
	if err != nil {
		return err
	}
	b, err := filepath.Abs(second)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if rel == "." || filepath.IsLocal(rel) {
			return errors.New("recovery source and destination must not overlap")
		}
	}
	return nil
}

func recoveryStageDirectory(target string) (string, error) {
	if err := recoveryCheckDirectory(filepath.Dir(target)); err != nil {
		return "", err
	}
	if _, err := os.Lstat(target); err == nil {
		return "", fmt.Errorf("recovery destination already exists: %s", target)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return os.MkdirTemp(filepath.Dir(target), ".artigate-recovery-")
}

func recoverySyncDirectories(ctx context.Context, root string, syncDir func(string) error) error {
	var directories []string
	if err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, name)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, directory := range slices.Backward(directories) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := syncDir(directory); err != nil {
			return err
		}
	}
	return nil
}
