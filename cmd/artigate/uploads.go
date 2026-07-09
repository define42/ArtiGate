package main

// The "uploads" stream: arbitrary operator-chosen files, pushed through the
// diode without any upstream ecosystem behind them. The low side accepts a
// multipart upload (one folder name plus one or more files), packs it into a
// signed bundle like every other stream, and the high side serves the result
// under /uploads/<folder>/<name> — browsable from the dashboard, where files
// can also be deleted again.
//
// Uploads differ from the package ecosystems in two deliberate ways:
//
//   - No export dedup. An upload is a one-shot operator action, and the high
//     side may have deleted the file since it was last sent — an index-driven
//     "already forwarded" skip would silently withhold the re-upload. Every
//     upload collect is therefore a full bundle (exportIfNew's force path).
//   - Mutable content. Re-uploading a name into the same folder replaces the
//     file on import; everything outside uploads/ stays immutable.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// UploadsManifest is the uploads section of a bundle manifest.
type UploadsManifest struct {
	Files []UploadFile `json:"files"`
}

// UploadFile is one uploaded file: its operator-chosen folder and name, and
// the bundle path (uploads/<folder>/<name>) carrying the content.
type UploadFile struct {
	Folder string `json:"folder"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// uploadsFileRel is the bundle (and repository) path of one uploaded file.
func uploadsFileRel(folder, name string) string {
	return path.Join("uploads", folder, name)
}

// validateUploadComponent checks one operator-chosen path element (a folder
// or file name): a single non-hidden path segment with no separators or
// control characters, short enough to stay a sane filesystem name.
func validateUploadComponent(kind, s string) error {
	switch {
	case strings.TrimSpace(s) == "":
		return fmt.Errorf("empty %s name", kind)
	case s != strings.TrimSpace(s):
		return fmt.Errorf("%s name %q has leading or trailing whitespace", kind, s)
	case len(s) > 128:
		return fmt.Errorf("%s name is longer than 128 characters", kind)
	case strings.HasPrefix(s, "."):
		return fmt.Errorf("%s name %q must not start with a dot", kind, s)
	case strings.ContainsAny(s, `/\`):
		return fmt.Errorf("%s name %q must not contain path separators", kind, s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s name %q contains control characters", kind, s)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Import-side validation
// -----------------------------------------------------------------------------

// validateUploadsManifest checks each uploaded file's folder, name, and that
// its bundle path is listed in the manifest file set with a matching SHA-256.
func validateUploadsManifest(m *UploadsManifest, seen map[string]bool, files []ManifestFile) error {
	shaByPath := map[string]string{}
	for _, f := range files {
		shaByPath[f.Path] = f.SHA256
	}
	for _, f := range m.Files {
		if err := validateUploadComponent("folder", f.Folder); err != nil {
			return err
		}
		if err := validateUploadComponent("file", f.Name); err != nil {
			return err
		}
		if want := uploadsFileRel(f.Folder, f.Name); f.Path != want {
			return fmt.Errorf("upload %s/%s has path %q, want %q", f.Folder, f.Name, f.Path, want)
		}
		if !seen[f.Path] {
			return fmt.Errorf("upload references file not listed in manifest.files: %s", f.Path)
		}
		if shaByPath[f.Path] != f.SHA256 {
			return fmt.Errorf("upload %s has mismatched manifest sha256", f.Path)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Low side: multipart collect
// -----------------------------------------------------------------------------

// uploadFolderFieldLimit bounds the multipart "folder" field; folder names are
// capped far below this anyway.
const uploadFolderFieldLimit = 4 << 10

// stagedUpload is one file part already streamed (and hashed) into staging.
type stagedUpload struct {
	name string
	tmp  string
	sha  string
	size int64
}

// HandleUploadsCollect accepts a multipart/form-data POST: a "folder" field
// plus one or more file parts. Files stream straight into the collect's
// staging directory while being hashed, so an upload is never buffered in
// memory (models can be tens of gigabytes).
func (s *LowServer) HandleUploadsCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return ExportResult{}, fmt.Errorf("uploads collect expects multipart/form-data: %w", err)
	}

	stagingBase := filepath.Join(s.cfg.Root, "uploads", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	folder, staged, err := stageUploadParts(ctx, mr, stageRoot)
	if err != nil {
		return ExportResult{}, err
	}
	return s.collectUploads(ctx, folder, staged, stageRoot)
}

// stageUploadParts drains the multipart stream: the folder field is read into
// memory, every file part streams to a hashed temp file under stageRoot. Part
// order is not trusted — the folder may arrive after the files.
func stageUploadParts(ctx context.Context, mr *multipart.Reader, stageRoot string) (folder string, staged []stagedUpload, err error) {
	seen := map[string]bool{}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, err
		}
		up, folderVal, err := consumeUploadPart(ctx, part, stageRoot)
		if err != nil {
			return "", nil, err
		}
		if folderVal != "" {
			folder = folderVal
			continue
		}
		if up.name == "" {
			continue // an unknown non-file field, drained and ignored
		}
		if seen[up.name] {
			return "", nil, fmt.Errorf("file %q appears twice in the upload", up.name)
		}
		seen[up.name] = true
		staged = append(staged, up)
	}
	if err := validateUploadComponent("folder", folder); err != nil {
		return "", nil, err
	}
	if len(staged) == 0 {
		return "", nil, errors.New("no file in the upload")
	}
	return folder, staged, nil
}

// consumeUploadPart reads one multipart part: the folder field yields its
// (trimmed) value, a file part is staged and hashed, anything else is drained.
func consumeUploadPart(ctx context.Context, part *multipart.Part, stageRoot string) (stagedUpload, string, error) {
	defer func() { _ = part.Close() }()
	switch {
	case part.FormName() == "folder" && part.FileName() == "":
		b, err := io.ReadAll(io.LimitReader(part, uploadFolderFieldLimit))
		if err != nil {
			return stagedUpload{}, "", err
		}
		return stagedUpload{}, strings.TrimSpace(string(b)), nil
	case part.FileName() != "":
		up, err := stageOneUpload(ctx, part, stageRoot)
		return up, "", err
	default:
		_, _ = io.Copy(io.Discard, part)
		return stagedUpload{}, "", nil
	}
}

// stageOneUpload streams one file part to a temp file under stageRoot,
// hashing it on the way through. A cancelled request surfaces as a read error
// on the part (the server closes the request body), so no explicit context
// polling is needed.
func stageOneUpload(ctx context.Context, part *multipart.Part, stageRoot string) (stagedUpload, error) {
	name := path.Base(filepath.ToSlash(part.FileName()))
	if err := validateUploadComponent("file", name); err != nil {
		return stagedUpload{}, err
	}
	f, err := os.CreateTemp(stageRoot, "part-")
	if err != nil {
		return stagedUpload{}, err
	}
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(f, h), part)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		_ = os.Remove(f.Name())
		return stagedUpload{}, fmt.Errorf("%s: %w", name, err)
	}
	emitProgress(ctx, "  ↑ %s (%s)", name, formatBytes(size))
	return stagedUpload{name: name, tmp: f.Name(), sha: hex.EncodeToString(h.Sum(nil)), size: size}, nil
}

// collectUploads moves the staged files into the bundle layout and exports
// them. Dedup is deliberately bypassed (see the file header): every upload is
// a full, self-contained bundle.
func (s *LowServer) collectUploads(ctx context.Context, folder string, staged []stagedUpload, stageRoot string) (ExportResult, error) {
	mu := s.streamLock(streamUploads)
	mu.Lock()
	defer mu.Unlock()

	var files []ManifestFile
	var entries []UploadFile
	for _, up := range staged {
		rel := uploadsFileRel(folder, up.name)
		abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return ExportResult{}, err
		}
		if err := os.Rename(up.tmp, abs); err != nil {
			return ExportResult{}, err
		}
		files = append(files, ManifestFile{Path: rel, SHA256: up.sha, Size: up.size})
		entries = append(entries, UploadFile{Folder: folder, Name: up.name, Path: rel, SHA256: up.sha, Size: up.size})
	}

	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	res, err := s.exportIfNew(ctx, streamUploads, files, true, func(seq int64) (ExportResult, error) {
		return s.writeUploadsBundle(ctx, seq, stageRoot, files, entries)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.Message = fmt.Sprintf("uploaded into folder %q", folder)
	return res, nil
}

func (s *LowServer) writeUploadsBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, entries []UploadFile) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamUploads, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamUploads,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"uploads"},
		Uploads:          &UploadsManifest{Files: entries},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	sig := ed25519.Sign(s.privateKey, manifestBytes)
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, sig, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamUploads, Sequence: seq, ExportedModules: len(files), BundleID: id}, nil
}

// -----------------------------------------------------------------------------
// High side: serve, list, delete
// -----------------------------------------------------------------------------

func (s *HighServer) uploadsDir() string {
	return filepath.Join(s.downloadDir, "uploads")
}

// serveUploads serves the uploaded files under /uploads/<folder>/<name>. It
// reports whether it wrote a response.
func (s *HighServer) serveUploads(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/uploads" && !strings.HasPrefix(p, "/uploads/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, "/uploads"), "/")
	if rel == "" || validateRelPath(rel) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.uploadsDir(), filepath.FromSlash(rel))
	if !safeJoin(s.uploadsDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	serveFile(w, r, abs)
	return true
}

// UploadedFile is one file in a folder listing.
type UploadedFile struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// UploadedFolder is one folder of uploaded files.
type UploadedFolder struct {
	Folder string         `json:"folder"`
	Files  []UploadedFile `json:"files"`
}

// UploadsListResponse is the body of GET /admin/uploads.
type UploadsListResponse struct {
	Folders []UploadedFolder `json:"folders"`
}

type deleteUploadRequest struct {
	Folder string `json:"folder"`
	Name   string `json:"name"`
}

// serveUploadsAdmin handles the /admin/uploads* endpoints. It reports whether
// it handled the request.
func (s *HighServer) serveUploadsAdmin(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/admin/uploads" && isReadMethod(r):
		folders, err := s.listUploadedFolders()
		return respondJSONOrError(w, http.StatusInternalServerError, UploadsListResponse{Folders: folders}, err)
	case r.URL.Path == "/admin/uploads/delete" && r.Method == http.MethodPost:
		return s.handleDeleteUpload(w, r)
	default:
		return false
	}
}

// handleDeleteUpload removes one uploaded file from the repository — the only
// deletion the high side offers, because uploads are operator-owned content
// rather than immutable mirrored artifacts. An emptied folder is removed with
// its last file.
func (s *HighServer) handleDeleteUpload(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	var req deleteUploadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse delete request: %v", err), http.StatusBadRequest)
		return true
	}
	if err := validateUploadComponent("folder", req.Folder); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	if err := validateUploadComponent("file", req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	abs := filepath.Join(s.uploadsDir(), req.Folder, req.Name)
	if !safeJoin(s.uploadsDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	if err := os.Remove(abs); errors.Is(err, os.ErrNotExist) {
		http.Error(w, "file not found", http.StatusNotFound)
		return true
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	// Best-effort: a folder lives only through its files.
	_ = os.Remove(filepath.Dir(abs))
	log.Printf("uploads: deleted %s/%s", req.Folder, req.Name)
	writeJSON(w, map[string]string{"status": "ok"})
	return true
}

// listUploadedFolders walks the two-level uploads tree (folder/file) and
// returns it sorted. The filesystem is the only state, so a deletion is
// simply the file no longer being there.
func (s *HighServer) listUploadedFolders() ([]UploadedFolder, error) {
	root := s.uploadsDir()
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var folders []UploadedFolder
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, err := listUploadedFiles(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			continue
		}
		folders = append(folders, UploadedFolder{Folder: e.Name(), Files: files})
	}
	sort.Slice(folders, func(i, j int) bool { return folders[i].Folder < folders[j].Folder })
	return folders, nil
}

func listUploadedFiles(dir string) ([]UploadedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []UploadedFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		files = append(files, UploadedFile{Name: e.Name(), Size: info.Size(), Modified: info.ModTime().UTC()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// uploadsTreeChildren renders the two-level uploads tree: the root yields the
// folders, and expanding a folder yields its files as leaves.
func uploadsTreeChildren(folders []UploadedFolder, treePath string) []UITreeNode {
	if treePath == "" {
		nodes := make([]UITreeNode, 0, len(folders))
		for _, f := range folders {
			// Kind "project" so the dashboard captions the count as "files"
			// (like Python projects), not "packages".
			nodes = append(nodes, UITreeNode{Label: f.Folder, Path: f.Folder, Kind: "project", Expandable: true, Count: len(f.Files)})
		}
		return nodes
	}
	for _, f := range folders {
		if f.Folder != treePath {
			continue
		}
		nodes := make([]UITreeNode, 0, len(f.Files))
		for _, file := range f.Files {
			nodes = append(nodes, UITreeNode{Label: file.Name, Path: f.Folder + "/" + file.Name, Kind: "file"})
		}
		return nodes
	}
	return []UITreeNode{}
}

// uploadsDetail describes one uploaded file, selected as "folder/name".
func (s *HighServer) uploadsDetail(spec string) (UIDetail, error) {
	folder, name, ok := strings.Cut(spec, "/")
	if !ok {
		return UIDetail{}, errors.New("invalid upload path")
	}
	if validateUploadComponent("folder", folder) != nil || validateUploadComponent("file", name) != nil {
		return UIDetail{}, errors.New("invalid upload path")
	}
	abs := filepath.Join(s.uploadsDir(), folder, name)
	if !safeJoin(s.uploadsDir(), abs) {
		return UIDetail{}, errors.New("unsafe path")
	}
	st, err := os.Stat(abs)
	if err != nil {
		return UIDetail{}, errors.New("file not found")
	}
	fields := []UIDetailField{
		{Label: "Folder", Value: folder, Mono: true},
		{Label: "File", Value: name, Mono: true},
		{Label: "Size", Value: formatBytes(st.Size())},
		{Label: "Modified", Value: st.ModTime().UTC().Format(time.RFC3339)},
		{Label: "Download", Value: "/" + uploadsFileRel(folder, name), Mono: true},
	}
	if sum, err := sha256File(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	return UIDetail{Title: name, Subtitle: "uploads/" + folder, Fields: fields}, nil
}
