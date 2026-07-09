package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// uploadPair is one name/content file of a test upload (a slice keeps the
// multipart part order deterministic).
type uploadPair struct{ name, content string }

// newUploadRequest builds the multipart POST the uploads form issues. An empty
// folder omits the field entirely.
func newUploadRequest(t *testing.T, folder string, files []uploadPair) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if folder != "" {
		if err := mw.WriteField("folder", folder); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		fw, err := mw.CreateFormFile("file", f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(fw, f.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/uploads/collect", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func collectUpload(t *testing.T, ls *LowServer, folder string, files []uploadPair) ExportResult {
	t.Helper()
	res, err := ls.HandleUploadsCollect(context.Background(), newUploadRequest(t, folder, files))
	if err != nil {
		t.Fatalf("HandleUploadsCollect: %v", err)
	}
	return res
}

func importNextUploads(t *testing.T, ls *LowServer, hs *HighServer, bundleID string) {
	t.Helper()
	transferAptBundle(t, ls, hs, bundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import %s: %v", bundleID, err)
	}
}

func deleteUpload(t *testing.T, srv *httptest.Server, folder, name string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"folder": folder, "name": name})
	resp, err := http.Post(srv.URL+"/admin/uploads/delete", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestUploadsRoundTrip drives the whole stream: upload two files into a folder
// on the low side, import on the high side, serve and list them, delete one,
// and bring it back — first unchanged (a deleted file must return by simply
// re-uploading, despite having been forwarded before), then with new content
// (a re-upload replaces the file).
func TestUploadsRoundTrip(t *testing.T) {
	ls, priv := newAptLowServer(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))

	res1 := collectUpload(t, ls, "tools", []uploadPair{{"hello.txt", "hello world"}, {"data.bin", "BYTES-1"}})
	if res1.BundleID != "uploads-bundle-000001" || res1.ExportedModules != 2 || res1.Skipped || res1.PriorFiles != 0 {
		t.Fatalf("first upload result = %+v", res1)
	}
	m := readBundleManifest(t, ls, res1.BundleID)
	if m.Uploads == nil || len(m.Uploads.Files) != 2 || m.Uploads.Files[0].Folder != "tools" {
		t.Fatalf("manifest uploads section = %+v", m.Uploads)
	}
	for _, f := range m.Files {
		if !strings.HasPrefix(f.Path, "uploads/tools/") {
			t.Fatalf("manifest file outside the folder namespace: %s", f.Path)
		}
	}

	importNextUploads(t, ls, hs, res1.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	assertServed(t, srv.URL+"/uploads/tools/hello.txt", "hello world")
	assertServed(t, srv.URL+"/uploads/tools/data.bin", "BYTES-1")

	// The listing shows the folder with both files.
	var list UploadsListResponse
	resp, err := http.Get(srv.URL + "/admin/uploads")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Folders) != 1 || list.Folders[0].Folder != "tools" || len(list.Folders[0].Files) != 2 {
		t.Fatalf("uploads listing = %+v", list.Folders)
	}

	// Delete one file: gone from serving; deleting again is a 404.
	if resp := deleteUpload(t, srv, "tools", "hello.txt"); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	if r, err := http.Get(srv.URL + "/uploads/tools/hello.txt"); err != nil || r.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted file GET = %v, %v; want 404", r.StatusCode, err)
	}
	if resp := deleteUpload(t, srv, "tools", "hello.txt"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", resp.StatusCode)
	}

	// Re-uploading the unchanged file must produce a bundle (never an
	// "already forwarded" skip — the high side just deleted it) and restore it.
	res2 := collectUpload(t, ls, "tools", []uploadPair{{"hello.txt", "hello world"}})
	if res2.Skipped || res2.PriorFiles != 0 || res2.BundleID != "uploads-bundle-000002" {
		t.Fatalf("re-upload result = %+v (uploads must never dedup-skip)", res2)
	}
	importNextUploads(t, ls, hs, res2.BundleID)
	assertServed(t, srv.URL+"/uploads/tools/hello.txt", "hello world")

	// Re-uploading with different content replaces the file on import.
	res3 := collectUpload(t, ls, "tools", []uploadPair{{"hello.txt", "hello v2"}})
	importNextUploads(t, ls, hs, res3.BundleID)
	assertServed(t, srv.URL+"/uploads/tools/hello.txt", "hello v2")

	// Deleting the folder's last files removes the folder from the listing.
	for _, name := range []string{"hello.txt", "data.bin"} {
		if resp := deleteUpload(t, srv, "tools", name); resp.StatusCode != http.StatusOK {
			t.Fatalf("delete %s status = %d", name, resp.StatusCode)
		}
	}
	folders, err := hs.listUploadedFolders()
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 0 {
		t.Fatalf("folders after deleting everything = %+v, want none", folders)
	}
}

// TestUploadsCollectValidation rejects bad folder names, path traversal, and
// empty uploads before anything is exported.
func TestUploadsCollectValidation(t *testing.T) {
	ls, _ := newAptLowServer(t)
	cases := []struct {
		desc   string
		folder string
		files  []uploadPair
		want   string
	}{
		{"missing folder", "", []uploadPair{{"a.txt", "x"}}, "empty folder name"},
		{"folder with slash", "a/b", []uploadPair{{"a.txt", "x"}}, "path separators"},
		{"dot-dot folder", "..", []uploadPair{{"a.txt", "x"}}, "must not start with a dot"},
		{"hidden folder", ".ssh", []uploadPair{{"a.txt", "x"}}, "must not start with a dot"},
		{"no files", "tools", nil, "no file in the upload"},
		{"hidden file", "tools", []uploadPair{{".bashrc", "x"}}, "must not start with a dot"},
		{"duplicate file", "tools", []uploadPair{{"a.txt", "x"}, {"a.txt", "y"}}, "appears twice"},
	}
	for _, tc := range cases {
		_, err := ls.HandleUploadsCollect(context.Background(), newUploadRequest(t, tc.folder, tc.files))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.desc, err, tc.want)
		}
	}
	// Nothing may have been exported or a sequence consumed.
	if seq := ls.peekSequence(streamUploads); seq != 1 {
		t.Errorf("next sequence = %d, want 1", seq)
	}
	// A path-y filename is neutralized to its base name rather than rejected
	// (browsers may send full client paths).
	res := collectUpload(t, ls, "tools", []uploadPair{{"dir/sub/tool.sh", "#!/bin/sh"}})
	m := readBundleManifest(t, ls, res.BundleID)
	if len(m.Files) != 1 || m.Files[0].Path != "uploads/tools/tool.sh" {
		t.Fatalf("path-y filename staged as %+v, want uploads/tools/tool.sh", m.Files)
	}
}

// TestValidateUploadsManifest covers the import-side checks: entries must
// reference listed manifest files at the canonical path with matching hashes.
func TestValidateUploadsManifest(t *testing.T) {
	sha := strings.Repeat("a", 64)
	good := UploadFile{Folder: "tools", Name: "a.txt", Path: "uploads/tools/a.txt", SHA256: sha, Size: 1}
	files := []ManifestFile{{Path: good.Path, SHA256: sha, Size: 1}}
	seen := map[string]bool{good.Path: true}

	if err := validateUploadsManifest(&UploadsManifest{Files: []UploadFile{good}}, seen, files); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	bad := good
	bad.Path = "uploads/other/a.txt"
	if err := validateUploadsManifest(&UploadsManifest{Files: []UploadFile{bad}}, seen, files); err == nil {
		t.Error("non-canonical path should be rejected")
	}
	unlisted := good
	unlisted.Name = "b.txt"
	unlisted.Path = "uploads/tools/b.txt"
	if err := validateUploadsManifest(&UploadsManifest{Files: []UploadFile{unlisted}}, seen, files); err == nil {
		t.Error("entry missing from manifest.files should be rejected")
	}
	mismatched := good
	mismatched.SHA256 = strings.Repeat("b", 64)
	if err := validateUploadsManifest(&UploadsManifest{Files: []UploadFile{mismatched}}, seen, files); err == nil {
		t.Error("sha mismatch should be rejected")
	}
	traversal := good
	traversal.Folder = ".."
	traversal.Path = "uploads/../a.txt"
	if err := validateUploadsManifest(&UploadsManifest{Files: []UploadFile{traversal}}, seen, files); err == nil {
		t.Error("traversal folder should be rejected")
	}
}

// TestUploadsCannotBeScheduled keeps the watch API away from a stream that has
// no upstream to re-pull.
func TestUploadsCannotBeScheduled(t *testing.T) {
	err := validateWatch(Watch{Stream: streamUploads, Label: "x", Spec: "{}", IntervalSeconds: 3600})
	if err == nil || !strings.Contains(err.Error(), "cannot be scheduled") {
		t.Fatalf("uploads watch = %v, want a 'cannot be scheduled' error", err)
	}
}

// TestUploadsTreeAndDetail exercises the dashboard endpoints: the two-level
// tree and the per-file detail panel.
func TestUploadsTreeAndDetail(t *testing.T) {
	ls, priv := newAptLowServer(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	res := collectUpload(t, ls, "docs", []uploadPair{{"readme.md", "# hi"}})
	importNextUploads(t, ls, hs, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	var tree struct {
		Nodes []UITreeNode `json:"nodes"`
	}
	getJSON := func(url string, into any) {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: HTTP %d", url, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			t.Fatal(err)
		}
	}
	getJSON(srv.URL+"/ui/api/tree?eco=uploads", &tree)
	if len(tree.Nodes) != 1 || tree.Nodes[0].Label != "docs" || !tree.Nodes[0].Expandable {
		t.Fatalf("root tree = %+v", tree.Nodes)
	}
	getJSON(srv.URL+"/ui/api/tree?eco=uploads&path=docs", &tree)
	if len(tree.Nodes) != 1 || tree.Nodes[0].Path != "docs/readme.md" || tree.Nodes[0].Kind != "file" {
		t.Fatalf("folder tree = %+v", tree.Nodes)
	}

	var detail UIDetail
	getJSON(srv.URL+"/ui/api/detail?eco=uploads&path="+`docs%2Freadme.md`, &detail)
	if detail.Title != "readme.md" {
		t.Fatalf("detail = %+v", detail)
	}
	fields := map[string]string{}
	for _, f := range detail.Fields {
		fields[f.Label] = f.Value
	}
	if fields["Download"] != "/uploads/docs/readme.md" || fields["Folder"] != "docs" {
		t.Fatalf("detail fields = %+v", detail.Fields)
	}

	// Traversal attempts against detail and delete fail cleanly.
	if resp, err := http.Get(srv.URL + "/ui/api/detail?eco=uploads&path=" + `..%2F..%2Fetc`); err != nil || resp.StatusCode == http.StatusOK {
		t.Fatalf("traversal detail = %v, %v; want an error status", resp.StatusCode, err)
	}
	if resp := deleteUpload(t, srv, "..", "passwd"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal delete status = %d, want 400", resp.StatusCode)
	}
}
