//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUploads pushes an arbitrary file through the uploads stream with a
// real curl multipart POST, verifies the high side serves it byte-for-byte,
// then exercises the one mutable corner of the mirror: deleting it again
// via the high side's loopback-gated admin endpoint.
func TestUploads(t *testing.T) {
	stack.Prepare(t)
	curl := requireTool(t, "curl")

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("generating payload: %v", err)
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "report.bin")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatalf("writing payload: %v", err)
	}

	out := run(t, tmp, nil, curl, "-fsS",
		"-X", "POST",
		"-F", "folder=e2e-docs",
		"-F", "file=@"+src,
		stack.LowURL+"/admin/uploads/collect")
	var res ExportResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("upload response does not parse as ExportResult: %v\n%s", err, out)
	}
	res = stack.checkResult(t, "uploads", res)
	if res.Stream != "uploads" {
		t.Fatalf("upload landed on stream %q, want uploads", res.Stream)
	}
	stack.WaitImported(t, "uploads", res.Sequence)

	servedURL := stack.HighURL + "/uploads/e2e-docs/report.bin"
	dl := filepath.Join(tmp, "downloaded.bin")
	run(t, tmp, nil, curl, "-fsS", "-o", dl, servedURL)
	got, err := os.ReadFile(dl)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded bytes differ from the uploaded file (%d vs %d bytes)", len(got), len(payload))
	}

	resp, err := http.Post(stack.HighURL+"/admin/uploads/delete", "application/json",
		strings.NewReader(`{"folder":"e2e-docs","name":"report.bin"}`))
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete returned HTTP %d", resp.StatusCode)
	}
	if code, _ := httpGet(t, servedURL); code != http.StatusNotFound {
		t.Fatalf("file still served after delete: HTTP %d", code)
	}
}
