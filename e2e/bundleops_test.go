//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// bundleFileSuffixes mirrors cmd/artigate's bundle triple, in the delivery
// order every transport uses: the archive first, the manifest last, so a
// bundle can never look complete (all three names present) before its content
// has fully arrived.
func bundleFileSuffixes() []string {
	return []string{".tar.gz", ".manifest.json.sig", ".manifest.json"}
}

// uploadsCollect pushes one in-memory file through the low side's uploads
// stream and returns the collect's ExportResult. The uploads stream needs no
// upstream network, which makes it the vehicle for every transport/trust test.
func uploadsCollect(t *testing.T, lowURL, folder, name string, content []byte) ExportResult {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("folder", folder); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(lowURL+"/admin/uploads/collect", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("uploads collect: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("uploads collect: reading body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("uploads collect: HTTP %d: %s", resp.StatusCode, body)
	}
	var res ExportResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("uploads collect response does not parse: %v\n%s", err, body)
	}
	return res
}

// deliverBundle plays the folder diode: it carries a bundle's three files
// from srcDir into the landing directory. Each file is written to a temp name
// and renamed into place so the importer can never observe a half-copied
// file, and the manifest goes last so the bundle only becomes complete once
// its archive is fully present. tamper, when non-nil, may rewrite each file's
// bytes on the way (keyed by suffix) — the tamper tests' injection point.
func deliverBundle(t *testing.T, srcDir, landing, bundleID string, tamper func(suffix string, b []byte) []byte) {
	t.Helper()
	for _, suffix := range bundleFileSuffixes() {
		b, err := os.ReadFile(filepath.Join(srcDir, bundleID+suffix))
		if err != nil {
			t.Fatalf("read bundle file: %v", err)
		}
		if tamper != nil {
			b = tamper(suffix, b)
		}
		dst := filepath.Join(landing, bundleID+suffix)
		tmp := dst + ".delivering"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			t.Fatalf("write %s: %v", tmp, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			t.Fatalf("rename into landing: %v", err)
		}
	}
}

// streamStatus mirrors the high side's full per-stream import status
// (cmd/artigate's StreamImportStatus).
type streamStatus struct {
	Stream               string   `json:"stream"`
	LastImportedSequence int64    `json:"last_imported_sequence"`
	NextExpectedSequence int64    `json:"next_expected_sequence"`
	HighestSeenSequence  int64    `json:"highest_seen_sequence"`
	BlockingMissing      int64    `json:"blocking_missing_sequence"`
	MissingRanges        []string `json:"missing_ranges"`
	QuarantinedSequences []int64  `json:"quarantined_sequences"`
	ReadyToImport        bool     `json:"ready_to_import"`
}

// highStreamStatus fetches /admin/status and returns the named stream's
// status (zero value when the stream has no state yet).
func highStreamStatus(t *testing.T, highURL, stream string) streamStatus {
	t.Helper()
	code, body := httpGet(t, highURL+"/admin/status")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/status = %d: %s", code, body)
	}
	var st struct {
		Streams []streamStatus `json:"streams"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("parse /admin/status: %v\n%s", err, body)
	}
	for _, s := range st.Streams {
		if s.Stream == stream {
			return s
		}
	}
	return streamStatus{Stream: stream}
}

// waitHighStream polls the stream's import status until cond holds, failing
// with the last observed status after the deadline. GET /admin/status also
// runs the quarantine sweep, so polling drives landing-directory sorting even
// between import ticks.
func waitHighStream(t *testing.T, highURL, stream, desc string, cond func(streamStatus) bool) streamStatus {
	t.Helper()
	deadline := time.Now().Add(importTimeout)
	var last streamStatus
	for time.Now().Before(deadline) {
		last = highStreamStatus(t, highURL, stream)
		if cond(last) {
			return last
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("stream %s never reached %q; last status: %+v", stream, desc, last)
	return streamStatus{}
}

// waitForFile polls until path exists (a rejected-reason marker, a duplicate
// filing), failing after the deadline.
func waitForFile(t *testing.T, path, what string) {
	t.Helper()
	deadline := time.Now().Add(importTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s never appeared at %s", what, path)
}
