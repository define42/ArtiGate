//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

// TestReexportReimportIdempotency covers the low-side re-export control plane
// and the high-side re-import idempotency together, end-to-end over the real
// HTTP diode: a bundle is collected and imported, then re-exported (the low
// side replays the exact archived bytes and re-transmits them), and the high
// side must recognise the already-imported sequence as a duplicate — filing it
// aside without advancing the stream or disturbing the served content. Neither
// path had e2e coverage. The uploads stream needs no upstream network, so the
// whole flow is deterministic.
func TestReexportReimportIdempotency(t *testing.T) {
	p := startTestPair(t, pairConfig{name: "reimport", httpDiode: true})

	content := []byte("idempotent-artifact-bytes\n")
	res := uploadsCollect(t, p.LowURL, "idem", "artifact.bin", content)
	if res.Sequence != 1 {
		t.Fatalf("first uploads bundle got sequence %d, want 1", res.Sequence)
	}
	if res.DiodeError != "" {
		t.Fatalf("bundle upload to the high side failed: %s", res.DiodeError)
	}
	waitHighStream(t, p.HighURL, "uploads", "seq 1 imported", func(s streamStatus) bool {
		return s.LastImportedSequence >= 1
	})
	servedURL := p.HighURL + "/uploads/idem/artifact.bin"
	if code, body := httpGet(t, servedURL); code != http.StatusOK || !bytes.Equal(body, content) {
		t.Fatalf("content not served after first import: HTTP %d, %d bytes", code, len(body))
	}

	// Re-export sequence 1: the low side replays the archived bundle and
	// re-transmits it over the diode to the high side.
	resp, err := http.Post(p.LowURL+"/admin/reexport?stream=uploads&sequences=1", "application/json", nil)
	if err != nil {
		t.Fatalf("reexport request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reexport returned HTTP %d", resp.StatusCode)
	}
	var rr struct {
		Sequences  []int64 `json:"sequences"`
		Reexported []struct {
			BundleID   string `json:"bundle_id"`
			DiodeError string `json:"diode_error"`
		} `json:"reexported"`
		Failed []string `json:"failed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		t.Fatalf("parse reexport result: %v", err)
	}
	if len(rr.Failed) != 0 || len(rr.Reexported) != 1 || rr.Reexported[0].DiodeError != "" {
		t.Fatalf("reexport did not cleanly replay sequence 1: %+v", rr)
	}

	// The re-transmitted bundle is an already-imported sequence, so the high
	// side must file it as a duplicate rather than re-import it. The duplicate
	// filing (landing/duplicates/<id>) is the durable signal it was recognised.
	bundleID := rr.Reexported[0].BundleID
	waitForFile(t, filepath.Join(p.Landing, "duplicates", bundleID+".manifest.json"),
		"duplicate filing for re-imported "+bundleID)

	// The stream never advanced past 1, and the content is still served
	// byte-for-byte — re-import changed nothing.
	if st := highStreamStatus(t, p.HighURL, "uploads"); st.LastImportedSequence != 1 {
		t.Fatalf("stream advanced to %d after a duplicate re-import, want 1", st.LastImportedSequence)
	}
	if code, body := httpGet(t, servedURL); code != http.StatusOK || !bytes.Equal(body, content) {
		t.Fatalf("content disturbed by duplicate re-import: HTTP %d, %d bytes", code, len(body))
	}
}
