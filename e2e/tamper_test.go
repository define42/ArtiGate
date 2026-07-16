//go:build e2e

package e2e

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestTamperRejectionServesPriorContent exercises the whole trust boundary
// end-to-end, which is otherwise only unit-tested: a first clean bundle is
// delivered, imported, and served; then a second bundle is delivered twice —
// once with a flipped manifest-signature byte, once with a corrupted archive
// byte — and each time the high side must reject it (a rejected/ reason marker
// appears, the bundle leaves landing, the stream does not advance, and the
// tampered content is never served) while continuing to serve the first
// bundle untouched.
//
// The pair uses the folder-diode flow (no push transport), so the test itself
// carries each bundle's bytes from the low side's export dir into the high
// side's landing directory and injects the tampering in transit — the diode
// carries zero trust exactly as a real folder or wire transport would.
func TestTamperRejectionServesPriorContent(t *testing.T) {
	p := startTestPair(t, pairConfig{name: "tamper"})

	// Bundle 1 (seq 1): delivered clean, must import and serve.
	good := []byte("the-verified-original-artifact\n")
	res1 := uploadsCollect(t, p.LowURL, "trust", "good.bin", good)
	if res1.Sequence != 1 {
		t.Fatalf("first uploads bundle got sequence %d, want 1", res1.Sequence)
	}
	deliverBundle(t, p.ExportDir, p.Landing, res1.BundleID, nil)
	waitHighStream(t, p.HighURL, "uploads", "seq 1 imported", func(s streamStatus) bool {
		return s.LastImportedSequence >= 1
	})
	goodURL := p.HighURL + "/uploads/trust/good.bin"
	if code, body := httpGet(t, goodURL); code != http.StatusOK || !bytes.Equal(body, good) {
		t.Fatalf("clean bundle not served byte-for-byte: HTTP %d, %d bytes", code, len(body))
	}

	// Bundle 2 (seq 2): produced once on the low side, then delivered tampered.
	// Its content must never reach the served tree under either attack.
	poison := []byte("attacker-substituted-bytes-should-never-serve\n")
	res2 := uploadsCollect(t, p.LowURL, "trust", "poison.bin", poison)
	if res2.Sequence != 2 {
		t.Fatalf("second uploads bundle got sequence %d, want 2", res2.Sequence)
	}
	poisonURL := p.HighURL + "/uploads/trust/poison.bin"

	t.Run("flipped signature byte", func(t *testing.T) {
		deliverAndExpectReject(t, p, res2.BundleID, flipByteIn(".manifest.json.sig"))
	})
	t.Run("corrupted archive byte", func(t *testing.T) {
		deliverAndExpectReject(t, p, res2.BundleID, flipByteIn(".tar.gz"))
	})

	// The tampered content never served, and the stream never advanced past 1.
	if code, _ := httpGet(t, poisonURL); code != http.StatusNotFound {
		t.Fatalf("tampered content is being served: HTTP %d, want 404", code)
	}
	if st := highStreamStatus(t, p.HighURL, "uploads"); st.LastImportedSequence != 1 {
		t.Fatalf("stream advanced to %d after rejections, want 1", st.LastImportedSequence)
	}
	// And the first, legitimately-signed bundle is still served untouched — a
	// rejection must not disturb already-verified content.
	if code, body := httpGet(t, goodURL); code != http.StatusOK || !bytes.Equal(body, good) {
		t.Fatalf("prior clean content disturbed by rejection: HTTP %d, %d bytes", code, len(body))
	}
}

// deliverAndExpectReject clears any prior rejection marker for the bundle,
// delivers it through the tamper hook, and asserts the high side rejects it:
// the reason marker (re)appears in rejected/ and the bundle no longer sits in
// landing, so it cannot be silently retried. Clearing first makes the marker's
// reappearance an unambiguous edge even when an earlier subtest already
// rejected the same bundle id.
func deliverAndExpectReject(t *testing.T, p *testPair, bundleID string, tamper func(string, []byte) []byte) {
	t.Helper()
	reason := filepath.Join(p.HighRoot, "rejected", bundleID+".reason.txt")
	if err := os.Remove(reason); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clearing prior reason marker: %v", err)
	}
	deliverBundle(t, p.ExportDir, p.Landing, bundleID, tamper)
	waitForFile(t, reason, "rejection reason for "+bundleID)
	for _, suffix := range bundleFileSuffixes() {
		if _, err := os.Stat(filepath.Join(p.Landing, bundleID+suffix)); !os.IsNotExist(err) {
			t.Fatalf("rejected bundle file %s%s still in landing (err=%v)", bundleID, suffix, err)
		}
	}
}

// flipByteIn returns a tamper hook that flips one bit in the middle of the
// bundle file with the given suffix, leaving the other two files intact. A
// corrupted signature fails Ed25519 verification; a corrupted archive fails
// the per-file SHA-256 check during extraction — both are content-invalid and
// must be rejected, not retried.
func flipByteIn(suffix string) func(string, []byte) []byte {
	return func(s string, b []byte) []byte {
		if s != suffix || len(b) == 0 {
			return b
		}
		out := append([]byte(nil), b...)
		out[len(out)/2] ^= 0x01
		return out
	}
}

// TestQuarantineSequenceGapResume covers per-stream sequencing end-to-end: a
// future bundle delivered before its predecessor is held in quarantine (the
// stream reports the gap and refuses to serve it), and once the missing
// predecessor arrives, both import in order and both become servable. This is
// the "each ecosystem is an independently sequenced stream" invariant that
// only unit tests touch today.
func TestQuarantineSequenceGapResume(t *testing.T) {
	p := startTestPair(t, pairConfig{name: "quarantine"})

	first := []byte("first-in-sequence\n")
	second := []byte("second-in-sequence\n")
	res1 := uploadsCollect(t, p.LowURL, "seq", "first.bin", first)
	res2 := uploadsCollect(t, p.LowURL, "seq", "second.bin", second)
	if res1.Sequence != 1 || res2.Sequence != 2 {
		t.Fatalf("unexpected sequences: %d, %d (want 1, 2)", res1.Sequence, res2.Sequence)
	}

	// Deliver seq 2 first. With seq 1 still missing, it must be quarantined —
	// held complete but not imported — and the stream must report seq 1 as the
	// blocking gap. Nothing from seq 2 may be served yet.
	deliverBundle(t, p.ExportDir, p.Landing, res2.BundleID, nil)
	st := waitHighStream(t, p.HighURL, "uploads", "seq 2 quarantined", func(s streamStatus) bool {
		return containsInt64(s.QuarantinedSequences, 2)
	})
	if st.LastImportedSequence != 0 || st.BlockingMissing != 1 {
		t.Fatalf("gap not reported: last=%d blocking=%d, want last=0 blocking=1", st.LastImportedSequence, st.BlockingMissing)
	}
	if code, _ := httpGet(t, p.HighURL+"/uploads/seq/second.bin"); code != http.StatusNotFound {
		t.Fatalf("quarantined content served before its predecessor: HTTP %d, want 404", code)
	}

	// Deliver the missing seq 1. The drain now imports 1, then resumes into the
	// quarantined 2, and both files become servable in order.
	deliverBundle(t, p.ExportDir, p.Landing, res1.BundleID, nil)
	waitHighStream(t, p.HighURL, "uploads", "both imported", func(s streamStatus) bool {
		return s.LastImportedSequence >= 2
	})
	for name, want := range map[string][]byte{"first.bin": first, "second.bin": second} {
		url := p.HighURL + "/uploads/seq/" + name
		if code, body := httpGet(t, url); code != http.StatusOK || !bytes.Equal(body, want) {
			t.Fatalf("%s not served after resume: HTTP %d, %d bytes", name, code, len(body))
		}
	}
	if st := highStreamStatus(t, p.HighURL, "uploads"); st.BlockingMissing != 0 || len(st.QuarantinedSequences) != 0 {
		t.Fatalf("gap not cleared after resume: %+v", st)
	}
}

func containsInt64(xs []int64, want int64) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
