//go:build e2e

package e2e

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestSnap mirrors a real snap from the Snap Store across the diode and
// consumes it the way snapd's offline flow does: the served .snap must be the
// squashfs the .assert's snap-revision assertion vouches for. The pair is
// what `snap ack` + `snap install` need, so verifying the digest binding here
// covers the install contract without a running snapd (which needs root and a
// daemon).
func TestSnap(t *testing.T) {
	stack.Prepare(t)

	// "hello" is tiny and stable; no_bases keeps its ~80 MB base snap out of
	// the transfer — the base path is covered by the unit suite.
	res := stack.Collect(t, "snap", map[string]any{
		"snaps":    []string{"hello"},
		"no_bases": true,
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the requested snap, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "snap", res.Sequence)

	revision, version := snapInfoRevision(t)
	t.Logf("mirrored hello revision %d (version %s)", revision, version)

	snapURL := fmt.Sprintf("%s/snap/files/hello/hello_%d.snap", stack.HighURL, revision)
	code, body := httpGet(t, snapURL)
	if code != 200 {
		t.Fatalf("GET %s: status %d", snapURL, code)
	}
	if len(body) < 4 || string(body[:4]) != "hsqs" {
		t.Fatalf("served snap does not start with the squashfs magic: %q", body[:min(4, len(body))])
	}

	assertURL := fmt.Sprintf("%s/snap/files/hello/hello_%d.assert", stack.HighURL, revision)
	code, assertText := httpGet(t, assertURL)
	if code != 200 {
		t.Fatalf("GET %s: status %d", assertURL, code)
	}
	for _, want := range []string{"type: account-key", "type: account", "type: snap-declaration", "type: snap-revision"} {
		if !strings.Contains(string(assertText), want) {
			t.Fatalf("served .assert misses %q:\n%s", want, assertText)
		}
	}

	// The downloaded archive's SHA3-384 must be the digest the store-signed
	// snap-revision assertion is keyed by — the binding snapd checks at
	// install time.
	sum := sha3.Sum384(body)
	digest := base64.RawURLEncoding.EncodeToString(sum[:])
	if !strings.Contains(string(assertText), "snap-sha3-384: "+digest) {
		t.Fatalf("served .assert does not vouch for the served archive (digest %s):\n%s", digest, assertText)
	}
	if !strings.Contains(string(assertText), fmt.Sprintf("snap-size: %d", len(body))) {
		t.Fatalf("served .assert declares a different snap-size than the %d served bytes", len(body))
	}
}

// snapInfoRevision reads the mirrored revision and version of hello from the
// regenerated /snap/info metadata.
func snapInfoRevision(t *testing.T) (int, string) {
	t.Helper()
	code, body := httpGet(t, stack.HighURL+"/snap/info/hello")
	if code != 200 {
		t.Fatalf("GET /snap/info/hello: status %d: %s", code, body)
	}
	var info struct {
		Name      string `json:"name"`
		Revisions []struct {
			Revision int    `json:"revision"`
			Version  string `json:"version"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("info response is not JSON: %v\n%s", err, body)
	}
	if info.Name != "hello" || len(info.Revisions) != 1 || info.Revisions[0].Revision < 1 {
		t.Fatalf("unexpected info response: %s", body)
	}
	return info.Revisions[0].Revision, info.Revisions[0].Version
}
