//go:build e2e

package e2e

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSnap downloads the mirrored application, base, and snapd runtime using
// an isolated high-only receiver, then boots a VM without a network device.
// The VM's snapd validates Canonical's assertion signatures with snap ack,
// installs all three without --dangerous, and executes snap run hello.
func TestSnap(t *testing.T) {
	stack.Prepare(t)
	image := prepareSnapReceiverVM(t)
	// A fresh classic receiver also needs the snapd runtime snap. It is an
	// implicit snapd prerequisite, not hello's declared base, so request it
	// explicitly; ArtiGate follows declared bases, not all snapd prerequisites.
	res := stack.Collect(t, "snap", map[string]any{"snaps": []string{"hello", "snapd"}})
	if res.ExportedModules < 3 {
		t.Fatalf("expected hello, its base, and snapd, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "snap", res.Sequence)

	receiver := newReceiver(t, stack.HighURL)
	files := t.TempDir()
	packages := downloadReceiverSnaps(t, receiver, files)
	if len(packages) < 3 {
		t.Fatal("high-side metadata omitted a Snap runtime dependency")
	}
	runSnapReceiverVM(t, image, files, packages)
}

func downloadReceiverSnaps(t *testing.T, receiver *receiver, dir string) []string {
	t.Helper()
	curl := requireTool(t, "curl")
	var packages []string
	queue, seen := []string{"hello", "snapd"}, map[string]bool{}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		body := receiver.RunStdout(t, dir, nil, curl, "-fsS", stack.HighURL+"/snap/info/"+url.PathEscape(name))
		var info struct {
			Name      string `json:"name"`
			Revisions []struct {
				Revision int    `json:"revision"`
				Base     string `json:"base"`
				Version  string `json:"version"`
			} `json:"revisions"`
		}
		if err := json.Unmarshal([]byte(body), &info); err != nil || info.Name != name || len(info.Revisions) != 1 || info.Revisions[0].Revision < 1 {
			t.Fatalf("invalid mirrored snap metadata: %s (error %v)", body, err)
		}
		revision := info.Revisions[0]
		t.Logf("mirrored %s revision %d (version %s)", name, revision.Revision, revision.Version)
		stem := fmt.Sprintf("%s_%d", name, revision.Revision)
		if filepath.Base(stem) != stem || strings.ContainsAny(stem, "'\n\r\\") {
			t.Fatalf("unsafe snap fixture filename %q", stem)
		}
		for _, ext := range []string{".snap", ".assert"} {
			receiver.Run(t, dir, nil, curl, "-fsS", "--output", stem+ext,
				stack.HighURL+"/snap/files/"+url.PathEscape(name)+"/"+url.PathEscape(stem+ext))
		}
		verifyReceiverSnapBinding(t, dir, stem)
		packages = append(packages, stem)
		if revision.Base != "" {
			queue = append(queue, revision.Base)
		}
	}
	// Dependency bases must be installed before the application that needs them.
	slices.Reverse(packages)
	return packages
}

func verifyReceiverSnapBinding(t *testing.T, dir, stem string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, stem+".snap"))
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := os.ReadFile(filepath.Join(dir, stem+".assert"))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 4 || string(body[:4]) != "hsqs" {
		t.Fatalf("%s is not a squashfs snap", stem)
	}
	sum := sha3.Sum384(body)
	digest := base64.RawURLEncoding.EncodeToString(sum[:])
	for _, want := range []string{
		"type: account-key", "type: account", "type: snap-declaration", "type: snap-revision",
		"snap-sha3-384: " + digest, fmt.Sprintf("snap-size: %d", len(body)),
	} {
		if !strings.Contains(string(assertion), want) {
			t.Fatalf("%s assertion lacks %q", stem, want)
		}
	}
}
