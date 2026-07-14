//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// posixVersion pins an immutable, dependency-free ansible.posix release, so
// the collect and the ansible-galaxy install ask for the same thing.
const posixVersion = "1.5.4"

// TestGalaxy mirrors a collection from the real Ansible Galaxy across the
// diode, asserts the regenerated v3 API, and consumes the mirror with the
// real ansible-galaxy client.
func TestGalaxy(t *testing.T) {
	stack.Prepare(t)

	res := stack.Collect(t, "galaxy", map[string]any{
		"collections": []string{"ansible.posix@" + posixVersion},
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned collection, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "galaxy", res.Sequence)

	// The discovery document must advertise the v3 API — ansible-galaxy
	// appends "api/" to the configured server URL and reads this first.
	code, body := httpGet(t, stack.HighURL+"/galaxy/api/")
	var disc struct {
		Available map[string]string `json:"available_versions"`
	}
	if code != 200 || json.Unmarshal(body, &disc) != nil || disc.Available["v3"] == "" {
		t.Fatalf("api discovery = %d %s", code, body)
	}

	// The regenerated version detail carries the artifact digest and an
	// absolute download URL pointing back at the mirror.
	code, body = httpGet(t, stack.HighURL+"/galaxy/api/v3/collections/ansible/posix/versions/"+posixVersion+"/")
	if code != 200 {
		t.Fatalf("version detail = %d %s", code, body)
	}
	var detail struct {
		DownloadURL string `json:"download_url"`
		Artifact    struct {
			SHA256 string `json:"sha256"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("version detail is not JSON: %v\n%s", err, body)
	}
	if !strings.HasPrefix(detail.DownloadURL, stack.HighURL+"/galaxy/download/") || len(detail.Artifact.SHA256) != 64 {
		t.Fatalf("version detail lacks download_url/sha256: %s", body)
	}

	// requireTool comes after the protocol asserts on purpose: when the
	// client tool is absent, the mirror itself has already been validated.
	ag := requireTool(t, "ansible-galaxy")
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, tmp, []string{"HOME=" + home}, ag,
		"collection", "install", "ansible.posix:"+posixVersion,
		"-s", stack.HighURL+"/galaxy/",
		"-p", filepath.Join(tmp, "collections"),
		"--no-cache", "-vvv")

	installed := filepath.Join(tmp, "collections", "ansible_collections", "ansible", "posix", "MANIFEST.json")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("installed collection MANIFEST.json missing: %v", err)
	}
}
