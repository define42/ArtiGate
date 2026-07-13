//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestApt mirrors the GitHub CLI's apt repository (a deliberately small
// archive: one package, newest version only) and consumes the regenerated
// mirror with a real, fully sandboxed apt-get: update parses the rebuilt
// Release/Packages indexes, download fetches the .deb and verifies its
// SHA256 against them. The mirror is unsigned, hence [trusted=yes].
func TestApt(t *testing.T) {
	stack.Prepare(t)
	aptGet := requireTool(t, "apt-get")
	dpkgDeb := requireTool(t, "dpkg-deb")

	res := stack.Collect(t, "apt", map[string]any{
		"name":          "ghcli",
		"uri":           "https://cli.github.com/packages",
		"suites":        []string{"stable"},
		"components":    []string{"main"},
		"architectures": []string{"amd64"},
	})
	stack.WaitImported(t, "apt", res.Sequence)

	code, body := httpGet(t, stack.HighURL+"/ui/api/repos?eco=apt")
	if code != 200 || !strings.Contains(string(body), `"ghcli"`) {
		t.Fatalf("high side does not list the ghcli apt mirror (HTTP %d): %s", code, body)
	}

	tmp := t.TempDir()
	for _, d := range []string{
		filepath.Join("state", "lists", "partial"),
		filepath.Join("cache", "archives", "partial"),
		"dl",
	} {
		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	writeFile(t, filepath.Join(tmp, "sources.list"),
		fmt.Sprintf("deb [trusted=yes arch=amd64] %s/apt/ghcli stable main\n", stack.HighURL))
	opts := []string{
		"-o", "Dir::Etc::sourcelist=" + filepath.Join(tmp, "sources.list"),
		"-o", "Dir::Etc::sourceparts=/dev/null",
		"-o", "Dir::State=" + filepath.Join(tmp, "state"),
		"-o", "Dir::Cache=" + filepath.Join(tmp, "cache"),
		"-o", "Dir::Etc::trusted=/dev/null",
		"-o", "Dir::Etc::trustedparts=/dev/null",
		"-o", "Acquire::Retries=2",
	}
	run(t, tmp, nil, aptGet, append(opts, "update")...)
	run(t, filepath.Join(tmp, "dl"), nil, aptGet, append(opts, "download", "gh")...)

	debs, err := filepath.Glob(filepath.Join(tmp, "dl", "gh_*.deb"))
	if err != nil || len(debs) != 1 {
		t.Fatalf("expected exactly one downloaded gh .deb, got %v (err %v)", debs, err)
	}
	out := run(t, tmp, nil, dpkgDeb, "--info", debs[0])
	if !strings.Contains(out, "Package: gh") {
		t.Fatalf("dpkg-deb --info does not describe package gh:\n%s", out)
	}
}
