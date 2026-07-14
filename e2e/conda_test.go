//go:build e2e

package e2e

import (
	"encoding/json"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestConda mirrors a tiny, dependency-free noarch package from the real
// conda-forge channel across the diode, checks the regenerated repodata, and
// — when a conda-family client is installed — solves an environment from the
// mirror alone.
//
// Fetching conda-forge's noarch repodata is a multi-hundred-megabyte
// download (~27 MB as .zst, far larger decompressed), which makes this the
// slowest collect in the suite.
func TestConda(t *testing.T) {
	stack.Prepare(t)

	res := stack.Collect(t, "conda", map[string]any{
		"channel":  "conda-forge",
		"subdirs":  []string{"noarch"},
		"packages": []string{"font-ttf-dejavu-sans-mono"},
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the requested package, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "conda", res.Sequence)

	// The regenerated per-subdir index is rebuilt from the verified
	// artifacts and lists the package under its exact upstream filename.
	code, body := httpGet(t, stack.HighURL+"/conda/conda-forge/noarch/repodata.json")
	if code != 200 || !strings.Contains(string(body), `"font-ttf-dejavu-sans-mono-`) {
		t.Fatalf("regenerated repodata.json = %d %.2000s", code, body)
	}
	var repodata struct {
		Info struct {
			Subdir string `json:"subdir"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &repodata); err != nil || repodata.Info.Subdir != "noarch" {
		t.Fatalf("repodata.json info.subdir = %q, %v", repodata.Info.Subdir, err)
	}

	// Optional client step. requireTool would skip the whole test and hide
	// the protocol-level assertions above on runners without a conda client,
	// so the lookup is local and a missing tool only logs.
	client := condaClientPath()
	if client == "" {
		t.Log("no micromamba/mamba/conda on PATH; skipping the client solve step")
		return
	}
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "env")
	clientEnv := []string{
		"HOME=" + tmp,
		"MAMBA_ROOT_PREFIX=" + filepath.Join(tmp, "mamba-root"),
		"CONDA_PKGS_DIRS=" + filepath.Join(tmp, "pkgs"),
	}
	// The channel URL pins the noarch subdir (conda-family clients strip a
	// trailing platform name and query only that subdir): the mirror carries
	// no platform subdir for this host, and clients would otherwise pair the
	// channel with the native platform.
	run(t, tmp, clientEnv, client, "create", "-y", "-p", envDir,
		"--override-channels", "-c", stack.HighURL+"/conda/conda-forge/noarch",
		"font-ttf-dejavu-sans-mono")
	if !condaDirHasFiles(envDir) {
		t.Fatalf("client env at %s contains no files", envDir)
	}
}

// condaClientPath returns the first conda-family client on PATH, or "".
func condaClientPath() string {
	for _, name := range []string{"micromamba", "mamba", "conda"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// condaDirHasFiles reports whether dir contains at least one regular file
// anywhere below it — the font package installs only data files, so any file
// proves the solve fetched and extracted the mirrored archive.
func condaDirHasFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
