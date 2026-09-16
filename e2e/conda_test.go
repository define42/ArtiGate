//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConda mirrors a tiny, dependency-free noarch package from the real
// conda-forge channel across the diode, checks the regenerated repodata, and
// solves an environment with a real conda-family client from the mirror alone.
//
// Fetching conda-forge's noarch repodata is a multi-hundred-megabyte
// download (~27 MB as .zst, far larger decompressed), which makes this the
// slowest collect in the suite.
func TestConda(t *testing.T) {
	stack.Prepare(t)
	client := requireTool(t, "micromamba", "mamba", "conda")

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
	newReceiver(t, stack.HighURL).Run(t, tmp, clientEnv, client, "create", "-y", "-p", envDir,
		"--override-channels", "-c", stack.HighURL+"/conda/conda-forge/noarch",
		"font-ttf-dejavu-sans-mono")
	assertCondaFontInstalled(t, envDir)
}

// The installed record and actual font payload prove extraction; an empty
// environment's conda-meta/history file alone must not satisfy the test.
func assertCondaFontInstalled(t *testing.T, dir string) {
	t.Helper()
	records, err := filepath.Glob(filepath.Join(dir, "conda-meta", "font-ttf-dejavu-sans-mono-*.json"))
	if err != nil || len(records) != 1 {
		t.Fatalf("installed font package records = %v, %v", records, err)
	}
	data, err := os.ReadFile(records[0])
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Name  string   `json:"name"`
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(data, &record); err != nil || record.Name != "font-ttf-dejavu-sans-mono" {
		t.Fatalf("installed font package record name=%q: %v", record.Name, err)
	}
	for _, file := range record.Files {
		// The conda-forge archive's info/files names fonts/DejaVuSans.ttf,
		// despite the package itself being named dejavu-sans-mono.
		if file != "fonts/DejaVuSans.ttf" {
			continue
		}
		font, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || len(font) < 1024 || !bytes.HasPrefix(font, []byte{0, 1, 0, 0}) {
			t.Fatalf("installed %s is not a TrueType font: bytes=%d, %v", file, len(font), err)
		}
		t.Logf("verified installed %s: %d bytes of TrueType data", file, len(font))
		return
	}
	t.Fatal("installed package record has no fonts/DejaVuSans.ttf payload")
}
