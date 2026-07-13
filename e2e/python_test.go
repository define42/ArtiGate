//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestPython is the canonical end-to-end scenario: the low side pulls
// requests (and its wheel closure) from real PyPI, the bundle crosses the
// diode, and a real pip installs it from the high side's PEP 503 index into
// a fresh venv. The installed library then proves itself by fetching the
// high side's own /healthz over HTTP.
func TestPython(t *testing.T) {
	stack.Prepare(t)
	python := requireTool(t, "python3")

	res := stack.Collect(t, "python", map[string]any{
		"requirements": []string{"requests==" + requestsVersion},
	})
	// requests pulls certifi, charset_normalizer, idna, and urllib3.
	if res.ExportedModules < 5 {
		t.Fatalf("expected the requests closure (>=5 projects), got %d", res.ExportedModules)
	}
	stack.WaitImported(t, "python", res.Sequence)

	tmp := t.TempDir()
	venv := filepath.Join(tmp, "venv")
	run(t, tmp, nil, python, "-m", "venv", venv)
	pipEnv := []string{"PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_NO_INPUT=1"}
	run(t, tmp, pipEnv, filepath.Join(venv, "bin", "pip"), "install",
		"--no-cache-dir",
		"--index-url", stack.HighURL+"/simple/",
		"requests=="+requestsVersion)

	writeFile(t, filepath.Join(tmp, "main.py"), fmt.Sprintf(`import requests

r = requests.get(%q, timeout=10)
print(r.status_code, r.text.strip())
`, stack.HighURL+"/healthz"))
	out := runStdout(t, tmp, nil, filepath.Join(venv, "bin", "python"), "main.py")
	if strings.TrimSpace(out) != "200 ok" {
		t.Fatalf("main.py printed %q, want %q", strings.TrimSpace(out), "200 ok")
	}
}

// requestsVersion pins an immutable PyPI release so the collect and the pip
// install ask for the same thing; its dependencies resolve freely.
const requestsVersion = "2.32.4"
