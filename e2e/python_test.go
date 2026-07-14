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

// termcolorSdistVersion pins a release that only ever shipped a source
// distribution (termcolor grew wheels in 2.x), exercising the sdist opt-in.
const termcolorSdistVersion = "1.1.0"

// TestPythonSDist mirrors a wheel-less release through the sdist opt-in (the
// index JSON API path — no pip, no build hooks on the low side) and installs
// it from the mirror with a real pip, which builds the sdist client-side like
// it would against PyPI.
func TestPythonSDist(t *testing.T) {
	stack.Prepare(t)
	python := requireTool(t, "python3")

	res := stack.Collect(t, "python", map[string]any{
		"sdists": []string{"termcolor==" + termcolorSdistVersion},
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned sdist project, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "python", res.Sequence)

	// The Simple page lists the sdist with its artifact hash.
	code, body := httpGet(t, stack.HighURL+"/simple/termcolor/")
	if code != 200 || !strings.Contains(string(body), "termcolor-"+termcolorSdistVersion+".tar.gz") ||
		!strings.Contains(string(body), "#sha256=") {
		t.Fatalf("simple page = %d %s", code, body)
	}

	tmp := t.TempDir()
	venv := filepath.Join(tmp, "venv")
	run(t, tmp, nil, python, "-m", "venv", venv)
	pipEnv := []string{"PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_NO_INPUT=1"}
	// A real air-gapped client builds sdists with its own preinstalled build
	// tooling; model that by seeding setuptools from the public index and
	// building without isolation — the mirror only has to serve the sdist.
	run(t, tmp, pipEnv, filepath.Join(venv, "bin", "pip"), "install", "--no-cache-dir", "setuptools")
	run(t, tmp, pipEnv, filepath.Join(venv, "bin", "pip"), "install",
		"--no-cache-dir", "--no-deps", "--no-build-isolation",
		"--index-url", stack.HighURL+"/simple/",
		"termcolor=="+termcolorSdistVersion)
	out := runStdout(t, tmp, nil, filepath.Join(venv, "bin", "python"), "-c",
		`import termcolor; print(termcolor.colored("ok", "green"))`)
	if !strings.Contains(out, "ok") {
		t.Fatalf("termcolor did not import from the mirrored sdist: %q", out)
	}
}
