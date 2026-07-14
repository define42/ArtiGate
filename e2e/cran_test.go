//go:build e2e

package e2e

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCRAN mirrors a real package (praise: pure R, zero dependencies beyond
// base) from the public CRAN mirror across the diode, checks the regenerated
// PACKAGES index, and — when an R interpreter is installed — installs the
// package from the mirror with the real install.packages.
func TestCRAN(t *testing.T) {
	stack.Prepare(t)

	res := stack.Collect(t, "cran", map[string]any{"packages": []string{"praise"}})
	if res.ExportedModules < 1 {
		t.Fatalf("expected at least the requested package, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "cran", res.Sequence)

	// The index is regenerated from the tarball's own DESCRIPTION and carries
	// the MD5 R verifies downloads against.
	code, body := httpGet(t, stack.HighURL+"/cran/src/contrib/PACKAGES")
	if code != 200 || !strings.Contains(string(body), "Package: praise") ||
		!strings.Contains(string(body), "MD5sum: ") {
		t.Fatalf("regenerated PACKAGES = %d %s", code, body)
	}

	// Client step: install from the mirror with real R when it is available.
	// The protocol assertions above already validated the mirror, so a
	// missing interpreter only skips the client half.
	rscript, err := exec.LookPath("Rscript")
	if err != nil {
		t.Skip("Rscript not installed; mirrored repository verified over HTTP only")
	}
	tmp := t.TempDir()
	lib := filepath.Join(tmp, "library")
	writeFile(t, filepath.Join(tmp, "install.R"), `
lib <- commandArgs(trailingOnly = TRUE)[1]
repo <- commandArgs(trailingOnly = TRUE)[2]
dir.create(lib, recursive = TRUE, showWarnings = FALSE)
install.packages("praise", lib = lib, repos = repo, type = "source", quiet = TRUE)
library(praise, lib.loc = lib)
cat(class(praise()), "\n")
`)
	out := run(t, tmp, []string{"HOME=" + tmp}, rscript, filepath.Join(tmp, "install.R"), lib, stack.HighURL+"/cran")
	if !strings.Contains(out, "character") {
		t.Fatalf("praise() did not run from the mirrored install:\n%s", out)
	}
}
