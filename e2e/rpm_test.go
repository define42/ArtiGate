//go:build e2e

package e2e

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRpm mirrors the GitHub CLI's rpm repository (one package, newest
// version, x86_64+noarch by default) and consumes it with a real dnf run
// entirely as an unprivileged user: repoquery parses the regenerated
// repomd.xml/primary metadata and resolves the package's download location,
// then the fetched .rpm is inspected with the real rpm tool.
func TestRpm(t *testing.T) {
	stack.Prepare(t)
	dnf := requireTool(t, "dnf")
	rpmBin := requireTool(t, "rpm")
	curl := requireTool(t, "curl")

	res := stack.Collect(t, "rpm", map[string]any{
		"name":     "ghcli-rpm",
		"base_url": "https://cli.github.com/packages/rpm",
	})
	stack.WaitImported(t, "rpm", res.Sequence)

	tmp := t.TempDir()
	repoURL := stack.HighURL + "/rpm/ghcli-rpm"
	out := run(t, tmp, nil, dnf,
		"--disablerepo=*",
		"--repofrompath=artigate,"+repoURL,
		"--setopt=artigate.gpgcheck=0",
		"--setopt=artigate.repo_gpgcheck=0",
		"--setopt=reposdir=/dev/null",
		"--setopt=cachedir="+filepath.Join(tmp, "cache"),
		"--setopt=logdir="+filepath.Join(tmp, "log"),
		"--setopt=varsdir="+filepath.Join(tmp, "vars"),
		"--releasever=e2e", // the mirror URL has no $releasever, but dnf insists on a value
		"-y",
		"repoquery", "--location", "gh")

	var location string
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, repoURL+"/") {
			location = l
			break
		}
	}
	if location == "" {
		t.Fatalf("dnf repoquery returned no package location under %s:\n%s", repoURL, out)
	}

	rpmPath := filepath.Join(tmp, "gh.rpm")
	run(t, tmp, nil, curl, "-fsS", "-o", rpmPath, location)
	info := run(t, tmp, nil, rpmBin, "-qpi", "--nosignature", rpmPath)
	if !regexp.MustCompile(`(?m)^Name\s*:\s*gh\b`).MatchString(info) {
		t.Fatalf("rpm -qpi does not describe package gh:\n%s", info)
	}
}
