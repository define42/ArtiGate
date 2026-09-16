//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestApt performs a real package installation in a fresh Debian receiver.
// Git is part of the bootstrapped toolchain because gh declares it as a
// dependency; gh itself and all APT metadata must come from high after isolation.
func TestApt(t *testing.T) {
	stack.Prepare(t)
	image := buildNativePackageReceiver(t, aptReceiverBase, `RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN ! command -v gh
`)
	res := stack.Collect(t, "apt", map[string]any{
		"name":          "ghcli",
		"uri":           "https://cli.github.com/packages",
		"suites":        []string{"stable"},
		"components":    []string{"main"},
		"architectures": []string{"amd64"},
	})
	stack.WaitImported(t, "apt", res.Sequence)

	receiver := newReceiver(t, stack.HighURL)
	repositories := receiver.RunStdout(t, "", nil, requireTool(t, "curl"), "-fsS", stack.HighURL+"/ui/api/repos?eco=apt")
	if !strings.Contains(repositories, `"ghcli"`) {
		t.Fatalf("high side does not list the ghcli APT mirror: %s", repositories)
	}
	out := receiver.Container(t, image, nil, "sh", "-ec", `
test ! -e /var/lib/dpkg/info/gh.list
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
printf 'deb [trusted=yes arch=amd64] %s/apt/ghcli stable main\n' "$1" > /etc/apt/sources.list
apt-get -o Acquire::Retries=0 -o Acquire::Languages=none update
apt-get -o Acquire::Retries=0 install -y --no-install-recommends gh
test "$(dpkg-query -W -f='${Status}' gh)" = 'install ok installed'
dpkg --verify gh
gh --version
`, "artigate-apt-receiver", stack.HighURL)
	if !strings.Contains(out, "gh version ") {
		t.Fatalf("installed APT package did not execute:\n%s", out)
	}
}
