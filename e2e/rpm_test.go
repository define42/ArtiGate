//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestRpm resolves regenerated primary/filelists metadata, installs the RPM,
// checks its installed files, and executes it in a fresh Fedora receiver.
func TestRpm(t *testing.T) {
	stack.Prepare(t)
	image := buildNativePackageReceiver(t, rpmReceiverBase, `RUN dnf install -y git ca-certificates && dnf clean all
RUN ! rpm -q gh
`)
	res := stack.Collect(t, "rpm", map[string]any{
		"name":     "ghcli-rpm",
		"base_url": "https://cli.github.com/packages/rpm",
	})
	stack.WaitImported(t, "rpm", res.Sequence)

	receiver := newReceiver(t, stack.HighURL)
	out := receiver.Container(t, image, nil, "sh", "-ec", `
if rpm -q gh; then echo 'receiver already contains gh' >&2; exit 1; fi
rm -f /etc/yum.repos.d/*.repo
printf '[artigate]\nname=ArtiGate receiver\nbaseurl=%s/rpm/ghcli-rpm\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=0\n' "$1" > /etc/yum.repos.d/artigate.repo
dnf --setopt=optional_metadata_types=filelists repoquery --available --files gh > /tmp/gh-filelist
cat /tmp/gh-filelist
grep -Fx /usr/bin/gh /tmp/gh-filelist
dnf install -y gh
rpm -q gh
rpm --verify gh
gh --version
`, "artigate-rpm-receiver", stack.HighURL)
	if !strings.Contains(out, "gh version ") {
		t.Fatalf("installed RPM package did not execute:\n%s", out)
	}
}
