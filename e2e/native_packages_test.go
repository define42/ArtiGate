//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Official multi-platform image digests, checked when the fixtures were added.
const (
	aptReceiverBase = "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
	rpmReceiverBase = "fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80"
)

// Bootstrap operating-system dependencies before the receiver is isolated.
// Each caller explicitly checks that the mirrored package is absent. Docker's
// layer cache can retain this toolchain, but the consumer always starts a fresh
// container and receives no downloaded packages or repository metadata cache.
func buildNativePackageReceiver(t *testing.T, base, setup string) string {
	t.Helper()
	requireDocker(t)
	run(t, "", nil, "docker", "pull", base)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+base+"\n"+setup)
	idFile := filepath.Join(dir, "image-id")
	run(t, dir, nil, "docker", "build", "--pull=false", "--iidfile", idFile, ".")
	body, err := os.ReadFile(idFile)
	if err != nil {
		t.Fatal(err)
	}
	image := strings.TrimSpace(string(body))
	if !strings.HasPrefix(image, "sha256:") {
		t.Fatalf("Docker did not return an immutable receiver image ID: %q", image)
	}
	return image
}
