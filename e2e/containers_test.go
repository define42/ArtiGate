//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestContainers mirrors hello-world from Docker Hub and pulls+runs it from
// the high side's read-only OCI registry with the real docker daemon. The
// pull name embeds the upstream registry (docker.io/library/...), and the
// daemon speaks plain HTTP to the loopback registry because 127.0.0.0/8 is
// insecure-allowed by default — no daemon.json needed.
func TestContainers(t *testing.T) {
	stack.Prepare(t)
	requireDocker(t)

	res := stack.Collect(t, "containers", map[string]any{
		"images": []string{"hello-world:latest"},
	})
	stack.WaitImported(t, "containers", res.Sequence)

	ref := stack.HighHost + "/docker.io/library/hello-world:latest"
	t.Cleanup(func() { _, _ = runAllowFail(t, "", nil, "docker", "rmi", "-f", ref) })
	run(t, "", nil, "docker", "pull", ref)
	out := run(t, "", nil, "docker", "run", "--rm", ref)
	if !strings.Contains(out, "Hello from Docker!") {
		t.Fatalf("docker run output missing the hello-world banner:\n%s", out)
	}
}
