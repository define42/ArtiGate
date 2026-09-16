//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// The receiver owns a fresh Docker daemon, so neither a warm host layer cache
// nor the host daemon's upstream network can satisfy a high-side pull.
const dockerReceiverImage = "docker:28.3.3-dind@sha256:a56b3bdde89315ed2cc0e4906e582b5033d93bf20d9cb9510c2cdd4e7f7690b1"

// TestContainers mirrors hello-world from Docker Hub and pulls+runs it from
// the high side's read-only OCI registry with the real docker daemon. The
// pull name embeds the upstream registry (docker.io/library/...), and the
// daemon speaks plain HTTP to the loopback registry because 127.0.0.0/8 is
// insecure-allowed by default — no daemon.json needed.
func TestContainers(t *testing.T) {
	stack.Prepare(t)
	requireDocker(t)
	run(t, "", nil, "docker", "pull", dockerReceiverImage)

	res := stack.Collect(t, "containers", map[string]any{
		"images": []string{"hello-world:latest"},
	})
	stack.WaitImported(t, "containers", res.Sequence)

	ref := stack.HighHost + "/docker.io/library/hello-world:latest"
	out := newReceiver(t, stack.HighURL).Container(t, dockerReceiverImage, []string{"--privileged"},
		"sh", "-ec", `
dockerd --host=unix:///tmp/receiver-docker.sock --data-root=/tmp/docker-data \
  --exec-root=/tmp/docker-exec --pidfile=/tmp/docker.pid --storage-driver=vfs \
  --iptables=false --ip6tables=false --bridge=none --ip-masq=false > /tmp/dockerd.log 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true' EXIT
export DOCKER_HOST=unix:///tmp/receiver-docker.sock
for attempt in $(seq 1 60); do
  if docker info >/dev/null 2>&1; then break; fi
  if ! kill -0 "$daemon" 2>/dev/null; then cat /tmp/dockerd.log; exit 1; fi
  sleep 1
done
docker info >/dev/null 2>&1 || { cat /tmp/dockerd.log; exit 1; }
test -z "$(docker image ls -q)"
docker pull "$1"
docker run --rm --network=none --pull=never "$1"
`, "receiver-docker", ref)
	if !strings.Contains(out, "Hello from Docker!") {
		t.Fatalf("docker run output missing the hello-world banner:\n%s", out)
	}
}
