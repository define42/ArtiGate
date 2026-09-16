//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestUDPDiode runs the shipped low/high binaries over their production IPv6
// multicast transport. A private veth pair represents the diode link; neither
// a test-only unicast override nor an upstream registry is required.
func TestUDPDiode(t *testing.T) {
	if os.Getenv("ARTIGATE_E2E_UDP_NAMESPACE") != "1" {
		runUDPDiodeNamespace(t)
		return
	}
	curl := requireTool(t, "curl")
	pair := startTestPair(t, pairConfig{
		name: "udp",
		highEnv: []string{
			"ARTIGATE_DIODE_INGEST=off", "ARTIGATE_CATCHER_INTERFACE=diode-rx",
			"ARTIGATE_CATCHER_GROUP=ff02::4147", "ARTIGATE_CATCHER_PORT=4147",
			"ARTIGATE_CATCHER_MTU=1500", "ARTIGATE_CATCHER_NETSETUP=off",
		},
		lowEnv: []string{
			"ARTIGATE_DIODE_URL=", "ARTIGATE_DIODE_HEARTBEAT=off", "ARTIGATE_PITCHER_INTERFACE=diode-tx",
			"ARTIGATE_PITCHER_GROUP=ff02::4147", "ARTIGATE_PITCHER_PORT=4147",
			"ARTIGATE_PITCHER_MTU=1500", "ARTIGATE_PITCHER_RATE_MBIT=10", "ARTIGATE_PITCHER_NETSETUP=off",
		},
	})
	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	source := filepath.Join(tmp, "diode.bin")
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	out := run(t, tmp, nil, curl, "-fsS", "-F", "folder=udp-e2e", "-F", "file=@"+source, pair.LowURL+"/admin/uploads/collect")
	var result ExportResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode UDP upload result: %v: %s", err, out)
	}
	result = pair.checkResult(t, "uploads", result)
	pair.WaitImported(t, "uploads", result.Sequence)
	destination := filepath.Join(tmp, "received.bin")
	newReceiver(t, pair.HighURL).Run(t, tmp, nil, curl, "-fsS", "-o", destination, pair.HighURL+"/uploads/udp-e2e/diode.bin")
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("UDP receiver returned different payload: %d bytes, want %d", len(got), len(payload))
	}
	t.Logf("verified %d bytes through real multicast pitcher/catcher binaries and isolated curl receiver", len(got))
}

func runUDPDiodeNamespace(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		requiredUnavailable(t, "real UDP multicast E2E requires Linux network namespaces")
	}
	unshare := requireTool(t, "unshare")
	requireTool(t, "ip")
	goTool := requireTool(t, "go")
	goRoot := strings.TrimSpace(runStdout(t, "", nil, goTool, "env", "GOROOT"))
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Resolve the actual Go toolchain before entering the user namespace: a
	// host's snap launcher cannot initialize there. The child reuses the
	// already-built ArtiGate binary and only builds the static receiver helper.
	env := []string{
		"ARTIGATE_E2E_UDP_NAMESPACE=1", "ARTIGATE_E2E_BIN=" + stack.Bin,
		"ARTIGATE_E2E_WORKDIR=" + filepath.Join(t.TempDir(), "udp-stack"),
		"PATH=" + filepath.Join(goRoot, "bin") + ":" + os.Getenv("PATH"), "GOTOOLCHAIN=local",
	}
	run(t, "", env, unshare, "--user", "--map-root-user", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
		"sh", "-ec", udpDiodeNamespaceScript, "udp-diode-e2e", testBinary,
		"-test.run=^TestUDPDiode$", "-test.v", "-test.count=1", "-test.timeout=3m")
}

const udpDiodeNamespaceScript = `
ip link set lo up
ip link add diode-tx type veth peer name diode-rx
ip link set diode-tx mtu 1500 up
ip link set diode-rx mtu 1500 up
ip -6 address add fe80::1/64 dev diode-tx nodad
ip -6 address add fe80::2/64 dev diode-rx nodad
exec "$@"
`
