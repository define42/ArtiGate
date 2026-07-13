//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const clientTimeout = 5 * time.Minute

func requireAll() bool { return os.Getenv("ARTIGATE_E2E_REQUIRE_ALL") == "1" }

// requireTool returns the path of the first of names found on PATH. A
// missing tool skips the test locally; under ARTIGATE_E2E_REQUIRE_ALL=1
// (CI) it fails instead, so a runner-image change cannot silently drop a
// stream from coverage.
func requireTool(t *testing.T, names ...string) string {
	t.Helper()
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	msg := fmt.Sprintf("client tool %s not on PATH", strings.Join(names, " / "))
	if requireAll() {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return ""
}

// requireDocker needs more than the CLI: the daemon must answer.
func requireDocker(t *testing.T) {
	t.Helper()
	requireTool(t, "docker")
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		msg := fmt.Sprintf("docker daemon unavailable: %v\n%s", err, out)
		if requireAll() {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
}

// run executes a client tool and fails the test (with the full output) on a
// non-zero exit. The output is always logged — it is the evidence that the
// real tool spoke to the mirror.
func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	out, err := runAllowFail(t, dir, env, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func runAllowFail(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("$ %s %s\n%s", name, strings.Join(args, " "), out)
	}
	return string(out), err
}

// runStdout is run for exact-output assertions: it returns stdout alone, so
// harmless tool chatter on stderr (JVM "Picked up JAVA_TOOL_OPTIONS"
// banners, `go: downloading ...` lines) cannot pollute the comparison.
func runStdout(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.Len()+stderr.Len() > 0 {
		t.Logf("$ %s %s\n%s%s", name, strings.Join(args, " "), stdout.String(), stderr.String())
	}
	if err != nil {
		t.Fatalf("%s %s: %v\nstdout: %s\nstderr: %s", name, strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// httpGet fetches a high-side URL and returns status + body. Plain-HTTP
// loopback requests never traverse a proxy (NO_PROXY covers 127.0.0.1 in
// proxied environments; there is none in CI).
func httpGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: reading body: %v", url, err)
	}
	return resp.StatusCode, b
}

// httpGetPrefix reads just the first n bytes of a response — enough to
// check a file magic without pulling a multi-megabyte artifact through the
// test twice. It returns the status, the prefix, and the Content-Length.
func httpGetPrefix(t *testing.T, url string, n int) (int, []byte, int64) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	prefix := make([]byte, n)
	read, err := io.ReadFull(resp.Body, prefix)
	if err != nil && read == 0 && resp.StatusCode == http.StatusOK {
		t.Fatalf("GET %s: reading prefix: %v", url, err)
	}
	return resp.StatusCode, prefix[:read], resp.ContentLength
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// isTransientUpstreamError classifies collect failures that are upstream
// weather rather than ArtiGate regressions: throttling, gateway errors, and
// connection turbulence. Only these may skip a test; anything else (404s,
// hash mismatches, parse errors) must fail loudly.
func isTransientUpstreamError(msg string) bool {
	m := strings.ToLower(msg)
	for _, marker := range []string{
		"429",
		"toomanyrequests",
		"rate limit",
		"status 502",
		"status 503",
		"status 504",
		" 502 ",
		" 503 ",
		" 504 ",
		"bad gateway",
		"service unavailable",
		"gateway timeout",
		"timeout",
		"timed out",
		"connection reset",
		"connection refused by upstream",
		"unexpected eof",
		"tls handshake",
	} {
		if strings.Contains(m, marker) {
			return true
		}
	}
	return false
}
