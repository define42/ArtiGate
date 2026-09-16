//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type receiver struct {
	address string
	socket  string
	bin     string
	env     []string
}

type receiverBuilder struct {
	once sync.Once
	bin  string
	err  error
}

// newReceiver gives one consumer a fresh home/cache and a kernel network
// namespace. No route, DNS server, upstream, or other host port is reachable.
// Only the exact high-side TCP endpoint is bridged, preserving HTTPS and Host.
func newReceiver(t *testing.T, highURL string) *receiver {
	t.Helper()
	if runtime.GOOS != "linux" {
		requiredUnavailable(t, "receiver isolation requires Linux network namespaces")
	}
	requireTool(t, "unshare")
	requireTool(t, "ip")
	u, err := url.Parse(highURL)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		t.Fatalf("receiver needs an explicit loopback high-side URL: %q", highURL)
	}
	receiverBuild := &stack.receiverBuild
	receiverBuild.once.Do(func() {
		receiverBuild.bin = filepath.Join(stack.WorkDir, "receiver")
		cmd := exec.Command("go", "build", "-tags", "e2e", "-o", receiverBuild.bin, "./receiver")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			receiverBuild.err = fmt.Errorf("build receiver: %w: %s", err, out)
		}
	})
	if receiverBuild.err != nil {
		t.Fatal(receiverBuild.err)
	}
	// Keep the Unix socket pathname below the kernel's 108-byte limit, even
	// when the test name and ARTIGATE_E2E_WORKDIR are long.
	dir, err := os.MkdirTemp("", "ag-rx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "high.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serveReceiverBridge(ctx, listener, u.Host)
	home := t.TempDir()
	return &receiver{address: u.Host, socket: socket, bin: receiverBuild.bin, env: receiverEnv(home)}
}

func receiverEnv(home string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "LANG=C.UTF-8",
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"PIP_CONFIG_FILE=/dev/null", "PIP_DISABLE_PIP_VERSION_CHECK=1",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GOTOOLCHAIN=local", "GOWORK=off",
		"DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
	}
	// Installed language toolchains are prerequisites, not package caches.
	for _, key := range []string{"JAVA_HOME", "DOTNET_ROOT", "GOROOT", "RUSTUP_HOME"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	if os.Getenv("RUSTUP_HOME") == "" {
		if originalHome, err := os.UserHomeDir(); err == nil {
			env = append(env, "RUSTUP_HOME="+filepath.Join(originalHome, ".rustup"))
		}
	}
	return env
}

func serveReceiverBridge(ctx context.Context, listener net.Listener, address string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
			if err != nil {
				return
			}
			defer upstream.Close()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = upstream.Close() })
			defer stop()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, conn)
				_ = upstream.(*net.TCPConn).CloseWrite()
				close(done)
			}()
			_, _ = io.Copy(conn, upstream)
			_ = conn.(*net.UnixConn).CloseWrite()
			<-done
		}()
	}
}

func (r *receiver) Run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	out, err := r.RunAllowFail(t, dir, env, name, args...)
	if err != nil {
		t.Fatalf("receiver %s: %v\n%s", name, err, out)
	}
	return out
}

func (r *receiver) RunAllowFail(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd, cancel := r.command(t, dir, env, name, args...)
	defer cancel()
	out, err := cmd.CombinedOutput()
	t.Logf("receiver $ %s %s\n%s", name, strings.Join(args, " "), out)
	return string(out), err
}

func (r *receiver) RunStdout(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd, cancel := r.command(t, dir, env, name, args...)
	defer cancel()
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	t.Logf("receiver $ %s %s\n%s%s", name, strings.Join(args, " "), stdout.String(), stderr.String())
	if err != nil {
		t.Fatalf("receiver %s: %v", name, err)
	}
	return stdout.String()
}

func (r *receiver) command(t *testing.T, dir string, env []string, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	// A snap launcher cannot run inside a user namespace. Use the installed
	// Go toolchain directly; other tools continue to use their resolved path.
	if filepath.Base(name) == "go" {
		root := strings.TrimSpace(runStdout(t, "", nil, name, "env", "GOROOT"))
		name = filepath.Join(root, "bin", "go")
	}
	ctx, cancel := context.WithTimeout(t.Context(), clientTimeout)
	argv := []string{
		"--user", "--map-root-user", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--", r.bin,
		"-loopback", "-listen", r.address, "-socket", r.socket, "--", name,
	}
	cmd := exec.CommandContext(ctx, "unshare", append(argv, args...)...)
	cmd.Dir, cmd.Env = dir, append(append([]string{}, r.env...), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	return cmd, cancel
}

// Container boots a fresh receiver container with no network interfaces other
// than loopback. Docker images/tooling must be provisioned before this call.
func (r *receiver) Container(t *testing.T, image string, options []string, command ...string) string {
	t.Helper()
	requireDocker(t)
	name := "artigate-receiver-" + filepath.Base(filepath.Dir(r.socket))
	t.Cleanup(func() { _, _ = runAllowFail(t, "", nil, "docker", "rm", "-f", name) })
	args := []string{
		"run", "--rm", "--pull=never", "--name", name,
		"--network=none", "--env", "HOME=/tmp/receiver-home",
		"--mount", "type=bind,src=" + r.bin + ",dst=/artigate-receiver,readonly",
		"--mount", "type=bind,src=" + filepath.Dir(r.socket) + ",dst=" + filepath.Dir(r.socket) + ",readonly",
		"--entrypoint", "/artigate-receiver",
	}
	for _, option := range options {
		if strings.HasPrefix(option, "--network") || strings.HasPrefix(option, "--net=") || option == "--net" || strings.HasPrefix(option, "--entrypoint") {
			t.Fatalf("receiver container cannot override its network/entrypoint: %s", option)
		}
	}
	args = append(args, options...)
	args = append(args, image, "-listen", r.address, "-socket", r.socket, "--")
	return run(t, "", nil, "docker", append(args, command...)...)
}
