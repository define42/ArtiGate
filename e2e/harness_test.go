//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Stack is the shared low+high pair every stream test drives. TestMain
// starts it once: both are real artigate processes on loopback ports, wired
// together over the HTTP diode transport (the low side uploads each bundle
// to the high side's /diode endpoint, which imports it immediately).
type Stack struct {
	Bin      string
	WorkDir  string
	LowURL   string
	HighURL  string
	HighHost string // "127.0.0.1:<port>" — the registry host in docker pull refs

	low  *server
	high *server
}

var stack *Stack

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	wd, keep, err := workDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: workdir: %v\n", err)
		return 1
	}
	st, err := startStack(wd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: starting stack: %v\n", err)
		dumpLogTail(os.Stderr, filepath.Join(wd, "high.log"))
		dumpLogTail(os.Stderr, filepath.Join(wd, "low.log"))
		return 1
	}
	stack = st
	code := m.Run()
	st.low.stop()
	st.high.stop()
	if code != 0 {
		dumpLogTail(os.Stderr, st.low.logPath)
		dumpLogTail(os.Stderr, st.high.logPath)
	}
	if code == 0 && !keep {
		_ = os.RemoveAll(wd)
	} else {
		fmt.Fprintf(os.Stderr, "e2e: workdir kept at %s\n", wd)
	}
	return code
}

// workDir returns the run's working directory and whether to keep it after
// a green run. ARTIGATE_E2E_WORKDIR pins it to a known path (CI uploads the
// server logs from there on failure); otherwise a temp dir is used and
// removed on success unless ARTIGATE_E2E_KEEP=1.
func workDir() (dir string, keep bool, err error) {
	if wd := os.Getenv("ARTIGATE_E2E_WORKDIR"); wd != "" {
		return wd, true, os.MkdirAll(wd, 0o755)
	}
	dir, err = os.MkdirTemp("", "artigate-e2e-")
	return dir, os.Getenv("ARTIGATE_E2E_KEEP") == "1", err
}

func startStack(wd string) (*Stack, error) {
	bin, err := buildBinary(wd)
	if err != nil {
		return nil, err
	}
	priv := filepath.Join(wd, "keys", "low.ed25519")
	pub := filepath.Join(wd, "keys", "high.ed25519.pub")
	if err := os.MkdirAll(filepath.Dir(priv), 0o755); err != nil {
		return nil, err
	}
	if out, err := exec.Command(bin, "keygen", "--private", priv, "--public", pub).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("keygen: %v\n%s", err, out)
	}
	token, err := diodeToken()
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"low-root", "high-root", "landing", "export"} {
		if err := os.MkdirAll(filepath.Join(wd, d), 0o755); err != nil {
			return nil, err
		}
	}

	// The high side must be up first: the low side uploads each bundle to
	// the high side's /diode ingest right after every export.
	high, err := startServer(bin, "high", filepath.Join(wd, "high.log"),
		func(port int) []string {
			return []string{
				"high",
				"--listen", fmt.Sprintf("127.0.0.1:%d", port),
				"--root", filepath.Join(wd, "high-root"),
				"--landing", filepath.Join(wd, "landing"),
				"--public-key", pub,
				"--import-interval", "2s",
			}
		},
		[]string{"ARTIGATE_DIODE_INGEST=on", "ARTIGATE_DIODE_TOKEN=" + token})
	if err != nil {
		return nil, fmt.Errorf("high side: %w", err)
	}
	low, err := startServer(bin, "low", filepath.Join(wd, "low.log"),
		func(port int) []string {
			return []string{
				"low",
				"--listen", fmt.Sprintf("127.0.0.1:%d", port),
				"--root", filepath.Join(wd, "low-root"),
				"--export-dir", filepath.Join(wd, "export"),
				"--private-key", priv,
				"--upstream-goproxy", "https://proxy.golang.org,direct",
				"--watch-interval", "0",
			}
		},
		[]string{"ARTIGATE_DIODE_URL=" + high.url + "/diode", "ARTIGATE_DIODE_TOKEN=" + token})
	if err != nil {
		high.stop()
		return nil, fmt.Errorf("low side: %w", err)
	}
	return &Stack{
		Bin:      bin,
		WorkDir:  wd,
		LowURL:   low.url,
		HighURL:  high.url,
		HighHost: strings.TrimPrefix(high.url, "http://"),
		low:      low,
		high:     high,
	}, nil
}

// buildBinary compiles cmd/artigate once for the whole run (or uses
// ARTIGATE_E2E_BIN). The test process runs with the package directory as
// its working directory, so the repository root is one level up.
func buildBinary(wd string) (string, error) {
	if bin := os.Getenv("ARTIGATE_E2E_BIN"); bin != "" {
		return bin, nil
	}
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(wd, "artigate")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/artigate")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./cmd/artigate: %v\n%s", err, out)
	}
	return bin, nil
}

// diodeToken returns a fresh shared token for the HTTP diode transport
// (both sides require at least 32 bytes).
func diodeToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// server is one running artigate process.
type server struct {
	cmd     *exec.Cmd
	url     string
	logPath string
	done    chan struct{} // closed once Wait returns
	waitErr error
}

// startServer picks a free loopback port, launches the role, and waits for
// /healthz. Binding a just-probed port can race another process, so a child
// that dies before ever answering is retried on a fresh port.
func startServer(bin, role, logPath string, argsFor func(port int) []string, extraEnv []string) (*server, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		port, err := pickFreePort()
		if err != nil {
			return nil, err
		}
		srv, err := launch(bin, argsFor(port), extraEnv, logPath)
		if err != nil {
			return nil, err
		}
		srv.url = fmt.Sprintf("http://127.0.0.1:%d", port)
		if err := srv.waitHealthz(30 * time.Second); err != nil {
			srv.stop()
			lastErr = err
			continue
		}
		return srv, nil
	}
	return nil, fmt.Errorf("%s did not become healthy after 3 attempts: %w", role, lastErr)
}

func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l.Close()
}

func launch(bin string, args, extraEnv []string, logPath string) (*server, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Inherit the full environment: the low side shells out to pip, mvn,
	// npm, and go, which need PATH and any proxy configuration of the host.
	cmd.Env = append(os.Environ(), extraEnv...)
	err = cmd.Start()
	_ = logFile.Close() // the child holds its own descriptor now
	if err != nil {
		return nil, err
	}
	srv := &server{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() {
		srv.waitErr = cmd.Wait()
		close(srv.done)
	}()
	return srv, nil
}

func (s *server) waitHealthz(timeout time.Duration) error {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-s.done:
			return fmt.Errorf("process exited before becoming healthy: %v", s.waitErr)
		default:
		}
		resp, err := client.Get(s.url + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("no healthy /healthz within %s", timeout)
}

// stop terminates the process gracefully (both roles drain on SIGTERM) and
// falls back to SIGKILL after 10s.
func (s *server) stop() {
	select {
	case <-s.done:
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
}

// Prepare registers the per-test failure hook: when the test fails, the
// tails of both server logs land in the test output so a CI failure is
// diagnosable without shell access.
func (s *Stack) Prepare(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			logTail(t, s.low.logPath)
			logTail(t, s.high.logPath)
		}
	})
}

const logTailBytes = 16 * 1024

func logTail(t *testing.T, path string) {
	t.Helper()
	tail, err := readTail(path, logTailBytes)
	if err != nil {
		t.Logf("no server log %s: %v", path, err)
		return
	}
	t.Logf("---- tail of %s ----\n%s", path, tail)
}

func dumpLogTail(w io.Writer, path string) {
	tail, err := readTail(path, logTailBytes)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "---- tail of %s ----\n%s\n", path, tail)
}

func readTail(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > n {
		if _, err := f.Seek(-n, io.SeekEnd); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(f)
	return string(b), err
}
