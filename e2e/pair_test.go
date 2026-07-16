//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pairConfig configures a dedicated low/high pair for tests that need their
// own transport wiring or environment (tamper injection, the UDP diode, the
// watch scheduler, login) instead of the shared Stack.
type pairConfig struct {
	name string // log file prefix inside the pair's workdir
	// httpDiode wires the low side to the high side over the HTTP diode
	// transport like the shared Stack; without it (and without pitcher
	// env) the export dir is the folder-diode outbox and the test carries
	// bundles into the landing directory itself.
	httpDiode bool
	// lowOnly starts no high side (dashboard/login tests).
	lowOnly        bool
	importInterval string // high --import-interval, default 1s
	watchInterval  string // low --watch-interval, default 0 (disabled)
	highEnv        []string
	lowEnv         []string
}

// testPair is a dedicated low/high pair plus the on-disk paths tests reach
// into (delivering, tampering with, or inspecting bundles directly).
type testPair struct {
	*Stack
	HighRoot  string
	Landing   string
	ExportDir string
	LowRoot   string
	PrivKey   string
	PubKey    string
}

// startTestPair launches a dedicated pair using the already-built binary and
// registers cleanup: servers stop first, then (on failure) both logs are
// tailed into the test output before the workdir is removed.
func startTestPair(t *testing.T, cfg pairConfig) *testPair {
	t.Helper()
	wd := t.TempDir()
	p := &testPair{
		HighRoot:  filepath.Join(wd, "high-root"),
		Landing:   filepath.Join(wd, "landing"),
		ExportDir: filepath.Join(wd, "export"),
		LowRoot:   filepath.Join(wd, "low-root"),
		PrivKey:   filepath.Join(wd, "keys", "low.ed25519"),
		PubKey:    filepath.Join(wd, "keys", "high.ed25519.pub"),
	}
	for _, d := range []string{p.HighRoot, p.Landing, p.ExportDir, p.LowRoot, filepath.Dir(p.PrivKey)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if out, err := exec.Command(stack.Bin, "keygen", "--private", p.PrivKey, "--public", p.PubKey).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	st := &Stack{Bin: stack.Bin, WorkDir: wd}
	p.Stack = st

	token, err := diodeToken()
	if err != nil {
		t.Fatalf("diode token: %v", err)
	}
	if !cfg.lowOnly {
		startPairHigh(t, p, cfg, token)
	}
	startPairLow(t, p, cfg, token)
	return p
}

func startPairHigh(t *testing.T, p *testPair, cfg pairConfig, token string) {
	t.Helper()
	env := append([]string{}, cfg.highEnv...)
	if cfg.httpDiode {
		env = append(env, "ARTIGATE_DIODE_INGEST=on", "ARTIGATE_DIODE_TOKEN="+token)
	}
	high, err := startServer(p.Bin, cfg.name+"-high", filepath.Join(p.WorkDir, cfg.name+"-high.log"),
		func(port int) []string {
			return []string{
				"high",
				"--listen", fmt.Sprintf("127.0.0.1:%d", port),
				"--root", p.HighRoot,
				"--landing", p.Landing,
				"--public-key", p.PubKey,
				"--import-interval", orDefault(cfg.importInterval, "1s"),
			}
		}, env)
	if err != nil {
		t.Fatalf("%s high side: %v", cfg.name, err)
	}
	p.high = high
	p.HighURL = high.url
	p.HighHost = strings.TrimPrefix(high.url, "http://")
	registerPairCleanup(t, high)
}

func startPairLow(t *testing.T, p *testPair, cfg pairConfig, token string) {
	t.Helper()
	env := append([]string{}, cfg.lowEnv...)
	if cfg.httpDiode {
		env = append(env, "ARTIGATE_DIODE_URL="+p.HighURL+"/diode", "ARTIGATE_DIODE_TOKEN="+token)
	}
	low, err := startServer(p.Bin, cfg.name+"-low", filepath.Join(p.WorkDir, cfg.name+"-low.log"),
		func(port int) []string {
			return []string{
				"low",
				"--listen", fmt.Sprintf("127.0.0.1:%d", port),
				"--root", p.LowRoot,
				"--export-dir", p.ExportDir,
				"--private-key", p.PrivKey,
				"--watch-interval", orDefault(cfg.watchInterval, "0"),
			}
		}, env)
	if err != nil {
		t.Fatalf("%s low side: %v", cfg.name, err)
	}
	p.low = low
	p.LowURL = low.url
	registerPairCleanup(t, low)
}

// registerPairCleanup stops the server at test end and, on failure, tails its
// log into the test output (cleanups run LIFO: stop, then dump).
func registerPairCleanup(t *testing.T, srv *server) {
	t.Cleanup(func() {
		if t.Failed() {
			logTail(t, srv.logPath)
		}
	})
	t.Cleanup(srv.stop)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
