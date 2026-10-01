//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecoveryCheckpointAndRetention restores a signed checkpoint, replays a
// retained delta, and builds with fresh native clients after the old archives
// have been pruned. Its original receiver supplies the full-history comparison.
func TestRecoveryCheckpointAndRetention(t *testing.T) {
	p := startTestPair(t, pairConfig{name: "recovery", httpDiode: true, lowEnv: []string{"GOFLAGS=-modcacherw"}})
	firstGo := p.Collect(t, "go", map[string]any{"modules": []string{"rsc.io/quote@v1.5.2"}, "resolve_deps": true})
	firstNpm := p.Collect(t, "npm", map[string]any{"packages": []string{"left-pad@1.3.0"}})
	p.WaitImported(t, "go", firstGo.Sequence)
	p.WaitImported(t, "npm", firstNpm.Sequence)
	if err := p.low.stop(); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(p.WorkDir, "checkpoint")
	created := recoveryCLI(t, p.Bin, "checkpoint", "create", "--root", p.LowRoot,
		"--private-key", p.PrivKey, "--output", cp)
	var checkpoint struct {
		Digest string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(created, &checkpoint); err != nil || checkpoint.Digest == "" {
		t.Fatalf("checkpoint result: %s: %v", created, err)
	}
	startPairLow(t, p, pairConfig{name: "recovery-tail", lowEnv: []string{"GOFLAGS=-modcacherw"}}, "")
	goTail := p.Collect(t, "go", map[string]any{"modules": []string{"rsc.io/quote@v1.5.2", "github.com/google/uuid@v1.6.0"}, "resolve_deps": true})
	npmTail := p.Collect(t, "npm", map[string]any{"packages": []string{"left-pad@1.3.0", "is-number@7.0.0"}})
	if err := p.low.stop(); err != nil {
		t.Fatal(err)
	}
	// Deliver the retained tail to the original receiver and drain the spool.
	recoveryMoveBundles(t, p.ExportDir, p.Landing)
	p.WaitImported(t, "go", goTail.Sequence)
	p.WaitImported(t, "npm", npmTail.Sequence)
	originalURL := p.HighURL
	plan := filepath.Join(p.WorkDir, "retention.json")
	recoveryCLI(t, p.Bin, "retention", "plan", "--root", p.LowRoot,
		"--export-dir", p.ExportDir, "--public-key", p.PubKey,
		"--checkpoint", cp, "--allow-bootstrap", "--output", plan)
	recoveryCLI(t, p.Bin, "retention", "apply", "--plan", plan, "--public-key", p.PubKey)
	for _, stream := range []string{"go", "npm"} {
		old := filepath.Join(p.LowRoot, "bundles", stream+"-bundle-000001.manifest.json")
		if _, err := os.Stat(old); !os.IsNotExist(err) {
			t.Fatalf("old %s bundle was not pruned: %v", stream, err)
		}
	}
	p.HighRoot = filepath.Join(p.WorkDir, "restored-high")
	p.Landing = filepath.Join(p.WorkDir, "restored-landing")
	recoveryCLI(t, p.Bin, "checkpoint", "restore", "--input", cp,
		"--public-key", p.PubKey, "--digest", checkpoint.Digest, "--root", p.HighRoot)
	if err := os.MkdirAll(p.Landing, 0o755); err != nil {
		t.Fatal(err)
	}
	recoveryCopyBundles(t, filepath.Join(p.LowRoot, "bundles"), p.Landing)
	startPairHigh(t, p, pairConfig{name: "recovery-restored"}, "")
	p.WaitImported(t, "go", goTail.Sequence)
	p.WaitImported(t, "npm", npmTail.Sequence)
	for _, path := range []string{"/go/rsc.io/quote/@v/v1.5.2.mod", "/go/github.com/google/uuid/@v/v1.6.0.zip", "/npm/left-pad", "/npm/is-number"} {
		oldCode, oldBody := httpGet(t, originalURL+path)
		newCode, newBody := httpGet(t, p.HighURL+path)
		// npm download URLs are expected to name their own serving host.
		oldBody = bytes.ReplaceAll(oldBody, []byte(originalURL), []byte(p.HighURL))
		if oldCode != newCode || !bytes.Equal(oldBody, newBody) {
			t.Fatalf("restored response differs from full replay for %s: HTTP %d/%d", path, oldCode, newCode)
		}
	}
	recoveryNativeClients(t, p)
}

func recoveryCLI(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("artigate %v: %v\n%s\n%s", args, err, stderr.String(), out)
	}
	return out
}

func recoveryMoveBundles(t *testing.T, source, target string) {
	t.Helper()
	recoveryCopyBundles(t, source, target)
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "-bundle-") {
			if err := os.Remove(filepath.Join(source, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func recoveryCopyBundles(t *testing.T, source, target string) {
	t.Helper()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.Contains(entry.Name(), "-bundle-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, entry.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func recoveryNativeClients(t *testing.T, p *testPair) {
	t.Helper()
	rx := newReceiver(t, p.HighURL)
	work := t.TempDir()
	writeFile(t, filepath.Join(work, "go.mod"), "module recovery.example/test\n\ngo 1.21\n\nrequire rsc.io/quote v1.5.2\n")
	writeFile(t, filepath.Join(work, "main.go"), "package main\nimport (\"fmt\"; \"rsc.io/quote\")\nfunc main(){fmt.Println(quote.Go())}\n")
	goEnv := []string{
		"GOPROXY=" + p.HighURL + "/go,off", "GOSUMDB=sum.golang.org", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod -modcacherw",
		"GOMODCACHE=" + filepath.Join(work, "gomodcache"), "GOCACHE=" + filepath.Join(work, "gocache"),
	}
	out := rx.RunStdout(t, work, goEnv, requireTool(t, "go"), "run", ".")
	if !strings.Contains(out, "Don't communicate by sharing memory") {
		t.Fatalf("unexpected restored Go execution: %s", out)
	}
	writeFile(t, filepath.Join(work, "package.json"), `{"name":"recovery-test","private":true,"version":"1.0.0"}`)
	writeFile(t, filepath.Join(work, ".npmrc"), fmt.Sprintf("registry=%s/npm/\ncache=%s\naudit=false\nfund=false\n", p.HighURL, filepath.Join(work, "npm-cache")))
	rx.Run(t, work, nil, requireTool(t, "npm"), "install", "left-pad@1.3.0", "is-number@7.0.0")
	out = rx.RunStdout(t, work, nil, requireTool(t, "node"), "-e", `console.log(require('left-pad')('42',5,'0'), require('is-number')(42))`)
	if strings.TrimSpace(out) != "00042 true" {
		t.Fatalf("unexpected restored npm execution: %s", out)
	}
}
