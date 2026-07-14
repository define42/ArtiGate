//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gitMirrorRepo is the tiny public repository the git stream test mirrors;
// its default branch is master and it carries a single README at the root.
const gitMirrorRepo = "https://github.com/octocat/Hello-World.git"

// TestGit mirrors a real repository across the diode — the low side speaks
// git's smart HTTP protocol as a pure-Go client, the high side regenerates
// the pack index from the verified pack and serves the dumb HTTP protocol —
// and consumes the result with stock git: clone, log, fsck --strict (object
// integrity end to end), and ls-remote against the mirror.
func TestGit(t *testing.T) {
	stack.Prepare(t)
	git := requireTool(t, "git")

	res := stack.Collect(t, "git", map[string]any{
		"url":  gitMirrorRepo,
		"name": "hello",
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly one mirrored repository, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "git", res.Sequence)

	// The regenerated dumb-protocol ref list is the first thing any git
	// client fetches (the smart probe is answered as plain text, which flips
	// stock git to the dumb protocol automatically).
	code, body := httpGet(t, stack.HighURL+"/git/hello/info/refs")
	if code != 200 || !strings.Contains(string(body), "refs/heads/master") {
		t.Fatalf("info/refs = %d %s", code, body)
	}

	tmp := t.TempDir()
	env := []string{"HOME=" + tmp, "GIT_TERMINAL_PROMPT=0"}
	clone := filepath.Join(tmp, "clone")
	run(t, tmp, env, git, "clone", stack.HighURL+"/git/hello.git", clone)
	if _, err := os.Stat(filepath.Join(clone, "README")); err != nil {
		t.Fatalf("clone carries no README: %v", err)
	}
	if out := runStdout(t, clone, env, git, "-C", clone, "log", "--oneline"); strings.TrimSpace(out) == "" {
		t.Fatal("git log in the clone is empty")
	}
	// fsck re-hashes every object: proof the pure-Go pack pipeline delivered
	// the repository bit-for-bit intact.
	run(t, clone, env, git, "-C", clone, "fsck", "--strict")

	// ls-remote against the mirror lists exactly the refs the high side
	// serves.
	lsRemote := runStdout(t, tmp, env, git, "ls-remote", stack.HighURL+"/git/hello.git")
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if !strings.Contains(lsRemote, line) {
			t.Errorf("ls-remote misses %q:\n%s", line, lsRemote)
		}
	}
}
