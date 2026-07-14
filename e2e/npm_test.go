//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestNpm mirrors left-pad from registry.npmjs.org, installs it from the
// high side's registry API with the real npm (which re-verifies the
// packument's integrity hash against the tarball), and requires it with
// node. left-pad@1.3.0 is tiny, dependency-free, and frozen forever.
func TestNpm(t *testing.T) {
	stack.Prepare(t)
	npm := requireTool(t, "npm")
	node := requireTool(t, "node")

	res := stack.Collect(t, "npm", map[string]any{"packages": []string{"left-pad@1.3.0"}})
	stack.WaitImported(t, "npm", res.Sequence)

	// The packument's dist-tags come from the mirrored upstream snapshot,
	// filtered to versions actually served: left-pad's real latest is 1.3.0
	// (its final release), so the tag must resolve on the mirror too.
	code, body := httpGet(t, stack.HighURL+"/npm/left-pad")
	if code != 200 || !strings.Contains(string(body), `"latest": "1.3.0"`) {
		t.Fatalf("packument dist-tags = %d %s", code, body)
	}

	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	writeFile(t, filepath.Join(proj, "package.json"), `{"name":"e2e-consumer","version":"1.0.0","private":true}`)
	writeFile(t, filepath.Join(proj, ".npmrc"), fmt.Sprintf(`registry=%s/npm/
cache=%s
audit=false
fund=false
update-notifier=false
`, stack.HighURL, filepath.Join(tmp, "npm-cache")))

	// A private HOME keeps the user's ~/.npmrc (and its registry) out of
	// the picture.
	env := []string{"HOME=" + filepath.Join(tmp, "home")}
	run(t, proj, env, npm, "install", "left-pad@1.3.0", "--no-audit", "--no-fund")
	out := runStdout(t, proj, env, node, "-e", `console.log(require('left-pad')('42', 5, '0'))`)
	if strings.TrimSpace(out) != "00042" {
		t.Fatalf("node printed %q, want %q", strings.TrimSpace(out), "00042")
	}
}
