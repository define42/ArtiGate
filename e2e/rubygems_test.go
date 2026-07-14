//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// rakeVersion pins an immutable release on rubygems.org with zero runtime
// dependencies, so the collect and the bundle install ask for exactly one
// gem.
const rakeVersion = "13.2.1"

// TestRubyGems mirrors a gem from the real rubygems.org compact index across
// the diode and consumes the regenerated index with the real bundler: the
// Gemfile's source points at the high side, so resolution (/versions,
// /info/rake), the .gem download, and checksum verification all go through
// ArtiGate.
func TestRubyGems(t *testing.T) {
	stack.Prepare(t)

	res := stack.Collect(t, "rubygems", map[string]any{"gems": []string{"rake@" + rakeVersion}})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned gem, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "rubygems", res.Sequence)

	// Protocol-level asserts come before the client step on purpose: when
	// bundler is missing, requireTool below skips the rest of the test, but
	// by then these asserts have already passed, so the regenerated compact
	// index is still exercised on every run.
	code, body := httpGet(t, stack.HighURL+"/rubygems/versions")
	if code != 200 || !strings.Contains(string(body), "\nrake "+rakeVersion+" ") {
		t.Fatalf("regenerated /versions = %d %s", code, body)
	}
	code, body = httpGet(t, stack.HighURL+"/rubygems/info/rake")
	if code != 200 || !strings.Contains(string(body), rakeVersion+" ") ||
		!strings.Contains(string(body), "checksum:") {
		t.Fatalf("regenerated /info/rake = %d %s", code, body)
	}

	bundle := requireTool(t, "bundle")

	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	writeFile(t, filepath.Join(proj, "Gemfile"), fmt.Sprintf("source %q\ngem \"rake\", %q\n",
		stack.HighURL+"/rubygems", rakeVersion))

	// A private HOME plus per-run gem/bundler paths keep the user's Ruby
	// setup (and its configured sources) out of the picture.
	env := []string{
		"HOME=" + filepath.Join(tmp, "home"),
		"GEM_HOME=" + filepath.Join(tmp, "gems"),
		"BUNDLE_PATH=" + filepath.Join(tmp, "vendor"),
		"BUNDLE_APP_CONFIG=" + filepath.Join(tmp, "bundleconfig"),
	}
	// bundle install resolves against the mirror's compact index (bundler
	// re-verifies each info line's checksum against the downloaded .gem).
	run(t, proj, env, bundle, "install")
	out := runStdout(t, proj, env, bundle, "exec", "rake", "--version")
	if !strings.Contains(out, rakeVersion) {
		t.Fatalf("bundle exec rake --version printed %q, want it to contain %q",
			strings.TrimSpace(out), rakeVersion)
	}
}
