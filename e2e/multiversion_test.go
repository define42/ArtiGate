//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// The multi-version / cross-bundle tests close a specific e2e blind spot:
// every index-regenerating stream was previously exercised with exactly one
// package at one version, so nothing end-to-end proved that a regenerated
// index lists more than one version, nor that "regenerate indexes from the
// artifacts actually present" accumulates content across *separate* bundles
// (the invariant behind the APT stanza-separator and RPM filelists bugs).
//
// Each test collects two versions of one package as two separate collects —
// two independently sequenced bundles — and then asserts the high side's
// regenerated index lists BOTH, and that the older, superseded artifact is
// still resolvable and downloadable by the real client after the newer bundle
// imported on top of it.
//
// They run on their own dedicated low+high pair rather than the shared stack:
// the shared stack's per-stream tests collect the same packages (left-pad,
// rake), and the low side dedups already-forwarded content across collects, so
// sharing a stack would make whichever test ran second see an unexpected
// "nothing new to export" skip. A private pair keeps each test self-contained.

// leftPadOldVersion and leftPadNewVersion are two immutable, dependency-free
// left-pad releases; npmjs keeps both forever.
const (
	leftPadOldVersion = "1.2.0"
	leftPadNewVersion = "1.3.0"
)

// TestNpmMultiVersionAccumulation mirrors two left-pad versions in two
// separate collects and asserts the regenerated packument lists both, then
// installs the older one with the real npm to prove the first bundle's
// artifact still serves after the second bundle imported.
func TestNpmMultiVersionAccumulation(t *testing.T) {
	npm := requireTool(t, "npm")
	node := requireTool(t, "node")
	p := startTestPair(t, pairConfig{name: "npmmultiver", httpDiode: true})

	// Two separate collects → two separate bundles on the npm stream.
	resOld := p.Collect(t, "npm", map[string]any{"packages": []string{"left-pad@" + leftPadOldVersion}})
	p.WaitImported(t, "npm", resOld.Sequence)
	resNew := p.Collect(t, "npm", map[string]any{"packages": []string{"left-pad@" + leftPadNewVersion}})
	if resNew.Sequence <= resOld.Sequence {
		t.Fatalf("second npm collect did not advance the stream: %d then %d", resOld.Sequence, resNew.Sequence)
	}
	p.WaitImported(t, "npm", resNew.Sequence)

	// The regenerated packument must list both versions — one delivered by each
	// bundle — proving the index accumulates artifacts across bundles rather
	// than reflecting only the newest one.
	code, body := httpGet(t, p.HighURL+"/npm/left-pad")
	if code != 200 {
		t.Fatalf("packument HTTP %d: %s", code, body)
	}
	var packument struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(body, &packument); err != nil {
		t.Fatalf("parse packument: %v\n%s", err, body)
	}
	for _, v := range []string{leftPadOldVersion, leftPadNewVersion} {
		if _, ok := packument.Versions[v]; !ok {
			t.Fatalf("packument versions %v missing %s (cross-bundle index did not accumulate)", keysOf(packument.Versions), v)
		}
	}

	// The real npm installs the OLDER version specifically, resolving it from
	// the accumulated packument and re-verifying its integrity against the
	// tarball the first bundle delivered.
	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	writeFile(t, filepath.Join(proj, "package.json"), `{"name":"e2e-consumer","version":"1.0.0","private":true}`)
	writeFile(t, filepath.Join(proj, ".npmrc"), fmt.Sprintf(`registry=%s/npm/
cache=%s
audit=false
fund=false
update-notifier=false
`, p.HighURL, filepath.Join(tmp, "npm-cache")))
	env := []string{"HOME=" + filepath.Join(tmp, "home")}
	run(t, proj, env, npm, "install", "left-pad@"+leftPadOldVersion, "--no-audit", "--no-fund")
	out := runStdout(t, proj, env, node, "-e",
		`const lp=require('left-pad'); console.log(require('left-pad/package.json').version, lp('42',5,'0'))`)
	if strings.TrimSpace(out) != leftPadOldVersion+" 00042" {
		t.Fatalf("node printed %q, want %q", strings.TrimSpace(out), leftPadOldVersion+" 00042")
	}
}

// rakeOldVersion and rakeNewVersion are two immutable, dependency-free rake
// releases on rubygems.org.
const (
	rakeOldVersion = "13.1.0"
	rakeNewVersion = "13.2.1"
)

// TestRubyGemsMultiVersionAccumulation mirrors two rake versions in two
// separate collects and asserts the regenerated compact index lists both,
// then installs the older one with the real bundler to prove the first
// bundle's .gem still serves after the second bundle imported.
func TestRubyGemsMultiVersionAccumulation(t *testing.T) {
	p := startTestPair(t, pairConfig{name: "rubygemsmultiver", httpDiode: true})

	resOld := p.Collect(t, "rubygems", map[string]any{"gems": []string{"rake@" + rakeOldVersion}})
	p.WaitImported(t, "rubygems", resOld.Sequence)
	resNew := p.Collect(t, "rubygems", map[string]any{"gems": []string{"rake@" + rakeNewVersion}})
	if resNew.Sequence <= resOld.Sequence {
		t.Fatalf("second rubygems collect did not advance the stream: %d then %d", resOld.Sequence, resNew.Sequence)
	}
	p.WaitImported(t, "rubygems", resNew.Sequence)

	// The regenerated /info/rake must carry an info line for each version — one
	// from each bundle — and /versions must list both tokens. A single blank
	// line or wrong separator (the class of bug these tests guard) would drop
	// one of them.
	code, body := httpGet(t, p.HighURL+"/rubygems/info/rake")
	if code != 200 {
		t.Fatalf("/info/rake HTTP %d: %s", code, body)
	}
	for _, v := range []string{rakeOldVersion, rakeNewVersion} {
		if !strings.Contains(string(body), "\n"+v+" ") && !strings.HasPrefix(string(body), v+" ") {
			t.Fatalf("/info/rake missing version %s (cross-bundle index did not accumulate):\n%s", v, body)
		}
	}
	code, body = httpGet(t, p.HighURL+"/rubygems/versions")
	if code != 200 || !strings.Contains(string(body), "\nrake ") {
		t.Fatalf("/versions = %d %s", code, body)
	}

	bundle := requireTool(t, "bundle")

	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	// Pin the OLDER version: bundler resolves it from the accumulated compact
	// index and re-verifies its checksum against the .gem the first bundle
	// delivered.
	writeFile(t, filepath.Join(proj, "Gemfile"), fmt.Sprintf("source %q\ngem \"rake\", %q\n",
		p.HighURL+"/rubygems", rakeOldVersion))
	env := []string{
		"HOME=" + filepath.Join(tmp, "home"),
		"GEM_HOME=" + filepath.Join(tmp, "gems"),
		"BUNDLE_PATH=" + filepath.Join(tmp, "vendor"),
		"BUNDLE_APP_CONFIG=" + filepath.Join(tmp, "bundleconfig"),
	}
	run(t, proj, env, bundle, "install")
	out := runStdout(t, proj, env, bundle, "exec", "rake", "--version")
	if !strings.Contains(out, rakeOldVersion) {
		t.Fatalf("bundle exec rake --version printed %q, want it to contain %q", strings.TrimSpace(out), rakeOldVersion)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
