//go:build e2e

package e2e

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoModules mirrors rsc.io/quote's module graph from proxy.golang.org
// and builds+runs a consumer with the real go toolchain pointed at the high
// side's GOPROXY — with ",off" as the fallback so any miss in the mirror is
// a hard failure, never a silent fetch from the internet. GOSUMDB stays
// enabled: the mirror serves the captured sum.golang.org records and tiles,
// so the toolchain's end-to-end checksum-database verification runs against
// the mirror alone.
func TestGoModules(t *testing.T) {
	stack.Prepare(t)
	goBin := requireTool(t, "go")

	res := stack.Collect(t, "go", map[string]any{
		"modules":      []string{"rsc.io/quote@v1.5.2"},
		"resolve_deps": true, // pulls rsc.io/sampler and golang.org/x/text too
	})
	stack.WaitImported(t, "go", res.Sequence)

	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	writeFile(t, filepath.Join(proj, "go.mod"), `module e2e.example/consumer

go 1.21

require rsc.io/quote v1.5.2
`)
	// quote.Go() rather than quote.Hello(): Hello() routes through
	// rsc.io/sampler's locale matching and answers in the language of the
	// host's LANG/LC_ALL — "Ahoy, world!" on some CI locales. Go() is a
	// fixed string, and the package still imports sampler and x/text, so
	// the mirrored three-module graph is exercised either way.
	writeFile(t, filepath.Join(proj, "main.go"), `package main

import (
	"fmt"

	"rsc.io/quote"
)

func main() {
	fmt.Println(quote.Go())
}
`)
	// The mirror must advertise checksum-database passthrough — otherwise the
	// toolchain would fall back to the real sum.golang.org, which the
	// air-gapped deployment this simulates cannot reach.
	resp, err := http.Get(stack.HighURL + "/go/sumdb/sum.golang.org/supported")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sumdb passthrough probe = %d, want 200", resp.StatusCode)
	}

	env := []string{
		"GOPROXY=" + stack.HighURL + "/go,off",
		// GOSUMDB stays on: the collect captured sum.golang.org's records and
		// proofs for every mirrored module, and the high side serves them
		// under /go/sumdb/ — so the toolchain checksum-verifies end to end
		// against the mirror alone.
		"GOSUMDB=sum.golang.org",
		// -modcacherw keeps the module cache deletable by t.TempDir cleanup
		// (go marks it read-only by default, which non-root CI cannot remove).
		"GOFLAGS=-mod=mod -modcacherw",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=" + filepath.Join(tmp, "home"),
		"GOPATH=" + filepath.Join(tmp, "gopath"),
		"GOMODCACHE=" + filepath.Join(tmp, "gomodcache"),
		"GOCACHE=" + filepath.Join(tmp, "gocache"),
	}
	run(t, proj, env, goBin, "mod", "tidy")
	out := runStdout(t, proj, env, goBin, "run", ".")
	const want = "Don't communicate by sharing memory, share memory by communicating."
	if strings.TrimSpace(out) != want {
		t.Fatalf("go run printed %q, want %q", strings.TrimSpace(out), want)
	}
}
