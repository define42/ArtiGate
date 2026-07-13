//go:build e2e

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestGoModules mirrors rsc.io/quote's module graph from proxy.golang.org
// and builds+runs a consumer with the real go toolchain pointed at the high
// side's GOPROXY — with ",off" as the fallback so any miss in the mirror is
// a hard failure, never a silent fetch from the internet.
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
	writeFile(t, filepath.Join(proj, "main.go"), `package main

import (
	"fmt"

	"rsc.io/quote"
)

func main() {
	fmt.Println(quote.Hello())
}
`)
	env := []string{
		"GOPROXY=" + stack.HighURL + "/go,off",
		"GOSUMDB=off", // no sumdb mirroring by design; trust the signed bundles
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=" + filepath.Join(tmp, "home"),
		"GOPATH=" + filepath.Join(tmp, "gopath"),
		"GOMODCACHE=" + filepath.Join(tmp, "gomodcache"),
		"GOCACHE=" + filepath.Join(tmp, "gocache"),
	}
	run(t, proj, env, goBin, "mod", "tidy")
	out := runStdout(t, proj, env, goBin, "run", ".")
	if strings.TrimSpace(out) != "Hello, world." {
		t.Fatalf("go run printed %q, want %q", strings.TrimSpace(out), "Hello, world.")
	}
}
