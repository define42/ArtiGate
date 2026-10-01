//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHarnessRaceCoverage(t *testing.T) {
	if !raceEnabled {
		t.Log("child race coverage is exercised by the -race suite")
		return
	}
	if err := requireRaceBinary(stack.Bin); err != nil {
		t.Fatal(err)
	}
	wd := t.TempDir()
	source := filepath.Join(wd, "main.go")
	const program = `package main
import (
	"runtime"
	"sync"
)
func main() {
	runtime.GOMAXPROCS(2)
	var value int
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for range 1000000 {
				value++
			}
		})
	}
	wg.Wait()
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(wd, "race-child")
	if out, err := exec.Command("go", "build", "-race", "-o", bin, source).CombinedOutput(); err != nil {
		t.Fatalf("build race fixture: %v\n%s", err, out)
	}
	// The child must override an inherited setting that hides errors.
	srv, err := launch(bin, nil, []string{"GORACE=log_path=/dev/null exitcode=0"}, filepath.Join(wd, "child.log"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-srv.done:
	case <-time.After(20 * time.Second):
		_ = srv.stop()
		t.Fatal("racing child did not terminate")
	}
	if err := srv.stop(); err == nil || !strings.Contains(err.Error(), "child data race detected") {
		t.Fatalf("child data race was not reported to the harness: %v", err)
	}
}
