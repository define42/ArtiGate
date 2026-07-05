package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGoScript is a stand-in for the `go` command. The low side shells out for
// list-versions, list-latest, single module downloads, and (for dependency
// resolution) a whole-graph download. Each download materializes the
// .info/.mod/.zip files into the module cache exactly where the real `go` would
// ($GOMODCACHE/cache/download/<module>/@v/<version>.*). For graph downloads the
// script reads the synthetic go.mod's require lines and emits an extra
// "example.com/dep" module so tests can prove transitive capture.
const fakeGoScript = `#!/usr/bin/env bash
set -eu
dldir="${GOMODCACHE}/cache/download"
emit() {
  local mod="$1" ver="$2"
  local d="${dldir}/${mod}/@v"
  mkdir -p "$d"
  printf '{"Version":"%s","Time":"2020-01-01T00:00:00Z"}' "$ver" > "${d}/${ver}.info"
  printf 'module %s\n' "$mod" > "${d}/${ver}.mod"
  printf 'fake-zip-bytes' > "${d}/${ver}.zip"
  printf '{"Path":"%s","Version":"%s","Info":"%s","GoMod":"%s","Zip":"%s"}\n' \
    "$mod" "$ver" "${d}/${ver}.info" "${d}/${ver}.mod" "${d}/${ver}.zip"
}
last=""
for a in "$@"; do last="$a"; done
case "$*" in
  *"-versions"*)
    printf '{"Path":"%s","Versions":["v1.0.0","v1.1.0"]}' "$last"
    ;;
  *"download -json all")
    in_block=0
    while read -r a b c; do
      if [ "$a" = "require" ] && [ "$b" = "(" ]; then in_block=1; continue; fi
      if [ "$in_block" = "1" ] && [ "$a" = ")" ]; then in_block=0; continue; fi
      if [ "$in_block" = "1" ]; then emit "$a" "$b"; continue; fi
      if [ "$a" = "require" ]; then emit "$b" "$c"; fi
    done < go.mod
    emit "example.com/dep" "v0.1.0"
    ;;
  *"download"*)
    emit "${last%@*}" "${last##*@}"
    ;;
  *)
    mod="${last%@latest}"
    printf '{"Path":"%s","Version":"v1.1.0","Time":"2020-01-01T00:00:00Z"}' "$mod"
    ;;
esac
`

func writeFakeGo(t *testing.T) string {
	return writeFakeGoWith(t, fakeGoScript)
}

func writeFakeGoWith(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake go shell script is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for fake go script")
	}
	p := filepath.Join(t.TempDir(), "go")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newFakeLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	return newFakeLowServerWithGo(t, writeFakeGo(t))
}

func newFakeLowServerWithGo(t *testing.T, goBin string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:            t.TempDir(),
		ExportDir:       filepath.Join(t.TempDir(), "out"),
		GoBinary:        goBin,
		UpstreamGOPROXY: "off",
		GOSUMDB:         "off",
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// poisonGoScript is a fake `go` that materializes modules normally but makes
// any module whose path contains "poison" unfetchable, like a version that was
// retracted or deleted upstream after it was first recorded.
const poisonGoScript = `#!/usr/bin/env bash
set -eu
dldir="${GOMODCACHE}/cache/download"
last=""
for a in "$@"; do last="$a"; done
case "$*" in
  *"download"*)
    mod="${last%@*}"; ver="${last##*@}"
    case "$mod" in
      *poison*)
        echo "${mod}@${ver}: reading ${mod}: 404 Not Found" >&2
        exit 1
        ;;
    esac
    d="${dldir}/${mod}/@v"
    mkdir -p "$d"
    printf '{"Version":"%s","Time":"2020-01-01T00:00:00Z"}' "$ver" > "${d}/${ver}.info"
    printf 'module %s\n' "$mod" > "${d}/${ver}.mod"
    printf 'fake-zip-bytes' > "${d}/${ver}.zip"
    printf '{"Path":"%s","Version":"%s","Info":"%s","GoMod":"%s","Zip":"%s"}\n' \
      "$mod" "$ver" "${d}/${ver}.info" "${d}/${ver}.mod" "${d}/${ver}.zip"
    ;;
esac
`

// TestLowServerGoLatest checks that "module@latest" resolution — used by
// /admin/go/collect for an unpinned module — picks the highest release version
// from the fake upstream.
func TestLowServerGoLatest(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	info, err := ls.goLatest(context.Background(), "example.com/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "v1.1.0" {
		t.Errorf("goLatest version = %q, want v1.1.0", info.Version)
	}
}

func TestLowServerExportAndReexport(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	ctx := context.Background()

	res, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedModules != 1 || res.Sequence != 1 || res.BundleID != "go-bundle-000001" {
		t.Fatalf("unexpected export result: %+v", res)
	}

	// The three signed bundle files must exist and the signature must verify.
	pub := priv.Public().(ed25519.PublicKey)
	manifestBytes, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, "go-bundle-000001.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	sigB64, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, "go-bundle-000001.manifest.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		t.Error("exported bundle signature does not verify")
	}

	// Re-exporting the same sequence must succeed and regenerate it.
	r := httptest.NewRequest(http.MethodPost, "/admin/reexport?sequences=1", nil)
	rr, err := ls.HandleReexportRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Reexported) != 1 || len(rr.Failed) != 0 {
		t.Errorf("reexport result: %+v", rr)
	}
}

func TestLowServerGoCollect(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	ctx := context.Background()

	// One concrete version and one "@latest" that the fake go resolves to v1.1.0.
	res, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{
		"example.com/foo/bar@v1.0.0",
		"example.com/foo/baz@latest",
	}})
	if err != nil {
		t.Fatalf("CollectGo: %v", err)
	}
	if res.BundleID != "go-bundle-000001" || res.ExportedModules != 2 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	// Deliver to a high server and confirm both modules are served.
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of collected go bundle failed: %v", err)
	}
	if !hs.isComplete("example.com/foo/bar", "v1.0.0") || !hs.isComplete("example.com/foo/baz", "v1.1.0") {
		t.Error("collected modules not complete on high side")
	}

	// A second collect of already-forwarded content is a no-op: Tier-1 dedup
	// produces no bundle and burns no sequence number.
	res2, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Skipped || res2.BundleID != "" {
		t.Errorf("re-collect of forwarded content = %+v, want skipped with no bundle", res2)
	}
	if seq := ls.peekSequence(streamGo); seq != 2 {
		t.Errorf("next go sequence = %d, want 2 (skip must not burn a number)", seq)
	}

	// An empty module list is rejected.
	if _, err := ls.CollectGo(ctx, GoCollectRequest{}); err == nil {
		t.Error("empty CollectGo should error")
	}
}

// TestLowServerConcurrentExportsUniqueSequences guards the within-stream
// export-sequence serialization. Before a stream's lock wrapped the whole
// allocate->write->commit, two concurrent exporters could peek the same
// sequence, both write the same go-bundle-NNNNNN.* files, and both advance the
// counter — silently dropping one exporter's modules or pairing a manifest with
// the other's signature (which permanently blocks the high side). Each
// concurrent export on a stream must instead receive a distinct sequence with
// an intact, verifiable bundle.
func TestLowServerConcurrentExportsUniqueSequences(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	pub := priv.Public().(ed25519.PublicKey)
	ctx := context.Background()

	const n = 12
	seqs := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := ls.CollectGo(ctx, GoCollectRequest{
				Modules: []string{fmt.Sprintf("example.com/mod%02d@v1.0.0", i)},
			})
			errs[i], seqs[i] = err, res.Sequence
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent CollectGo %d failed: %v", i, err)
		}
	}

	// The assigned sequences must be exactly 1..n — no duplicates, no gaps.
	sorted := append([]int64(nil), seqs...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	for i, seq := range sorted {
		if seq != int64(i+1) {
			t.Fatalf("sequences are not a clean 1..%d permutation: %v", n, sorted)
		}
	}

	// Every bundle must be present and its signature must verify; a torn
	// manifest/signature pair from interleaved writers would fail here.
	for seq := int64(1); seq <= n; seq++ {
		assertBundleSigned(t, ls.cfg.ExportDir, bundleIDForSequence(seq), pub)
	}

	// The counter must have advanced exactly past the last sequence.
	if got := ls.peekSequence(streamGo); got != int64(n+1) {
		t.Errorf("NextSequence after %d concurrent collects = %d, want %d", n, got, n+1)
	}
}

// TestStreamLocksAreIndependent proves the per-stream export locks let different
// ecosystems export concurrently while still serializing within a stream:
// holding the go lock must not block acquiring the python lock (so a long
// APT/Go fetch never blocks a Python collect), but must block a second
// acquisition of the go lock.
func TestStreamLocksAreIndependent(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	goMu := ls.streamLock(streamGo)
	goMu.Lock()
	defer goMu.Unlock()

	// A different stream's lock is a different mutex and must be immediately
	// acquirable while the go lock is held.
	if ls.streamLock(streamPython) == goMu {
		t.Fatal("python and go must not share an export lock")
	}
	gotPy := make(chan struct{})
	go func() {
		pyMu := ls.streamLock(streamPython)
		pyMu.Lock()
		pyMu.Unlock()
		close(gotPy)
	}()
	select {
	case <-gotPy:
	case <-time.After(2 * time.Second):
		t.Fatal("python export blocked while the go stream lock was held")
	}

	// The same stream's lock, by contrast, must not be acquirable concurrently.
	gotGo := make(chan struct{})
	go func() {
		goMu.Lock() // blocks until the deferred Unlock releases it after the test
		goMu.Unlock()
		close(gotGo)
	}()
	select {
	case <-gotGo:
		t.Fatal("a second go export acquired the go lock while it was already held")
	case <-time.After(200 * time.Millisecond):
		// Expected: still blocked while this test holds the go lock.
	}
}

// assertBundleSigned checks that a bundle's three files exist in dir and that
// its signature verifies against pub over the manifest bytes.
func assertBundleSigned(t *testing.T, dir, bundleID string, pub ed25519.PublicKey) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, bundleID+".tar.gz")); err != nil {
		t.Errorf("bundle %s archive missing: %v", bundleID, err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(dir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatalf("read manifest %s: %v", bundleID, err)
	}
	sigB64, err := os.ReadFile(filepath.Join(dir, bundleID+".manifest.json.sig"))
	if err != nil {
		t.Fatalf("read sig %s: %v", bundleID, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		t.Fatalf("decode sig %s: %v", bundleID, err)
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		t.Errorf("bundle %s signature does not verify", bundleID)
	}
}

// TestLowServerExportSkipsUnfetchableModule proves one unfetchable module no
// longer poisons the whole batch: the healthy modules still export, the bad one
// is reported as skipped, and the sequence stream keeps moving.
func TestLowServerExportSkipsUnfetchableModule(t *testing.T) {
	ls, priv := newFakeLowServerWithGo(t, writeFakeGoWith(t, poisonGoScript))
	pub := priv.Public().(ed25519.PublicKey)
	ctx := context.Background()

	res, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{
		"example.com/good/one@v1.0.0",
		"example.com/poison/gone@v2.0.0",
	}})
	if err != nil {
		t.Fatalf("CollectGo must succeed despite one unfetchable module: %v", err)
	}
	if res.Sequence != 1 || res.BundleID != "go-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("export = %+v, want seq 1 / go-bundle-000001 / 1 module", res)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "example.com/poison/gone" {
		t.Fatalf("SkippedModules = %+v, want the poison module", res.SkippedModules)
	}
	assertBundleSigned(t, ls.cfg.ExportDir, "go-bundle-000001", pub)

	// The stream keeps flowing: a new healthy module exports as sequence 2 while
	// the poison one is skipped again.
	res2, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{
		"example.com/good/two@v1.0.0",
		"example.com/poison/gone@v2.0.0",
	}})
	if err != nil {
		t.Fatalf("second CollectGo failed: %v", err)
	}
	if res2.Sequence != 2 || res2.ExportedModules != 1 || len(res2.SkippedModules) != 1 {
		t.Errorf("second export = %+v, want seq 2 / 1 module / 1 skipped", res2)
	}
}

// TestLowServerExportAllUnfetchableDoesNotBurnSequence proves that when every
// pending module is unfetchable, no empty bundle is written and the sequence
// number is not advanced (which would make the high side wait forever).
func TestLowServerExportAllUnfetchableDoesNotBurnSequence(t *testing.T) {
	ls, _ := newFakeLowServerWithGo(t, writeFakeGoWith(t, poisonGoScript))
	ctx := context.Background()

	_, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{
		"example.com/poison/a@v1.0.0",
		"example.com/poison/b@v1.0.0",
	}})
	if err == nil {
		t.Fatal("CollectGo should error when every module is unfetchable")
	}
	if got := ls.peekSequence(streamGo); got != 1 {
		t.Errorf("NextSequence = %d, want 1 (no sequence burned)", got)
	}
	if entries, _ := os.ReadDir(ls.cfg.ExportDir); len(entries) != 0 {
		t.Errorf("export dir should have no bundle files, found %d entries", len(entries))
	}
}

// TestCollectGoRejectsFlagInjection proves a module spec that looks like a `go`
// flag is rejected and never reaches the fetcher as a command-line argument,
// whether it resolves via @latest or is a concrete version.
func TestCollectGoRejectsFlagInjection(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	ctx := context.Background()

	// @latest form is rejected at resolution (validated before `go list`).
	if _, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"-C@latest"}}); err == nil {
		t.Error("CollectGo accepted a flag-like module spec (@latest)")
	}
	// Concrete-version form is rejected at fetch (validated before `go mod
	// download`), so nothing is exported.
	if _, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"-modfile@v1.0.0"}}); err == nil {
		t.Error("CollectGo accepted a flag-like module spec (concrete version)")
	}
}

// TestCollectGoModToleratesToolchainStderr reproduces the go.mod upload failure
// where GOTOOLCHAIN=auto writes "go: downloading go1.X ..." to stderr while the
// module-graph JSON goes to stdout. Merging the two streams spliced that "go:"
// line into the JSON and broke parsing ("invalid character 'g'"); runGoDir must
// read stdout alone.
func TestCollectGoModToleratesToolchainStderr(t *testing.T) {
	noisy := strings.Replace(fakeGoScript, "set -eu\n",
		"set -eu\necho 'go: downloading go1.26.3 (linux/amd64)' >&2\n", 1)
	ls, _ := newFakeLowServerWithGo(t, writeFakeGoWith(t, noisy))

	goMod := "module example.com/authbroker\n\ngo 1.26.3\n\n" +
		"require example.com/foo/bar v1.0.0\n"
	res, err := ls.CollectGo(context.Background(), GoCollectRequest{GoMod: goMod})
	if err != nil {
		t.Fatalf("CollectGo must tolerate toolchain-download stderr noise: %v", err)
	}
	if res.ExportedModules < 1 || res.BundleID != "go-bundle-000001" {
		t.Errorf("unexpected result: %+v", res)
	}
}

// TestCollectGoBareModuleResolvesLatest proves a bare module path (no @version)
// — how the UI's "newest of <module>" input arrives — resolves to the newest
// version and is fetched.
func TestCollectGoBareModuleResolvesLatest(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	res, err := ls.CollectGo(context.Background(), GoCollectRequest{Modules: []string{"example.com/foo/bar"}})
	if err != nil {
		t.Fatalf("CollectGo: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Fatalf("expected 1 module, got %+v", res)
	}
	// The fake upstream's newest example.com/foo/bar is v1.1.0.
	if !fileExists(filepath.Join(ls.downloadDir, "example.com", "foo", "bar", "@v", "v1.1.0.info")) {
		t.Error("bare module did not resolve to the newest version (v1.1.0)")
	}
}

func TestLowServerGoCollectWithDeps(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	ctx := context.Background()

	res, err := ls.CollectGo(ctx, GoCollectRequest{
		Modules:     []string{"example.com/foo/bar@v1.0.0"},
		ResolveDeps: true,
	})
	if err != nil {
		t.Fatalf("CollectGo with deps: %v", err)
	}
	// The requested module plus its transitive dep (example.com/dep) are bundled.
	if res.ExportedModules != 2 {
		t.Fatalf("ExportedModules = %d, want 2 (root + transitive dep)", res.ExportedModules)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import failed: %v", err)
	}
	if !hs.isComplete("example.com/foo/bar", "v1.0.0") {
		t.Error("root module not complete on high side")
	}
	if !hs.isComplete("example.com/dep", "v0.1.0") {
		t.Error("transitive dependency was not captured and served")
	}
}

func TestLowServerGoCollectFromGoMod(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	ctx := context.Background()

	// A real-world go.mod using a require block.
	goMod := "module example.com/myapp\n\ngo 1.22\n\n" +
		"require (\n" +
		"\texample.com/foo/bar v1.0.0\n" +
		"\texample.com/foo/baz v1.1.0 // indirect\n" +
		")\n"

	res, err := ls.CollectGo(ctx, GoCollectRequest{GoMod: goMod})
	if err != nil {
		t.Fatalf("CollectGo from go.mod: %v", err)
	}
	// Both required modules plus the toolchain-discovered transitive dep.
	if res.ExportedModules != 3 {
		t.Fatalf("ExportedModules = %d, want 3", res.ExportedModules)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import failed: %v", err)
	}
	for _, m := range []struct{ mod, ver string }{
		{"example.com/foo/bar", "v1.0.0"},
		{"example.com/foo/baz", "v1.1.0"},
		{"example.com/dep", "v0.1.0"},
	} {
		if !hs.isComplete(m.mod, m.ver) {
			t.Errorf("%s@%s not complete on high side", m.mod, m.ver)
		}
	}
}

func TestLowServerGoCollectAdmin(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	body := strings.NewReader(`{"modules":["example.com/foo/bar@v1.0.0"]}`)
	resp, err := http.Post(srv.URL+"/admin/go/collect", "application/json", body) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("go collect admin status = %d, want 200", resp.StatusCode)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.ExportedModules != 1 || res.BundleID != "go-bundle-000001" {
		t.Errorf("unexpected admin collect result: %+v", res)
	}
}

// TestLowToHighPipeline exports a bundle on the low side, delivers it to a high
// server, imports it, and serves it back — the whole diode round-trip.
func TestLowToHighPipeline(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	ctx := context.Background()
	if _, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}}); err != nil {
		t.Fatal(err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)

	// Deliver the exported bundle files into the high-side landing directory.
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := "go-bundle-000001" + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}

	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("high import of low-produced bundle failed: %v", err)
	}
	if !res.Imported || len(res.ImportedBundles) != 1 {
		t.Fatalf("unexpected high import result: %+v", res)
	}
	if !hs.isComplete("example.com/foo/bar", "v1.0.0") {
		t.Error("module not complete on high side after pipeline")
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	if code, body := httpGet(t, srv.URL+"/go/example.com/foo/bar/@v/list"); code != http.StatusOK || !strings.Contains(body, "v1.0.0") {
		t.Errorf("high list after pipeline: status %d body %q", code, body)
	}
}
