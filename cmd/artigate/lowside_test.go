package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake go shell script is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for fake go script")
	}
	p := filepath.Join(t.TempDir(), "go")
	if err := os.WriteFile(p, []byte(fakeGoScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newFakeLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:            t.TempDir(),
		ExportDir:       filepath.Join(t.TempDir(), "out"),
		AutoApprove:     true,
		GoBinary:        writeFakeGo(t),
		UpstreamGOPROXY: "off",
		GOSUMDB:         "off",
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	return ls, priv
}

func TestLowServerGoListAndLatest(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	ctx := context.Background()

	versions, err := ls.goListVersions(ctx, "example.com/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(versions, ",") != "v1.0.0,v1.1.0" {
		t.Errorf("goListVersions = %v", versions)
	}

	info, err := ls.goLatest(ctx, "example.com/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "v1.1.0" {
		t.Errorf("goLatest version = %q, want v1.1.0", info.Version)
	}
}

func TestLowServerServeProxy(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	cases := []struct {
		path    string
		wantSub string
	}{
		{"/example.com/foo/bar/@v/list", "v1.0.0"},
		{"/example.com/foo/bar/@latest", `"v1.1.0"`},
		{"/example.com/foo/bar/@v/v1.0.0.info", `"Version":"v1.0.0"`}, // missing -> fetched -> served
	}
	for _, c := range cases {
		code, body := httpGet(t, srv.URL+c.path)
		if code != http.StatusOK {
			t.Errorf("GET %s: status %d", c.path, code)
		}
		if !strings.Contains(body, c.wantSub) {
			t.Errorf("GET %s: body %q missing %q", c.path, body, c.wantSub)
		}
	}

	// The @latest and .info requests above recorded two modules; export them.
	resp, err := http.Post(srv.URL+"/admin/export", "", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /admin/export: status %d", resp.StatusCode)
	}
	if code, _ := httpGet(t, srv.URL+"/admin/bundles"); code != http.StatusOK {
		t.Errorf("GET /admin/bundles: status %d", code)
	}
}

func TestLowServerExportAndReexport(t *testing.T) {
	ls, priv := newFakeLowServer(t)
	ctx := context.Background()
	ls.recordRequest("example.com/foo/bar", "v1.0.0")

	res, err := ls.ExportPending(ctx)
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
	rr, err := ls.HandleReexportRequest(ctx, r)
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

	// A second collect advances the sequence rather than reusing it.
	res2, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.BundleID != "go-bundle-000002" {
		t.Errorf("second collect bundle = %s, want go-bundle-000002", res2.BundleID)
	}

	// An empty module list is rejected.
	if _, err := ls.CollectGo(ctx, GoCollectRequest{}); err == nil {
		t.Error("empty CollectGo should error")
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
	ls.recordRequest("example.com/foo/bar", "v1.0.0")
	if _, err := ls.ExportPending(ctx); err != nil {
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
	if !res.Imported || res.Sequence != 1 {
		t.Fatalf("unexpected high import result: %+v", res)
	}
	if !hs.isComplete("example.com/foo/bar", "v1.0.0") {
		t.Error("module not complete on high side after pipeline")
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	if code, body := httpGet(t, srv.URL+"/example.com/foo/bar/@v/list"); code != http.StatusOK || !strings.Contains(body, "v1.0.0") {
		t.Errorf("high list after pipeline: status %d body %q", code, body)
	}
}
