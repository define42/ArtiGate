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
	"time"
)

func TestNormalizePyName(t *testing.T) {
	tests := map[string]string{
		"My_Package":  "my-package",
		"my.package":  "my-package",
		"my-package":  "my-package",
		"Flask":       "flask",
		"zope.event":  "zope-event",
		"a__b--c..d":  "a-b-c-d",
		"ruamel.yaml": "ruamel-yaml",
	}
	for in, want := range tests {
		if got := normalizePyName(in); got != want {
			t.Errorf("normalizePyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWheelFilename(t *testing.T) {
	tests := []struct {
		filename string
		project  string
		version  string
		ok       bool
	}{
		{"requests-2.32.4-py3-none-any.whl", "requests", "2.32.4", true},
		{"urllib3-2.5.0-py3-none-any.whl", "urllib3", "2.5.0", true},
		{"numpy-2.1.0-cp312-cp312-manylinux_2_28_x86_64.whl", "numpy", "2.1.0", true},
		{"My_Pkg-1.0-1-py3-none-any.whl", "my-pkg", "1.0", true}, // build tag present
		{"requests-2.32.4.tar.gz", "", "", false},                // sdist, not a wheel
		{"broken.whl", "", "", false},                            // too few components
	}
	for _, tt := range tests {
		project, version, ok := parseWheelFilename(tt.filename)
		if ok != tt.ok || project != tt.project || version != tt.version {
			t.Errorf("parseWheelFilename(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.filename, project, version, ok, tt.project, tt.version, tt.ok)
		}
	}
}

func TestValidatePythonProjects(t *testing.T) {
	seen := map[string]bool{"python/packages/requests-2.32.4-py3-none-any.whl": true}
	good := []PythonProject{{
		Name: "requests", NormalizedName: "requests", Version: "2.32.4",
		Files: []PythonFile{{Filename: "requests-2.32.4-py3-none-any.whl", Path: "python/packages/requests-2.32.4-py3-none-any.whl", SHA256: strings.Repeat("a", 64)}},
	}}
	if err := validatePythonProjects(good, seen); err != nil {
		t.Errorf("valid projects rejected: %v", err)
	}

	bad := []struct {
		name     string
		projects []PythonProject
	}{
		{"missing version", []PythonProject{{NormalizedName: "x"}}},
		{"no files", []PythonProject{{NormalizedName: "x", Version: "1.0"}}},
		{"unlisted file", []PythonProject{{NormalizedName: "x", Version: "1.0", Files: []PythonFile{{Path: "python/packages/other.whl"}}}}},
	}
	for _, tt := range bad {
		if err := validatePythonProjects(tt.projects, seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

func TestPipDownloadArgs(t *testing.T) {
	plain := pipDownloadArgs("/dest", PythonCollectRequest{Requirements: []string{"requests"}})
	if strings.Contains(strings.Join(plain, " "), "--only-binary") {
		t.Errorf("plain request should not force --only-binary: %v", plain)
	}
	if plain[len(plain)-1] != "requests" {
		t.Errorf("requirement not appended last: %v", plain)
	}

	targeted := pipDownloadArgs("/dest", PythonCollectRequest{
		Requirements: []string{"numpy"},
		Target: &PythonTarget{
			PythonVersion: "3.12", Implementation: "cp", ABI: "cp312",
			Platforms: []string{"manylinux_2_28_x86_64"},
		},
	})
	joined := strings.Join(targeted, " ")
	for _, want := range []string{"--only-binary=:all:", "--python-version 3.12", "--implementation cp", "--abi cp312", "--platform manylinux_2_28_x86_64"} {
		if !strings.Contains(joined, want) {
			t.Errorf("targeted args missing %q: %v", want, targeted)
		}
	}
}

// writeSignedPythonBundle builds a signed Python wheel bundle in landing,
// reusing the production collect/tar/sign helpers.
func writeSignedPythonBundle(t *testing.T, landing string, priv ed25519.PrivateKey, seq, prevSeq int64, wheels map[string]string) {
	t.Helper()
	src := t.TempDir()
	dest := filepath.Join(src, "python", "packages")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range wheels {
		writeFile(t, filepath.Join(dest, name), []byte(content))
	}
	files, projects, err := collectPythonDist(dest)
	if err != nil {
		t.Fatal(err)
	}

	bundleID := bundleIDForSequence(seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: prevSeq,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Ecosystems:       []string{"python"},
		Python:           &PythonManifest{Projects: projects},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestBytes)

	if err := os.MkdirAll(landing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createTarGzAtomic(filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json"), manifestBytes)
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
}

func TestHighServerPythonImportAndServe(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 1, 0, map[string]string{
		"requests-2.32.4-py3-none-any.whl": "wheel-requests",
		"urllib3-2.5.0-py3-none-any.whl":   "wheel-urllib3",
	})

	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("ImportNext: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Root simple index lists both normalized projects.
	code, body := httpGet(t, srv.URL+"/simple/")
	if code != http.StatusOK || !strings.Contains(body, `/simple/requests/`) || !strings.Contains(body, `/simple/urllib3/`) {
		t.Fatalf("simple root: status %d body %q", code, body)
	}

	// Project page links the wheel with a sha256 fragment.
	code, body = httpGet(t, srv.URL+"/simple/requests/")
	if code != http.StatusOK {
		t.Fatalf("project page status %d", code)
	}
	if !strings.Contains(body, "/packages/requests-2.32.4-py3-none-any.whl#sha256=") {
		t.Errorf("project page missing hashed link: %q", body)
	}

	// The wheel itself is downloadable and its bytes are intact.
	code, body = httpGet(t, srv.URL+"/packages/requests-2.32.4-py3-none-any.whl")
	if code != http.StatusOK || body != "wheel-requests" {
		t.Errorf("wheel download: status %d body %q", code, body)
	}

	// Name normalization: a non-normalized request resolves to the project.
	if code, _ := httpGet(t, srv.URL+"/simple/Requests/"); code != http.StatusOK {
		t.Errorf("normalized lookup /simple/Requests/ status %d, want 200", code)
	}
	// Unknown project 404s.
	if code, _ := httpGet(t, srv.URL+"/simple/nope/"); code != http.StatusNotFound {
		t.Errorf("unknown project status %d, want 404", code)
	}
	// Path traversal on /packages/ is rejected.
	if code, _ := httpGet(t, srv.URL+"/packages/..%2f..%2fetc"); code == http.StatusOK {
		t.Error("traversal path should not succeed")
	}
}

const fakePipScript = `#!/usr/bin/env bash
set -eu
dest=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dest" ]; then dest="$a"; fi
  prev="$a"
done
mkdir -p "$dest"
printf 'wheel-requests' > "$dest/requests-2.32.4-py3-none-any.whl"
printf 'wheel-urllib3'  > "$dest/urllib3-2.5.0-py3-none-any.whl"
`

func writeFakePip(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake pip shell script is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for fake pip script")
	}
	p := filepath.Join(t.TempDir(), "pip")
	if err := os.WriteFile(p, []byte(fakePipScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newPyLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:      t.TempDir(),
		ExportDir: filepath.Join(t.TempDir(), "out"),
		PipBinary: writeFakePip(t),
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	return ls, priv
}

func TestLowServerPythonCollectAdmin(t *testing.T) {
	ls, _ := newPyLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	body := strings.NewReader(`{"requirements":["requests"]}`)
	resp, err := http.Post(srv.URL+"/admin/python/collect", "application/json", body) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("collect admin status = %d, want 200", resp.StatusCode)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "go-bundle-000001" || res.ExportedModules != 2 {
		t.Errorf("unexpected collect result: %+v", res)
	}

	// An empty requirements list is rejected with 400.
	bad, err := http.Post(srv.URL+"/admin/python/collect", "application/json", strings.NewReader(`{}`)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("empty collect status = %d, want 400", bad.StatusCode)
	}
}

func TestLowToHighPythonPipeline(t *testing.T) {
	ls, priv := newPyLowServer(t)
	res, err := ls.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"requests"}})
	if err != nil {
		t.Fatalf("CollectPython: %v", err)
	}
	if res.BundleID != "go-bundle-000001" || res.ExportedModules != 2 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	// Deliver the low-produced bundle to a high server.
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
		t.Fatalf("high import of python bundle failed: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()
	code, body := httpGet(t, srv.URL+"/simple/")
	if code != http.StatusOK || !strings.Contains(body, "requests") || !strings.Contains(body, "urllib3") {
		t.Errorf("pipeline simple index: status %d body %q", code, body)
	}
	if code, body := httpGet(t, srv.URL+"/packages/urllib3-2.5.0-py3-none-any.whl"); code != http.StatusOK || body != "wheel-urllib3" {
		t.Errorf("pipeline wheel download: status %d body %q", code, body)
	}
}
