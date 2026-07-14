package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if !strings.Contains(strings.Join(plain, " "), "--only-binary=:all:") {
		t.Errorf("plain request must enforce wheels-only: %v", plain)
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

func TestPythonRejectsOnlyBinaryFalse(t *testing.T) {
	no := false
	err := validatePythonRequest(PythonCollectRequest{
		Requirements: []string{"requests"},
		Target:       &PythonTarget{OnlyBinary: &no},
	})
	if err == nil || !strings.Contains(err.Error(), "wheels-only") {
		t.Fatalf("only_binary=false validation = %v, want wheels-only error", err)
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
	files, projects, _, err := collectPythonDist(dest)
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
	if err := createTarGzAtomic(context.Background(), filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
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
	t.Cleanup(func() { _ = ls.Close() })
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
	if res.BundleID != "python-bundle-000001" || res.ExportedModules != 2 {
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
	if res.BundleID != "python-bundle-000001" || res.ExportedModules != 2 {
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

func TestValidatePipArg(t *testing.T) {
	valid := []string{
		"requests",
		"requests==2.32.4",
		"urllib3>=1.26,<2",
		"flask[async]",
		`requests; python_version < "3.9"`, // PEP 508 marker, contains spaces
	}
	invalid := []string{
		"",
		"   ",
		"-r/etc/passwd",
		"--index-url=http://attacker.example/simple",
		"-e.",
		"pkg\nname", // control character
	}
	for _, r := range valid {
		if err := validatePipArg("requirement", r); err != nil {
			t.Errorf("validatePipArg(%q) = %v, want nil", r, err)
		}
	}
	for _, r := range invalid {
		if err := validatePipArg("requirement", r); err == nil {
			t.Errorf("validatePipArg(%q) = nil, want error", r)
		}
	}
}

// TestCollectPythonRejectsFlagInjection proves a flag-like requirement is
// rejected before pip is ever invoked, so it cannot be reparsed as a pip option
// (e.g. redirecting the index or reading a file as a requirements list).
func TestCollectPythonRejectsFlagInjection(t *testing.T) {
	ls, _ := newPyLowServer(t)
	_, err := ls.CollectPython(context.Background(), PythonCollectRequest{
		Requirements: []string{"--index-url=http://attacker.example/simple", "evilpkg"},
	})
	if err == nil {
		t.Fatal("CollectPython accepted a flag-like requirement")
	}
	if !strings.Contains(err.Error(), "'-'") {
		t.Errorf("error should explain the flag rejection, got: %v", err)
	}
}

// TestHighServerSimpleEscapesHTML proves the PEP 503 pages HTML-escape package
// and wheel names, so a crafted filename that crossed the diode cannot inject
// script into an operator's browser.
func TestHighServerSimpleEscapesHTML(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// A wheel whose filename carries HTML metacharacters. It must still parse as
	// a wheel so it reaches the /simple/ pages.
	name := `x"><xss>-1.0-py3-none-any.whl`
	if _, _, ok := parseWheelFilename(name); !ok {
		t.Fatalf("test wheel name did not parse as a wheel: %q", name)
	}
	if err := os.MkdirAll(hs.pythonDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hs.pythonDir(), name), []byte("wheel-bytes"))
	project := normalizePyName(`x"><xss>`)

	srv := httptest.NewServer(hs)
	defer srv.Close()

	for _, p := range []string{"/simple/", "/simple/" + url.PathEscape(project) + "/"} {
		code, body := httpGet(t, srv.URL+p)
		if code != http.StatusOK {
			t.Fatalf("GET %s status %d", p, code)
		}
		if strings.Contains(body, "<xss>") {
			t.Errorf("GET %s echoed an unescaped tag from a crafted name:\n%s", p, body)
		}
		if !strings.Contains(body, "&lt;xss&gt;") {
			t.Errorf("GET %s did not HTML-escape the crafted name:\n%s", p, body)
		}
	}
}

func TestParseSdistFilename(t *testing.T) {
	tests := []struct {
		filename, name, version string
		ok                      bool
	}{
		{"legacypkg-1.0.0.tar.gz", "legacypkg", "1.0.0", true},
		{"My_Pkg-2.3.tar.gz", "my-pkg", "2.3", true},                                 // normalized name
		{"django-rest-framework-3.14.tar.gz", "django-rest-framework", "3.14", true}, // hyphenated name
		{"foo-1.0.zip", "foo", "1.0", true},
		{"bar-3.1.4.tar.bz2", "bar", "3.1.4", true},
		{"requests-2.32.4-py3-none-any.whl", "", "", false}, // a wheel, not an sdist
		{"noextension", "", "", false},
	}
	for _, tt := range tests {
		name, version, ok := parseSdistFilename(tt.filename)
		if ok != tt.ok || name != tt.name || version != tt.version {
			t.Errorf("parseSdistFilename(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.filename, name, version, ok, tt.name, tt.version, tt.ok)
		}
	}
}

// fakePipMixedScript writes one wheel and one source distribution, simulating a
// requirements set where a package publishes only an sdist.
const fakePipMixedScript = `#!/usr/bin/env bash
set -eu
dest=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dest" ]; then dest="$a"; fi
  prev="$a"
done
mkdir -p "$dest"
printf 'wheel-requests' > "$dest/requests-2.32.4-py3-none-any.whl"
printf 'sdist-legacy'   > "$dest/legacypkg-1.0.0.tar.gz"
`

// fakePipSdistOnlyScript writes only a source distribution (no wheel at all).
const fakePipSdistOnlyScript = `#!/usr/bin/env bash
set -eu
dest=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dest" ]; then dest="$a"; fi
  prev="$a"
done
mkdir -p "$dest"
printf 'sdist-only' > "$dest/onlysdist-2.0.0.tar.gz"
`

func newPyLowServerWithPip(t *testing.T, script string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake pip shell script is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for fake pip script")
	}
	_, priv := newTestKeys(t)
	pip := filepath.Join(t.TempDir(), "pip")
	if err := os.WriteFile(pip, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), PipBinary: pip}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// TestCollectPythonReportsUnexpectedSdists is defense in depth for a broken or
// replaced pip executable that ignores --only-binary: unexpected sdists are
// never bundled, while any wheels it produced remain usable.
func TestCollectPythonReportsUnexpectedSdists(t *testing.T) {
	ls, _ := newPyLowServerWithPip(t, fakePipMixedScript)

	res, err := ls.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"requests", "legacypkg"}})
	if err != nil {
		t.Fatalf("CollectPython: %v", err)
	}
	if res.BundleID != "python-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("expected the one wheel bundled, got %+v", res)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "legacypkg" || res.SkippedModules[0].Version != "1.0.0" {
		t.Fatalf("expected legacypkg reported as skipped, got %+v", res.SkippedModules)
	}
}

// TestCollectPythonAllSdistsFails proves a requirements set with no wheels at
// all fails with a clear source-distribution message and burns no sequence.
func TestCollectPythonAllSdistsFails(t *testing.T) {
	ls, _ := newPyLowServerWithPip(t, fakePipSdistOnlyScript)

	_, err := ls.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"onlysdist"}})
	if err == nil || !strings.Contains(err.Error(), "source distribution") {
		t.Fatalf("expected a source-distribution error, got %v", err)
	}
	if seq := ls.peekSequence(streamPython); seq != 1 {
		t.Errorf("failed collect burned a sequence: next = %d, want 1", seq)
	}
}

// writeWheelZip writes a real (zip) wheel at path with the given entries.
func writeWheelZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, buf.Bytes())
}

// wheelMetadata renders a minimal core-metadata header block with an optional
// Requires-Python header, followed by a description body whose look-alike
// header must never be picked up.
func wheelMetadata(requiresPython string) string {
	m := "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
	if requiresPython != "" {
		m += "Requires-Python: " + requiresPython + "\n"
	}
	return m + "\nDescription body\nRequires-Python: from-the-body\n"
}

func TestWheelRequiresPython(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		entries map[string]string
		want    string
	}{
		{"header present", map[string]string{
			"demo/__init__.py":            "",
			"demo-1.0.dist-info/METADATA": wheelMetadata(">=3.9"),
		}, ">=3.9"},
		{"no header", map[string]string{"demo-1.0.dist-info/METADATA": wheelMetadata("")}, ""},
		{"lowercase and CRLF", map[string]string{
			"demo-1.0.dist-info/METADATA": "name: demo\r\nrequires-python: >=3.8, <4\r\n\r\nbody\r\n",
		}, ">=3.8, <4"},
		{"nested dist-info ignored", map[string]string{"sub/demo-1.0.dist-info/METADATA": wheelMetadata(">=3.9")}, ""},
	}
	for _, tt := range tests {
		p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+"-1.0-py3-none-any.whl")
		writeWheelZip(t, p, tt.entries)
		if got := wheelRequiresPython(p); got != tt.want {
			t.Errorf("%s: wheelRequiresPython = %q, want %q", tt.name, got, tt.want)
		}
	}

	notZip := filepath.Join(dir, "bad-1.0-py3-none-any.whl")
	writeFile(t, notZip, []byte("not a zip"))
	if got := wheelRequiresPython(notZip); got != "" {
		t.Errorf("non-zip wheel = %q, want empty", got)
	}
	if got := wheelRequiresPython(filepath.Join(dir, "absent.whl")); got != "" {
		t.Errorf("missing wheel = %q, want empty", got)
	}
}

func TestNegotiatePySimple(t *testing.T) {
	tests := []struct{ accept, want string }{
		{"", pySimpleLegacyType},
		{"text/html", pySimpleLegacyType},
		{"*/*", pySimpleLegacyType},
		{"text/*", pySimpleLegacyType},
		// pip's real Accept header prefers JSON.
		{"application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01", pySimpleJSONType},
		{"application/vnd.pypi.simple.v1+json", pySimpleJSONType},
		{"application/vnd.pypi.simple.v1+html", pySimpleHTMLType},
		{"application/vnd.pypi.simple.v1+json;q=0.2, text/html;q=0.9", pySimpleLegacyType},
		{"application/vnd.pypi.simple.v1+json;q=0", pySimpleLegacyType}, // q=0 is never selected
		{"application/json", pySimpleLegacyType},                        // unknown type falls back
		{"Application/VND.PyPI.Simple.V1+JSON", pySimpleJSONType},       // media type is case-insensitive
	}
	for _, tt := range tests {
		if got := negotiatePySimple(tt.accept); got != tt.want {
			t.Errorf("negotiatePySimple(%q) = %q, want %q", tt.accept, got, tt.want)
		}
	}
}

// httpGetAccept is httpGet with an Accept request header; it also returns the
// response Content-Type.
func httpGetAccept(t *testing.T, rawURL, accept string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil) //nolint:noctx // short-lived test request
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", accept)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body), resp.Header.Get("Content-Type")
}

// pipJSONAccept is the Accept header current pip sends to the Simple API.
const pipJSONAccept = "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01"

// TestPySimpleRequiresPythonAndJSON proves the project page carries each
// wheel's Requires-Python (PEP 503 data-requires-python, HTML-escaped) and
// that the PEP 691 JSON representations are served under content negotiation,
// with hashes and metadata read from the verified artifacts on disk.
func TestPySimpleRequiresPythonAndJSON(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if err := os.MkdirAll(hs.pythonDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	writeWheelZip(t, filepath.Join(hs.pythonDir(), "demo-1.0-py3-none-any.whl"),
		map[string]string{"demo-1.0.dist-info/METADATA": wheelMetadata(">=3.9")})
	writeFile(t, filepath.Join(hs.pythonDir(), "plain-2.0-py3-none-any.whl"), []byte("not-a-zip"))

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// PEP 503 HTML: Requires-Python is emitted HTML-escaped on the anchor.
	code, body := httpGet(t, srv.URL+"/simple/demo/")
	if code != http.StatusOK || !strings.Contains(body, ` data-requires-python="&gt;=3.9"`) {
		t.Errorf("HTML project page missing data-requires-python: status %d body %q", code, body)
	}
	// A wheel without readable metadata omits the attribute.
	code, body = httpGet(t, srv.URL+"/simple/plain/")
	if code != http.StatusOK || strings.Contains(body, "data-requires-python") {
		t.Errorf("metadata-less wheel must omit the attribute: status %d body %q", code, body)
	}

	assertPySimpleProjectJSON(t, hs, srv.URL)

	// JSON root index lists both projects.
	code, body, contentType := httpGetAccept(t, srv.URL+"/simple/", pipJSONAccept)
	if code != http.StatusOK || contentType != pySimpleJSONType {
		t.Fatalf("JSON root: status %d content-type %q", code, contentType)
	}
	var root pySimpleRoot
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatal(err)
	}
	if root.Meta.APIVersion != "1.0" || len(root.Projects) != 2 ||
		root.Projects[0].Name != "demo" || root.Projects[1].Name != "plain" {
		t.Errorf("JSON root = %+v", root)
	}

	// The versioned HTML type is honored when the client prefers it.
	code, body, contentType = httpGetAccept(t, srv.URL+"/simple/demo/", pySimpleHTMLType)
	if code != http.StatusOK || contentType != pySimpleHTMLType || !strings.Contains(body, "data-requires-python") {
		t.Errorf("versioned HTML: status %d content-type %q body %q", code, contentType, body)
	}
}

// assertPySimpleProjectJSON checks the PEP 691 project page for the demo
// wheel, decoding into a generic map so the exact JSON key spelling
// (api-version, requires-python, hashes.sha256) is verified.
func assertPySimpleProjectJSON(t *testing.T, hs *HighServer, baseURL string) {
	t.Helper()
	code, body, contentType := httpGetAccept(t, baseURL+"/simple/demo/", pipJSONAccept)
	if code != http.StatusOK || contentType != pySimpleJSONType {
		t.Fatalf("JSON project page: status %d content-type %q", code, contentType)
	}
	var page map[string]any
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("JSON project page did not parse: %v\n%s", err, body)
	}
	if meta, _ := page["meta"].(map[string]any); meta["api-version"] != "1.0" {
		t.Errorf("meta = %v, want api-version 1.0", page["meta"])
	}
	if page["name"] != "demo" {
		t.Errorf("name = %v, want demo", page["name"])
	}
	files, _ := page["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("files = %v, want one entry", page["files"])
	}
	file, _ := files[0].(map[string]any)
	if file["filename"] != "demo-1.0-py3-none-any.whl" || file["url"] != "/packages/demo-1.0-py3-none-any.whl" {
		t.Errorf("file identity = %v", file)
	}
	wantSum, err := sha256File(filepath.Join(hs.pythonDir(), "demo-1.0-py3-none-any.whl"))
	if err != nil {
		t.Fatal(err)
	}
	if hashes, _ := file["hashes"].(map[string]any); hashes["sha256"] != wantSum {
		t.Errorf("hashes = %v, want sha256 %s", file["hashes"], wantSum)
	}
	if file["requires-python"] != ">=3.9" {
		t.Errorf("requires-python = %v, want >=3.9", file["requires-python"])
	}
	if _, ok := file["yanked"]; ok {
		t.Errorf("yanked must be omitted, got %v", file["yanked"])
	}
}

// TestCollectPythonDistRequiresPython proves the collect step records each
// wheel's Requires-Python in the manifest's project entries.
func TestCollectPythonDistRequiresPython(t *testing.T) {
	dest := t.TempDir()
	writeWheelZip(t, filepath.Join(dest, "demo-1.0-py3-none-any.whl"),
		map[string]string{"demo-1.0.dist-info/METADATA": wheelMetadata(">=3.10")})
	_, projects, _, err := collectPythonDist(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || len(projects[0].Files) != 1 {
		t.Fatalf("unexpected projects: %+v", projects)
	}
	if got := projects[0].Files[0].RequiresPython; got != ">=3.10" {
		t.Errorf("manifest RequiresPython = %q, want %q", got, ">=3.10")
	}
}
