package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Unit: spec parsing, platforms, version validation
// -----------------------------------------------------------------------------

func TestTerraformParseProviderSpec(t *testing.T) {
	good := []struct {
		spec             string
		ns, typ, version string
	}{
		{"hashicorp/null@3.2.2", "hashicorp", "null", "3.2.2"},
		{"hashicorp/null", "hashicorp", "null", ""},
		{"hashicorp/null@latest", "hashicorp", "null", ""},
		{"My-Org.io/type_x@1.0.0-beta.1+meta", "My-Org.io", "type_x", "1.0.0-beta.1+meta"},
	}
	for _, tt := range good {
		got, err := parseTfProviderSpec(tt.spec)
		if err != nil {
			t.Errorf("parseTfProviderSpec(%q) = %v, want nil", tt.spec, err)
			continue
		}
		if got.ns != tt.ns || got.typ != tt.typ || got.version != tt.version {
			t.Errorf("parseTfProviderSpec(%q) = %+v, want {%s %s %s}", tt.spec, got, tt.ns, tt.typ, tt.version)
		}
	}
	bad := []string{
		"", "null", "a/b/c", "hashicorp/", "/null", "-ns/null", ".ns/null", "_ns/null",
		"ns/-type", "ns/nu ll", "ns/null@v1.0.0", "ns/null@^1.0", "ns/null@..",
		"ns/null@1.0.0/..", strings.Repeat("a", 129) + "/null",
	}
	for _, spec := range bad {
		if _, err := parseTfProviderSpec(spec); err == nil {
			t.Errorf("parseTfProviderSpec(%q) = nil, want error", spec)
		}
	}
}

func TestTerraformParseModuleSpec(t *testing.T) {
	good := []struct {
		spec                      string
		ns, name, system, version string
	}{
		{"terraform-aws-modules/vpc/aws@5.8.1", "terraform-aws-modules", "vpc", "aws", "5.8.1"},
		{"org/vpc/aws", "org", "vpc", "aws", ""},
		{"org/vpc/aws@latest", "org", "vpc", "aws", ""},
	}
	for _, tt := range good {
		got, err := parseTfModuleSpec(tt.spec)
		if err != nil {
			t.Errorf("parseTfModuleSpec(%q) = %v, want nil", tt.spec, err)
			continue
		}
		if got.ns != tt.ns || got.name != tt.name || got.system != tt.system || got.version != tt.version {
			t.Errorf("parseTfModuleSpec(%q) = %+v, want {%s %s %s %s}", tt.spec, got, tt.ns, tt.name, tt.system, tt.version)
		}
	}
	bad := []string{
		"", "vpc", "org/vpc", "org/vpc/aws/extra", "org//aws", ".org/vpc/aws",
		"org/vpc/-aws", "org/v pc/aws", "org/vpc/aws@bad", "org/vpc/aws@..",
	}
	for _, spec := range bad {
		if _, err := parseTfModuleSpec(spec); err == nil {
			t.Errorf("parseTfModuleSpec(%q) = nil, want error", spec)
		}
	}
}

func TestTerraformPlatforms(t *testing.T) {
	got, err := tfPlatforms(TerraformCollectRequest{})
	if err != nil || len(got) != 1 || got[0] != [2]string{"linux", "amd64"} {
		t.Errorf("default platforms = %v, %v; want [[linux amd64]]", got, err)
	}
	got, err = tfPlatforms(TerraformCollectRequest{Platforms: []string{"linux_amd64", "darwin_arm64", "linux_amd64"}})
	if err != nil || len(got) != 2 || got[0] != [2]string{"linux", "amd64"} || got[1] != [2]string{"darwin", "arm64"} {
		t.Errorf("explicit platforms = %v, %v; want deduped [[linux amd64] [darwin arm64]]", got, err)
	}
	for _, bad := range []string{"linuxamd64", "_amd64", "linux_", "linux/amd64", "linux__amd64", "linux amd64"} {
		if _, err := tfPlatforms(TerraformCollectRequest{Platforms: []string{bad}}); err == nil {
			t.Errorf("tfPlatforms(%q) = nil, want error", bad)
		}
	}
}

func TestTerraformValidateVersion(t *testing.T) {
	valid := []string{"1.0.0", "0.0.1", "2024.1.10-rc.1+build.5", "1"}
	invalid := []string{"", "latest", "v1.0.0", "-1.0", ".1", "1.0.0/..", "1 0", "1.0.0\n2"}
	for _, v := range valid {
		if err := validateTfVersion(v); err != nil {
			t.Errorf("validateTfVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalid {
		if err := validateTfVersion(v); err == nil {
			t.Errorf("validateTfVersion(%q) = nil, want error", v)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: SHA256SUMS parsing, git source splitting, X-Terraform-Get resolution
// -----------------------------------------------------------------------------

func TestTerraformParseSHA256SUMS(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.ToUpper(strings.Repeat("b1", 32))
	text := digestA + "  one.zip\n" +
		digestB + " *two.zip\n" + // "*name" marks binary mode in coreutils sums
		"not a sums line\n" +
		"deadbeef  short-digest.zip\n" + // digest not 64 hex chars: ignored
		digestA + "  three  parts\n" + // three fields: ignored
		"\n"
	got := parseSHA256SUMS(text)
	if len(got) != 2 {
		t.Fatalf("parseSHA256SUMS kept %d entries, want 2: %v", len(got), got)
	}
	if got["one.zip"] != digestA {
		t.Errorf("one.zip = %q, want %q", got["one.zip"], digestA)
	}
	if got["two.zip"] != strings.ToLower(digestB) {
		t.Errorf("two.zip = %q, want lowercased %q", got["two.zip"], digestB)
	}
}

func TestTerraformSplitGitSource(t *testing.T) {
	good := []struct {
		in, repo, subdir, ref string
	}{
		{"https://host.example/org/repo//sub/dir?ref=v1.2.3", "https://host.example/org/repo", "sub/dir", "v1.2.3"},
		{"https://host.example/org/repo?ref=abc123", "https://host.example/org/repo", "", "abc123"},
		{"https://host.example/org/repo", "https://host.example/org/repo", "", ""},
		{"https://host.example/org/repo//sub/", "https://host.example/org/repo", "sub", ""},
		{"http://host.example/repo.git//modules/x?ref=main", "http://host.example/repo.git", "modules/x", "main"},
	}
	for _, tt := range good {
		repo, subdir, ref, err := splitGitSource(tt.in)
		if err != nil {
			t.Errorf("splitGitSource(%q) = %v, want nil", tt.in, err)
			continue
		}
		if repo != tt.repo || subdir != tt.subdir || ref != tt.ref {
			t.Errorf("splitGitSource(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.in, repo, subdir, ref, tt.repo, tt.subdir, tt.ref)
		}
	}
	for _, in := range []string{"", "ssh://git@host/repo?ref=x", "git@github.com:org/repo.git", "file:///etc"} {
		if _, _, _, err := splitGitSource(in); err == nil {
			t.Errorf("splitGitSource(%q) = nil, want error (only http(s) remotes)", in)
		}
	}
}

func TestTerraformResolveTfGet(t *testing.T) {
	dl := "https://reg.example/v1/modules/org/vpc/aws/1.0.0/download"
	tests := []struct{ got, want string }{
		{"https://cdn.example/archive.tar.gz", "https://cdn.example/archive.tar.gz"},            // absolute passthrough
		{"git::https://host/repo//sub?ref=v1", "git::https://host/repo//sub?ref=v1"},            // scheme-prefixed passthrough
		{"./archive.tar.gz", "https://reg.example/v1/modules/org/vpc/aws/1.0.0/archive.tar.gz"}, // sibling
		{"/x", "https://reg.example/x"},                                          // host-absolute
		{"../up.tar.gz", "https://reg.example/v1/modules/org/vpc/aws/up.tar.gz"}, // parent
	}
	for _, tt := range tests {
		got, err := resolveTfGet(dl, tt.got)
		if err != nil || got != tt.want {
			t.Errorf("resolveTfGet(%q) = %q, %v; want %q", tt.got, got, err, tt.want)
		}
	}
}

func TestTerraformMergePlatforms(t *testing.T) {
	prev := []TerraformPlatform{{OS: "linux", Arch: "amd64", SHA256: "old"}}
	next := []TerraformPlatform{
		{OS: "linux", Arch: "amd64", SHA256: "new"},
		{OS: "darwin", Arch: "arm64", SHA256: "mac"},
	}
	got := mergeTfPlatforms(prev, next)
	if len(got) != 2 {
		t.Fatalf("merged platforms = %+v, want 2", got)
	}
	if got[0].OS != "darwin" || got[1].OS != "linux" { // sorted by os_arch key
		t.Errorf("merge order = %+v, want darwin before linux", got)
	}
	if got[1].SHA256 != "new" { // the newer record wins per os/arch
		t.Errorf("linux/amd64 merged to %+v, want the newer record", got[1])
	}
}

// -----------------------------------------------------------------------------
// Unit: manifest validation
// -----------------------------------------------------------------------------

// tfTestCanonicalRecords builds a provider and a module record with the exact
// canonical repository paths, plus the manifest.files set covering them (the
// zip's files entry carrying the same SHA-256 the platform record declares).
func tfTestCanonicalRecords() (TerraformProvider, TerraformModule, map[string]bool, []ManifestFile) {
	dir := tfProviderDir("hashicorp", "null", "1.0.0")
	zipName := tfProviderZipName("null", "1.0.0", "linux", "amd64")
	sums := path.Join(dir, "terraform-provider-null_1.0.0_SHA256SUMS")
	p := TerraformProvider{
		Namespace: "hashicorp", Type: "null", Version: "1.0.0",
		Platforms: []TerraformPlatform{{
			OS: "linux", Arch: "amd64", Filename: zipName,
			Path: path.Join(dir, zipName), SHA256: strings.Repeat("a", 64),
		}},
		SHASumsPath:    sums,
		SHASumsSigPath: sums + ".sig",
		KeysPath:       path.Join(dir, "signing_keys.json"),
	}
	mod := TerraformModule{
		Namespace: "org", Name: "vpc", System: "aws", Version: "2.0.0",
		Path: tfModuleRel("org", "vpc", "aws", "2.0.0"), SHA256: strings.Repeat("b", 64),
	}
	files := []ManifestFile{
		{Path: p.Platforms[0].Path, SHA256: p.Platforms[0].SHA256, Size: 1},
		{Path: p.SHASumsPath, SHA256: strings.Repeat("c", 64), Size: 1},
		{Path: p.SHASumsSigPath, SHA256: strings.Repeat("d", 64), Size: 1},
		{Path: p.KeysPath, SHA256: strings.Repeat("e", 64), Size: 1},
		{Path: mod.Path, SHA256: mod.SHA256, Size: 1},
	}
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		seen[f.Path] = true
	}
	return p, mod, seen, files
}

func TestTerraformValidateManifest(t *testing.T) {
	if err := validateTerraformManifest(&TerraformManifest{}, map[string]bool{}, nil); err != nil {
		t.Errorf("empty manifest rejected: %v", err)
	}
	p, mod, seen, files := tfTestCanonicalRecords()
	if p.Platforms[0].Path != "terraform/providers/hashicorp/null/1.0.0/terraform-provider-null_1.0.0_linux_amd64.zip" {
		t.Fatalf("canonical zip path helper drifted: %s", p.Platforms[0].Path)
	}
	if mod.Path != "terraform/modules/org/vpc/aws/2.0.0/module.tar.gz" {
		t.Fatalf("canonical module path helper drifted: %s", mod.Path)
	}
	m := &TerraformManifest{Providers: []TerraformProvider{p}, Modules: []TerraformModule{mod}}
	if err := validateTerraformManifest(m, seen, files); err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	// The shasum cross-check is case-insensitive (upstream registries list
	// hex digests in either case).
	m.Providers[0].Platforms[0].SHA256 = strings.ToUpper(m.Providers[0].Platforms[0].SHA256)
	if err := validateTerraformManifest(m, seen, files); err != nil {
		t.Fatalf("uppercase platform shasum rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(p *TerraformProvider, mod *TerraformModule, seen map[string]bool)
	}{
		{"non-canonical zip filename", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Platforms[0].Filename = "renamed.zip"
		}},
		{"zip path not listed in files", func(p *TerraformProvider, _ *TerraformModule, seen map[string]bool) {
			delete(seen, p.Platforms[0].Path)
		}},
		{"SHA256SUMS path not listed in files", func(p *TerraformProvider, _ *TerraformModule, seen map[string]bool) {
			delete(seen, p.SHASumsPath)
		}},
		{"non-canonical SHA256SUMS path", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.SHASumsPath = "terraform/providers/hashicorp/null/1.0.0/SUMS"
		}},
		{"non-canonical signature path", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.SHASumsSigPath = p.SHASumsPath
		}},
		{"signing keys not listed in files", func(p *TerraformProvider, _ *TerraformModule, seen map[string]bool) {
			delete(seen, p.KeysPath)
		}},
		{"no platforms", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Platforms = nil
		}},
		{"platform shasum differs from the delivered file", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Platforms[0].SHA256 = strings.Repeat("f", 64)
		}},
		{"empty platform shasum", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Platforms[0].SHA256 = ""
		}},
		{"traversal namespace", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Namespace = "../etc"
		}},
		{"bad provider version", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Version = "v1.0.0"
		}},
		{"bad platform os", func(p *TerraformProvider, _ *TerraformModule, _ map[string]bool) {
			p.Platforms[0].OS = ".."
		}},
		{"module path wrong", func(_ *TerraformProvider, mod *TerraformModule, _ map[string]bool) {
			mod.Path = "terraform/modules/org/vpc/aws/2.0.0/evil.tar.gz"
		}},
		{"module path not listed in files", func(_ *TerraformProvider, mod *TerraformModule, seen map[string]bool) {
			delete(seen, mod.Path)
		}},
		{"bad module system", func(_ *TerraformProvider, mod *TerraformModule, _ map[string]bool) {
			mod.System = "a ws"
		}},
	}
	for _, tt := range cases {
		p, mod, seen, files := tfTestCanonicalRecords()
		tt.mutate(&p, &mod, seen)
		m := &TerraformManifest{Providers: []TerraformProvider{p}, Modules: []TerraformModule{mod}}
		if err := validateTerraformManifest(m, seen, files); err == nil {
			t.Errorf("%s: manifest accepted, want error", tt.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration fixtures: fake registry, low server, fake git, archives
// -----------------------------------------------------------------------------

// fakeTfRegistry is a minimal in-process Terraform registry: a discovery
// document with relative service URLs (exercising tfDiscover's resolution)
// plus per-test provider and module endpoints.
type fakeTfRegistry struct {
	t   *testing.T
	mux *http.ServeMux
	srv *httptest.Server
}

func newFakeTfRegistry(t *testing.T) *fakeTfRegistry {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"providers.v1": "/v1/providers/", "modules.v1": "/v1/modules/"})
	})
	return &fakeTfRegistry{t: t, mux: mux, srv: srv}
}

func (f *fakeTfRegistry) serveBytes(p string, b []byte) {
	f.mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(b) })
}

// registerProvider wires the version list (the requested version plus a newer
// prerelease decoy that must never be auto-picked), the linux/amd64 download
// descriptor, and the artifact endpoints for one provider. tamperSums lists a
// wrong digest in the served SHA256SUMS so the collect-time cross-check fails.
// It returns the zip payload.
func (f *fakeTfRegistry) registerProvider(ns, typ, version string, tamperSums bool) []byte {
	f.t.Helper()
	zip := []byte("fake-provider-zip " + ns + "/" + typ + "@" + version)
	zipName := tfProviderZipName(typ, version, "linux", "amd64")
	sumsName := "terraform-provider-" + typ + "_" + version + "_SHA256SUMS"
	digest := aptSHA256(zip)
	listed := digest
	if tamperSums {
		listed = strings.Repeat("0", 64)
	}
	files := "/files/" + ns + "/" + typ + "/" + version
	api := "/v1/providers/" + ns + "/" + typ
	f.mux.HandleFunc(api+"/versions", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"versions": []map[string]string{
			{"version": version},
			{"version": "9.9.9-beta.1"},
		}})
	})
	f.mux.HandleFunc(api+"/"+version+"/download/linux/amd64", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"protocols":             []string{"5.0"},
			"os":                    "linux",
			"arch":                  "amd64",
			"filename":              zipName,
			"download_url":          f.srv.URL + files + "/" + zipName,
			"shasums_url":           f.srv.URL + files + "/" + sumsName,
			"shasums_signature_url": f.srv.URL + files + "/" + sumsName + ".sig",
			"shasum":                digest,
			"signing_keys": map[string]any{
				"gpg_public_keys": []map[string]string{{"key_id": "AA", "ascii_armor": "---"}},
			},
		})
	})
	f.serveBytes(files+"/"+zipName, zip)
	f.serveBytes(files+"/"+sumsName, []byte(listed+"  "+zipName+"\n"))
	f.serveBytes(files+"/"+sumsName+".sig", []byte("fake-detached-gpg-signature"))
	return zip
}

// registerModule wires one module version's list and download endpoints; the
// download answers 204 with the given X-Terraform-Get value.
func (f *fakeTfRegistry) registerModule(ns, name, system, version, terraformGet string) {
	f.t.Helper()
	api := "/v1/modules/" + ns + "/" + name + "/" + system
	f.mux.HandleFunc(api+"/versions", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"modules": []any{
			map[string]any{"versions": []map[string]string{{"version": version}}},
		}})
	})
	f.mux.HandleFunc(api+"/"+version+"/download", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Terraform-Get", terraformGet)
		w.WriteHeader(http.StatusNoContent)
	})
}

// tfTestLowServer builds a low server pointed at the fake registry, with an
// optional fake git binary for module sources.
func tfTestLowServer(t *testing.T, registry, gitBinary string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:              t.TempDir(),
		ExportDir:         filepath.Join(t.TempDir(), "out"),
		TerraformRegistry: registry,
		GitBinary:         gitBinary,
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// tfTestImport delivers one exported bundle to a fresh high server and
// imports it.
func tfTestImport(t *testing.T, ls *LowServer, priv ed25519.PrivateKey, bundleID string) *HighServer {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, bundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of terraform bundle failed: %v", err)
	}
	return hs
}

// tfTestTarGz packs the given path→content map into a tar.gz.
func tfTestTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tfTestListTarGz reads a tar.gz back into a path→content map.
func tfTestListTarGz(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("module archive is not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("module archive is not a tar: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(b)
	}
	return out
}

// tfTestWriteFakeGit writes a stand-in git binary. A clone invocation
// (either `clone --depth 1 [--branch <ref>] -- <url> <dir>` or the fallback
// `clone -- <url> <dir>`) populates <dir> with a repository tree: README.md
// and .git at the root, the module files under modules/sub — including a
// nested .git that must never be packed. `-C <dir> checkout --detach <ref>`
// succeeds silently. failShallow makes the `--branch` clone form fail so the
// full-clone-plus-checkout fallback runs. Every invocation's arguments are
// appended to the returned log file.
func tfTestWriteFakeGit(t *testing.T, failShallow bool) (bin, argsLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake git shell script is not portable to Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for fake git script")
	}
	fail := ""
	if failShallow {
		fail = `case " $* " in *" --branch "*) echo "fake git: no shallow refs" >&2; exit 1 ;; esac
`
	}
	dir := t.TempDir()
	script := `#!/usr/bin/env bash
set -eu
echo "$@" >> "$(dirname "$0")/git-args.log"
` + fail + `if [ "$1" = "-C" ]; then
  exit 0
fi
for last in "$@"; do :; done
dest="$last"
mkdir -p "$dest/modules/sub/vars" "$dest/modules/sub/.git" "$dest/.git"
echo "ref: refs/heads/main" > "$dest/.git/HEAD"
echo "top-level file outside the module subdir" > "$dest/README.md"
printf 'resource "null_resource" "sub" {}\n' > "$dest/modules/sub/main.tf"
printf 'variable "region" {}\n' > "$dest/modules/sub/vars/variables.tf"
echo "[core]" > "$dest/modules/sub/.git/config"
`
	bin = filepath.Join(dir, "git")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, filepath.Join(dir, "git-args.log")
}

// -----------------------------------------------------------------------------
// Integration: providers
// -----------------------------------------------------------------------------

// TestTerraformProviderPipeline mirrors one provider from a fake registry
// (resolving the newest stable release over a newer prerelease), checks the
// bundle manifest carries the full verification chain, imports the bundle,
// and drives the regenerated provider registry protocol on the high side.
func TestTerraformProviderPipeline(t *testing.T) {
	reg := newFakeTfRegistry(t)
	zip := reg.registerProvider("hashicorp", "null", "1.0.0", false)
	ls, priv := tfTestLowServer(t, reg.srv.URL, "")

	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{Providers: []string{"hashicorp/null"}})
	if err != nil {
		t.Fatalf("CollectTerraform: %v", err)
	}
	if res.BundleID != "terraform-bundle-000001" || res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if m.Terraform == nil || len(m.Terraform.Providers) != 1 {
		t.Fatalf("manifest carries no terraform provider: %+v", m.Terraform)
	}
	p := m.Terraform.Providers[0]
	dir := "terraform/providers/hashicorp/null/1.0.0"
	if p.Namespace != "hashicorp" || p.Type != "null" || p.Version != "1.0.0" {
		t.Errorf("provider identity = %+v, want hashicorp/null@1.0.0 (stable beats the 9.9.9-beta.1 decoy)", p)
	}
	if p.SHASumsPath != dir+"/terraform-provider-null_1.0.0_SHA256SUMS" ||
		p.SHASumsSigPath != p.SHASumsPath+".sig" ||
		p.KeysPath != dir+"/signing_keys.json" {
		t.Errorf("verification-chain paths = %+v", p)
	}
	zipName := tfProviderZipName("null", "1.0.0", "linux", "amd64")
	if len(p.Platforms) != 1 {
		t.Fatalf("platforms = %+v, want exactly linux/amd64", p.Platforms)
	}
	pl := p.Platforms[0]
	if pl.OS != "linux" || pl.Arch != "amd64" || pl.Filename != zipName ||
		pl.Path != dir+"/"+zipName || pl.SHA256 != aptSHA256(zip) {
		t.Errorf("platform record = %+v", pl)
	}
	if len(m.Files) != 4 { // zip + SHA256SUMS + .sig + signing_keys.json
		t.Errorf("bundle files = %+v, want 4", m.Files)
	}

	hs := tfTestImport(t, ls, priv, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	assertTfDiscovery(t, srv.URL)
	assertTfProviderVersions(t, srv.URL)
	assertTfProviderDownload(t, srv.URL, zip, zipName)

	// The imported zip landed intact in the repository.
	got, err := os.ReadFile(filepath.Join(hs.downloadDir, filepath.FromSlash(pl.Path)))
	if err != nil || !bytes.Equal(got, zip) {
		t.Errorf("imported zip on disk: %d bytes, %v (want %d bytes)", len(got), err, len(zip))
	}

	// Unknown platform, version, and provider all 404.
	for _, miss := range []string{
		"/terraform/v1/providers/hashicorp/null/1.0.0/download/darwin/arm64",
		"/terraform/v1/providers/hashicorp/null/9.9.9/download/linux/amd64",
		"/terraform/v1/providers/hashicorp/nope/versions",
	} {
		if code, _ := httpGet(t, srv.URL+miss); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", miss, code)
		}
	}
}

func assertTfDiscovery(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/.well-known/terraform.json")
	if code != http.StatusOK {
		t.Fatalf("discovery status %d: %s", code, body)
	}
	var disc map[string]string
	if err := json.Unmarshal([]byte(body), &disc); err != nil {
		t.Fatalf("discovery is not JSON: %v", err)
	}
	if disc["providers.v1"] != "/terraform/v1/providers/" || disc["modules.v1"] != "/terraform/v1/modules/" {
		t.Errorf("discovery = %v", disc)
	}
}

func assertTfProviderVersions(t *testing.T, base string) {
	t.Helper()
	code, body := httpGet(t, base+"/terraform/v1/providers/hashicorp/null/versions")
	if code != http.StatusOK {
		t.Fatalf("versions status %d: %s", code, body)
	}
	var vers struct {
		Versions []struct {
			Version   string   `json:"version"`
			Protocols []string `json:"protocols"`
			Platforms []struct {
				OS   string `json:"os"`
				Arch string `json:"arch"`
			} `json:"platforms"`
		} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &vers); err != nil {
		t.Fatalf("versions not JSON: %v\n%s", err, body)
	}
	if len(vers.Versions) != 1 || vers.Versions[0].Version != "1.0.0" {
		t.Fatalf("versions = %+v, want exactly 1.0.0", vers.Versions)
	}
	v := vers.Versions[0]
	if len(v.Protocols) != 1 || v.Protocols[0] != "5.0" {
		t.Errorf("protocols = %v, want [5.0]", v.Protocols)
	}
	if len(v.Platforms) != 1 || v.Platforms[0].OS != "linux" || v.Platforms[0].Arch != "amd64" {
		t.Errorf("platforms = %+v, want [{linux amd64}]", v.Platforms)
	}
}

func assertTfProviderDownload(t *testing.T, base string, zip []byte, zipName string) {
	t.Helper()
	code, body := httpGet(t, base+"/terraform/v1/providers/hashicorp/null/1.0.0/download/linux/amd64")
	if code != http.StatusOK {
		t.Fatalf("download descriptor status %d: %s", code, body)
	}
	var doc tfDownloadDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("download descriptor not JSON: %v\n%s", err, body)
	}
	filesBase := base + "/terraform/providers/hashicorp/null/1.0.0"
	if doc.SHASum != aptSHA256(zip) {
		t.Errorf("shasum = %q, want the collected zip digest %q", doc.SHASum, aptSHA256(zip))
	}
	if doc.Filename != zipName {
		t.Errorf("filename = %q, want %q", doc.Filename, zipName)
	}
	if doc.DownloadURL != filesBase+"/"+zipName {
		t.Errorf("download_url = %q, want absolute %q", doc.DownloadURL, filesBase+"/"+zipName)
	}
	sums := filesBase + "/terraform-provider-null_1.0.0_SHA256SUMS"
	if doc.SHASumsURL != sums || doc.SHASumsSignatureURL != sums+".sig" {
		t.Errorf("shasums URLs = %q / %q, want %q(.sig)", doc.SHASumsURL, doc.SHASumsSignatureURL, sums)
	}
	var keys struct {
		GPG []struct {
			KeyID string `json:"key_id"`
		} `json:"gpg_public_keys"`
	}
	if err := json.Unmarshal(doc.SigningKeys, &keys); err != nil || len(keys.GPG) != 1 || keys.GPG[0].KeyID != "AA" {
		t.Errorf("signing_keys = %s (%v), want gpg_public_keys[0].key_id AA", doc.SigningKeys, err)
	}
}

// TestTerraformArtifactRoutes fetches the artifact URLs the API advertises:
// the download descriptor's download_url must serve the exact collected zip,
// shasums_url/shasums_signature_url the mirrored verification chain, and the
// module download's X-Terraform-Get target the mirrored archive — this is
// what terraform itself does on install. Regression test: tfServablePath must
// match the rel serveTerraform actually dispatches (the "terraform/" prefix
// already trimmed), or every artifact URL 404s.
func TestTerraformArtifactRoutes(t *testing.T) {
	reg := newFakeTfRegistry(t)
	zip := reg.registerProvider("hashicorp", "null", "1.0.0", false)
	archive := tfTestTarGz(t, map[string]string{"main.tf": "# vpc module\n"})
	reg.serveBytes("/archives/vpc-aws-1.0.0.tar.gz", archive)
	reg.registerModule("org", "vpc", "aws", "1.0.0", reg.srv.URL+"/archives/vpc-aws-1.0.0.tar.gz")
	ls, priv := tfTestLowServer(t, reg.srv.URL, "")
	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{
		Providers: []string{"hashicorp/null@1.0.0"},
		Modules:   []string{"org/vpc/aws@1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectTerraform: %v", err)
	}
	hs := tfTestImport(t, ls, priv, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	zipName := tfProviderZipName("null", "1.0.0", "linux", "amd64")
	filesBase := srv.URL + "/terraform/providers/hashicorp/null/1.0.0"

	code, body := httpGet(t, filesBase+"/"+zipName)
	if code != http.StatusOK || body != string(zip) {
		t.Errorf("zip download: status %d, %d bytes (want 200 with %d bytes)", code, len(body), len(zip))
	}
	code, body = httpGet(t, filesBase+"/terraform-provider-null_1.0.0_SHA256SUMS")
	if code != http.StatusOK || !strings.Contains(body, aptSHA256(zip)+"  "+zipName) {
		t.Errorf("SHA256SUMS download: status %d body %q", code, body)
	}
	code, body = httpGet(t, filesBase+"/terraform-provider-null_1.0.0_SHA256SUMS.sig")
	if code != http.StatusOK || body != "fake-detached-gpg-signature" {
		t.Errorf("SHA256SUMS.sig download: status %d body %q", code, body)
	}
	code, body = httpGet(t, srv.URL+"/terraform/modules/org/vpc/aws/1.0.0/module.tar.gz")
	if code != http.StatusOK || body != string(archive) {
		t.Errorf("module archive download: status %d, %d bytes (want 200 with %d bytes)", code, len(body), len(archive))
	}
}

// TestTerraformCollectSkipsTamperedProvider proves the collect-time
// verification chain: a registry whose SHA256SUMS does not list the zip with
// the registry-declared digest fails that provider — skipped when other items
// succeed, a hard error (with no sequence burned) when it is the only item.
func TestTerraformCollectSkipsTamperedProvider(t *testing.T) {
	reg := newFakeTfRegistry(t)
	reg.registerProvider("hashicorp", "bad", "1.0.0", true)
	reg.registerProvider("hashicorp", "good", "1.0.0", false)

	ls, _ := tfTestLowServer(t, reg.srv.URL, "")
	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{
		Providers: []string{"hashicorp/bad@1.0.0", "hashicorp/good@1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectTerraform: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	sk := res.SkippedModules[0]
	if sk.Module != "hashicorp/bad" || sk.Version != "1.0.0" || !strings.Contains(sk.Error, "SHA256SUMS") {
		t.Errorf("skipped record = %+v, want hashicorp/bad with a SHA256SUMS error", sk)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	if len(m.Terraform.Providers) != 1 || m.Terraform.Providers[0].Type != "good" {
		t.Errorf("bundle providers = %+v, want only hashicorp/good", m.Terraform.Providers)
	}
	// The tampered provider's already-staged zip was rolled back out of the
	// file list: the bundle carries exactly the good provider's four files.
	if len(m.Files) != 4 {
		t.Errorf("bundle files = %+v, want only the good provider's 4 files", m.Files)
	}

	// Tampered provider as the only item: the whole collect fails...
	ls2, _ := tfTestLowServer(t, reg.srv.URL, "")
	_, err = ls2.CollectTerraform(context.Background(), TerraformCollectRequest{Providers: []string{"hashicorp/bad@1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "nothing could be fetched") {
		t.Fatalf("tampered-only collect = %v, want 'nothing could be fetched'", err)
	}
	// ...without burning a sequence number.
	if seq := ls2.peekSequence(streamTerraform); seq != 1 {
		t.Errorf("sequence advanced to %d after failed collect, want 1", seq)
	}
}

// -----------------------------------------------------------------------------
// Integration: modules
// -----------------------------------------------------------------------------

// TestTerraformModuleArchivePipeline mirrors a module whose registry download
// points at an https tar.gz archive, imports it, and drives the regenerated
// module registry protocol.
func TestTerraformModuleArchivePipeline(t *testing.T) {
	reg := newFakeTfRegistry(t)
	archive := tfTestTarGz(t, map[string]string{"main.tf": "# vpc module\n"})
	reg.serveBytes("/archives/vpc-aws-1.0.0.tar.gz", archive)
	reg.registerModule("org", "vpc", "aws", "1.0.0", reg.srv.URL+"/archives/vpc-aws-1.0.0.tar.gz")
	ls, priv := tfTestLowServer(t, reg.srv.URL, "")

	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{Modules: []string{"org/vpc/aws"}})
	if err != nil {
		t.Fatalf("CollectTerraform: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	if m.Terraform == nil || len(m.Terraform.Modules) != 1 {
		t.Fatalf("manifest carries no terraform module: %+v", m.Terraform)
	}
	mod := m.Terraform.Modules[0]
	if mod.Version != "1.0.0" || mod.Path != "terraform/modules/org/vpc/aws/1.0.0/module.tar.gz" ||
		mod.SHA256 != aptSHA256(archive) {
		t.Errorf("module record = %+v", mod)
	}

	hs := tfTestImport(t, ls, priv, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/terraform/v1/modules/org/vpc/aws/versions")
	if code != http.StatusOK {
		t.Fatalf("module versions status %d: %s", code, body)
	}
	var mv struct {
		Modules []struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"modules"`
	}
	if err := json.Unmarshal([]byte(body), &mv); err != nil {
		t.Fatalf("module versions not JSON: %v\n%s", err, body)
	}
	if len(mv.Modules) != 1 || len(mv.Modules[0].Versions) != 1 || mv.Modules[0].Versions[0].Version != "1.0.0" {
		t.Errorf("module versions = %+v, want exactly 1.0.0", mv.Modules)
	}

	resp, err := http.Get(srv.URL + "/terraform/v1/modules/org/vpc/aws/1.0.0/download") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("module download status %d, want 204", resp.StatusCode)
	}
	wantGet := srv.URL + "/terraform/modules/org/vpc/aws/1.0.0/module.tar.gz"
	if got := resp.Header.Get("X-Terraform-Get"); got != wantGet {
		t.Errorf("X-Terraform-Get = %q, want %q", got, wantGet)
	}

	// The X-Terraform-Get target serves the exact mirrored tar.gz
	// (TestTerraformArtifactRoutes drives the route); verify the imported
	// archive bytes on disk here. A subdir-less https source mirrors
	// bit-faithfully — no repack.
	data, err := os.ReadFile(filepath.Join(hs.downloadDir, filepath.FromSlash(mod.Path)))
	if err != nil || !bytes.Equal(data, archive) {
		t.Fatalf("imported module archive: %v (%d bytes, want %d)", err, len(data), len(archive))
	}
	if entries := tfTestListTarGz(t, data); entries["main.tf"] == "" {
		t.Errorf("imported archive missing main.tf: %v", entries)
	}

	// Unknown module and version 404.
	for _, miss := range []string{
		"/terraform/v1/modules/org/vpc/nope/versions",
		"/terraform/v1/modules/org/vpc/aws/2.0.0/download",
	} {
		if code, _ := httpGet(t, srv.URL+miss); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", miss, code)
		}
	}
}

// TestTerraformSplitArchiveSource covers go-getter source splitting for http
// archive sources: the //subdir selector leaves the fetched URL, the query
// stays with the URL, and only go-getter's "archive" hint is dropped from it
// (signed-URL parameters must survive).
func TestTerraformSplitArchiveSource(t *testing.T) {
	tests := []struct {
		source, dlURL, subdir string
	}{
		{"https://h/m/a.tar.gz", "https://h/m/a.tar.gz", ""},
		{"https://h/m/a.tgz", "https://h/m/a.tgz", ""},
		{"https://h/dl?archive=tar.gz", "https://h/dl", ""},
		// The module registry protocol's documented sample form.
		{"https://h/repo/tarball/v0.0.1//*?archive=tar.gz", "https://h/repo/tarball/v0.0.1", "*"},
		{"https://h/m/a.tar.gz//modules/x", "https://h/m/a.tar.gz", "modules/x"},
		{"https://h/m/a.tar.gz//modules/x/?archive=tar.gz&token=s3cr3t", "https://h/m/a.tar.gz?token=s3cr3t", "modules/x"},
	}
	for _, tt := range tests {
		dlURL, subdir, err := splitArchiveSource(tt.source)
		if err != nil || dlURL != tt.dlURL || subdir != tt.subdir {
			t.Errorf("splitArchiveSource(%q) = (%q, %q, %v), want (%q, %q)",
				tt.source, dlURL, subdir, err, tt.dlURL, tt.subdir)
		}
	}
	for _, source := range []string{
		"ftp://h/a.tar.gz",
		"https://h/not-an-archive",
		"https://h/not-an-archive//*",
		"https://h/a.zip?archive=zip",
	} {
		if _, _, err := splitArchiveSource(source); err == nil {
			t.Errorf("splitArchiveSource(%q) accepted an unsupported source", source)
		}
	}
}

// TestTerraformResolveArchiveSubdir covers selector resolution inside an
// extracted archive: literal paths, the "//*" single-top-directory wildcard,
// deeper globs, and the unsafe/ambiguous rejections.
func TestTerraformResolveArchiveSubdir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repo-abc", "modules", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "repo-abc", "file.tf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for sub, want := range map[string]string{
		"*":                    filepath.Join(root, "repo-abc"),
		"repo-abc":             filepath.Join(root, "repo-abc"),
		"repo-abc/modules/sub": filepath.Join(root, "repo-abc", "modules", "sub"),
		"*/modules/sub":        filepath.Join(root, "repo-abc", "modules", "sub"),
	} {
		if got, err := resolveArchiveSubdir(root, sub); err != nil || got != want {
			t.Errorf("resolveArchiveSubdir(%q) = (%q, %v), want %q", sub, got, err, want)
		}
	}
	for _, sub := range []string{"..", "../x", "a\\b", "nope", "repo-abc/file.tf", "*/nope"} {
		if _, err := resolveArchiveSubdir(root, sub); err == nil {
			t.Errorf("resolveArchiveSubdir(%q) = nil error, want error", sub)
		}
	}
	// Two top-level directories make the wildcard ambiguous.
	if err := os.MkdirAll(filepath.Join(root, "second"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveArchiveSubdir(root, "*"); err == nil {
		t.Error("ambiguous wildcard accepted")
	}
}

// TestTerraformModuleArchiveSubdirPipeline mirrors modules whose registry
// download is the module-registry-protocol sample form: an https endpoint
// with a go-getter "//*" (or concrete //path) selector and ?archive=tar.gz
// hint. The selector must leave the fetched URL — the fake upstream serves
// only the clean path — and the selected directory must be repacked as the
// module root, or terraform init unpacks an unusable tree.
func TestTerraformModuleArchiveSubdirPipeline(t *testing.T) {
	reg := newFakeTfRegistry(t)
	upstream := tfTestTarGz(t, map[string]string{
		"org-repo-abc123/main.tf":            "# module root\n",
		"org-repo-abc123/modules/sub/sub.tf": "# nested\n",
	})
	reg.serveBytes("/tarball/v1.0.0", upstream)
	reg.registerModule("org", "vpc", "aws", "1.0.0", reg.srv.URL+"/tarball/v1.0.0//*?archive=tar.gz")
	reg.serveBytes("/tarball/v2.0.0", upstream)
	reg.registerModule("org", "sub", "aws", "2.0.0",
		reg.srv.URL+"/tarball/v2.0.0//org-repo-abc123/modules/sub?archive=tar.gz")
	ls, priv := tfTestLowServer(t, reg.srv.URL, "")

	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{
		Modules: []string{"org/vpc/aws", "org/sub/aws"},
	})
	if err != nil {
		t.Fatalf("CollectTerraform: %v", err)
	}
	if res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	hs := tfTestImport(t, ls, priv, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// "//*" re-roots the single top-level directory: its content sits at the
	// archive root, without the upstream directory prefix.
	code, body := httpGet(t, srv.URL+"/terraform/modules/org/vpc/aws/1.0.0/module.tar.gz")
	if code != http.StatusOK {
		t.Fatalf("wildcard module archive status %d", code)
	}
	entries := tfTestListTarGz(t, []byte(body))
	if entries["main.tf"] != "# module root\n" || entries["modules/sub/sub.tf"] != "# nested\n" {
		t.Errorf("re-rooted archive entries = %v", entries)
	}
	if _, hasTop := entries["org-repo-abc123/main.tf"]; hasTop {
		t.Error("archive still carries the upstream top-level directory")
	}

	// A concrete "//path" selector re-roots that nested directory.
	code, body = httpGet(t, srv.URL+"/terraform/modules/org/sub/aws/2.0.0/module.tar.gz")
	if code != http.StatusOK {
		t.Fatalf("subdir module archive status %d", code)
	}
	entries = tfTestListTarGz(t, []byte(body))
	if len(entries) != 1 || entries["sub.tf"] != "# nested\n" {
		t.Errorf("nested-selector archive entries = %v", entries)
	}
}

// TestTerraformRegistryOverride proves a collect request's Registry field
// overrides the configured upstream for that collect (mirroring OpenTofu ad
// hoc): the configured registry here is unreachable and must never be
// contacted.
func TestTerraformRegistryOverride(t *testing.T) {
	reg := newFakeTfRegistry(t)
	reg.registerProvider("opentofu", "random", "1.0.0", false)
	ls, _ := tfTestLowServer(t, "http://127.0.0.1:9", "")

	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{
		Providers: []string{"opentofu/random@1.0.0"},
		Registry:  reg.srv.URL + "/", // a trailing slash is tolerated
	})
	if err != nil {
		t.Fatalf("CollectTerraform with request-level registry: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Errorf("unexpected collect result: %+v", res)
	}
}

// TestTerraformModuleDownloadForms covers the registry download responses
// beyond 204+X-Terraform-Get: a 200 body naming a location, an endpoint that
// yields no source at all, and a module with only prerelease versions.
func TestTerraformModuleDownloadForms(t *testing.T) {
	reg := newFakeTfRegistry(t)
	archive := tfTestTarGz(t, map[string]string{"main.tf": "# net module\n"})
	reg.serveBytes("/archives/net.tar.gz", archive)
	reg.mux.HandleFunc("/v1/modules/org/net/aws/1.2.3/download", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"location": reg.srv.URL + "/archives/net.tar.gz"})
	})
	reg.mux.HandleFunc("/v1/modules/org/net/aws/9.9.9/download", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	reg.registerModule("org", "pre", "aws", "1.0.0-rc.1", "unused") // prerelease only
	ls, _ := tfTestLowServer(t, reg.srv.URL, "")
	ctx := context.Background()

	res, err := ls.CollectTerraform(ctx, TerraformCollectRequest{Modules: []string{"org/net/aws@1.2.3"}})
	if err != nil || res.ExportedModules != 1 {
		t.Fatalf("CollectTerraform (location body) = %+v, %v", res, err)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	if m.Terraform.Modules[0].SHA256 != aptSHA256(archive) {
		t.Errorf("module record = %+v, want the located archive", m.Terraform.Modules[0])
	}

	// No X-Terraform-Get and no location body fails the module.
	_, err = ls.CollectTerraform(ctx, TerraformCollectRequest{Modules: []string{"org/net/aws@9.9.9"}})
	if err == nil || !strings.Contains(err.Error(), "X-Terraform-Get") {
		t.Errorf("sourceless module collect = %v, want an X-Terraform-Get error", err)
	}

	// A bare spec never resolves to a prerelease.
	_, err = ls.CollectTerraform(ctx, TerraformCollectRequest{Modules: []string{"org/pre/aws"}})
	if err == nil || !strings.Contains(err.Error(), "no release versions") {
		t.Errorf("prerelease-only module collect = %v, want 'no release versions'", err)
	}
}

// TestTerraformFetchModuleArchiveSources pins which module source forms are
// mirrored: http(s) tar.gz archives (a ?archive=tar.gz marker counts, its
// query stripped for the fetch) — and nothing else.
func TestTerraformFetchModuleArchiveSources(t *testing.T) {
	reg := newFakeTfRegistry(t)
	archive := tfTestTarGz(t, map[string]string{"main.tf": "# q module\n"})
	reg.serveBytes("/dl/plain", archive)
	ls, _ := tfTestLowServer(t, reg.srv.URL, "")
	ctx := context.Background()

	sum, _, err := ls.fetchTerraformModuleArchive(ctx, reg.srv.URL+"/dl/plain?archive=tar.gz", filepath.Join(t.TempDir(), "m.tar.gz"))
	if err != nil || sum != aptSHA256(archive) {
		t.Errorf("archive=tar.gz source = %q, %v; want the served archive digest", sum, err)
	}

	for _, src := range []string{
		"s3::https://bucket.example/key.tar.gz", // unsupported go-getter scheme
		"https://host.example/module.zip",       // not a tar.gz archive
		"ftp://host.example/module.tar.gz",      // not http(s)
	} {
		if _, _, err := ls.fetchTerraformModuleArchive(ctx, src, filepath.Join(t.TempDir(), "m.tar.gz")); err == nil {
			t.Errorf("fetchTerraformModuleArchive(%q) = nil, want error", src)
		}
	}
}

// TestTerraformModuleGitPipeline mirrors a module whose registry source is a
// git URL with a //subdir and ?ref: the fake git populates a repository tree,
// and the packed module.tar.gz must carry the subdir's content at the archive
// root with every .git tree excluded. A forced re-collect must produce a
// bit-identical archive (deterministic packing drives content dedup).
// Regression test: packGitModule must create the module's staging directory
// before placing its clone tempdir inside it, or every git:: collect fails
// with ENOENT (https archive sources create the parent themselves).
func TestTerraformModuleGitPipeline(t *testing.T) {
	gitBin, argsLog := tfTestWriteFakeGit(t, false)
	reg := newFakeTfRegistry(t)
	reg.registerModule("org", "vpc", "aws", "1.0.0", "git::https://git.example/org/repo//modules/sub?ref=v1.0.0")
	ls, priv := tfTestLowServer(t, reg.srv.URL, gitBin)

	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{Modules: []string{"org/vpc/aws@1.0.0"}})
	if err != nil {
		t.Fatalf("CollectTerraform (git module): %v", err)
	}
	if res.ExportedModules != 1 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	// git was invoked as a shallow clone of the repo URL without the //subdir.
	log, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("fake git was never invoked: %v", err)
	}
	firstCall, _, _ := strings.Cut(string(log), "\n")
	if !strings.HasPrefix(firstCall, "clone --depth 1 --branch v1.0.0 -- https://git.example/org/repo ") {
		t.Errorf("git invocation = %q, want a shallow clone of the bare repo URL at the ref", firstCall)
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if len(m.Terraform.Modules) != 1 {
		t.Fatalf("manifest modules = %+v", m.Terraform)
	}
	sum := m.Terraform.Modules[0].SHA256

	hs := tfTestImport(t, ls, priv, res.BundleID)
	data, err := os.ReadFile(filepath.Join(hs.downloadDir, filepath.FromSlash(m.Terraform.Modules[0].Path)))
	if err != nil {
		t.Fatalf("imported module archive missing: %v", err)
	}
	if aptSHA256(data) != sum {
		t.Errorf("imported archive digest %s does not match the manifest %s", aptSHA256(data), sum)
	}
	entries := tfTestListTarGz(t, data)
	if entries["main.tf"] == "" || entries["vars/variables.tf"] == "" {
		t.Errorf("subdir content not at archive root: %v", entries)
	}
	for name := range entries {
		if strings.Contains(name, ".git") {
			t.Errorf(".git entry leaked into the module archive: %s", name)
		}
		if strings.HasPrefix(name, "modules/") || name == "README.md" {
			t.Errorf("content outside the //modules/sub subdir leaked: %s", name)
		}
	}

	// Determinism: a forced second collect re-clones and re-packs, and must
	// produce the identical archive digest.
	res2, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{
		Modules: []string{"org/vpc/aws@1.0.0"}, Force: true,
	})
	if err != nil {
		t.Fatalf("forced re-collect: %v", err)
	}
	if res2.BundleID != "terraform-bundle-000002" {
		t.Fatalf("forced re-collect result: %+v", res2)
	}
	m2 := readBundleManifest(t, ls, res2.BundleID)
	if got := m2.Terraform.Modules[0].SHA256; got != sum {
		t.Errorf("re-packed module archive sha = %s, want deterministic %s", got, sum)
	}
}

// TestTerraformPackGitModule exercises the git packaging path directly (with
// an existing parent directory, sidestepping the collect-path bug documented
// on TestTerraformModuleGitPipeline): the //subdir is re-rooted at the
// archive top, .git trees and files outside the subdir never leak, the clone
// runs against the bare repo URL at the requested ref, and packing the same
// tree twice yields bit-identical archives.
func TestTerraformPackGitModule(t *testing.T) {
	gitBin, argsLog := tfTestWriteFakeGit(t, false)
	ls, _ := tfTestLowServer(t, "", gitBin)
	ctx := context.Background()

	abs := filepath.Join(t.TempDir(), "module.tar.gz")
	sum, size, err := ls.packGitModule(ctx, "https://git.example/org/repo//modules/sub?ref=v1.0.0", abs)
	if err != nil {
		t.Fatalf("packGitModule: %v", err)
	}
	if size <= 0 {
		t.Errorf("packGitModule size = %d, want > 0", size)
	}

	// git was invoked as a shallow clone of the repo URL without the //subdir.
	log, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("fake git was never invoked: %v", err)
	}
	firstCall, _, _ := strings.Cut(string(log), "\n")
	if !strings.HasPrefix(firstCall, "clone --depth 1 --branch v1.0.0 -- https://git.example/org/repo ") {
		t.Errorf("git invocation = %q, want a shallow clone of the bare repo URL at the ref", firstCall)
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if got := aptSHA256(data); got != sum {
		t.Errorf("returned sha %s does not match the packed archive %s", sum, got)
	}
	entries := tfTestListTarGz(t, data)
	if entries["main.tf"] == "" || entries["vars/variables.tf"] == "" {
		t.Errorf("subdir content not at archive root: %v", entries)
	}
	for name := range entries {
		if strings.Contains(name, ".git") {
			t.Errorf(".git entry leaked into the module archive: %s", name)
		}
		if strings.HasPrefix(name, "modules/") || name == "README.md" {
			t.Errorf("content outside the //modules/sub subdir leaked: %s", name)
		}
	}

	// Determinism: a second clone+pack produces the identical digest, so
	// re-collecting an unchanged module dedups instead of re-shipping.
	abs2 := filepath.Join(t.TempDir(), "module.tar.gz")
	sum2, _, err := ls.packGitModule(ctx, "https://git.example/org/repo//modules/sub?ref=v1.0.0", abs2)
	if err != nil {
		t.Fatalf("second packGitModule: %v", err)
	}
	if sum2 != sum {
		t.Errorf("re-packed archive sha = %s, want deterministic %s", sum2, sum)
	}

	// A subdir that resolves outside the clone is refused.
	if _, _, err := ls.packGitModule(ctx, "https://git.example/org/repo//..?ref=v1", filepath.Join(t.TempDir(), "m.tar.gz")); err == nil {
		t.Error("traversal subdir accepted")
	}
}

// TestTerraformGitCloneFallback drives gitCloneModule against a git whose
// shallow --branch clone fails (a commit-hash ref): it must fall back to a
// full clone plus a detached checkout of the ref.
func TestTerraformGitCloneFallback(t *testing.T) {
	gitBin, argsLog := tfTestWriteFakeGit(t, true)
	ls, _ := tfTestLowServer(t, "", gitBin)

	dir := filepath.Join(t.TempDir(), "clone")
	if err := ls.gitCloneModule(context.Background(), "https://git.example/org/repo", "abc1234", dir); err != nil {
		t.Fatalf("gitCloneModule fallback: %v", err)
	}
	if !fileExists(filepath.Join(dir, "modules", "sub", "main.tf")) {
		t.Error("fallback clone did not populate the working tree")
	}
	log, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(log)), "\n")
	if len(calls) != 3 {
		t.Fatalf("git calls = %q, want shallow attempt + full clone + checkout", calls)
	}
	if !strings.HasPrefix(calls[0], "clone --depth 1 --branch abc1234 -- ") {
		t.Errorf("first call = %q, want the shallow --branch attempt", calls[0])
	}
	if !strings.HasPrefix(calls[1], "clone -- https://git.example/org/repo ") {
		t.Errorf("second call = %q, want the full clone", calls[1])
	}
	if !strings.HasPrefix(calls[2], "-C ") || !strings.HasSuffix(calls[2], " checkout --detach abc1234") {
		t.Errorf("third call = %q, want the detached checkout", calls[2])
	}
}

// -----------------------------------------------------------------------------
// Integration: high side trusts nothing
// -----------------------------------------------------------------------------

// tfTestWriteSignedProviderBundle hand-builds a signed terraform bundle for
// acme/thing@1.0.0 whose mirrored SHA256SUMS either covers the zip's digest
// or lists a wrong one.
func tfTestWriteSignedProviderBundle(t *testing.T, landing string, priv ed25519.PrivateKey, sumsMatch bool) {
	t.Helper()
	src := t.TempDir()
	zip := []byte("zip-payload-for-import")
	dir := tfProviderDir("acme", "thing", "1.0.0")
	zipName := tfProviderZipName("thing", "1.0.0", "linux", "amd64")
	digest := aptSHA256(zip)
	listed := digest
	if !sumsMatch {
		listed = strings.Repeat("0", 64)
	}
	sumsRel := path.Join(dir, "terraform-provider-thing_1.0.0_SHA256SUMS")
	contents := map[string][]byte{
		path.Join(dir, zipName):             zip,
		sumsRel:                             []byte(listed + "  " + zipName + "\n"),
		sumsRel + ".sig":                    []byte("fake-signature"),
		path.Join(dir, "signing_keys.json"): []byte(`{"gpg_public_keys":[{"key_id":"AA"}]}`),
	}
	var files []ManifestFile
	for rel, b := range contents {
		abs := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, b)
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, mf)
	}
	provider := TerraformProvider{
		Namespace: "acme", Type: "thing", Version: "1.0.0",
		Protocols: []string{"5.0"},
		Platforms: []TerraformPlatform{{
			OS: "linux", Arch: "amd64", Filename: zipName,
			Path: path.Join(dir, zipName), SHA256: digest,
		}},
		SHASumsPath:    sumsRel,
		SHASumsSigPath: sumsRel + ".sig",
		KeysPath:       path.Join(dir, "signing_keys.json"),
	}
	bundleID := bundleIDFor(streamTerraform, 1)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamTerraform,
		Sequence:         1,
		PreviousSequence: 0,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Ecosystems:       []string{"terraform"},
		Terraform:        &TerraformManifest{Providers: []TerraformProvider{provider}},
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

// TestTerraformImportSkipsMismatchedSums proves publishTerraformProvider's
// cross-check on the untrusted side: a signed bundle whose mirrored
// SHA256SUMS does not cover the installed zip imports without wedging the
// stream, but the provider version is not served; a consistent chain is.
func TestTerraformImportSkipsMismatchedSums(t *testing.T) {
	for _, tt := range []struct {
		name     string
		match    bool
		wantCode int
	}{
		{"sums cover the zip", true, http.StatusOK},
		{"sums do not cover the zip", false, http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			tfTestWriteSignedProviderBundle(t, hs.cfg.Landing, priv, tt.match)
			if _, err := hs.ImportNext(); err != nil {
				t.Fatalf("import failed entirely (a bad provider must be skipped, not wedge the stream): %v", err)
			}
			srv := httptest.NewServer(hs)
			defer srv.Close()
			code, _ := httpGet(t, srv.URL+"/terraform/v1/providers/acme/thing/versions")
			if code != tt.wantCode {
				t.Errorf("versions status = %d, want %d", code, tt.wantCode)
			}
		})
	}
}

// TestTerraformUITreeAndDetail walks the dashboard tree for both mirrored
// kinds (providers/<ns>/<type> and modules/<ns>/<name>/<system>) and checks
// the detail panels.
func TestTerraformUITreeAndDetail(t *testing.T) {
	reg := newFakeTfRegistry(t)
	zip := reg.registerProvider("hashicorp", "null", "1.0.0", false)
	archive := tfTestTarGz(t, map[string]string{"main.tf": "# vpc module\n"})
	reg.serveBytes("/archives/vpc.tar.gz", archive)
	reg.registerModule("org", "vpc", "aws", "1.0.0", reg.srv.URL+"/archives/vpc.tar.gz")
	ls, priv := tfTestLowServer(t, reg.srv.URL, "")
	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{
		Providers: []string{"hashicorp/null@1.0.0"},
		Modules:   []string{"org/vpc/aws@1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectTerraform: %v", err)
	}
	if res.ExportedModules != 2 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	hs := tfTestImport(t, ls, priv, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	steps := []struct{ path, want string }{
		{"", `"providers"`},
		{"", `"modules"`},
		{"providers", `"hashicorp"`},
		{"providers/hashicorp", `"null"`},
		{"providers/hashicorp/null", "1.0.0"},
		{"modules/org/vpc", `"aws"`},
		{"modules/org/vpc/aws", "1.0.0"},
	}
	for _, st := range steps {
		if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=terraform&path="+st.path); !strings.Contains(body, st.want) {
			t.Errorf("terraform tree at %q missing %s: %s", st.path, st.want, body)
		}
	}

	code, body := httpGet(t, srv.URL+"/ui/api/detail?eco=terraform&path=providers/hashicorp/null@1.0.0")
	if code != http.StatusOK || !strings.Contains(body, aptSHA256(zip)) {
		t.Errorf("provider detail: status %d, body %q missing the platform digest", code, body)
	}
	var d UIDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	wantURL := "/terraform/providers/hashicorp/null/1.0.0/" + tfProviderZipName("null", "1.0.0", "linux", "amd64")
	if len(d.Downloads) != 1 || d.Downloads[0].URL != wantURL {
		t.Errorf("provider detail downloads = %+v, want %s", d.Downloads, wantURL)
	}

	code, body = httpGet(t, srv.URL+"/ui/api/detail?eco=terraform&path=modules/org/vpc/aws@1.0.0")
	if code != http.StatusOK || !strings.Contains(body, aptSHA256(archive)) ||
		!strings.Contains(body, "/terraform/modules/org/vpc/aws/1.0.0/module.tar.gz") {
		t.Errorf("module detail: status %d body %q", code, body)
	}

	for _, miss := range []string{
		"providers/hashicorp/null@9.9.9", // unknown version
		"modules/org/vpc/aws@9.9.9",
		"providers/hashicorp/null",     // no @version
		"nonsense/x@1.0.0",             // neither providers nor modules
		"providers/hashicorp@1.0.0",    // wrong segment count
		"providers/hashicorp/null@../", // invalid version
	} {
		if code, _ := httpGet(t, srv.URL+"/ui/api/detail?eco=terraform&path="+miss); code != http.StatusNotFound {
			t.Errorf("detail %q = %d, want 404", miss, code)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration: route hardening and the admin endpoint
// -----------------------------------------------------------------------------

func TestTerraformRouteHardening(t *testing.T) {
	reg := newFakeTfRegistry(t)
	reg.registerProvider("hashicorp", "null", "1.0.0", false)
	ls, priv := tfTestLowServer(t, reg.srv.URL, "")
	res, err := ls.CollectTerraform(context.Background(), TerraformCollectRequest{Providers: []string{"hashicorp/null@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	hs := tfTestImport(t, ls, priv, res.BundleID)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// The regenerated metadata and mirrored keys exist on disk...
	metaDir := filepath.Join(hs.downloadDir, "terraform", "providers", "hashicorp", "null", "1.0.0")
	if !fileExists(filepath.Join(metaDir, "metadata.json")) || !fileExists(filepath.Join(metaDir, "signing_keys.json")) {
		t.Fatal("expected metadata.json and signing_keys.json on disk after import")
	}
	// ...but stay private: only zips, SHA256SUMS(.sig), and module archives serve.
	for _, private := range []string{
		"/terraform/providers/hashicorp/null/1.0.0/metadata.json",
		"/terraform/providers/hashicorp/null/1.0.0/signing_keys.json",
	} {
		if code, _ := httpGet(t, srv.URL+private); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (private file)", private, code)
		}
	}

	// Traversal and junk paths are rejected, never served.
	for _, bad := range []string{
		"/terraform/providers/..%2f..%2fimport-state.json",
		"/terraform/providers/../../../etc/passwd",
		"/terraform/modules/..%2fx/module.tar.gz",
		"/terraform/v1/providers/hashicorp/null/versions/extra",
		"/terraform/v1/modules/org/vpc/aws/1.0.0/download/extra",
		"/terraform/nope",
		"/terraform",
	} {
		code, _ := httpGet(t, srv.URL+bad)
		if code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 404/400", bad, code)
		}
	}

	// Write methods are refused everywhere in the terraform namespace.
	for _, target := range []string{
		"/.well-known/terraform.json",
		"/terraform/v1/providers/hashicorp/null/versions",
		"/terraform/providers/hashicorp/null/1.0.0/x.zip",
	} {
		resp, err := http.Post(srv.URL+target, "application/json", strings.NewReader("{}")) //nolint:noctx // test request
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", target, resp.StatusCode)
		}
	}

	// Corrupt stored signing keys surface as a 500 on the download descriptor
	// rather than being embedded into a response.
	writeFile(t, filepath.Join(metaDir, "signing_keys.json"), []byte("not json"))
	if code, _ := httpGet(t, srv.URL+"/terraform/v1/providers/hashicorp/null/1.0.0/download/linux/amd64"); code != http.StatusInternalServerError {
		t.Errorf("download with corrupt stored keys = %d, want 500", code)
	}
}

// TestTerraformCollectAdmin drives the low-side admin endpoint end to end and
// checks request validation surfaces as 400s.
func TestTerraformCollectAdmin(t *testing.T) {
	reg := newFakeTfRegistry(t)
	reg.registerProvider("hashicorp", "null", "1.0.0", false)
	ls, _ := tfTestLowServer(t, reg.srv.URL, "")
	srv := httptest.NewServer(ls)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/admin/terraform/collect", "application/json", //nolint:noctx // test request
		strings.NewReader(`{"providers":["hashicorp/null@1.0.0"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect admin status = %d, want 200: %s", resp.StatusCode, b)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "terraform-bundle-000001" || res.ExportedModules != 1 {
		t.Errorf("unexpected collect result: %+v", res)
	}

	for _, body := range []string{
		`{}`,                            // nothing requested
		`not json`,                      // malformed body
		`{"providers":["one-segment"]}`, // bad provider spec
		`{"modules":["a/b"]}`,           // bad module spec
		`{"providers":["a/b"],"platforms":["nounderscore"]}`, // bad platform
		`{"providers":["a/b"],"registry":"ftp://x"}`,         // non-http(s) registry
	} {
		resp, err := http.Post(srv.URL+"/admin/terraform/collect", "application/json", strings.NewReader(body)) //nolint:noctx // test request
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("collect %s: status = %d, want 400", body, resp.StatusCode)
		}
	}
}
