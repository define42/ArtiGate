package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

func vsxTestSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// vsxTestZip builds a zip archive from ordered name/body pairs.
func vsxTestZip(t *testing.T, files []struct{ name, body string }) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// vsxTestVSIX builds a minimal valid .vsix: a zip with the manifest at
// extension/package.json plus some neighbors.
func vsxTestVSIX(t *testing.T, packageJSON string) []byte {
	t.Helper()
	return vsxTestZip(t, []struct{ name, body string }{
		{"extension.vsixmanifest", `<PackageManifest Version="2.0.0"/>`},
		{"extension/package.json", packageJSON},
		{"extension/readme.md", "readme"},
	})
}

// vsxTestPackageJSON renders an extension manifest; extra appends raw JSON
// members (e.g. extensionDependencies).
func vsxTestPackageJSON(publisher, name, version, extra string) string {
	s := fmt.Sprintf(`{"publisher":%q,"name":%q,"version":%q,"displayName":"Display %s","description":"Improves %s","engines":{"vscode":"^1.80.0"}`,
		publisher, name, version, name, name)
	if extra != "" {
		s += "," + extra
	}
	return s + "}"
}

// vsxTestExt describes one extension version a fake registry publishes.
type vsxTestExt struct {
	publisher, name, version string
	latest                   bool // answers the versionless /api/<pub>/<name> route
	vsix                     []byte
	deps                     []map[string]string // dependencies as {"namespace","extension"} objects
	pack                     []string            // bundledExtensions as "publisher.name" strings
	sha256                   string              // digest published via files.sha256 ("" = none)
}

// fakeVSXRegistry serves the Open VSX API subset ArtiGate reads: extension
// metadata at /api/<pub>/<name>[/<version>], archives, and optional .sha256
// digest files (in sha256sum "digest  filename" format).
func fakeVSXRegistry(t *testing.T, exts []vsxTestExt) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for _, e := range exts {
		fname := fmt.Sprintf("%s.%s-%s.vsix", e.publisher, e.name, e.version)
		files := map[string]string{"download": srv.URL + "/files/" + fname}
		if e.sha256 != "" {
			files["sha256"] = srv.URL + "/files/" + fname + ".sha256"
			digestLine := e.sha256 + "  " + fname + "\n"
			mux.HandleFunc("/files/"+fname+".sha256", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, digestLine)
			})
		}
		vsix := e.vsix
		mux.HandleFunc("/files/"+fname, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(vsix) })
		doc, err := json.Marshal(map[string]any{
			"namespace":         e.publisher,
			"name":              e.name,
			"version":           e.version,
			"files":             files,
			"dependencies":      e.deps,
			"bundledExtensions": e.pack,
		})
		if err != nil {
			t.Fatal(err)
		}
		serveDoc := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(doc) }
		mux.HandleFunc("/api/"+e.publisher+"/"+e.name+"/"+e.version, serveDoc)
		if e.latest {
			mux.HandleFunc("/api/"+e.publisher+"/"+e.name, serveDoc)
		}
	}
	return srv
}

func newVSXLowServer(t *testing.T, registryURL string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{
		Root:           t.TempDir(),
		ExportDir:      filepath.Join(t.TempDir(), "out"),
		VSXRegistryURL: registryURL,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// vsxExtractBundle unpacks a collected bundle's archive into the high side's
// repository root and returns its manifest, standing in for the importer's
// verify-and-extract step (registry wiring is centralized, so the vsx hooks
// are exercised directly).
func vsxExtractBundle(t *testing.T, ls *LowServer, hs *HighServer, bundleID string) BundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.VSX == nil || len(m.VSX.Extensions) == 0 {
		t.Fatalf("manifest carries no vsx extensions: %s", b)
	}
	f, err := os.Open(filepath.Join(ls.cfg.ExportDir, bundleID+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := validateRelPath(hdr.Name); err != nil {
			t.Fatalf("bundle member %q: %v", hdr.Name, err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		abs := filepath.Join(hs.downloadDir, filepath.FromSlash(hdr.Name))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, data)
	}
	return m
}

// vsxServe mounts the vsx serving hook on its own test server.
func vsxServe(t *testing.T, hs *HighServer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hs.serveVSX(w, r) {
			http.Error(w, "unclaimed", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func vsxPostQuery(t *testing.T, base, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(base+"/vsx/gallery/extensionquery", "application/json", strings.NewReader(body)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// vsxDecodeQuery parses an extensionquery response into its entries and the
// ResultCount/TotalCount metadata value.
func vsxDecodeQuery(t *testing.T, body string) ([]vsxGalleryExtension, int) {
	t.Helper()
	var doc struct {
		Results []struct {
			Extensions     []vsxGalleryExtension `json:"extensions"`
			ResultMetadata []struct {
				MetadataType  string `json:"metadataType"`
				MetadataItems []struct {
					Name  string `json:"name"`
					Count int    `json:"count"`
				} `json:"metadataItems"`
			} `json:"resultMetadata"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("extensionquery response is not JSON: %v\n%s", err, body)
	}
	if len(doc.Results) != 1 {
		t.Fatalf("expected one result block, got %d: %s", len(doc.Results), body)
	}
	total := -1
	for _, md := range doc.Results[0].ResultMetadata {
		if md.MetadataType != "ResultCount" {
			continue
		}
		for _, item := range md.MetadataItems {
			if item.Name == "TotalCount" {
				total = item.Count
			}
		}
	}
	if total < 0 {
		t.Fatalf("response carries no TotalCount: %s", body)
	}
	return doc.Results[0].Extensions, total
}

// vsxPlaceArtifact writes a .vsix directly into the high-side repository at
// its canonical path and returns the matching bundle record.
func vsxPlaceArtifact(t *testing.T, hs *HighServer, publisher, name, version string, vsix []byte) VSXExtension {
	t.Helper()
	filename := vsxFilename(publisher, name, version)
	rel := vsxFileRel(publisher, name, filename)
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, vsix)
	return VSXExtension{Publisher: publisher, Name: name, Version: version, Filename: filename, Path: rel, SHA256: vsxTestSHA256(vsix)}
}

// -----------------------------------------------------------------------------
// Unit: descriptor, naming, spec parsing, manifest validation
// -----------------------------------------------------------------------------

// TestVSXEcosystemDescriptor pins the registry descriptor's identity and
// hooks, and that its flags hook wires the registry override.
func TestVSXEcosystemDescriptor(t *testing.T) {
	e := vsxEcosystem()
	if e.stream != streamVSX || e.label == "" || e.title == "" || e.contentDesc == "" {
		t.Errorf("descriptor identity incomplete: %+v", e)
	}
	if e.collect == nil || e.watchCollect == nil || e.publish == nil || e.serve == nil || e.scanTree == nil || e.detail == nil || e.flags == nil {
		t.Error("descriptor is missing hooks")
	}
	if e.manifestContent(BundleManifest{}) {
		t.Error("an empty manifest must carry no vsx content")
	}
	ext := VSXExtension{
		Publisher: "pub", Name: "name", Version: "1.0.0",
		Filename: "pub.name-1.0.0.vsix", Path: "vsx/files/pub/name/pub.name-1.0.0.vsix",
		SHA256: strings.Repeat("a", 64),
	}
	m := BundleManifest{VSX: &VSXManifest{Extensions: []VSXExtension{ext}}}
	if !e.manifestContent(m) {
		t.Error("a manifest with an extension must carry vsx content")
	}
	if err := e.validateContent(m, map[string]bool{ext.Path: true}); err != nil {
		t.Errorf("validateContent rejected a canonical record: %v", err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cfg LowConfig
	e.flags(fs, &cfg)
	if err := fs.Parse([]string{"-vsx-registry", "https://vsx.example"}); err != nil {
		t.Fatal(err)
	}
	if cfg.VSXRegistryURL != "https://vsx.example" {
		t.Errorf("-vsx-registry did not set VSXRegistryURL: %q", cfg.VSXRegistryURL)
	}
}

func TestVSXValidateNamesAndVersions(t *testing.T) {
	validNames := []string{"usernamehw", "errorlens", "ms-python", "A0", "a", "x_y", "a" + strings.Repeat("b", 127)}
	invalidNames := []string{"", ".", "..", "-x", "_x", "a.b", "a/b", "a b", "a" + strings.Repeat("b", 128)}
	for _, n := range validNames {
		if err := validateVSXName(n); err != nil {
			t.Errorf("validateVSXName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateVSXName(n); err == nil {
			t.Errorf("validateVSXName(%q) = nil, want error", n)
		}
	}

	validVersions := []string{"3.16.0", "1.0.0-beta.1", "1.0.0+build.5", "0.0.1", "10.20.30", "1" + strings.Repeat("0", 63)}
	invalidVersions := []string{"", "v1.0.0", "latest", "-1.0", ".", "..", "1 0", "1/0", "1" + strings.Repeat("0", 64)}
	for _, v := range validVersions {
		if err := validateVSXVersion(v); err != nil {
			t.Errorf("validateVSXVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVersions {
		if err := validateVSXVersion(v); err == nil {
			t.Errorf("validateVSXVersion(%q) = nil, want error", v)
		}
	}
}

func TestVSXParseSpec(t *testing.T) {
	good := []struct{ spec, publisher, name, version string }{
		{"usernamehw.errorlens", "usernamehw", "errorlens", ""},
		{"pub.name@1.2.3", "pub", "name", "1.2.3"},
		{"pub.name@latest", "pub", "name", ""},
	}
	for _, tt := range good {
		publisher, name, version, err := parseVSXSpec(tt.spec)
		if err != nil || publisher != tt.publisher || name != tt.name || version != tt.version {
			t.Errorf("parseVSXSpec(%q) = (%q, %q, %q, %v), want (%q, %q, %q)",
				tt.spec, publisher, name, version, err, tt.publisher, tt.name, tt.version)
		}
	}
	for _, spec := range []string{"", "nodot", "pub.", ".name", "pub.name.extra", "-pub.name", "pub.name@v1.0.0", "pub.name@bad ver"} {
		if _, _, _, err := parseVSXSpec(spec); err == nil {
			t.Errorf("parseVSXSpec(%q) = nil error, want rejection", spec)
		}
	}
}

func TestVSXValidateExtensions(t *testing.T) {
	canon := VSXExtension{
		Publisher: "alpha", Name: "main", Version: "1.0.0",
		Filename: "alpha.main-1.0.0.vsix", Path: "vsx/files/alpha/main/alpha.main-1.0.0.vsix",
		SHA256: strings.Repeat("a", 64),
	}
	seen := map[string]bool{canon.Path: true}
	if err := validateVSXExtensions([]VSXExtension{canon}, seen); err != nil {
		t.Errorf("canonical record rejected: %v", err)
	}

	badFilename := canon
	badFilename.Filename = "main-1.0.0.vsix"
	badPath := canon
	badPath.Path = "vsx/files/other/main/alpha.main-1.0.0.vsix"
	badPublisher := canon
	badPublisher.Publisher = ".."
	badVersion := canon
	badVersion.Version = "latest"
	bad := []struct {
		name string
		ext  VSXExtension
		seen map[string]bool
	}{
		{"non-canonical filename", badFilename, seen},
		{"non-canonical path", badPath, map[string]bool{badPath.Path: true}},
		{"path not in seen map", canon, map[string]bool{}},
		{"invalid publisher", badPublisher, seen},
		{"invalid version", badVersion, seen},
	}
	for _, tt := range bad {
		if err := validateVSXExtensions([]VSXExtension{tt.ext}, tt.seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// TestVSXExtensionRefShapes proves every reference shape upstream metadata
// has used decodes — objects with "extension" or "name", flattened strings —
// and junk elements degrade to skippable empties instead of failing the
// whole extension.
func TestVSXExtensionRefShapes(t *testing.T) {
	doc := `{
	  "namespace": "a", "name": "b", "version": "1.0.0", "files": {},
	  "dependencies": [
	    {"namespace": "x", "extension": "y"},
	    {"namespace": "p", "name": "q"},
	    "r.s",
	    42,
	    {"namespace": "bad..ns", "extension": "y"}
	  ],
	  "bundledExtensions": ["m.n"]
	}`
	var ext vsxUpstreamExtension
	if err := json.Unmarshal([]byte(doc), &ext); err != nil {
		t.Fatalf("metadata with mixed reference shapes must parse: %v", err)
	}
	d := &vsxDownloader{}
	wants := d.refWants(&ext)
	got := make([]string, 0, len(wants))
	for _, w := range wants {
		got = append(got, w.publisher+"."+w.name)
	}
	want := []string{"x.y", "p.q", "r.s", "m.n"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("refWants = %v, want %v", got, want)
	}
	// The RE-invalid reference is reported, the junk element silently skipped.
	if len(d.failed) != 1 || !strings.Contains(d.failed[0].Error, "invalid extension reference") {
		t.Errorf("expected one invalid-reference failure, got %+v", d.failed)
	}
}

// -----------------------------------------------------------------------------
// Integration: collect -> extract -> publish -> gallery
// -----------------------------------------------------------------------------

// vsxPipelineRegistry publishes the standing test corpus: a pinned root with
// an object-form dependency and a string-form pack member, a digest-verified
// dependency whose own dependency is missing upstream, and a pack member.
func vsxPipelineRegistry(t *testing.T, alphaV1, alphaV2, betaV, gammaV []byte) *httptest.Server {
	t.Helper()
	return fakeVSXRegistry(t, []vsxTestExt{
		{
			publisher: "alpha", name: "main", version: "1.0.0", vsix: alphaV1,
			deps: []map[string]string{{"namespace": "beta", "extension": "dep"}},
			pack: []string{"gamma.pack"},
		},
		{publisher: "alpha", name: "main", version: "2.0.0", latest: true, vsix: alphaV2},
		{
			publisher: "beta", name: "dep", version: "2.1.0", latest: true, vsix: betaV,
			sha256: vsxTestSHA256(betaV),
			deps:   []map[string]string{{"namespace": "missing", "extension": "gone"}},
		},
		{publisher: "gamma", name: "pack", version: "3.0.0", latest: true, vsix: gammaV},
	})
}

// TestVSXCollectPipeline mirrors a pinned extension with its dependency and
// pack closure from a fake Open VSX registry, regenerates the high-side
// metadata from the archives, and drives the gallery protocol: exact-id and
// free-text queries, asset and direct downloads, pagination, method gates,
// and artifact-presence gating.
func TestVSXCollectPipeline(t *testing.T) {
	alphaV1 := vsxTestVSIX(t, vsxTestPackageJSON("alpha", "main", "1.0.0",
		`"extensionDependencies":["beta.dep"],"extensionPack":["gamma.pack"]`))
	alphaV2 := vsxTestVSIX(t, vsxTestPackageJSON("alpha", "main", "2.0.0", ""))
	betaV := vsxTestVSIX(t, vsxTestPackageJSON("beta", "dep", "2.1.0", ""))
	gammaV := vsxTestVSIX(t, vsxTestPackageJSON("gamma", "pack", "3.0.0", ""))
	reg := vsxPipelineRegistry(t, alphaV1, alphaV2, betaV, gammaV)

	ls, priv := newVSXLowServer(t, reg.URL)
	res, err := ls.CollectVSX(context.Background(), VSXCollectRequest{Extensions: []string{"alpha.main@1.0.0"}})
	if err != nil {
		t.Fatalf("CollectVSX: %v", err)
	}
	// The pinned root plus its dependency and pack member; the dependency's
	// missing dependency is reported, not fatal.
	if res.BundleID != "vsx-bundle-000001" || res.ExportedModules != 3 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "missing.gone" {
		t.Fatalf("expected missing.gone in SkippedModules, got %+v", res.SkippedModules)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	m := vsxExtractBundle(t, ls, hs, res.BundleID)
	vsxAssertManifest(t, m, alphaV1)
	if err := hs.publishVSX(m.VSX); err != nil {
		t.Fatalf("publishVSX: %v", err)
	}
	vsxAssertStoredMetadata(t, hs)

	srv := vsxServe(t, hs)
	vsxAssertExactQuery(t, srv.URL, alphaV1)
	vsxAssertSearchAndPagination(t, srv.URL)
	vsxAssertDownloads(t, srv.URL, alphaV1, betaV)
	vsxAssertGates(t, srv.URL)

	// Serving is gated on the artifact still being present: dropping one
	// archive drops its extension from the gallery and 404s its asset.
	if err := os.Remove(filepath.Join(hs.downloadDir, filepath.FromSlash("vsx/files/gamma/pack/gamma.pack-3.0.0.vsix"))); err != nil {
		t.Fatal(err)
	}
	code, body := vsxPostQuery(t, srv.URL, `{}`)
	exts, total := vsxDecodeQuery(t, body)
	if code != http.StatusOK || total != 2 || len(exts) != 2 {
		t.Errorf("after removing the archive: %d extensions (total %d), want 2", len(exts), total)
	}
	if code, _ := httpGet(t, srv.URL+"/vsx/assets/gamma/pack/3.0.0/"+vsxAssetVSIXPackage); code != http.StatusNotFound {
		t.Errorf("asset for a removed archive must 404, got %d", code)
	}
}

// vsxAssertManifest checks the produced bundle manifest: canonical records
// that the high side's import validation accepts, with the collected bytes'
// digests.
func vsxAssertManifest(t *testing.T, m BundleManifest, alphaV1 []byte) {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
	}
	if err := validateVSXExtensions(m.VSX.Extensions, seen); err != nil {
		t.Fatalf("import-side validation would reject the produced bundle: %v", err)
	}
	byID := map[string]VSXExtension{}
	for _, e := range m.VSX.Extensions {
		byID[e.Publisher+"."+e.Name+"@"+e.Version] = e
	}
	alpha, ok := byID["alpha.main@1.0.0"]
	if !ok {
		t.Fatalf("manifest missing alpha.main@1.0.0: %+v", m.VSX.Extensions)
	}
	if alpha.Filename != "alpha.main-1.0.0.vsix" || alpha.Path != "vsx/files/alpha/main/alpha.main-1.0.0.vsix" {
		t.Errorf("alpha record not canonical: %+v", alpha)
	}
	if alpha.SHA256 != vsxTestSHA256(alphaV1) {
		t.Errorf("alpha SHA256 = %s, want %s", alpha.SHA256, vsxTestSHA256(alphaV1))
	}
	if _, ok := byID["beta.dep@2.1.0"]; !ok {
		t.Errorf("dependency beta.dep@2.1.0 not mirrored: %+v", m.VSX.Extensions)
	}
	if _, ok := byID["gamma.pack@3.0.0"]; !ok {
		t.Errorf("pack member gamma.pack@3.0.0 not mirrored: %+v", m.VSX.Extensions)
	}
}

// vsxAssertStoredMetadata checks the regenerated per-version store: filename
// plus the archive's own manifest, keyed under publisher/name/version.
func vsxAssertStoredMetadata(t *testing.T, hs *HighServer) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(hs.downloadDir, filepath.FromSlash("vsx/metadata/alpha/main/1.0.0.json")))
	if err != nil {
		t.Fatalf("stored metadata missing: %v", err)
	}
	var st vsxStoredManifest
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("stored metadata is not JSON: %v", err)
	}
	if st.Filename != "alpha.main-1.0.0.vsix" {
		t.Errorf("stored filename = %q", st.Filename)
	}
	var meta struct {
		Version     string `json:"version"`
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(st.Manifest, &meta); err != nil || meta.Version != "1.0.0" || meta.DisplayName != "Display main" {
		t.Errorf("stored manifest = %s (err %v)", st.Manifest, err)
	}
}

// vsxUUIDRE matches the deterministic 8-4-4-4-12 identifiers the gallery
// serves.
var vsxUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// vsxAssertExactQuery drives a filterType-7 lookup (case-insensitive) and
// checks the entry's identity, asset links, and manifest-derived properties.
func vsxAssertExactQuery(t *testing.T, base string, alphaV1 []byte) {
	t.Helper()
	code, body := vsxPostQuery(t, base,
		`{"filters":[{"criteria":[{"filterType":8,"value":"Microsoft.VisualStudio.Code"},{"filterType":7,"value":"ALPHA.MAIN"},{"filterType":12,"value":"4096"}],"pageNumber":1,"pageSize":50}],"flags":950}`)
	if code != http.StatusOK {
		t.Fatalf("extensionquery status %d: %s", code, body)
	}
	exts, total := vsxDecodeQuery(t, body)
	if total != 1 || len(exts) != 1 {
		t.Fatalf("exact query matched %d (total %d), want 1: %s", len(exts), total, body)
	}
	e := exts[0]
	if e.ExtensionName != "main" || e.Publisher.PublisherName != "alpha" || e.DisplayName != "Display main" {
		t.Errorf("unexpected entry identity: %+v", e)
	}
	if !vsxUUIDRE.MatchString(e.ExtensionID) || e.ExtensionID != vsxUUID("alpha.main") || !vsxUUIDRE.MatchString(e.Publisher.PublisherID) {
		t.Errorf("ids not deterministic UUID-shaped: %q / %q", e.ExtensionID, e.Publisher.PublisherID)
	}
	if e.Flags != "validated" || e.Statistics == nil {
		t.Errorf("entry flags/statistics: %q / %v", e.Flags, e.Statistics)
	}
	if len(e.Versions) != 1 {
		t.Fatalf("expected one version, got %+v", e.Versions)
	}
	v := e.Versions[0]
	wantAsset := base + "/vsx/assets/alpha/main/1.0.0"
	if v.Version != "1.0.0" || v.AssetURI != wantAsset || v.FallbackAssetURI != wantAsset {
		t.Errorf("version entry = %+v, want assetUri %s", v, wantAsset)
	}
	if _, err := time.Parse(time.RFC3339, v.LastUpdated); err != nil {
		t.Errorf("lastUpdated %q is not RFC3339: %v", v.LastUpdated, err)
	}
	vsxAssertVersionFilesAndProps(t, v, wantAsset, alphaV1)
}

// vsxAssertVersionFilesAndProps checks a version entry's file sources — the
// vsix package must actually download from the advertised source — and the
// engine/dependency/pack properties surfaced from the embedded manifest.
func vsxAssertVersionFilesAndProps(t *testing.T, v vsxGalleryVersion, wantAsset string, alphaV1 []byte) {
	t.Helper()
	files := map[string]string{}
	for _, f := range v.Files {
		files[f.AssetType] = f.Source
	}
	if files[vsxAssetVSIXPackage] != wantAsset+"/"+vsxAssetVSIXPackage || files[vsxAssetManifest] != wantAsset+"/"+vsxAssetManifest {
		t.Errorf("version files = %+v", v.Files)
	}
	if code, got := httpGet(t, files[vsxAssetVSIXPackage]); code != http.StatusOK || got != string(alphaV1) {
		t.Errorf("vsix asset download: status %d, %d bytes (want %d)", code, len(got), len(alphaV1))
	}
	props := map[string]string{}
	for _, p := range v.Properties {
		props[p.Key] = p.Value
	}
	if props[vsxPropEngine] != "^1.80.0" {
		t.Errorf("engine property = %q, want ^1.80.0", props[vsxPropEngine])
	}
	if props[vsxPropDependencies] != "beta.dep" || props[vsxPropPack] != "gamma.pack" {
		t.Errorf("dependency/pack properties = %+v", props)
	}
}

// vsxAssertSearchAndPagination drives filterType-10 text search, the
// list-everything default, and pageNumber/pageSize windows.
func vsxAssertSearchAndPagination(t *testing.T, base string) {
	t.Helper()
	_, body := vsxPostQuery(t, base,
		`{"filters":[{"criteria":[{"filterType":10,"value":"Improves DEP"}],"pageNumber":1,"pageSize":50}]}`)
	exts, total := vsxDecodeQuery(t, body)
	if total != 1 || len(exts) != 1 || exts[0].ExtensionName != "dep" {
		t.Errorf("text search matched %+v (total %d), want beta.dep", exts, total)
	}
	_, body = vsxPostQuery(t, base,
		`{"filters":[{"criteria":[{"filterType":10,"value":"no such extension anywhere"}]}]}`)
	if exts, total := vsxDecodeQuery(t, body); total != 0 || len(exts) != 0 {
		t.Errorf("non-matching search returned %d (total %d)", len(exts), total)
	}
	// No id/text criteria at all lists everything.
	_, body = vsxPostQuery(t, base, ``)
	if exts, total := vsxDecodeQuery(t, body); total != 3 || len(exts) != 3 {
		t.Errorf("empty query listed %d (total %d), want 3", len(exts), total)
	}
	_, body = vsxPostQuery(t, base, `{"filters":[{"criteria":[],"pageNumber":1,"pageSize":2}]}`)
	exts, total = vsxDecodeQuery(t, body)
	if total != 3 || len(exts) != 2 || exts[0].ExtensionName != "main" || exts[1].ExtensionName != "dep" {
		t.Errorf("page 1 = %+v (total %d), want [main dep] of 3", exts, total)
	}
	_, body = vsxPostQuery(t, base, `{"filters":[{"criteria":[],"pageNumber":2,"pageSize":2}]}`)
	exts, total = vsxDecodeQuery(t, body)
	if total != 3 || len(exts) != 1 || exts[0].ExtensionName != "pack" {
		t.Errorf("page 2 = %+v (total %d), want [pack] of 3", exts, total)
	}
	_, body = vsxPostQuery(t, base, `{"filters":[{"criteria":[],"pageNumber":9,"pageSize":2}]}`)
	if exts, total := vsxDecodeQuery(t, body); total != 3 || len(exts) != 0 {
		t.Errorf("out-of-range page = %d entries (total %d), want 0 of 3", len(exts), total)
	}
}

// vsxAssertDownloads checks the manifest asset and the direct /vsx/files
// route, including the digest-verified dependency's exact bytes.
func vsxAssertDownloads(t *testing.T, base string, alphaV1, betaV []byte) {
	t.Helper()
	resp, err := http.Get(base + "/vsx/assets/alpha/main/1.0.0/" + vsxAssetManifest) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("manifest asset: status %d content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &meta); err != nil || meta.Version != "1.0.0" {
		t.Errorf("manifest asset body = %s (err %v)", b, err)
	}
	if code, _ := httpGet(t, base+"/vsx/assets/alpha/main/1.0.0/Some.Other.Asset"); code != http.StatusNotFound {
		t.Errorf("unknown asset type must 404, got %d", code)
	}
	if code, _ := httpGet(t, base+"/vsx/assets/alpha/main/9.9.9/"+vsxAssetVSIXPackage); code != http.StatusNotFound {
		t.Errorf("unknown version asset must 404, got %d", code)
	}
	if code, got := httpGet(t, base+"/vsx/files/alpha/main/alpha.main-1.0.0.vsix"); code != http.StatusOK || got != string(alphaV1) {
		t.Errorf("direct download: status %d, %d bytes (want %d)", code, len(got), len(alphaV1))
	}
	if code, got := httpGet(t, base+"/vsx/files/beta/dep/beta.dep-2.1.0.vsix"); code != http.StatusOK || got != string(betaV) {
		t.Errorf("verified dependency download: status %d, %d bytes (want %d)", code, len(got), len(betaV))
	}
}

// vsxAssertGates checks the method gates, malformed queries, and traversal
// rejection.
func vsxAssertGates(t *testing.T, base string) {
	t.Helper()
	if code, _ := httpGet(t, base+"/vsx/gallery/extensionquery"); code != http.StatusMethodNotAllowed {
		t.Errorf("GET extensionquery status %d, want 405", code)
	}
	resp, err := http.Post(base+"/vsx/files/alpha/main/alpha.main-1.0.0.vsix", "application/octet-stream", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST on a file route status %d, want 405", resp.StatusCode)
	}
	if code, body := vsxPostQuery(t, base, `{not json`); code != http.StatusBadRequest {
		t.Errorf("malformed query status %d: %s", code, body)
	}
	if code, _ := httpGet(t, base+"/vsx/gallery/nope"); code != http.StatusNotFound {
		t.Errorf("unknown gallery route status %d, want 404", code)
	}
	for _, p := range []string{
		"/vsx/files/alpha/main/..%2f..%2f..%2fmetadata%2falpha%2fmain%2f1.0.0.json",
		"/vsx/metadata/alpha/main/1.0.0.json",
		"/vsx/files/alpha/main/1.0.0.json",
	} {
		if code, _ := httpGet(t, base+p); code == http.StatusOK {
			t.Errorf("%s returned 200, want rejection", p)
		}
	}
}

// TestVSXCollectLatestNoDepsAndDedupe covers latest-version resolution, the
// no_deps opt-out, and first-spec-wins dedup within one collect.
func TestVSXCollectLatestNoDepsAndDedupe(t *testing.T) {
	alphaV1 := vsxTestVSIX(t, vsxTestPackageJSON("alpha", "main", "1.0.0", ""))
	alphaV2 := vsxTestVSIX(t, vsxTestPackageJSON("alpha", "main", "2.0.0", ""))
	betaV := vsxTestVSIX(t, vsxTestPackageJSON("beta", "dep", "2.1.0", ""))
	gammaV := vsxTestVSIX(t, vsxTestPackageJSON("gamma", "pack", "3.0.0", ""))
	reg := vsxPipelineRegistry(t, alphaV1, alphaV2, betaV, gammaV)

	// An unpinned spec resolves to the newest version; NoDeps leaves the
	// dependency references (beta.dep -> missing.gone) untouched, so nothing
	// is skipped.
	ls, _ := newVSXLowServer(t, reg.URL)
	res, err := ls.CollectVSX(context.Background(), VSXCollectRequest{Extensions: []string{"alpha.main"}, NoDeps: true})
	if err != nil {
		t.Fatalf("CollectVSX latest: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected latest collect result: %+v", res)
	}
	m := vsxManifestFromExport(t, ls, res.BundleID)
	if len(m.Extensions) != 1 || m.Extensions[0].Version != "2.0.0" {
		t.Errorf("latest resolution picked %+v, want 2.0.0", m.Extensions)
	}

	// Requesting the same extension twice keeps the first version selected.
	ls2, _ := newVSXLowServer(t, reg.URL)
	res, err = ls2.CollectVSX(context.Background(), VSXCollectRequest{
		Extensions: []string{"beta.dep@2.1.0", "beta.dep"}, NoDeps: true,
	})
	if err != nil {
		t.Fatalf("CollectVSX dedupe: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Fatalf("dedupe exported %d, want 1", res.ExportedModules)
	}
	m = vsxManifestFromExport(t, ls2, res.BundleID)
	if len(m.Extensions) != 1 || m.Extensions[0].Version != "2.1.0" {
		t.Errorf("dedupe kept %+v, want the first-selected 2.1.0", m.Extensions)
	}
}

// vsxManifestFromExport reads the exported bundle's vsx manifest.
func vsxManifestFromExport(t *testing.T, ls *LowServer, bundleID string) *VSXManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.VSX == nil {
		t.Fatalf("manifest carries no vsx content: %s", b)
	}
	return m.VSX
}

// TestVSXCollectDigestTamper proves a registry whose published sha256 does
// not match the served archive is skipped (and reported), and that a sole
// tampered extension fails the whole collect.
func TestVSXCollectDigestTamper(t *testing.T) {
	badV := vsxTestVSIX(t, vsxTestPackageJSON("bad", "ext", "1.0.0", ""))
	goodV := vsxTestVSIX(t, vsxTestPackageJSON("good", "ok", "1.0.0", ""))
	reg := fakeVSXRegistry(t, []vsxTestExt{
		{publisher: "bad", name: "ext", version: "1.0.0", latest: true, vsix: badV, sha256: vsxTestSHA256([]byte("not the real archive"))},
		{publisher: "good", name: "ok", version: "1.0.0", latest: true, vsix: goodV},
	})

	ls, _ := newVSXLowServer(t, reg.URL)
	res, err := ls.CollectVSX(context.Background(), VSXCollectRequest{Extensions: []string{"bad.ext", "good.ok"}, NoDeps: true})
	if err != nil {
		t.Fatalf("collect with one good extension should succeed: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Errorf("ExportedModules = %d, want 1 (only good.ok)", res.ExportedModules)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "bad.ext" ||
		!strings.Contains(res.SkippedModules[0].Error, "sha256") {
		t.Fatalf("expected bad.ext skipped with a sha256 error, got %+v", res.SkippedModules)
	}

	// The tampered extension on its own leaves nothing to export: hard failure.
	if _, err := ls.CollectVSX(context.Background(), VSXCollectRequest{Extensions: []string{"bad.ext"}, NoDeps: true}); err == nil {
		t.Fatal("a tampered sole extension should fail the collect")
	}
}

// -----------------------------------------------------------------------------
// High side: publish identity checks
// -----------------------------------------------------------------------------

// TestVSXPublishRejections documents the high-side guarantee for archives
// whose embedded package.json disagrees with the bundle record: publish logs
// and skips them, so they never enter the gallery, while the (SHA-256
// verified) archives themselves stay downloadable.
func TestVSXPublishRejections(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	ok := vsxPlaceArtifact(t, hs, "okcase", "ext", "1.0.0",
		vsxTestVSIX(t, vsxTestPackageJSON("OkCase", "Ext", "1.0.0", ""))) // case-folded identity is accepted
	verMis := vsxPlaceArtifact(t, hs, "vermis", "ext", "1.0.0",
		vsxTestVSIX(t, vsxTestPackageJSON("vermis", "ext", "9.9.9", "")))
	nameMis := vsxPlaceArtifact(t, hs, "namemis", "ext", "1.0.0",
		vsxTestVSIX(t, vsxTestPackageJSON("namemis", "different", "1.0.0", "")))
	badJSON := vsxPlaceArtifact(t, hs, "badjson", "ext", "1.0.0", vsxTestVSIX(t, "not json{"))
	wrongCase := vsxPlaceArtifact(t, hs, "wrongcase", "ext", "1.0.0",
		vsxTestZip(t, []struct{ name, body string }{
			{"Extension/package.json", vsxTestPackageJSON("wrongcase", "ext", "1.0.0", "")},
		})) // the manifest path is case-sensitive
	notZip := vsxPlaceArtifact(t, hs, "notzip", "ext", "1.0.0", []byte("not a zip archive"))

	m := &VSXManifest{Extensions: []VSXExtension{ok, verMis, nameMis, badJSON, wrongCase, notZip}}
	if err := hs.publishVSX(m); err != nil {
		t.Fatalf("publish must log-and-skip bad archives, not fail: %v", err)
	}

	srv := vsxServe(t, hs)
	_, body := vsxPostQuery(t, srv.URL, `{}`)
	exts, total := vsxDecodeQuery(t, body)
	if total != 1 || len(exts) != 1 || exts[0].Publisher.PublisherName != "okcase" {
		t.Errorf("gallery lists %+v (total %d), want only okcase.ext", exts, total)
	}
	if code, _ := httpGet(t, srv.URL+"/vsx/assets/vermis/ext/1.0.0/"+vsxAssetVSIXPackage); code != http.StatusNotFound {
		t.Errorf("rejected version's asset must 404, got %d", code)
	}
	// The verified artifact itself is still served for forensics/manual use.
	if code, _ := httpGet(t, srv.URL+"/vsx/files/vermis/ext/vermis.ext-1.0.0.vsix"); code != http.StatusOK {
		t.Errorf("rejected version's archive should still download, got %d", code)
	}

	// A record pointing outside the vsx tree is refused outright.
	evil := ok
	evil.Path = "npm/packages/evil/evil-1.0.0.tgz"
	if err := hs.publishVSXExtension(evil); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("out-of-tree path must be rejected, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Dashboard tree/detail
// -----------------------------------------------------------------------------

func TestVSXTreeAndDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	v1 := vsxTestVSIX(t, vsxTestPackageJSON("alpha", "main", "1.0.0", ""))
	v2 := vsxTestVSIX(t, vsxTestPackageJSON("alpha", "main", "2.0.0", ""))
	rec1 := vsxPlaceArtifact(t, hs, "alpha", "main", "1.0.0", v1)
	rec2 := vsxPlaceArtifact(t, hs, "alpha", "main", "2.0.0", v2)
	if err := hs.publishVSX(&VSXManifest{Extensions: []VSXExtension{rec1, rec2}}); err != nil {
		t.Fatal(err)
	}

	mods, err := hs.listVSXExtensions()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Module != "alpha.main" ||
		strings.Join(mods[0].Versions, " ") != "2.0.0 1.0.0" {
		t.Fatalf("listVSXExtensions = %+v, want alpha.main [2.0.0 1.0.0]", mods)
	}

	tree, err := vsxEcosystem().scanTree(hs)
	if err != nil {
		t.Fatal(err)
	}
	root := tree.children("")
	if len(root) != 1 || root[0].Label != "alpha.main" || !root[0].Expandable || root[0].Count != 2 {
		t.Fatalf("tree root = %+v", root)
	}
	leaves := tree.children("alpha.main")
	if len(leaves) != 2 || leaves[0].Path != "alpha.main@2.0.0" || leaves[1].Path != "alpha.main@1.0.0" {
		t.Fatalf("tree leaves = %+v", leaves)
	}

	d, err := vsxEcosystem().detail(hs, "alpha.main@1.0.0")
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if d.Title != "alpha.main" || d.Subtitle != "1.0.0" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	fields := map[string]string{}
	for _, f := range d.Fields {
		fields[f.Label] = f.Value
	}
	if fields["Display name"] != "Display main" || fields["VS Code engine"] != "^1.80.0" {
		t.Errorf("detail fields = %+v", fields)
	}
	if fields["SHA-256"] != vsxTestSHA256(v1) || fields["Archive size"] == "" {
		t.Errorf("detail digest/size fields = %+v", fields)
	}
	if fields["Asset path"] != "/vsx/assets/alpha/main/1.0.0" {
		t.Errorf("detail asset path = %q", fields["Asset path"])
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/vsx/files/alpha/main/alpha.main-1.0.0.vsix" ||
		d.Downloads[0].Label != "alpha.main-1.0.0.vsix" {
		t.Errorf("detail downloads = %+v", d.Downloads)
	}

	for _, spec := range []string{"alpha.main@9.9.9", "alpha.main", "garbage", "@1.0.0", "alpha.main@", "alphamain@1.0.0"} {
		if _, err := hs.vsxDetail(spec); err == nil {
			t.Errorf("vsxDetail(%q) = nil error, want rejection", spec)
		}
	}
}

// -----------------------------------------------------------------------------
// Collect request parsing
// -----------------------------------------------------------------------------

func TestVSXHandleCollectRequests(t *testing.T) {
	ls, _ := newVSXLowServer(t, "http://127.0.0.1:0")

	r := httptest.NewRequest(http.MethodPost, "/admin/vsx/collect", strings.NewReader("not json"))
	if _, err := ls.HandleVSXCollect(context.Background(), r); err == nil ||
		!strings.Contains(err.Error(), "parse vsx collect request") {
		t.Errorf("malformed body error = %v", err)
	}

	r = httptest.NewRequest(http.MethodPost, "/admin/vsx/collect", strings.NewReader(``))
	if _, err := ls.HandleVSXCollect(context.Background(), r); err == nil ||
		!strings.Contains(err.Error(), "no extensions") {
		t.Errorf("empty request error = %v", err)
	}

	r = httptest.NewRequest(http.MethodPost, "/admin/vsx/collect", strings.NewReader(`{"extensions":["nodot"]}`))
	if _, err := ls.HandleVSXCollect(context.Background(), r); err == nil ||
		!strings.Contains(err.Error(), "publisher.name") {
		t.Errorf("bad spec error = %v", err)
	}
}
