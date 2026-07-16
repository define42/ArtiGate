package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

func helmTestSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// helmTestChartTgz builds a valid chart archive whose top-level directory and
// embedded Chart.yaml identity both match name/version.
func helmTestChartTgz(t *testing.T, name, version string) []byte {
	t.Helper()
	return helmTestChartTgzNamed(t, name, name, version)
}

// helmTestChartTgzNamed builds a gzipped tar containing "<dir>/Chart.yaml"
// whose YAML declares chartName/version. Splitting the directory from the
// embedded name lets a test forge an archive whose embedded identity disagrees
// with its filename.
func helmTestChartTgzNamed(t *testing.T, dir, chartName, version string) []byte {
	t.Helper()
	chartYAML := fmt.Sprintf(
		"apiVersion: v2\nname: %s\nversion: %s\ndescription: A Helm chart for %s\nappVersion: %q\n",
		chartName, version, chartName, "1.16.0",
	)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := []struct{ name, body string }{
		{dir + "/Chart.yaml", chartYAML},
		{dir + "/values.yaml", "replicaCount: 1\n"},
		{dir + "/templates/deployment.yaml", "kind: Deployment\n"},
	}
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
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

// helmTestEntry describes one chart version to publish from a fake repository:
// the bytes served at its URL and the digest string written into index.yaml
// ("" omits the digest, exercising the unverified download path).
type helmTestEntry struct {
	name    string
	version string
	digest  string
	body    []byte
	url     string
}

// fakeHelmRepo serves an upstream Helm chart repository: an index.yaml built by
// hand plus each chart archive at its (repo-relative) URL.
func fakeHelmRepo(t *testing.T, entries []helmTestEntry) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	byName := map[string][]map[string]any{}
	for _, e := range entries {
		u := e.url
		if u == "" {
			u = "charts/" + e.name + "-" + e.version + ".tgz"
		}
		entry := map[string]any{"name": e.name, "version": e.version, "urls": []string{u}}
		if e.digest != "" {
			entry["digest"] = e.digest
		}
		byName[e.name] = append(byName[e.name], entry)
		if strings.Contains(u, "://") {
			continue // absolute URLs are not served by this repo
		}
		body := e.body
		mux.HandleFunc("/"+u, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	idx, err := yaml.Marshal(map[string]any{"apiVersion": "v1", "entries": byName})
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(idx) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// helmMirrorFromExport recovers the derived mirror slug from the exported
// bundle manifest (the ExportResult does not carry it).
func helmMirrorFromExport(t *testing.T, ls *LowServer, bundleID string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Helm == nil || len(m.Helm.Repos) == 0 {
		t.Fatalf("manifest carries no helm repos: %s", b)
	}
	return m.Helm.Repos[0].Name
}

func helmMaybeEntry(idx helmIndex, name, version string) map[string]any {
	for _, e := range idx.Entries[name] {
		if v, _ := e["version"].(string); v == version {
			return e
		}
	}
	return nil
}

func helmFindEntry(t *testing.T, idx helmIndex, name, version string) map[string]any {
	t.Helper()
	e := helmMaybeEntry(idx, name, version)
	if e == nil {
		t.Fatalf("index missing %s@%s: %+v", name, version, idx.Entries)
	}
	return e
}

func helmEntryVersions(idx helmIndex, name string) []string {
	out := make([]string, 0, len(idx.Entries[name]))
	for _, e := range idx.Entries[name] {
		v, _ := e["version"].(string)
		out = append(out, v)
	}
	return out
}

func newHelmLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// -----------------------------------------------------------------------------
// Unit: naming/version validation
// -----------------------------------------------------------------------------

func TestHelmValidateNames(t *testing.T) {
	validNames := []string{"ingress-nginx", "nginx", "a", "chart.name", "chart_name", "A0"}
	invalidNames := []string{"", "..", ".", "-flag", "_private", ".hidden", "a/b", "a b", strings.Repeat("x", 129)}
	for _, n := range validNames {
		if err := validateHelmChartName(n); err != nil {
			t.Errorf("validateHelmChartName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalidNames {
		if err := validateHelmChartName(n); err == nil {
			t.Errorf("validateHelmChartName(%q) = nil, want error", n)
		}
	}

	validVersions := []string{"v1.2.3", "1.2.3", "1.2.3-beta.1", "0.5.0", "1.0.0+build.5", "10.20.30"}
	invalidVersions := []string{"", "..", "-1.0", "latest", "v", "beta", "/1.0", " 1.0"}
	for _, v := range validVersions {
		if err := validateHelmVersion(v); err != nil {
			t.Errorf("validateHelmVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalidVersions {
		if err := validateHelmVersion(v); err == nil {
			t.Errorf("validateHelmVersion(%q) = nil, want error", v)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: chart URL resolution
// -----------------------------------------------------------------------------

func TestHelmChartURL(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
		first   string
		want    string
		wantErr bool
	}{
		{"absolute passthrough", "https://charts.example.com", "https://cdn.example.net/web-1.0.0.tgz", "https://cdn.example.net/web-1.0.0.tgz", false},
		{"relative against host root", "https://charts.example.com", "charts/web-1.0.0.tgz", "https://charts.example.com/charts/web-1.0.0.tgz", false},
		{"relative against repo path", "https://charts.example.com/stable", "web-1.0.0.tgz", "https://charts.example.com/stable/web-1.0.0.tgz", false},
		{"non-http scheme rejected", "https://charts.example.com", "ftp://evil.example/x.tgz", "", true},
		{"no download url", "https://charts.example.com", "", "", true},
	}
	for _, tt := range tests {
		entry := &helmUpstreamEntry{Name: "web", Version: "1.0.0"}
		if tt.first != "" {
			entry.URLs = []string{tt.first}
		}
		got, err := helmChartURL(tt.repoURL, entry)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: helmChartURL = %q, want error", tt.name, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: helmChartURL = %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: version selection
// -----------------------------------------------------------------------------

func TestHelmSelectChart(t *testing.T) {
	idx := &helmUpstreamIndex{Entries: map[string][]helmUpstreamEntry{
		"web": {
			{Name: "web", Version: "1.0.0"},
			{Name: "web", Version: "2.0.0-beta.1"},
			{Name: "web", Version: "0.9.0"},
		},
		"pre": {
			{Name: "pre", Version: "2.0.0-beta.1"},
			{Name: "pre", Version: "2.0.0-beta.2"},
		},
	}}

	if e, err := selectHelmChart(idx, "web", "2.0.0-beta.1"); err != nil || e.Version != "2.0.0-beta.1" {
		t.Errorf("pinned select = %+v, %v; want 2.0.0-beta.1", e, err)
	}
	if _, err := selectHelmChart(idx, "web", "9.9.9"); err == nil {
		t.Error("pinned missing version should error")
	}
	// A stable release wins over a newer prerelease when nothing is pinned.
	if e, err := selectHelmChart(idx, "web", ""); err != nil || e.Version != "1.0.0" {
		t.Errorf("newest stable select = %+v, %v; want 1.0.0", e, err)
	}
	// With only prereleases, the newest prerelease is used.
	if e, err := selectHelmChart(idx, "pre", ""); err != nil || e.Version != "2.0.0-beta.2" {
		t.Errorf("prerelease fallback = %+v, %v; want 2.0.0-beta.2", e, err)
	}
	if _, err := selectHelmChart(idx, "absent", ""); err == nil {
		t.Error("unknown chart should error")
	}
}

// -----------------------------------------------------------------------------
// Unit: import-side manifest validation
// -----------------------------------------------------------------------------

func TestHelmValidateRepos(t *testing.T) {
	canonPath := "helm/bitnami/charts/web_1.0.0.tgz"
	canonCharts := []HelmChart{{
		Name: "web", Version: "1.0.0", Filename: "web_1.0.0.tgz", Path: canonPath, SHA256: strings.Repeat("a", 64),
	}}
	seenCanon := map[string]bool{canonPath: true}

	good := []HelmRepo{{Name: "bitnami", URL: "https://charts.example.com", Charts: canonCharts}}
	if err := validateHelmRepos(good, seenCanon); err != nil {
		t.Errorf("valid repo rejected: %v", err)
	}

	bad := []struct {
		name  string
		repos []HelmRepo
		seen  map[string]bool
	}{
		{
			"bad mirror name",
			[]HelmRepo{{Name: "../x", URL: "u", Charts: canonCharts}},
			seenCanon,
		},
		{
			"non-canonical filename",
			[]HelmRepo{{Name: "bitnami", URL: "u", Charts: []HelmChart{
				{Name: "web", Version: "1.0.0", Filename: "web.tgz", Path: "helm/bitnami/charts/web.tgz"},
			}}},
			map[string]bool{"helm/bitnami/charts/web.tgz": true},
		},
		{
			// The pre-fix '-'-joined filename is ambiguous (a-1@1.0.0 vs
			// a@1-1.0.0) and must no longer validate as canonical.
			"legacy hyphen filename",
			[]HelmRepo{{Name: "bitnami", URL: "u", Charts: []HelmChart{
				{Name: "web", Version: "1.0.0", Filename: "web-1.0.0.tgz", Path: "helm/bitnami/charts/web-1.0.0.tgz"},
			}}},
			map[string]bool{"helm/bitnami/charts/web-1.0.0.tgz": true},
		},
		{
			"path not in seen map",
			[]HelmRepo{{Name: "bitnami", URL: "u", Charts: canonCharts}},
			map[string]bool{},
		},
		{
			"no url",
			[]HelmRepo{{Name: "bitnami", URL: "", Charts: canonCharts}},
			seenCanon,
		},
		{
			"no charts",
			[]HelmRepo{{Name: "bitnami", URL: "u", Charts: nil}},
			seenCanon,
		},
	}
	for _, tt := range bad {
		if err := validateHelmRepos(tt.repos, tt.seen); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration: low -> high pipeline
// -----------------------------------------------------------------------------

// TestHelmLowToHighPipeline mirrors a fake repo (stable preferred over a newer
// prerelease; one chart with no upstream digest), transfers the signed bundle,
// imports it, and checks the regenerated index.yaml, the served archive bytes,
// and the serving hardening (private metadata, traversal, method).
func TestHelmLowToHighPipeline(t *testing.T) {
	web100 := helmTestChartTgz(t, "web", "1.0.0")
	web2b1 := helmTestChartTgz(t, "web", "2.0.0-beta.1")
	db := helmTestChartTgz(t, "db", "0.5.0")
	repo := fakeHelmRepo(t, []helmTestEntry{
		{name: "web", version: "1.0.0", digest: "sha256:" + helmTestSHA256(web100), body: web100},
		{name: "web", version: "2.0.0-beta.1", digest: helmTestSHA256(web2b1), body: web2b1}, // bare hex digest
		{name: "db", version: "0.5.0", digest: "", body: db},                                 // no digest -> unverified path
	})

	ls, priv := newHelmLowServer(t)
	res, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		URL: repo.URL, Charts: []string{"web", "db@0.5.0"},
	})
	if err != nil {
		t.Fatalf("CollectHelm: %v", err)
	}
	// web resolved to the stable 1.0.0 (not the newer 2.0.0-beta.1); two charts.
	if res.BundleID != "helm-bundle-000001" || res.ExportedModules != 2 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	mirror := helmMirrorFromExport(t, ls, res.BundleID)

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/helm/"+mirror+"/index.yaml")
	if code != http.StatusOK {
		t.Fatalf("index.yaml status %d: %s", code, body)
	}
	var idx helmIndex
	if err := yaml.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatalf("index.yaml is not YAML: %v\n%s", err, body)
	}

	web := helmFindEntry(t, idx, "web", "1.0.0")
	if got, _ := web["digest"].(string); got != helmTestSHA256(web100) {
		t.Errorf("web 1.0.0 digest = %q, want %q", got, helmTestSHA256(web100))
	}
	urls, _ := web["urls"].([]any)
	if len(urls) != 1 {
		t.Fatalf("web 1.0.0 urls = %v, want one entry", web["urls"])
	}
	if s, _ := urls[0].(string); s != "charts/web_1.0.0.tgz" {
		t.Errorf("web 1.0.0 url = %v, want charts/web_1.0.0.tgz", urls[0])
	}
	if s, _ := web["description"].(string); s == "" {
		t.Errorf("web 1.0.0 entry missing embedded description: %v", web)
	}
	if s, _ := web["appVersion"].(string); s == "" {
		t.Errorf("web 1.0.0 entry missing embedded appVersion: %v", web)
	}
	// The unselected prerelease was never collected: only 1.0.0 is indexed.
	if n := len(idx.Entries["web"]); n != 1 {
		t.Errorf("web index has %d versions, want 1: %v", n, idx.Entries["web"])
	}
	// db came through the no-digest path; its digest is recomputed high-side.
	dbEntry := helmFindEntry(t, idx, "db", "0.5.0")
	if got, _ := dbEntry["digest"].(string); got != helmTestSHA256(db) {
		t.Errorf("db 0.5.0 digest = %q, want %q", got, helmTestSHA256(db))
	}

	// The archive downloads with the exact collected bytes.
	if code, got := httpGet(t, srv.URL+"/helm/"+mirror+"/charts/web_1.0.0.tgz"); code != http.StatusOK || got != string(web100) {
		t.Errorf("web archive download: status %d, %d bytes (want %d)", code, len(got), len(web100))
	}

	// The private metadata store is never served.
	if code, _ := httpGet(t, srv.URL+"/helm/"+mirror+"/metadata/web_1.0.0.json"); code != http.StatusNotFound {
		t.Errorf("metadata store must 404, got %d", code)
	}
	// Path traversal is rejected.
	for _, p := range []string{
		"/helm/..%2f..%2fimport-state.json",
		"/helm/" + mirror + "/charts/..%2f..%2fmetadata%2fweb_1.0.0.json",
	} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("traversal %s returned 200, want rejection", p)
		}
	}
	// Non-read methods are rejected.
	resp, err := http.Post(srv.URL+"/helm/"+mirror+"/index.yaml", "application/yaml", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST index.yaml status %d, want 405", resp.StatusCode)
	}
}

// TestHelmCollectDigestTamper proves an upstream whose declared digest does not
// match the served archive is skipped (and reported), and that a sole tampered
// chart fails the whole collect.
func TestHelmCollectDigestTamper(t *testing.T) {
	web := helmTestChartTgz(t, "web", "1.0.0")
	db := helmTestChartTgz(t, "db", "0.5.0")
	repo := fakeHelmRepo(t, []helmTestEntry{
		// web's index digest is for different bytes than are actually served.
		{name: "web", version: "1.0.0", digest: "sha256:" + helmTestSHA256([]byte("not the real chart")), body: web},
		{name: "db", version: "0.5.0", digest: "sha256:" + helmTestSHA256(db), body: db},
	})

	ls, _ := newHelmLowServer(t)
	res, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		URL: repo.URL, Charts: []string{"web@1.0.0", "db@0.5.0"},
	})
	if err != nil {
		t.Fatalf("collect with one good chart should succeed: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Errorf("ExportedModules = %d, want 1 (only db)", res.ExportedModules)
	}
	if len(res.SkippedModules) != 1 || res.SkippedModules[0].Module != "web" {
		t.Fatalf("expected web in SkippedModules, got %+v", res.SkippedModules)
	}
	if !strings.Contains(res.SkippedModules[0].Error, "sha256") {
		t.Errorf("skip reason should mention sha256, got %q", res.SkippedModules[0].Error)
	}

	// The tampered chart on its own leaves nothing to export: hard failure.
	if _, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		URL: repo.URL, Charts: []string{"web@1.0.0"},
	}); err == nil {
		t.Fatal("a tampered sole chart should fail the collect")
	}
}

// TestHelmImportMismatchedChartName documents the high-side guarantee for an
// archive whose embedded Chart.yaml names a different chart than its bundle
// identity: publish logs and skips it, so it is absent from the regenerated
// index.yaml, yet the (SHA-256-verified) archive is still served.
func TestHelmImportMismatchedChartName(t *testing.T) {
	forged := helmTestChartTgzNamed(t, "web", "notweb", "1.0.0")
	repo := fakeHelmRepo(t, []helmTestEntry{
		{name: "web", version: "1.0.0", digest: "sha256:" + helmTestSHA256(forged), body: forged},
	})

	ls, priv := newHelmLowServer(t)
	res, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		Name: "bitnami", URL: repo.URL, Charts: []string{"web@1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectHelm: %v", err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	// Import tolerates the mismatch (the chart is logged and skipped, not fatal).
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import should tolerate a mismatched chart: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// The archive itself is still served (it passed SHA-256 verification).
	if code, got := httpGet(t, srv.URL+"/helm/bitnami/charts/web_1.0.0.tgz"); code != http.StatusOK || got != string(forged) {
		t.Errorf("forged archive should still be served, got status %d", code)
	}
	// But the regenerated index lists no chart.
	code, body := httpGet(t, srv.URL+"/helm/bitnami/index.yaml")
	if code != http.StatusOK {
		t.Fatalf("index.yaml status %d", code)
	}
	var idx helmIndex
	if err := yaml.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatalf("index.yaml is not YAML: %v\n%s", err, body)
	}
	if len(idx.Entries) != 0 {
		t.Errorf("index should be empty after the name mismatch, got %v", idx.Entries)
	}
}

// TestHelmSecondBundleAccumulates imports a second bundle for the same mirror
// (the prerelease) and confirms both versions appear in index.yaml, newest
// first, without clobbering the first bundle's chart.
func TestHelmSecondBundleAccumulates(t *testing.T) {
	web100 := helmTestChartTgz(t, "web", "1.0.0")
	web2b1 := helmTestChartTgz(t, "web", "2.0.0-beta.1")
	repo := fakeHelmRepo(t, []helmTestEntry{
		{name: "web", version: "1.0.0", digest: "sha256:" + helmTestSHA256(web100), body: web100},
		{name: "web", version: "2.0.0-beta.1", digest: "sha256:" + helmTestSHA256(web2b1), body: web2b1},
	})

	ls, priv := newHelmLowServer(t)
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)

	res1, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		Name: "bitnami", URL: repo.URL, Charts: []string{"web@1.0.0"},
	})
	if err != nil {
		t.Fatalf("collect 1: %v", err)
	}
	transferAptBundle(t, ls, hs, res1.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import 1: %v", err)
	}

	res2, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		Name: "bitnami", URL: repo.URL, Charts: []string{"web@2.0.0-beta.1"},
	})
	if err != nil {
		t.Fatalf("collect 2: %v", err)
	}
	if res2.BundleID != "helm-bundle-000002" {
		t.Fatalf("second bundle id = %s, want helm-bundle-000002", res2.BundleID)
	}
	transferAptBundle(t, ls, hs, res2.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import 2: %v", err)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/helm/bitnami/index.yaml")
	if code != http.StatusOK {
		t.Fatalf("index.yaml status %d", code)
	}
	var idx helmIndex
	if err := yaml.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatalf("index.yaml is not YAML: %v\n%s", err, body)
	}
	if got := helmEntryVersions(idx, "web"); len(got) != 2 || got[0] != "2.0.0-beta.1" || got[1] != "1.0.0" {
		t.Errorf("web versions = %v, want [2.0.0-beta.1 1.0.0] (newest first)", got)
	}
	for _, f := range []string{"web_1.0.0.tgz", "web_2.0.0-beta.1.tgz"} {
		if code, _ := httpGet(t, srv.URL+"/helm/bitnami/charts/"+f); code != http.StatusOK {
			t.Errorf("archive %s not served, got %d", f, code)
		}
	}
}

// TestHelmAdversarialNameVersionNoCollision is the regression test for the
// flattened-key collision: chart "a-1" at 1.0.0 and chart "a" at 1-1.0.0 both
// flatten to "a-1-1.0.0" under a '-'-joined key, letting one silently
// overwrite the other's archive and metadata. With the '_'-joined canonical
// stem they must be collected, indexed, and served as two distinct charts.
func TestHelmAdversarialNameVersionNoCollision(t *testing.T) {
	first := helmTestChartTgz(t, "a-1", "1.0.0")
	second := helmTestChartTgz(t, "a", "1-1.0.0")
	repo := fakeHelmRepo(t, []helmTestEntry{
		{name: "a-1", version: "1.0.0", digest: "sha256:" + helmTestSHA256(first), body: first, url: "pool/first.tgz"},
		{name: "a", version: "1-1.0.0", digest: "sha256:" + helmTestSHA256(second), body: second, url: "pool/second.tgz"},
	})

	ls, priv := newHelmLowServer(t)
	res, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		Name: "hostile", URL: repo.URL, Charts: []string{"a-1@1.0.0", "a@1-1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectHelm: %v", err)
	}
	if res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("both charts must survive the collect: %+v", res)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/helm/hostile/index.yaml")
	if code != http.StatusOK {
		t.Fatalf("index.yaml status %d", code)
	}
	var idx helmIndex
	if err := yaml.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatalf("index.yaml is not YAML: %v\n%s", err, body)
	}
	// Both identities are indexed, each with its own digest.
	e1 := helmFindEntry(t, idx, "a-1", "1.0.0")
	if got, _ := e1["digest"].(string); got != helmTestSHA256(first) {
		t.Errorf("a-1 digest = %q, want %q (clobbered by the colliding chart?)", got, helmTestSHA256(first))
	}
	e2 := helmFindEntry(t, idx, "a", "1-1.0.0")
	if got, _ := e2["digest"].(string); got != helmTestSHA256(second) {
		t.Errorf("a digest = %q, want %q (clobbered by the colliding chart?)", got, helmTestSHA256(second))
	}
	// Each archive is served under its own canonical name with its own bytes.
	if code, got := httpGet(t, srv.URL+"/helm/hostile/charts/a-1_1.0.0.tgz"); code != http.StatusOK || got != string(first) {
		t.Errorf("a-1 archive: status %d, wrong bytes (%d)", code, len(got))
	}
	if code, got := httpGet(t, srv.URL+"/helm/hostile/charts/a_1-1.0.0.tgz"); code != http.StatusOK || got != string(second) {
		t.Errorf("a archive: status %d, wrong bytes (%d)", code, len(got))
	}
	// The dashboard resolves each identity to its own metadata.
	for _, spec := range []struct{ chart, version string }{{"a-1", "1.0.0"}, {"a", "1-1.0.0"}} {
		d, err := hs.helmDetail("hostile/" + spec.chart + "@" + spec.version)
		if err != nil || d.Title != spec.chart || d.Subtitle != spec.version {
			t.Errorf("detail %s@%s = %+v, %v", spec.chart, spec.version, d, err)
		}
	}
}

// -----------------------------------------------------------------------------
// Admin endpoint and dashboard wiring
// -----------------------------------------------------------------------------

// TestHelmCollectAdmin drives the low-side POST /admin/helm/collect endpoint
// end to end and confirms the empty-request rejection.
func TestHelmCollectAdmin(t *testing.T) {
	web := helmTestChartTgz(t, "web", "1.0.0")
	repo := fakeHelmRepo(t, []helmTestEntry{
		{name: "web", version: "1.0.0", digest: "sha256:" + helmTestSHA256(web), body: web},
	})
	ls, _ := newHelmLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	body := fmt.Sprintf(`{"name":"bitnami","url":%q,"charts":["web@1.0.0"]}`, repo.URL)
	resp, err := http.Post(srv.URL+"/admin/helm/collect", "application/json", strings.NewReader(body)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect status %d, want 200: %s", resp.StatusCode, b)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "helm-bundle-000001" || res.ExportedModules != 1 {
		t.Errorf("unexpected collect result: %+v", res)
	}

	bad, err := http.Post(srv.URL+"/admin/helm/collect", "application/json", strings.NewReader(`{}`)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("empty collect status %d, want 400", bad.StatusCode)
	}
}

// TestHelmTreeAndDetail exercises the high-side dashboard tree (mirror -> chart
// -> versions) and the per-version detail panel for an imported chart.
func TestHelmTreeAndDetail(t *testing.T) {
	web := helmTestChartTgz(t, "web", "1.0.0")
	repo := fakeHelmRepo(t, []helmTestEntry{
		{name: "web", version: "1.0.0", digest: "sha256:" + helmTestSHA256(web), body: web},
	})
	ls, priv := newHelmLowServer(t)
	res, err := ls.CollectHelm(context.Background(), HelmCollectRequest{
		Name: "bitnami", URL: repo.URL, Charts: []string{"web@1.0.0"},
	})
	if err != nil {
		t.Fatalf("CollectHelm: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	steps := []struct{ path, want string }{
		{"", `"bitnami"`},        // root: mirrors
		{"bitnami", `"web"`},     // mirror: charts
		{"bitnami/web", "1.0.0"}, // chart: versions
	}
	for _, st := range steps {
		code, body := httpGet(t, srv.URL+"/ui/api/tree?eco=helm&path="+st.path)
		if code != http.StatusOK || !strings.Contains(body, st.want) {
			t.Errorf("helm tree at %q: status %d missing %s: %s", st.path, code, st.want, body)
		}
	}

	code, body := httpGet(t, srv.URL+"/ui/api/detail?eco=helm&path=bitnami/web@1.0.0")
	if code != http.StatusOK {
		t.Fatalf("helm detail status %d body %q", code, body)
	}
	var d UIDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	if d.Title != "web" || d.Subtitle != "1.0.0" {
		t.Errorf("helm detail title/subtitle = %q/%q, want web/1.0.0", d.Title, d.Subtitle)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/helm/bitnami/charts/web_1.0.0.tgz" {
		t.Errorf("helm detail downloads = %+v", d.Downloads)
	}
	if code, _ := httpGet(t, srv.URL+"/ui/api/detail?eco=helm&path=bitnami/web@9.9.9"); code != http.StatusNotFound {
		t.Errorf("missing version detail should 404, got %d", code)
	}
}

// TestHelmDetailLegacyStemFallback: metadata written before the
// collision-safe stem lives under "<name>-<version>.json". The detail lookup
// still resolves it — but only for the chart whose embedded identity matches,
// so the ambiguous legacy key can never answer for a colliding sibling.
func TestHelmDetailLegacyStemFallback(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	chartsDir := filepath.Join(hs.helmDir(), "legacy", "charts")
	metaDir := filepath.Join(hs.helmDir(), "legacy", "metadata")
	for _, d := range []string{chartsDir, metaDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A pre-fix import of chart "a" version "1-1.0.0": stem and archive name
	// were both '-'-joined.
	writeFile(t, filepath.Join(chartsDir, "a-1-1.0.0.tgz"), []byte("legacy archive"))
	st := helmStoredChart{
		Filename: "a-1-1.0.0.tgz",
		Digest:   "d",
		Metadata: map[string]any{"name": "a", "version": "1-1.0.0"},
	}
	if err := writeJSONAtomic(filepath.Join(metaDir, "a-1-1.0.0.json"), st, 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := hs.helmDetail("legacy/a@1-1.0.0")
	if err != nil || d.Title != "a" || d.Subtitle != "1-1.0.0" {
		t.Fatalf("legacy detail = %+v, %v; want chart a@1-1.0.0", d, err)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/helm/legacy/charts/a-1-1.0.0.tgz" {
		t.Errorf("legacy downloads = %+v", d.Downloads)
	}
	// The same legacy stem is what chart "a-1" at 1.0.0 would look up — the
	// identity check must refuse to answer for it.
	if _, err := hs.helmDetail("legacy/a-1@1.0.0"); err == nil {
		t.Error("legacy stem must not answer for the colliding sibling chart")
	}
}
