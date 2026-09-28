package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type npmMetadataReply struct {
	status int
	body   string
}

type npmMetadataFixture struct {
	low      *LowServer
	high     *HighServer
	priv     ed25519.PrivateKey
	registry *httptest.Server
	reply    atomic.Pointer[npmMetadataReply]
	tarballs map[string][]byte
}

func newNpmMetadataFixture(t *testing.T) *npmMetadataFixture {
	t.Helper()
	fx := &npmMetadataFixture{tarballs: map[string][]byte{}}
	mux := http.NewServeMux()
	for _, pkg := range []struct{ name, version string }{
		{name: "tagpkg", version: "1.0.0"},
		{name: "tagpkg", version: "2.0.0"},
		{name: "otherpkg", version: "1.0.0"},
	} {
		data := makeNpmTgz(t, "package", pkg.name, pkg.version)
		fx.tarballs[pkg.name+"@"+pkg.version] = data
		mux.HandleFunc("/"+pkg.name+"/-/"+npmTarballFilename(pkg.name, pkg.version), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(data)
		})
	}
	mux.HandleFunc("/otherpkg", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"}}`))
	})
	mux.HandleFunc("/tagpkg", func(w http.ResponseWriter, _ *http.Request) {
		reply := fx.reply.Load()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.status)
		_, _ = w.Write([]byte(reply.body))
	})
	fx.setTags(t, map[string]string{"latest": "1.0.0"})
	fx.registry = httptest.NewServer(mux)
	t.Cleanup(fx.registry.Close)
	_, fx.priv = newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}
	var err error
	fx.low, err = NewLowServer(cfg, fx.priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fx.low.Close() })
	fx.high = newTestHighServer(t, fx.priv.Public().(ed25519.PublicKey))
	fx.selectVersions(t, "1.0.0", "2.0.0")
	return fx
}

func (fx *npmMetadataFixture) setTags(t *testing.T, tags map[string]string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": "tagpkg", "dist-tags": tags})
	if err != nil {
		t.Fatal(err)
	}
	fx.reply.Store(&npmMetadataReply{status: http.StatusOK, body: string(body)})
}

func (fx *npmMetadataFixture) selectVersions(t *testing.T, versions ...string) {
	t.Helper()
	fx.selectPackages(t, map[string][]string{"tagpkg": versions})
}

func (fx *npmMetadataFixture) selectPackages(t *testing.T, packages map[string][]string) {
	t.Helper()
	pkgs := map[string]npmLockPackage{}
	for name, versions := range packages {
		for _, version := range versions {
			pkgs[fmt.Sprintf("node_modules/p%d", len(pkgs))] = npmLockPackage{
				Name: name, Version: version,
				Resolved:  fx.registry.URL + "/" + name + "/-/" + npmTarballFilename(name, version),
				Integrity: sriFor(fx.tarballs[name+"@"+version]),
			}
		}
	}
	lock, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": pkgs})
	if err != nil {
		t.Fatal(err)
	}
	fx.low.cfg.NpmBinary = writeFakeNpm(t, string(lock))
}

func (fx *npmMetadataFixture) collect(t *testing.T) ExportResult {
	t.Helper()
	result, err := fx.low.CollectNpm(t.Context(), NpmCollectRequest{Packages: []string{"tagpkg"}})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return result
}

func (fx *npmMetadataFixture) importBundle(t *testing.T, result ExportResult, sequence int64, prior int) {
	t.Helper()
	if result.Skipped || result.Sequence != sequence || result.PriorFiles != prior {
		t.Fatalf("collect = %+v, want sequence %d with %d prior files", result, sequence, prior)
	}
	manifest := readBundleManifest(t, fx.low, result.BundleID)
	if manifest.Npm == nil || len(manifest.Npm.Packages) == 0 {
		t.Fatal("bundle has no npm package records")
	}
	if prior > 0 {
		assertNpmMetadataOnlyArchive(t, fx.low, result.BundleID, manifest.Files)
	}
	transferAptBundle(t, fx.low, fx.high, result.BundleID)
	if _, err := fx.high.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}
}

func assertNpmMetadataOnlyArchive(t *testing.T, low *LowServer, bundleID string, files []ManifestFile) {
	t.Helper()
	for _, file := range files {
		if !file.Prior {
			t.Errorf("metadata-only bundle redelivers %s", file.Path)
		}
	}
	if entries := listArchiveEntries(t, low.cfg.ExportDir, bundleID); len(entries) != 0 {
		t.Errorf("metadata-only archive contains files: %v", entries)
	}
}

func (fx *npmMetadataFixture) assertTags(t *testing.T, want map[string]string) {
	t.Helper()
	rec := httptest.NewRecorder()
	fx.high.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/tagpkg", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("packument status %d: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Tags map[string]string `json:"dist-tags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(doc.Tags, want) {
		t.Fatalf("served tags = %v, want %v", doc.Tags, want)
	}
}

func (fx *npmMetadataFixture) assertSkipped(t *testing.T, sequence int64) {
	t.Helper()
	res := fx.collect(t)
	if !res.Skipped || res.Sequence != 0 || res.BundleID != "" {
		t.Fatalf("unchanged collect = %+v, want skipped", res)
	}
	if next := fx.low.peekSequence(streamNpm); next != sequence {
		t.Fatalf("next sequence = %d, want %d", next, sequence)
	}
}

func TestCollectNpmMetadataTagUpdates(t *testing.T) {
	fx := newNpmMetadataFixture(t)
	fx.importBundle(t, fx.collect(t), 1, 0)
	fx.assertTags(t, map[string]string{"latest": "1.0.0"})
	cases := []struct {
		name   string
		tags   map[string]string
		served map[string]string
	}{
		{name: "add", tags: map[string]string{"latest": "1.0.0", "stable": "1.0.0"}},
		{name: "move", tags: map[string]string{"latest": "2.0.0", "stable": "1.0.0"}},
		{name: "return to earlier snapshot", tags: map[string]string{"latest": "1.0.0", "stable": "1.0.0"}},
		{name: "remove", tags: map[string]string{"latest": "1.0.0"}},
		{name: "empty", tags: map[string]string{}, served: map[string]string{"latest": "2.0.0"}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx.setTags(t, tc.tags)
			sequence := int64(i + 2)
			fx.importBundle(t, fx.collect(t), sequence, 2)
			want := tc.tags
			if tc.served != nil {
				want = tc.served
			}
			fx.assertTags(t, want)
			fx.assertSkipped(t, sequence+1)
		})
	}
}

func TestCollectNpmMetadataSubsetAndRestart(t *testing.T) {
	fx := newNpmMetadataFixture(t)
	fx.importBundle(t, fx.collect(t), 1, 0)
	fx.selectVersions(t, "1.0.0")
	fx.assertSkipped(t, 2)

	// The new tag targets a version already mirrored, outside this collect.
	fx.setTags(t, map[string]string{"latest": "2.0.0", "stable": "1.0.0", "next": "3.0.0"})
	fx.importBundle(t, fx.collect(t), 2, 1)
	want := map[string]string{"latest": "2.0.0", "stable": "1.0.0"}
	fx.assertTags(t, want)
	if err := fx.low.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	fx.low, err = NewLowServer(fx.low.cfg, fx.priv)
	if err != nil {
		t.Fatal(err)
	}
	fx.high, err = NewHighServer(fx.high.cfg, fx.priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	fx.assertTags(t, want)
	for _, version := range []string{"1.0.0", "2.0.0"} {
		fx.selectVersions(t, version)
		fx.assertSkipped(t, 3)
	}
	fx.selectVersions(t, "1.0.0", "2.0.0")
	fx.assertSkipped(t, 3)
}

func TestCollectNpmMetadataMissingPreservesTags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "HTTP failure", status: http.StatusServiceUnavailable},
		{name: "not found", status: http.StatusNotFound},
		{name: "invalid JSON", status: http.StatusOK, body: "{"},
		{name: "missing tags", status: http.StatusOK, body: `{"name":"tagpkg"}`},
		{name: "null tags", status: http.StatusOK, body: `{"dist-tags":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newNpmMetadataFixture(t)
			want := map[string]string{"latest": "1.0.0", "stable": "1.0.0"}
			fx.setTags(t, want)
			fx.selectVersions(t, "1.0.0")
			fx.importBundle(t, fx.collect(t), 1, 0)
			fx.reply.Store(&npmMetadataReply{status: tc.status, body: tc.body})
			fx.assertSkipped(t, 2)
			fx.selectVersions(t, "2.0.0")
			fx.importBundle(t, fx.collect(t), 2, 0)
			fx.assertTags(t, want)
			fx.setTags(t, want)
			fx.assertSkipped(t, 3)
		})
	}
}

func TestCollectNpmMetadataDryRunAndForce(t *testing.T) {
	fx := newNpmMetadataFixture(t)
	fx.importBundle(t, fx.collect(t), 1, 0)
	fx.setTags(t, map[string]string{"latest": "2.0.0"})
	req := NpmCollectRequest{Packages: []string{"tagpkg"}}
	dry, err := fx.low.CollectNpm(withDryRunCollect(t.Context()), req)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || dry.Skipped || dry.BundleID != "" || dry.Sequence != 0 || dry.Estimate == nil {
		t.Fatalf("metadata dry run = %+v, want an export estimate without a bundle", dry)
	}
	if dry.PriorFiles != 2 || dry.Estimate.NewFiles != 0 || dry.Estimate.NewBytes != 0 || dry.Estimate.Bundles != 1 {
		t.Fatalf("metadata dry run estimate = %+v, want one bundle with two prior files", dry)
	}
	fx.importBundle(t, fx.collect(t), 2, 2)
	fx.assertSkipped(t, 3)
	req.Force = true
	forced, err := fx.low.CollectNpm(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if entries := listArchiveEntries(t, fx.low.cfg.ExportDir, forced.BundleID); len(entries) != 2 {
		t.Fatalf("forced bundle entries = %v, want both tarballs", entries)
	}
	fx.importBundle(t, forced, 3, 0)
	fx.assertTags(t, map[string]string{"latest": "2.0.0"})
}

func TestCollectNpmMetadataFailedExportRetry(t *testing.T) {
	fx := newNpmMetadataFixture(t)
	fx.importBundle(t, fx.collect(t), 1, 0)
	fx.setTags(t, map[string]string{"latest": "2.0.0"})
	out := fx.low.cfg.ExportDir
	blocker := filepath.Join(t.TempDir(), "blocked-export")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx.low.cfg.ExportDir = blocker
	_, err := fx.low.CollectNpm(t.Context(), NpmCollectRequest{Packages: []string{"tagpkg"}})
	fx.low.cfg.ExportDir = out
	if err == nil {
		t.Fatal("metadata export succeeded with an unusable export directory")
	}
	if sequence := fx.low.peekSequence(streamNpm); sequence != 2 {
		t.Fatalf("failed metadata export advanced next sequence to %d", sequence)
	}
	fx.importBundle(t, fx.collect(t), 2, 2)
	fx.assertTags(t, map[string]string{"latest": "2.0.0"})
	fx.assertSkipped(t, 3)
}

func TestCollectNpmMetadataIndependentPackages(t *testing.T) {
	fx := newNpmMetadataFixture(t)
	fx.selectPackages(t, map[string][]string{"tagpkg": {"1.0.0"}, "otherpkg": {"1.0.0"}})
	fx.importBundle(t, fx.collect(t), 1, 0)
	fx.selectVersions(t, "1.0.0")
	fx.setTags(t, map[string]string{"latest": "1.0.0", "stable": "1.0.0"})
	fx.importBundle(t, fx.collect(t), 2, 1)
	fx.selectPackages(t, map[string][]string{"otherpkg": {"1.0.0"}})
	fx.assertSkipped(t, 3)
	fx.selectVersions(t, "1.0.0")
	fx.assertSkipped(t, 3)
}
