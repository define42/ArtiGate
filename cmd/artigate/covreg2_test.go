package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// covR2WriteFile writes b to p, creating parent directories first.
func covR2WriteFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, b)
}

// -----------------------------------------------------------------------------
// Pure parsers / helpers (container.go + hf.go)
// -----------------------------------------------------------------------------

func TestCovR2_WildcardToRange(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.26.x", ">= 1.26.0, < 1.27.0"},
		{"1.x", ">= 1.0.0, < 2.0.0"},
		{"v2.x", ">= 2.0.0, < 3.0.0"},    // "v" prefix stripped
		{"1.2.3.x", ">= 1.2.3, < 1.2.4"}, // a 4th component clamps the bump to index 2
		{"x", ">= 0"},                    // no fixed components
	}
	for _, tc := range cases {
		if got := wildcardToRange(tc.in); got != tc.want {
			t.Errorf("wildcardToRange(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A non-numeric fixed component is unreachable through the wildcard RE, but
	// the direct guard returns the pattern unchanged (fails later in parsing).
	if got := wildcardToRange("a.x"); got != "a.x" {
		t.Errorf("wildcardToRange(a.x) = %q, want the pattern unchanged", got)
	}
}

func TestCovR2_ParseContainerCollectRefs(t *testing.T) {
	if _, err := parseContainerCollectRefs(nil); err == nil {
		t.Error("empty image list should be rejected")
	}
	if _, err := parseContainerCollectRefs([]string{"  ", ""}); err == nil {
		t.Error("whitespace-only image list should be rejected")
	}
	if _, err := parseContainerCollectRefs([]string{"NOTVALID UPPER"}); err == nil {
		t.Error("unparseable reference should be rejected")
	}
	refs, err := parseContainerCollectRefs([]string{"alpine:3.20", "alpine:3.20", " ", "ghcr.io/org/app:v1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("deduped refs = %+v, want 2", refs)
	}
}

func TestCovR2_ValidateContainerRepoErrors(t *testing.T) {
	digest := containerSHA([]byte("m"))
	blob := containerSHA([]byte("b"))
	good := ContainerRepo{
		Registry: "docker.io", Repository: "library/alpine",
		Images: []ContainerImage{{Tag: "3.20", Digest: digest, MediaType: mtDockerManifest, Blobs: []ContainerBlob{{Digest: blob, Size: 1}}}},
	}
	files := []ManifestFile{
		{Path: containerBlobRel(digest), SHA256: strings.TrimPrefix(digest, "sha256:"), Size: 1},
		{Path: containerBlobRel(blob), SHA256: strings.TrimPrefix(blob, "sha256:"), Size: 1},
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.Path] = true
	}

	badReg := good
	badReg.Registry = "Bad Registry"
	badRepo := good
	badRepo.Repository = "../escape"
	noImages := good
	noImages.Images = nil
	for _, bad := range []ContainerRepo{badReg, badRepo, noImages} {
		if err := validateContainerRepos([]ContainerRepo{bad}, seen, files); err == nil {
			t.Errorf("repo %+v must be rejected", bad)
		}
	}
	if err := validateContainerRepos([]ContainerRepo{good}, seen, files); err != nil {
		t.Fatalf("valid repo rejected: %v", err)
	}
}

func TestCovR2_ParseHFRepoInfo(t *testing.T) {
	ref := hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "main"}
	commit := strings.Repeat("ab", 20)
	oid := strings.Repeat("cd", 32)

	body := []byte(`{"sha":"` + commit + `","siblings":[` +
		`{"rfilename":"config.json","size":10},` +
		`{"rfilename":"model.bin","size":1,"lfs":{"oid":"` + oid + `","size":4096}}]}`)
	gotCommit, files, err := parseHFRepoInfo(ref, body)
	if err != nil {
		t.Fatalf("parseHFRepoInfo: %v", err)
	}
	if gotCommit != commit || len(files) != 2 {
		t.Fatalf("commit=%q files=%+v", gotCommit, files)
	}
	// Files are sorted; the LFS entry carries the upstream oid and the LFS size.
	byPath := map[string]hfRepoFileMeta{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	if byPath["model.bin"].LFS != oid || byPath["model.bin"].Size != 4096 {
		t.Errorf("lfs file = %+v", byPath["model.bin"])
	}
	if byPath["config.json"].LFS != "" {
		t.Errorf("non-lfs file should carry no oid: %+v", byPath["config.json"])
	}

	bad := [][]byte{
		[]byte(`{`),                            // unparseable JSON
		[]byte(`{"sha":"nope","siblings":[]}`), // no commit hash
		[]byte(`{"sha":"` + commit + `","siblings":[{"rfilename":"../evil"}]}`), // unsafe path
		[]byte(`{"sha":"` + commit + `","siblings":[]}`),                        // no files
	}
	for _, b := range bad {
		if _, _, err := parseHFRepoInfo(ref, b); err == nil {
			t.Errorf("parseHFRepoInfo(%s) should fail", b)
		}
	}
}

func TestCovR2_ParseHFCollectRequest(t *testing.T) {
	if _, _, err := parseHFCollectRequest(HFCollectRequest{}); err == nil {
		t.Error("empty request should be rejected")
	}
	if _, _, err := parseHFCollectRequest(HFCollectRequest{Models: []string{"  "}, Repos: []string{""}}); err == nil {
		t.Error("whitespace-only request should be rejected")
	}
	if _, _, err := parseHFCollectRequest(HFCollectRequest{Models: []string{"not a ref"}}); err == nil {
		t.Error("unparseable model should be rejected")
	}
	if _, _, err := parseHFCollectRequest(HFCollectRequest{Repos: []string{"nohost"}}); err == nil {
		t.Error("unparseable repo should be rejected")
	}
	refs, repoRefs, err := parseHFCollectRequest(HFCollectRequest{
		Models: []string{"unsloth/m-GGUF:Q4_0", "unsloth/m-GGUF:Q4_0"},
		Repos:  []string{"openai/gpt-oss-20b", "openai/gpt-oss-20b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || len(repoRefs) != 1 {
		t.Fatalf("deduped = %d models, %d repos", len(refs), len(repoRefs))
	}
}

func TestCovR2_ValidateHFRepoErrors(t *testing.T) {
	config := []byte("config-bytes")
	rel := hfBlobRel(containerSHA(config))
	seen := map[string]bool{rel: true}
	shaByPath := map[string]string{rel: hexSHA(config)}

	good := HFRepo{
		Org: "openai", Name: "gpt-oss-20b", Revision: strings.Repeat("ab", 20), Ref: "main",
		Files: []HFRepoFile{{Path: "config.json", SHA256: hexSHA(config), Size: int64(len(config))}},
	}
	if err := validateHFRepo(good, seen, shaByPath); err != nil {
		t.Fatalf("valid repo rejected: %v", err)
	}

	badOrg := good
	badOrg.Org = ".bad"
	badName := good
	badName.Name = "a/b"
	badRef := good
	badRef.Ref = "bad ref"
	badSHA := good
	badSHA.Files = []HFRepoFile{{Path: "config.json", SHA256: "nothex", Size: 1}}
	mismatch := good
	mismatch.Files = []HFRepoFile{{Path: "config.json", SHA256: strings.Repeat("00", 32), Size: 1}}
	for _, bad := range []HFRepo{badOrg, badName, badRef, badSHA, mismatch} {
		if err := validateHFRepo(bad, seen, shaByPath); err == nil {
			t.Errorf("repo %+v must be rejected", bad)
		}
	}
}

func TestCovR2_HFIndexNames(t *testing.T) {
	// A missing root is not an error — it just has no entries.
	names, err := hfIndexNames(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil || names != nil {
		t.Fatalf("hfIndexNames(missing) = %v, %v", names, err)
	}
	root := t.TempDir()
	covR2WriteFile(t, filepath.Join(root, "org", "modelA", "_index.json"), []byte("{}"))
	covR2WriteFile(t, filepath.Join(root, "org", "modelB", "_index.json"), []byte("{}"))
	covR2WriteFile(t, filepath.Join(root, "org", "modelB", "not-an-index.json"), []byte("{}"))
	names, err = hfIndexNames(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "org/modelA" || names[1] != "org/modelB" {
		t.Fatalf("hfIndexNames = %+v", names)
	}
}

// -----------------------------------------------------------------------------
// Low side: container registry client error paths
// -----------------------------------------------------------------------------

func TestCovR2_FetchToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/err", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusInternalServerError) })
	mux.HandleFunc("/garbage", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	mux.HandleFunc("/empty", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	mux.HandleFunc("/access", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"access_token":"acc"}`)) })
	mux.HandleFunc("/tok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"token":"good"}`)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{})
	c := ls.newContainerClient()
	ctx := context.Background()

	// A non-Bearer challenge is rejected by parseBearerChallenge.
	if _, err := c.fetchToken(ctx, `Basic realm="x"`, "org/app", nil); err == nil {
		t.Error("Basic challenge should fail")
	}
	challenge := func(path string) string {
		return `Bearer realm="` + srv.URL + path + `",service="svc"`
	}
	for _, path := range []string{"/err", "/garbage", "/empty"} {
		if _, err := c.fetchToken(ctx, challenge(path), "org/app", nil); err == nil {
			t.Errorf("token endpoint %s should fail", path)
		}
	}
	// The access_token field is used when token is absent.
	if tok, err := c.fetchToken(ctx, challenge("/access"), "org/app", nil); err != nil || tok != "acc" {
		t.Fatalf("access_token fallback = %q, %v", tok, err)
	}
	// A challenge without a scope makes fetchToken synthesize a pull scope.
	if tok, err := c.fetchToken(ctx, `Bearer realm="`+srv.URL+`/tok"`, "org/app", nil); err != nil || tok != "good" {
		t.Fatalf("token = %q, %v", tok, err)
	}
}

func TestCovR2_ContainerGetRetry(t *testing.T) {
	// org/loop always answers 401 (even with a token) but points at a working
	// token endpoint; get exhausts its one retry and reports the final
	// unauthorized. org/basic answers 401 with a Basic challenge, which needs a
	// login that this anonymous client does not have.
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]string{"token": "t"}) })
	mux.HandleFunc("/v2/org/loop/manifests/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="svc"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	mux.HandleFunc("/v2/org/basic/manifests/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	c := ls.newContainerClient()

	if _, err := c.get(context.Background(), imageRef{Registry: "example.com", Repository: "org/loop"}, "manifests/x", ""); err == nil {
		t.Error("a registry that stays 401 after a token should fail")
	}
	if _, err := c.get(context.Background(), imageRef{Registry: "example.com", Repository: "org/basic"}, "manifests/x", ""); err == nil {
		t.Error("a Basic challenge without a login should fail")
	}
}

func TestCovR2_FetchTagPageErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/boom/tags/list", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusInternalServerError) })
	mux.HandleFunc("/v2/org/garbage/tags/list", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	c := ls.newContainerClient()
	if _, _, err := c.fetchTagPage(context.Background(), imageRef{Registry: "example.com", Repository: "org/boom"}, "tags/list"); err == nil {
		t.Error("HTTP 500 tags/list should fail")
	}
	if _, _, err := c.fetchTagPage(context.Background(), imageRef{Registry: "example.com", Repository: "org/garbage"}, "tags/list"); err == nil {
		t.Error("unparseable tags/list should fail")
	}
}

func TestCovR2_DownloadContainerBlob(t *testing.T) {
	content := []byte("covr2-blob")
	digest := containerSHA(content)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/app/blobs/"+digest, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(content) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	c := ls.newContainerClient()
	ref := imageRef{Registry: "example.com", Repository: "org/app", Tag: "t"}
	ctx := context.Background()
	stage := t.TempDir()
	good := ociDescriptor{Digest: digest, Size: int64(len(content))}

	// Bad digest and missing size are rejected before any fetch.
	if _, err := c.downloadContainerBlob(ctx, ref, ociDescriptor{Digest: "sha256:zz", Size: 1}, stage, map[string]bool{}, false); err == nil {
		t.Error("bad digest should fail")
	}
	if _, err := c.downloadContainerBlob(ctx, ref, ociDescriptor{Digest: digest, Size: 0}, stage, map[string]bool{}, false); err == nil {
		t.Error("zero size should fail")
	}
	// An already-staged blob is returned without a download.
	rel := containerBlobRel(digest)
	if mf, err := c.downloadContainerBlob(ctx, ref, good, stage, map[string]bool{rel: true}, false); err != nil || mf.Path != rel {
		t.Fatalf("staged blob = %+v, %v", mf, err)
	}
	// A prior-forwarded blob is skipped and marked Prior when allowPrior is set.
	c.prior = func(string, string) bool { return true }
	if mf, err := c.downloadContainerBlob(ctx, ref, good, stage, map[string]bool{}, true); err != nil || !mf.Prior {
		t.Fatalf("prior blob = %+v, %v", mf, err)
	}
	c.prior = nil
	// A real download succeeds and lands the verified bytes.
	if mf, err := c.downloadContainerBlob(ctx, ref, good, stage, map[string]bool{}, false); err != nil {
		t.Fatalf("download: %v", err)
	} else if b, _ := os.ReadFile(filepath.Join(stage, filepath.FromSlash(mf.Path))); string(b) != string(content) {
		t.Fatalf("staged content = %q", b)
	}
	// A missing blob (404) fails.
	missing := containerSHA([]byte("nope"))
	if _, err := c.downloadContainerBlob(ctx, ref, ociDescriptor{Digest: missing, Size: 4}, stage, map[string]bool{}, false); err == nil {
		t.Error("404 blob should fail")
	}
}

func TestCovR2_MirrorContainerImageErrors(t *testing.T) {
	mux := http.NewServeMux()
	// A manifest whose body is not JSON (but a manifest Content-Type) parses in
	// fetchManifestRaw yet fails the mirror's own unmarshal.
	mux.HandleFunc("/v2/org/badjson/manifests/t", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mtDockerManifest)
		_, _ = w.Write([]byte("not json"))
	})
	// A well-formed manifest that lists no config/layers.
	mux.HandleFunc("/v2/org/empty/manifests/t", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mtDockerManifest)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"` + mtDockerManifest + `","config":{"digest":""},"layers":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	c := ls.newContainerClient()
	stage := t.TempDir()
	for _, repo := range []string{"org/badjson", "org/empty"} {
		ref := imageRef{Registry: "example.com", Repository: repo, Tag: "t"}
		if _, _, err := c.mirrorContainerImage(context.Background(), ref, stage, map[string]bool{}); err == nil {
			t.Errorf("%s should fail to mirror", repo)
		}
	}
}

func TestCovR2_StageContainerManifestBlobSeen(t *testing.T) {
	stage := t.TempDir()
	body := []byte("manifest-bytes")
	digest := containerSHA(body)
	rel := containerBlobRel(digest)
	// A manifest already staged is returned without another write.
	mf, err := stageContainerManifestBlob(stage, digest, body, map[string]bool{rel: true})
	if err != nil || mf.Path != rel {
		t.Fatalf("seen manifest = %+v, %v", mf, err)
	}
	if fileExists(filepath.Join(stage, filepath.FromSlash(rel))) {
		t.Error("seen manifest should not have been written")
	}
}

func TestCovR2_CollectContainersErrors(t *testing.T) {
	ls, _ := newContainerLowServer(t, map[string]string{})
	// A parse failure short-circuits before any staging.
	if _, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{}); err == nil {
		t.Error("empty collect should fail")
	}
	// An unreachable registry means nothing can be fetched.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }))
	t.Cleanup(dead.Close)
	ls2, _ := newContainerLowServer(t, map[string]string{"docker.io": dead.URL})
	if _, err := ls2.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"alpine:3.20"}}); err == nil {
		t.Error("collect against a 404 registry should fail")
	}
}

// -----------------------------------------------------------------------------
// High side: container serving + dashboard error paths
// -----------------------------------------------------------------------------

func TestCovR2_HandleContainerManifestAndResource(t *testing.T) {
	hs, alpine, _ := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Unknown repository and unknown tag.
	assertHTTPStatus(t, srv.URL+"/v2/docker.io/library/nope/manifests/3.20", http.StatusNotFound)
	assertHTTPStatus(t, srv.URL+"/v2/docker.io/library/alpine/manifests/nosuch", http.StatusNotFound)

	// A HEAD returns headers with no body.
	headReq, _ := http.NewRequest(http.MethodHead, srv.URL+"/v2/docker.io/library/alpine/manifests/3.20", nil) //nolint:noctx // test request
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK || headResp.Header.Get("Docker-Content-Digest") != alpine.manifestDigest {
		t.Fatalf("HEAD manifest = %d %q", headResp.StatusCode, headResp.Header.Get("Docker-Content-Digest"))
	}

	// A repository whose manifest blob was removed reports a missing blob.
	_ = os.Remove(hs.containerBlobPath(alpine.manifestDigest))
	assertHTTPStatus(t, srv.URL+"/v2/docker.io/library/alpine/manifests/3.20", http.StatusNotFound)

	// handleContainerResource routing edge cases.
	assertHTTPStatus(t, srv.URL+"/v2/single/tags/list", http.StatusNotFound)   // invalid (one-segment) name
	assertHTTPStatus(t, srv.URL+"/v2/single/manifests/x", http.StatusNotFound) // invalid name on manifests
	assertHTTPStatus(t, srv.URL+"/v2/foo/bar/unknownroute", http.StatusNotFound)
}

func TestCovR2_HandleContainerCatalogEmpty(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	code, body := httpGet(t, srv.URL+"/v2/_catalog")
	if code != http.StatusOK || !strings.Contains(body, `"repositories"`) || !strings.Contains(body, "[]") {
		t.Fatalf("_catalog on empty server = %d %q", code, body)
	}
	// listContainerRepoNames over a missing tree returns no names.
	names, err := hs.listContainerRepoNames()
	if err != nil || len(names) != 0 {
		t.Fatalf("listContainerRepoNames(empty) = %+v, %v", names, err)
	}
}

func TestCovR2_ContainerDetailErrors(t *testing.T) {
	hs, _, _ := collectAndImportContainers(t)
	for _, spec := range []string{
		"no-at-sign",                      // no '@'
		"BAD NAME@3.20",                   // invalid repository name
		"docker.io/library/nope@3.20",     // unknown repository
		"docker.io/library/alpine@nosuch", // unknown tag
		"docker.io/library/alpine@",       // empty ref
	} {
		if _, err := hs.containerDetail(spec); err == nil {
			t.Errorf("containerDetail(%q) should fail", spec)
		}
	}
}

func TestCovR2_ContainerImageLayersFallbacks(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// No blobs -> no layers box.
	if got := hs.containerImageLayers(ContainerImage{}); got != nil {
		t.Errorf("no-blob layers = %+v, want nil", got)
	}
	// Config blob missing on disk -> nil.
	missing := ContainerImage{Blobs: []ContainerBlob{{Digest: containerSHA([]byte("absent")), Size: 1}}}
	if got := hs.containerImageLayers(missing); got != nil {
		t.Errorf("missing-config layers = %+v, want nil", got)
	}
	// A config that does not parse -> nil.
	writeContainerConfig := func(body string) string {
		digest := containerSHA([]byte(body))
		covR2WriteFile(t, hs.containerBlobPath(digest), []byte(body))
		return digest
	}
	garbage := writeContainerConfig("not json")
	if got := hs.containerImageLayers(ContainerImage{Blobs: []ContainerBlob{{Digest: garbage, Size: 1}}}); got != nil {
		t.Errorf("garbage-config layers = %+v, want nil", got)
	}
	// A config with no history falls back to the raw layer list.
	cfg := writeContainerConfig(`{"architecture":"amd64","os":"linux"}`)
	layerDigest := containerSHA([]byte("layer"))
	img := ContainerImage{Blobs: []ContainerBlob{{Digest: cfg, Size: 1}, {Digest: layerDigest, Size: 5}}}
	layers := hs.containerImageLayers(img)
	if len(layers) != 1 || layers[0].Digest != layerDigest || layers[0].Command != "(no build history recorded)" {
		t.Fatalf("raw layers = %+v", layers)
	}
	// A config blob past the render cap is treated as unreadable, so an
	// attacker-influenced giant config cannot be read whole into memory by an
	// unauthenticated /ui/api/detail render.
	oversize := writeContainerConfig(strings.Repeat("A", maxRenderedBlobBytes+1))
	if got := hs.containerImageLayers(ContainerImage{Blobs: []ContainerBlob{{Digest: oversize, Size: 1}}}); got != nil {
		t.Errorf("oversize-config layers = %+v, want nil (cap enforced)", got)
	}
}

func TestCovR2_ListContainerReposUntagged(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	pin := containerSHA([]byte("pinned"))
	if err := hs.mergeContainerRepo(ContainerRepo{
		Registry: "ghcr.io", Repository: "org/app",
		Images: []ContainerImage{{Digest: pin}}, // digest-only, no tag
	}); err != nil {
		t.Fatal(err)
	}
	mods, err := hs.listContainerRepos()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || len(mods[0].Versions) != 1 || mods[0].Versions[0] != pin {
		t.Fatalf("listContainerRepos = %+v (untagged pin should list its digest)", mods)
	}
}

// -----------------------------------------------------------------------------
// Low side: Hugging Face client error paths
// -----------------------------------------------------------------------------

func TestCovR2_FetchHFManifestErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/boom/manifests/t", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusInternalServerError) })
	mux.HandleFunc("/v2/org/badjson/manifests/t", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mtDockerManifest)
		_, _ = w.Write([]byte("not json"))
	})
	mux.HandleFunc("/v2/org/idx/manifests/t", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mtDockerList)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"` + mtDockerList + `","manifests":[]}`))
	})
	mux.HandleFunc("/v2/org/empty/manifests/t", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mtDockerManifest)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"` + mtDockerManifest + `","config":{"digest":""},"layers":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newHFLowServer(t, srv.URL)
	c := ls.newHFClient()
	for _, name := range []string{"boom", "badjson", "idx", "empty"} {
		ref := hfRef{Org: "org", Name: name, Tag: "t"}
		if _, _, _, _, err := c.fetchHFManifest(context.Background(), ref); err == nil {
			t.Errorf("fetchHFManifest(%s) should fail", name)
		}
	}
}

func TestCovR2_DownloadHFBlob(t *testing.T) {
	content := []byte("covr2-hf-blob")
	digest := containerSHA(content)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/model/blobs/"+digest, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(content) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newHFLowServer(t, srv.URL)
	c := ls.newHFClient()
	ref := hfRef{Org: "org", Name: "model", Tag: "t"}
	ctx := context.Background()
	stage := t.TempDir()
	good := ociDescriptor{Digest: digest, Size: int64(len(content))}
	rel := hfBlobRel(digest)

	if _, err := c.downloadHFBlob(ctx, ref, ociDescriptor{Digest: "sha256:zz", Size: 1}, stage, map[string]bool{}); err == nil {
		t.Error("bad digest should fail")
	}
	if _, err := c.downloadHFBlob(ctx, ref, ociDescriptor{Digest: digest, Size: 0}, stage, map[string]bool{}); err == nil {
		t.Error("zero size should fail")
	}
	if mf, err := c.downloadHFBlob(ctx, ref, good, stage, map[string]bool{rel: true}); err != nil || mf.Path != rel {
		t.Fatalf("staged = %+v, %v", mf, err)
	}
	c.prior = func(string, string) bool { return true }
	if mf, err := c.downloadHFBlob(ctx, ref, good, stage, map[string]bool{}); err != nil || !mf.Prior {
		t.Fatalf("prior = %+v, %v", mf, err)
	}
	c.prior = nil
	if _, err := c.downloadHFBlob(ctx, ref, good, stage, map[string]bool{}); err != nil {
		t.Fatalf("download: %v", err)
	}
	if _, err := c.downloadHFBlob(ctx, ref, ociDescriptor{Digest: containerSHA([]byte("x")), Size: 3}, stage, map[string]bool{}); err == nil {
		t.Error("404 blob should fail")
	}
}

func TestCovR2_FetchHFRepoInfoErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/org/gone/revision/main", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	mux.HandleFunc("/api/models/org/boom/revision/main", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusInternalServerError) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newHFLowServer(t, srv.URL)
	c := ls.newHFClient()
	if _, _, err := c.fetchHFRepoInfo(context.Background(), hfRepoRef{Org: "org", Name: "gone", Rev: "main"}); err == nil {
		t.Error("404 repo info should fail")
	}
	if _, _, err := c.fetchHFRepoInfo(context.Background(), hfRepoRef{Org: "org", Name: "boom", Rev: "main"}); err == nil {
		t.Error("500 repo info should fail")
	}
}

func TestCovR2_DownloadHFRepoFiles(t *testing.T) {
	lfsContent := []byte("lfs-weights-bytes")
	plainContent := []byte(`{"model_type":"x"}`)
	mux := http.NewServeMux()
	mux.HandleFunc("/lfs", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(lfsContent) })
	mux.HandleFunc("/plain", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(plainContent) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newHFLowServer(t, srv.URL)
	c := ls.newHFClient()
	ref := hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "main"}
	ctx := context.Background()
	stage := t.TempDir()

	// LFS: successful verified stream to the blob path.
	lfsMeta := hfRepoFileMeta{Path: "model.bin", Size: int64(len(lfsContent)), LFS: hexSHA(lfsContent)}
	rf, _, err := c.downloadHFRepoLFSFile(ctx, ref, lfsMeta, srv.URL+"/lfs", stage, map[string]bool{})
	if err != nil || rf.SHA256 != hexSHA(lfsContent) {
		t.Fatalf("lfs download = %+v, %v", rf, err)
	}
	// LFS: staged-hit and prior-skip short-circuits.
	rel := hfBlobRel("sha256:" + lfsMeta.LFS)
	if _, _, err := c.downloadHFRepoLFSFile(ctx, ref, lfsMeta, srv.URL+"/lfs", stage, map[string]bool{rel: true}); err != nil {
		t.Fatalf("staged lfs: %v", err)
	}
	c.prior = func(string, string) bool { return true }
	if _, mf, err := c.downloadHFRepoLFSFile(ctx, ref, lfsMeta, srv.URL+"/lfs", stage, map[string]bool{}); err != nil || !mf.Prior {
		t.Fatalf("prior lfs = %+v, %v", mf, err)
	}
	c.prior = nil
	// LFS: a hash mismatch (declared oid differs from the served bytes) fails.
	wrongMeta := hfRepoFileMeta{Path: "model.bin", Size: int64(len(lfsContent)), LFS: strings.Repeat("00", 32)}
	if _, _, err := c.downloadHFRepoLFSFile(ctx, ref, wrongMeta, srv.URL+"/lfs", stage, map[string]bool{}); err == nil {
		t.Error("lfs hash mismatch should fail")
	}
	// LFS: a 404 fails.
	if _, _, err := c.downloadHFRepoLFSFile(ctx, ref, lfsMeta, srv.URL+"/404", stage, map[string]bool{}); err == nil {
		t.Error("lfs 404 should fail")
	}

	// Plain (non-LFS): hashed at download and placed by the computed hash.
	plainMeta := hfRepoFileMeta{Path: "config.json", Size: int64(len(plainContent))}
	prf, _, err := c.downloadHFRepoPlainFile(ctx, ref, plainMeta, srv.URL+"/plain", stage, map[string]bool{})
	if err != nil || prf.SHA256 != hexSHA(plainContent) {
		t.Fatalf("plain download = %+v, %v", prf, err)
	}
	// Plain: staged-hit removes the temp and returns.
	prel := hfBlobRel("sha256:" + hexSHA(plainContent))
	if _, _, err := c.downloadHFRepoPlainFile(ctx, ref, plainMeta, srv.URL+"/plain", stage, map[string]bool{prel: true}); err != nil {
		t.Fatalf("staged plain: %v", err)
	}
	// Plain: a download error propagates.
	if _, _, err := c.downloadHFRepoPlainFile(ctx, ref, plainMeta, srv.URL+"/404", stage, map[string]bool{}); err == nil {
		t.Error("plain 404 should fail")
	}

	// downloadHFToTemp directly: success then a 404.
	sha, n, tmp, err := c.downloadHFToTemp(ctx, "cfg", srv.URL+"/plain", stage, hfMaxPlainFileBytes)
	if err != nil || sha != hexSHA(plainContent) || n != int64(len(plainContent)) {
		t.Fatalf("downloadHFToTemp = %q %d, %v", sha, n, err)
	}
	_ = os.Remove(tmp)
	if _, _, _, err := c.downloadHFToTemp(ctx, "cfg", srv.URL+"/404", stage, hfMaxPlainFileBytes); err == nil {
		t.Error("downloadHFToTemp 404 should fail")
	}
	// A body past the limit is rejected and leaves no staged temp behind.
	if _, _, _, err := c.downloadHFToTemp(ctx, "cfg", srv.URL+"/plain", stage, int64(len(plainContent)-1)); err == nil || !strings.Contains(err.Error(), "non-LFS file limit") {
		t.Errorf("oversized plain download = %v, want a non-LFS file limit error", err)
	}
}

func TestCovR2_MirrorHFRepoErrors(t *testing.T) {
	up := fakeGptOssRepo()
	hub := fakeHFHub(t, nil, map[string]fakeHFRepoUpstream{"openai/gpt-oss-20b": up}, "")
	ls, _ := newHFLowServer(t, hub.URL)
	c := ls.newHFClient()
	stage := t.TempDir()

	// Excluding every file leaves nothing to mirror.
	ref := hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "main"}
	if _, _, err := c.mirrorHFRepo(context.Background(), ref, []string{"config.json", "*.safetensors", "original"}, stage, map[string]bool{}); err == nil {
		t.Error("mirroring an all-excluded repo should fail")
	}

	// A repository that cannot be resolved is reported as a per-repo failure.
	repos, _, failed := ls.mirrorHFRepos(context.Background(),
		[]hfRepoRef{{Org: "nobody", Name: "nothing", Rev: "main"}}, nil, stage, false)
	if len(repos) != 0 || len(failed) != 1 {
		t.Fatalf("mirrorHFRepos = %d repos, %d failed", len(repos), len(failed))
	}
}

func TestCovR2_StageHFManifestBlobSeen(t *testing.T) {
	stage := t.TempDir()
	body := []byte("hf-manifest-bytes")
	digest := containerSHA(body)
	rel := hfBlobRel(digest)
	mf, err := stageHFManifestBlob(stage, digest, body, map[string]bool{rel: true})
	if err != nil || mf.Path != rel {
		t.Fatalf("seen manifest = %+v, %v", mf, err)
	}
	if fileExists(filepath.Join(stage, filepath.FromSlash(rel))) {
		t.Error("seen manifest should not have been written")
	}
}

func TestCovR2_CollectHFErrors(t *testing.T) {
	ls, _ := newHFLowServer(t, "")
	if _, err := ls.CollectHF(context.Background(), HFCollectRequest{}); err == nil {
		t.Error("empty hf collect should fail")
	}
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }))
	t.Cleanup(dead.Close)
	ls2, _ := newHFLowServer(t, dead.URL)
	if _, err := ls2.CollectHF(context.Background(), HFCollectRequest{Models: []string{"unsloth/m-GGUF:Q4_0"}}); err == nil {
		t.Error("hf collect against a 404 hub should fail")
	}
}

// -----------------------------------------------------------------------------
// High side: Hugging Face serving error paths
// -----------------------------------------------------------------------------

func TestCovR2_HandleHFManifestEdges(t *testing.T) {
	hs, gpt, _ := collectAndImportHF(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// A HEAD returns headers with no body.
	headReq, _ := http.NewRequest(http.MethodHead, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", nil) //nolint:noctx // test request
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK || headResp.Header.Get("Docker-Content-Digest") != gpt.digest {
		t.Fatalf("HEAD hf manifest = %d %q", headResp.StatusCode, headResp.Header.Get("Docker-Content-Digest"))
	}

	// Removing the manifest blob makes the manifest request report it missing.
	_ = os.Remove(hs.hfBlobPath(gpt.digest))
	assertHTTPStatus(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", http.StatusNotFound)
}

func TestCovR2_HandleHFDownloadEdges(t *testing.T) {
	hs, gpt, _ := collectAndImportHF(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// A non-GET/HEAD method is rejected.
	postReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf", nil) //nolint:noctx // test request
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /hf download = %d, want 405", postResp.StatusCode)
	}

	// Removing the model blob makes the download report it missing.
	_ = os.Remove(hs.hfBlobPath(containerSHA(gpt.gguf)))
	assertHTTPStatus(t, srv.URL+"/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf", http.StatusNotFound)
}

func TestCovR2_ServeHFHubEdges(t *testing.T) {
	hs, up, _ := collectAndImportHFRepo(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// A resolve request with a non-GET/HEAD method is rejected (405), which also
	// exercises the resolve branch of serveHFHub.
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/openai/gpt-oss-20b/resolve/main/config.json", strings.NewReader("x")) //nolint:noctx // test request
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT resolve = %d, want 405", putResp.StatusCode)
	}

	// A revision that is not mirrored yields RevisionNotFound.
	assertHTTPStatus(t, srv.URL+"/openai/gpt-oss-20b/resolve/dev/config.json", http.StatusNotFound)

	// Removing a file's blob makes resolve report the blob missing.
	_ = os.Remove(hs.hfBlobPath("sha256:" + hexSHA(up.files["config.json"])))
	resp, err := http.Get(srv.URL + "/openai/gpt-oss-20b/resolve/main/config.json") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Error-Code") != "EntryNotFound" {
		t.Errorf("resolve missing blob = %d %q", resp.StatusCode, resp.Header.Get("X-Error-Code"))
	}

	// A resolve for a repository that is not mirrored falls through to a 404.
	assertHTTPStatus(t, srv.URL+"/nobody/nothing/resolve/main/config.json", http.StatusNotFound)
}

func TestCovR2_LoadHFRepoIndexFold(t *testing.T) {
	hs, _, _ := collectAndImportHFRepo(t)
	// A wrong-case org resolves through the case-insensitive fallback scan.
	idx, err := hs.loadHFRepoIndexFold("OpenAI", "GPT-OSS-20B")
	if err != nil {
		t.Fatalf("loadHFRepoIndexFold(wrong case): %v", err)
	}
	if idx.Org != "openai" || idx.Name != "gpt-oss-20b" {
		t.Fatalf("folded index = %+v", idx)
	}
	// A repository that does not exist at all still reports not-found.
	if _, err := hs.loadHFRepoIndexFold("nobody", "nothing"); err == nil {
		t.Error("unknown repo fold should fail")
	}
}

// -----------------------------------------------------------------------------
// Tar-over-gzip scan decompression budget (M3 regression)
// -----------------------------------------------------------------------------

const (
	tarScanProbeFillerBytes = 256 << 10 // decompressed filler ahead of the wanted member
	tarScanProbeBudget      = 64 << 10  // scan budget that runs out inside the filler
)

// tarScanProbeTgz builds the shape of a tar bomb: a filler entry larger than
// tarScanProbeBudget followed by the scanner's wanted member, gzip-compressed.
// A scanner whose traversal is bounded runs out of budget inside the filler
// and never sees the member; an unbounded traversal (the M3 bug) inflates its
// way through and finds it.
func tarScanProbeTgz(t *testing.T, member, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{
		{"0-filler.bin", make([]byte, tarScanProbeFillerBytes)},
		{member, []byte(content)},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
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

// tarScanProbeCases lists every "scan a .tar.gz for one named member" reader
// with the member it wants and a probe reporting whether the member was found
// under the given total-decompression budget.
func tarScanProbeCases() []struct {
	name    string
	member  string
	content string
	found   func(tgz string, budget int64) bool
} {
	return []struct {
		name    string
		member  string
		content string
		found   func(tgz string, budget int64) bool
	}{
		{
			name:    "python-sdistRequiresPython",
			member:  "pkg-1.0/PKG-INFO",
			content: "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\nRequires-Python: >=3.9\n",
			found: func(tgz string, budget int64) bool {
				return sdistRequiresPythonBounded(tgz, budget) == ">=3.9"
			},
		},
		{
			name:    "apk-apkIndexFromArchive",
			member:  "APKINDEX",
			content: "P:pkg\nV:1.0-r0\nA:x86_64\n",
			found: func(tgz string, budget int64) bool {
				b, err := os.ReadFile(tgz)
				if err != nil {
					return false
				}
				text, err := apkIndexFromArchiveBounded(b, 1<<20, budget)
				return err == nil && strings.Contains(text, "P:pkg")
			},
		},
		{
			name:    "npm-extractNpmPackageJSON",
			member:  "package/package.json",
			content: `{"name":"pkg","version":"1.0.0"}`,
			found: func(tgz string, budget int64) bool {
				b, err := extractNpmPackageJSONBounded(tgz, budget)
				return err == nil && strings.Contains(string(b), `"pkg"`)
			},
		},
		{
			name:    "helm-extractChartYAML",
			member:  "chart/Chart.yaml",
			content: "apiVersion: v2\nname: chart\nversion: 1.0.0\n",
			found: func(tgz string, budget int64) bool {
				meta, err := extractChartYAMLBounded(tgz, budget)
				return err == nil && meta["name"] == "chart"
			},
		},
		{
			name:    "galaxy-extractGalaxyCollectionInfo",
			member:  "MANIFEST.json",
			content: `{"collection_info":{"namespace":"ns","name":"col","version":"1.0.0"}}`,
			found: func(tgz string, budget int64) bool {
				info, err := extractGalaxyCollectionInfoBounded(tgz, budget)
				return err == nil && info.Namespace == "ns"
			},
		},
		{
			name:    "cran-extractCRANDescription",
			member:  "pkg/DESCRIPTION",
			content: "Package: pkg\nVersion: 1.0\n",
			found: func(tgz string, budget int64) bool {
				desc, err := extractCRANDescriptionBounded(tgz, "pkg", budget)
				return err == nil && desc["Package"] == "pkg"
			},
		},
	}
}

// TestTarScanDecompressionBudget is the M3 regression test: every "scan a
// .tar.gz for one named member" reader must bound the total bytes it
// decompresses, because tar.Reader.Next() inflates every skipped entry — a
// crafted archive with the wanted member placed after a gzip bomb would
// otherwise be inflated wholesale. python/apk/npm shipped without the bound
// once (helm/galaxy/cran were fixed a pass earlier), so each scanner is probed
// twice over the same bomb-shaped archive: with a budget that runs out inside
// the filler it must give up without finding the member, and with the default
// budget it must find it — proving the budget, not a parse error, stopped it.
func TestTarScanDecompressionBudget(t *testing.T) {
	dir := t.TempDir()
	for i, tc := range tarScanProbeCases() {
		tgz := filepath.Join(dir, fmt.Sprintf("probe-%d.tar.gz", i))
		writeFile(t, tgz, tarScanProbeTgz(t, tc.member, tc.content))
		if tc.found(tgz, tarScanProbeBudget) {
			t.Errorf("%s: member found behind a filler larger than the scan budget — total decompression is not bounded", tc.name)
		}
		if !tc.found(tgz, tarScanMaxDecompressedBytes) {
			t.Errorf("%s: member not found under the default budget — probe archive or scanner broken", tc.name)
		}
	}
}
