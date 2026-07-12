package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Pure reference/label helpers (container.go + hf.go)
// -----------------------------------------------------------------------------

func TestCovReg_RefLabelHelpers(t *testing.T) {
	// refVersionLabel prefers tag, then constraint, then digest.
	if got := refVersionLabel(imageRef{Tag: "3.20"}); got != "3.20" {
		t.Errorf("refVersionLabel tag = %q", got)
	}
	if got := refVersionLabel(imageRef{Constraint: "1.26.x"}); got != "1.26.x" {
		t.Errorf("refVersionLabel constraint = %q", got)
	}
	dg := "sha256:" + strings.Repeat("ab", 32)
	if got := refVersionLabel(imageRef{Digest: dg}); got != dg {
		t.Errorf("refVersionLabel digest = %q", got)
	}

	// refSuffix renders ":tag" or "@digest".
	if got := refSuffix(ContainerImage{Tag: "3.20"}); got != ":3.20" {
		t.Errorf("refSuffix tag = %q", got)
	}
	if got := refSuffix(ContainerImage{Digest: dg}); got != "@"+dg {
		t.Errorf("refSuffix digest = %q", got)
	}
}

func TestCovReg_RawContainerLayers(t *testing.T) {
	layers := rawContainerLayers([]ContainerBlob{
		{Digest: "sha256:aaa", Size: 10},
		{Digest: "sha256:bbb", Size: 2048},
	})
	if len(layers) != 2 {
		t.Fatalf("rawContainerLayers len = %d, want 2", len(layers))
	}
	if layers[0].Command != "(no build history recorded)" || layers[0].Digest != "sha256:aaa" || layers[0].Size == "" {
		t.Errorf("layer[0] = %+v", layers[0])
	}
	if layers[1].Digest != "sha256:bbb" {
		t.Errorf("layer[1] = %+v", layers[1])
	}
	if got := rawContainerLayers(nil); len(got) != 0 {
		t.Errorf("rawContainerLayers(nil) = %+v", got)
	}
}

func TestCovReg_ShortCommitAndFirstFile(t *testing.T) {
	long := strings.Repeat("a", 40)
	if got := shortCommit(long); got != long[:12] {
		t.Errorf("shortCommit(long) = %q", got)
	}
	if got := shortCommit("abc"); got != "abc" {
		t.Errorf("shortCommit(short) = %q", got)
	}

	// firstHFRepoFile prefers config.json, else the first file, else "".
	snap := HFRepoSnapshot{Files: []HFRepoFile{{Path: "model.safetensors"}, {Path: "config.json"}}}
	if got := firstHFRepoFile(snap); got != "config.json" {
		t.Errorf("firstHFRepoFile config = %q", got)
	}
	snap = HFRepoSnapshot{Files: []HFRepoFile{{Path: "tokenizer.json"}, {Path: "x.bin"}}}
	if got := firstHFRepoFile(snap); got != "tokenizer.json" {
		t.Errorf("firstHFRepoFile first = %q", got)
	}
	if got := firstHFRepoFile(HFRepoSnapshot{}); got != "" {
		t.Errorf("firstHFRepoFile empty = %q", got)
	}
}

func TestCovReg_HFManifestMediaType(t *testing.T) {
	// Body's own mediaType wins when it is a manifest/index type.
	if got := hfManifestMediaType("text/plain", mtOCIManifest); got != mtOCIManifest {
		t.Errorf("bodyType branch = %q", got)
	}
	// Else the response Content-Type (with parameters stripped) is used.
	if got := hfManifestMediaType(mtDockerList+"; charset=utf-8", "application/json"); got != mtDockerList {
		t.Errorf("contentType branch = %q", got)
	}
	// Else the Docker schema-2 default.
	if got := hfManifestMediaType("application/json", "application/json"); got != mtDockerManifest {
		t.Errorf("default branch = %q", got)
	}
}

func TestCovReg_ContainerAPIBase(t *testing.T) {
	ls, _ := newContainerLowServer(t, map[string]string{"example.com": "https://mirror.local"})
	if got := ls.containerAPIBase("example.com"); got != "https://mirror.local" {
		t.Errorf("override base = %q", got)
	}
	if got := ls.containerAPIBase(containerDefaultRegistry); got != containerDockerHubAPI {
		t.Errorf("docker.io base = %q", got)
	}
	if got := ls.containerAPIBase("ghcr.io"); got != "https://ghcr.io" {
		t.Errorf("plain host base = %q", got)
	}
}

// -----------------------------------------------------------------------------
// writeVerifiedBlob (container.go) — the streaming verified writer
// -----------------------------------------------------------------------------

func TestCovReg_WriteVerifiedBlob(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("verified-blob-content")
	sha := hexSHA(payload)

	// Success: exact size + sha, written under a fresh subdirectory (MkdirAll).
	abs := filepath.Join(dir, "sub", "blob")
	if err := writeVerifiedBlob(abs, strings.NewReader(string(payload)), int64(len(payload)), sha); err != nil {
		t.Fatalf("writeVerifiedBlob success: %v", err)
	}
	got, err := os.ReadFile(abs)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("blob content = %q, %v", got, err)
	}

	// Size mismatch (too many bytes): the LimitReader reads wantSize+1, so n differs.
	over := filepath.Join(dir, "over")
	if err := writeVerifiedBlob(over, strings.NewReader(string(payload)+"x"), int64(len(payload)), sha); err == nil {
		t.Error("oversize blob should fail")
	}
	if fileExists(over) {
		t.Error("failed blob file should be removed (size mismatch)")
	}

	// Size mismatch (too few bytes).
	short := filepath.Join(dir, "short")
	if err := writeVerifiedBlob(short, strings.NewReader("ab"), int64(len(payload)), sha); err == nil {
		t.Error("undersize blob should fail")
	}

	// SHA mismatch: right size, wrong expected hash.
	badSHA := filepath.Join(dir, "badsha")
	if err := writeVerifiedBlob(badSHA, strings.NewReader(string(payload)), int64(len(payload)), strings.Repeat("00", 32)); err == nil {
		t.Error("sha mismatch should fail")
	}
	if fileExists(badSHA) {
		t.Error("failed blob file should be removed (sha mismatch)")
	}
}

// -----------------------------------------------------------------------------
// verifyContainerConfigPlatform (container.go)
// -----------------------------------------------------------------------------

func TestCovReg_VerifyContainerConfigPlatform(t *testing.T) {
	stage := t.TempDir()
	ref := imageRef{Registry: "docker.io", Repository: "library/alpine", Tag: "3.20"}

	writeConfig := func(body string) string {
		digest := containerSHA([]byte(body))
		abs := filepath.Join(stage, filepath.FromSlash(containerBlobRel(digest)))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, []byte(body))
		return digest
	}

	// linux/amd64 passes.
	ok := writeConfig(`{"architecture":"amd64","os":"linux"}`)
	if err := verifyContainerConfigPlatform(stage, ref, ok); err != nil {
		t.Errorf("linux/amd64 config rejected: %v", err)
	}

	// Wrong architecture fails with a platform message.
	bad := writeConfig(`{"architecture":"arm64","os":"linux"}`)
	if err := verifyContainerConfigPlatform(stage, ref, bad); err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Errorf("arm64 config error = %v", err)
	}

	// Unparseable config fails.
	garbage := writeConfig(`not json`)
	if err := verifyContainerConfigPlatform(stage, ref, garbage); err == nil {
		t.Error("garbage config should fail to parse")
	}

	// Missing config file fails.
	missing := containerSHA([]byte("never-written"))
	if err := verifyContainerConfigPlatform(stage, ref, missing); err == nil {
		t.Error("missing config file should fail")
	}
}

// -----------------------------------------------------------------------------
// HandleContainerCollect / HandleHFCollect (the HTTP entry points)
// -----------------------------------------------------------------------------

func TestCovReg_HandleContainerCollect(t *testing.T) {
	img := makeFakeImage("layer-covreg")
	up := fakeContainerRegistry(t, map[string]fakeImage{"library/alpine:3.20": img})
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": up.URL})

	req := httptest.NewRequest(http.MethodPost, "/admin/containers/collect",
		strings.NewReader(`{"images":["alpine:3.20"]}`))
	res, err := ls.HandleContainerCollect(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleContainerCollect: %v", err)
	}
	if res.ExportedModules != 1 || res.BundleID != "containers-bundle-000001" {
		t.Fatalf("result = %+v", res)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	if m.Containers == nil || len(m.Containers.Repos) != 1 {
		t.Fatalf("manifest repos = %+v", m.Containers)
	}

	// Malformed JSON body is rejected before any collect runs.
	badReq := httptest.NewRequest(http.MethodPost, "/admin/containers/collect", strings.NewReader(`{not json`))
	if _, err := ls.HandleContainerCollect(context.Background(), badReq); err == nil {
		t.Error("malformed container collect body should fail")
	}

	// Empty body carries no images and is rejected.
	emptyReq := httptest.NewRequest(http.MethodPost, "/admin/containers/collect", strings.NewReader(""))
	if _, err := ls.HandleContainerCollect(context.Background(), emptyReq); err == nil {
		t.Error("empty container collect body should fail")
	}
}

func TestCovReg_HandleHFCollect(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-covreg")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")
	ls, _ := newHFLowServer(t, hub.URL)

	req := httptest.NewRequest(http.MethodPost, "/admin/hf/collect",
		strings.NewReader(`{"models":["hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0"]}`))
	res, err := ls.HandleHFCollect(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleHFCollect: %v", err)
	}
	if res.ExportedModules != 1 || res.BundleID != "hf-bundle-000001" {
		t.Fatalf("result = %+v", res)
	}

	badReq := httptest.NewRequest(http.MethodPost, "/admin/hf/collect", strings.NewReader(`{oops`))
	if _, err := ls.HandleHFCollect(context.Background(), badReq); err == nil {
		t.Error("malformed hf collect body should fail")
	}

	emptyReq := httptest.NewRequest(http.MethodPost, "/admin/hf/collect", strings.NewReader(""))
	if _, err := ls.HandleHFCollect(context.Background(), emptyReq); err == nil {
		t.Error("empty hf collect body should fail")
	}
}

// -----------------------------------------------------------------------------
// fetchManifestRaw media-type fallbacks (container.go)
// -----------------------------------------------------------------------------

func TestCovReg_FetchManifestRawMediaTypeFallback(t *testing.T) {
	// A registry that mislabels the manifest's Content-Type: the collector must
	// fall back to the document's own mediaType field.
	goodBody := []byte(`{"schemaVersion":2,"mediaType":"` + mtDockerManifest + `","config":{"digest":"sha256:x"},"layers":[]}`)
	badBody := []byte(`{"schemaVersion":2,"config":{"digest":"sha256:x"}}`) // no mediaType, no valid Content-Type

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/good/manifests/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain") // not a manifest type
		_, _ = w.Write(goodBody)
	})
	mux.HandleFunc("/v2/org/bad/manifests/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(badBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	client := ls.newContainerClient()

	body, mt, digest, err := client.fetchManifestRaw(context.Background(),
		imageRef{Registry: "example.com", Repository: "org/good"}, "v1")
	if err != nil {
		t.Fatalf("fetchManifestRaw fallback: %v", err)
	}
	if mt != mtDockerManifest || digest != containerSHA(goodBody) || string(body) != string(goodBody) {
		t.Fatalf("fallback result mt=%q digest=%q", mt, digest)
	}

	if _, _, _, err := client.fetchManifestRaw(context.Background(),
		imageRef{Registry: "example.com", Repository: "org/bad"}, "v1"); err == nil {
		t.Error("manifest with no discernible media type should fail")
	}
}

// -----------------------------------------------------------------------------
// mergeContainerRepo / mergeHFModel / mergeHFRepo (high-side index merges)
// -----------------------------------------------------------------------------

func TestCovReg_MergeContainerRepo(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	d1 := containerSHA([]byte("manifest-1"))
	d2 := containerSHA([]byte("manifest-2"))
	pin := containerSHA([]byte("pinned"))

	// First import: one tag.
	if err := hs.mergeContainerRepo(ContainerRepo{
		Registry: "docker.io", Repository: "library/alpine",
		Images: []ContainerImage{{Tag: "3.20", Digest: d1}},
	}); err != nil {
		t.Fatal(err)
	}
	// Second import: the tag moves to a new digest, and a digest-pinned image is added.
	if err := hs.mergeContainerRepo(ContainerRepo{
		Registry: "docker.io", Repository: "library/alpine",
		Images: []ContainerImage{{Tag: "3.20", Digest: d2}, {Digest: pin}},
	}); err != nil {
		t.Fatal(err)
	}

	repo, err := hs.loadContainerRepoIndex("docker.io/library/alpine")
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.Images) != 2 {
		t.Fatalf("merged images = %+v", repo.Images)
	}
	byKey := map[string]string{}
	for _, img := range repo.Images {
		if img.Tag != "" {
			byKey["tag:"+img.Tag] = img.Digest
		} else {
			byKey["pin"] = img.Digest
		}
	}
	if byKey["tag:3.20"] != d2 {
		t.Errorf("re-imported tag should move to %s, got %s", d2, byKey["tag:3.20"])
	}
	if byKey["pin"] != pin {
		t.Errorf("digest pin = %s, want %s", byKey["pin"], pin)
	}
}

func TestCovReg_MergeHFModel(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	d1 := containerSHA([]byte("hf-manifest-1"))
	d2 := containerSHA([]byte("hf-manifest-2"))

	if err := hs.mergeHFModel(HFModel{Org: "unsloth", Name: "gpt-oss-20b-GGUF",
		Variants: []HFVariant{{Tag: "Q4_0", Digest: d1}}}); err != nil {
		t.Fatal(err)
	}
	// Re-import: Q4_0 moves to a new digest; Q8_0 is added.
	if err := hs.mergeHFModel(HFModel{Org: "unsloth", Name: "gpt-oss-20b-GGUF",
		Variants: []HFVariant{{Tag: "Q4_0", Digest: d2}, {Tag: "Q8_0", Digest: d1}}}); err != nil {
		t.Fatal(err)
	}

	model, err := hs.loadHFModelIndex("unsloth", "gpt-oss-20b-GGUF")
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Variants) != 2 {
		t.Fatalf("variants = %+v", model.Variants)
	}
	got := map[string]string{}
	for _, v := range model.Variants {
		got[v.Tag] = v.Digest
	}
	if got["Q4_0"] != d2 || got["Q8_0"] != d1 {
		t.Fatalf("merged variants = %+v", got)
	}
}

func TestCovReg_MergeHFRepo(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	rev1 := strings.Repeat("ab", 20)
	rev2 := strings.Repeat("cd", 20)

	if err := hs.mergeHFRepo(HFRepo{Org: "openai", Name: "gpt-oss-20b", Revision: rev1, Ref: "main",
		Files: []HFRepoFile{{Path: "config.json", SHA256: strings.Repeat("11", 32), Size: 3}}}); err != nil {
		t.Fatal(err)
	}
	// Re-import the same revision (replaced in place) plus move "main" to a new commit.
	if err := hs.mergeHFRepo(HFRepo{Org: "openai", Name: "gpt-oss-20b", Revision: rev1, Ref: "main",
		Files: []HFRepoFile{{Path: "config.json", SHA256: strings.Repeat("22", 32), Size: 5}}}); err != nil {
		t.Fatal(err)
	}
	if err := hs.mergeHFRepo(HFRepo{Org: "openai", Name: "gpt-oss-20b", Revision: rev2, Ref: "main",
		Files: []HFRepoFile{{Path: "config.json", SHA256: strings.Repeat("33", 32), Size: 7}}}); err != nil {
		t.Fatal(err)
	}

	idx, err := hs.loadHFRepoIndex("openai", "gpt-oss-20b")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Snapshots) != 2 {
		t.Fatalf("snapshots = %+v", idx.Snapshots)
	}
	if idx.Refs["main"] != rev2 {
		t.Errorf(`Refs["main"] = %q, want %q`, idx.Refs["main"], rev2)
	}
	// The rev1 snapshot must reflect the replaced (second) import.
	for _, snap := range idx.Snapshots {
		if snap.Revision == rev1 {
			if len(snap.Files) != 1 || snap.Files[0].Size != 5 {
				t.Errorf("rev1 snapshot not replaced: %+v", snap.Files)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// handleContainerBlob / handleHFBlob error paths (per-repo isolation)
// -----------------------------------------------------------------------------

func TestCovReg_HandleContainerBlobErrors(t *testing.T) {
	hs, alpine, _ := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Invalid digest syntax.
	assertHTTPStatus(t, srv.URL+"/v2/docker.io/library/alpine/blobs/sha256:zzz", http.StatusNotFound)
	// Unknown repository.
	assertHTTPStatus(t, srv.URL+"/v2/docker.io/library/nope/blobs/"+containerSHA(alpine.layer), http.StatusNotFound)
	// Valid digest, real repo, but a blob it does not reference.
	assertHTTPStatus(t, srv.URL+"/v2/docker.io/library/alpine/blobs/"+containerSHA([]byte("stranger")), http.StatusNotFound)
	// The real blob still serves.
	assertHTTPBody(t, srv.URL+"/v2/docker.io/library/alpine/blobs/"+containerSHA(alpine.layer), string(alpine.layer))
}

func TestCovReg_HandleHFBlobErrors(t *testing.T) {
	hs, gpt, _ := collectAndImportHF(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Invalid digest syntax.
	assertHTTPStatus(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/blobs/sha256:nothex", http.StatusNotFound)
	// Valid digest the model does not reference.
	assertHTTPStatus(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/blobs/"+containerSHA([]byte("stranger")), http.StatusNotFound)
	// The real model blob still serves.
	assertHTTPBody(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/blobs/"+containerSHA(gpt.gguf), string(gpt.gguf))
}

// -----------------------------------------------------------------------------
// validHFHubRequest via parseHFHubPath (hf.go)
// -----------------------------------------------------------------------------

func TestCovReg_ParseHFHubPathValidation(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	valid := []string{
		"/api/models/openai/gpt-oss-20b",
		"/api/models/openai/gpt-oss-20b/revision/main",
		"/api/models/openai/gpt-oss-20b/revision/" + commit,
		"/openai/gpt-oss-20b/resolve/main/config.json",
	}
	for _, p := range valid {
		if _, ok := parseHFHubPath(p); !ok {
			t.Errorf("parseHFHubPath(%q) should be valid", p)
		}
	}
	invalid := []string{
		"/api/models/.bad/name",                           // org may not start with '.'
		"/api/models/openai/gpt-oss-20b/revision/bad rev", // invalid revision chars
		"/openai/gpt-oss-20b/resolve/main/../escape",      // path traversal in file
		"/api/models/openai",                              // too few segments
		"/openai/gpt-oss-20b/resolve/main",                // resolve with no file
	}
	for _, p := range invalid {
		if req, ok := parseHFHubPath(p); ok {
			t.Errorf("parseHFHubPath(%q) = %+v, want no match", p, req)
		}
	}
}
