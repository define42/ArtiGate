package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Reference parsing
// -----------------------------------------------------------------------------

func TestParseHFRef(t *testing.T) {
	tests := []struct {
		in   string
		want hfRef
	}{
		{"hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0", hfRef{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Tag: "Q4_0"}},
		{"huggingface.co/unsloth/gpt-oss-20b-GGUF:Q4_0", hfRef{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Tag: "Q4_0"}},
		{"https://huggingface.co/unsloth/gpt-oss-20b-GGUF", hfRef{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Tag: "latest"}},
		{"unsloth/gpt-oss-20b-GGUF:Q4_0", hfRef{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Tag: "Q4_0"}},
		{"bartowski/Llama-3.2-1B-Instruct-GGUF", hfRef{Org: "bartowski", Name: "Llama-3.2-1B-Instruct-GGUF", Tag: "latest"}},
		{"  hf.co/org/model:IQ3_M  ", hfRef{Org: "org", Name: "model", Tag: "IQ3_M"}},
	}
	for _, tc := range tests {
		got, err := parseHFRef(tc.in)
		if err != nil {
			t.Errorf("parseHFRef(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHFRef(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	invalid := []string{
		"",
		"gpt-oss-20b-GGUF",              // no organization
		"hf.co/unsloth",                 // no model name
		"docker.io/library/alpine:3.20", // not a Hugging Face host
		"hf.co:8080/unsloth/model:Q4_0", // ports are not supported
		"hf.co/unsloth/model@sha256:" + strings.Repeat("ab", 32), // digest pins unsupported
		"hf.co/unsloth/a/b/model:Q4_0",                           // too many segments
		"hf.co/.unsloth/model",                                   // org may not start with '.'
		"hf.co/unsloth/..:Q4_0",                                  // path traversal
		"hf.co/unsloth/model:bad tag",                            // invalid tag characters
	}
	for _, in := range invalid {
		if got, err := parseHFRef(in); err == nil {
			t.Errorf("parseHFRef(%q) = %+v, want error", in, got)
		}
	}
}

func TestParseHFResourcePath(t *testing.T) {
	tests := []struct {
		in   string
		want hfResource
	}{
		{"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", hfResource{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Route: "manifests", Ref: "Q4_0"}},
		{"/v2/hf.co/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", hfResource{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Route: "manifests", Ref: "Q4_0"}},
		{"/v2/org/model/blobs/sha256:" + strings.Repeat("ab", 32), hfResource{Org: "org", Name: "model", Route: "blobs", Ref: "sha256:" + strings.Repeat("ab", 32)}},
		{"/v2/org/model/tags/list", hfResource{Org: "org", Name: "model", Route: "tags"}},
	}
	for _, tc := range tests {
		got, ok := parseHFResourcePath(tc.in)
		if !ok || got != tc.want {
			t.Errorf("parseHFResourcePath(%q) = %+v, %v; want %+v", tc.in, got, ok, tc.want)
		}
	}

	// Container repositories (dotted first segment), the registry root, and
	// catalog paths must never be claimed as HF resources.
	for _, in := range []string{
		"/v2/",
		"/v2/_catalog",
		"/v2/docker.io/library/alpine/manifests/3.20",
		"/v2/org/model/manifests",         // no reference
		"/v2/org/model/tags/wrong",        // not tags/list
		"/v2/org/model/extra/manifests/x", // too many segments
	} {
		if got, ok := parseHFResourcePath(in); ok {
			t.Errorf("parseHFResourcePath(%q) = %+v, want no match", in, got)
		}
	}
}

func TestParseHFDownloadPath(t *testing.T) {
	org, name, tag, ok := parseHFDownloadPath("/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf")
	if !ok || org != "unsloth" || name != "gpt-oss-20b-GGUF" || tag != "Q4_0" {
		t.Fatalf("parseHFDownloadPath = %q %q %q %v", org, name, tag, ok)
	}
	for _, in := range []string{
		"/hf/",
		"/hf/unsloth/model",                  // no tag file
		"/hf/unsloth/model/Q4_0",             // missing .gguf suffix
		"/hf/unsloth/model/.gguf",            // empty tag
		"/hf/unsloth/a/b/Q4_0.gguf",          // too many segments
		"/hf/docker.io/model/Q4_0.gguf",      // dotted org
		"/v2/unsloth/model/blobs/sha256:abc", // registry route, not a download
	} {
		if _, _, _, ok := parseHFDownloadPath(in); ok {
			t.Errorf("parseHFDownloadPath(%q) matched, want no match", in)
		}
	}
}

func TestParseHFRepoRef(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	tests := []struct {
		in   string
		want hfRepoRef
	}{
		{"openai/gpt-oss-20b", hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "main"}},
		{"hf.co/openai/gpt-oss-20b@main", hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "main"}},
		{"https://huggingface.co/openai/gpt-oss-20b", hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "main"}},
		{"https://huggingface.co/openai/gpt-oss-20b/tree/dev", hfRepoRef{Org: "openai", Name: "gpt-oss-20b", Rev: "dev"}},
		{"org/name@" + commit, hfRepoRef{Org: "org", Name: "name", Rev: commit}},
	}
	for _, tc := range tests {
		got, err := parseHFRepoRef(tc.in)
		if err != nil {
			t.Errorf("parseHFRepoRef(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHFRepoRef(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
	for _, in := range []string{
		"",
		"gpt-oss-20b",            // no organization
		"hf.co/openai",           // no repository name
		"docker.io/library/x",    // not a Hugging Face host
		"org/name@bad rev",       // invalid revision characters
		"org/name@a/b",           // revision with a slash
		"org/name:Q4_0",          // a variant tag belongs in the models list
		"hf.co/org/a/b/name@dev", // too many segments
	} {
		if got, err := parseHFRepoRef(in); err == nil {
			t.Errorf("parseHFRepoRef(%q) = %+v, want error", in, got)
		}
	}
}

func TestHFExcluded(t *testing.T) {
	tests := []struct {
		patterns []string
		path     string
		want     bool
	}{
		{[]string{"original"}, "original/model.safetensors", true},
		{[]string{"original/"}, "original/a/b.bin", true},
		{[]string{"original"}, "original", true},
		{[]string{"original"}, "originals/x", false},
		{[]string{"*.bin"}, "model.bin", true},
		{[]string{"*.bin"}, "metal/model.bin", false}, // path.Match * does not cross /
		{[]string{"original", "metal"}, "metal/model.bin", true},
		{nil, "anything", false},
	}
	for _, tc := range tests {
		if got := hfExcluded(tc.patterns, tc.path); got != tc.want {
			t.Errorf("hfExcluded(%v, %q) = %v, want %v", tc.patterns, tc.path, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Fake Hugging Face model API
// -----------------------------------------------------------------------------

// fakeHFModel is one model variant (config + model blob + template + manifest)
// served by the fake hub.
type fakeHFModel struct {
	gguf     []byte
	template []byte
	config   []byte
	manifest []byte
	digest   string
}

func makeFakeHFModel(quant, ggufContent string) fakeHFModel {
	m := fakeHFModel{
		gguf:     []byte(ggufContent),
		template: []byte("{{ .Prompt }}"),
		config:   []byte(`{"model_format":"gguf","model_family":"llama","model_type":"20.9B","file_type":"` + quant + `"}`),
	}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerManifest,
		"config": map[string]any{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"digest":    containerSHA(m.config),
			"size":      len(m.config),
		},
		"layers": []map[string]any{
			{"mediaType": mtOllamaModel, "digest": containerSHA(m.gguf), "size": len(m.gguf)},
			{"mediaType": "application/vnd.ollama.image.template", "digest": containerSHA(m.template), "size": len(m.template)},
		},
	}
	m.manifest, _ = json.Marshal(manifest)
	m.digest = containerSHA(m.manifest)
	return m
}

// fakeHFRepoUpstream is one full repository served by the fake hub's file
// API: a pinned commit, its files, and which of them are LFS-backed (and so
// list an upstream sha256).
type fakeHFRepoUpstream struct {
	sha   string
	files map[string][]byte
	lfs   map[string]bool
}

// hexSHA is a file content's bare hex sha256 (no "sha256:" prefix).
func hexSHA(b []byte) string {
	return strings.TrimPrefix(containerSHA(b), "sha256:")
}

// fakeHFHub serves the given "org/name:tag" variants over the Ollama-style
// model API and the given full repositories over the Hub file API. A
// non-empty requireToken demands that exact bearer token on every request
// (gated-model behavior).
func fakeHFHub(t *testing.T, models map[string]fakeHFModel, repos map[string]fakeHFRepoUpstream, requireToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if requireToken != "" && r.Header.Get("Authorization") != "Bearer "+requireToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	serve := func(body []byte, contentType string) http.HandlerFunc {
		return authed(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(body)
		})
	}
	registered := map[string]bool{}
	handle := func(pattern string, h http.HandlerFunc) {
		if !registered[pattern] { // blobs shared between variants register once
			registered[pattern] = true
			mux.HandleFunc(pattern, h)
		}
	}
	for key, m := range models {
		name, tag, ok := strings.Cut(key, ":")
		if !ok {
			t.Fatalf("bad fake model key %q", key)
		}
		handle("/v2/"+name+"/manifests/"+tag, serve(m.manifest, mtDockerManifest))
		for _, b := range [][]byte{m.config, m.gguf, m.template} {
			handle("/v2/"+name+"/blobs/"+containerSHA(b), serve(b, "application/octet-stream"))
		}
	}
	for name, up := range repos {
		info := fakeHFRepoInfoJSON(up)
		handle("/api/models/"+name+"/revision/main", serve(info, "application/json"))
		handle("/api/models/"+name+"/revision/"+up.sha, serve(info, "application/json"))
		for p, content := range up.files {
			handle("/"+name+"/resolve/"+up.sha+"/"+p, serve(content, "application/octet-stream"))
		}
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fakeHFRepoInfoJSON renders the /api/models/...?blobs=true response: the
// commit sha plus every file, with lfs.oid only for LFS-backed files (the
// collector must hash the rest itself).
func fakeHFRepoInfoJSON(up fakeHFRepoUpstream) []byte {
	var paths []string
	for p := range up.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	siblings := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		sib := map[string]any{"rfilename": p, "size": len(up.files[p])}
		if up.lfs[p] {
			sib["lfs"] = map[string]any{"oid": hexSHA(up.files[p]), "size": len(up.files[p])}
		}
		siblings = append(siblings, sib)
	}
	b, _ := json.Marshal(map[string]any{"sha": up.sha, "siblings": siblings})
	return b
}

func newHFLowServer(t *testing.T, endpoint string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	ls, priv := newAptLowServer(t)
	ls.cfg.HFEndpoint = endpoint
	return ls, priv
}

// -----------------------------------------------------------------------------
// Low side: collect
// -----------------------------------------------------------------------------

func TestCollectHF(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-bytes-q4")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")
	ls, _ := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0"}})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.BundleID != "hf-bundle-000001" || res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if m.HuggingFace == nil || len(m.HuggingFace.Models) != 1 {
		t.Fatalf("manifest has no hf models: %+v", m.HuggingFace)
	}
	got := m.HuggingFace.Models[0]
	if got.Org != "unsloth" || got.Name != "gpt-oss-20b-GGUF" {
		t.Fatalf("model identity = %+v", got)
	}
	if len(got.Variants) != 1 || got.Variants[0].Tag != "Q4_0" || got.Variants[0].Digest != model.digest {
		t.Fatalf("variant record = %+v", got.Variants)
	}
	if blob, ok := hfModelBlob(got.Variants[0]); !ok || blob.Digest != containerSHA(model.gguf) {
		t.Fatalf("model blob = %+v, %v", got.Variants[0].Blobs, ok)
	}
	// manifest + config + model + template, all content-addressed.
	if len(m.Files) != 4 {
		t.Fatalf("bundle files = %+v, want 4", m.Files)
	}
	for _, f := range m.Files {
		if !strings.HasPrefix(f.Path, "hf/blobs/sha256/") || !strings.HasSuffix(f.Path, f.SHA256) {
			t.Errorf("file %s is not content-addressed by its sha256", f.Path)
		}
	}
}

func TestCollectHFSharedBlobsListedOnce(t *testing.T) {
	// Two variants of one model share the template blob (and the fake config
	// differs per quant, so only the template is shared).
	q4 := makeFakeHFModel("Q4_0", "gguf-q4")
	q8 := makeFakeHFModel("Q8_0", "gguf-q8")
	hub := fakeHFHub(t, map[string]fakeHFModel{
		"unsloth/gpt-oss-20b-GGUF:Q4_0": q4,
		"unsloth/gpt-oss-20b-GGUF:Q8_0": q8,
	}, nil, "")
	ls, _ := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{
		Models: []string{"unsloth/gpt-oss-20b-GGUF:Q4_0", "unsloth/gpt-oss-20b-GGUF:Q8_0"},
	})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.ExportedModules != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	if len(m.HuggingFace.Models) != 1 || len(m.HuggingFace.Models[0].Variants) != 2 {
		t.Fatalf("models = %+v", m.HuggingFace.Models)
	}
	// 2 manifests + 2 configs + 2 ggufs + 1 shared template = 7 files.
	if len(m.Files) != 7 {
		t.Fatalf("bundle files = %d, want 7 (shared template listed once): %+v", len(m.Files), m.Files)
	}
}

func TestCollectHFSkipsUnfetchable(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-bytes")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")
	ls, _ := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{
		Models: []string{"unsloth/gpt-oss-20b-GGUF:Q4_0", "unsloth/gpt-oss-20b-GGUF:NoSuchQuant"},
	})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.SkippedModules[0].Module != "hf.co/unsloth/gpt-oss-20b-GGUF" || res.SkippedModules[0].Version != "NoSuchQuant" {
		t.Fatalf("skipped = %+v", res.SkippedModules)
	}

	// All models failing must not burn a sequence number.
	if _, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"unsloth/gpt-oss-20b-GGUF:AlsoMissing"}}); err == nil {
		t.Fatal("collect of only unfetchable models should fail")
	}
	if seq := ls.peekSequence(streamHF); seq != 2 {
		t.Fatalf("next sequence = %d, want 2", seq)
	}
}

func TestCollectHFSafetensorsRepoHint(t *testing.T) {
	// The Hub answers 400 (not 404) when a repository exists but has no GGUF
	// weights — e.g. openai/gpt-oss-20b, the original safetensors release. The
	// failure must say why and point at GGUF conversions.
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/openai/gpt-oss-20b/manifests/latest", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ls, _ := newHFLowServer(t, srv.URL)

	_, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"hf.co/openai/gpt-oss-20b"}})
	if err == nil {
		t.Fatal("collect of a safetensors-only repository should fail")
	}
	for _, want := range []string{"HTTP 400", "GGUF"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestCollectHFGatedToken(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-gated")
	hub := fakeHFHub(t, map[string]fakeHFModel{"meta/gated-GGUF:Q4_0": model}, nil, "hf_secret")
	ls, _ := newHFLowServer(t, hub.URL)

	// Without a token the collect fails with a hint at ARTIGATE_HF_TOKEN.
	_, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"meta/gated-GGUF:Q4_0"}})
	if err == nil || !strings.Contains(err.Error(), "ARTIGATE_HF_TOKEN") {
		t.Fatalf("tokenless collect of a gated model: %v", err)
	}

	t.Setenv("ARTIGATE_HF_TOKEN", "hf_secret")
	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"meta/gated-GGUF:Q4_0"}})
	if err != nil {
		t.Fatalf("CollectHF with token: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// fakeGptOssRepo is a fake safetensors release: an LFS-backed weights file, a
// small non-LFS config (the collector must hash it itself), and an extra
// full-weights copy under original/ for exclude tests — the shape of the real
// openai/gpt-oss-20b.
func fakeGptOssRepo() fakeHFRepoUpstream {
	return fakeHFRepoUpstream{
		sha: strings.Repeat("ab", 20),
		files: map[string][]byte{
			"config.json":                      []byte(`{"model_type":"gpt_oss"}`),
			"model-00001-of-00001.safetensors": []byte("safetensors-weights"),
			"original/model.safetensors":       []byte("original-weights"),
		},
		lfs: map[string]bool{
			"model-00001-of-00001.safetensors": true,
			"original/model.safetensors":       true,
		},
	}
}

func TestCollectHFRepoSnapshot(t *testing.T) {
	up := fakeGptOssRepo()
	hub := fakeHFHub(t, nil, map[string]fakeHFRepoUpstream{"openai/gpt-oss-20b": up}, "")
	ls, _ := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{
		Repos:       []string{"hf.co/openai/gpt-oss-20b"},
		RepoExclude: []string{"original"},
	})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.BundleID != "hf-bundle-000001" || res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if m.HuggingFace == nil || len(m.HuggingFace.Repos) != 1 {
		t.Fatalf("manifest has no hf repos: %+v", m.HuggingFace)
	}
	repo := m.HuggingFace.Repos[0]
	if repo.Org != "openai" || repo.Name != "gpt-oss-20b" || repo.Revision != up.sha || repo.Ref != "main" {
		t.Fatalf("repo record = %+v", repo)
	}
	if len(repo.Files) != 2 || repo.Files[0].Path != "config.json" || repo.Files[1].Path != "model-00001-of-00001.safetensors" {
		t.Fatalf("repo files = %+v (original/ should be excluded)", repo.Files)
	}
	if repo.Files[0].SHA256 != hexSHA(up.files["config.json"]) {
		t.Errorf("non-LFS file sha256 = %q (should be hashed at download)", repo.Files[0].SHA256)
	}
	if len(m.Files) != 2 {
		t.Fatalf("bundle files = %+v, want 2", m.Files)
	}
	for _, f := range m.Files {
		if !strings.HasPrefix(f.Path, "hf/blobs/sha256/") || !strings.HasSuffix(f.Path, f.SHA256) {
			t.Errorf("file %s is not content-addressed by its sha256", f.Path)
		}
	}
}

// -----------------------------------------------------------------------------
// Import-side validation
// -----------------------------------------------------------------------------

func TestValidateHFModels(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-validate")
	files := []ManifestFile{}
	seen := map[string]bool{}
	for _, b := range [][]byte{model.manifest, model.config, model.gguf, model.template} {
		digest := containerSHA(b)
		rel := hfBlobRel(digest)
		files = append(files, ManifestFile{Path: rel, SHA256: strings.TrimPrefix(digest, "sha256:"), Size: int64(len(b))})
		seen[rel] = true
	}
	good := HFModel{Org: "unsloth", Name: "gpt-oss-20b-GGUF", Variants: []HFVariant{{
		Tag: "Q4_0", Digest: model.digest, MediaType: mtDockerManifest, Size: int64(len(model.manifest)),
		Blobs: []HFBlob{
			{Digest: containerSHA(model.config), Size: int64(len(model.config))},
			{Digest: containerSHA(model.gguf), Size: int64(len(model.gguf)), MediaType: mtOllamaModel},
			{Digest: containerSHA(model.template), Size: int64(len(model.template))},
		},
	}}}
	if err := validateHFModels([]HFModel{good}, seen, files); err != nil {
		t.Fatalf("valid model rejected: %v", err)
	}

	unlisted := good
	unlisted.Variants = []HFVariant{good.Variants[0]}
	unlisted.Variants[0].Blobs = append([]HFBlob{}, good.Variants[0].Blobs...)
	unlisted.Variants[0].Blobs[1] = HFBlob{Digest: containerSHA([]byte("not-in-bundle")), Size: 3}
	if err := validateHFModels([]HFModel{unlisted}, seen, files); err == nil {
		t.Fatal("variant referencing an unlisted blob must be rejected")
	}

	for _, bad := range []HFModel{
		{Org: "../etc", Name: "x", Variants: good.Variants},
		{Org: "unsloth", Name: "a/b", Variants: good.Variants},
		{Org: "unsloth", Name: "gpt-oss-20b-GGUF"},
	} {
		if err := validateHFModels([]HFModel{bad}, seen, files); err == nil {
			t.Errorf("model %+v must be rejected", bad)
		}
	}
}

func TestValidateHFRepos(t *testing.T) {
	config := []byte("config-bytes")
	weights := []byte("weights-bytes")
	files := []ManifestFile{}
	seen := map[string]bool{}
	for _, b := range [][]byte{config, weights} {
		rel := hfBlobRel(containerSHA(b))
		files = append(files, ManifestFile{Path: rel, SHA256: hexSHA(b), Size: int64(len(b))})
		seen[rel] = true
	}
	good := HFRepo{Org: "openai", Name: "gpt-oss-20b", Revision: strings.Repeat("ab", 20), Ref: "main", Files: []HFRepoFile{
		{Path: "config.json", SHA256: hexSHA(config), Size: int64(len(config))},
		{Path: "model.safetensors", SHA256: hexSHA(weights), Size: int64(len(weights))},
	}}
	if err := validateHFRepos([]HFRepo{good}, seen, files); err != nil {
		t.Fatalf("valid repo rejected: %v", err)
	}

	badRevision := good
	badRevision.Revision = "main" // must be a full commit hash
	badPath := good
	badPath.Files = []HFRepoFile{{Path: "../evil", SHA256: hexSHA(config), Size: 1}}
	unlisted := good
	unlisted.Files = []HFRepoFile{{Path: "config.json", SHA256: hexSHA([]byte("not-bundled")), Size: 1}}
	noFiles := good
	noFiles.Files = nil
	for _, bad := range []HFRepo{badRevision, badPath, unlisted, noFiles} {
		if err := validateHFRepos([]HFRepo{bad}, seen, files); err == nil {
			t.Errorf("repo %+v must be rejected", bad)
		}
	}
}

// -----------------------------------------------------------------------------
// Full pipeline: low collect -> bundle transfer -> high import -> /v2 serving
// -----------------------------------------------------------------------------

// collectAndImportHF mirrors two models into one bundle and imports it on a
// fresh high server.
func collectAndImportHF(t *testing.T) (*HighServer, fakeHFModel, fakeHFModel) {
	t.Helper()
	gpt := makeFakeHFModel("Q4_0", "gguf-gpt-oss")
	tiny := makeFakeHFModel("Q8_0", "gguf-tiny")
	hub := fakeHFHub(t, map[string]fakeHFModel{
		"unsloth/gpt-oss-20b-GGUF:Q4_0": gpt,
		"bartowski/Tiny-GGUF:Q8_0":      tiny,
	}, nil, "")
	ls, priv := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{
		Models: []string{"hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0", "bartowski/Tiny-GGUF:Q8_0"},
	})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.ExportedModules != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range bundleSuffixes() {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of hf bundle failed: %v", err)
	}
	return hs, gpt, tiny
}

func TestLowToHighHFPipeline(t *testing.T) {
	hs, gpt, tiny := collectAndImportHF(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Manifest by tag — the path an `ollama pull <host>/<org>/<model>:<tag>`
	// issues — with the digest and content-type headers ollama relies on.
	resp, err := http.Get(srv.URL + "/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	body := readAllString(t, resp)
	if resp.StatusCode != http.StatusOK || body != string(gpt.manifest) {
		t.Fatalf("manifest by tag: %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != gpt.digest {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, gpt.digest)
	}
	if got := resp.Header.Get("Content-Type"); got != mtDockerManifest {
		t.Errorf("Content-Type = %q", got)
	}

	// The explicit hf.co/ namespace, a case-insensitive quant tag or model
	// name (the Hub resolves both case-insensitively), and lookup by manifest
	// digest all resolve the same variant.
	assertHTTPBody(t, srv.URL+"/v2/hf.co/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", string(gpt.manifest))
	assertHTTPBody(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/q4_0", string(gpt.manifest))
	assertHTTPBody(t, srv.URL+"/v2/Unsloth/gpt-oss-20b-gguf/manifests/Q4_0", string(gpt.manifest))
	assertHTTPBody(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/"+gpt.digest, string(gpt.manifest))

	// Blobs by digest; the model file supports range requests (ollama resumes).
	assertHTTPBody(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/blobs/"+containerSHA(gpt.gguf), string(gpt.gguf))
	assertHFRangeRequest(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/blobs/"+containerSHA(gpt.gguf), string(gpt.gguf))

	// tags/list.
	code, got := httpGet(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/tags/list")
	if code != http.StatusOK || !strings.Contains(got, `"Q4_0"`) {
		t.Fatalf("tags/list: %d %q", code, got)
	}

	// The friendly /hf/ download route serves the raw model file with a
	// descriptive filename (for vLLM / llama.cpp), case-insensitively.
	dlResp, err := http.Get(srv.URL + "/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	dlBody := readAllString(t, dlResp)
	if dlResp.StatusCode != http.StatusOK || dlBody != string(gpt.gguf) {
		t.Fatalf("gguf download: %d %q", dlResp.StatusCode, dlBody)
	}
	if cd := dlResp.Header.Get("Content-Disposition"); !strings.Contains(cd, `filename="gpt-oss-20b-GGUF-Q4_0.gguf"`) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	assertHTTPBody(t, srv.URL+"/hf/unsloth/gpt-oss-20b-gguf/q4_0.gguf", string(gpt.gguf))
	assertHTTPStatus(t, srv.URL+"/hf/unsloth/gpt-oss-20b-GGUF/NoSuchQuant.gguf", http.StatusNotFound)
	assertHTTPStatus(t, srv.URL+"/hf/nobody/No-Such-GGUF/latest.gguf", http.StatusNotFound)

	// Models do not mix: one model cannot read another's blobs even though the
	// store is shared, and unknown models 404.
	assertHTTPStatus(t, srv.URL+"/v2/bartowski/Tiny-GGUF/blobs/"+containerSHA(gpt.gguf), http.StatusNotFound)
	assertHTTPStatus(t, srv.URL+"/v2/bartowski/Tiny-GGUF/manifests/Q4_0", http.StatusNotFound)
	assertHTTPStatus(t, srv.URL+"/v2/nobody/No-Such-GGUF/manifests/latest", http.StatusNotFound)
	assertHTTPBody(t, srv.URL+"/v2/bartowski/Tiny-GGUF/manifests/Q8_0", string(tiny.manifest))

	// The registry stays read-only (the shared /v2 write rejection applies).
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", strings.NewReader("{}")) //nolint:noctx // test request
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT manifest = %d, want 405", putResp.StatusCode)
	}
}

// assertHFRangeRequest fetches the first four bytes of a blob and expects a
// 206 partial response — what ollama uses to resume an interrupted pull.
func assertHFRangeRequest(t *testing.T, url, full string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx // test request
	req.Header.Set("Range", "bytes=0-3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAllString(t, resp)
	if resp.StatusCode != http.StatusPartialContent || body != full[:4] {
		t.Errorf("range request: %d %q, want 206 %q", resp.StatusCode, body, full[:4])
	}
}

// -----------------------------------------------------------------------------
// Dashboard
// -----------------------------------------------------------------------------

func TestHFDashboardAndDetail(t *testing.T) {
	hs, gpt, _ := collectAndImportHF(t)

	mods, err := hs.listHFModels()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].Module != "bartowski/Tiny-GGUF" || mods[1].Module != "unsloth/gpt-oss-20b-GGUF" {
		t.Fatalf("listHFModels = %+v", mods)
	}
	if len(mods[1].Versions) != 1 || mods[1].Versions[0] != "Q4_0" {
		t.Fatalf("versions = %+v", mods[1].Versions)
	}

	repos, err := hs.hfRepoList()
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[1].Name != "unsloth/gpt-oss-20b-GGUF" || len(repos[1].Tags) != 1 {
		t.Fatalf("hfRepoList = %+v", repos)
	}

	detail, err := hs.hfDetail("unsloth/gpt-oss-20b-GGUF@Q4_0")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Title != "unsloth/gpt-oss-20b-GGUF" || detail.Subtitle != "Q4_0" {
		t.Fatalf("detail = %+v", detail)
	}
	if detail.CopyRef != "unsloth/gpt-oss-20b-GGUF:Q4_0" {
		t.Errorf("CopyRef = %q", detail.CopyRef)
	}
	wantFields := map[string]string{
		"Quantization":    "Q4_0",
		"Format":          "gguf",
		"Manifest digest": gpt.digest,
		"Model file":      "/v2/unsloth/gpt-oss-20b-GGUF/blobs/" + containerSHA(gpt.gguf),
		"Download":        "/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf",
	}
	got := map[string]string{}
	for _, f := range detail.Fields {
		got[f.Label] = f.Value
	}
	for label, want := range wantFields {
		if got[label] != want {
			t.Errorf("field %s = %q, want %q", label, got[label], want)
		}
	}

	if _, err := hs.hfDetail("unsloth/gpt-oss-20b-GGUF@NoSuch"); err == nil {
		t.Error("detail of an unknown variant should fail")
	}
	if _, err := hs.hfDetail("../../etc@x"); err == nil {
		t.Error("detail of an invalid spec should fail")
	}
}

// -----------------------------------------------------------------------------
// Full repositories: collect -> import -> Hub API serving
// -----------------------------------------------------------------------------

// collectAndImportHFRepo mirrors one full repository plus one GGUF model in a
// single bundle (the two modes share the stream and blob store) and imports
// it on a fresh high server.
func collectAndImportHFRepo(t *testing.T) (*HighServer, fakeHFRepoUpstream, fakeHFModel) {
	t.Helper()
	up := fakeGptOssRepo()
	gguf := makeFakeHFModel("Q4_0", "gguf-alongside-repo")
	hub := fakeHFHub(t,
		map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": gguf},
		map[string]fakeHFRepoUpstream{"openai/gpt-oss-20b": up}, "")
	ls, priv := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{
		Models:      []string{"unsloth/gpt-oss-20b-GGUF:Q4_0"},
		Repos:       []string{"openai/gpt-oss-20b"},
		RepoExclude: []string{"original"},
	})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.ExportedModules != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range bundleSuffixes() {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of hf bundle failed: %v", err)
	}
	return hs, up, gguf
}

func TestLowToHighHFHubPipeline(t *testing.T) {
	hs, up, gguf := collectAndImportHFRepo(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Model info — what huggingface_hub repo_info/snapshot_download read:
	// the pinned commit and the file list, for the default revision, the
	// branch name, and the commit itself.
	for _, u := range []string{
		"/api/models/openai/gpt-oss-20b",
		"/api/models/openai/gpt-oss-20b/revision/main",
		"/api/models/openai/gpt-oss-20b/revision/" + up.sha,
	} {
		code, body := httpGet(t, srv.URL+u)
		if code != http.StatusOK || !strings.Contains(body, `"sha": "`+up.sha+`"`) || !strings.Contains(body, "config.json") {
			t.Fatalf("GET %s: %d %q", u, code, body)
		}
	}

	// File metadata — the HEAD request hf_hub_download issues, expecting the
	// sha256 ETag (its cache key) and X-Repo-Commit (its snapshot directory).
	headReq, _ := http.NewRequest(http.MethodHead, srv.URL+"/openai/gpt-oss-20b/resolve/main/config.json", nil) //nolint:noctx // test request
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD resolve = %d", headResp.StatusCode)
	}
	if got := headResp.Header.Get("ETag"); got != `"`+hexSHA(up.files["config.json"])+`"` {
		t.Errorf("ETag = %q", got)
	}
	if got := headResp.Header.Get("X-Repo-Commit"); got != up.sha {
		t.Errorf("X-Repo-Commit = %q, want %q", got, up.sha)
	}

	// Downloads by branch and by commit, with resume (Range) support.
	weights := string(up.files["model-00001-of-00001.safetensors"])
	assertHTTPBody(t, srv.URL+"/openai/gpt-oss-20b/resolve/main/model-00001-of-00001.safetensors", weights)
	assertHTTPBody(t, srv.URL+"/openai/gpt-oss-20b/resolve/"+up.sha+"/config.json", string(up.files["config.json"]))
	assertHFRangeRequest(t, srv.URL+"/openai/gpt-oss-20b/resolve/main/model-00001-of-00001.safetensors", weights)

	// Misses carry the X-Error-Code values huggingface_hub maps to typed
	// errors; the excluded original/ subtree was never mirrored.
	for _, tc := range []struct{ url, code string }{
		{"/openai/gpt-oss-20b/resolve/main/tokenizer.json", "EntryNotFound"},
		{"/openai/gpt-oss-20b/resolve/main/original/model.safetensors", "EntryNotFound"},
		{"/api/models/openai/gpt-oss-20b/revision/nope", "RevisionNotFound"},
		{"/api/models/nobody/nothing", "RepoNotFound"},
	} {
		resp, err := http.Get(srv.URL + tc.url) //nolint:noctx // test request
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Error-Code") != tc.code {
			t.Errorf("GET %s = %d, X-Error-Code %q; want 404 %q", tc.url, resp.StatusCode, resp.Header.Get("X-Error-Code"), tc.code)
		}
	}

	// The Hub API namespace is read-only.
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/models/openai/gpt-oss-20b", strings.NewReader("{}")) //nolint:noctx // test request
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT /api/models = %d, want 405", putResp.StatusCode)
	}

	// The GGUF model imported in the same bundle still serves over /v2.
	assertHTTPBody(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", string(gguf.manifest))
}

func TestHFRepoDashboardAndDetail(t *testing.T) {
	hs, up, _ := collectAndImportHFRepo(t)

	mods, err := hs.listHFModels()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].Module != "openai/gpt-oss-20b" || mods[1].Module != "unsloth/gpt-oss-20b-GGUF" {
		t.Fatalf("listHFModels = %+v", mods)
	}
	if len(mods[0].Versions) != 1 || mods[0].Versions[0] != "main" {
		t.Fatalf("repo versions = %+v", mods[0].Versions)
	}

	repos, err := hs.hfRepoList()
	if err != nil {
		t.Fatal(err)
	}
	var full *UIRepo
	for i := range repos {
		if repos[i].Kind == "repo" {
			full = &repos[i]
		}
	}
	if full == nil || full.Name != "openai/gpt-oss-20b" {
		t.Fatalf("hfRepoList has no full-repo entry: %+v", repos)
	}

	detail, err := hs.hfDetail("openai/gpt-oss-20b@main")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Title != "openai/gpt-oss-20b" || detail.Subtitle != "main" {
		t.Fatalf("detail = %+v", detail)
	}
	got := map[string]string{}
	for _, f := range detail.Fields {
		got[f.Label] = f.Value
	}
	if got["Revision"] != up.sha || got["Files"] != "2" {
		t.Errorf("detail fields = %+v", got)
	}
	if _, err := hs.hfDetail("openai/gpt-oss-20b@nope"); err == nil {
		t.Error("detail of an unknown revision should fail")
	}
}
