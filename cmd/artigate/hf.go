package main

// Hugging Face (AI model) ecosystem adapter. The hf stream mirrors two kinds
// of content, both addressed by simple references:
//
// GGUF model variants — "hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0", where the
// repository names the model and the tag selects a variant/quantization
// ("latest" picks the repository's default). The low side fetches Hugging
// Face's Ollama-compatible model API — the same protocol behind `ollama run
// hf.co/<org>/<repo>:<quant>`: GET /v2/<org>/<repo>/manifests/<tag> returns a
// Docker-schema-2 manifest whose layers are the GGUF model file, chat
// template, params, and license, and /v2/<org>/<repo>/blobs/<digest> serves
// each blob. The quantization is resolved upstream, never guessed from
// filenames. The high side serves the same read-only manifests/blobs API
// under /v2/, so an air-gapped Ollama pulls directly from the mirror:
//
//	ollama pull <high-host>/unsloth/gpt-oss-20b-GGUF:Q4_0
//
// (An Ollama model name is host/namespace/model:tag — exactly two path
// segments after the host — so unlike containers the upstream "hf.co" cannot
// be embedded in the pull name; every model in this stream is from hf.co by
// construction. The explicit /v2/hf.co/<org>/<repo>/... form is also served,
// for curl and scripts.)
//
// Full repository snapshots — "openai/gpt-oss-20b[@<branch-or-commit>]", for
// releases that publish safetensors rather than GGUF. The low side pins the
// revision to its commit hash via the Hub API
// (/api/models/<org>/<repo>/revision/<rev>?blobs=true, which also carries
// every LFS file's SHA-256), downloads each file from
// /<org>/<repo>/resolve/<commit>/<path>, and stores it content-addressed. The
// high side serves the subset of the Hub HTTP API that huggingface_hub
// clients use to download — /api/models/... model info and
// /<org>/<repo>/resolve/<revision>/<path> with the ETag/X-Repo-Commit
// headers — so air-gapped vLLM, transformers, and `hf download` work
// unchanged by pointing HF_ENDPOINT at the mirror:
//
//	export HF_ENDPOINT=http://<high-host>
//	vllm serve openai/gpt-oss-20b
//
// Everything in both modes is stored in one content-addressed blob store
// (hf/blobs/), so a file shared between variants, revisions, or modes is
// bundled and stored once.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type HFManifest struct {
	Models []HFModel `json:"models,omitempty"`
	// Repos are full repository snapshots (safetensors releases and friends),
	// mirrored file-by-file for clients that speak the Hub API.
	Repos []HFRepo `json:"repos,omitempty"`
}

// HFModel is one Hugging Face model repository ("<org>/<name>") with the
// variants collected from it.
type HFModel struct {
	Org      string      `json:"org"`  // e.g. unsloth
	Name     string      `json:"name"` // e.g. gpt-oss-20b-GGUF
	Variants []HFVariant `json:"variants"`
}

// HFVariant is one resolved model variant (a quantization tag such as Q4_0, or
// "latest" for the repository's default). Digest is the SHA-256 of the stored
// manifest blob; Blobs lists the config and layers it references (all stored
// content-addressed under hf/blobs/).
type HFVariant struct {
	Tag       string   `json:"tag"`
	Digest    string   `json:"digest"`
	MediaType string   `json:"media_type"`
	Size      int64    `json:"size"`
	Blobs     []HFBlob `json:"blobs"`
}

// HFBlob is one blob a variant references. MediaType distinguishes the model
// file (application/vnd.ollama.image.model) from the template/params/license
// side-cars, for the dashboard.
type HFBlob struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type,omitempty"`
}

// HFRepo is one full repository snapshot, pinned to the commit hash its
// revision resolved to at collect time. Files are stored content-addressed in
// the shared hf blob store; Path is the file's repository-relative name.
type HFRepo struct {
	Org      string `json:"org"`
	Name     string `json:"name"`
	Revision string `json:"revision"` // commit hash pinned at collect time
	// Ref is the branch or tag the revision was resolved from ("main" by
	// default); empty when the collect pinned a commit hash directly.
	Ref   string       `json:"ref,omitempty"`
	Files []HFRepoFile `json:"files"`
}

type HFRepoFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// mtOllamaModel marks the layer holding the model file itself (the GGUF).
const mtOllamaModel = "application/vnd.ollama.image.model"

// hfBlobRel returns the bundle/repository-relative path of a blob,
// e.g. hf/blobs/sha256/ab1/ab12... — content-addressed and shared across
// models, sharded like the container blob store.
func hfBlobRel(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	return path.Join("hf", "blobs", "sha256", containerBlobShardHex(hex), hex)
}

// -----------------------------------------------------------------------------
// Model references
// -----------------------------------------------------------------------------

const (
	hfDefaultEndpoint = "https://huggingface.co"
	hfDefaultTag      = "latest" // Hugging Face maps it to the repo's default quantization

	// hfManifestAccept covers the manifest flavors the model API may return
	// (in practice always the Docker schema-2 form, like Ollama's own registry).
	hfManifestAccept = mtDockerManifest + ", " + mtOCIManifest
)

var (
	// hfOrgRE matches a Hugging Face user/organization name. Orgs never contain
	// dots, which is what lets a reference's first segment be told apart from a
	// registry host (hf.co) and, on the high side, an HF model name be told
	// apart from a container repository (whose first segment is a dotted host).
	hfOrgRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$`)
	// hfNameRE matches a model repository name (dots are common: "Llama-3.2-...").
	hfNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	// hfCommitRE matches a full git commit hash — what a repository snapshot
	// is pinned to.
	hfCommitRE = regexp.MustCompile(`^[a-f0-9]{40}$`)
	// hfRevRE matches a branch or tag name in a repository reference.
	hfRevRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// hfSHA256RE matches a bare hex sha256, as carried in HFRepoFile.
	hfSHA256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// hfRef is a parsed model reference: organization, repository name, and the
// variant tag (a quantization such as Q4_0, or "latest").
type hfRef struct {
	Org  string
	Name string
	Tag  string
}

// String renders the reference in its familiar form, for messages.
func (r hfRef) String() string {
	return "hf.co/" + r.Org + "/" + r.Name + ":" + r.Tag
}

// parseHFRef parses "hf.co/<org>/<repo>[:<tag>]". The hf.co (or
// huggingface.co) prefix and a pasted https:// scheme are optional; a missing
// tag means "latest" (the repository's default quantization).
func parseHFRef(spec string) (hfRef, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return hfRef{}, errors.New("empty model reference")
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(spec, "https://"), "http://")
	if strings.Contains(rest, "@") {
		return hfRef{}, fmt.Errorf("%q: digest pins are not supported; use a tag such as :Q4_0", spec)
	}
	var ref hfRef
	// The tag is after the last ':' that follows the last '/'.
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		ref.Tag = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	if ref.Tag == "" {
		ref.Tag = hfDefaultTag
	}
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	// An explicit host must be Hugging Face; orgs never contain dots, so a
	// dotted first segment is always meant as a host.
	if len(segs) == 3 || (len(segs) > 0 && strings.ContainsAny(segs[0], ".:")) {
		if len(segs) != 3 || !isHFHost(segs[0]) {
			return hfRef{}, fmt.Errorf("%q: only hf.co/<org>/<repo>[:<tag>] references are supported", spec)
		}
		segs = segs[1:]
	}
	if len(segs) != 2 {
		return hfRef{}, fmt.Errorf("%q: need <org>/<repo>[:<tag>], e.g. hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0", spec)
	}
	ref.Org, ref.Name = segs[0], segs[1]
	if !hfOrgRE.MatchString(ref.Org) {
		return hfRef{}, fmt.Errorf("invalid organization %q in %q", ref.Org, spec)
	}
	if !hfNameRE.MatchString(ref.Name) {
		return hfRef{}, fmt.Errorf("invalid model name %q in %q", ref.Name, spec)
	}
	if !containerTagRE.MatchString(ref.Tag) {
		return hfRef{}, fmt.Errorf("invalid tag %q in %q", ref.Tag, spec)
	}
	return ref, nil
}

func isHFHost(host string) bool {
	switch strings.ToLower(host) {
	case "hf.co", "huggingface.co", "www.huggingface.co":
		return true
	default:
		return false
	}
}

// hfRepoRef is a parsed full-repository reference: organization, repository
// name, and the revision to snapshot — a branch/tag name or a commit hash,
// "main" by default.
type hfRepoRef struct {
	Org  string
	Name string
	Rev  string
}

func (r hfRepoRef) String() string {
	return "hf.co/" + r.Org + "/" + r.Name + "@" + r.Rev
}

// parseHFRepoRef parses "hf.co/<org>/<repo>[@<branch-or-commit>]". Like
// variant references the hf.co (or huggingface.co) prefix and a pasted
// https:// scheme are optional; a pasted browser URL ending in /tree/<rev> is
// understood too. A missing revision means "main".
func parseHFRepoRef(spec string) (hfRepoRef, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return hfRepoRef{}, errors.New("empty repository reference")
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(spec, "https://"), "http://")
	var ref hfRepoRef
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		ref.Rev = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segs) > 0 && strings.ContainsAny(segs[0], ".:") {
		if !isHFHost(segs[0]) {
			return hfRepoRef{}, fmt.Errorf("%q: only hf.co/<org>/<repo>[@<revision>] references are supported", spec)
		}
		segs = segs[1:]
	}
	// A pasted browser URL: .../<org>/<repo>/tree/<rev>.
	if len(segs) == 4 && segs[2] == "tree" && ref.Rev == "" {
		ref.Rev = segs[3]
		segs = segs[:2]
	}
	if len(segs) != 2 {
		return hfRepoRef{}, fmt.Errorf("%q: need <org>/<repo>[@<revision>], e.g. openai/gpt-oss-20b", spec)
	}
	ref.Org, ref.Name = segs[0], segs[1]
	if ref.Rev == "" {
		ref.Rev = "main"
	}
	if !hfOrgRE.MatchString(ref.Org) {
		return hfRepoRef{}, fmt.Errorf("invalid organization %q in %q", ref.Org, spec)
	}
	if !hfNameRE.MatchString(ref.Name) {
		return hfRepoRef{}, fmt.Errorf("invalid repository name %q in %q", ref.Name, spec)
	}
	if !hfRevRE.MatchString(ref.Rev) && !hfCommitRE.MatchString(ref.Rev) {
		return hfRepoRef{}, fmt.Errorf("invalid revision %q in %q", ref.Rev, spec)
	}
	return ref, nil
}

// -----------------------------------------------------------------------------
// Low side: model API client (stdlib only)
// -----------------------------------------------------------------------------

// hfBlobDownloadTimeout bounds one blob download. Model blobs are far larger
// than container layers (a 20B-parameter GGUF is tens of gigabytes).
const hfBlobDownloadTimeout = 4 * time.Hour

// hfClient talks to the Hugging Face model API for one collect run.
type hfClient struct {
	base string
	// token is an optional Hugging Face access token (ARTIGATE_HF_TOKEN) for
	// gated or private models; public models need none. net/http drops the
	// Authorization header on the cross-host CDN redirects blob downloads
	// follow, so the token is never leaked downstream.
	token string
	// prior reports whether a blob (bundle path + sha256) was already
	// forwarded on the hf stream, letting the collector skip the download and
	// emit a prior manifest reference. Nil means never skip.
	prior func(path, sha256 string) bool
}

func (s *LowServer) newHFClient() *hfClient {
	base := s.cfg.HFEndpoint
	if base == "" {
		base = hfDefaultEndpoint
	}
	return &hfClient{base: strings.TrimRight(base, "/"), token: os.Getenv("ARTIGATE_HF_TOKEN")}
}

// do performs one request against the Hugging Face endpoint, attaching the
// optional access token and translating auth failures into an actionable
// error (label names the model in that message). The caller must close the
// returned body.
func (c *hfClient) do(ctx context.Context, label, rawURL, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		_ = resp.Body.Close()
		if c.token == "" {
			return nil, fmt.Errorf("%s: HTTP %d — the model may be gated or private; set ARTIGATE_HF_TOKEN to a Hugging Face access token", label, resp.StatusCode)
		}
		return nil, fmt.Errorf("%s: HTTP %d — the ARTIGATE_HF_TOKEN was not accepted for this model", label, resp.StatusCode)
	}
	return resp, nil
}

// get performs one Ollama-compatible model API request (urlPath is relative
// to /v2/<org>/<name>/). The caller must close the returned body.
func (c *hfClient) get(ctx context.Context, ref hfRef, urlPath, accept string) (*http.Response, error) {
	return c.do(ctx, ref.String(), c.base+"/v2/"+ref.Org+"/"+ref.Name+"/"+urlPath, accept)
}

// fetchHFManifest downloads and parses the variant's manifest, returning the
// raw bytes (stored and served verbatim), the parsed form, and its media type
// and content digest.
func (c *hfClient) fetchHFManifest(ctx context.Context, ref hfRef) (body []byte, m ociManifest, mediaType, digest string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.get(ctx, ref, "manifests/"+ref.Tag, hfManifestAccept)
	if err != nil {
		return nil, ociManifest{}, "", "", err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, ociManifest{}, "", "", err
	}
	// The Hub's Ollama-compatible endpoint serves GGUF repositories only: an
	// unknown model or tag is a 404, and a repository without GGUF weights (a
	// safetensors-only release such as openai/gpt-oss-20b) is a 400.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return nil, ociManifest{}, "", "", fmt.Errorf("%s: HTTP %d — check the model exists, publishes GGUF files (a safetensors-only release cannot be mirrored; use one of its GGUF conversions, usually named <model>-GGUF), and has this quantization", ref, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ociManifest{}, "", "", fmt.Errorf("%s: manifest: HTTP %d", ref, resp.StatusCode)
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, ociManifest{}, "", "", fmt.Errorf("%s: parse manifest: %w", ref, err)
	}
	mediaType = hfManifestMediaType(resp.Header.Get("Content-Type"), m.MediaType)
	if isContainerIndexType(mediaType) {
		return nil, ociManifest{}, "", "", fmt.Errorf("%s: got a multi-platform index; expected a model manifest", ref)
	}
	if m.Config.Digest == "" || len(m.Layers) == 0 {
		return nil, ociManifest{}, "", "", fmt.Errorf("%s: manifest has no config or layers (not an Ollama-compatible GGUF model?)", ref)
	}
	sum := sha256.Sum256(body)
	return body, m, mediaType, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// hfManifestMediaType picks the manifest media type: the document's own
// mediaType field when it carries one, else the response Content-Type, else
// the Docker schema-2 default (what Hugging Face serves in practice).
func hfManifestMediaType(contentType, bodyType string) string {
	if isContainerManifestType(bodyType) || isContainerIndexType(bodyType) {
		return bodyType
	}
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = strings.TrimSpace(contentType[:i])
	}
	if isContainerManifestType(contentType) || isContainerIndexType(contentType) {
		return contentType
	}
	return mtDockerManifest
}

// downloadHFBlob streams one blob into the staging blob store, verifying its
// size and SHA-256 against the manifest's descriptor. Blobs already staged
// (shared between variants) are skipped, and a blob whose digest this stream
// has already forwarded is not downloaded at all — it becomes a prior manifest
// reference (blobs are content-addressed, so the descriptor supplies
// everything the manifest entry needs).
func (c *hfClient) downloadHFBlob(ctx context.Context, ref hfRef, desc ociDescriptor, stageRoot string, staged map[string]bool) (ManifestFile, error) {
	if !containerDigestRE.MatchString(desc.Digest) {
		return ManifestFile{}, fmt.Errorf("%s: unsupported blob digest %q (only sha256 is supported)", ref, desc.Digest)
	}
	if desc.Size <= 0 {
		return ManifestFile{}, fmt.Errorf("%s: blob %s has no size in the manifest", ref, desc.Digest)
	}
	rel := hfBlobRel(desc.Digest)
	mf := ManifestFile{Path: rel, SHA256: strings.TrimPrefix(desc.Digest, "sha256:"), Size: desc.Size}
	if staged[rel] {
		return mf, nil
	}
	if c.prior != nil && c.prior(rel, mf.SHA256) {
		emitProgress(ctx, "    ≡ blob %s already forwarded (download skipped)", shortDigest(desc.Digest))
		staged[rel] = true
		mf.Prior = true
		return mf, nil
	}
	ctx, cancel := context.WithTimeout(ctx, hfBlobDownloadTimeout)
	defer cancel()
	resp, err := c.get(ctx, ref, "blobs/"+desc.Digest, "")
	if err != nil {
		return ManifestFile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ManifestFile{}, fmt.Errorf("%s: blob %s: HTTP %d", ref, desc.Digest, resp.StatusCode)
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	body := newProgressReader(ctx, resp.Body, "blob "+shortDigest(desc.Digest), desc.Size)
	if err := writeVerifiedBlob(abs, body, desc.Size, mf.SHA256); err != nil {
		return ManifestFile{}, fmt.Errorf("%s: blob %s: %w", ref, desc.Digest, err)
	}
	emitProgress(ctx, "    ↓ blob %s (%s)", shortDigest(desc.Digest), formatBytes(desc.Size))
	staged[rel] = true
	return mf, nil
}

// hfRepoFileMeta is one repository file as listed by the Hub API: its
// repo-relative path, size, and — for LFS-backed files (all the large ones) —
// its upstream SHA-256 to verify against.
type hfRepoFileMeta struct {
	Path string
	Size int64
	LFS  string // hex sha256 when the file is LFS-backed, else ""
}

// fetchHFRepoInfo resolves a repository revision to its commit hash and file
// list. One call to /api/models/.../revision/...?blobs=true carries the
// commit, every file path/size, and the LFS files' SHA-256s.
func (c *hfClient) fetchHFRepoInfo(ctx context.Context, ref hfRepoRef) (commit string, files []hfRepoFileMeta, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	full := c.base + "/api/models/" + ref.Org + "/" + ref.Name + "/revision/" + url.PathEscape(ref.Rev) + "?blobs=true"
	resp, err := c.do(ctx, ref.String(), full, "application/json")
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", nil, fmt.Errorf("%s: repository or revision not found", ref)
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("%s: repository info: HTTP %d", ref, resp.StatusCode)
	}
	return parseHFRepoInfo(ref, body)
}

// parseHFRepoInfo decodes a /revision listing into the commit hash and the
// sorted per-file metadata, rejecting unsafe paths and empty repositories.
func parseHFRepoInfo(ref hfRepoRef, body []byte) (commit string, files []hfRepoFileMeta, err error) {
	var info struct {
		SHA      string `json:"sha"`
		Siblings []struct {
			Rfilename string `json:"rfilename"`
			Size      int64  `json:"size"`
			LFS       *struct {
				OID  string `json:"oid"`
				Size int64  `json:"size"`
			} `json:"lfs"`
		} `json:"siblings"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", nil, fmt.Errorf("%s: parse repository info: %w", ref, err)
	}
	if !hfCommitRE.MatchString(info.SHA) {
		return "", nil, fmt.Errorf("%s: repository info has no commit hash", ref)
	}
	for _, sib := range info.Siblings {
		if err := validateRelPath(sib.Rfilename); err != nil {
			return "", nil, fmt.Errorf("%s: unsafe file path %q in repository listing", ref, sib.Rfilename)
		}
		meta := hfRepoFileMeta{Path: sib.Rfilename, Size: sib.Size}
		if sib.LFS != nil && hfSHA256RE.MatchString(sib.LFS.OID) {
			meta.LFS = sib.LFS.OID
			if sib.LFS.Size > 0 {
				meta.Size = sib.LFS.Size
			}
		}
		files = append(files, meta)
	}
	if len(files) == 0 {
		return "", nil, fmt.Errorf("%s: repository lists no files", ref)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return info.SHA, files, nil
}

// downloadHFRepoFile fetches one repository file into the content-addressed
// staging store. LFS files stream straight to their blob path, verified
// against the upstream SHA-256 and size; small non-LFS files (configs,
// tokenizers) carry no upstream sha256, so they are hashed while downloading
// and then placed by the computed hash.
func (c *hfClient) downloadHFRepoFile(ctx context.Context, ref hfRepoRef, commit string, meta hfRepoFileMeta, stageRoot string, staged map[string]bool) (HFRepoFile, ManifestFile, error) {
	rawURL := c.base + "/" + ref.Org + "/" + ref.Name + "/resolve/" + commit + "/" + escapeHFRepoPath(meta.Path)
	if meta.LFS != "" && meta.Size > 0 {
		return c.downloadHFRepoLFSFile(ctx, ref, meta, rawURL, stageRoot, staged)
	}
	return c.downloadHFRepoPlainFile(ctx, ref, meta, rawURL, stageRoot, staged)
}

// downloadHFRepoLFSFile streams an LFS-backed file straight to its blob path,
// verifying the upstream SHA-256 and size. The Hub API declares LFS files'
// SHA-256 up front, so one this stream has already forwarded is not downloaded
// at all — it becomes a prior manifest reference. (Non-LFS files carry no
// upstream hash and are always fetched.)
func (c *hfClient) downloadHFRepoLFSFile(ctx context.Context, ref hfRepoRef, meta hfRepoFileMeta, rawURL, stageRoot string, staged map[string]bool) (HFRepoFile, ManifestFile, error) {
	rel := hfBlobRel("sha256:" + meta.LFS)
	rf := HFRepoFile{Path: meta.Path, SHA256: meta.LFS, Size: meta.Size}
	mf := ManifestFile{Path: rel, SHA256: meta.LFS, Size: meta.Size}
	if staged[rel] {
		return rf, mf, nil
	}
	if c.prior != nil && c.prior(rel, meta.LFS) {
		emitProgress(ctx, "    ≡ %s already forwarded (download skipped)", meta.Path)
		staged[rel] = true
		mf.Prior = true
		return rf, mf, nil
	}
	ctx, cancel := context.WithTimeout(ctx, hfBlobDownloadTimeout)
	defer cancel()
	resp, err := c.do(ctx, ref.String(), rawURL, "")
	if err != nil {
		return HFRepoFile{}, ManifestFile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return HFRepoFile{}, ManifestFile{}, fmt.Errorf("%s: %s: HTTP %d", ref, meta.Path, resp.StatusCode)
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	body := newProgressReader(ctx, resp.Body, meta.Path, meta.Size)
	if err := writeVerifiedBlob(abs, body, meta.Size, meta.LFS); err != nil {
		return HFRepoFile{}, ManifestFile{}, fmt.Errorf("%s: %s: %w", ref, meta.Path, err)
	}
	emitProgress(ctx, "    ↓ %s (%s)", meta.Path, formatBytes(meta.Size))
	staged[rel] = true
	return rf, mf, nil
}

// downloadHFRepoPlainFile fetches a small non-LFS file (config, tokenizer),
// hashing it while downloading and placing it by the computed hash.
func (c *hfClient) downloadHFRepoPlainFile(ctx context.Context, ref hfRepoRef, meta hfRepoFileMeta, rawURL, stageRoot string, staged map[string]bool) (HFRepoFile, ManifestFile, error) {
	sha, size, tmp, err := c.downloadHFToTemp(ctx, ref.String()+": "+meta.Path, rawURL, stageRoot)
	if err != nil {
		return HFRepoFile{}, ManifestFile{}, err
	}
	rel := hfBlobRel("sha256:" + sha)
	rf := HFRepoFile{Path: meta.Path, SHA256: sha, Size: size}
	mf := ManifestFile{Path: rel, SHA256: sha, Size: size}
	if staged[rel] {
		_ = os.Remove(tmp)
		return rf, mf, nil
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		_ = os.Remove(tmp)
		return HFRepoFile{}, ManifestFile{}, err
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return HFRepoFile{}, ManifestFile{}, err
	}
	emitProgress(ctx, "    ↓ %s (%s)", meta.Path, formatBytes(size))
	staged[rel] = true
	return rf, mf, nil
}

// downloadHFToTemp streams a URL into a temp file under stageRoot, returning
// the content's hex sha256 and size. The caller moves it into place (or
// removes it).
func (c *hfClient) downloadHFToTemp(ctx context.Context, label, rawURL, stageRoot string) (sha string, size int64, tmpPath string, err error) {
	ctx, cancel := context.WithTimeout(ctx, hfBlobDownloadTimeout)
	defer cancel()
	resp, err := c.do(ctx, label, rawURL, "")
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("%s: HTTP %d", label, resp.StatusCode)
	}
	f, err := os.CreateTemp(stageRoot, "dl-")
	if err != nil {
		return "", 0, "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		_ = os.Remove(f.Name())
		return "", 0, "", fmt.Errorf("%s: %w", label, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, f.Name(), nil
}

// escapeHFRepoPath escapes a repo-relative file path for a resolve URL,
// keeping the "/" separators.
func escapeHFRepoPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// -----------------------------------------------------------------------------
// Low side: collector
// -----------------------------------------------------------------------------

// HFCollectRequest is the body of POST /admin/hf/collect.
//
// Models are GGUF variant references, e.g. "hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0"
// (the hf.co prefix is optional; a missing tag means the repository's default
// quantization). Repos are full repository snapshots, e.g. "openai/gpt-oss-20b"
// or "org/name@<branch-or-commit>" — for safetensors releases consumed through
// the Hub API (vLLM, transformers). RepoExclude optionally skips repository
// paths: a bare directory name ("original" or "original/") skips that whole
// subtree, anything else is matched as a path.Match pattern against the full
// file path.
type HFCollectRequest struct {
	Models      []string `json:"models"`
	Repos       []string `json:"repos"`
	RepoExclude []string `json:"repo_exclude"`
	// Force disables export dedup for this collect: every blob is downloaded
	// and packed even when already forwarded, producing a full self-contained
	// bundle (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

func (s *LowServer) HandleHFCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req HFCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse hf collect request: %w", err)
		}
	}
	return s.CollectHF(ctx, req)
}

// CollectHF mirrors the requested model variants and repository snapshots
// into a signed bundle on the hf stream. A model that cannot be fetched is
// skipped and reported, so one broken reference never blocks the rest of the
// batch.
func (s *LowServer) CollectHF(ctx context.Context, req HFCollectRequest) (ExportResult, error) {
	refs, repoRefs, err := parseHFCollectRequest(req)
	if err != nil {
		return ExportResult{}, err
	}

	mu := s.streamLock(streamHF)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "hf", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	emitProgress(ctx, "Resolving %d reference(s) on Hugging Face…", len(refs)+len(repoRefs))
	models, files, failed := s.mirrorHFModels(ctx, refs, stageRoot, req.Force)
	repos, repoFiles, repoFailed := s.mirrorHFRepos(ctx, repoRefs, req.RepoExclude, stageRoot, req.Force)
	files = mergeManifestFiles(files, repoFiles)
	failed = append(failed, repoFailed...)
	if len(models)+len(repos) == 0 {
		return ExportResult{}, fmt.Errorf("nothing could be fetched: %s", summarizeFailures(failed))
	}

	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	res, err := s.exportIfNew(ctx, streamHF, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeHFBundle(ctx, seq, stageRoot, files, models, repos)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// parseHFCollectRequest parses and de-duplicates both reference lists.
func parseHFCollectRequest(req HFCollectRequest) ([]hfRef, []hfRepoRef, error) {
	var refs []hfRef
	seen := map[string]bool{}
	for _, spec := range req.Models {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		ref, err := parseHFRef(spec)
		if err != nil {
			return nil, nil, err
		}
		if key := ref.String(); !seen[key] {
			seen[key] = true
			refs = append(refs, ref)
		}
	}
	var repoRefs []hfRepoRef
	for _, spec := range req.Repos {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		ref, err := parseHFRepoRef(spec)
		if err != nil {
			return nil, nil, err
		}
		if key := "repo " + ref.String(); !seen[key] {
			seen[key] = true
			repoRefs = append(repoRefs, ref)
		}
	}
	if len(refs)+len(repoRefs) == 0 {
		return nil, nil, errors.New("no models or repositories provided")
	}
	return refs, repoRefs, nil
}

// mergeManifestFiles concatenates two manifest file lists, keeping the first
// entry for each path (both modes stage into the same content-addressed
// store, so a shared blob may be reported by each).
func mergeManifestFiles(a, b []ManifestFile) []ManifestFile {
	seen := map[string]bool{}
	out := make([]ManifestFile, 0, len(a)+len(b))
	for _, f := range append(a, b...) {
		if !seen[f.Path] {
			seen[f.Path] = true
			out = append(out, f)
		}
	}
	return out
}

// mirrorHFModels fetches every requested variant into stageRoot, grouping the
// results by model repository. Per-model failures are collected, not fatal.
func (s *LowServer) mirrorHFModels(ctx context.Context, refs []hfRef, stageRoot string, force bool) ([]HFModel, []ManifestFile, []FailedModule) {
	client := s.newHFClient()
	client.prior = s.priorFileCheck(streamHF, force)
	byModel := map[string]*HFModel{}
	var order []string
	var files []ManifestFile
	// staged marks blobs already downloaded; listed dedupes the manifest file
	// list separately, because a variant reports every blob it references even
	// when another variant already staged it (shared licenses, templates).
	staged := map[string]bool{}
	listed := map[string]bool{}
	var failed []FailedModule

	for _, ref := range refs {
		emitProgress(ctx, "→ %s", ref)
		variant, mf, err := client.mirrorHFVariant(ctx, ref, stageRoot, staged)
		if err != nil {
			emitProgress(ctx, "  ✗ %s: %s", ref, err)
			failed = append(failed, FailedModule{Module: "hf.co/" + ref.Org + "/" + ref.Name, Version: ref.Tag, Error: err.Error()})
			continue
		}
		emitProgress(ctx, "  ✓ %s (%d blob(s))", ref, len(mf))
		for _, f := range mf {
			if !listed[f.Path] {
				listed[f.Path] = true
				files = append(files, f)
			}
		}
		key := ref.Org + "/" + ref.Name
		model, ok := byModel[key]
		if !ok {
			model = &HFModel{Org: ref.Org, Name: ref.Name}
			byModel[key] = model
			order = append(order, key)
		}
		model.Variants = append(model.Variants, variant)
	}

	models := make([]HFModel, 0, len(order))
	for _, key := range order {
		models = append(models, *byModel[key])
	}
	return models, files, failed
}

// mirrorHFVariant resolves one reference to its manifest and downloads the
// manifest, config, and layer blobs into the staging store. It returns the
// variant record plus the manifest files it references.
func (c *hfClient) mirrorHFVariant(ctx context.Context, ref hfRef, stageRoot string, staged map[string]bool) (HFVariant, []ManifestFile, error) {
	manifestBytes, m, mediaType, digest, err := c.fetchHFManifest(ctx, ref)
	if err != nil {
		return HFVariant{}, nil, err
	}
	variant := HFVariant{Tag: ref.Tag, Digest: digest, MediaType: mediaType, Size: int64(len(manifestBytes))}
	var files []ManifestFile
	inVariant := map[string]bool{}
	for _, desc := range append([]ociDescriptor{m.Config}, m.Layers...) {
		mf, err := c.downloadHFBlob(ctx, ref, desc, stageRoot, staged)
		if err != nil {
			return HFVariant{}, nil, err
		}
		if !inVariant[mf.Path] {
			inVariant[mf.Path] = true
			files = append(files, mf)
		}
		variant.Blobs = append(variant.Blobs, HFBlob{Digest: desc.Digest, Size: desc.Size, MediaType: desc.MediaType})
	}
	manifestFile, err := stageHFManifestBlob(stageRoot, digest, manifestBytes, staged)
	if err != nil {
		return HFVariant{}, nil, err
	}
	return variant, append(files, manifestFile), nil
}

// mirrorHFRepos snapshots every requested repository into stageRoot.
// Per-repository failures are collected, not fatal.
func (s *LowServer) mirrorHFRepos(ctx context.Context, refs []hfRepoRef, exclude []string, stageRoot string, force bool) ([]HFRepo, []ManifestFile, []FailedModule) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	client := s.newHFClient()
	client.prior = s.priorFileCheck(streamHF, force)
	staged := map[string]bool{}
	listed := map[string]bool{}
	var repos []HFRepo
	var files []ManifestFile
	var failed []FailedModule

	for _, ref := range refs {
		emitProgress(ctx, "→ %s (full repository)", ref)
		repo, mf, err := client.mirrorHFRepo(ctx, ref, exclude, stageRoot, staged)
		if err != nil {
			emitProgress(ctx, "  ✗ %s: %s", ref, err)
			failed = append(failed, FailedModule{Module: "hf.co/" + ref.Org + "/" + ref.Name, Version: ref.Rev, Error: err.Error()})
			continue
		}
		emitProgress(ctx, "  ✓ %s @ %s (%d file(s))", ref, shortCommit(repo.Revision), len(repo.Files))
		for _, f := range mf {
			if !listed[f.Path] {
				listed[f.Path] = true
				files = append(files, f)
			}
		}
		repos = append(repos, repo)
	}
	return repos, files, failed
}

// mirrorHFRepo resolves one repository reference to its commit hash and
// downloads every (non-excluded) file into the content-addressed staging
// store.
func (c *hfClient) mirrorHFRepo(ctx context.Context, ref hfRepoRef, exclude []string, stageRoot string, staged map[string]bool) (HFRepo, []ManifestFile, error) {
	commit, metas, err := c.fetchHFRepoInfo(ctx, ref)
	if err != nil {
		return HFRepo{}, nil, err
	}
	repo := HFRepo{Org: ref.Org, Name: ref.Name, Revision: commit}
	// A branch/tag is recorded so the high side can serve it as a named
	// revision; a collect pinned to a commit hash carries no ref.
	if !hfCommitRE.MatchString(ref.Rev) {
		repo.Ref = ref.Rev
	}
	var files []ManifestFile
	skipped := 0
	for _, meta := range metas {
		if hfExcluded(exclude, meta.Path) {
			skipped++
			continue
		}
		rf, mf, err := c.downloadHFRepoFile(ctx, ref, commit, meta, stageRoot, staged)
		if err != nil {
			return HFRepo{}, nil, err
		}
		repo.Files = append(repo.Files, rf)
		files = append(files, mf)
	}
	if skipped > 0 {
		emitProgress(ctx, "  (skipped %d excluded file(s))", skipped)
	}
	if len(repo.Files) == 0 {
		return HFRepo{}, nil, fmt.Errorf("%s: every file was excluded; nothing to mirror", ref)
	}
	return repo, files, nil
}

// hfExcluded reports whether a repository path matches any exclude pattern: a
// bare directory name excludes its whole subtree; anything else is a
// path.Match pattern against the full path.
func hfExcluded(patterns []string, p string) bool {
	for _, pat := range patterns {
		pat = strings.TrimSuffix(strings.TrimSpace(pat), "/")
		if pat == "" {
			continue
		}
		if p == pat || strings.HasPrefix(p, pat+"/") {
			return true
		}
		if ok, _ := path.Match(pat, p); ok {
			return true
		}
	}
	return false
}

// shortCommit abbreviates a commit hash for progress lines and version labels.
func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// stageHFManifestBlob stores the variant manifest itself as a content-addressed
// blob in the staging store, so the high side can replay the exact bytes.
func stageHFManifestBlob(stageRoot, digest string, manifestBytes []byte, staged map[string]bool) (ManifestFile, error) {
	rel := hfBlobRel(digest)
	mf := ManifestFile{Path: rel, SHA256: strings.TrimPrefix(digest, "sha256:"), Size: int64(len(manifestBytes))}
	if staged[rel] {
		return mf, nil
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, manifestBytes, 0o644); err != nil {
		return ManifestFile{}, err
	}
	staged[rel] = true
	return mf, nil
}

func (s *LowServer) writeHFBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, models []HFModel, repos []HFRepo) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamHF, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamHF,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"hf"},
		HuggingFace:      &HFManifest{Models: models, Repos: repos},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	total := len(repos)
	for _, m := range models {
		total += len(m.Variants)
	}
	return ExportResult{Stream: streamHF, Sequence: seq, ExportedModules: total, BundleID: id}, nil
}

// -----------------------------------------------------------------------------
// Import-side validation
// -----------------------------------------------------------------------------

// validateHF checks the manifest's Hugging Face section: model variants and
// repository snapshots both reference only blobs listed in the manifest file
// set with a SHA-256 matching their content-addressed path — the digest a
// client will pull by is exactly the hash the import verifies.
func validateHF(m *HFManifest, seen map[string]bool, files []ManifestFile) error {
	if err := validateHFModels(m.Models, seen, files); err != nil {
		return err
	}
	return validateHFRepos(m.Repos, seen, files)
}

// validateHFModels checks each model's identity and that every referenced blob
// (manifest, config, layers) appears in the manifest file set with a SHA-256
// matching its content-addressed path.
func validateHFModels(models []HFModel, seen map[string]bool, files []ManifestFile) error {
	shaByPath := map[string]string{}
	for _, f := range files {
		shaByPath[f.Path] = f.SHA256
	}
	for _, model := range models {
		if err := validateHFModel(model, seen, shaByPath); err != nil {
			return err
		}
	}
	return nil
}

// validateHFRepos checks each repository snapshot's identity, pinned
// revision, and that every file is safe to install and listed in the
// manifest's content-addressed file set.
func validateHFRepos(repos []HFRepo, seen map[string]bool, files []ManifestFile) error {
	shaByPath := map[string]string{}
	for _, f := range files {
		shaByPath[f.Path] = f.SHA256
	}
	for _, repo := range repos {
		if err := validateHFRepo(repo, seen, shaByPath); err != nil {
			return err
		}
	}
	return nil
}

func validateHFRepo(repo HFRepo, seen map[string]bool, shaByPath map[string]string) error {
	if !hfOrgRE.MatchString(repo.Org) {
		return fmt.Errorf("invalid hf organization %q", repo.Org)
	}
	if !hfNameRE.MatchString(repo.Name) {
		return fmt.Errorf("invalid hf repository name %q", repo.Name)
	}
	if !hfCommitRE.MatchString(repo.Revision) {
		return fmt.Errorf("hf repo %s/%s has invalid revision %q (need a full commit hash)", repo.Org, repo.Name, repo.Revision)
	}
	if repo.Ref != "" && !hfRevRE.MatchString(repo.Ref) {
		return fmt.Errorf("hf repo %s/%s has invalid ref %q", repo.Org, repo.Name, repo.Ref)
	}
	if len(repo.Files) == 0 {
		return fmt.Errorf("hf repo %s/%s has no files", repo.Org, repo.Name)
	}
	for _, f := range repo.Files {
		if err := validateRelPath(f.Path); err != nil {
			return fmt.Errorf("hf repo %s/%s file %q: %w", repo.Org, repo.Name, f.Path, err)
		}
		if !hfSHA256RE.MatchString(f.SHA256) {
			return fmt.Errorf("hf repo file %s has invalid sha256", f.Path)
		}
		rel := hfBlobRel("sha256:" + f.SHA256)
		if !seen[rel] {
			return fmt.Errorf("hf repo file %s references blob not listed in manifest.files: %s", f.Path, rel)
		}
		if shaByPath[rel] != f.SHA256 {
			return fmt.Errorf("hf repo blob %s has mismatched manifest sha256", rel)
		}
	}
	return nil
}

func validateHFModel(model HFModel, seen map[string]bool, shaByPath map[string]string) error {
	if !hfOrgRE.MatchString(model.Org) {
		return fmt.Errorf("invalid hf organization %q", model.Org)
	}
	if !hfNameRE.MatchString(model.Name) {
		return fmt.Errorf("invalid hf model name %q", model.Name)
	}
	if len(model.Variants) == 0 {
		return fmt.Errorf("hf model %s/%s has no variants", model.Org, model.Name)
	}
	for _, v := range model.Variants {
		if !containerTagRE.MatchString(v.Tag) {
			return fmt.Errorf("invalid hf variant tag %q", v.Tag)
		}
		if err := requireHFBlobListed(v.Digest, seen, shaByPath); err != nil {
			return err
		}
		for _, b := range v.Blobs {
			if err := requireHFBlobListed(b.Digest, seen, shaByPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// requireHFBlobListed checks that a digest's content-addressed file is listed
// in the manifest with a matching SHA-256.
func requireHFBlobListed(digest string, seen map[string]bool, shaByPath map[string]string) error {
	if !containerDigestRE.MatchString(digest) {
		return fmt.Errorf("invalid hf blob digest %q", digest)
	}
	rel := hfBlobRel(digest)
	if !seen[rel] {
		return fmt.Errorf("hf variant references file not listed in manifest.files: %s", rel)
	}
	if shaByPath[rel] != strings.TrimPrefix(digest, "sha256:") {
		return fmt.Errorf("hf blob %s has mismatched manifest sha256", rel)
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: per-model index, merged on import
// -----------------------------------------------------------------------------

func (s *HighServer) hfDir() string {
	return filepath.Join(s.downloadDir, "hf")
}

func (s *HighServer) hfBlobPath(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(s.hfDir(), "blobs", "sha256", containerBlobShardHex(hex), hex)
}

// hfModelIndexPath is where a model's accumulated variant index lives. The
// "_index.json" name cannot collide with model content: org and name are
// single path segments that may not start with "_".
func (s *HighServer) hfModelIndexPath(org, name string) string {
	return filepath.Join(s.hfDir(), "models", org, name, "_index.json")
}

// publishHF merges each imported model and repository snapshot into its
// persistent index. It is called after the bundle's blobs are installed.
func (s *HighServer) publishHF(m *HFManifest) error {
	if m == nil {
		return nil
	}
	for _, model := range m.Models {
		if err := s.mergeHFModel(model); err != nil {
			return fmt.Errorf("publish hf model %s/%s: %w", model.Org, model.Name, err)
		}
	}
	for _, repo := range m.Repos {
		if err := s.mergeHFRepo(repo); err != nil {
			return fmt.Errorf("publish hf repo %s/%s: %w", repo.Org, repo.Name, err)
		}
	}
	return nil
}

// mergeHFModel merges newly imported variants into the model's index: a
// re-imported tag moves to its new digest (the model was updated upstream),
// and other tags accumulate.
func (s *HighServer) mergeHFModel(model HFModel) error {
	merged, err := s.loadHFModelIndex(model.Org, model.Name)
	if errors.Is(err, os.ErrNotExist) {
		merged = HFModel{Org: model.Org, Name: model.Name}
	} else if err != nil {
		return err
	}
	byTag := map[string]int{}
	for i, v := range merged.Variants {
		byTag[v.Tag] = i
	}
	for _, v := range model.Variants {
		if i, ok := byTag[v.Tag]; ok {
			merged.Variants[i] = v
		} else {
			byTag[v.Tag] = len(merged.Variants)
			merged.Variants = append(merged.Variants, v)
		}
	}
	sort.Slice(merged.Variants, func(i, j int) bool { return merged.Variants[i].Tag < merged.Variants[j].Tag })
	return writeJSONAtomic(s.hfModelIndexPath(model.Org, model.Name), merged, 0o644)
}

func (s *HighServer) loadHFModelIndex(org, name string) (HFModel, error) {
	b, err := os.ReadFile(s.hfModelIndexPath(org, name))
	if err != nil {
		return HFModel{}, err
	}
	var model HFModel
	if err := json.Unmarshal(b, &model); err != nil {
		return HFModel{}, err
	}
	return model, nil
}

// loadHFModelIndexFold loads a model index by exact org/name, falling back to
// a case-insensitive scan of the mirrored models — the Hub resolves repository
// names case-insensitively, so a pull typed in the wrong case still works.
func (s *HighServer) loadHFModelIndexFold(org, name string) (HFModel, error) {
	model, err := s.loadHFModelIndex(org, name)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return model, err
	}
	names, listErr := s.listHFModelNames()
	if listErr != nil {
		return HFModel{}, err
	}
	want := org + "/" + name
	for _, n := range names {
		if strings.EqualFold(n, want) {
			if o, r, ok := strings.Cut(n, "/"); ok {
				return s.loadHFModelIndex(o, r)
			}
		}
	}
	return HFModel{}, err
}

// listHFModelNames walks the models tree and returns every model's
// "<org>/<name>", sorted.
func (s *HighServer) listHFModelNames() ([]string, error) {
	return hfIndexNames(filepath.Join(s.hfDir(), "models"))
}

// listHFRepoNames walks the repository-snapshot tree and returns every
// repo's "<org>/<name>", sorted.
func (s *HighServer) listHFRepoNames() ([]string, error) {
	return hfIndexNames(filepath.Join(s.hfDir(), "repos"))
}

// hfIndexNames returns the "<org>/<name>" of every _index.json under root.
func hfIndexNames(root string) ([]string, error) {
	var names []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || d.Name() != "_index.json" {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(p))
		if relErr != nil {
			return nil
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// -----------------------------------------------------------------------------
// High side: repository snapshot index, merged on import
// -----------------------------------------------------------------------------

// HFRepoIndex is a repository's accumulated snapshot index on the high side.
type HFRepoIndex struct {
	Org  string `json:"org"`
	Name string `json:"name"`
	// Refs maps a collected branch/tag to the commit it resolved to at the
	// most recent import, so clients asking for "main" get the newest
	// mirrored snapshot of main.
	Refs      map[string]string `json:"refs,omitempty"`
	Snapshots []HFRepoSnapshot  `json:"snapshots"`
}

type HFRepoSnapshot struct {
	Revision string       `json:"revision"`
	Files    []HFRepoFile `json:"files"`
}

// hfRepoIndexPath is where a repository's snapshot index lives. Like the
// variant index, "_index.json" cannot collide with content: org and name are
// single path segments that may not start with "_".
func (s *HighServer) hfRepoIndexPath(org, name string) string {
	return filepath.Join(s.hfDir(), "repos", org, name, "_index.json")
}

// mergeHFRepo merges a newly imported snapshot into the repository's index: a
// re-imported revision is replaced, other revisions accumulate, and the
// collected ref (e.g. "main") moves to the new commit.
func (s *HighServer) mergeHFRepo(repo HFRepo) error {
	merged, err := s.loadHFRepoIndex(repo.Org, repo.Name)
	if errors.Is(err, os.ErrNotExist) {
		merged = HFRepoIndex{Org: repo.Org, Name: repo.Name}
	} else if err != nil {
		return err
	}
	snap := HFRepoSnapshot{Revision: repo.Revision, Files: repo.Files}
	replaced := false
	for i := range merged.Snapshots {
		if merged.Snapshots[i].Revision == repo.Revision {
			merged.Snapshots[i] = snap
			replaced = true
			break
		}
	}
	if !replaced {
		merged.Snapshots = append(merged.Snapshots, snap)
	}
	sort.Slice(merged.Snapshots, func(i, j int) bool { return merged.Snapshots[i].Revision < merged.Snapshots[j].Revision })
	if repo.Ref != "" {
		if merged.Refs == nil {
			merged.Refs = map[string]string{}
		}
		merged.Refs[repo.Ref] = repo.Revision
	}
	return writeJSONAtomic(s.hfRepoIndexPath(repo.Org, repo.Name), merged, 0o644)
}

func (s *HighServer) loadHFRepoIndex(org, name string) (HFRepoIndex, error) {
	b, err := os.ReadFile(s.hfRepoIndexPath(org, name))
	if err != nil {
		return HFRepoIndex{}, err
	}
	var idx HFRepoIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return HFRepoIndex{}, err
	}
	return idx, nil
}

// loadHFRepoIndexFold loads a repository index by exact org/name, falling
// back to a case-insensitive scan — the Hub resolves repository names
// case-insensitively.
func (s *HighServer) loadHFRepoIndexFold(org, name string) (HFRepoIndex, error) {
	idx, err := s.loadHFRepoIndex(org, name)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return idx, err
	}
	names, listErr := s.listHFRepoNames()
	if listErr != nil {
		return HFRepoIndex{}, err
	}
	want := org + "/" + name
	for _, n := range names {
		if strings.EqualFold(n, want) {
			if o, r, ok := strings.Cut(n, "/"); ok {
				return s.loadHFRepoIndex(o, r)
			}
		}
	}
	return HFRepoIndex{}, err
}

// resolveHFRepoRevision maps a requested revision — a branch/tag name, a
// commit hash, or empty for the default — to a stored snapshot.
func resolveHFRepoRevision(idx HFRepoIndex, rev string) (HFRepoSnapshot, bool) {
	if rev == "" {
		rev = "main"
	}
	want := rev
	if commit, ok := idx.Refs[want]; ok {
		want = commit
	}
	for _, snap := range idx.Snapshots {
		if snap.Revision == want {
			return snap, true
		}
	}
	// A repository collected under a single snapshot serves it for the
	// default revision too, so a "@v1.0"-pinned mirror still answers "main".
	if rev == "main" && len(idx.Snapshots) == 1 {
		return idx.Snapshots[0], true
	}
	return HFRepoSnapshot{}, false
}

// -----------------------------------------------------------------------------
// High side: read-only model registry under /v2/
// -----------------------------------------------------------------------------

// hfResource is one parsed /v2 request that names a Hugging Face model:
// <org>/<name> plus a manifests, blobs, or tags route.
type hfResource struct {
	Org   string
	Name  string
	Route string // "manifests", "blobs", or "tags"
	Ref   string // tag or digest for manifests; digest for blobs
}

// parseHFResourcePath splits a /v2/... path into an HF model resource. The
// optional hf.co/ prefix is accepted for explicitness; the bare
// /v2/<org>/<name>/... form is what `ollama pull <host>/<org>/<name>:<tag>`
// requests (an Ollama name has room for exactly two segments after the host).
func parseHFResourcePath(p string) (hfResource, bool) {
	rest, ok := strings.CutPrefix(p, "/v2/")
	if !ok {
		return hfResource{}, false
	}
	rest = strings.TrimPrefix(rest, "hf.co/")
	segs := strings.Split(rest, "/")
	if len(segs) != 4 {
		return hfResource{}, false
	}
	res := hfResource{Org: segs[0], Name: segs[1]}
	if !hfOrgRE.MatchString(res.Org) || !hfNameRE.MatchString(res.Name) {
		return hfResource{}, false
	}
	switch {
	case segs[2] == "manifests" && segs[3] != "":
		res.Route, res.Ref = "manifests", segs[3]
	case segs[2] == "blobs" && segs[3] != "":
		res.Route, res.Ref = "blobs", segs[3]
	case segs[2] == "tags" && segs[3] == "list":
		res.Route = "tags"
	default:
		return hfResource{}, false
	}
	return res, true
}

// serveHF handles every Hugging Face route on the high side: the friendly
// model-file download under /hf/, the Hub API for repository snapshots
// (/api/models/... and .../resolve/...), and the Ollama-compatible registry
// on the shared /v2/ space. There it runs before the container registry and
// claims a request only when it names a mirrored HF model — a container
// repository's first segment is a dotted registry host, which can never parse
// as an HF organization, and anything unclaimed (including non-GET methods,
// rejected uniformly as read-only) falls through to the container handler. It
// reports whether it wrote a response.
func (s *HighServer) serveHF(w http.ResponseWriter, r *http.Request) bool {
	if org, name, tag, ok := parseHFDownloadPath(r.URL.Path); ok {
		s.handleHFDownload(w, r, org, name, tag)
		return true
	}
	if hreq, ok := parseHFHubPath(r.URL.Path); ok {
		return s.serveHFHub(w, r, hreq)
	}
	res, ok := parseHFResourcePath(r.URL.Path)
	if !ok {
		return false
	}
	model, err := s.loadHFModelIndexFold(res.Org, res.Name)
	if err != nil {
		return false // not a mirrored model; let the container registry answer
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false // the container handler rejects writes uniformly
	}
	switch res.Route {
	case "manifests":
		s.handleHFManifest(w, r, model, res.Ref)
	case "blobs":
		s.handleHFBlob(w, r, model, res.Ref)
	default:
		s.handleHFTags(w, model)
	}
	return true
}

// findHFVariant resolves a tag or manifest digest against a model's index.
// Tags match exactly first, then case-insensitively — quantization tags are
// case-insensitive upstream, so :q4_0 pulls the variant collected as Q4_0.
func findHFVariant(model HFModel, ref string) (HFVariant, bool) {
	if containerDigestRE.MatchString(ref) {
		for _, v := range model.Variants {
			if v.Digest == ref {
				return v, true
			}
		}
		return HFVariant{}, false
	}
	for _, v := range model.Variants {
		if v.Tag == ref {
			return v, true
		}
	}
	for _, v := range model.Variants {
		if strings.EqualFold(v.Tag, ref) {
			return v, true
		}
	}
	return HFVariant{}, false
}

func (s *HighServer) handleHFManifest(w http.ResponseWriter, r *http.Request, model HFModel, ref string) {
	v, ok := findHFVariant(model, ref)
	if !ok {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "model variant not found")
		return
	}
	b, err := os.ReadFile(s.hfBlobPath(v.Digest))
	if err != nil {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest blob missing")
		return
	}
	mediaType := v.MediaType
	if mediaType == "" {
		mediaType = mtDockerManifest
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", v.Digest)
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

// handleHFBlob serves a model/config/side-car blob, but only when the
// requested model's index references it (per-model isolation over the shared
// store). http.ServeFile handles Range requests, so an interrupted ollama
// pull resumes.
func (s *HighServer) handleHFBlob(w http.ResponseWriter, r *http.Request, model HFModel, digest string) {
	if !containerDigestRE.MatchString(digest) {
		registryError(w, http.StatusNotFound, "DIGEST_INVALID", "invalid digest")
		return
	}
	if !hfModelReferencesBlob(model, digest) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}
	abs := s.hfBlobPath(digest)
	if !fileExists(abs) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", digest)
	http.ServeFile(w, r, abs)
}

// parseHFDownloadPath splits the friendly model-file route
// /hf/<org>/<name>/<tag>.gguf — a stable, human-readable URL for the variant's
// raw GGUF, for clients that load a file rather than pull from a registry
// (vLLM, llama.cpp).
func parseHFDownloadPath(p string) (org, name, tag string, ok bool) {
	rest, found := strings.CutPrefix(p, "/hf/")
	if !found {
		return "", "", "", false
	}
	segs := strings.Split(rest, "/")
	if len(segs) != 3 {
		return "", "", "", false
	}
	tag, found = strings.CutSuffix(segs[2], ".gguf")
	if !found {
		return "", "", "", false
	}
	org, name = segs[0], segs[1]
	if !hfOrgRE.MatchString(org) || !hfNameRE.MatchString(name) || !containerTagRE.MatchString(tag) {
		return "", "", "", false
	}
	return org, name, tag, true
}

// handleHFDownload serves a variant's model file (its GGUF layer) as a plain
// download with a descriptive filename. http.ServeFile handles Range requests,
// so interrupted downloads resume.
func (s *HighServer) handleHFDownload(w http.ResponseWriter, r *http.Request, org, name, tag string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	model, err := s.loadHFModelIndexFold(org, name)
	if err != nil {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	v, ok := findHFVariant(model, tag)
	if !ok {
		http.Error(w, "model variant not found", http.StatusNotFound)
		return
	}
	blob, ok := hfModelBlob(v)
	if !ok {
		http.Error(w, "variant has no model file", http.StatusNotFound)
		return
	}
	abs := s.hfBlobPath(blob.Digest)
	if !fileExists(abs) {
		http.Error(w, "model blob missing", http.StatusNotFound)
		return
	}
	// Name and tag are charset-validated, so the canonical-case filename is
	// header-safe as-is.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", hfDownloadFilename(model.Name, v.Tag)))
	w.Header().Set("Docker-Content-Digest", blob.Digest)
	http.ServeFile(w, r, abs)
}

// hfDownloadFilename is the suggested on-disk name for a variant's model
// file, e.g. "gpt-oss-20b-GGUF-Q4_0.gguf".
func hfDownloadFilename(name, tag string) string {
	return name + "-" + tag + ".gguf"
}

func hfModelReferencesBlob(model HFModel, digest string) bool {
	for _, v := range model.Variants {
		if v.Digest == digest {
			return true
		}
		for _, b := range v.Blobs {
			if b.Digest == digest {
				return true
			}
		}
	}
	return false
}

func (s *HighServer) handleHFTags(w http.ResponseWriter, model HFModel) {
	tags := []string{}
	for _, v := range model.Variants {
		tags = append(tags, v.Tag)
	}
	sort.Strings(tags)
	writeJSON(w, map[string]any{"name": model.Org + "/" + model.Name, "tags": tags})
}

// -----------------------------------------------------------------------------
// High side: Hub-compatible API for repository snapshots
// -----------------------------------------------------------------------------
//
// The subset of the Hub HTTP API that huggingface_hub clients (vLLM,
// transformers, `hf download`) use to download a model, served at the server
// root so clients simply set HF_ENDPOINT to this mirror:
//
//	GET /api/models/<org>/<name>[/revision/<rev>]  — model info (sha + file list)
//	GET /<org>/<name>/resolve/<rev>/<path>         — file download
//
// The resolve responses carry the ETag and X-Repo-Commit headers
// hf_hub_download reads, and misses carry the X-Error-Code values it maps to
// typed errors.

// hfHubRequest is one parsed Hub API request.
type hfHubRequest struct {
	Org  string
	Name string
	Rev  string // requested revision; empty means the default ("main")
	File string // repo-relative path for resolve requests; empty for info
	Info bool   // an /api/models info request
}

// parseHFHubPath recognizes the two Hub API shapes. /api/models/... is
// unambiguously this API's namespace; the resolve form is claimed only when
// it fully parses (org, name, revision, and a safe file path).
func parseHFHubPath(p string) (hfHubRequest, bool) {
	if rest, ok := strings.CutPrefix(p, "/api/models/"); ok {
		segs := strings.Split(rest, "/")
		switch {
		case len(segs) == 2:
			req := hfHubRequest{Org: segs[0], Name: segs[1], Info: true}
			return req, validHFHubRequest(req)
		case len(segs) == 4 && segs[2] == "revision" && segs[3] != "":
			req := hfHubRequest{Org: segs[0], Name: segs[1], Rev: segs[3], Info: true}
			return req, validHFHubRequest(req)
		}
		return hfHubRequest{}, false
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) >= 5 && segs[2] == "resolve" && segs[3] != "" {
		req := hfHubRequest{Org: segs[0], Name: segs[1], Rev: segs[3], File: strings.Join(segs[4:], "/")}
		if validateRelPath(req.File) != nil {
			return hfHubRequest{}, false
		}
		return req, validHFHubRequest(req)
	}
	return hfHubRequest{}, false
}

func validHFHubRequest(req hfHubRequest) bool {
	if !hfOrgRE.MatchString(req.Org) || !hfNameRE.MatchString(req.Name) {
		return false
	}
	return req.Rev == "" || hfRevRE.MatchString(req.Rev) || hfCommitRE.MatchString(req.Rev)
}

// hubError writes a Hub-style JSON error. The X-Error-Code header is what
// huggingface_hub maps to its typed errors (RepoNotFound, RevisionNotFound,
// EntryNotFound), giving clients clean messages instead of bare 404s.
func hubError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("X-Error-Code", code)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// serveHFHub dispatches one Hub API request. Info requests own their
// namespace and always answer; a resolve request for a repository that is not
// mirrored falls through (the URL space stays free for a 404 elsewhere).
func (s *HighServer) serveHFHub(w http.ResponseWriter, r *http.Request, hreq hfHubRequest) bool {
	if hreq.Info {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		s.handleHFHubInfo(w, hreq)
		return true
	}
	idx, err := s.loadHFRepoIndexFold(hreq.Org, hreq.Name)
	if err != nil {
		return false // not a mirrored repository
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	s.handleHFHubResolve(w, r, idx, hreq)
	return true
}

// handleHFHubInfo answers /api/models/...: the resolved commit hash plus the
// snapshot's file list — what snapshot_download and list_repo_files read.
func (s *HighServer) handleHFHubInfo(w http.ResponseWriter, hreq hfHubRequest) {
	idx, err := s.loadHFRepoIndexFold(hreq.Org, hreq.Name)
	if err != nil {
		hubError(w, http.StatusNotFound, "RepoNotFound", "repository not mirrored")
		return
	}
	snap, ok := resolveHFRepoRevision(idx, hreq.Rev)
	if !ok {
		hubError(w, http.StatusNotFound, "RevisionNotFound", "revision not mirrored")
		return
	}
	name := idx.Org + "/" + idx.Name
	siblings := make([]map[string]any, 0, len(snap.Files))
	for _, f := range snap.Files {
		siblings = append(siblings, map[string]any{"rfilename": f.Path, "size": f.Size})
	}
	writeJSON(w, map[string]any{
		"id":        name,
		"modelId":   name,
		"sha":       snap.Revision,
		"private":   false,
		"gated":     false,
		"disabled":  false,
		"downloads": 0,
		"likes":     0,
		"tags":      []string{},
		"siblings":  siblings,
	})
}

// handleHFHubResolve serves one repository file with the metadata headers
// hf_hub_download expects: a strong ETag (the file's sha256, its cache key)
// and X-Repo-Commit (the snapshot's commit, naming the client's snapshot
// directory). http.ServeFile handles Range requests and If-None-Match.
func (s *HighServer) handleHFHubResolve(w http.ResponseWriter, r *http.Request, idx HFRepoIndex, hreq hfHubRequest) {
	snap, ok := resolveHFRepoRevision(idx, hreq.Rev)
	if !ok {
		hubError(w, http.StatusNotFound, "RevisionNotFound", "revision not mirrored")
		return
	}
	var file HFRepoFile
	found := false
	for _, f := range snap.Files {
		if f.Path == hreq.File {
			file, found = f, true
			break
		}
	}
	if !found {
		hubError(w, http.StatusNotFound, "EntryNotFound", "file not in mirrored snapshot")
		return
	}
	abs := s.hfBlobPath("sha256:" + file.SHA256)
	if !fileExists(abs) {
		hubError(w, http.StatusNotFound, "EntryNotFound", "file blob missing")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+file.SHA256+`"`)
	w.Header().Set("X-Repo-Commit", snap.Revision)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(file.Path)))
	http.ServeFile(w, r, abs)
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail/repos
// -----------------------------------------------------------------------------

// listHFModels returns UIModule entries keyed "<org>/<name>" — variant tags
// and repository snapshot labels both appear as versions; the generic
// segment-tree builder groups them by organization at the top level.
func (s *HighServer) listHFModels() ([]UIModule, error) {
	byName := map[string]*UIModule{}
	var order []string
	add := func(name string, versions []string) {
		m, ok := byName[name]
		if !ok {
			m = &UIModule{Module: name}
			byName[name] = m
			order = append(order, name)
		}
		m.Versions = append(m.Versions, versions...)
	}
	modelNames, err := s.listHFModelNames()
	if err != nil {
		return nil, err
	}
	for _, name := range modelNames {
		model, ok := s.hfModelByName(name)
		if !ok {
			continue
		}
		var versions []string
		for _, v := range model.Variants {
			versions = append(versions, v.Tag)
		}
		sort.Strings(versions)
		add(name, versions)
	}
	repoNames, err := s.listHFRepoNames()
	if err != nil {
		return nil, err
	}
	for _, name := range repoNames {
		idx, ok := s.hfRepoIndexByName(name)
		if !ok {
			continue
		}
		add(name, hfRepoVersionLabels(idx))
	}
	sort.Strings(order)
	mods := make([]UIModule, 0, len(order))
	for _, name := range order {
		mods = append(mods, *byName[name])
	}
	return mods, nil
}

// hfRepoIndexByName loads a repository index by its "<org>/<name>" key.
func (s *HighServer) hfRepoIndexByName(name string) (HFRepoIndex, bool) {
	org, repo, ok := strings.Cut(name, "/")
	if !ok || !hfOrgRE.MatchString(org) || !hfNameRE.MatchString(repo) {
		return HFRepoIndex{}, false
	}
	idx, err := s.loadHFRepoIndex(org, repo)
	if err != nil {
		return HFRepoIndex{}, false
	}
	return idx, true
}

// hfRepoVersionLabels renders a repository's dashboard version labels: the
// collected refs ("main"), plus a short commit for any snapshot no ref points
// at.
func hfRepoVersionLabels(idx HFRepoIndex) []string {
	referenced := map[string]bool{}
	var out []string
	for ref, commit := range idx.Refs {
		referenced[commit] = true
		out = append(out, ref)
	}
	for _, snap := range idx.Snapshots {
		if !referenced[snap.Revision] {
			out = append(out, shortCommit(snap.Revision))
		}
	}
	sort.Strings(out)
	return out
}

// hfModelByName loads a model index by its "<org>/<name>" key.
func (s *HighServer) hfModelByName(name string) (HFModel, bool) {
	org, repo, ok := strings.Cut(name, "/")
	if !ok || !hfOrgRE.MatchString(org) || !hfNameRE.MatchString(repo) {
		return HFModel{}, false
	}
	model, err := s.loadHFModelIndex(org, repo)
	if err != nil {
		return HFModel{}, false
	}
	return model, true
}

// hfRepoList lists the mirrored content for the "Set me up" guide: GGUF
// models with their variant tags, and full repository snapshots (marked with
// Kind "repo" so the guide renders the HF_ENDPOINT workflow for them).
func (s *HighServer) hfRepoList() ([]UIRepo, error) {
	names, err := s.listHFModelNames()
	if err != nil {
		return nil, err
	}
	repos := make([]UIRepo, 0, len(names))
	for _, name := range names {
		model, ok := s.hfModelByName(name)
		if !ok {
			continue
		}
		var tags []string
		for _, v := range model.Variants {
			tags = append(tags, v.Tag)
		}
		sort.Strings(tags)
		repos = append(repos, UIRepo{Name: name, Tags: tags})
	}
	repoNames, err := s.listHFRepoNames()
	if err != nil {
		return nil, err
	}
	for _, name := range repoNames {
		idx, ok := s.hfRepoIndexByName(name)
		if !ok {
			continue
		}
		repos = append(repos, UIRepo{Name: name, Tags: hfRepoVersionLabels(idx), Kind: "repo"})
	}
	return repos, nil
}

// hfModelConfig is the part of a variant's config blob ArtiGate reads for the
// dashboard: what kind of model this is and how it is quantized.
type hfModelConfig struct {
	ModelFormat string `json:"model_format"` // e.g. gguf
	ModelFamily string `json:"model_family"` // e.g. gptoss
	ModelType   string `json:"model_type"`   // parameter count, e.g. 20.9B
	FileType    string `json:"file_type"`    // quantization, e.g. Q4_0
}

// hfDetail describes one model variant or repository snapshot for the
// dashboard. spec is "<org>/<name>@<tag-revision-or-digest>".
func (s *HighServer) hfDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid model spec")
	}
	name, ref := spec[:i], spec[i+1:]
	if model, ok := s.hfModelByName(name); ok {
		if v, ok := findHFVariant(model, ref); ok {
			return s.hfVariantDetail(name, v), nil
		}
	}
	if idx, ok := s.hfRepoIndexByName(name); ok {
		if detail, ok := s.hfRepoDetail(idx, ref); ok {
			return detail, nil
		}
	}
	return UIDetail{}, errors.New("variant not found")
}

// hfVariantDetail describes one GGUF variant.
func (s *HighServer) hfVariantDetail(name string, v HFVariant) UIDetail {
	fields := []UIDetailField{
		{Label: "Model", Value: name, Mono: true},
		{Label: "Variant", Value: v.Tag, Mono: true},
	}
	fields = append(fields, s.hfConfigFields(v)...)
	var total int64
	for _, b := range v.Blobs {
		total += b.Size
	}
	fields = append(fields, UIDetailField{Label: "Manifest digest", Value: v.Digest, Mono: true})
	if modelBlob, ok := hfModelBlob(v); ok {
		fields = append(fields,
			UIDetailField{Label: "Model file size", Value: formatBytes(modelBlob.Size)},
			UIDetailField{Label: "Model file", Value: "/v2/" + name + "/blobs/" + modelBlob.Digest, Mono: true},
			// The friendly route for clients that load a file instead of
			// pulling from a registry (vLLM, llama.cpp).
			UIDetailField{Label: "Download", Value: "/hf/" + name + "/" + v.Tag + ".gguf", Mono: true},
		)
	}
	fields = append(fields, UIDetailField{Label: "Total blob size", Value: formatBytes(total)})
	// CopyRef is the host-relative pull reference; the dashboard prepends its
	// own host, so the operator copies exactly what `ollama pull` needs.
	return UIDetail{
		Title:    name,
		Subtitle: v.Tag,
		Fields:   fields,
		CopyRef:  name + ":" + v.Tag,
	}
}

// hfRepoDetail describes one repository snapshot, matched by ref name, full
// commit, or the short-commit label the tree shows.
func (s *HighServer) hfRepoDetail(idx HFRepoIndex, ref string) (UIDetail, bool) {
	snap, label, ok := findHFRepoSnapshot(idx, ref)
	if !ok {
		return UIDetail{}, false
	}
	name := idx.Org + "/" + idx.Name
	var total int64
	for _, f := range snap.Files {
		total += f.Size
	}
	fields := []UIDetailField{
		{Label: "Repository", Value: name, Mono: true},
	}
	if label != "" {
		fields = append(fields, UIDetailField{Label: "Ref", Value: label, Mono: true})
	}
	fields = append(fields,
		UIDetailField{Label: "Revision", Value: snap.Revision, Mono: true},
		UIDetailField{Label: "Files", Value: fmt.Sprint(len(snap.Files))},
		UIDetailField{Label: "Total size", Value: formatBytes(total)},
		UIDetailField{Label: "Example file", Value: "/" + name + "/resolve/" + snap.Revision + "/" + firstHFRepoFile(snap), Mono: true},
		UIDetailField{Label: "Clients", Value: "set HF_ENDPOINT to this server (vLLM, transformers, hf download)"},
	)
	subtitle := label
	if subtitle == "" {
		subtitle = shortCommit(snap.Revision)
	}
	return UIDetail{Title: name, Subtitle: subtitle, Fields: fields}, true
}

// findHFRepoSnapshot resolves a dashboard version label — a ref name, a full
// commit, or a short commit — returning the ref name when one matched.
func findHFRepoSnapshot(idx HFRepoIndex, ref string) (HFRepoSnapshot, string, bool) {
	if commit, ok := idx.Refs[ref]; ok {
		for _, snap := range idx.Snapshots {
			if snap.Revision == commit {
				return snap, ref, true
			}
		}
	}
	for _, snap := range idx.Snapshots {
		if snap.Revision == ref || shortCommit(snap.Revision) == ref {
			return snap, "", true
		}
	}
	return HFRepoSnapshot{}, "", false
}

// firstHFRepoFile picks a representative file for the detail panel's example
// resolve URL (config.json when present — every Hub client fetches it first).
func firstHFRepoFile(snap HFRepoSnapshot) string {
	for _, f := range snap.Files {
		if f.Path == "config.json" {
			return f.Path
		}
	}
	if len(snap.Files) > 0 {
		return snap.Files[0].Path
	}
	return ""
}

// hfModelBlob returns the variant's model-file layer (the GGUF itself).
func hfModelBlob(v HFVariant) (HFBlob, bool) {
	for _, b := range v.Blobs {
		if b.MediaType == mtOllamaModel {
			return b, true
		}
	}
	return HFBlob{}, false
}

// hfConfigFields reads the variant's config blob and renders its format,
// family, parameter count, and quantization. Missing or unreadable configs
// simply contribute no fields.
func (s *HighServer) hfConfigFields(v HFVariant) []UIDetailField {
	if len(v.Blobs) == 0 {
		return nil
	}
	b, err := os.ReadFile(s.hfBlobPath(v.Blobs[0].Digest)) // Blobs[0] is the config
	if err != nil {
		return nil
	}
	var cfg hfModelConfig
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	var fields []UIDetailField
	for _, f := range []struct{ label, value string }{
		{"Format", cfg.ModelFormat},
		{"Family", cfg.ModelFamily},
		{"Parameters", cfg.ModelType},
		{"Quantization", cfg.FileType},
	} {
		if f.value != "" {
			fields = append(fields, UIDetailField{Label: f.label, Value: f.value})
		}
	}
	return fields
}
