package main

// Container (OCI/Docker image) ecosystem adapter — mirrors images for
// linux/amd64 only.
//
// Low side: resolve each image reference against its upstream registry using
// the OCI Distribution HTTP API (anonymous Bearer-token auth), pick the
// linux/amd64 manifest out of a multi-platform index, download the config and
// every layer blob (streamed to disk, SHA-256 verified against the manifest's
// digests), and pack everything into the standard signed ArtiGate bundle.
// Blobs are stored content-addressed, so layers shared between images are
// bundled once.
//
// High side: images from different upstream registries are kept in separate
// namespaces — the served repository name is "<registry>/<repository>"
// (e.g. docker.io/library/alpine), so docker.io and ghcr.io content never
// mixes. The high side serves a read-only OCI Distribution registry under
// /v2/, enough for docker/podman/containerd to pull:
//
//	docker pull <high-host>/docker.io/library/alpine:3.20

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	goversion "github.com/hashicorp/go-version"
)

// containersEcosystem is the container image stream's registry entry (see
// ecosystems in ecosystem.go).
func containersEcosystem() ecosystem {
	return ecosystem{
		stream:       streamContainers,
		label:        "Containers",
		title:        "Container images",
		collect:      (*LowServer).HandleContainerCollect,
		watchCollect: watchAdapter((*LowServer).CollectContainers),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.ContainerRegistries, "container-registry", "", "comma-separated host=baseURL overrides for container registries (e.g. docker.io=https://mirror.example.com)")
		},
		manifestContent: func(m BundleManifest) bool { return m.Containers != nil && len(m.Containers.Repos) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateContainerRepos(m.Containers.Repos, seen, m.Files)
		},
		contentDesc: "container repos",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishContainers(m.Containers) },
		serve:       (*HighServer).serveContainers,
		scanTree:    segmentTreeScan((*HighServer).listContainerRepos),
		detail:      (*HighServer).containerDetail,
		repoList:    (*HighServer).containerRepoList,
	}
}

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type ContainerManifest struct {
	Repos []ContainerRepo `json:"repos"`
}

// ContainerRepo is one repository on one upstream registry. Registry and
// Repository stay separate so the high side can namespace by origin.
type ContainerRepo struct {
	Registry   string           `json:"registry"`   // e.g. docker.io
	Repository string           `json:"repository"` // e.g. library/alpine
	Images     []ContainerImage `json:"images"`
}

// ContainerImage is one resolved linux/amd64 image manifest. Digest is the
// SHA-256 of the stored manifest blob; Blobs lists the config and layers it
// references (all stored content-addressed under containers/blobs/).
type ContainerImage struct {
	Tag       string          `json:"tag,omitempty"`
	Digest    string          `json:"digest"`
	MediaType string          `json:"media_type"`
	Size      int64           `json:"size"`
	Blobs     []ContainerBlob `json:"blobs"`
}

type ContainerBlob struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// containerBlobShardHex returns a blob's sharding subdirectory: the first three
// characters of its hex digest, which spreads blobs across 16^3 = 4096
// directories so no single directory holds the entire store. Docker's own
// registry and git use the same first-N-hex-character scheme. Digests are
// validated to 64 hex chars before they reach here; the guard only avoids a
// panic on malformed input.
func containerBlobShardHex(hex string) string {
	if len(hex) < 3 {
		return hex
	}
	return hex[:3]
}

// shortDigest abbreviates a "sha256:<hex>" digest to its first 12 hex
// characters for progress lines, matching how docker displays layer IDs.
func shortDigest(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// containerBlobRel returns the bundle/repository-relative path of a blob,
// e.g. containers/blobs/sha256/ab1/ab12... The store is content-addressed and
// shared across repositories, so identical layers are kept once; blobs are
// sharded by digest prefix (see containerBlobShardHex) to keep any one
// directory small.
func containerBlobRel(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	return path.Join("containers", "blobs", "sha256", containerBlobShardHex(hex), hex)
}

// -----------------------------------------------------------------------------
// Image references and OCI protocol constants
// -----------------------------------------------------------------------------

const (
	containerDefaultRegistry = "docker.io"
	// Docker Hub's API endpoint differs from its logical registry name.
	containerDockerHubAPI = "https://registry-1.docker.io"

	mtDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mtDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtOCIIndex       = "application/vnd.oci.image.index.v1+json"
)

// containerManifestAccept is the Accept header for manifest requests: both
// single-image manifests and multi-platform indexes, Docker and OCI flavors.
const containerManifestAccept = mtDockerManifest + ", " + mtOCIManifest + ", " + mtDockerList + ", " + mtOCIIndex

var (
	// containerRepoComponentRE matches one repository path component per the
	// distribution spec (lowercase alphanumerics with ., _, __, or - separators).
	containerRepoComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$`)
	containerTagRE           = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	containerDigestRE        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	containerRegistryRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
)

// imageRef is a parsed image reference: registry host, repository path, and a
// tag, digest, or version constraint in the tag position.
type imageRef struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	// Constraint is a version constraint written where a tag would be
	// ("golang:1.26.x", "golang:<2.0.0"); the collector resolves it to the
	// newest matching numeric tag at collect time.
	Constraint string
}

// String renders the reference back in its familiar form, for messages.
func (r imageRef) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Constraint != "" {
		s += ":" + r.Constraint
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// parseImageRef parses a docker-style image reference such as "alpine:3.20",
// "ghcr.io/org/app:v1", or "registry.access.redhat.com/ubi9/ubi@sha256:...".
// Docker Hub short names are normalized ("alpine" -> docker.io/library/alpine)
// and a missing tag defaults to "latest".
func parseImageRef(spec string) (imageRef, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return imageRef{}, errors.New("empty image reference")
	}
	var ref imageRef
	rest := spec
	if i := strings.Index(rest, "@"); i >= 0 {
		ref.Digest = rest[i+1:]
		rest = rest[:i]
		if !containerDigestRE.MatchString(ref.Digest) {
			return imageRef{}, fmt.Errorf("invalid digest in %q (need sha256:<64 hex>)", spec)
		}
	}
	// The tag is after the last ':' that follows the last '/'; a ':' before a
	// '/' belongs to a registry port, which is not supported (see below).
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		ref.Tag = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	// A version constraint may stand where a tag would ("1.26.x", "<2.0.0");
	// it is resolved to the newest matching numeric tag at collect time.
	if looksLikeVersionConstraint(ref.Tag) {
		if ref.Digest != "" {
			return imageRef{}, fmt.Errorf("%q pins a digest and cannot also carry the version constraint %q", spec, ref.Tag)
		}
		ref.Constraint = ref.Tag
		ref.Tag = ""
		if _, err := parseVersionConstraint(ref.Constraint); err != nil {
			return imageRef{}, fmt.Errorf("invalid version constraint %q in %q: %w", ref.Constraint, spec, err)
		}
	}
	ref.Registry, ref.Repository = splitRegistryRepo(rest)
	if ref.Tag == "" && ref.Digest == "" && ref.Constraint == "" {
		ref.Tag = "latest"
	}
	return ref, validateImageRef(spec, ref)
}

// splitRegistryRepo splits "host/path" per docker's rule: the first component
// is a registry only if it looks like a host (contains '.' or ':', or is
// "localhost"); otherwise the whole string is a Docker Hub repository, with
// single-component names moved under library/.
func splitRegistryRepo(s string) (registry, repository string) {
	first, rest, ok := strings.Cut(s, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return normalizeContainerRegistry(first), rest
	}
	if !strings.Contains(s, "/") {
		s = "library/" + s
	}
	return containerDefaultRegistry, s
}

// normalizeContainerRegistry folds Docker Hub's aliases into "docker.io".
func normalizeContainerRegistry(host string) string {
	switch strings.ToLower(host) {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return containerDefaultRegistry
	default:
		return strings.ToLower(host)
	}
}

func validateImageRef(spec string, ref imageRef) error {
	if strings.Contains(ref.Registry, ":") {
		return fmt.Errorf("registry %q in %q has a port; registries on non-standard ports cannot be mirrored (the port cannot appear in the high-side pull name)", ref.Registry, spec)
	}
	if !containerRegistryRE.MatchString(ref.Registry) {
		return fmt.Errorf("invalid registry host %q in %q", ref.Registry, spec)
	}
	if err := validateContainerRepository(ref.Repository); err != nil {
		return fmt.Errorf("%w in %q", err, spec)
	}
	if ref.Tag != "" && !containerTagRE.MatchString(ref.Tag) {
		return fmt.Errorf("invalid tag %q in %q", ref.Tag, spec)
	}
	return nil
}

func validateContainerRepository(repository string) error {
	if repository == "" {
		return errors.New("empty repository")
	}
	for _, comp := range strings.Split(repository, "/") {
		if !containerRepoComponentRE.MatchString(comp) {
			return fmt.Errorf("invalid repository %q", repository)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Version constraints in the tag position ("golang:1.26.x", "golang:<2.0.0")
// -----------------------------------------------------------------------------

var (
	// containerWildcardRE matches wildcard version patterns such as "1.26.x",
	// "1.x", "2.x.x", or "1.26.*".
	containerWildcardRE = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*(\.[x*])+$`)
	// containerNumericTagRE matches the plain numeric tags ("1.26.3", "v2.0",
	// "17") that constraint resolution considers; variant tags such as
	// "1.26.3-alpine" are ignored so a variant never outranks the plain image.
	containerNumericTagRE = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}$`)
	// containerWildcardPartRE rewrites ".x"/".*" components inside an operator
	// expression ("< 2.x.x" -> "< 2.0.0").
	containerWildcardPartRE = regexp.MustCompile(`([0-9])\.[x*]`)
)

// looksLikeVersionConstraint reports whether the tag position holds a version
// constraint rather than an exact tag: an operator expression ("<2.0.0",
// ">= 1.24, < 2.0", "~> 1.26") or a wildcard pattern ("1.26.x"). Plain
// versions like "3.20" remain exact tags. (A repository could in principle
// publish a literal tag named "1.26.x"; such a tag cannot be pulled through
// ArtiGate — pin its digest instead.)
func looksLikeVersionConstraint(tag string) bool {
	if tag == "" {
		return false
	}
	if tag == "x" || tag == "*" {
		return true
	}
	return strings.ContainsAny(tag, "<>=~!, ") || containerWildcardRE.MatchString(tag)
}

// parseVersionConstraint turns the accepted constraint syntaxes into a
// hashicorp/go-version constraint set.
func parseVersionConstraint(spec string) (goversion.Constraints, error) {
	return goversion.NewConstraint(normalizeVersionConstraint(spec))
}

// normalizeVersionConstraint rewrites the user-facing syntaxes into what
// go-version understands: "1.26.x" becomes ">= 1.26.0, < 1.27.0", wildcard
// components inside operators become zeros ("< 2.x.x" -> "< 2.0.0"), and a
// bare "x"/"*" matches everything.
func normalizeVersionConstraint(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "x" || spec == "*" {
		return ">= 0"
	}
	if containerWildcardRE.MatchString(spec) {
		return wildcardToRange(spec)
	}
	// Operator expression: collapse any wildcard components to .0 repeatedly
	// (each pass rewrites one level: "2.x.x" -> "2.0.x" -> "2.0.0").
	for strings.ContainsAny(spec, "x*") {
		rewritten := containerWildcardPartRE.ReplaceAllString(spec, "${1}.0")
		if rewritten == spec {
			break
		}
		spec = rewritten
	}
	return spec
}

// wildcardToRange converts "1.26.x" style patterns into the half-open range
// they mean: ">= 1.26.0, < 1.27.0" (and "1.x" into ">= 1.0.0, < 2.0.0").
func wildcardToRange(pattern string) string {
	parts := strings.Split(strings.TrimPrefix(pattern, "v"), ".")
	var fixed []string
	for _, p := range parts {
		if p == "x" || p == "*" {
			break
		}
		fixed = append(fixed, p)
	}
	if len(fixed) == 0 {
		return ">= 0"
	}
	lower := make([]string, 3)
	upper := make([]string, 3)
	for i := 0; i < 3; i++ {
		lower[i], upper[i] = "0", "0"
		if i < len(fixed) {
			lower[i], upper[i] = fixed[i], fixed[i]
		}
	}
	// Increment the last fixed component for the exclusive upper bound.
	last := len(fixed) - 1
	if last > 2 {
		last = 2
	}
	n, err := strconv.Atoi(upper[last])
	if err != nil {
		return pattern // unreachable given the wildcard RE; fail in NewConstraint
	}
	upper[last] = strconv.Itoa(n + 1)
	for i := last + 1; i < 3; i++ {
		upper[i] = "0"
	}
	return fmt.Sprintf(">= %s, < %s", strings.Join(lower, "."), strings.Join(upper, "."))
}

// -----------------------------------------------------------------------------
// OCI descriptor / manifest JSON shapes
// -----------------------------------------------------------------------------

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type ociDescriptor struct {
	MediaType string       `json:"mediaType"`
	Digest    string       `json:"digest"`
	Size      int64        `json:"size"`
	Platform  *ociPlatform `json:"platform,omitempty"`
}

// ociManifest covers both an image manifest (Config/Layers) and an index
// (Manifests); the media type says which fields are meaningful.
type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
	Manifests []ociDescriptor `json:"manifests"`
}

func isContainerIndexType(mt string) bool {
	return mt == mtDockerList || mt == mtOCIIndex
}

func isContainerManifestType(mt string) bool {
	return mt == mtDockerManifest || mt == mtOCIManifest
}

// pickAmd64Manifest returns the linux/amd64 entry of a multi-platform index.
// Attestation entries (platform "unknown/unknown") simply never match.
func pickAmd64Manifest(entries []ociDescriptor) (ociDescriptor, error) {
	for _, d := range entries {
		if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == "amd64" {
			return d, nil
		}
	}
	return ociDescriptor{}, errors.New("image has no linux/amd64 manifest")
}

// -----------------------------------------------------------------------------
// Low side: registry client (stdlib only, anonymous Bearer-token auth)
// -----------------------------------------------------------------------------

// containerAPIBase returns the HTTPS API endpoint for a registry, honoring any
// configured override (used for private mirrors and tests).
func (s *LowServer) containerAPIBase(registry string) string {
	if base, ok := s.containerRegistryBases[registry]; ok {
		return base
	}
	if registry == containerDefaultRegistry {
		return containerDockerHubAPI
	}
	return "https://" + registry
}

// parseContainerRegistryOverrides parses the --container-registry flag value:
// comma-separated host=baseURL pairs mapping a registry name to the endpoint
// its API is actually fetched from.
func parseContainerRegistryOverrides(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		host, base, ok := strings.Cut(pair, "=")
		if !ok || host == "" || base == "" {
			return nil, fmt.Errorf("invalid --container-registry entry %q (need host=baseURL)", pair)
		}
		u, err := url.Parse(base)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid --container-registry base URL %q (need http/https)", base)
		}
		out[normalizeContainerRegistry(host)] = strings.TrimRight(base, "/")
	}
	return out, nil
}

// containerClient talks to upstream registries for one collect run, caching
// one anonymous pull token per repository.
type containerClient struct {
	ls     *LowServer
	tokens map[string]string // "<registry>/<repository>" -> Bearer token
	// prior reports whether a blob (bundle path + sha256) was already
	// forwarded on the containers stream, letting the collector skip the
	// download and emit a prior manifest reference. Nil means never skip.
	prior func(path, sha256 string) bool
}

func (s *LowServer) newContainerClient() *containerClient {
	return &containerClient{ls: s, tokens: map[string]string{}}
}

// get performs one registry API request (urlPath is relative to /v2/), doing
// the Bearer token dance on a 401 and retrying once. The caller must close the
// returned body.
func (c *containerClient) get(ctx context.Context, ref imageRef, urlPath, accept string) (*http.Response, error) {
	full := c.ls.containerAPIBase(ref.Registry) + "/v2/" + ref.Repository + "/" + urlPath
	key := ref.Registry + "/" + ref.Repository
	resp, err := c.doContainerGet(ctx, full, accept, c.tokens[key])
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("Www-Authenticate")
	_ = resp.Body.Close()
	token, err := c.fetchToken(ctx, challenge, ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref.Registry, err)
	}
	c.tokens[key] = token
	resp, err = c.doContainerGet(ctx, full, accept, token)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: unauthorized (only anonymous pulls of public images are supported)", full)
	}
	return resp, nil
}

func (c *containerClient) doContainerGet(ctx context.Context, rawURL, accept, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		// net/http drops Authorization on cross-host redirects, so a CDN
		// redirect for a blob (S3 etc.) is followed without leaking the token.
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

// fetchToken obtains an anonymous pull token from the endpoint named in a
// Bearer WWW-Authenticate challenge.
func (c *containerClient) fetchToken(ctx context.Context, challenge, repository string) (string, error) {
	realm, params, err := parseBearerChallenge(challenge)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + repository + ":pull"
	}
	q.Set("scope", scope)
	tokenURL := realm + "?" + q.Encode()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %s: HTTP %d", realm, resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.Token == "" {
		tok.Token = tok.AccessToken
	}
	if tok.Token == "" {
		return "", errors.New("token endpoint returned no token")
	}
	return tok.Token, nil
}

// parseBearerChallenge extracts the realm and parameters from a header like
// `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`.
func parseBearerChallenge(challenge string) (realm string, params map[string]string, err error) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(challenge), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", nil, fmt.Errorf("registry requires unsupported authentication %q (only anonymous Bearer pulls are supported)", scheme)
	}
	params = map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		params[strings.ToLower(k)] = strings.Trim(v, `"`)
	}
	realm = params["realm"]
	if realm == "" {
		return "", nil, errors.New("Bearer challenge has no realm")
	}
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", nil, fmt.Errorf("invalid Bearer realm %q", realm)
	}
	return realm, params, nil
}

// fetchContainerManifest downloads a manifest by tag or digest, verifies its
// digest, and — when it is a multi-platform index — follows it down to the
// linux/amd64 image manifest. It returns the image manifest's raw bytes,
// media type, and digest.
func (c *containerClient) fetchContainerManifest(ctx context.Context, ref imageRef) (body []byte, mediaType, digest string, err error) {
	reference := ref.Digest
	if reference == "" {
		reference = ref.Tag
	}
	body, mediaType, digest, err = c.fetchManifestRaw(ctx, ref, reference)
	if err != nil {
		return nil, "", "", err
	}
	if !isContainerIndexType(mediaType) {
		return body, mediaType, digest, nil
	}
	var index ociManifest
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, "", "", fmt.Errorf("%s: parse manifest index: %w", ref, err)
	}
	desc, err := pickAmd64Manifest(index.Manifests)
	if err != nil {
		return nil, "", "", fmt.Errorf("%s: %w", ref, err)
	}
	sub := ref
	sub.Digest, sub.Tag = desc.Digest, ""
	return c.fetchManifestRaw(ctx, sub, desc.Digest)
}

// fetchManifestRaw fetches one manifest document and verifies its content
// digest (against the requested digest, when fetching by digest).
func (c *containerClient) fetchManifestRaw(ctx context.Context, ref imageRef, reference string) (body []byte, mediaType, digest string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.get(ctx, ref, "manifests/"+reference, containerManifestAccept)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("%s: manifest %s: HTTP %d", ref, reference, resp.StatusCode)
	}
	sum := sha256.Sum256(body)
	digest = "sha256:" + hex.EncodeToString(sum[:])
	if containerDigestRE.MatchString(reference) && digest != reference {
		return nil, "", "", fmt.Errorf("%s: manifest digest mismatch: got %s want %s", ref, digest, reference)
	}
	mediaType = resp.Header.Get("Content-Type")
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	if !isContainerManifestType(mediaType) && !isContainerIndexType(mediaType) {
		// Some registries omit or mangle the Content-Type; fall back to the
		// document's own mediaType field.
		var m ociManifest
		if json.Unmarshal(body, &m) == nil && (isContainerManifestType(m.MediaType) || isContainerIndexType(m.MediaType)) {
			mediaType = m.MediaType
		} else {
			return nil, "", "", fmt.Errorf("%s: unsupported manifest media type %q", ref, mediaType)
		}
	}
	return body, mediaType, digest, nil
}

// resolveConstraintTag resolves a version-constraint reference to the newest
// upstream tag satisfying it. Only plain numeric tags (1.26.3, v2.0, 17) are
// considered, so variant tags like "1.26.3-alpine" never outrank the plain
// image; when two tags name the same version ("1.26" and "1.26.0"), the more
// specific one wins.
func (c *containerClient) resolveConstraintTag(ctx context.Context, ref imageRef) (string, error) {
	constraints, err := parseVersionConstraint(ref.Constraint)
	if err != nil {
		return "", err
	}
	tags, err := c.listUpstreamTags(ctx, ref)
	if err != nil {
		return "", err
	}
	var bestTag string
	var bestVer *goversion.Version
	for _, tag := range tags {
		if !containerNumericTagRE.MatchString(tag) {
			continue
		}
		v, err := goversion.NewVersion(tag)
		if err != nil || !constraints.Check(v) {
			continue
		}
		if bestVer == nil || v.GreaterThan(bestVer) || (v.Equal(bestVer) && len(tag) > len(bestTag)) {
			bestVer, bestTag = v, tag
		}
	}
	if bestTag == "" {
		return "", fmt.Errorf("%s/%s: no numeric tag matches %q (%d tags upstream; variant tags like 1.2.3-alpine are not considered)",
			ref.Registry, ref.Repository, ref.Constraint, len(tags))
	}
	return bestTag, nil
}

// listUpstreamTags fetches a repository's full tag list, following the
// distribution API's Link-header pagination.
func (c *containerClient) listUpstreamTags(ctx context.Context, ref imageRef) ([]string, error) {
	var all []string
	next := "tags/list?n=1000"
	// The page cap is a runaway guard; 100 pages is a million tags.
	for page := 0; page < 100 && next != ""; page++ {
		tags, link, err := c.fetchTagPage(ctx, ref, next)
		if err != nil {
			return nil, err
		}
		all = append(all, tags...)
		next = link
	}
	return all, nil
}

// fetchTagPage fetches one page of tags/list and returns the next page's
// query (rebuilt from the Link header), or "" on the last page.
func (c *containerClient) fetchTagPage(ctx context.Context, ref imageRef, urlPath string) (tags []string, next string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.get(ctx, ref, urlPath, "application/json")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s/%s: tags/list: HTTP %d", ref.Registry, ref.Repository, resp.StatusCode)
	}
	var list struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, "", fmt.Errorf("%s/%s: parse tags/list: %w", ref.Registry, ref.Repository, err)
	}
	return list.Tags, nextTagPage(resp.Header.Get("Link")), nil
}

// nextTagPage extracts the follow-up tags/list query from a pagination Link
// header like `</v2/library/golang/tags/list?last=1.20&n=1000>; rel="next"`.
// The path always names the same endpoint, so only the query is kept.
func nextTagPage(link string) string {
	if link == "" || !strings.Contains(link, `rel="next"`) {
		return ""
	}
	start := strings.IndexByte(link, '<')
	end := strings.IndexByte(link, '>')
	if start < 0 || end <= start {
		return ""
	}
	u, err := url.Parse(link[start+1 : end])
	if err != nil || u.RawQuery == "" {
		return ""
	}
	return "tags/list?" + u.RawQuery
}

// downloadContainerBlob streams one blob into the staging blob store,
// verifying its size and SHA-256 against the manifest's descriptor. Blobs
// already staged (shared layers) are skipped. When allowPrior is set, a blob
// whose digest this stream has already forwarded is not downloaded at all —
// it becomes a prior manifest reference (blobs are content-addressed, so the
// descriptor supplies everything the manifest entry needs).
func (c *containerClient) downloadContainerBlob(ctx context.Context, ref imageRef, desc ociDescriptor, stageRoot string, seen map[string]bool, allowPrior bool) (ManifestFile, error) {
	if !containerDigestRE.MatchString(desc.Digest) {
		return ManifestFile{}, fmt.Errorf("%s: unsupported blob digest %q (only sha256 is supported)", ref, desc.Digest)
	}
	if desc.Size <= 0 {
		return ManifestFile{}, fmt.Errorf("%s: blob %s has no size in the manifest", ref, desc.Digest)
	}
	rel := containerBlobRel(desc.Digest)
	mf := ManifestFile{Path: rel, SHA256: strings.TrimPrefix(desc.Digest, "sha256:"), Size: desc.Size}
	if seen[rel] {
		return mf, nil
	}
	if allowPrior && c.prior != nil && c.prior(rel, mf.SHA256) {
		emitProgress(ctx, "    ≡ blob %s already forwarded (download skipped)", shortDigest(desc.Digest))
		seen[rel] = true
		mf.Prior = true
		return mf, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
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
	seen[rel] = true
	return mf, nil
}

// writeVerifiedBlob streams r to abs while hashing, and fails (removing the
// file) unless exactly wantSize bytes arrived with SHA-256 wantSHA. Layers can
// be gigabytes, so this never buffers the blob in memory.
func writeVerifiedBlob(abs string, r io.Reader, wantSize int64, wantSHA string) error {
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, wantSize+1))
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		_ = os.Remove(abs)
		return err
	}
	if n != wantSize {
		_ = os.Remove(abs)
		return fmt.Errorf("size mismatch: got %d want %d", n, wantSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		_ = os.Remove(abs)
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, wantSHA)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Low side: collector
// -----------------------------------------------------------------------------

// ContainerCollectRequest is the body of POST /admin/containers/collect:
// docker-style image references, e.g. "alpine:3.20" or
// "ghcr.io/org/app@sha256:...". Only linux/amd64 is mirrored.
type ContainerCollectRequest struct {
	Images []string `json:"images"`
	// Force disables export dedup for this collect: every blob is downloaded
	// and packed even when already forwarded, producing a full self-contained
	// bundle (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

func (s *LowServer) HandleContainerCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req ContainerCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse container collect request: %w", err)
		}
	}
	return s.CollectContainers(ctx, req)
}

// CollectContainers mirrors the requested images (linux/amd64) into a signed
// bundle on the containers stream. An image that cannot be fetched is skipped
// and reported, so one broken reference never blocks the rest of the batch.
func (s *LowServer) CollectContainers(ctx context.Context, req ContainerCollectRequest) (ExportResult, error) {
	refs, err := parseContainerCollectRefs(req.Images)
	if err != nil {
		return ExportResult{}, err
	}

	mu := s.streamLock(streamContainers)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "containers", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	emitProgress(ctx, "Resolving %d image reference(s) (linux/amd64)…", len(refs))
	repos, files, failed := s.mirrorContainerImages(ctx, refs, stageRoot, req.Force)
	if len(repos) == 0 {
		return ExportResult{}, fmt.Errorf("no images could be fetched: %s", summarizeFailures(failed))
	}

	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	res, err := s.exportIfNew(ctx, streamContainers, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeContainerBundle(ctx, seq, stageRoot, files, repos)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// parseContainerCollectRefs parses and de-duplicates the requested references.
func parseContainerCollectRefs(images []string) ([]imageRef, error) {
	if len(images) == 0 {
		return nil, errors.New("no images provided")
	}
	var refs []imageRef
	seen := map[string]bool{}
	for _, spec := range images {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		ref, err := parseImageRef(spec)
		if err != nil {
			return nil, err
		}
		if key := ref.String(); !seen[key] {
			seen[key] = true
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return nil, errors.New("no images provided")
	}
	return refs, nil
}

// mirrorContainerImages fetches every requested image into stageRoot, grouping
// the results by repository. Per-image failures are collected, not fatal.
func (s *LowServer) mirrorContainerImages(ctx context.Context, refs []imageRef, stageRoot string, force bool) ([]ContainerRepo, []ManifestFile, []FailedModule) {
	client := s.newContainerClient()
	client.prior = s.priorFileCheck(streamContainers, force)
	byRepo := map[string]*ContainerRepo{}
	var order []string
	var files []ManifestFile
	// staged marks blobs already downloaded; listed dedupes the manifest file
	// list separately, because an image reports every blob it references even
	// when a previous image already staged it (shared base layers, configs).
	staged := map[string]bool{}
	listed := map[string]bool{}
	var failed []FailedModule

	for _, ref := range refs {
		emitProgress(ctx, "→ %s", ref)
		img, mf, err := client.resolveAndMirrorImage(ctx, ref, stageRoot, staged)
		if err != nil {
			emitProgress(ctx, "  ✗ %s: %s", ref, err)
			failed = append(failed, FailedModule{Module: ref.Registry + "/" + ref.Repository, Version: refVersionLabel(ref), Error: err.Error()})
			continue
		}
		emitProgress(ctx, "  ✓ %s (%d blob(s))", ref, len(mf))
		for _, f := range mf {
			if !listed[f.Path] {
				listed[f.Path] = true
				files = append(files, f)
			}
		}
		key := ref.Registry + "/" + ref.Repository
		repo, ok := byRepo[key]
		if !ok {
			repo = &ContainerRepo{Registry: ref.Registry, Repository: ref.Repository}
			byRepo[key] = repo
			order = append(order, key)
		}
		repo.Images = append(repo.Images, img)
	}

	repos := make([]ContainerRepo, 0, len(order))
	for _, key := range order {
		repos = append(repos, *byRepo[key])
	}
	return repos, files, failed
}

// refVersionLabel is the reference's tag, constraint, or digest — whichever
// identifies the requested version in reports.
func refVersionLabel(ref imageRef) string {
	switch {
	case ref.Tag != "":
		return ref.Tag
	case ref.Constraint != "":
		return ref.Constraint
	default:
		return ref.Digest
	}
}

// resolveAndMirrorImage resolves a version-constraint reference to a concrete
// tag (a plain tag or digest passes through) and mirrors that image. The
// resolved tag — not the constraint — is what the bundle records, so the high
// side serves e.g. golang:1.26.3 for a "golang:1.26.x" collect.
func (c *containerClient) resolveAndMirrorImage(ctx context.Context, ref imageRef, stageRoot string, seenFile map[string]bool) (ContainerImage, []ManifestFile, error) {
	if ref.Constraint != "" {
		tag, err := c.resolveConstraintTag(ctx, ref)
		if err != nil {
			return ContainerImage{}, nil, err
		}
		log.Printf("containers: %s resolved to tag %s", ref, tag)
		emitProgress(ctx, "  %s resolved to tag %s", ref, tag)
		ref.Tag, ref.Constraint = tag, ""
	}
	return c.mirrorContainerImage(ctx, ref, stageRoot, seenFile)
}

// mirrorContainerImage resolves one reference to its linux/amd64 manifest and
// downloads the manifest, config, and layer blobs into the staging store. It
// returns the image record plus the manifest files it references.
func (c *containerClient) mirrorContainerImage(ctx context.Context, ref imageRef, stageRoot string, seenFile map[string]bool) (ContainerImage, []ManifestFile, error) {
	manifestBytes, mediaType, digest, err := c.fetchContainerManifest(ctx, ref)
	if err != nil {
		return ContainerImage{}, nil, err
	}
	var m ociManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return ContainerImage{}, nil, fmt.Errorf("%s: parse image manifest: %w", ref, err)
	}
	if m.Config.Digest == "" || len(m.Layers) == 0 {
		return ContainerImage{}, nil, fmt.Errorf("%s: image manifest has no config or layers", ref)
	}

	img := ContainerImage{Tag: ref.Tag, Digest: digest, MediaType: mediaType, Size: int64(len(manifestBytes))}
	blobs, files, err := c.downloadImageBlobs(ctx, ref, m, stageRoot, seenFile)
	if err != nil {
		return ContainerImage{}, nil, err
	}
	img.Blobs = blobs
	if err := verifyContainerConfigPlatform(stageRoot, ref, m.Config.Digest); err != nil {
		return ContainerImage{}, nil, err
	}
	manifestFile, err := stageContainerManifestBlob(stageRoot, digest, manifestBytes, seenFile)
	if err != nil {
		return ContainerImage{}, nil, err
	}
	return img, append(files, manifestFile), nil
}

// downloadImageBlobs stages an image's config and layer blobs, returning the
// blob records for the bundle manifest.
func (c *containerClient) downloadImageBlobs(ctx context.Context, ref imageRef, m ociManifest, stageRoot string, seenFile map[string]bool) ([]ContainerBlob, []ManifestFile, error) {
	var blobs []ContainerBlob
	var files []ManifestFile
	inImage := map[string]bool{}
	for i, desc := range append([]ociDescriptor{m.Config}, m.Layers...) {
		if strings.Contains(desc.MediaType, "foreign") {
			return nil, nil, fmt.Errorf("%s: layer %s is a foreign (non-distributable) layer", ref, desc.Digest)
		}
		// The config blob (index 0) is read back from staging for the platform
		// check, so only layers may skip their download as prior content.
		mf, err := c.downloadContainerBlob(ctx, ref, desc, stageRoot, seenFile, i > 0)
		if err != nil {
			return nil, nil, err
		}
		if !inImage[mf.Path] {
			inImage[mf.Path] = true
			files = append(files, mf)
		}
		blobs = append(blobs, ContainerBlob{Digest: desc.Digest, Size: desc.Size})
	}
	return blobs, files, nil
}

// stageContainerManifestBlob stores the image manifest itself as a
// content-addressed blob in the staging store.
func stageContainerManifestBlob(stageRoot, digest string, manifestBytes []byte, seenFile map[string]bool) (ManifestFile, error) {
	rel := containerBlobRel(digest)
	mf := ManifestFile{Path: rel, SHA256: strings.TrimPrefix(digest, "sha256:"), Size: int64(len(manifestBytes))}
	if seenFile[rel] {
		return mf, nil
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, manifestBytes, 0o644); err != nil {
		return ManifestFile{}, err
	}
	seenFile[rel] = true
	return mf, nil
}

// verifyContainerConfigPlatform reads the staged config blob and rejects the
// image unless it declares linux/amd64 — the only platform ArtiGate mirrors.
func verifyContainerConfigPlatform(stageRoot string, ref imageRef, configDigest string) error {
	b, err := os.ReadFile(filepath.Join(stageRoot, filepath.FromSlash(containerBlobRel(configDigest))))
	if err != nil {
		return err
	}
	var cfg ociPlatform
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("%s: parse image config: %w", ref, err)
	}
	if (cfg.OS != "" && cfg.OS != "linux") || (cfg.Architecture != "" && cfg.Architecture != "amd64") {
		return fmt.Errorf("%s: image is %s/%s; only linux/amd64 is mirrored", ref, cfg.OS, cfg.Architecture)
	}
	return nil
}

func (s *LowServer) writeContainerBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, repos []ContainerRepo) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamContainers, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamContainers,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"containers"},
		Containers:       &ContainerManifest{Repos: repos},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	total := 0
	for _, r := range repos {
		total += len(r.Images)
	}
	return ExportResult{Stream: streamContainers, Sequence: seq, ExportedModules: total, BundleID: id}, nil
}

// -----------------------------------------------------------------------------
// Import-side validation
// -----------------------------------------------------------------------------

// validateContainerRepos checks each repo's identity and that every referenced
// blob (manifest, config, layers) appears in the manifest file set with a
// SHA-256 matching its content-addressed path — the digest a client will pull
// by is exactly the hash the import verifies.
func validateContainerRepos(repos []ContainerRepo, seen map[string]bool, files []ManifestFile) error {
	shaByPath := map[string]string{}
	for _, f := range files {
		shaByPath[f.Path] = f.SHA256
	}
	for _, repo := range repos {
		if err := validateContainerRepo(repo, seen, shaByPath); err != nil {
			return err
		}
	}
	return nil
}

func validateContainerRepo(repo ContainerRepo, seen map[string]bool, shaByPath map[string]string) error {
	if !containerRegistryRE.MatchString(repo.Registry) {
		return fmt.Errorf("invalid container registry %q", repo.Registry)
	}
	if err := validateContainerRepository(repo.Repository); err != nil {
		return err
	}
	if len(repo.Images) == 0 {
		return fmt.Errorf("container repo %s/%s has no images", repo.Registry, repo.Repository)
	}
	for _, img := range repo.Images {
		if err := validateContainerImage(img, seen, shaByPath); err != nil {
			return err
		}
	}
	return nil
}

func validateContainerImage(img ContainerImage, seen map[string]bool, shaByPath map[string]string) error {
	if img.Tag != "" && !containerTagRE.MatchString(img.Tag) {
		return fmt.Errorf("invalid container tag %q", img.Tag)
	}
	if err := requireContainerBlobListed(img.Digest, seen, shaByPath); err != nil {
		return err
	}
	for _, b := range img.Blobs {
		if err := requireContainerBlobListed(b.Digest, seen, shaByPath); err != nil {
			return err
		}
	}
	return nil
}

// requireContainerBlobListed checks that a digest's content-addressed file is
// listed in the manifest with a matching SHA-256.
func requireContainerBlobListed(digest string, seen map[string]bool, shaByPath map[string]string) error {
	if !containerDigestRE.MatchString(digest) {
		return fmt.Errorf("invalid container blob digest %q", digest)
	}
	rel := containerBlobRel(digest)
	if !seen[rel] {
		return fmt.Errorf("container image references file not listed in manifest.files: %s", rel)
	}
	if shaByPath[rel] != strings.TrimPrefix(digest, "sha256:") {
		return fmt.Errorf("container blob %s has mismatched manifest sha256", rel)
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: per-repo index, merged on import
// -----------------------------------------------------------------------------

func (s *HighServer) containersDir() string {
	return filepath.Join(s.downloadDir, "containers")
}

func (s *HighServer) containerBlobPath(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(s.containersDir(), "blobs", "sha256", containerBlobShardHex(hex), hex)
}

// containerRepoIndexPath is where a repository's accumulated tag index lives.
// The "_index.json" name cannot collide with real registry content: an image
// repository component may not start with "_".
func (s *HighServer) containerRepoIndexPath(name string) string {
	return filepath.Join(s.containersDir(), "repos", filepath.FromSlash(name), "_index.json")
}

// publishContainers merges each imported repo into its persistent index. It is
// called after the bundle's blobs are installed.
func (s *HighServer) publishContainers(m *ContainerManifest) error {
	if m == nil {
		return nil
	}
	for _, repo := range m.Repos {
		if err := s.mergeContainerRepo(repo); err != nil {
			return fmt.Errorf("publish container repo %s/%s: %w", repo.Registry, repo.Repository, err)
		}
	}
	return nil
}

// mergeContainerRepo merges newly imported images into the repo's index: a
// re-imported tag moves to its new digest, and digest-pinned images accumulate.
func (s *HighServer) mergeContainerRepo(repo ContainerRepo) error {
	name := repo.Registry + "/" + repo.Repository
	merged, err := s.loadContainerRepoIndex(name)
	if errors.Is(err, os.ErrNotExist) {
		merged = ContainerRepo{Registry: repo.Registry, Repository: repo.Repository}
	} else if err != nil {
		return err
	}
	key := func(img ContainerImage) string {
		if img.Tag != "" {
			return "tag:" + img.Tag
		}
		return "digest:" + img.Digest
	}
	byKey := map[string]int{}
	for i, img := range merged.Images {
		byKey[key(img)] = i
	}
	for _, img := range repo.Images {
		if i, ok := byKey[key(img)]; ok {
			merged.Images[i] = img
		} else {
			byKey[key(img)] = len(merged.Images)
			merged.Images = append(merged.Images, img)
		}
	}
	sort.Slice(merged.Images, func(i, j int) bool {
		if merged.Images[i].Tag != merged.Images[j].Tag {
			return merged.Images[i].Tag < merged.Images[j].Tag
		}
		return merged.Images[i].Digest < merged.Images[j].Digest
	})
	return writeJSONAtomic(s.containerRepoIndexPath(name), merged, 0o644)
}

func (s *HighServer) loadContainerRepoIndex(name string) (ContainerRepo, error) {
	b, err := os.ReadFile(s.containerRepoIndexPath(name))
	if err != nil {
		return ContainerRepo{}, err
	}
	var repo ContainerRepo
	if err := json.Unmarshal(b, &repo); err != nil {
		return ContainerRepo{}, err
	}
	return repo, nil
}

// listContainerRepoNames walks the repos tree and returns every repository's
// "<registry>/<repository>" name, sorted.
func (s *HighServer) listContainerRepoNames() ([]string, error) {
	root := filepath.Join(s.containersDir(), "repos")
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
// High side: read-only OCI Distribution registry under /v2/
// -----------------------------------------------------------------------------

// registryError writes an OCI-distribution JSON error, the format docker and
// podman expect from a registry.
func registryError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
}

// serveContainers handles the OCI Distribution routes. Repository names embed
// their upstream registry (docker.io/library/alpine), so clients pull
// <high-host>/docker.io/library/alpine:3.20 and origins never mix. It reports
// whether it wrote a response.
func (s *HighServer) serveContainers(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/v2" && p != "/v2/" && !strings.HasPrefix(p, "/v2/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		registryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "read-only registry")
		return true
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(p, "/v2"), "/")
	switch {
	case rest == "":
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		writeJSON(w, map[string]string{})
	case rest == "_catalog":
		s.handleContainerCatalog(w)
	default:
		s.handleContainerResource(w, r, rest)
	}
	return true
}

func (s *HighServer) handleContainerCatalog(w http.ResponseWriter) {
	names, err := s.listContainerRepoNames()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, map[string][]string{"repositories": names})
}

// handleContainerResource routes /v2/<name>/{tags/list,manifests/<ref>,blobs/<digest>}.
// The repository name itself contains slashes, so the route keyword is found
// from the right.
func (s *HighServer) handleContainerResource(w http.ResponseWriter, r *http.Request, rest string) {
	if name, ok := strings.CutSuffix(rest, "/tags/list"); ok {
		if !validContainerName(name) {
			registryError(w, http.StatusNotFound, "NAME_INVALID", "invalid repository name")
			return
		}
		s.handleContainerTags(w, name)
		return
	}
	for _, route := range []string{"/manifests/", "/blobs/"} {
		i := strings.LastIndex(rest, route)
		if i <= 0 {
			continue
		}
		name, ref := rest[:i], rest[i+len(route):]
		if !validContainerName(name) {
			registryError(w, http.StatusNotFound, "NAME_INVALID", "invalid repository name")
			return
		}
		if route == "/manifests/" {
			s.handleContainerManifest(w, r, name, ref)
		} else {
			s.handleContainerBlob(w, r, name, ref)
		}
		return
	}
	registryError(w, http.StatusNotFound, "UNSUPPORTED", "unknown registry path")
}

// validContainerName accepts "<registry>/<repository>" names: at least two
// path-safe lowercase segments.
func validContainerName(name string) bool {
	if validateRelPath(name) != nil {
		return false
	}
	segs := strings.Split(name, "/")
	if len(segs) < 2 {
		return false
	}
	for _, seg := range segs {
		if !containerRepoComponentRE.MatchString(seg) {
			return false
		}
	}
	return true
}

func (s *HighServer) handleContainerTags(w http.ResponseWriter, name string) {
	repo, err := s.loadContainerRepoIndex(name)
	if err != nil {
		registryError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository not found")
		return
	}
	tags := []string{}
	for _, img := range repo.Images {
		if img.Tag != "" {
			tags = append(tags, img.Tag)
		}
	}
	sort.Strings(tags)
	writeJSON(w, map[string]any{"name": name, "tags": tags})
}

// handleContainerManifest serves a manifest by tag or digest. Only manifests
// recorded in this repository's index are served, so one repository can never
// expose another's content even though the blob store is shared.
func (s *HighServer) handleContainerManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	repo, err := s.loadContainerRepoIndex(name)
	if err != nil {
		registryError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository not found")
		return
	}
	img, ok := findContainerImage(repo, ref)
	if !ok {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not found")
		return
	}
	b, err := os.ReadFile(s.containerBlobPath(img.Digest))
	if err != nil {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest blob missing")
		return
	}
	w.Header().Set("Content-Type", img.MediaType)
	w.Header().Set("Docker-Content-Digest", img.Digest)
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

// findContainerImage resolves a tag or digest against a repo's index.
func findContainerImage(repo ContainerRepo, ref string) (ContainerImage, bool) {
	byDigest := containerDigestRE.MatchString(ref)
	for _, img := range repo.Images {
		if byDigest && img.Digest == ref {
			return img, true
		}
		if !byDigest && img.Tag == ref {
			return img, true
		}
	}
	return ContainerImage{}, false
}

// handleContainerBlob serves a config/layer blob, but only when the requesting
// repository's index references it (per-repo isolation over the shared store).
func (s *HighServer) handleContainerBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	if !containerDigestRE.MatchString(digest) {
		registryError(w, http.StatusNotFound, "DIGEST_INVALID", "invalid digest")
		return
	}
	repo, err := s.loadContainerRepoIndex(name)
	if err != nil {
		registryError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository not found")
		return
	}
	if !containerRepoReferencesBlob(repo, digest) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}
	abs := s.containerBlobPath(digest)
	if !fileExists(abs) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", digest)
	http.ServeFile(w, r, abs)
}

func containerRepoReferencesBlob(repo ContainerRepo, digest string) bool {
	for _, img := range repo.Images {
		if img.Digest == digest {
			return true
		}
		for _, b := range img.Blobs {
			if b.Digest == digest {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail/repos
// -----------------------------------------------------------------------------

// listContainerRepos returns UIModule entries keyed "<registry>/<repository>"
// with the tags (or digests, for untagged pins) as versions; the generic
// segment-tree builder then groups them registry-first, so each upstream
// (docker.io, ghcr.io, ...) is its own top-level branch.
func (s *HighServer) listContainerRepos() ([]UIModule, error) {
	names, err := s.listContainerRepoNames()
	if err != nil {
		return nil, err
	}
	mods := make([]UIModule, 0, len(names))
	for _, name := range names {
		repo, err := s.loadContainerRepoIndex(name)
		if err != nil {
			continue
		}
		var versions []string
		for _, img := range repo.Images {
			if img.Tag != "" {
				versions = append(versions, img.Tag)
			} else {
				versions = append(versions, img.Digest)
			}
		}
		sort.Strings(versions)
		mods = append(mods, UIModule{Module: name, Versions: versions})
	}
	return mods, nil
}

// containerRepoList lists the mirrored repositories (with their tags) for the
// "Set me up" guide.
func (s *HighServer) containerRepoList() ([]UIRepo, error) {
	names, err := s.listContainerRepoNames()
	if err != nil {
		return nil, err
	}
	repos := make([]UIRepo, 0, len(names))
	for _, name := range names {
		repo, err := s.loadContainerRepoIndex(name)
		if err != nil {
			continue
		}
		var tags []string
		for _, img := range repo.Images {
			if img.Tag != "" {
				tags = append(tags, img.Tag)
			}
		}
		sort.Strings(tags)
		repos = append(repos, UIRepo{Name: name, Tags: tags})
	}
	return repos, nil
}

// containerDetail describes one image for the dashboard. spec is
// "<registry>/<repository>@<tag-or-digest>".
func (s *HighServer) containerDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid image spec")
	}
	name, ref := spec[:i], spec[i+1:]
	if !validContainerName(name) {
		return UIDetail{}, errors.New("invalid repository name")
	}
	repo, err := s.loadContainerRepoIndex(name)
	if err != nil {
		return UIDetail{}, errors.New("repository not found")
	}
	img, ok := findContainerImage(repo, ref)
	if !ok {
		return UIDetail{}, errors.New("image not found")
	}
	var total int64
	for _, b := range img.Blobs {
		total += b.Size
	}
	fields := []UIDetailField{
		{Label: "Registry", Value: repo.Registry, Mono: true},
		{Label: "Repository", Value: repo.Repository, Mono: true},
	}
	if img.Tag != "" {
		fields = append(fields, UIDetailField{Label: "Tag", Value: img.Tag, Mono: true})
	}
	fields = append(fields,
		UIDetailField{Label: "Manifest digest", Value: img.Digest, Mono: true},
		UIDetailField{Label: "Platform", Value: "linux/amd64"},
		// The first blob is the config; the rest are layers.
		UIDetailField{Label: "Layers", Value: fmt.Sprint(max(0, len(img.Blobs)-1))},
		UIDetailField{Label: "Total blob size", Value: formatBytes(total)},
	)
	subtitle := img.Tag
	if subtitle == "" {
		subtitle = img.Digest
	}
	// CopyRef is the host-relative pull reference (<registry>/<repository>:<tag>);
	// the dashboard prepends its own host and renders it as a prominent
	// click-to-copy button, so the operator copies exactly what `docker pull`
	// needs for this ArtiGate.
	return UIDetail{
		Title:    name,
		Subtitle: subtitle,
		Fields:   fields,
		CopyRef:  name + refSuffix(img),
		Layers:   s.containerImageLayers(img),
	}, nil
}

// refSuffix renders how a client appends the reference: ":tag" or "@digest".
func refSuffix(img ContainerImage) string {
	if img.Tag != "" {
		return ":" + img.Tag
	}
	return "@" + img.Digest
}

// ociHistory is one entry of an image config's build history.
type ociHistory struct {
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
}

// ociImageConfig is the part of an image config blob ArtiGate reads: the build
// history that names the command each step ran.
type ociImageConfig struct {
	History []ociHistory `json:"history"`
}

// containerImageLayers reads an image's config blob and returns its build
// history as layer entries: the command each step ran and, for steps that
// produced a filesystem layer, the matching stored layer's size and digest.
// The config's non-empty history entries are in the same order as the
// manifest's layers, which are stored as img.Blobs[1:] (img.Blobs[0] is the
// config). Returns nil if the config is missing or unreadable, so the panel
// simply omits the layers box.
func (s *HighServer) containerImageLayers(img ContainerImage) []UIImageLayer {
	if len(img.Blobs) == 0 {
		return nil
	}
	layerBlobs := img.Blobs[1:] // Blobs[0] is the config; the rest are layers.
	b, err := os.ReadFile(s.containerBlobPath(img.Blobs[0].Digest))
	if err != nil {
		return nil
	}
	var cfg ociImageConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil
	}
	// Some minimal images ship no history; fall back to the raw layer list.
	if len(cfg.History) == 0 {
		return rawContainerLayers(layerBlobs)
	}
	out := make([]UIImageLayer, 0, len(cfg.History))
	li := 0
	for _, h := range cfg.History {
		entry := UIImageLayer{Command: cleanDockerfileCommand(h.CreatedBy), Empty: h.EmptyLayer}
		if !h.EmptyLayer && li < len(layerBlobs) {
			entry.Size = formatBytes(layerBlobs[li].Size)
			entry.Digest = layerBlobs[li].Digest
			li++
		}
		out = append(out, entry)
	}
	return out
}

// rawContainerLayers lists layer blobs without commands, for images whose
// config carries no build history.
func rawContainerLayers(layerBlobs []ContainerBlob) []UIImageLayer {
	out := make([]UIImageLayer, 0, len(layerBlobs))
	for _, lb := range layerBlobs {
		out = append(out, UIImageLayer{Command: "(no build history recorded)", Size: formatBytes(lb.Size), Digest: lb.Digest})
	}
	return out
}

// cleanDockerfileCommand turns a config history "created_by" into a readable
// build step, mirroring `docker history`: a "/bin/sh -c #(nop)  CMD ..." meta
// step becomes "CMD ...", and a plain "/bin/sh -c <cmd>" becomes "RUN <cmd>".
// Buildkit steps (already prefixed "RUN"/"COPY"/…) pass through unchanged.
func cleanDockerfileCommand(createdBy string) string {
	s := strings.TrimSpace(createdBy)
	if s == "" {
		return "(metadata)"
	}
	const nop = "/bin/sh -c #(nop)"
	if rest, ok := strings.CutPrefix(s, nop); ok {
		return strings.TrimSpace(rest)
	}
	if rest, ok := strings.CutPrefix(s, "/bin/sh -c "); ok {
		return "RUN " + strings.TrimSpace(rest)
	}
	return s
}
