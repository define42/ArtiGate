package main

// NPM (registry) ecosystem adapter. The low side delegates dependency
// resolution to the installed `npm` tool (`npm install --package-lock-only`,
// which resolves the full graph and writes a package-lock.json without
// installing anything), then downloads every resolved registry tarball over
// plain HTTP — verifying the lockfile's SRI integrity — and packs them into the
// same numbered, signed ArtiGate bundle format used by the other ecosystems.
// The high side serves the tarballs through the npm registry API (packument,
// version manifest, tarball download), regenerating all metadata from each
// tarball's own embedded package.json at import time (never trusting a
// transferred metadata file).
//
// Policy: registry tarballs only. Dependencies resolved to git or file URLs are
// skipped and reported, because the high side can only serve registry content.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // sha1 is only the legacy npm dist.shasum field, not a security control
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// npmEcosystem is the NPM package stream's registry entry (see ecosystems in
// ecosystem.go).
func npmEcosystem() ecosystem {
	return ecosystem{
		stream:       streamNpm,
		label:        "NPM",
		title:        "NPM packages",
		collect:      (*LowServer).HandleNpmCollect,
		watchCollect: watchAdapter((*LowServer).CollectNpm),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.NpmBinary, "npm", "npm", "npm command used to resolve NPM package graphs")
			fs.StringVar(&cfg.NpmRegistry, "npm-registry", "", "registry URL npm resolves against (default: npm's own configuration)")
		},
		manifestContent: func(m BundleManifest) bool { return m.Npm != nil && len(m.Npm.Packages) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			if err := validateNpmPackages(m.Npm.Packages, seen); err != nil {
				return err
			}
			if err := validateNpmDistTags(m.Npm.DistTags); err != nil {
				return err
			}
			return validateNpmKeys(m.Npm.Keys)
		},
		contentDesc: "npm packages",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishNpm(m.Npm) },
		serve:       (*HighServer).serveNpm,
		scanTree:    flatTreeScan((*HighServer).listNpmPackages),
		detail:      (*HighServer).npmDetail,
	}
}

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type NpmManifest struct {
	Packages []NpmPackage `json:"packages"`
	// DistTags carries each mirrored package's upstream dist-tags
	// (name -> tag -> version) as observed at collect time. The high side
	// serves a tag only while its target version is actually mirrored, and
	// always regenerates "latest" as a fallback, so a stale or hostile tag can
	// never point outside the verified store. Tag movement alone does not
	// change the mirrored file set, so refreshing tags for an unchanged
	// package set needs a force collect.
	DistTags map[string]map[string]string `json:"dist_tags,omitempty"`
	// Keys carries each upstream registry's published signing keys
	// (GET /-/npm/v1/keys) observed at collect time, keyed by registry host.
	// The high side serves the merged set at its own keys endpoint, so
	// `npm audit signatures` verifies mirrored packages against the mirror.
	Keys map[string][]NpmRegistryKey `json:"keys,omitempty"`
}

// NpmRegistryKey is one entry of a registry's /-/npm/v1/keys document, passed
// through verbatim — the fields are what npm matches dist.signatures against.
type NpmRegistryKey struct {
	Expires *string `json:"expires"`
	KeyID   string  `json:"keyid"`
	KeyType string  `json:"keytype"`
	Scheme  string  `json:"scheme"`
	Key     string  `json:"key"`
}

// NpmRegistrySignature is one upstream dist.signatures entry: an ECDSA
// signature over "<name>@<version>:<integrity>". The mirror serves the same
// bytes, so the recomputed integrity — and therefore the signature — verifies
// unchanged.
type NpmRegistrySignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type NpmPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Path     string `json:"path"` // e.g. npm/packages/@scope/pkg/pkg-1.0.0.tgz
	SHA256   string `json:"sha256"`
	// Integrity is the SRI string from the resolving lockfile, kept for audit;
	// the high side recomputes integrity from the artifact itself.
	Integrity string `json:"integrity,omitempty"`
	// Signatures are the upstream registry's dist.signatures for this exact
	// version, served back in the mirrored packument.
	Signatures []NpmRegistrySignature `json:"signatures,omitempty"`
	// AttestationsPath is the mirrored attestations document
	// (/-/npm/v1/attestations/<name>@<version>) for this version, with the
	// provenance predicate type dist.attestations advertises. Both are set
	// together or not at all.
	AttestationsPath          string `json:"attestations_path,omitempty"`
	AttestationsPredicateType string `json:"attestations_predicate_type,omitempty"`
}

// npmAttestationsRel is the bundle path of one version's mirrored
// attestations document.
func npmAttestationsRel(name, version string) string {
	return path.Join("npm", "attestations", name, version+".json")
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// npmNamePartRE matches one path-safe npm name element (the scope or the
// package part). The first character excludes ".", "_", and "-" so an element
// can never be ".", "..", or something a CLI would parse as a flag.
var npmNamePartRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// npmVersionRE matches an npm (semver) version, which always starts with a
// digit, so it can never be ".."/"-flag" or contain a path separator.
var npmVersionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

// validateNpmName checks a package name ("lodash" or "@scope/pkg") is
// well-formed and path-safe: names become filesystem directories and npm
// arguments, so this guards traversal and flag injection.
func validateNpmName(name string) error {
	if name == "" || len(name) > 214 {
		return fmt.Errorf("invalid npm package name %q", name)
	}
	parts := strings.Split(name, "/")
	switch {
	case len(parts) == 1 && npmNamePartRE.MatchString(parts[0]):
		return nil
	case len(parts) == 2 && strings.HasPrefix(parts[0], "@") &&
		npmNamePartRE.MatchString(strings.TrimPrefix(parts[0], "@")) &&
		npmNamePartRE.MatchString(parts[1]):
		return nil
	}
	return fmt.Errorf("invalid npm package name %q", name)
}

func validateNpmVersion(v string) error {
	if !npmVersionRE.MatchString(v) {
		return fmt.Errorf("invalid npm version %q", v)
	}
	return nil
}

// npmDistTagRE matches a dist-tag name. npm accepts a looser charset, but
// tags become URL path segments and JSON keys on the high side, so only the
// path-safe core is mirrored; the first character excludes ".", "_", and "-"
// like package name elements.
var npmDistTagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validateNpmDistTag(tag string) error {
	if !npmDistTagRE.MatchString(tag) {
		return fmt.Errorf("invalid npm dist-tag %q", tag)
	}
	return nil
}

// validateNpmDistTags checks a manifest's dist-tag map: every package name,
// tag name, and target version must be well-formed. Targets are not required
// to be files of this bundle — a tag may point at a version an earlier bundle
// delivered; serving filters to versions actually present.
func validateNpmDistTags(tags map[string]map[string]string) error {
	for name, m := range tags {
		if err := validateNpmName(name); err != nil {
			return fmt.Errorf("dist-tags: %w", err)
		}
		for tag, version := range m {
			if err := validateNpmDistTag(tag); err != nil {
				return fmt.Errorf("dist-tags for %s: %w", name, err)
			}
			if err := validateNpmVersion(version); err != nil {
				return fmt.Errorf("dist-tag %s of %s: %w", tag, name, err)
			}
		}
	}
	return nil
}

// npmTarballBase is the unscoped part of a package name, which the registry
// uses as the tarball basename ("@scope/pkg" -> "pkg").
func npmTarballBase(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// npmTarballFilename renders the registry-convention tarball filename,
// e.g. ("@scope/pkg", "1.0.0") -> "pkg-1.0.0.tgz".
func npmTarballFilename(name, version string) string {
	return npmTarballBase(name) + "-" + version + ".tgz"
}

// validateNpmPackages checks that every package in a bundle manifest names a
// valid, path-safe package and version and references a file present in the
// manifest's file set under the npm tree.
func validateNpmPackages(pkgs []NpmPackage, seen map[string]bool) error {
	for _, p := range pkgs {
		if err := validateNpmName(p.Name); err != nil {
			return err
		}
		if err := validateNpmVersion(p.Version); err != nil {
			return fmt.Errorf("npm package %s: %w", p.Name, err)
		}
		if !strings.HasPrefix(p.Path, "npm/packages/") {
			return fmt.Errorf("npm package %s@%s file outside npm/packages: %s", p.Name, p.Version, p.Path)
		}
		if !seen[p.Path] {
			return fmt.Errorf("npm package %s@%s references file not listed in manifest.files: %s", p.Name, p.Version, p.Path)
		}
		if err := validateNpmPackageProvenance(p, seen); err != nil {
			return err
		}
	}
	return nil
}

// validateNpmPackageProvenance checks one package's passthrough verification
// material: bounded, well-formed signatures, and an attestations reference
// that names exactly its own canonical path in the verified file set.
func validateNpmPackageProvenance(p NpmPackage, seen map[string]bool) error {
	if len(p.Signatures) > 16 {
		return fmt.Errorf("npm package %s@%s carries %d signatures (max 16)", p.Name, p.Version, len(p.Signatures))
	}
	for _, sig := range p.Signatures {
		if sig.KeyID == "" || len(sig.KeyID) > 256 || sig.Sig == "" || len(sig.Sig) > 8192 {
			return fmt.Errorf("npm package %s@%s has a malformed registry signature", p.Name, p.Version)
		}
	}
	if p.AttestationsPath == "" && p.AttestationsPredicateType == "" {
		return nil
	}
	if p.AttestationsPath != npmAttestationsRel(p.Name, p.Version) {
		return fmt.Errorf("npm package %s@%s has non-canonical attestations path %s", p.Name, p.Version, p.AttestationsPath)
	}
	if !seen[p.AttestationsPath] {
		return fmt.Errorf("npm package %s@%s references attestations not listed in manifest.files: %s", p.Name, p.Version, p.AttestationsPath)
	}
	if p.AttestationsPredicateType == "" || len(p.AttestationsPredicateType) > 256 {
		return fmt.Errorf("npm package %s@%s has a malformed attestations predicate type", p.Name, p.Version)
	}
	return nil
}

// npmRegistryHostRE matches a registry host key in the manifest's keys map:
// a lowercase hostname with an optional port.
var npmRegistryHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

// validateNpmKeys checks a manifest's per-registry signing-key snapshots:
// path-safe host keys and bounded, well-formed key records — these are served
// back verbatim at the mirror's own keys endpoint.
func validateNpmKeys(keys map[string][]NpmRegistryKey) error {
	for host, list := range keys {
		if !npmRegistryHostRE.MatchString(host) || len(host) > 255 {
			return fmt.Errorf("invalid npm registry host %q in keys", host)
		}
		if len(list) > 64 {
			return fmt.Errorf("npm registry %s publishes %d keys (max 64)", host, len(list))
		}
		for _, k := range list {
			if !wellFormedNpmRegistryKey(k) {
				return fmt.Errorf("npm registry %s has a malformed signing key", host)
			}
		}
	}
	return nil
}

// wellFormedNpmRegistryKey bounds one key record's fields.
func wellFormedNpmRegistryKey(k NpmRegistryKey) bool {
	return k.KeyID != "" && len(k.KeyID) <= 256 && k.Key != "" && len(k.Key) <= 4096 &&
		len(k.KeyType) <= 128 && len(k.Scheme) <= 128 && (k.Expires == nil || len(*k.Expires) <= 64)
}

// -----------------------------------------------------------------------------
// High side: npm registry API
// -----------------------------------------------------------------------------

func (s *HighServer) npmPackagesDir() string {
	return filepath.Join(s.downloadDir, "npm", "packages")
}

func (s *HighServer) npmMetadataDir() string {
	return filepath.Join(s.downloadDir, "npm", "metadata")
}

// npmStoredManifest is the per-version metadata the high side regenerates at
// import time from the tarball's own embedded package.json (plus the digests it
// computes from the artifact bytes). It is what packuments are assembled from.
// Signatures and the attestations predicate are the one passthrough exception:
// they come from the signed bundle manifest (upstream verification material
// cannot be regenerated locally — that is its point) and are validated there.
type npmStoredManifest struct {
	Filename  string          `json:"filename"`
	Shasum    string          `json:"shasum"`
	Integrity string          `json:"integrity"`
	Manifest  json.RawMessage `json:"manifest"`
	// Signatures are the upstream registry's dist.signatures for this version.
	Signatures []NpmRegistrySignature `json:"signatures,omitempty"`
	// AttestationsPredicateType marks a version whose attestations document is
	// mirrored (npm/attestations/<name>/<version>.json) and names the
	// provenance predicate dist.attestations advertises.
	AttestationsPredicateType string `json:"attestations_predicate_type,omitempty"`
}

// serveNpm handles the npm registry routes under /npm/: packument
// (/npm/<name>), version manifest (/npm/<name>/<version>), tarball
// download (/npm/<name>/-/<file>.tgz), and the bulk-audit endpoint backed
// by the mirrored OSV npm database (osvnpmaudit.go). Scoped names arrive
// either literal (@scope/pkg) or URL-encoded (@scope%2fpkg); both decode to
// the same path. It reports whether it wrote a response for the request.
func (s *HighServer) serveNpm(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/npm" && !strings.HasPrefix(p, "/npm/") {
		return false
	}
	rest := strings.Trim(strings.TrimPrefix(p, "/npm"), "/")
	// npm audit POSTs, so its route must dodge the read-method gate below.
	if rest == npmAuditBulkRoute {
		s.handleNpmAuditBulk(w, r)
		return true
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	// The registry meta endpoints npm's signature verification uses; both live
	// under "-/npm/v1/", which can never be a package path (names cannot be "-").
	if rest == "-/npm/v1/keys" {
		s.handleNpmKeys(w)
		return true
	}
	if spec, ok := strings.CutPrefix(rest, "-/npm/v1/attestations/"); ok {
		s.handleNpmAttestations(w, r, spec)
		return true
	}
	if name, file, ok := splitNpmTarballPath(rest); ok {
		s.handleNpmTarball(w, r, name, file)
		return true
	}
	name, version, ok := splitNpmPackagePath(rest)
	if !ok || validateNpmName(name) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	if version == "" {
		s.handleNpmPackument(w, r, name)
	} else {
		s.handleNpmVersion(w, r, name, version)
	}
	return true
}

// splitNpmTarballPath splits "<name>/-/<file>" into its package name and
// tarball filename.
func splitNpmTarballPath(rest string) (name, file string, ok bool) {
	name, file, ok = strings.Cut(rest, "/-/")
	if !ok || name == "" || file == "" || strings.ContainsRune(file, '/') {
		return "", "", false
	}
	return name, file, true
}

// splitNpmPackagePath splits a packument or version-manifest path into the
// package name and optional version: "lodash", "@scope/pkg", "lodash/4.17.21",
// "@scope/pkg/1.0.0".
func splitNpmPackagePath(rest string) (name, version string, ok bool) {
	segs := strings.Split(rest, "/")
	scoped := strings.HasPrefix(segs[0], "@")
	switch {
	case len(segs) == 1 && !scoped:
		return segs[0], "", true
	case len(segs) == 2 && scoped:
		return segs[0] + "/" + segs[1], "", true
	case len(segs) == 2 && !scoped:
		return segs[0], segs[1], true
	case len(segs) == 3 && scoped:
		return segs[0] + "/" + segs[1], segs[2], true
	}
	return "", "", false
}

// npmBaseURL reconstructs the absolute base URL clients reached this server on,
// for the dist.tarball links inside packuments (npm requires absolute URLs).
func npmBaseURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *HighServer) handleNpmPackument(w http.ResponseWriter, r *http.Request, name string) {
	versions, err := s.npmVersionObjects(npmBaseURL(r), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(versions) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"name":      name,
		"dist-tags": s.npmDistTags(name, versions),
		"versions":  versions,
	})
}

// npmDistTags assembles a packument's dist-tags: the mirrored upstream tags
// filtered to versions actually served, with "latest" regenerated from the
// present versions whenever the upstream tag is absent or points at a version
// this mirror does not hold.
func (s *HighServer) npmDistTags(name string, versions map[string]any) map[string]string {
	names := make([]string, 0, len(versions))
	for v := range versions {
		names = append(names, v)
	}
	tags := map[string]string{"latest": npmLatestVersion(names)}
	for tag, version := range s.readNpmStoredTags(name) {
		if _, ok := versions[version]; ok {
			tags[tag] = version
		}
	}
	return tags
}

func (s *HighServer) handleNpmVersion(w http.ResponseWriter, r *http.Request, name, version string) {
	if validateNpmVersion(version) != nil {
		// The registry API also answers GET /<name>/<tag>; resolve a mirrored
		// dist-tag whose target version is served, and 404 anything else.
		version = s.npmResolveTag(name, version)
		if version == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	st, err := s.readNpmStoredManifest(name, version)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, npmVersionObject(st, name, version, npmBaseURL(r)))
}

// npmResolveTag maps a stored dist-tag to its target version, or "" when the
// tag is unknown or its target is not served.
func (s *HighServer) npmResolveTag(name, tag string) string {
	if validateNpmDistTag(tag) != nil {
		return ""
	}
	version := s.readNpmStoredTags(name)[tag]
	if version == "" {
		return ""
	}
	if _, err := s.readNpmStoredManifest(name, version); err != nil {
		return ""
	}
	return version
}

// handleNpmKeys serves the merged signing keys of every mirrored upstream
// registry at the endpoint npm expects of the configured registry
// (/-/npm/v1/keys). Like an upstream registry that signs nothing, it 404s
// until a collect has captured keys.
func (s *HighServer) handleNpmKeys(w http.ResponseWriter) {
	keys := s.mergedNpmKeys()
	if len(keys) == 0 {
		http.Error(w, "no registry signing keys mirrored", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"keys": keys})
}

// mergedNpmKeys flattens the stored per-registry key snapshots into one list,
// de-duplicated by key identity and sorted for stable output.
func (s *HighServer) mergedNpmKeys() []NpmRegistryKey {
	stored := s.readNpmStoredKeys()
	hosts := make([]string, 0, len(stored.Hosts))
	for host := range stored.Hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	seen := map[string]bool{}
	var out []NpmRegistryKey
	for _, host := range hosts {
		for _, k := range stored.Hosts[host] {
			id := k.KeyID + "\x00" + k.Key
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

// handleNpmAttestations serves one version's mirrored attestations document
// (/-/npm/v1/attestations/<name>@<version>), the URL dist.attestations points
// at and `npm audit signatures` fetches to verify provenance.
func (s *HighServer) handleNpmAttestations(w http.ResponseWriter, r *http.Request, spec string) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	name, version := spec[:i], spec[i+1:]
	if validateNpmName(name) != nil || validateNpmVersion(version) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(npmAttestationsRel(name, version)))
	if !safeJoin(filepath.Join(s.downloadDir, "npm", "attestations"), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

func (s *HighServer) handleNpmTarball(w http.ResponseWriter, r *http.Request, name, file string) {
	if validateNpmName(name) != nil || !strings.HasSuffix(file, ".tgz") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.npmPackagesDir(), filepath.FromSlash(name), file)
	if !safeJoin(s.npmPackagesDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// npmVersionObjects assembles the packument's versions map for one package
// from the regenerated per-version metadata, serving only versions whose
// tarball is actually present.
func (s *HighServer) npmVersionObjects(baseURL, name string) (map[string]any, error) {
	dir := filepath.Join(s.npmMetadataDir(), filepath.FromSlash(name))
	if !safeJoin(s.npmMetadataDir(), dir) {
		return nil, errors.New("unsafe path")
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, e := range entries {
		version := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || version == e.Name() || validateNpmVersion(version) != nil {
			continue
		}
		st, err := s.readNpmStoredManifest(name, version)
		if err != nil {
			continue
		}
		out[version] = npmVersionObject(st, name, version, baseURL)
	}
	return out, nil
}

// readNpmStoredManifest loads one version's regenerated metadata and checks its
// tarball is still present (only complete versions are served).
func (s *HighServer) readNpmStoredManifest(name, version string) (npmStoredManifest, error) {
	p := filepath.Join(s.npmMetadataDir(), filepath.FromSlash(name), version+".json")
	if !safeJoin(s.npmMetadataDir(), p) {
		return npmStoredManifest{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return npmStoredManifest{}, err
	}
	var st npmStoredManifest
	if err := json.Unmarshal(b, &st); err != nil {
		return npmStoredManifest{}, err
	}
	if st.Filename == "" || strings.ContainsRune(st.Filename, '/') {
		return npmStoredManifest{}, fmt.Errorf("invalid stored filename for %s@%s", name, version)
	}
	tarball := filepath.Join(s.npmPackagesDir(), filepath.FromSlash(name), st.Filename)
	if !safeJoin(s.npmPackagesDir(), tarball) || !fileExists(tarball) {
		return npmStoredManifest{}, fmt.Errorf("tarball missing for %s@%s", name, version)
	}
	return st, nil
}

// npmVersionObject renders one packument versions[] entry: the embedded
// package.json patched with the identity the mirror serves it under and a dist
// section pointing back at this server. Upstream registry signatures and the
// attestations pointer pass through — the integrity they sign is recomputed
// from the same bytes, so npm verifies them against the mirror unchanged.
func npmVersionObject(st npmStoredManifest, name, version, baseURL string) map[string]any {
	obj := map[string]any{}
	if len(st.Manifest) > 0 {
		_ = json.Unmarshal(st.Manifest, &obj)
	}
	obj["name"] = name
	obj["version"] = version
	dist := map[string]any{
		"tarball":   baseURL + "/npm/" + name + "/-/" + st.Filename,
		"shasum":    st.Shasum,
		"integrity": st.Integrity,
	}
	if len(st.Signatures) > 0 {
		dist["signatures"] = st.Signatures
	}
	if st.AttestationsPredicateType != "" {
		dist["attestations"] = map[string]any{
			"url":        baseURL + "/npm/-/npm/v1/attestations/" + name + "@" + version,
			"provenance": map[string]string{"predicateType": st.AttestationsPredicateType},
		}
	}
	obj["dist"] = dist
	if npmHasInstallScript(obj) {
		obj["hasInstallScript"] = true
	}
	return obj
}

// npmHasInstallScript reports whether the manifest declares a (pre/post)install
// script, which npm's install planner wants surfaced on the version object.
func npmHasInstallScript(obj map[string]any) bool {
	scripts, ok := obj["scripts"].(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := scripts[k]; ok {
			return true
		}
	}
	return false
}

// npmLatestVersion picks the version the "latest" dist-tag points at: the
// highest release, or the highest version overall when only pre-releases are
// mirrored. npm versions are semver without the "v" prefix, so the shared Go
// semver comparison applies with one prepended.
func npmLatestVersion(versions []string) string {
	var bestRelease, bestAny string
	for _, v := range versions {
		if p := parseSemver("v" + v); p.ok && p.pre == "" {
			if bestRelease == "" || compareVersions("v"+bestRelease, "v"+v) < 0 {
				bestRelease = v
			}
		}
		if bestAny == "" || compareVersions("v"+bestAny, "v"+v) < 0 {
			bestAny = v
		}
	}
	if bestRelease != "" {
		return bestRelease
	}
	return bestAny
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// publishNpm regenerates the served per-version metadata for every package in
// an imported bundle from the tarball's own embedded package.json. A package
// whose tarball cannot be parsed is logged and skipped (its version 404s)
// rather than wedging the stream's import forever.
// publishNpm regenerates the served npm metadata from each tarball's own
// embedded package.json (never trusting a transferred packument).
func (s *HighServer) publishNpm(m *NpmManifest) error {
	if m == nil {
		return nil
	}
	for _, p := range m.Packages {
		if err := s.publishNpmPackage(p); err != nil {
			log.Printf("npm publish %s@%s: %v", p.Name, p.Version, err)
		}
	}
	for name, tags := range m.DistTags {
		if err := s.publishNpmDistTags(name, tags); err != nil {
			log.Printf("npm publish dist-tags %s: %v", name, err)
		}
	}
	if err := s.publishNpmKeys(m.Keys); err != nil {
		log.Printf("npm publish registry keys: %v", err)
	}
	return nil
}

// npmStoredKeys is the accumulated per-registry signing-key store backing the
// keys endpoint. The "_keys.json" stem at the metadata root can never collide
// with a package directory: names may not start with "_".
type npmStoredKeys struct {
	Hosts map[string][]NpmRegistryKey `json:"hosts"`
}

// publishNpmKeys merges one bundle's per-registry key snapshots into the
// store: each named host's set is replaced whole (keys are upstream state,
// rotated upstream), hosts the bundle does not mention keep their last
// snapshot. Imports are serialized, so read-merge-write is race-free.
func (s *HighServer) publishNpmKeys(keys map[string][]NpmRegistryKey) error {
	if len(keys) == 0 {
		return nil
	}
	if err := validateNpmKeys(keys); err != nil {
		return err
	}
	stored := s.readNpmStoredKeys()
	if stored.Hosts == nil {
		stored.Hosts = map[string][]NpmRegistryKey{}
	}
	for host, list := range keys {
		stored.Hosts[host] = list
	}
	return writeJSONAtomic(filepath.Join(s.npmMetadataDir(), "_keys.json"), stored, 0o644)
}

// readNpmStoredKeys loads the accumulated key store; missing or unreadable
// means no keys captured yet.
func (s *HighServer) readNpmStoredKeys() npmStoredKeys {
	var st npmStoredKeys
	b, err := os.ReadFile(filepath.Join(s.npmMetadataDir(), "_keys.json"))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return npmStoredKeys{}
	}
	return st
}

// npmStoredTags is the per-package dist-tag snapshot stored beside the
// version metadata. Its "_tags" stem can never collide with a version file:
// versions always start with a digit.
type npmStoredTags struct {
	Tags map[string]string `json:"tags"`
}

// publishNpmDistTags stores one package's upstream dist-tag snapshot. Each
// bundle carrying the package replaces the whole snapshot — tags are upstream
// state, not accumulated history. Serving re-filters against the versions
// actually present, so a tag naming an absent version is stored but inert.
func (s *HighServer) publishNpmDistTags(name string, tags map[string]string) error {
	if err := validateNpmName(name); err != nil {
		return err
	}
	if err := validateNpmDistTags(map[string]map[string]string{name: tags}); err != nil {
		return err
	}
	out := filepath.Join(s.npmMetadataDir(), filepath.FromSlash(name), "_tags.json")
	if !safeJoin(s.npmMetadataDir(), out) {
		return fmt.Errorf("unsafe dist-tags path for %s", name)
	}
	return writeJSONAtomic(out, npmStoredTags{Tags: tags}, 0o644)
}

// readNpmStoredTags loads one package's stored dist-tag snapshot; a missing
// or unreadable snapshot is simply no extra tags.
func (s *HighServer) readNpmStoredTags(name string) map[string]string {
	p := filepath.Join(s.npmMetadataDir(), filepath.FromSlash(name), "_tags.json")
	if !safeJoin(s.npmMetadataDir(), p) {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var st npmStoredTags
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	return st.Tags
}

func (s *HighServer) publishNpmPackage(p NpmPackage) error {
	if err := validateNpmName(p.Name); err != nil {
		return err
	}
	if err := validateNpmVersion(p.Version); err != nil {
		return err
	}
	tarball := filepath.Join(s.downloadDir, filepath.FromSlash(p.Path))
	if !strings.HasPrefix(p.Path, "npm/packages/") || !safeJoin(s.downloadDir, tarball) {
		return fmt.Errorf("unsafe tarball path %s", p.Path)
	}
	manifest, err := extractNpmPackageJSON(tarball)
	if err != nil {
		return err
	}
	shasum, integrity, err := npmFileDigests(tarball)
	if err != nil {
		return err
	}
	st := npmStoredManifest{
		Filename: path.Base(p.Path), Shasum: shasum, Integrity: integrity, Manifest: manifest,
		Signatures: p.Signatures,
	}
	// The attestations pointer is stored only when the mirrored document is
	// actually installed, so dist.attestations never advertises a 404.
	if p.AttestationsPredicateType != "" &&
		fileExists(filepath.Join(s.downloadDir, filepath.FromSlash(npmAttestationsRel(p.Name, p.Version)))) {
		st.AttestationsPredicateType = p.AttestationsPredicateType
	}
	out := filepath.Join(s.npmMetadataDir(), filepath.FromSlash(p.Name), p.Version+".json")
	if !safeJoin(s.npmMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s@%s", p.Name, p.Version)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// extractNpmPackageJSON reads the package manifest embedded in an npm tarball.
// npm strips one leading path component on install (usually "package/"), so
// any depth-one directory containing a package.json counts; the first match
// wins.
func extractNpmPackageJSON(tgzPath string) (json.RawMessage, error) {
	return extractNpmPackageJSONBounded(tgzPath, tarScanMaxDecompressedBytes)
}

// extractNpmPackageJSONBounded is extractNpmPackageJSON with the scan's
// total-decompression budget as a parameter, so the gzip-bomb bound is
// regression-testable without a multi-GiB fixture.
func extractNpmPackageJSONBounded(tgzPath string, scanBudget int64) (json.RawMessage, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	// Bound total decompression: tr.Next() inflates every skipped entry, so a
	// gzip bomb with package.json last (or absent) would otherwise inflate wholesale.
	tr := tar.NewReader(io.LimitReader(gz, scanBudget))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("tarball has no package.json")
		}
		if err != nil {
			return nil, err
		}
		parts := strings.Split(path.Clean(strings.TrimPrefix(hdr.Name, "./")), "/")
		if hdr.Typeflag != tar.TypeReg || len(parts) != 2 || parts[1] != "package.json" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 8<<20))
		if err != nil {
			return nil, err
		}
		if !json.Valid(b) {
			return nil, errors.New("embedded package.json is not valid JSON")
		}
		return b, nil
	}
}

// npmFileDigests computes the digests npm clients verify downloads against:
// the legacy dist.shasum (SHA-1 hex) and the SRI dist.integrity (sha512).
func npmFileDigests(p string) (shasum, integrity string, err error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h1 := sha1.New() //nolint:gosec // legacy npm dist.shasum field, not a security control
	h512 := sha512.New()
	if _, err := io.Copy(io.MultiWriter(h1, h512), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(h1.Sum(nil)), "sha512-" + base64.StdEncoding.EncodeToString(h512.Sum(nil)), nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listNpmPackages groups the mirrored packages by name with their versions,
// from the regenerated metadata tree.
func (s *HighServer) listNpmPackages() ([]UIModule, error) {
	root := s.npmMetadataDir()
	byName := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		name := path.Dir(relSlash)
		if name == "." || validateNpmName(name) != nil {
			return nil
		}
		byName[name] = append(byName[name], strings.TrimSuffix(d.Name(), ".json"))
		return nil
	})
	if err != nil {
		return nil, err
	}
	pkgs := make([]UIModule, 0, len(byName))
	for name, versions := range byName {
		sort.Slice(versions, func(i, j int) bool { return compareVersions("v"+versions[i], "v"+versions[j]) < 0 })
		pkgs = append(pkgs, UIModule{Module: name, Versions: versions})
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Module < pkgs[j].Module })
	return pkgs, nil
}

// npmTreeChildren returns the two-level npm tree: the root ("") yields the
// package names (scoped names stay whole, like the registry shows them), and
// expanding a package yields its version leaves.
func npmTreeChildren(pkgs []UIModule, prefix string) []UITreeNode {
	if prefix == "" {
		nodes := make([]UITreeNode, 0, len(pkgs))
		for _, p := range pkgs {
			nodes = append(nodes, UITreeNode{Label: p.Module, Path: p.Module, Kind: "module", Expandable: true, Count: len(p.Versions)})
		}
		return nodes
	}
	for _, p := range pkgs {
		if p.Module != prefix {
			continue
		}
		nodes := make([]UITreeNode, 0, len(p.Versions))
		for _, v := range p.Versions {
			nodes = append(nodes, UITreeNode{Label: v, Path: p.Module + "@" + v, Kind: "version"})
		}
		return nodes
	}
	return []UITreeNode{}
}

// npmDetail describes one mirrored package version for the dashboard detail
// panel. spec is "<name>@<version>" (the name itself may be "@scope/pkg").
func (s *HighServer) npmDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid package@version")
	}
	name, version := spec[:i], spec[i+1:]
	if validateNpmName(name) != nil || validateNpmVersion(version) != nil {
		return UIDetail{}, errors.New("invalid package or version")
	}
	st, err := s.readNpmStoredManifest(name, version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Package", Value: name, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	fields = append(fields, npmManifestFields(st.Manifest)...)
	tarball := filepath.Join(s.npmPackagesDir(), filepath.FromSlash(name), st.Filename)
	if fi, err := os.Stat(tarball); err == nil {
		fields = append(fields, UIDetailField{Label: "Tarball size", Value: formatBytes(fi.Size())})
	}
	if sum, err := s.detailDigests.get(tarball); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	fields = append(fields,
		UIDetailField{Label: "Integrity", Value: st.Integrity, Mono: true},
		UIDetailField{Label: "Registry path", Value: "/npm/" + name + "/-/" + st.Filename, Mono: true},
	)
	downloads := []UIDownload{{Label: st.Filename, URL: "/npm/" + name + "/-/" + st.Filename}}
	return UIDetail{Title: name, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// npmManifestFields extracts the human-facing bits of an embedded package.json
// for the detail panel.
func npmManifestFields(manifest json.RawMessage) []UIDetailField {
	var meta struct {
		Description  string          `json:"description"`
		License      json.RawMessage `json:"license"`
		Dependencies map[string]any  `json:"dependencies"`
	}
	if json.Unmarshal(manifest, &meta) != nil {
		return nil
	}
	var fields []UIDetailField
	if meta.Description != "" {
		fields = append(fields, UIDetailField{Label: "Description", Value: meta.Description})
	}
	var license string
	if json.Unmarshal(meta.License, &license) == nil && license != "" {
		fields = append(fields, UIDetailField{Label: "License", Value: license})
	}
	if len(meta.Dependencies) > 0 {
		fields = append(fields, UIDetailField{Label: "Dependencies", Value: fmt.Sprintf("%d", len(meta.Dependencies))})
	}
	return fields
}

// -----------------------------------------------------------------------------
// Low side: npm resolver/collector
// -----------------------------------------------------------------------------

// NpmCollectRequest is the body of POST /admin/npm/collect.
//
// Packages is a list of npm install specs ("lodash", "lodash@4.17.21",
// "react@^18.2", "@scope/pkg@latest"); the full dependency graph of the listed
// packages is resolved and bundled. Alternatively, PackageJSON may carry a
// project's own package.json (with an optional PackageLock pinning the exact
// resolved graph), in which case ArtiGate mirrors exactly what that project
// resolves. When PackageJSON is set, Packages is ignored.
type NpmCollectRequest struct {
	Packages    []string `json:"packages"`
	PackageJSON string   `json:"package_json"`
	PackageLock string   `json:"package_lock"`
	// Force disables export dedup for this collect: every tarball is packed
	// even when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// validateNpmSpecArg rejects a user-supplied package spec that npm would
// reparse as a CLI option. Specs never legitimately begin with '-' or contain
// whitespace, so refusing those closes argument injection such as a spec of
// "--registry=http://attacker/".
func validateNpmSpecArg(spec string) error {
	if spec == "" {
		return errors.New("empty npm package spec")
	}
	if strings.HasPrefix(spec, "-") {
		return fmt.Errorf("npm spec %q must not start with '-' (would be parsed as an npm flag)", spec)
	}
	for _, r := range spec {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("npm spec %q contains a space or control character", spec)
		}
	}
	return nil
}

func validateNpmRequest(req NpmCollectRequest) error {
	if strings.TrimSpace(req.PackageJSON) != "" {
		if !json.Valid([]byte(req.PackageJSON)) {
			return errors.New("package_json is not valid JSON")
		}
		if strings.TrimSpace(req.PackageLock) != "" && !json.Valid([]byte(req.PackageLock)) {
			return errors.New("package_lock is not valid JSON")
		}
		return nil
	}
	if strings.TrimSpace(req.PackageLock) != "" {
		return errors.New("package_lock requires package_json")
	}
	if len(req.Packages) == 0 {
		return errors.New("no npm packages or package_json provided")
	}
	for _, spec := range req.Packages {
		if err := validateNpmSpecArg(spec); err != nil {
			return err
		}
	}
	return nil
}

// HandleNpmCollect parses a JSON collect request from the admin endpoint and
// runs the collection. The body limit is generous because a request may embed
// a project's package-lock.json.
func (s *LowServer) HandleNpmCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req NpmCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse npm collect request: %w", err)
		}
	}
	return s.CollectNpm(ctx, req)
}

// CollectNpm resolves the requested dependency graph with npm, downloads every
// resolved registry tarball, and writes them into a signed bundle on the npm
// stream. Packages whose tarball cannot be fetched (or that resolve outside
// the registry, e.g. git URLs) are skipped and reported so one of them never
// blocks the rest of the batch.
func (s *LowServer) CollectNpm(ctx context.Context, req NpmCollectRequest) (ExportResult, error) {
	if err := validateNpmRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the npm stream's lock for the whole resolve->download->write->
	// commit so a concurrent npm exporter cannot claim the same sequence number
	// between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamNpm)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "npm", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	emitProgress(ctx, "Resolving the dependency graph with npm…")
	entries, skipped, err := s.resolveNpmLock(ctx, stageRoot, req)
	if err != nil {
		return ExportResult{}, err
	}
	// Upstream metadata (dist-tags, registry signatures, attestation pointers,
	// signing keys) is fetched before the tarballs so each package record can
	// carry its verification material.
	meta := fetchNpmUpstreamMeta(ctx, entries)
	emitProgress(ctx, "Downloading %d tarball(s)…", len(entries))
	pkgs, files, failed, err := s.downloadNpmPackages(ctx, stageRoot, entries, meta)
	if err != nil {
		return ExportResult{}, err
	}
	failed = append(skipped, failed...)
	if len(pkgs) == 0 {
		return ExportResult{}, fmt.Errorf("no npm packages could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	// exportIfNew peeks/commits the sequence around the write (so a failed
	// collection never burns a number) and skips entirely when every tarball was
	// already forwarded.
	res, err := s.exportIfNew(ctx, streamNpm, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeNpmBundle(ctx, seq, stageRoot, files, pkgs, meta)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// resolveNpmLock materializes the project (uploaded or synthetic), lets npm
// resolve the full dependency graph into a package-lock.json without
// installing anything, and parses the lock back.
func (s *LowServer) resolveNpmLock(ctx context.Context, dir string, req NpmCollectRequest) ([]npmLockEntry, []FailedModule, error) {
	specs, err := writeNpmProject(dir, req)
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.runNpm(ctx, dir, npmInstallArgs(s.cfg.NpmRegistry, specs)...); err != nil {
		return nil, nil, err
	}
	lock, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("npm produced no package-lock.json: %w", err)
	}
	return parseNpmLock(lock)
}

// writeNpmProject writes the package.json (and optional package-lock.json) the
// resolution runs against, returning the specs to pass to npm install (empty
// when an uploaded project defines the dependencies itself).
func writeNpmProject(dir string, req NpmCollectRequest) ([]string, error) {
	pj := strings.TrimSpace(req.PackageJSON)
	specs := req.Packages
	if pj != "" {
		specs = nil
	} else {
		pj = `{"name":"artigate-collect","version":"0.0.0","private":true}`
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pj), 0o644); err != nil {
		return nil, err
	}
	if lock := strings.TrimSpace(req.PackageLock); lock != "" && len(specs) == 0 {
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
			return nil, err
		}
	}
	return specs, nil
}

// npmInstallArgs builds the argument list for the resolving npm run.
// --package-lock-only resolves and writes the lockfile without downloading or
// installing packages; scripts are always disabled.
func npmInstallArgs(registry string, specs []string) []string {
	args := []string{"install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}
	if registry != "" {
		args = append(args, "--registry="+registry)
	}
	return append(args, specs...)
}

func (s *LowServer) runNpm(ctx context.Context, dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	bin := s.cfg.NpmBinary
	if bin == "" {
		bin = "npm"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	// Keep npm's cache inside the working root instead of $HOME, and silence
	// the interactive niceties that only add noise to a daemon's logs.
	cmd.Env = append(os.Environ(),
		"npm_config_cache="+filepath.Join(s.cfg.Root, "npm", "cache"),
		"npm_config_update_notifier=false",
		"npm_config_progress=false",
	)
	// npm output is only used for error diagnostics (the resolved graph is read
	// from the lockfile afterward), so combined output is fine here.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("npm %s failed: %w\n%s", strings.Join(args, " "), err, tailBytes(out, 4096))
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// package-lock.json parsing
// -----------------------------------------------------------------------------

// npmLockEntry is one resolved registry package from a lockfile.
type npmLockEntry struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
}

type npmLockPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Link      bool   `json:"link"`
	InBundle  bool   `json:"inBundle"`
}

// parseNpmLock extracts the deduplicated set of resolved registry packages
// from a lockfileVersion >= 2 package-lock.json. Entries that cannot be
// mirrored (git/file URLs, invalid names) are reported as skipped rather than
// failing the parse; entries that need no mirroring (the root project,
// workspace links, dependencies bundled inside a parent tarball) are dropped
// silently.
func parseNpmLock(b []byte) ([]npmLockEntry, []FailedModule, error) {
	var lock struct {
		Packages map[string]npmLockPackage `json:"packages"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if len(lock.Packages) == 0 {
		return nil, nil, errors.New(`package-lock.json has no "packages" map (lockfileVersion 2+, npm 7 or newer, is required)`)
	}
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	seen := map[string]bool{}
	var entries []npmLockEntry
	var skipped []FailedModule
	for _, key := range keys {
		p := lock.Packages[key]
		name := npmLockEntryName(key, p.Name)
		if name == "" || p.Link || p.InBundle {
			continue
		}
		if e, fail := npmLockEntryFor(name, p); fail != nil {
			skipped = append(skipped, *fail)
		} else if !seen[e.Name+"@"+e.Version] {
			seen[e.Name+"@"+e.Version] = true
			entries = append(entries, e)
		}
	}
	return entries, skipped, nil
}

// npmLockEntryName derives a lock entry's package name. Keys outside
// node_modules (the root project, workspace directories) yield "" — they are
// never mirrored, whatever their "name" field says. Within node_modules the
// explicit "name" field wins when present (version aliases), otherwise the
// part of the key after the last "node_modules/".
func npmLockEntryName(key, explicit string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return ""
	}
	if explicit != "" {
		return explicit
	}
	return key[i+len("node_modules/"):]
}

// npmLockEntryFor validates one lock package into a fetchable entry, or
// explains why it must be skipped.
func npmLockEntryFor(name string, p npmLockPackage) (npmLockEntry, *FailedModule) {
	fail := func(msg string) (npmLockEntry, *FailedModule) {
		return npmLockEntry{}, &FailedModule{Module: name, Version: p.Version, Error: msg}
	}
	if err := validateNpmName(name); err != nil {
		return fail(err.Error())
	}
	if p.Version == "" || validateNpmVersion(p.Version) != nil {
		return fail(fmt.Sprintf("invalid version %q in lockfile", p.Version))
	}
	if p.Resolved == "" {
		return fail("no resolved URL in lockfile")
	}
	if u, err := url.Parse(p.Resolved); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fail(fmt.Sprintf("unsupported resolved URL %q (only registry tarballs are mirrored)", p.Resolved))
	}
	// A registry tarball is mirrored only when the lockfile pins its integrity;
	// without it the download could not be verified before being signed into a
	// bundle, so skip and report it rather than forward unverified bytes.
	if strings.TrimSpace(p.Integrity) == "" {
		return fail("no integrity hash in lockfile (an unverifiable tarball is never mirrored)")
	}
	return npmLockEntry{Name: name, Version: p.Version, Resolved: p.Resolved, Integrity: p.Integrity}, nil
}

// -----------------------------------------------------------------------------
// Upstream metadata collection (dist-tags, signatures, attestations, keys)
// -----------------------------------------------------------------------------

// npmMaxPackumentBytes caps one abbreviated packument fetched for dist-tags.
const npmMaxPackumentBytes = 32 << 20

// npmMaxAttestationsBytes caps one version's attestations document (sigstore
// bundles are tens of KB; the cap is generous headroom).
const npmMaxAttestationsBytes = 8 << 20

// npmMaxKeysBytes caps one registry's /-/npm/v1/keys document.
const npmMaxKeysBytes = 1 << 20

// npmAbbreviatedType is the registry media type for the abbreviated
// (install-oriented) packument, a fraction of the full document.
const npmAbbreviatedType = "application/vnd.npm.install-v1+json"

// npmRegistryBaseFor derives the registry base URL that served a resolved
// tarball ("https://host[/prefix]/<name>/-/<file>" -> "https://host[/prefix]"),
// so dist-tags are always asked of the registry the packages actually came
// from — including path-prefixed private registries.
func npmRegistryBaseFor(name, resolved string) string {
	i := strings.Index(resolved, "/"+name+"/-/")
	if i <= 0 {
		return ""
	}
	return resolved[:i]
}

// npmUpstreamMeta is what one collect learns from the upstream registries
// beyond the tarballs themselves: dist-tags per package, registry signatures
// and attestation pointers per exact version, and each registry's signing
// keys. All of it is verification material or polish — fetched best-effort,
// never failing the collect; a package without it simply mirrors bare.
type npmUpstreamMeta struct {
	tags map[string]map[string]string
	sigs map[string][]NpmRegistrySignature // "name@version" ->
	atts map[string]npmAttestationsRef     // "name@version" ->
	keys map[string][]NpmRegistryKey       // registry host ->
	// bases records each package's registry base for the attestation fetch.
	bases map[string]string
}

// npmAttestationsRef is a version's dist.attestations pointer as upstream
// published it.
type npmAttestationsRef struct {
	PredicateType string
}

// fetchNpmUpstreamMeta fetches each mirrored package's upstream metadata and
// each involved registry's signing keys. Any failure skips that piece with a
// progress note and never fails the collect. Invalid records are dropped here
// so the signed manifest only ever carries what the high side's strict
// validation accepts.
func fetchNpmUpstreamMeta(ctx context.Context, entries []npmLockEntry) npmUpstreamMeta {
	meta := npmUpstreamMeta{
		tags: map[string]map[string]string{}, sigs: map[string][]NpmRegistrySignature{},
		atts: map[string]npmAttestationsRef{}, keys: map[string][]NpmRegistryKey{}, bases: map[string]string{},
	}
	versionsByName := map[string][]string{}
	for _, e := range entries {
		if _, ok := meta.bases[e.Name]; !ok {
			meta.bases[e.Name] = npmRegistryBaseFor(e.Name, e.Resolved)
		}
		versionsByName[e.Name] = append(versionsByName[e.Name], e.Version)
	}
	emitProgress(ctx, "Fetching upstream metadata (dist-tags, signatures) for %d package(s)…", len(meta.bases))
	for name, base := range meta.bases {
		if base == "" {
			continue
		}
		if err := fetchNpmPackumentMeta(ctx, base, name, versionsByName[name], &meta); err != nil {
			emitProgress(ctx, "  ✗ metadata %s: %s", name, err)
		}
	}
	fetchNpmRegistryKeys(ctx, &meta)
	return meta
}

// fetchNpmPackumentMeta reads one package's abbreviated packument and records
// its dist-tags plus the registry signatures and attestation pointers of the
// versions this collect mirrors.
func fetchNpmPackumentMeta(ctx context.Context, base, name string, versions []string, meta *npmUpstreamMeta) error {
	b, err := npmRegistryGet(ctx, base+"/"+url.PathEscape(name), npmAbbreviatedType, npmMaxPackumentBytes)
	if err != nil {
		return err
	}
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Dist struct {
				Signatures   []NpmRegistrySignature `json:"signatures"`
				Attestations struct {
					URL        string `json:"url"`
					Provenance struct {
						PredicateType string `json:"predicateType"`
					} `json:"provenance"`
				} `json:"attestations"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse packument: %w", err)
	}
	if cleaned := cleanNpmDistTags(doc.DistTags); len(cleaned) > 0 {
		meta.tags[name] = cleaned
	}
	for _, version := range versions {
		v, ok := doc.Versions[version]
		if !ok {
			continue
		}
		key := name + "@" + version
		if sigs := cleanNpmSignatures(v.Dist.Signatures); len(sigs) > 0 {
			meta.sigs[key] = sigs
		}
		if pt := v.Dist.Attestations.Provenance.PredicateType; pt != "" && len(pt) <= 256 {
			meta.atts[key] = npmAttestationsRef{PredicateType: pt}
		}
	}
	return nil
}

// cleanNpmSignatures keeps only the well-formed, bounded signature entries of
// an upstream dist.signatures list.
func cleanNpmSignatures(sigs []NpmRegistrySignature) []NpmRegistrySignature {
	var out []NpmRegistrySignature
	for _, s := range sigs {
		if s.KeyID == "" || len(s.KeyID) > 256 || s.Sig == "" || len(s.Sig) > 8192 {
			continue
		}
		out = append(out, s)
		if len(out) == 16 {
			break
		}
	}
	return out
}

// fetchNpmRegistryKeys fetches /-/npm/v1/keys once per distinct registry
// base. A registry that publishes no keys (404) is simply skipped.
func fetchNpmRegistryKeys(ctx context.Context, meta *npmUpstreamMeta) {
	seen := map[string]bool{}
	for _, base := range meta.bases {
		host := npmRegistryHost(base)
		if base == "" || host == "" || seen[base] {
			continue
		}
		seen[base] = true
		b, err := npmRegistryGet(ctx, base+"/-/npm/v1/keys", "application/json", npmMaxKeysBytes)
		if err != nil {
			continue // registries without signing keys are the normal case
		}
		var doc struct {
			Keys []NpmRegistryKey `json:"keys"`
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Keys) == 0 {
			continue
		}
		if keys := map[string][]NpmRegistryKey{host: doc.Keys}; validateNpmKeys(keys) == nil {
			meta.keys[host] = doc.Keys
			emitProgress(ctx, "  ⊕ %d signing key(s) from %s", len(doc.Keys), host)
		}
	}
}

// npmRegistryHost extracts the lowercased host (with any port) of a registry
// base URL, the key the signed manifest carries its key snapshot under.
func npmRegistryHost(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Host)
	if !npmRegistryHostRE.MatchString(host) {
		return ""
	}
	return host
}

// npmRegistryGet performs one bounded registry metadata request.
func npmRegistryGet(ctx context.Context, rawURL, accept string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// stageNpmAttestations mirrors one version's attestations document into the
// staging tree, returning its manifest file. found=false with nil error means
// upstream advertises attestations but the document could not be fetched —
// the version then serves without dist.attestations rather than advertising
// a dead URL.
func stageNpmAttestations(ctx context.Context, stageRoot, base string, e npmLockEntry) (ManifestFile, bool, error) {
	b, err := npmRegistryGet(ctx, base+"/-/npm/v1/attestations/"+url.PathEscape(e.Name)+"@"+url.PathEscape(e.Version),
		"application/json", npmMaxAttestationsBytes)
	if err != nil {
		return ManifestFile{}, false, err
	}
	var doc struct {
		Attestations []json.RawMessage `json:"attestations"`
	}
	if json.Unmarshal(b, &doc) != nil || len(doc.Attestations) == 0 {
		return ManifestFile{}, false, errors.New("attestations document is empty or malformed")
	}
	rel := npmAttestationsRel(e.Name, e.Version)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, false, err
	}
	if err := os.WriteFile(abs, b, 0o644); err != nil {
		return ManifestFile{}, false, err
	}
	mf, err := hashManifestFile(abs, rel)
	if err != nil {
		return ManifestFile{}, false, err
	}
	return mf, true, nil
}

// cleanNpmDistTags keeps only the well-formed tag entries of an upstream
// dist-tag map.
func cleanNpmDistTags(tags map[string]string) map[string]string {
	out := map[string]string{}
	for tag, version := range tags {
		if validateNpmDistTag(tag) == nil && validateNpmVersion(version) == nil {
			out[tag] = version
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Tarball download with SRI verification
// -----------------------------------------------------------------------------

// downloadNpmPackages fetches every resolved tarball into the staging tree,
// verifying each against the lockfile's integrity, and attaches each
// package's upstream verification material. A failed download is collected
// rather than aborting the batch.
func (s *LowServer) downloadNpmPackages(ctx context.Context, stageRoot string, entries []npmLockEntry, meta npmUpstreamMeta) ([]NpmPackage, []ManifestFile, []FailedModule, error) {
	var pkgs []NpmPackage
	var files []ManifestFile
	var failed []FailedModule
	for i, e := range entries {
		emitProgress(ctx, "→ [%d/%d] %s@%s", i+1, len(entries), e.Name, e.Version)
		rel := path.Join("npm", "packages", e.Name, npmTarballFilename(e.Name, e.Version))
		abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, nil, nil, err
		}
		if err := downloadNpmTarball(ctx, e.Resolved, e.Integrity, abs); err != nil {
			emitProgress(ctx, "  ✗ %s@%s: %s", e.Name, e.Version, err)
			failed = append(failed, FailedModule{Module: e.Name, Version: e.Version, Error: err.Error()})
			continue
		}
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			return nil, nil, nil, err
		}
		files = append(files, mf)
		pkg := NpmPackage{
			Name: e.Name, Version: e.Version, Filename: path.Base(rel),
			Path: rel, SHA256: mf.SHA256, Integrity: e.Integrity,
			Signatures: meta.sigs[e.Name+"@"+e.Version],
		}
		if attFile, ok := attachNpmAttestations(ctx, stageRoot, e, meta, &pkg); ok {
			files = append(files, attFile)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, files, failed, nil
}

// attachNpmAttestations mirrors a version's attestations document when
// upstream advertises one, recording it on the package. Failures warn and
// leave the package without dist.attestations — never advertising a document
// the mirror does not hold.
func attachNpmAttestations(ctx context.Context, stageRoot string, e npmLockEntry, meta npmUpstreamMeta, pkg *NpmPackage) (ManifestFile, bool) {
	att, ok := meta.atts[e.Name+"@"+e.Version]
	base := meta.bases[e.Name]
	if !ok || base == "" {
		return ManifestFile{}, false
	}
	mf, found, err := stageNpmAttestations(ctx, stageRoot, base, e)
	if err != nil || !found {
		if err == nil {
			err = errors.New("document missing upstream")
		}
		emitProgress(ctx, "  ⚠ attestations %s@%s: %s", e.Name, e.Version, err)
		return ManifestFile{}, false
	}
	emitProgress(ctx, "  ⊕ attestations %s@%s (%s)", e.Name, e.Version, att.PredicateType)
	pkg.AttestationsPath = mf.Path
	pkg.AttestationsPredicateType = att.PredicateType
	return mf, true
}

// downloadNpmTarball streams one tarball to dest, verifying the SRI integrity
// from the lockfile as it downloads. On any failure the partial file is
// removed.
func downloadNpmTarball(ctx context.Context, rawURL, integrity, dest string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	verifier, err := newSRIVerifier(integrity)
	if err != nil {
		return err
	}
	// Defense in depth: npmLockEntryFor already rejects integrity-less entries,
	// but never let this function store a tarball it cannot verify.
	if verifier == nil {
		return errors.New("refusing to store an npm tarball with no integrity hash")
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = os.Remove(dest)
		}
	}()
	w := io.Writer(f)
	if verifier != nil {
		w = io.MultiWriter(f, verifier)
	}
	if _, err = io.Copy(w, io.LimitReader(resp.Body, 2<<30)); err != nil { // 2 GiB cap per tarball
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if verifier != nil {
		err = verifier.verify()
	}
	return err
}

// sriVerifier checks a stream against one Subresource Integrity hash (the
// format npm lockfiles carry, e.g. "sha512-<base64>").
type sriVerifier struct {
	hash.Hash

	algo string
	want []byte
}

// newSRIVerifier picks the strongest supported hash from an SRI string
// (space-separated "algo-base64" entries). It returns nil for an empty string
// — old lockfile entries may carry no integrity — but errors when integrity is
// present yet no algorithm is usable, so a download is never silently
// unverified.
func newSRIVerifier(integrity string) (*sriVerifier, error) {
	entries := strings.Fields(integrity)
	if len(entries) == 0 {
		return nil, nil
	}
	newHash := map[string]func() hash.Hash{
		"sha512": sha512.New,
		"sha384": sha512.New384,
		"sha256": sha256.New,
		"sha1":   sha1.New, //nolint:gosec // legacy npm lockfiles pin sha1; still better than unverified
	}
	for _, algo := range []string{"sha512", "sha384", "sha256", "sha1"} {
		for _, e := range entries {
			b64, ok := strings.CutPrefix(e, algo+"-")
			if !ok {
				continue
			}
			want, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("invalid %s integrity value: %w", algo, err)
			}
			return &sriVerifier{Hash: newHash[algo](), algo: algo, want: want}, nil
		}
	}
	return nil, fmt.Errorf("unsupported integrity %q", integrity)
}

func (v *sriVerifier) verify() error {
	got := v.Sum(nil)
	if subtle.ConstantTimeCompare(got, v.want) != 1 {
		return fmt.Errorf("%s integrity mismatch: got %s want %s", v.algo,
			base64.StdEncoding.EncodeToString(got), base64.StdEncoding.EncodeToString(v.want))
	}
	return nil
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeNpmBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, pkgs []NpmPackage, meta npmUpstreamMeta) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	tags := meta.tags
	if len(tags) == 0 {
		tags = nil
	}
	keys := meta.keys
	if len(keys) == 0 {
		keys = nil
	}
	id := bundleIDFor(streamNpm, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamNpm,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"npm"},
		Npm:              &NpmManifest{Packages: pkgs, DistTags: tags, Keys: keys},
		Files:            files,
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamNpm, Sequence: seq, ExportedModules: len(pkgs), BundleID: id}, nil
}
