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
			return validateNpmPackages(m.Npm.Packages, seen)
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
	}
	return nil
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
type npmStoredManifest struct {
	Filename  string          `json:"filename"`
	Shasum    string          `json:"shasum"`
	Integrity string          `json:"integrity"`
	Manifest  json.RawMessage `json:"manifest"`
}

// serveNpm handles the npm registry routes under /npm/: packument
// (/npm/<name>), version manifest (/npm/<name>/<version>), and tarball
// download (/npm/<name>/-/<file>.tgz). Scoped names arrive either literal
// (@scope/pkg) or URL-encoded (@scope%2fpkg); both decode to the same path.
// It reports whether it wrote a response for the request.
func (s *HighServer) serveNpm(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/npm" && !strings.HasPrefix(p, "/npm/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.Trim(strings.TrimPrefix(p, "/npm"), "/")
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
	names := make([]string, 0, len(versions))
	for v := range versions {
		names = append(names, v)
	}
	writeJSON(w, map[string]any{
		"name":      name,
		"dist-tags": map[string]string{"latest": npmLatestVersion(names)},
		"versions":  versions,
	})
}

func (s *HighServer) handleNpmVersion(w http.ResponseWriter, r *http.Request, name, version string) {
	if validateNpmVersion(version) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	st, err := s.readNpmStoredManifest(name, version)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, npmVersionObject(st, name, version, npmBaseURL(r)))
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
// section pointing back at this server.
func npmVersionObject(st npmStoredManifest, name, version, baseURL string) map[string]any {
	obj := map[string]any{}
	if len(st.Manifest) > 0 {
		_ = json.Unmarshal(st.Manifest, &obj)
	}
	obj["name"] = name
	obj["version"] = version
	obj["dist"] = map[string]string{
		"tarball":   baseURL + "/npm/" + name + "/-/" + st.Filename,
		"shasum":    st.Shasum,
		"integrity": st.Integrity,
	}
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
	return nil
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
	st := npmStoredManifest{Filename: path.Base(p.Path), Shasum: shasum, Integrity: integrity, Manifest: manifest}
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
	tr := tar.NewReader(gz)
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
	if sum, err := sha256File(tarball); err == nil {
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
	emitProgress(ctx, "Downloading %d tarball(s)…", len(entries))
	pkgs, files, failed, err := s.downloadNpmPackages(ctx, stageRoot, entries)
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
		return s.writeNpmBundle(ctx, seq, stageRoot, files, pkgs)
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
// Tarball download with SRI verification
// -----------------------------------------------------------------------------

// downloadNpmPackages fetches every resolved tarball into the staging tree,
// verifying each against the lockfile's integrity. A failed download is
// collected rather than aborting the batch.
func (s *LowServer) downloadNpmPackages(ctx context.Context, stageRoot string, entries []npmLockEntry) ([]NpmPackage, []ManifestFile, []FailedModule, error) {
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
		pkgs = append(pkgs, NpmPackage{
			Name: e.Name, Version: e.Version, Filename: path.Base(rel),
			Path: rel, SHA256: mf.SHA256, Integrity: e.Integrity,
		})
	}
	return pkgs, files, failed, nil
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

func (s *LowServer) writeNpmBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, pkgs []NpmPackage) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})
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
		Npm:              &NpmManifest{Packages: pkgs},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamNpm, Sequence: seq, ExportedModules: len(pkgs), BundleID: id}, nil
}
