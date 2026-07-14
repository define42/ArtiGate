package main

// PHP Composer ecosystem adapter. The low side resolves packages against a
// Composer v2 repository (repo.packagist.org by default): it expands the
// minified p2 metadata, picks the requested releases plus the require closure
// of each, downloads the dist zips, and packs them into the same numbered,
// signed ArtiGate bundle format used by the other ecosystems. Each release's
// expanded version object travels inside the Ed25519-signed manifest with its
// dist and source sections removed — the high side re-renders the Composer v2
// repository API from those verified objects on the fly, injecting a dist
// section that points at the zip it serves itself, so `composer install`
// works against <base>/composer.
//
// Policy: http(s) zip dists only, and dependency resolution implements a
// documented pragmatic subset of Composer's constraint syntax over stable
// releases — a constraint outside the subset is reported, never guessed at.

import (
	"context"
	"crypto/sha1" //nolint:gosec // sha1 is only the legacy composer dist.shasum field, not a security control
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
)

// composerEcosystem is the Composer package stream's registry entry (see
// ecosystems in ecosystem.go).
func composerEcosystem() ecosystem {
	return ecosystem{
		stream:       streamComposer,
		label:        "Composer",
		title:        "PHP Composer packages",
		collect:      (*LowServer).HandleComposerCollect,
		watchCollect: watchAdapter((*LowServer).CollectComposer),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.ComposerRepoURL, "composer-repo", "", "Composer repository package metadata and dists are resolved from (default "+defaultComposerRepoURL+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.Composer != nil && len(m.Composer.Packages) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateComposerPackages(m.Composer.Packages, seen)
		},
		contentDesc: "composer packages",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishComposer(m.Composer) },
		serve:       (*HighServer).serveComposer,
		scanTree:    flatTreeScan((*HighServer).listComposerPackages),
		detail:      (*HighServer).composerDetail,
	}
}

const defaultComposerRepoURL = "https://repo.packagist.org"

// composerMinifiedFormat marks the diff-compressed p2 metadata format
// packagist serves; anything else is taken as full version objects.
const composerMinifiedFormat = "composer/2.0"

// composerMaxMetadataBytes caps one p2 metadata file held in memory.
const composerMaxMetadataBytes = 64 << 20

// composerMaxResolved bounds a dependency closure so a pathological
// repository cannot grow a request without limit.
const composerMaxResolved = 2000

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type ComposerManifest struct {
	Packages []ComposerPackage `json:"packages"`
}

// ComposerPackage records one mirrored package release. Metadata is the
// upstream Composer v2 (p2) version object with its dist section removed; the
// high side re-adds a dist section pointing at the verified zip it serves.
type ComposerPackage struct {
	Name              string          `json:"name"`
	Version           string          `json:"version"`
	VersionNormalized string          `json:"version_normalized"`
	Path              string          `json:"path"`
	SHA256            string          `json:"sha256"`
	Metadata          json.RawMessage `json:"metadata"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// composerNamePartRE is Composer's own rule for the vendor and project parts
// of a package name (lowercase only). Starting alphanumeric keeps every part
// path-safe: a part can never be ".", "..", or something a CLI would parse as
// a flag.
var composerNamePartRE = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*$`)

// composerVersionNormalizedRE matches a normalized version, which always
// starts with a digit, so it can never be ".."/"-flag" or contain a path
// separator.
var composerVersionNormalizedRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,63}$`)

// composerVersionRE matches a pretty version, which may start with a "v"
// ("v2.0.2" tags) but is always alphanumeric-first and path-safe.
var composerVersionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)

// validateComposerName checks a "vendor/project" package name is well-formed
// and path-safe: names become filesystem directories and URL segments on both
// sides of the diode.
func validateComposerName(name string) error {
	vendor, project, ok := strings.Cut(name, "/")
	if !ok || len(name) > 214 ||
		!composerNamePartRE.MatchString(vendor) || !composerNamePartRE.MatchString(project) {
		return fmt.Errorf("invalid composer package name %q", name)
	}
	return nil
}

func validateComposerVersionNormalized(v string) error {
	if !composerVersionNormalizedRE.MatchString(v) {
		return fmt.Errorf("invalid normalized composer version %q", v)
	}
	return nil
}

func validateComposerVersion(v string) error {
	if !composerVersionRE.MatchString(v) {
		return fmt.Errorf("invalid composer version %q", v)
	}
	return nil
}

// composerDistRel is the repository-relative path a release's dist zip is
// stored under, keyed by the normalized version (unique per release, and
// digit-first so it is path-safe).
func composerDistRel(name, versionNormalized string) string {
	return path.Join("composer", "dist", name, versionNormalized+".zip")
}

// validateComposerRecord checks one manifest record: path-safe identity, the
// canonical storage path, and the pruned metadata object (everything except
// membership in the manifest's file set, which only the importer can check).
func validateComposerRecord(p ComposerPackage) error {
	if err := validateComposerName(p.Name); err != nil {
		return err
	}
	if err := validateComposerVersion(p.Version); err != nil {
		return fmt.Errorf("composer package %s: %w", p.Name, err)
	}
	if err := validateComposerVersionNormalized(p.VersionNormalized); err != nil {
		return fmt.Errorf("composer package %s: %w", p.Name, err)
	}
	if p.Path != composerDistRel(p.Name, p.VersionNormalized) {
		return fmt.Errorf("composer package %s@%s has non-canonical path %s", p.Name, p.Version, p.Path)
	}
	return validateComposerMetadata(p)
}

// validateComposerMetadata checks the manifest-carried version object: a JSON
// object naming exactly this release, with the dist and source sections that
// were removed at collect time still absent — the high side serves a dist of
// its own, and a source section would leak internal VCS URLs and tempt
// clients to bypass the mirror.
func validateComposerMetadata(p ComposerPackage) error {
	var obj map[string]any
	if err := json.Unmarshal(p.Metadata, &obj); err != nil || obj == nil {
		return fmt.Errorf("composer package %s@%s has unparsable metadata", p.Name, p.Version)
	}
	if name, _ := obj["name"].(string); name != p.Name {
		return fmt.Errorf("composer package %s@%s metadata names %q", p.Name, p.Version, obj["name"])
	}
	if vn, _ := obj["version_normalized"].(string); vn != p.VersionNormalized {
		return fmt.Errorf("composer package %s@%s metadata normalizes to %q", p.Name, p.Version, obj["version_normalized"])
	}
	for _, key := range []string{"dist", "source"} {
		if _, ok := obj[key]; ok {
			return fmt.Errorf("composer package %s@%s metadata carries a %s section", p.Name, p.Version, key)
		}
	}
	return nil
}

// validateComposerPackages checks every package record of a bundle manifest.
func validateComposerPackages(pkgs []ComposerPackage, seen map[string]bool) error {
	for _, p := range pkgs {
		if err := validateComposerRecord(p); err != nil {
			return err
		}
		if !seen[p.Path] {
			return fmt.Errorf("composer package %s@%s references file not listed in manifest.files: %s", p.Name, p.Version, p.Path)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Version ordering
// -----------------------------------------------------------------------------

// composerVersionFields parses dotted integer fields ("1.2.3" -> [1 2 3 0],
// n=3) after stripping a "v" prefix. Up to four fields; anything non-numeric
// fails.
func composerVersionFields(s string) (fields [4]int, n int, err error) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if s == "" || len(parts) > len(fields) {
		return fields, 0, fmt.Errorf("unsupported version %q", s)
	}
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return fields, 0, fmt.Errorf("unsupported version %q", s)
		}
		fields[i] = v
	}
	return fields, len(parts), nil
}

// composerStability ranks a normalized stability suffix ("beta2", "RC1",
// "dev") and extracts its numeric tiebreaker. Stable (no suffix) ranks above
// every pre-release; a patch suffix ranks above stable, like Composer orders
// re-releases. Unrecognized suffixes sort lowest, with dev.
func composerStability(suffix string) (rank, num int) {
	if suffix == "" {
		return 4, 0
	}
	word := strings.ToLower(strings.TrimRight(suffix, "0123456789"))
	if digits := suffix[len(word):]; digits != "" {
		num, _ = strconv.Atoi(digits)
	}
	switch word {
	case "patch", "pl", "p":
		return 5, num
	case "rc":
		return 3, num
	case "beta", "b":
		return 2, num
	case "alpha", "a":
		return 1, num
	default:
		return 0, num
	}
}

// composerCompareVersions orders two Composer versions by their normalized
// shape: up to four dot-separated integer fields (missing fields count as
// zero), then stability (dev < alpha < beta < RC < stable < patch), then the
// suffix's numeric tiebreaker ("beta2" above "beta1").
func composerCompareVersions(a, b string) int {
	anum, asuf, _ := strings.Cut(a, "-")
	bnum, bsuf, _ := strings.Cut(b, "-")
	af, _, _ := composerVersionFields(anum)
	bf, _, _ := composerVersionFields(bnum)
	for i := range af {
		if af[i] != bf[i] {
			return composerIntCompare(af[i], bf[i])
		}
	}
	ar, an := composerStability(asuf)
	br, bn := composerStability(bsuf)
	if ar != br {
		return composerIntCompare(ar, br)
	}
	return composerIntCompare(an, bn)
}

func composerIntCompare(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// composerVersionStable reports whether a normalized version is a stable
// release: no "-" stability suffix.
func composerVersionStable(versionNormalized string) bool {
	return !strings.Contains(versionNormalized, "-")
}

// -----------------------------------------------------------------------------
// Constraint matching (pragmatic subset)
// -----------------------------------------------------------------------------

// composerPlainVersionRE matches the version literals the constraint subset
// accepts: dotted integers with an optional stability suffix.
var composerPlainVersionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z.]+)?$`)

// composerConstraintMatches reports whether a normalized version satisfies a
// Composer version constraint. It implements the pragmatic subset ArtiGate
// needs for stable-release resolution — "||"/"|" OR groups of
// whitespace/comma AND parts, each "*", "^", "~", a comparison, a trailing
// ".*" wildcard, or a bare version — and errors on anything else so the
// caller reports the dependency instead of guessing. Every part is evaluated
// even after the outcome is decided, so an unsupported operator anywhere in
// the expression always surfaces.
func composerConstraintMatches(constraint, versionNormalized string) (bool, error) {
	matched := false
	for _, group := range strings.Split(strings.ReplaceAll(constraint, "||", "|"), "|") {
		parts := strings.FieldsFunc(group, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		if len(parts) == 0 {
			return false, fmt.Errorf("unsupported constraint %q", constraint)
		}
		ok, err := composerGroupMatches(parts, versionNormalized)
		if err != nil {
			return false, err
		}
		matched = matched || ok
	}
	return matched, nil
}

// composerGroupMatches evaluates one AND group: every part must match.
func composerGroupMatches(parts []string, vnorm string) (bool, error) {
	all := true
	for _, part := range parts {
		ok, err := composerPartMatches(part, vnorm)
		if err != nil {
			return false, err
		}
		all = all && ok
	}
	return all, nil
}

// composerPartMatches evaluates one constraint part against a normalized
// version.
func composerPartMatches(part, vnorm string) (bool, error) {
	if part == "*" {
		return true, nil
	}
	if op, ver, ok := composerCutOperator(part); ok {
		return composerOpMatches(op, ver, vnorm)
	}
	switch {
	case strings.HasPrefix(part, "^"):
		return composerCaretMatches(strings.TrimPrefix(part, "^"), vnorm)
	case strings.HasPrefix(part, "~"):
		return composerTildeMatches(strings.TrimPrefix(part, "~"), vnorm)
	case strings.HasSuffix(part, ".*"):
		return composerWildcardMatches(part, vnorm)
	default:
		return composerBareMatches(part, vnorm)
	}
}

// composerCutOperator splits a comparison part into its operator and version.
func composerCutOperator(part string) (op, ver string, ok bool) {
	for _, o := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(part, o) {
			return o, part[len(o):], true
		}
	}
	return "", "", false
}

// composerOpMatches evaluates one comparison part (">=7.4", "!=2.0", ...).
func composerOpMatches(op, ver, vnorm string) (bool, error) {
	ver = strings.TrimPrefix(ver, "v")
	if !composerPlainVersionRE.MatchString(ver) {
		return false, fmt.Errorf("unsupported constraint version %q", ver)
	}
	c := composerCompareVersions(vnorm, ver)
	switch op {
	case ">=":
		return c >= 0, nil
	case ">":
		return c > 0, nil
	case "<=":
		return c <= 0, nil
	case "<":
		return c < 0, nil
	case "!=":
		return c != 0, nil
	default: // "="
		return c == 0, nil
	}
}

// composerBoundFields parses the numeric fields of a range operator's bound,
// tolerating a stability suffix ("2.0-beta1" -> [2 0 0 0], 2 fields).
func composerBoundFields(spec string) ([4]int, int, error) {
	if !composerPlainVersionRE.MatchString(spec) {
		return [4]int{}, 0, fmt.Errorf("unsupported version %q", spec)
	}
	num, _, _ := strings.Cut(spec, "-")
	return composerVersionFields(num)
}

// composerFieldsVersion renders numeric fields back into a version literal.
func composerFieldsVersion(f [4]int) string {
	return fmt.Sprintf("%d.%d.%d.%d", f[0], f[1], f[2], f[3])
}

// composerCaretMatches implements "^X[.Y[.Z]]": at least the given version
// and below the next major — below 0.(Y+1) for a 0.Y base, the caret's
// compatibility unit for pre-1.0 ranges (pragmatic subset of Composer's
// rule).
func composerCaretMatches(spec, vnorm string) (bool, error) {
	spec = strings.TrimPrefix(spec, "v")
	fields, n, err := composerBoundFields(spec)
	if err != nil {
		return false, fmt.Errorf("unsupported caret constraint %q", "^"+spec)
	}
	if composerCompareVersions(vnorm, spec) < 0 {
		return false, nil
	}
	upper := [4]int{fields[0] + 1, 0, 0, 0}
	if fields[0] == 0 && n >= 2 {
		upper = [4]int{0, fields[1] + 1, 0, 0}
	}
	return composerCompareVersions(vnorm, composerFieldsVersion(upper)) < 0, nil
}

// composerTildeMatches implements "~X.Y" (>= X.Y, below (X+1).0) and "~X.Y.Z"
// (>= X.Y.Z, below X.(Y+1).0): the rightmost given field may float. A
// single-field "~X" is outside the subset and rejected.
func composerTildeMatches(spec, vnorm string) (bool, error) {
	spec = strings.TrimPrefix(spec, "v")
	fields, n, err := composerBoundFields(spec)
	if err != nil || n < 2 {
		return false, fmt.Errorf("unsupported tilde constraint %q", "~"+spec)
	}
	if composerCompareVersions(vnorm, spec) < 0 {
		return false, nil
	}
	upper := fields
	upper[n-2]++
	for i := n - 1; i < len(upper); i++ {
		upper[i] = 0
	}
	return composerCompareVersions(vnorm, composerFieldsVersion(upper)) < 0, nil
}

// composerWildcardMatches implements "X.*" / "X.Y.*": the named leading
// fields must equal the version's, the starred tail may be anything.
func composerWildcardMatches(part, vnorm string) (bool, error) {
	fields, n, err := composerVersionFields(strings.TrimSuffix(part, ".*"))
	if err != nil {
		return false, fmt.Errorf("unsupported wildcard constraint %q", part)
	}
	return composerFieldsMatch(vnorm, fields, n), nil
}

// composerBareMatches implements a bare version part: exact-ish, the given
// fields matching the normalized version's leading fields ("2.0.2" matches
// "2.0.2.0") and any stability suffix matching exactly.
func composerBareMatches(part, vnorm string) (bool, error) {
	p := strings.TrimPrefix(part, "v")
	if !composerPlainVersionRE.MatchString(p) {
		return false, fmt.Errorf("unsupported constraint %q", part)
	}
	num, suffix, _ := strings.Cut(p, "-")
	fields, n, err := composerVersionFields(num)
	if err != nil {
		return false, fmt.Errorf("unsupported constraint %q", part)
	}
	_, vsuffix, _ := strings.Cut(vnorm, "-")
	if !strings.EqualFold(suffix, vsuffix) {
		return false, nil
	}
	return composerFieldsMatch(vnorm, fields, n), nil
}

// composerFieldsMatch reports whether the first n numeric fields of a
// normalized version equal the given fields.
func composerFieldsMatch(vnorm string, fields [4]int, n int) bool {
	num, _, _ := strings.Cut(vnorm, "-")
	vf, _, err := composerVersionFields(num)
	if err != nil {
		return false
	}
	for i := 0; i < n; i++ {
		if vf[i] != fields[i] {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Upstream p2 metadata
// -----------------------------------------------------------------------------

// composerExpandMinified expands the composer/2.0 minified version list: the
// first element is a complete version object, each later element carries only
// the keys that changed from the previous expanded object, and a key whose
// value is the string "__unset" is removed.
func composerExpandMinified(list []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	cur := map[string]any{}
	for _, diff := range list {
		next := make(map[string]any, len(cur)+len(diff))
		for k, v := range cur {
			next[k] = v
		}
		for k, v := range diff {
			if s, ok := v.(string); ok && s == "__unset" {
				delete(next, k)
				continue
			}
			next[k] = v
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// composerString reads one string field of a version object.
func composerString(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

// fetchComposerMetadata downloads one package's Composer v2 metadata file
// (<base>/p2/<vendor>/<project>.json) and expands it into full version
// objects.
func fetchComposerMetadata(ctx context.Context, base, name string) ([]map[string]any, error) {
	b, err := httpGetBytes(ctx, base+"/p2/"+name+".json", composerMaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	var file struct {
		Minified string                      `json:"minified"`
		Packages map[string][]map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, fmt.Errorf("parse composer metadata for %s: %w", name, err)
	}
	list := file.Packages[name]
	if len(list) == 0 {
		return nil, errors.New("package not found in the repository metadata")
	}
	if file.Minified == composerMinifiedFormat {
		list = composerExpandMinified(list)
	}
	return list, nil
}

// composerSelectRelease picks the version object a request spec names: the
// exact pretty or normalized version when pinned, else the newest stable
// release (the newest of anything only when no stable release exists).
func composerSelectRelease(versions []map[string]any, version string) (map[string]any, error) {
	if version != "" {
		for _, obj := range versions {
			if composerString(obj, "version") == version || composerString(obj, "version_normalized") == version {
				return obj, nil
			}
		}
		return nil, fmt.Errorf("version %s not found in the repository metadata", version)
	}
	if best := composerNewestRelease(versions, true); best != nil {
		return best, nil
	}
	if best := composerNewestRelease(versions, false); best != nil {
		return best, nil
	}
	return nil, errors.New("no usable version in the repository metadata")
}

// composerNewestRelease returns the highest-versioned object, optionally
// restricted to stable releases; nil when none qualifies.
func composerNewestRelease(versions []map[string]any, stableOnly bool) map[string]any {
	var best map[string]any
	bestV := ""
	for _, obj := range versions {
		vnorm := composerString(obj, "version_normalized")
		if validateComposerVersionNormalized(vnorm) != nil {
			continue
		}
		if stableOnly && !composerVersionStable(vnorm) {
			continue
		}
		if best == nil || composerCompareVersions(bestV, vnorm) < 0 {
			best, bestV = obj, vnorm
		}
	}
	return best
}

// composerSelectDependency picks the newest stable release satisfying a
// require constraint. Only stable candidates are considered, like a default
// (minimum-stability: stable) Composer project resolves.
func composerSelectDependency(versions []map[string]any, constraint string) (map[string]any, error) {
	var best map[string]any
	bestV := ""
	for _, obj := range versions {
		vnorm := composerString(obj, "version_normalized")
		if validateComposerVersionNormalized(vnorm) != nil || !composerVersionStable(vnorm) {
			continue
		}
		match, err := composerConstraintMatches(constraint, vnorm)
		if err != nil {
			return nil, err
		}
		if match && (best == nil || composerCompareVersions(bestV, vnorm) < 0) {
			best, bestV = obj, vnorm
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no stable version satisfies %q", constraint)
	}
	return best, nil
}

// composerPlatformPackage reports whether a require name is a platform
// package — PHP itself, extensions, system libraries, or the Composer API
// versions — which describes the runtime, never a mirrorable package.
func composerPlatformPackage(name string) bool {
	switch name {
	case "php", "hhvm", "composer-plugin-api", "composer-runtime-api":
		return true
	}
	return strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-")
}

// -----------------------------------------------------------------------------
// High side: Composer repository serving
// -----------------------------------------------------------------------------

func (s *HighServer) composerDistDir() string {
	return filepath.Join(s.downloadDir, "composer", "dist")
}

func (s *HighServer) composerMetadataDir() string {
	return filepath.Join(s.downloadDir, "composer", "metadata")
}

// composerStoredVersion is the per-release metadata the high side regenerates
// at import time: the manifest-carried version object plus the SHA-1 it
// computes from the artifact bytes (Composer verifies dist.shasum with SHA-1
// when non-empty). The served p2 files are assembled from these.
type composerStoredVersion struct {
	Filename string          `json:"filename"`
	Version  string          `json:"version"`
	Shasum   string          `json:"shasum"`
	Metadata json.RawMessage `json:"metadata"`
}

// serveComposer handles the Composer v2 repository routes under /composer/:
// packages.json, the per-package p2 metadata rendered on the fly from the
// stored version objects (gated on the zip being present), and the dist
// downloads. It reports whether it wrote a response for the request.
func (s *HighServer) serveComposer(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/composer" && !strings.HasPrefix(p, "/composer/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.Trim(strings.TrimPrefix(p, "/composer"), "/")
	switch {
	case rest == "packages.json":
		s.handleComposerRoot(w)
	case strings.HasPrefix(rest, "p2/"):
		s.handleComposerP2(w, r, strings.TrimPrefix(rest, "p2/"))
	case strings.HasPrefix(rest, "dist/"):
		s.handleComposerDist(w, r, strings.TrimPrefix(rest, "dist/"))
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

// handleComposerRoot serves packages.json, the repository entry point:
// metadata-url tells Composer where the per-package files live, and
// available-packages stops it probing names the mirror does not carry.
func (s *HighServer) handleComposerRoot(w http.ResponseWriter) {
	pkgs, err := s.listComposerPackages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Module)
	}
	writeJSON(w, map[string]any{
		"metadata-url":       "/composer/p2/%package%.json",
		"available-packages": names,
	})
}

// handleComposerP2 answers /composer/p2/<vendor>/<project>.json and its ~dev
// variant. Entries are full version objects — no "minified" key — newest
// first, each with a dist section pointing back at this server.
func (s *HighServer) handleComposerP2(w http.ResponseWriter, r *http.Request, rest string) {
	stem, ok := strings.CutSuffix(rest, ".json")
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	name, dev := strings.CutSuffix(stem, "~dev")
	if validateComposerName(name) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	objects, err := s.composerVersionObjects(npmBaseURL(r), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(objects) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if dev {
		// Composer asks for dev versions alongside the stable file; the mirror
		// carries none, and an empty list is the truthful answer.
		objects = []map[string]any{}
	}
	writeJSON(w, map[string]any{"packages": map[string]any{name: objects}})
}

// handleComposerDist serves one dist zip under /composer/dist/. The
// regenerated metadata store stays private.
func (s *HighServer) handleComposerDist(w http.ResponseWriter, r *http.Request, rest string) {
	if validateRelPath(rest) != nil || !composerDistPath(rest) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.composerDistDir(), filepath.FromSlash(rest))
	if !safeJoin(s.composerDistDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// composerDistPath restricts the served dist tree to the one client-facing
// shape: <vendor>/<project>/<version_normalized>.zip.
func composerDistPath(rest string) bool {
	segs := strings.Split(rest, "/")
	if len(segs) != 3 {
		return false
	}
	stem, ok := strings.CutSuffix(segs[2], ".zip")
	return ok && validateComposerName(segs[0]+"/"+segs[1]) == nil &&
		validateComposerVersionNormalized(stem) == nil
}

// composerStoredRelease pairs one servable release's normalized version with
// its stored metadata.
type composerStoredRelease struct {
	vnorm  string
	stored composerStoredVersion
}

// composerStoredReleases loads every servable release of a package — the
// stored metadata whose zip is still present — unsorted.
func (s *HighServer) composerStoredReleases(name string) ([]composerStoredRelease, error) {
	dir := filepath.Join(s.composerMetadataDir(), filepath.FromSlash(name))
	if !safeJoin(s.composerMetadataDir(), dir) {
		return nil, errors.New("unsafe path")
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []composerStoredRelease
	for _, e := range entries {
		vnorm := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || vnorm == e.Name() || validateComposerVersionNormalized(vnorm) != nil {
			continue
		}
		st, err := s.readComposerStored(name, vnorm)
		if err != nil {
			continue
		}
		out = append(out, composerStoredRelease{vnorm: vnorm, stored: st})
	}
	return out, nil
}

// readComposerStored loads one release's regenerated metadata and checks its
// zip is still present (only complete releases are served).
func (s *HighServer) readComposerStored(name, vnorm string) (composerStoredVersion, error) {
	p := filepath.Join(s.composerMetadataDir(), filepath.FromSlash(name), vnorm+".json")
	if !safeJoin(s.composerMetadataDir(), p) {
		return composerStoredVersion{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return composerStoredVersion{}, err
	}
	var st composerStoredVersion
	if err := json.Unmarshal(b, &st); err != nil {
		return composerStoredVersion{}, err
	}
	if st.Filename != vnorm+".zip" || validateComposerVersion(st.Version) != nil {
		return composerStoredVersion{}, fmt.Errorf("invalid stored metadata for %s@%s", name, vnorm)
	}
	zip := filepath.Join(s.composerDistDir(), filepath.FromSlash(name), st.Filename)
	if !safeJoin(s.composerDistDir(), zip) || !fileExists(zip) {
		return composerStoredVersion{}, fmt.Errorf("zip missing for %s@%s", name, vnorm)
	}
	return st, nil
}

// composerVersionObjects renders one package's served p2 version list from
// the regenerated per-release metadata, newest first.
func (s *HighServer) composerVersionObjects(baseURL, name string) ([]map[string]any, error) {
	releases, err := s.composerStoredReleases(name)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(releases))
	for _, rel := range releases {
		if obj := composerServedVersionObject(rel.stored, name, rel.vnorm, baseURL); obj != nil {
			out = append(out, obj)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		vi := composerString(out[i], "version_normalized")
		vj := composerString(out[j], "version_normalized")
		return composerCompareVersions(vi, vj) > 0
	})
	return out, nil
}

// composerServedVersionObject renders one served p2 entry: the stored version
// object with a dist section injected that points back at this server (the
// upstream dist was removed at collect time).
func composerServedVersionObject(st composerStoredVersion, name, vnorm, baseURL string) map[string]any {
	obj := map[string]any{}
	if json.Unmarshal(st.Metadata, &obj) != nil || obj == nil {
		return nil
	}
	obj["dist"] = map[string]any{
		"type":   "zip",
		"url":    baseURL + "/composer/dist/" + name + "/" + vnorm + ".zip",
		"shasum": st.Shasum,
	}
	return obj
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// publishComposer regenerates the served per-release metadata for every
// package in an imported bundle. A record that cannot be published is logged
// and skipped (its version 404s) rather than wedging the stream's import
// forever.
func (s *HighServer) publishComposer(m *ComposerManifest) error {
	if m == nil {
		return nil
	}
	for _, p := range m.Packages {
		if err := s.publishComposerPackage(p); err != nil {
			log.Printf("composer publish %s@%s: %v", p.Name, p.Version, err)
		}
	}
	return nil
}

// publishComposerPackage regenerates one release's stored metadata. The zip
// is never opened: the version object travels inside the Ed25519-signed
// manifest, and the dist.shasum Composer clients verify is recomputed here
// from the byte-verified artifact itself.
func (s *HighServer) publishComposerPackage(p ComposerPackage) error {
	if err := validateComposerRecord(p); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(p.Path))
	if !strings.HasPrefix(p.Path, "composer/dist/") || !safeJoin(s.composerDistDir(), abs) {
		return fmt.Errorf("unsafe dist path %s", p.Path)
	}
	shasum, err := composerSha1File(abs)
	if err != nil {
		return err
	}
	st := composerStoredVersion{
		Filename: p.VersionNormalized + ".zip",
		Version:  p.Version,
		Shasum:   shasum,
		Metadata: p.Metadata,
	}
	out := filepath.Join(s.composerMetadataDir(), filepath.FromSlash(p.Name), p.VersionNormalized+".json")
	if !safeJoin(s.composerMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s@%s", p.Name, p.Version)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// composerSha1File returns the hex SHA-1 of a file — the dist.shasum field
// Composer clients verify downloads against when non-empty. Integrity across
// the diode rests on the bundle's SHA-256 verification; this is only the
// client-facing legacy digest.
func composerSha1File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New() //nolint:gosec // legacy composer dist.shasum field, not a security control
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listComposerPackages groups the mirrored releases by package name with
// their pretty versions, from the regenerated metadata tree.
func (s *HighServer) listComposerPackages() ([]UIModule, error) {
	vendors, err := os.ReadDir(s.composerMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIModule
	for _, v := range vendors {
		if !v.IsDir() {
			continue
		}
		out = s.appendComposerVendor(out, v.Name())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// appendComposerVendor appends one vendor directory's packages that still
// have at least one servable release.
func (s *HighServer) appendComposerVendor(out []UIModule, vendor string) []UIModule {
	projects, err := os.ReadDir(filepath.Join(s.composerMetadataDir(), vendor))
	if err != nil {
		return out
	}
	for _, p := range projects {
		name := vendor + "/" + p.Name()
		if !p.IsDir() || validateComposerName(name) != nil {
			continue
		}
		if versions := s.composerServableVersions(name); len(versions) > 0 {
			out = append(out, UIModule{Module: name, Versions: versions})
		}
	}
	return out
}

// composerServableVersions lists one package's pretty versions whose zip is
// present, oldest first.
func (s *HighServer) composerServableVersions(name string) []string {
	releases, err := s.composerStoredReleases(name)
	if err != nil {
		return nil
	}
	sort.Slice(releases, func(i, j int) bool {
		return composerCompareVersions(releases[i].vnorm, releases[j].vnorm) < 0
	})
	versions := make([]string, 0, len(releases))
	for _, rel := range releases {
		versions = append(versions, rel.stored.Version)
	}
	return versions
}

// composerDetail describes one mirrored release for the dashboard detail
// panel. spec is "<vendor>/<project>@<version_normalized>" (split at the last
// "@"); the pretty version the tree lists is accepted too.
func (s *HighServer) composerDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid package@version")
	}
	name, version := spec[:i], spec[i+1:]
	if validateComposerName(name) != nil || validateComposerVersion(version) != nil {
		return UIDetail{}, errors.New("invalid package@version")
	}
	rel, err := s.composerFindStored(name, version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	return s.composerDetailFor(name, rel), nil
}

// composerFindStored loads a release by its normalized version, falling back
// to a pretty-version match (the dashboard tree lists pretty versions).
func (s *HighServer) composerFindStored(name, version string) (composerStoredRelease, error) {
	if validateComposerVersionNormalized(version) == nil {
		if st, err := s.readComposerStored(name, version); err == nil {
			return composerStoredRelease{vnorm: version, stored: st}, nil
		}
	}
	releases, err := s.composerStoredReleases(name)
	if err != nil {
		return composerStoredRelease{}, err
	}
	for _, rel := range releases {
		if rel.stored.Version == version {
			return rel, nil
		}
	}
	return composerStoredRelease{}, errors.New("version not found")
}

// composerDetailFor renders the detail panel for one servable release.
func (s *HighServer) composerDetailFor(name string, rel composerStoredRelease) UIDetail {
	fields := []UIDetailField{
		{Label: "Package", Value: name, Mono: true},
		{Label: "Version", Value: rel.stored.Version, Mono: true},
		{Label: "Normalized", Value: rel.vnorm, Mono: true},
	}
	var meta map[string]any
	_ = json.Unmarshal(rel.stored.Metadata, &meta)
	fields = append(fields, composerMetaFields(meta)...)
	abs := filepath.Join(s.composerDistDir(), filepath.FromSlash(name), rel.stored.Filename)
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Zip size", Value: formatBytes(fi.Size())})
	}
	if sum, err := sha256File(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	distPath := "/composer/dist/" + name + "/" + rel.stored.Filename
	fields = append(fields, UIDetailField{Label: "Dist path", Value: distPath, Mono: true})
	downloads := []UIDownload{{Label: rel.stored.Filename, URL: distPath}}
	return UIDetail{Title: name, Subtitle: rel.stored.Version, Fields: fields, Downloads: downloads}
}

// composerMetaFields renders the descriptive fields carried in the stored
// version object: license, description, type, and the require count.
func composerMetaFields(meta map[string]any) []UIDetailField {
	var out []UIDetailField
	if lic := composerLicenseString(meta["license"]); lic != "" {
		out = append(out, UIDetailField{Label: "License", Value: lic})
	}
	for _, key := range []string{"description", "type"} {
		if v, _ := meta[key].(string); v != "" {
			out = append(out, UIDetailField{Label: strings.ToUpper(key[:1]) + key[1:], Value: v})
		}
	}
	if req, ok := meta["require"].(map[string]any); ok {
		out = append(out, UIDetailField{Label: "Require", Value: fmt.Sprintf("%d dependencies", len(req))})
	}
	return out
}

// composerLicenseString renders the metadata license entry (usually a list).
func composerLicenseString(v any) string {
	switch l := v.(type) {
	case string:
		return l
	case []any:
		parts := make([]string, 0, len(l))
		for _, e := range l {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

// -----------------------------------------------------------------------------
// Low side: package collector
// -----------------------------------------------------------------------------

// ComposerCollectRequest is the body of POST /admin/composer/collect.
type ComposerCollectRequest struct {
	// Packages lists the packages to mirror: "vendor/project" for the newest
	// stable release, or "vendor/project:1.2.3" to pin (matched against the
	// pretty or normalized version). The require closure of every selected
	// release is mirrored with it.
	Packages []string `json:"packages"`
	// NoDeps mirrors only the named releases, skipping the require closure.
	NoDeps bool `json:"no_deps,omitempty"`
	// Force disables export dedup for this collect: every zip is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseComposerSpec splits "vendor/project" or "vendor/project:1.2.3".
func parseComposerSpec(spec string) (name, version string, err error) {
	name, version, _ = strings.Cut(strings.TrimSpace(spec), ":")
	if err := validateComposerName(name); err != nil {
		return "", "", err
	}
	if version != "" {
		if err := validateComposerVersion(version); err != nil {
			return "", "", fmt.Errorf("package %s: %w", name, err)
		}
	}
	return name, version, nil
}

// validateComposerRequest checks the collect request before any network work.
func validateComposerRequest(req ComposerCollectRequest) error {
	if len(req.Packages) == 0 {
		return errors.New("no composer packages provided")
	}
	for _, spec := range req.Packages {
		if _, _, err := parseComposerSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// composerRepoBase resolves the configured Composer repository base URL.
func (s *LowServer) composerRepoBase() string {
	base := strings.TrimSuffix(strings.TrimSpace(s.cfg.ComposerRepoURL), "/")
	if base == "" {
		return defaultComposerRepoURL
	}
	return base
}

// HandleComposerCollect parses a JSON collect request from the admin endpoint
// and runs the collection.
func (s *LowServer) HandleComposerCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req ComposerCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse composer collect request: %w", err)
		}
	}
	return s.CollectComposer(ctx, req)
}

// CollectComposer resolves the requested packages (and, unless opted out,
// their require closure) against the configured Composer repository,
// downloads the dist zips, and writes them into a signed bundle on the
// composer stream. Packages that cannot be resolved or fetched are skipped
// and reported so one of them never blocks the rest of the batch.
func (s *LowServer) CollectComposer(ctx context.Context, req ComposerCollectRequest) (ExportResult, error) {
	if err := validateComposerRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the composer stream's lock for the whole fetch->write->commit
	// so a concurrent composer exporter cannot claim the same sequence number
	// between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamComposer)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "composer", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	dl := &composerDownloader{
		base:      s.composerRepoBase(),
		stageRoot: stageRoot,
		noDeps:    req.NoDeps,
		done:      map[string]bool{},
		tried:     map[string]bool{},
		meta:      map[string][]map[string]any{},
		metaErr:   map[string]error{},
	}
	dl.run(ctx, req.Packages)
	if len(dl.pkgs) == 0 {
		return ExportResult{}, fmt.Errorf("no composer packages could be fetched: %s", summarizeFailures(dl.failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(dl.files))

	res, err := s.exportIfNew(ctx, streamComposer, stageRoot, dl.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeComposerBundle(ctx, seq, stageRoot, dl.files, dl.pkgs)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = dl.failed
	return res, nil
}

// composerDownloader walks the require closure, downloading each release
// once.
type composerDownloader struct {
	base      string
	stageRoot string
	noDeps    bool
	pkgs      []ComposerPackage
	files     []ManifestFile
	failed    []FailedModule
	queue     []composerDep
	done      map[string]bool             // "name@version_normalized" downloaded
	tried     map[string]bool             // "name constraint" edges already resolved
	meta      map[string][]map[string]any // package -> expanded version objects
	metaErr   map[string]error            // package -> cached fetch failure
}

// composerDep is one require edge awaiting resolution.
type composerDep struct {
	name       string
	constraint string
}

// run resolves and downloads the requested specs and, unless the request
// opted out, their require closure (breadth-first, capped).
func (d *composerDownloader) run(ctx context.Context, specs []string) {
	for i, spec := range specs {
		name, version, _ := parseComposerSpec(spec)
		emitProgress(ctx, "→ [%d/%d] %s@%s", i+1, len(specs), name, orDefault(version, "latest"))
		d.collectRequested(ctx, name, version)
	}
	for len(d.queue) > 0 && len(d.done) < composerMaxResolved {
		dep := d.queue[0]
		d.queue = d.queue[1:]
		d.resolveDep(ctx, dep)
	}
}

// collectRequested resolves one requested spec to a release and fetches it.
func (d *composerDownloader) collectRequested(ctx context.Context, name, version string) {
	versions, err := d.metadata(ctx, name)
	var obj map[string]any
	if err == nil {
		obj, err = composerSelectRelease(versions, version)
	}
	if err != nil {
		d.fail(ctx, name, orDefault(version, "latest"), err)
		return
	}
	d.fetchRelease(ctx, name, obj)
}

// resolveDep resolves one require edge to the newest stable release
// satisfying its constraint and fetches it (with its own requires in turn).
func (d *composerDownloader) resolveDep(ctx context.Context, dep composerDep) {
	if err := validateComposerName(dep.name); err != nil {
		d.fail(ctx, dep.name, dep.constraint, err)
		return
	}
	versions, err := d.metadata(ctx, dep.name)
	var obj map[string]any
	if err == nil {
		obj, err = composerSelectDependency(versions, dep.constraint)
	}
	if err != nil {
		d.fail(ctx, dep.name, dep.constraint, err)
		return
	}
	if !d.done[dep.name+"@"+composerString(obj, "version_normalized")] {
		emitProgress(ctx, "→ %s@%s (dependency)", dep.name, composerString(obj, "version"))
		d.fetchRelease(ctx, dep.name, obj)
	}
}

// metadata fetches and caches one package's expanded upstream version list.
// Failures are cached too, so a package required by many others is requested
// only once.
func (d *composerDownloader) metadata(ctx context.Context, name string) ([]map[string]any, error) {
	if versions, ok := d.meta[name]; ok {
		return versions, d.metaErr[name]
	}
	versions, err := fetchComposerMetadata(ctx, d.base, name)
	d.meta[name] = versions
	if err != nil {
		d.metaErr[name] = err
	}
	return versions, err
}

// fetchRelease downloads one release's dist zip into the staging tree and
// records its manifest entry; the release's own requires are queued unless
// the collect asked for no dependencies.
func (d *composerDownloader) fetchRelease(ctx context.Context, name string, obj map[string]any) {
	version := composerString(obj, "version")
	vnorm := composerString(obj, "version_normalized")
	if err := composerCheckIdentity(name, obj); err != nil {
		d.fail(ctx, name, orDefault(version, "?"), err)
		return
	}
	if d.done[name+"@"+vnorm] {
		return
	}
	distURL, err := composerDistURL(obj)
	if err != nil {
		d.fail(ctx, name, version, err)
		return
	}
	rel := composerDistRel(name, vnorm)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	// Packagist dist entries carry an empty shasum, so there is nothing
	// upstream-declared to verify against: integrity rests on TLS to the
	// metadata-declared URL, the same policy as helm's digest-less path.
	sum, size, err := downloadFileSHA256(ctx, distURL, abs)
	if err != nil {
		d.fail(ctx, name, version, err)
		return
	}
	metadata, err := composerPruneMetadata(obj)
	if err != nil {
		d.fail(ctx, name, version, err)
		return
	}
	d.done[name+"@"+vnorm] = true
	d.pkgs = append(d.pkgs, ComposerPackage{
		Name: name, Version: version, VersionNormalized: vnorm,
		Path: rel, SHA256: sum, Metadata: metadata,
	})
	d.files = append(d.files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	if !d.noDeps {
		d.queueDeps(obj)
	}
}

// queueDeps queues a release's require entries for resolution. Platform
// packages describe the runtime and are skipped, as is any edge whose
// constraint names a dev version — the mirror serves tagged releases only.
func (d *composerDownloader) queueDeps(obj map[string]any) {
	req, _ := obj["require"].(map[string]any)
	names := make([]string, 0, len(req))
	for name := range req {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		constraint, _ := req[name].(string)
		if composerPlatformPackage(name) || strings.Contains(constraint, "dev") {
			continue
		}
		key := name + " " + constraint
		if d.tried[key] {
			continue
		}
		d.tried[key] = true
		d.queue = append(d.queue, composerDep{name: name, constraint: constraint})
	}
}

// fail records one skipped package so the batch reports it without aborting.
func (d *composerDownloader) fail(ctx context.Context, name, version string, err error) {
	emitProgress(ctx, "  ✗ %s@%s: %s", name, version, err)
	d.failed = append(d.failed, FailedModule{Module: name, Version: version, Error: err.Error()})
}

// composerCheckIdentity checks the upstream version object names the package
// being fetched, with path-safe version identifiers.
func composerCheckIdentity(name string, obj map[string]any) error {
	if got := composerString(obj, "name"); got != name {
		return fmt.Errorf("upstream metadata names %q", got)
	}
	if err := validateComposerVersion(composerString(obj, "version")); err != nil {
		return err
	}
	return validateComposerVersionNormalized(composerString(obj, "version_normalized"))
}

// composerDistURL extracts a release's dist download URL: http(s) zips only —
// the high side re-advertises every dist as a zip it serves itself, so any
// other dist type could not be consumed truthfully.
func composerDistURL(obj map[string]any) (string, error) {
	dist, _ := obj["dist"].(map[string]any)
	if dist == nil {
		return "", errors.New("release has no dist")
	}
	if typ, _ := dist["type"].(string); typ != "zip" {
		return "", fmt.Errorf("unsupported dist type %q", dist["type"])
	}
	raw, _ := dist["url"].(string)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("dist url %q is not http(s)", raw)
	}
	return raw, nil
}

// composerPruneMetadata renders the version object carried in the manifest:
// the expanded upstream object minus its dist and source sections. The high
// side re-adds a dist pointing at itself; a source section would leak
// internal git URLs and tempt clients to bypass the mirror.
func composerPruneMetadata(obj map[string]any) (json.RawMessage, error) {
	pruned := make(map[string]any, len(obj))
	for k, v := range obj {
		if k == "dist" || k == "source" {
			continue
		}
		pruned[k] = v
	}
	return json.Marshal(pruned)
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeComposerBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, pkgs []ComposerPackage) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].VersionNormalized < pkgs[j].VersionNormalized
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	id := bundleIDFor(streamComposer, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamComposer,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"composer"},
		Composer:         &ComposerManifest{Packages: pkgs},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamComposer, Sequence: seq, ExportedModules: len(pkgs), BundleID: id}, nil
}
