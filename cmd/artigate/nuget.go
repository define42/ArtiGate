package main

// NuGet ecosystem adapter. The low side resolves package ids against a NuGet
// v3 source (api.nuget.org by default), walks nuspec dependencies, downloads
// the .nupkg archives, and packs them into the same numbered, signed ArtiGate
// bundle format used by the other ecosystems. The high side serves a NuGet v3
// feed of its own — service index, flat container (package base address),
// registration pages, and a minimal search — regenerating all metadata from
// each package's embedded .nuspec at import time (never trusting a
// transferred metadata file). Clients add <base>/nuget/v3/index.json as a
// package source.

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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

// nugetEcosystem is the NuGet package stream's registry entry (see
// ecosystems in ecosystem.go).
func nugetEcosystem() ecosystem {
	return ecosystem{
		stream:       streamNuget,
		label:        "NuGet",
		title:        "NuGet packages",
		collect:      (*LowServer).HandleNugetCollect,
		watchCollect: watchAdapter((*LowServer).CollectNuget),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.NugetSource, "nuget-source", "", "NuGet v3 service index packages are resolved from (default "+defaultNugetSource+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.Nuget != nil && len(m.Nuget.Packages) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateNugetPackages(m.Nuget.Packages, seen)
		},
		contentDesc: "nuget packages",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishNuget(m.Nuget) },
		serve:       (*HighServer).serveNuget,
		scanTree:    flatTreeScan((*HighServer).listNugetPackages),
		detail:      (*HighServer).nugetDetail,
	}
}

const defaultNugetSource = "https://api.nuget.org/v3/index.json"

// nugetMaxNuspecBytes caps one .nuspec parsed from a package archive.
const nugetMaxNuspecBytes = 8 << 20

// nugetMaxResolved bounds a dependency resolution so a pathological graph
// cannot grow without limit.
const nugetMaxResolved = 4000

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type NugetManifest struct {
	Packages []NugetPackage `json:"packages"`
}

// NugetPackage records one mirrored package. ID keeps the upstream nuspec's
// canonical casing; Version is the normalized (SemVer2) form; Path uses the
// lowercase identity the v3 flat-container layout requires.
type NugetPackage struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// nugetIDRE matches a path-safe NuGet package id. The first character excludes
// ".", "_", and "-" so an id can never be ".."/"-flag".
var nugetIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// nugetVersionRE matches a normalized package version, which always starts
// with a digit, so it can never be ".."/"-flag" or contain a path separator.
var nugetVersionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

func validateNugetID(id string) error {
	if !nugetIDRE.MatchString(id) {
		return fmt.Errorf("invalid nuget package id %q", id)
	}
	return nil
}

func validateNugetVersion(v string) error {
	if !nugetVersionRE.MatchString(v) {
		return fmt.Errorf("invalid nuget version %q", v)
	}
	return nil
}

// nugetPackageRel is the repository-relative path of one package archive,
// following the flat-container layout ({id}/{version}/{id}.{version}.nupkg,
// all lowercase).
func nugetPackageRel(id, version string) string {
	idl, verl := strings.ToLower(id), strings.ToLower(version)
	return path.Join("nuget", "packages", idl, verl, idl+"."+verl+".nupkg")
}

// validateNugetPackages checks every package record of a bundle manifest.
func validateNugetPackages(pkgs []NugetPackage, seen map[string]bool) error {
	for _, p := range pkgs {
		if err := validateNugetID(p.ID); err != nil {
			return err
		}
		if err := validateNugetVersion(p.Version); err != nil {
			return fmt.Errorf("nuget package %s: %w", p.ID, err)
		}
		if p.Version != nugetNormalizeVersion(p.Version) {
			return fmt.Errorf("nuget package %s has non-normalized version %s", p.ID, p.Version)
		}
		if p.Path != nugetPackageRel(p.ID, p.Version) {
			return fmt.Errorf("nuget package %s@%s has non-canonical path %s", p.ID, p.Version, p.Path)
		}
		if !seen[p.Path] {
			return fmt.Errorf("nuget package %s@%s references file not listed in manifest.files: %s", p.ID, p.Version, p.Path)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Version normalization, comparison, ranges
// -----------------------------------------------------------------------------

// nugetVer is a parsed NuGet version: up to four numeric parts plus an
// optional pre-release tag. Build metadata is dropped, as NuGet normalization
// specifies.
type nugetVer struct {
	nums [4]int64
	pre  string
}

func parseNugetVer(v string) (nugetVer, error) {
	v, _, _ = strings.Cut(strings.TrimSpace(v), "+")
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nugetVer{}, fmt.Errorf("invalid nuget version %q", v)
	}
	var out nugetVer
	out.pre = pre
	for i, p := range parts {
		n, err := parseVersionInt(p)
		if err != nil {
			return nugetVer{}, fmt.Errorf("invalid nuget version %q", v)
		}
		out.nums[i] = n
	}
	return out, nil
}

// nugetNormalizeVersion renders the SemVer2-normalized form NuGet uses for
// identity: leading zeros removed, exactly three numeric parts (a non-zero
// fourth legacy part is kept), build metadata dropped. An unparsable version
// is returned unchanged (validation rejects it elsewhere).
func nugetNormalizeVersion(v string) string {
	p, err := parseNugetVer(v)
	if err != nil {
		return v
	}
	out := fmt.Sprintf("%d.%d.%d", p.nums[0], p.nums[1], p.nums[2])
	if p.nums[3] != 0 {
		out += fmt.Sprintf(".%d", p.nums[3])
	}
	if p.pre != "" {
		out += "-" + p.pre
	}
	return out
}

// compareNugetVer orders two parsed versions: numeric parts, then a release
// outranks any pre-release, then the semver pre-release ordering
// (case-insensitive, as NuGet compares).
func compareNugetVer(a, b nugetVer) int {
	for i := range a.nums {
		if c := cmpInt64(a.nums[i], b.nums[i]); c != 0 {
			return c
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	}
	return comparePrerelease(strings.ToLower(a.pre), strings.ToLower(b.pre))
}

// nugetRange is a parsed NuGet dependency version range.
type nugetRange struct {
	min, max       *nugetVer
	minInc, maxInc bool
}

// parseNugetRange parses the nuspec range forms: "1.0" (minimum, inclusive),
// "[1.0]" (exact), and the interval notation "[1.0,2.0)" with either bound
// optional. An empty range accepts anything.
func parseNugetRange(s string) (nugetRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nugetRange{}, nil
	}
	if !strings.HasPrefix(s, "[") && !strings.HasPrefix(s, "(") {
		v, err := parseNugetVer(s)
		if err != nil {
			return nugetRange{}, err
		}
		return nugetRange{min: &v, minInc: true}, nil
	}
	if len(s) < 3 || (!strings.HasSuffix(s, "]") && !strings.HasSuffix(s, ")")) {
		return nugetRange{}, fmt.Errorf("invalid version range %q", s)
	}
	r := nugetRange{minInc: s[0] == '[', maxInc: s[len(s)-1] == ']'}
	inner := s[1 : len(s)-1]
	lo, hi, found := strings.Cut(inner, ",")
	if !found { // "[1.0]" exact pin
		v, err := parseNugetVer(inner)
		if err != nil || !r.minInc || !r.maxInc {
			return nugetRange{}, fmt.Errorf("invalid version range %q", s)
		}
		return nugetRange{min: &v, max: &v, minInc: true, maxInc: true}, nil
	}
	if err := parseNugetBound(lo, &r.min); err != nil {
		return nugetRange{}, fmt.Errorf("invalid version range %q", s)
	}
	if err := parseNugetBound(hi, &r.max); err != nil {
		return nugetRange{}, fmt.Errorf("invalid version range %q", s)
	}
	return r, nil
}

func parseNugetBound(s string, out **nugetVer) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	v, err := parseNugetVer(s)
	if err != nil {
		return err
	}
	*out = &v
	return nil
}

func (r nugetRange) matches(v nugetVer) bool {
	if r.min != nil {
		if c := compareNugetVer(v, *r.min); c < 0 || (c == 0 && !r.minInc) {
			return false
		}
	}
	if r.max != nil {
		if c := compareNugetVer(v, *r.max); c > 0 || (c == 0 && !r.maxInc) {
			return false
		}
	}
	return true
}

// allowsPrerelease reports whether the range itself names a pre-release, which
// is what lets NuGet resolve pre-release dependency versions.
func (r nugetRange) allowsPrerelease() bool {
	return (r.min != nil && r.min.pre != "") || (r.max != nil && r.max.pre != "")
}

// -----------------------------------------------------------------------------
// High side: NuGet v3 feed
// -----------------------------------------------------------------------------

func (s *HighServer) nugetPackagesDir() string {
	return filepath.Join(s.downloadDir, "nuget", "packages")
}

func (s *HighServer) nugetMetadataDir() string {
	return filepath.Join(s.downloadDir, "nuget", "metadata")
}

// serveNuget handles the NuGet v3 routes under /nuget/: the service index,
// the flat container (versions list, .nupkg, .nuspec), registration pages,
// and a minimal search. It reports whether it wrote a response for the
// request.
func (s *HighServer) serveNuget(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/nuget" && !strings.HasPrefix(p, "/nuget/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.TrimPrefix(p, "/nuget")
	switch {
	case rest == "/v3/index.json":
		s.handleNugetServiceIndex(w, r)
	case strings.HasPrefix(rest, "/v3-flatcontainer/"):
		s.handleNugetFlat(w, r, strings.TrimPrefix(rest, "/v3-flatcontainer/"))
	case strings.HasPrefix(rest, "/v3/registration/"):
		s.handleNugetRegistration(w, r, strings.TrimPrefix(rest, "/v3/registration/"))
	case rest == "/v3/search":
		s.handleNugetSearch(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

func nugetResource(id, typ string) map[string]string {
	return map[string]string{"@id": id, "@type": typ}
}

func (s *HighServer) handleNugetServiceIndex(w http.ResponseWriter, r *http.Request) {
	base := npmBaseURL(r)
	resources := []map[string]string{
		nugetResource(base+"/nuget/v3-flatcontainer/", "PackageBaseAddress/3.0.0"),
		nugetResource(base+"/nuget/v3/registration/", "RegistrationsBaseUrl"),
		nugetResource(base+"/nuget/v3/registration/", "RegistrationsBaseUrl/3.4.0"),
		nugetResource(base+"/nuget/v3/registration/", "RegistrationsBaseUrl/3.6.0"),
		nugetResource(base+"/nuget/v3/search", "SearchQueryService"),
		nugetResource(base+"/nuget/v3/search", "SearchQueryService/3.0.0-rc"),
	}
	writeJSON(w, map[string]any{"version": "3.0.0", "resources": resources})
}

// handleNugetFlat serves the package base address routes:
// {id}/index.json, {id}/{ver}/{id}.{ver}.nupkg, and {id}/{ver}/{id}.nuspec.
func (s *HighServer) handleNugetFlat(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(strings.ToLower(rest), "/")
	switch {
	case len(segs) == 2 && segs[1] == "index.json" && validateNugetID(segs[0]) == nil:
		s.handleNugetVersionsList(w, segs[0])
	case len(segs) == 3 && validateNugetID(segs[0]) == nil && validateNugetVersion(segs[1]) == nil:
		s.handleNugetFlatFile(w, r, segs[0], segs[1], segs[2])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *HighServer) handleNugetVersionsList(w http.ResponseWriter, id string) {
	versions, err := s.nugetVersions(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(versions) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	lower := make([]string, len(versions))
	for i, v := range versions {
		lower[i] = strings.ToLower(v)
	}
	writeJSON(w, map[string]any{"versions": lower})
}

func (s *HighServer) handleNugetFlatFile(w http.ResponseWriter, r *http.Request, id, version, file string) {
	switch file {
	case id + "." + version + ".nupkg":
		abs := filepath.Join(s.downloadDir, filepath.FromSlash(nugetPackageRel(id, version)))
		if !safeJoin(s.nugetPackagesDir(), abs) {
			http.Error(w, "unsafe path", http.StatusBadRequest)
			return
		}
		serveFile(w, r, abs)
	case id + ".nuspec":
		abs := filepath.Join(s.nugetMetadataDir(), id, version+".nuspec")
		if !safeJoin(s.nugetMetadataDir(), abs) {
			http.Error(w, "unsafe path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		serveFile(w, r, abs)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// nugetVersions lists one package's mirrored versions (normalized, sorted
// ascending), only counting versions whose archive is present.
func (s *HighServer) nugetVersions(id string) ([]string, error) {
	dir := filepath.Join(s.nugetMetadataDir(), strings.ToLower(id))
	if !safeJoin(s.nugetMetadataDir(), dir) {
		return nil, errors.New("unsafe path")
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		version := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || version == e.Name() || validateNugetVersion(version) != nil {
			continue
		}
		if _, err := s.readNugetStored(id, version); err == nil {
			out = append(out, version)
		}
	}
	sort.Slice(out, func(i, j int) bool { return nugetVersionLess(out[i], out[j]) })
	return out, nil
}

func nugetVersionLess(a, b string) bool {
	av, aerr := parseNugetVer(a)
	bv, berr := parseNugetVer(b)
	if aerr != nil || berr != nil {
		return a < b
	}
	return compareNugetVer(av, bv) < 0
}

// nugetStoredManifest is the per-version metadata the high side regenerates at
// import time from the package's own embedded .nuspec.
type nugetStoredManifest struct {
	ID          string          `json:"id"`
	Version     string          `json:"version"`
	Description string          `json:"description,omitempty"`
	Authors     string          `json:"authors,omitempty"`
	Groups      []nugetDepGroup `json:"dependency_groups,omitempty"`
}

type nugetDepGroup struct {
	TargetFramework string        `json:"target_framework,omitempty"`
	Dependencies    []nugetDepRef `json:"dependencies,omitempty"`
}

type nugetDepRef struct {
	ID    string `json:"id"`
	Range string `json:"range,omitempty"`
}

// readNugetStored loads one version's regenerated metadata and checks its
// archive is still present (only complete versions are served).
func (s *HighServer) readNugetStored(id, version string) (nugetStoredManifest, error) {
	p := filepath.Join(s.nugetMetadataDir(), strings.ToLower(id), strings.ToLower(version)+".json")
	if !safeJoin(s.nugetMetadataDir(), p) {
		return nugetStoredManifest{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nugetStoredManifest{}, err
	}
	var st nugetStoredManifest
	if err := json.Unmarshal(b, &st); err != nil {
		return nugetStoredManifest{}, err
	}
	pkg := filepath.Join(s.downloadDir, filepath.FromSlash(nugetPackageRel(id, version)))
	if !safeJoin(s.nugetPackagesDir(), pkg) || !fileExists(pkg) {
		return nugetStoredManifest{}, fmt.Errorf("package missing for %s@%s", id, version)
	}
	return st, nil
}

// handleNugetRegistration dispatches the registration routes: the per-package
// index ({id}/index.json) and the per-version leaf ({id}/{version}.json) that
// the index items and the search results advertise as their "@id".
func (s *HighServer) handleNugetRegistration(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(strings.ToLower(rest), "/")
	if len(segs) != 2 || validateNugetID(segs[0]) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if segs[1] == "index.json" {
		s.handleNugetRegistrationIndex(w, r, segs[0])
		return
	}
	version, ok := strings.CutSuffix(segs[1], ".json")
	if !ok || validateNugetVersion(version) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.handleNugetRegistrationLeaf(w, r, segs[0], nugetNormalizeVersion(version))
}

// handleNugetRegistrationLeaf serves one version's registration leaf document:
// the same inlined catalog entry the index carries, plus the listed flag and
// the backlink to the registration index, as clients following a search
// result's versions[].@id expect.
func (s *HighServer) handleNugetRegistrationLeaf(w http.ResponseWriter, r *http.Request, id, version string) {
	leaf := s.nugetRegistrationLeaf(npmBaseURL(r), id, version)
	if leaf == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	leaf["listed"] = true
	leaf["registration"] = npmBaseURL(r) + "/nuget/v3/registration/" + id + "/index.json"
	writeJSON(w, leaf)
}

// handleNugetRegistrationIndex serves one package's registration index: a
// single inlined page whose leaves carry the catalog entry (identity,
// dependency groups) and the package content URL.
func (s *HighServer) handleNugetRegistrationIndex(w http.ResponseWriter, r *http.Request, id string) {
	versions, err := s.nugetVersions(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(versions) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	base := npmBaseURL(r)
	items := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		if leaf := s.nugetRegistrationLeaf(base, id, v); leaf != nil {
			items = append(items, leaf)
		}
	}
	if len(items) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	indexURL := base + "/nuget/v3/registration/" + id + "/index.json"
	page := map[string]any{
		"@id":   indexURL + "#page",
		"count": len(items),
		"lower": strings.ToLower(versions[0]),
		"upper": strings.ToLower(versions[len(versions)-1]),
		"items": items,
	}
	writeJSON(w, map[string]any{"@id": indexURL, "count": 1, "items": []any{page}})
}

// nugetRegistrationLeaf renders one registration page item from the stored
// metadata.
func (s *HighServer) nugetRegistrationLeaf(base, id, version string) map[string]any {
	st, err := s.readNugetStored(id, version)
	if err != nil {
		return nil
	}
	verl := strings.ToLower(version)
	content := base + "/nuget/v3-flatcontainer/" + id + "/" + verl + "/" + id + "." + verl + ".nupkg"
	groups := make([]map[string]any, 0, len(st.Groups))
	for _, g := range st.Groups {
		deps := make([]map[string]any, 0, len(g.Dependencies))
		for _, d := range g.Dependencies {
			deps = append(deps, map[string]any{"id": d.ID, "range": d.Range})
		}
		group := map[string]any{"dependencies": deps}
		if g.TargetFramework != "" {
			group["targetFramework"] = g.TargetFramework
		}
		groups = append(groups, group)
	}
	entry := map[string]any{
		"@id":              base + "/nuget/v3/registration/" + id + "/" + verl + ".json",
		"id":               st.ID,
		"version":          st.Version,
		"listed":           true,
		"packageContent":   content,
		"dependencyGroups": groups,
	}
	if st.Description != "" {
		entry["description"] = st.Description
	}
	if st.Authors != "" {
		entry["authors"] = st.Authors
	}
	return map[string]any{"@id": entry["@id"], "catalogEntry": entry, "packageContent": content}
}

const (
	// nugetSearchDefaultTake and nugetSearchMaxTake bound one search response.
	// The v3 search protocol pages with skip/take (nuget.org defaults take to
	// 20); before the window was enforced, a q-less unauthenticated request
	// listed every mirrored package — with its whole version list — in one
	// body, an I/O and response cost proportional to the mirror per hit.
	nugetSearchDefaultTake = 20
	nugetSearchMaxTake     = 100
)

// handleNugetSearch implements a minimal search over the mirrored packages: a
// case-insensitive substring match on the id, newest version listed first,
// paged by the protocol's skip/take. Ids are matched before any stored
// metadata is read — servability needs only directory scans and stats — and
// full metadata is loaded for the returned window alone, so a request's cost
// is bounded by the take cap rather than the mirror size.
func (s *HighServer) handleNugetSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	ids, err := s.listNugetIDs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	matched := make([]string, 0, len(ids))
	for _, id := range ids {
		if (q == "" || strings.Contains(id, q)) && s.nugetHasServableVersion(id) {
			matched = append(matched, id)
		}
	}
	base := npmBaseURL(r)
	data := []map[string]any{}
	for _, id := range nugetSearchPage(matched, r.URL.Query()) {
		if item := s.nugetSearchItem(base, id); item != nil {
			data = append(data, item)
		}
	}
	writeJSON(w, map[string]any{"totalHits": len(matched), "data": data})
}

// nugetHasServableVersion reports whether at least one of the package's
// stored versions still has its archive on disk — the same gate
// readNugetStored applies, minus reading any stored JSON, so counting every
// matching id per search request stays cheap. The window's items are still
// built through readNugetStored, which re-checks completeness per version.
func (s *HighServer) nugetHasServableVersion(id string) bool {
	dir := filepath.Join(s.nugetMetadataDir(), id)
	if !safeJoin(s.nugetMetadataDir(), dir) {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		version := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || version == e.Name() || validateNugetVersion(version) != nil {
			continue
		}
		pkg := filepath.Join(s.downloadDir, filepath.FromSlash(nugetPackageRel(id, version)))
		if safeJoin(s.nugetPackagesDir(), pkg) && fileExists(pkg) {
			return true
		}
	}
	return false
}

// nugetSearchPage applies the request's skip/take window to the matched ids.
func nugetSearchPage(ids []string, query url.Values) []string {
	skip := nugetSearchParam(query.Get("skip"), 0, len(ids))
	take := nugetSearchParam(query.Get("take"), nugetSearchDefaultTake, nugetSearchMaxTake)
	ids = ids[skip:]
	if take < len(ids) {
		ids = ids[:take]
	}
	return ids
}

// nugetSearchParam parses one non-negative paging parameter, falling back to
// fallback when absent, malformed, or negative, and clamping to limit.
func nugetSearchParam(raw string, fallback, limit int) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		n = fallback
	}
	return min(n, limit)
}

func (s *HighServer) nugetSearchItem(base, id string) map[string]any {
	versions, err := s.nugetVersions(id)
	if err != nil || len(versions) == 0 {
		return nil
	}
	latest := versions[len(versions)-1]
	st, err := s.readNugetStored(id, latest)
	if err != nil {
		return nil
	}
	vlist := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		vlist = append(vlist, map[string]any{
			"version": strings.ToLower(v),
			"@id":     base + "/nuget/v3/registration/" + id + "/" + strings.ToLower(v) + ".json",
		})
	}
	item := map[string]any{
		"@type":        "Package",
		"registration": base + "/nuget/v3/registration/" + id + "/index.json",
		"id":           st.ID,
		"version":      st.Version,
		"versions":     vlist,
	}
	if st.Description != "" {
		item["description"] = st.Description
	}
	return item
}

// listNugetIDs lists every mirrored package id (lowercase directory names of
// the metadata tree).
func (s *HighServer) listNugetIDs() ([]string, error) {
	entries, err := os.ReadDir(s.nugetMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && validateNugetID(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listNugetPackages groups the mirrored packages by id with their versions,
// from the regenerated metadata tree.
func (s *HighServer) listNugetPackages() ([]UIModule, error) {
	ids, err := s.listNugetIDs()
	if err != nil {
		return nil, err
	}
	out := make([]UIModule, 0, len(ids))
	for _, id := range ids {
		versions, err := s.nugetVersions(id)
		if err != nil || len(versions) == 0 {
			continue
		}
		label := id
		if st, err := s.readNugetStored(id, versions[len(versions)-1]); err == nil && st.ID != "" {
			label = st.ID
		}
		out = append(out, UIModule{Module: label, Versions: versions})
	}
	return out, nil
}

// nugetDetail describes one mirrored package version for the dashboard detail
// panel. spec is "<id>@<version>".
func (s *HighServer) nugetDetail(spec string) (UIDetail, error) {
	id, version, ok := strings.Cut(spec, "@")
	if !ok || validateNugetID(id) != nil || validateNugetVersion(version) != nil {
		return UIDetail{}, errors.New("invalid package@version")
	}
	st, err := s.readNugetStored(id, version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Package", Value: st.ID, Mono: true},
		{Label: "Version", Value: st.Version, Mono: true},
	}
	if st.Description != "" {
		fields = append(fields, UIDetailField{Label: "Description", Value: st.Description})
	}
	if st.Authors != "" {
		fields = append(fields, UIDetailField{Label: "Authors", Value: st.Authors})
	}
	deps := 0
	for _, g := range st.Groups {
		deps += len(g.Dependencies)
	}
	if deps > 0 {
		fields = append(fields, UIDetailField{Label: "Dependencies", Value: fmt.Sprintf("%d", deps)})
	}
	rel := nugetPackageRel(id, version)
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(rel))
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Package size", Value: formatBytes(fi.Size())})
	}
	if sum, err := s.detailDigests.get(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	idl, verl := strings.ToLower(id), strings.ToLower(version)
	dl := "/nuget/v3-flatcontainer/" + idl + "/" + verl + "/" + idl + "." + verl + ".nupkg"
	fields = append(fields, UIDetailField{Label: "Feed path", Value: dl, Mono: true})
	downloads := []UIDownload{{Label: idl + "." + verl + ".nupkg", URL: dl}}
	return UIDetail{Title: st.ID, Subtitle: st.Version, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// publishNuget regenerates the served per-version metadata for every package
// in an imported bundle from the archive's own embedded .nuspec. A package
// whose archive cannot be parsed is logged and skipped (its version 404s)
// rather than wedging the stream's import forever.
// publishNuget regenerates the served NuGet metadata from each package's own
// embedded .nuspec (never trusting transferred metadata).
func (s *HighServer) publishNuget(m *NugetManifest) error {
	if m == nil {
		return nil
	}
	for _, p := range m.Packages {
		if err := s.publishNugetPackage(p); err != nil {
			log.Printf("nuget publish %s@%s: %v", p.ID, p.Version, err)
		}
	}
	return nil
}

func (s *HighServer) publishNugetPackage(p NugetPackage) error {
	if err := validateNugetID(p.ID); err != nil {
		return err
	}
	if err := validateNugetVersion(p.Version); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(p.Path))
	if !strings.HasPrefix(p.Path, "nuget/packages/") || !safeJoin(s.nugetPackagesDir(), abs) {
		return fmt.Errorf("unsafe package path %s", p.Path)
	}
	raw, spec, err := extractNuspec(abs)
	if err != nil {
		return err
	}
	if !strings.EqualFold(spec.Metadata.ID, p.ID) {
		return fmt.Errorf("embedded nuspec names %q", spec.Metadata.ID)
	}
	if nugetNormalizeVersion(spec.Metadata.Version) != p.Version {
		return fmt.Errorf("embedded nuspec version is %q", spec.Metadata.Version)
	}
	idl, verl := strings.ToLower(p.ID), strings.ToLower(p.Version)
	st := nugetStoredManifest{
		ID: spec.Metadata.ID, Version: p.Version,
		Description: spec.Metadata.Description, Authors: spec.Metadata.Authors,
		Groups: nuspecDepGroups(spec),
	}
	out := filepath.Join(s.nugetMetadataDir(), idl, verl+".json")
	if !safeJoin(s.nugetMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s@%s", p.ID, p.Version)
	}
	if err := writeJSONAtomic(out, st, 0o644); err != nil {
		return err
	}
	return writeBytesAtomic(filepath.Join(s.nugetMetadataDir(), idl, verl+".nuspec"), raw, 0o644)
}

// -----------------------------------------------------------------------------
// nuspec parsing
// -----------------------------------------------------------------------------

type nuspecXML struct {
	Metadata struct {
		ID           string `xml:"id"`
		Version      string `xml:"version"`
		Description  string `xml:"description"`
		Authors      string `xml:"authors"`
		Dependencies struct {
			Groups       []nuspecGroup `xml:"group"`
			Dependencies []nuspecDep   `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"metadata"`
}

type nuspecGroup struct {
	TargetFramework string      `xml:"targetFramework,attr"`
	Dependencies    []nuspecDep `xml:"dependency"`
}

type nuspecDep struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// extractNuspec reads the .nuspec embedded at the root of a .nupkg (a zip).
func extractNuspec(nupkgPath string) ([]byte, *nuspecXML, error) {
	zr, err := zip.OpenReader(nupkgPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open nupkg: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.ContainsRune(f.Name, '/') || !strings.HasSuffix(strings.ToLower(f.Name), ".nuspec") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(rc, nugetMaxNuspecBytes))
		_ = rc.Close()
		if err != nil {
			return nil, nil, err
		}
		spec, err := parseNuspec(raw)
		if err != nil {
			return nil, nil, err
		}
		return raw, spec, nil
	}
	return nil, nil, errors.New("nupkg has no root-level .nuspec")
}

func parseNuspec(raw []byte) (*nuspecXML, error) {
	var spec nuspecXML
	if err := xml.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("parse nuspec: %w", err)
	}
	if spec.Metadata.ID == "" || spec.Metadata.Version == "" {
		return nil, errors.New("nuspec is missing id or version")
	}
	return &spec, nil
}

// nuspecDepGroups renders a nuspec's dependency section (grouped or legacy
// flat) into the stored form.
func nuspecDepGroups(spec *nuspecXML) []nugetDepGroup {
	var out []nugetDepGroup
	appendGroup := func(tf string, deps []nuspecDep) {
		g := nugetDepGroup{TargetFramework: tf}
		for _, d := range deps {
			if validateNugetID(d.ID) != nil {
				continue
			}
			g.Dependencies = append(g.Dependencies, nugetDepRef{ID: d.ID, Range: strings.TrimSpace(d.Version)})
		}
		out = append(out, g)
	}
	if len(spec.Metadata.Dependencies.Dependencies) > 0 {
		appendGroup("", spec.Metadata.Dependencies.Dependencies)
	}
	for _, g := range spec.Metadata.Dependencies.Groups {
		appendGroup(g.TargetFramework, g.Dependencies)
	}
	return out
}

// -----------------------------------------------------------------------------
// Low side: resolver/collector
// -----------------------------------------------------------------------------

// NugetCollectRequest is the body of POST /admin/nuget/collect.
//
// Packages is a list of specs ("Newtonsoft.Json" for the newest stable
// release, "Newtonsoft.Json@13.0.3" to pin). By default the transitive
// dependency graph from each package's nuspec is resolved (lowest applicable
// version, like NuGet restore) and bundled too; ResolveDeps=false mirrors
// only the listed packages.
type NugetCollectRequest struct {
	Packages    []string `json:"packages"`
	ResolveDeps *bool    `json:"resolve_deps,omitempty"`
	// Force disables export dedup for this collect: every package is packed
	// even when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseNugetSpec splits "id" or "id@version".
func parseNugetSpec(spec string) (id, version string, err error) {
	id, version, _ = strings.Cut(spec, "@")
	if err := validateNugetID(id); err != nil {
		return "", "", err
	}
	if version != "" && version != "latest" {
		if err := validateNugetVersion(version); err != nil {
			return "", "", fmt.Errorf("package %s: %w", id, err)
		}
		return id, nugetNormalizeVersion(version), nil
	}
	return id, "", nil
}

func validateNugetRequest(req NugetCollectRequest) error {
	if len(req.Packages) == 0 {
		return errors.New("no nuget packages provided")
	}
	for _, spec := range req.Packages {
		if _, _, err := parseNugetSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// HandleNugetCollect parses a JSON collect request from the admin endpoint
// and runs the collection.
func (s *LowServer) HandleNugetCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req NugetCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse nuget collect request: %w", err)
		}
	}
	return s.CollectNuget(ctx, req)
}

func (s *LowServer) nugetSource() string {
	if s.cfg.NugetSource != "" {
		return s.cfg.NugetSource
	}
	return defaultNugetSource
}

// CollectNuget resolves the requested packages (and by default their
// dependency graph) against the configured v3 source, downloads every .nupkg,
// and writes them into a signed bundle on the nuget stream. Packages that
// cannot be resolved or fetched are skipped and reported so one of them never
// blocks the rest of the batch.
func (s *LowServer) CollectNuget(ctx context.Context, req NugetCollectRequest) (ExportResult, error) {
	if err := validateNugetRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the nuget stream's lock for the whole resolve->download->
	// write->commit so a concurrent nuget exporter cannot claim the same
	// sequence number between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamNuget)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "nuget", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	emitProgress(ctx, "Resolving %d package(s) against %s…", len(req.Packages), s.nugetSource())
	res := newNugetResolver(s, req, stageRoot)
	pkgs, files, failed := res.resolve(ctx, req.Packages)
	if len(pkgs) == 0 {
		return ExportResult{}, fmt.Errorf("no nuget packages could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	out, err := s.exportIfNew(ctx, streamNuget, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeNugetBundle(ctx, seq, stageRoot, files, pkgs)
	})
	if err != nil {
		return ExportResult{}, err
	}
	out.SkippedModules = failed
	return out, nil
}

// nugetResolver walks the flat container, downloading packages and following
// their nuspec dependencies breadth-first.
type nugetResolver struct {
	s           *LowServer
	stageRoot   string
	flatBase    string // PackageBaseAddress resource, trailing slash trimmed
	regBase     string // RegistrationsBaseUrl resource ("" when the feed has none)
	resolveDeps bool
	versions    map[string][]string // lowercase id -> normalized versions (ascending)
	picked      map[string]bool     // lowercase id@version already downloaded
	satisfiedBy map[string][]nugetVer
}

func newNugetResolver(s *LowServer, req NugetCollectRequest, stageRoot string) *nugetResolver {
	return &nugetResolver{
		s:           s,
		stageRoot:   stageRoot,
		resolveDeps: req.ResolveDeps == nil || *req.ResolveDeps,
		versions:    map[string][]string{},
		picked:      map[string]bool{},
		satisfiedBy: map[string][]nugetVer{},
	}
}

// nugetWant is one resolution demand: an id pinned to an exact version, a
// dependency range, or the newest release.
type nugetWant struct {
	id    string
	exact string
	rng   string
}

func (w nugetWant) describe() string {
	switch {
	case w.exact != "":
		return w.exact
	case w.rng != "":
		return w.rng
	}
	return "latest"
}

// resolve downloads the requested packages and their dependency closure.
func (r *nugetResolver) resolve(ctx context.Context, specs []string) ([]NugetPackage, []ManifestFile, []FailedModule) {
	var failed []FailedModule
	if err := r.loadServiceIndex(ctx); err != nil {
		return nil, nil, []FailedModule{{Module: "service index", Error: err.Error()}}
	}
	queue := make([]nugetWant, 0, len(specs))
	for _, spec := range specs {
		id, version, _ := parseNugetSpec(spec)
		queue = append(queue, nugetWant{id: id, exact: version})
	}
	var pkgs []NugetPackage
	var files []ManifestFile
	for len(queue) > 0 && len(pkgs) < nugetMaxResolved {
		want := queue[0]
		queue = queue[1:]
		pkg, mf, deps, err := r.fetchOne(ctx, want)
		if err != nil {
			failed = append(failed, FailedModule{Module: want.id, Version: want.describe(), Error: err.Error()})
			continue
		}
		if pkg == nil {
			continue // already satisfied
		}
		pkgs = append(pkgs, *pkg)
		files = append(files, *mf)
		queue = append(queue, deps...)
	}
	return pkgs, files, failed
}

// nugetResourceURLOK reports whether a service-index resource URL is usable
// as a fetch base: an absolute http(s) URL with a host and no embedded login
// (resource URLs are echoed in progress and error text, so a credential
// there would leak — including across the diode in failure reports).
func nugetResourceURLOK(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

// loadServiceIndex reads the v3 service index and locates the flat-container
// base URL packages are fetched from, plus the registration base their
// upstream digests are looked up under (feeds without one skip digest
// pinning). The first usable resource of each type wins.
func (r *nugetResolver) loadServiceIndex(ctx context.Context) error {
	b, err := httpGetBytes(ctx, r.s.nugetSource(), 4<<20)
	if err != nil {
		return err
	}
	var idx struct {
		Resources []struct {
			ID   string `json:"@id"`
			Type string `json:"@type"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return fmt.Errorf("parse service index: %w", err)
	}
	for _, res := range idx.Resources {
		switch res.Type {
		case "PackageBaseAddress/3.0.0":
			if r.flatBase == "" && nugetResourceURLOK(res.ID) {
				r.flatBase = strings.TrimSuffix(res.ID, "/")
			}
		case "RegistrationsBaseUrl", "RegistrationsBaseUrl/3.4.0", "RegistrationsBaseUrl/3.6.0":
			if r.regBase == "" && nugetResourceURLOK(res.ID) {
				r.regBase = strings.TrimSuffix(res.ID, "/")
			}
		}
	}
	if r.flatBase == "" {
		return errors.New("service index has no PackageBaseAddress/3.0.0 resource")
	}
	return nil
}

// idVersions lists a package's published versions (normalized, ascending),
// cached per collect.
func (r *nugetResolver) idVersions(ctx context.Context, id string) ([]string, error) {
	idl := strings.ToLower(id)
	if got, ok := r.versions[idl]; ok {
		return got, nil
	}
	b, err := httpGetBytes(ctx, r.flatBase+"/"+idl+"/index.json", 16<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse versions list: %w", err)
	}
	out := make([]string, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		n := nugetNormalizeVersion(v)
		if validateNugetVersion(n) == nil {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return nugetVersionLess(out[i], out[j]) })
	r.versions[idl] = out
	return out, nil
}

// fetchOne resolves one want to a concrete version, downloads it, and returns
// its dependency wants. A nil package with nil error means the want was
// already satisfied.
func (r *nugetResolver) fetchOne(ctx context.Context, want nugetWant) (*NugetPackage, *ManifestFile, []nugetWant, error) {
	version, err := r.selectVersion(ctx, want)
	if err != nil {
		return nil, nil, nil, err
	}
	if version == "" {
		return nil, nil, nil, nil
	}
	key := strings.ToLower(want.id) + "@" + strings.ToLower(version)
	if r.picked[key] {
		return nil, nil, nil, nil
	}
	r.picked[key] = true
	emitProgress(ctx, "→ %s@%s", want.id, version)
	pkg, mf, deps, err := r.downloadPackage(ctx, want.id, version)
	if err != nil {
		emitProgress(ctx, "  ✗ %s@%s: %s", want.id, version, err)
		return nil, nil, nil, err
	}
	if v, perr := parseNugetVer(version); perr == nil {
		idl := strings.ToLower(pkg.ID)
		r.satisfiedBy[idl] = append(r.satisfiedBy[idl], v)
	}
	return pkg, mf, deps, nil
}

// selectVersion picks the version one want resolves to; "" means an already
// selected version satisfies the range.
func (r *nugetResolver) selectVersion(ctx context.Context, want nugetWant) (string, error) {
	if want.exact != "" {
		versions, err := r.idVersions(ctx, want.id)
		if err != nil {
			return "", err
		}
		for _, v := range versions {
			if strings.EqualFold(v, want.exact) {
				return v, nil
			}
		}
		return "", fmt.Errorf("version %s not found upstream", want.exact)
	}
	rng, err := parseNugetRange(want.rng)
	if err != nil {
		return "", err
	}
	if want.rng != "" && r.rangeSatisfied(want.id, rng) {
		return "", nil
	}
	versions, err := r.idVersions(ctx, want.id)
	if err != nil {
		return "", err
	}
	if want.rng == "" {
		return pickNugetLatest(versions)
	}
	return pickNugetMinimum(versions, rng)
}

func (r *nugetResolver) rangeSatisfied(id string, rng nugetRange) bool {
	for _, v := range r.satisfiedBy[strings.ToLower(id)] {
		if rng.matches(v) {
			return true
		}
	}
	return false
}

// pickNugetLatest returns the highest stable version, falling back to the
// highest pre-release.
func pickNugetLatest(versions []string) (string, error) {
	for i := len(versions) - 1; i >= 0; i-- {
		if v, err := parseNugetVer(versions[i]); err == nil && v.pre == "" {
			return versions[i], nil
		}
	}
	if len(versions) > 0 {
		return versions[len(versions)-1], nil
	}
	return "", errors.New("no versions published upstream")
}

// pickNugetMinimum returns the lowest version satisfying the range — NuGet's
// dependency resolution rule — preferring stable versions unless the range
// itself names a pre-release.
func pickNugetMinimum(versions []string, rng nugetRange) (string, error) {
	pick := func(includePre bool) string {
		for _, s := range versions {
			v, err := parseNugetVer(s)
			if err != nil || (!includePre && v.pre != "") {
				continue
			}
			if rng.matches(v) {
				return s
			}
		}
		return ""
	}
	if v := pick(rng.allowsPrerelease()); v != "" {
		return v, nil
	}
	if v := pick(true); v != "" {
		return v, nil
	}
	return "", errors.New("no published version satisfies the dependency range")
}

// nugetCatalogEntry is the subset of a catalog/registration entry that pins
// a package's bytes.
type nugetCatalogEntry struct {
	PackageHash          string `json:"packageHash"`
	PackageHashAlgorithm string `json:"packageHashAlgorithm"`
}

// upstreamDigest looks up the upstream-published digest of one package: the
// version's registration leaf carries a catalogEntry — inlined, or as the
// URL of the catalog document — whose packageHash pins the .nupkg bytes. It
// returns ("", "") when the feed publishes none, leaving integrity on TLS
// like the other index-less fetches; a published digest that then mismatches
// fails the download.
func (r *nugetResolver) upstreamDigest(ctx context.Context, idl, verl string) (checksumType, digest string) {
	if r.regBase == "" {
		return "", ""
	}
	b, err := httpGetBytes(ctx, r.regBase+"/"+idl+"/"+verl+".json", 4<<20)
	if err != nil {
		return "", ""
	}
	var leaf struct {
		CatalogEntry json.RawMessage `json:"catalogEntry"`
	}
	if err := json.Unmarshal(b, &leaf); err != nil {
		return "", ""
	}
	entry, ok := fetchNugetCatalogEntry(ctx, leaf.CatalogEntry)
	if !ok {
		return "", ""
	}
	return nugetEntryDigest(entry)
}

// fetchNugetCatalogEntry resolves a registration leaf's catalogEntry field:
// the entry object inlined, or the URL of the catalog document to fetch.
func fetchNugetCatalogEntry(ctx context.Context, raw json.RawMessage) (nugetCatalogEntry, bool) {
	var entry nugetCatalogEntry
	if json.Unmarshal(raw, &entry) == nil && entry.PackageHash != "" {
		return entry, true
	}
	var catalogURL string
	if json.Unmarshal(raw, &catalogURL) != nil || !nugetResourceURLOK(catalogURL) {
		return nugetCatalogEntry{}, false
	}
	b, err := httpGetBytes(ctx, catalogURL, 4<<20)
	if err != nil {
		return nugetCatalogEntry{}, false
	}
	if json.Unmarshal(b, &entry) != nil || entry.PackageHash == "" {
		return nugetCatalogEntry{}, false
	}
	return entry, true
}

// nugetEntryDigest converts a catalog entry's base64 packageHash into the
// (checksumType, hex digest) pair downloadVerifiedFile takes. An algorithm
// the mirror does not know — or a hash of the wrong length — reports no
// digest rather than failing the package.
func nugetEntryDigest(entry nugetCatalogEntry) (checksumType, digest string) {
	sizes := map[string]int{"sha512": sha512.Size, "sha256": sha256.Size}
	algo := strings.ToLower(strings.TrimSpace(entry.PackageHashAlgorithm))
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.PackageHash))
	if err != nil || len(raw) == 0 || len(raw) != sizes[algo] {
		return "", ""
	}
	return algo, hex.EncodeToString(raw)
}

// downloadPackage fetches one .nupkg into the staging tree, validates its
// embedded nuspec against the requested identity, and returns the dependency
// wants its nuspec declares. The archive is verified against the upstream
// catalog digest when the feed publishes one (nuget.org always does); the
// flat container itself publishes no digests, so without a registration
// entry integrity rests on TLS to the configured source. The embedded nuspec
// check keeps a mixed-up upstream response out of the bundle either way.
func (r *nugetResolver) downloadPackage(ctx context.Context, id, version string) (*NugetPackage, *ManifestFile, []nugetWant, error) {
	idl, verl := strings.ToLower(id), strings.ToLower(version)
	rel := nugetPackageRel(id, version)
	abs := filepath.Join(r.stageRoot, filepath.FromSlash(rel))
	dlURL := r.flatBase + "/" + idl + "/" + verl + "/" + idl + "." + verl + ".nupkg"
	var sum string
	var size int64
	var err error
	if checksumType, digest := r.upstreamDigest(ctx, idl, verl); digest != "" {
		sum, size, err = downloadVerifiedFile(ctx, dlURL, abs, 0, checksumType, digest)
	} else {
		sum, size, err = downloadFileSHA256(ctx, dlURL, abs)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	_, spec, err := extractNuspec(abs)
	if err != nil {
		return nil, nil, nil, err
	}
	if !strings.EqualFold(spec.Metadata.ID, id) || nugetNormalizeVersion(spec.Metadata.Version) != version {
		return nil, nil, nil, fmt.Errorf("downloaded package identifies as %s@%s", spec.Metadata.ID, spec.Metadata.Version)
	}
	pkg := &NugetPackage{ID: spec.Metadata.ID, Version: version, Path: rel, SHA256: sum}
	mf := &ManifestFile{Path: rel, SHA256: sum, Size: size}
	return pkg, mf, r.depWants(spec), nil
}

// depWants expands a nuspec's dependency groups into new wants, deduplicated
// by id and range across target frameworks.
func (r *nugetResolver) depWants(spec *nuspecXML) []nugetWant {
	if !r.resolveDeps {
		return nil
	}
	seen := map[string]bool{}
	var out []nugetWant
	for _, g := range nuspecDepGroups(spec) {
		for _, d := range g.Dependencies {
			key := strings.ToLower(d.ID) + "|" + d.Range
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, nugetWant{id: d.ID, rng: d.Range})
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeNugetBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, pkgs []NugetPackage) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].ID == pkgs[j].ID {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].ID < pkgs[j].ID
	})
	id := bundleIDFor(streamNuget, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamNuget,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"nuget"},
		Nuget:            &NugetManifest{Packages: pkgs},
		Files:            files,
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamNuget, Sequence: seq, ExportedModules: len(pkgs), BundleID: id}, nil
}
