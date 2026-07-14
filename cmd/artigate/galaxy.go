package main

// Ansible Galaxy collection ecosystem adapter. The low side resolves the
// requested collections — and, unless disabled, the dependency closure their
// metadata declares — against a Galaxy server's v3 API, downloads the
// collection artifacts verifying the API-declared SHA-256 and size, and packs
// them into the same numbered, signed ArtiGate bundle format used by the
// other ecosystems. The high side regenerates a Galaxy v3 API of its own from
// each artifact's embedded MANIFEST.json (never trusting transferred
// metadata) and serves it with the artifacts, so
// `ansible-galaxy collection install -s <base>/galaxy/` works.

import (
	"archive/tar"
	"compress/gzip"
	"context"
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

// galaxyEcosystem is the Ansible Galaxy collection stream's registry entry
// (see ecosystems in ecosystem.go).
func galaxyEcosystem() ecosystem {
	return ecosystem{
		stream:       streamGalaxy,
		label:        "Ansible",
		title:        "Ansible collections",
		collect:      (*LowServer).HandleGalaxyCollect,
		watchCollect: watchAdapter((*LowServer).CollectGalaxy),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.GalaxyServerURL, "galaxy-server", "", "Galaxy server Ansible collections are fetched from (default "+defaultGalaxyServerURL+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.Galaxy != nil && len(m.Galaxy.Collections) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateGalaxyCollections(m.Galaxy.Collections, seen)
		},
		contentDesc: "ansible collections",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishGalaxy(m.Galaxy) },
		serve:       (*HighServer).serveGalaxy,
		scanTree:    segmentTreeScan((*HighServer).listGalaxyCollections),
		detail:      (*HighServer).galaxyDetail,
	}
}

// defaultGalaxyServerURL is the Galaxy server collections are fetched from
// when no --galaxy-server override is configured.
const defaultGalaxyServerURL = "https://galaxy.ansible.com"

// galaxyMaxResolved bounds a dependency closure so a pathological dependency
// graph cannot grow a request without limit.
const galaxyMaxResolved = 500

// galaxyMaxVersionPages caps how many pages of a collection's version list
// are followed during constraint resolution.
const galaxyMaxVersionPages = 20

// galaxyMaxManifestBytes caps one MANIFEST.json parsed from a collection
// archive.
const galaxyMaxManifestBytes = 4 << 20

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type GalaxyManifest struct {
	Collections []GalaxyCollection `json:"collections"`
}

// GalaxyCollection records one mirrored collection version (.tar.gz artifact).
type GalaxyCollection struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// galaxyNameRE matches a collection namespace or name: Galaxy's rule is
// lowercase letters, digits, and underscores, never starting with an
// underscore — which also makes both path-safe.
var galaxyNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)

// galaxyVersionRE matches a collection version: strict-ish semver (Galaxy
// requires major.minor.patch, with optional prerelease/build suffixes). It
// always starts with a digit and excludes "/", so it is path-safe.
var galaxyVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.+-]*)?$`)

// validateGalaxyName checks one collection namespace or name against
// Galaxy's naming rule.
func validateGalaxyName(name string) error {
	if !galaxyNameRE.MatchString(name) {
		return fmt.Errorf("invalid collection namespace or name %q", name)
	}
	return nil
}

// validateGalaxyVersion checks one collection version string.
func validateGalaxyVersion(v string) error {
	if !galaxyVersionRE.MatchString(v) {
		return fmt.Errorf("invalid collection version %q", v)
	}
	return nil
}

// validateGalaxyIdentity checks a namespace/name/version triple in one go.
func validateGalaxyIdentity(namespace, name, version string) error {
	if err := validateGalaxyName(namespace); err != nil {
		return err
	}
	if err := validateGalaxyName(name); err != nil {
		return err
	}
	return validateGalaxyVersion(version)
}

// galaxyFilename is the canonical artifact name of a collection version,
// exactly what ansible-galaxy publishes and Galaxy serves.
func galaxyFilename(namespace, name, version string) string {
	return namespace + "-" + name + "-" + version + ".tar.gz"
}

// galaxyFileRel is the repository-relative path of one collection artifact.
func galaxyFileRel(namespace, name, filename string) string {
	return path.Join("galaxy", "collections", namespace, name, filename)
}

// galaxyParseArtifactFilename splits "<namespace>-<name>-<version>.tar.gz".
// Namespaces and names never contain "-", so the first two dashes are the
// separators (versions may carry more, e.g. a prerelease suffix).
func galaxyParseArtifactFilename(file string) (namespace, name, version string, ok bool) {
	stem, found := strings.CutSuffix(file, ".tar.gz")
	if !found {
		return "", "", "", false
	}
	namespace, rest, ok1 := strings.Cut(stem, "-")
	name, version, ok2 := strings.Cut(rest, "-")
	if !ok1 || !ok2 || validateGalaxyIdentity(namespace, name, version) != nil {
		return "", "", "", false
	}
	return namespace, name, version, true
}

// validateGalaxyCollections checks every collection record of a bundle
// manifest: path-safe identity, the canonical filename and storage path, and
// that the referenced file is listed in the manifest's file set.
func validateGalaxyCollections(cols []GalaxyCollection, seen map[string]bool) error {
	for _, c := range cols {
		if err := validateGalaxyIdentity(c.Namespace, c.Name, c.Version); err != nil {
			return err
		}
		addr := c.Namespace + "." + c.Name
		if c.Filename != galaxyFilename(c.Namespace, c.Name, c.Version) {
			return fmt.Errorf("collection %s@%s has non-canonical filename %s", addr, c.Version, c.Filename)
		}
		if c.Path != galaxyFileRel(c.Namespace, c.Name, c.Filename) || !seen[c.Path] {
			return fmt.Errorf("collection %s@%s references file not listed in manifest.files: %s", addr, c.Version, c.Path)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Semver constraints (the dependency spec language ansible-galaxy uses)
// -----------------------------------------------------------------------------

// galaxyParseVersion parses a collection version into the shared semver
// parts, ignoring build metadata like semver precedence does.
func galaxyParseVersion(v string) parsedSemver {
	core, _, _ := strings.Cut(v, "+")
	return parseSemver("v" + core)
}

// galaxyCompareParsed orders two parsed collection versions by semver
// precedence (a prerelease sorts before its release).
func galaxyCompareParsed(a, b parsedSemver) int {
	for _, pair := range [][2]int64{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
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
	return comparePrerelease(a.pre, b.pre)
}

// galaxyVersionLess orders two collection version strings; versions that do
// not parse as semver sort first.
func galaxyVersionLess(a, b string) bool {
	pa, pb := galaxyParseVersion(a), galaxyParseVersion(b)
	switch {
	case pa.ok && pb.ok:
		return galaxyCompareParsed(pa, pb) < 0
	case pa.ok != pb.ok:
		return !pa.ok
	default:
		return a < b
	}
}

// galaxyConstraintVersionRE captures a constraint clause's version: one to
// three numeric parts, an optional prerelease, and optional build metadata
// (ignored for ordering, like semver requires).
var galaxyConstraintVersionRE = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.+-]+)?$`)

// galaxyParseConstraintVersion parses the version part of one constraint
// clause. Missing minor/patch parts count as zero, and parts reports how
// many numeric components were written (for "~"'s precision).
func galaxyParseConstraintVersion(s string) (v parsedSemver, parts int, ok bool) {
	m := galaxyConstraintVersionRE.FindStringSubmatch(s)
	if m == nil {
		return parsedSemver{}, 0, false
	}
	v = parsedSemver{ok: true, pre: m[4]}
	v.major, _ = strconv.ParseInt(m[1], 10, 64)
	parts = 1
	if m[2] != "" {
		v.minor, _ = strconv.ParseInt(m[2], 10, 64)
		parts = 2
	}
	if m[3] != "" {
		v.patch, _ = strconv.ParseInt(m[3], 10, 64)
		parts = 3
	}
	return v, parts, true
}

// galaxyConstraintTerm is one comparator clause of a dependency constraint.
type galaxyConstraintTerm struct {
	op    string // "==", "!=", ">=", "<=", ">", "<", "^", "~"
	raw   string // the version literal as written, without the operator
	parts int    // numeric components written (for "~"'s precision)
	ver   parsedSemver
}

// galaxyConstraintOps lists the comparator prefixes a constraint clause may
// carry, two-character operators first so they win the prefix match.
func galaxyConstraintOps() []string {
	return []string{"==", ">=", "<=", "!=", ">", "<", "=", "^", "~"}
}

// galaxyParseConstraintTerm parses one comparator clause, like ">=1.0.0" or
// a bare "1.2.3" (an exact match, like ansible-galaxy treats it).
func galaxyParseConstraintTerm(raw string) (galaxyConstraintTerm, error) {
	s := strings.TrimSpace(raw)
	op := "=="
	for _, cand := range galaxyConstraintOps() {
		if strings.HasPrefix(s, cand) {
			op, s = cand, strings.TrimSpace(strings.TrimPrefix(s, cand))
			break
		}
	}
	if op == "=" {
		op = "=="
	}
	ver, parts, ok := galaxyParseConstraintVersion(s)
	if !ok {
		return galaxyConstraintTerm{}, fmt.Errorf("invalid version constraint %q", raw)
	}
	return galaxyConstraintTerm{op: op, raw: s, parts: parts, ver: ver}, nil
}

// galaxyCaretUpper is the exclusive upper bound of a "^" clause: the next
// major, or — for 0.x versions — the next minor (or patch for 0.0.x).
func galaxyCaretUpper(v parsedSemver) parsedSemver {
	switch {
	case v.major > 0:
		return parsedSemver{ok: true, major: v.major + 1}
	case v.minor > 0:
		return parsedSemver{ok: true, minor: v.minor + 1}
	default:
		return parsedSemver{ok: true, patch: v.patch + 1}
	}
}

// galaxyTildeUpper is the exclusive upper bound of a "~" clause: the next
// minor when one was written ("~1.2", "~1.2.3"), the next major otherwise.
func galaxyTildeUpper(v parsedSemver, parts int) parsedSemver {
	if parts <= 1 {
		return parsedSemver{ok: true, major: v.major + 1}
	}
	return parsedSemver{ok: true, major: v.major, minor: v.minor + 1}
}

// matches reports whether a candidate version satisfies this one clause.
func (t galaxyConstraintTerm) matches(v parsedSemver) bool {
	cmp := galaxyCompareParsed(v, t.ver)
	switch t.op {
	case "==":
		return cmp == 0
	case "!=":
		return cmp != 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case "^":
		return cmp >= 0 && galaxyCompareParsed(v, galaxyCaretUpper(t.ver)) < 0
	default: // "~"
		return cmp >= 0 && galaxyCompareParsed(v, galaxyTildeUpper(t.ver, t.parts)) < 0
	}
}

// galaxyConstraint is a parsed dependency constraint: the AND of its
// comma-separated clauses. No clauses ("*" or empty) matches every release.
type galaxyConstraint struct {
	terms []galaxyConstraintTerm
	// allowPre marks a constraint that names a prerelease itself; only then
	// may prerelease candidates satisfy it, like ansible-galaxy resolves.
	allowPre bool
}

// galaxyParseConstraint parses a Galaxy dependency constraint: "*",
// comma-ANDed comparator clauses like ">=1.0.0,<2.0.0", the "^"/"~"
// shorthands, or an exact "==1.2.3"/"=1.2.3"/bare "1.2.3".
func galaxyParseConstraint(spec string) (galaxyConstraint, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return galaxyConstraint{}, nil
	}
	var c galaxyConstraint
	for _, raw := range strings.Split(spec, ",") {
		term, err := galaxyParseConstraintTerm(raw)
		if err != nil {
			return galaxyConstraint{}, err
		}
		if term.ver.pre != "" {
			c.allowPre = true
		}
		c.terms = append(c.terms, term)
	}
	return c, nil
}

// match reports whether one concrete version satisfies the constraint.
func (c galaxyConstraint) match(v parsedSemver) bool {
	if !v.ok || (v.pre != "" && !c.allowPre) {
		return false
	}
	for _, t := range c.terms {
		if !t.matches(v) {
			return false
		}
	}
	return true
}

// exact reports the one version an equality-only constraint pins, letting
// resolution skip the full version listing.
func (c galaxyConstraint) exact() (string, bool) {
	if len(c.terms) == 1 && c.terms[0].op == "==" && c.terms[0].parts == 3 {
		return c.terms[0].raw, true
	}
	return "", false
}

// galaxySemverMatch reports whether a collection version satisfies a Galaxy
// dependency constraint. Unparsable constraints or versions never match.
func galaxySemverMatch(constraint, version string) bool {
	c, err := galaxyParseConstraint(constraint)
	if err != nil {
		return false
	}
	return c.match(galaxyParseVersion(version))
}

// galaxyPickVersion picks the newest version in vs that satisfies the
// constraint.
func galaxyPickVersion(vs []string, c galaxyConstraint) (string, bool) {
	best := ""
	var bestParsed parsedSemver
	for _, v := range vs {
		p := galaxyParseVersion(v)
		if !c.match(p) {
			continue
		}
		if best == "" || galaxyCompareParsed(bestParsed, p) < 0 {
			best, bestParsed = v, p
		}
	}
	return best, best != ""
}

// -----------------------------------------------------------------------------
// High side: regenerated Galaxy v3 API
// -----------------------------------------------------------------------------

func (s *HighServer) galaxyDir() string {
	return filepath.Join(s.downloadDir, "galaxy")
}

func (s *HighServer) galaxyCollectionsDir() string {
	return filepath.Join(s.galaxyDir(), "collections")
}

func (s *HighServer) galaxyMetadataDir() string {
	return filepath.Join(s.galaxyDir(), "metadata")
}

// galaxyStoredVersion is the per-version metadata the high side regenerates
// at import time from the artifact's own embedded MANIFEST.json, plus the
// digest and size it computes from the artifact on disk. The served v3 API
// responses are assembled from these.
type galaxyStoredVersion struct {
	Filename     string            `json:"filename"`
	SHA256       string            `json:"sha256"`
	Size         int64             `json:"size"`
	Dependencies map[string]string `json:"dependencies"`
}

// galaxyCollectionAPIPath is the served v3 collection endpoint path.
func galaxyCollectionAPIPath(namespace, name string) string {
	return "/galaxy/api/v3/collections/" + namespace + "/" + name + "/"
}

// galaxyVersionAPIPath is the served v3 version-detail endpoint path.
func galaxyVersionAPIPath(namespace, name, version string) string {
	return galaxyCollectionAPIPath(namespace, name) + "versions/" + version + "/"
}

// serveGalaxy handles the regenerated Galaxy v3 API under /galaxy/: the API
// discovery document, collection pages, version lists and details, and the
// artifact downloads. Trailing slashes are optional — every route answers
// the slashed and slashless forms identically. It reports whether it wrote a
// response for the request.
func (s *HighServer) serveGalaxy(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/galaxy" && !strings.HasPrefix(p, "/galaxy/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.Trim(strings.TrimPrefix(p, "/galaxy"), "/")
	if rest == "api" {
		// ansible-galaxy appends "api/" to a configured server URL that
		// lacks it and reads this discovery document first.
		writeJSON(w, map[string]any{
			"available_versions": map[string]string{"v3": "v3/"},
			"description":        "ArtiGate mirrored Galaxy",
		})
		return true
	}
	if file, ok := strings.CutPrefix(rest, "download/"); ok {
		s.handleGalaxyDownload(w, r, file)
		return true
	}
	s.handleGalaxyAPI(w, r, rest)
	return true
}

// handleGalaxyAPI routes the /galaxy/api/v3/collections/... endpoints.
func (s *HighServer) handleGalaxyAPI(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(rest, "/")
	if len(segs) < 5 || segs[0] != "api" || segs[1] != "v3" || segs[2] != "collections" ||
		validateGalaxyName(segs[3]) != nil || validateGalaxyName(segs[4]) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	namespace, name := segs[3], segs[4]
	switch {
	case len(segs) == 5:
		s.handleGalaxyCollectionPage(w, r, namespace, name)
	case len(segs) == 6 && segs[5] == "versions":
		s.handleGalaxyVersionList(w, r, namespace, name)
	case len(segs) == 7 && segs[5] == "versions" && validateGalaxyVersion(segs[6]) == nil:
		s.handleGalaxyVersionDetail(w, r, namespace, name, segs[6])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// galaxyServedVersion pairs one servable version with its stored metadata
// and the artifact's modification time (the closest available
// created/updated stamp for the regenerated API).
type galaxyServedVersion struct {
	version string
	stored  galaxyStoredVersion
	mtime   time.Time
}

// galaxyServedVersions lists one collection's versions whose artifact is
// still present, newest first, from the regenerated metadata store.
func (s *HighServer) galaxyServedVersions(namespace, name string) []galaxyServedVersion {
	dir := filepath.Join(s.galaxyMetadataDir(), namespace, name)
	if !safeJoin(s.galaxyMetadataDir(), dir) {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []galaxyServedVersion
	for _, e := range entries {
		version := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || version == e.Name() || validateGalaxyVersion(version) != nil {
			continue
		}
		st, err := s.readGalaxyStored(namespace, name, version)
		if err != nil {
			continue
		}
		fi, err := os.Stat(filepath.Join(s.galaxyCollectionsDir(), namespace, name, st.Filename))
		if err != nil {
			continue
		}
		out = append(out, galaxyServedVersion{version: version, stored: st, mtime: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return galaxyVersionLess(out[j].version, out[i].version) })
	return out
}

// readGalaxyStored loads one version's regenerated metadata and checks its
// artifact is still present (only complete versions are served).
func (s *HighServer) readGalaxyStored(namespace, name, version string) (galaxyStoredVersion, error) {
	p := filepath.Join(s.galaxyMetadataDir(), namespace, name, version+".json")
	if !safeJoin(s.galaxyMetadataDir(), p) {
		return galaxyStoredVersion{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return galaxyStoredVersion{}, err
	}
	var st galaxyStoredVersion
	if err := json.Unmarshal(b, &st); err != nil {
		return galaxyStoredVersion{}, err
	}
	if st.Filename != galaxyFilename(namespace, name, version) {
		return galaxyStoredVersion{}, fmt.Errorf("invalid stored filename for %s.%s@%s", namespace, name, version)
	}
	abs := filepath.Join(s.galaxyCollectionsDir(), namespace, name, st.Filename)
	if !safeJoin(s.galaxyCollectionsDir(), abs) || !fileExists(abs) {
		return galaxyStoredVersion{}, fmt.Errorf("artifact missing for %s.%s@%s", namespace, name, version)
	}
	return st, nil
}

// handleGalaxyCollectionPage answers a collection endpoint with the highest
// servable version, 404ing when nothing of the collection is mirrored.
func (s *HighServer) handleGalaxyCollectionPage(w http.ResponseWriter, r *http.Request, namespace, name string) {
	served := s.galaxyServedVersions(namespace, name)
	if len(served) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	base := npmBaseURL(r)
	highest := served[0]
	stamp := highest.mtime.UTC().Format(time.RFC3339)
	writeJSON(w, map[string]any{
		"href":       base + galaxyCollectionAPIPath(namespace, name),
		"namespace":  namespace,
		"name":       name,
		"deprecated": false,
		"highest_version": map[string]any{
			"href":    base + galaxyVersionAPIPath(namespace, name, highest.version),
			"version": highest.version,
		},
		"created_at": stamp,
		"updated_at": stamp,
	})
}

// handleGalaxyVersionList answers a collection's version list in a single
// page, newest first (limit/offset parameters are ignored — everything a
// client could page through is already here).
func (s *HighServer) handleGalaxyVersionList(w http.ResponseWriter, r *http.Request, namespace, name string) {
	served := s.galaxyServedVersions(namespace, name)
	if len(served) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	base := npmBaseURL(r)
	self := base + galaxyCollectionAPIPath(namespace, name) + "versions/"
	data := make([]map[string]any, 0, len(served))
	for _, sv := range served {
		stamp := sv.mtime.UTC().Format(time.RFC3339)
		data = append(data, map[string]any{
			"version":    sv.version,
			"href":       base + galaxyVersionAPIPath(namespace, name, sv.version),
			"created_at": stamp,
			"updated_at": stamp,
		})
	}
	writeJSON(w, map[string]any{
		"meta":  map[string]any{"count": len(served)},
		"links": map[string]any{"first": self, "previous": nil, "next": nil, "last": self},
		"data":  data,
	})
}

// handleGalaxyVersionDetail answers one version's detail — the document
// ansible-galaxy installs from — gated on the artifact still being present.
func (s *HighServer) handleGalaxyVersionDetail(w http.ResponseWriter, r *http.Request, namespace, name, version string) {
	st, err := s.readGalaxyStored(namespace, name, version)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	base := npmBaseURL(r)
	deps := st.Dependencies
	if deps == nil {
		deps = map[string]string{}
	}
	doc := map[string]any{
		"artifact":     map[string]any{"filename": st.Filename, "sha256": st.SHA256, "size": st.Size},
		"collection":   map[string]any{"name": name, "href": base + galaxyCollectionAPIPath(namespace, name)},
		"namespace":    map[string]any{"name": namespace},
		"download_url": base + "/galaxy/download/" + st.Filename,
		"name":         name,
		"version":      version,
		"hidden":       false,
		"href":         base + galaxyVersionAPIPath(namespace, name, version),
		"signatures":   []any{},
		"metadata":     map[string]any{"dependencies": deps, "tags": []any{}, "contents": []any{}},
	}
	if fi, err := os.Stat(filepath.Join(s.galaxyCollectionsDir(), namespace, name, st.Filename)); err == nil {
		stamp := fi.ModTime().UTC().Format(time.RFC3339)
		doc["created_at"], doc["updated_at"] = stamp, stamp
	}
	writeJSON(w, doc)
}

// handleGalaxyDownload serves one collection artifact by its canonical
// filename.
func (s *HighServer) handleGalaxyDownload(w http.ResponseWriter, r *http.Request, file string) {
	namespace, name, _, ok := galaxyParseArtifactFilename(file)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.galaxyCollectionsDir(), namespace, name, file)
	if !safeJoin(s.galaxyCollectionsDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// galaxyCollectionInfo is the embedded MANIFEST.json subset the high side
// regenerates metadata from: the collection_info identity and dependencies.
type galaxyCollectionInfo struct {
	Namespace    string            `json:"namespace"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

// galaxyEmbeddedManifest is the top-level shape of a collection archive's
// MANIFEST.json.
type galaxyEmbeddedManifest struct {
	CollectionInfo galaxyCollectionInfo `json:"collection_info"`
}

// publishGalaxy regenerates the served per-version metadata for every
// collection in an imported bundle from the artifact's own embedded
// MANIFEST.json (never trusting transferred API documents). A collection
// whose archive cannot be parsed, or whose embedded identity disagrees with
// its bundle record, is logged and skipped (its version 404s) rather than
// wedging the stream's import forever.
func (s *HighServer) publishGalaxy(m *GalaxyManifest) error {
	if m == nil {
		return nil
	}
	for _, c := range m.Collections {
		if err := s.publishGalaxyCollection(c); err != nil {
			log.Printf("galaxy publish %s.%s@%s: %v", c.Namespace, c.Name, c.Version, err)
		}
	}
	return nil
}

// publishGalaxyCollection regenerates one version's stored metadata from the
// artifact's embedded MANIFEST.json, cross-checking the embedded identity
// against the bundle record.
func (s *HighServer) publishGalaxyCollection(c GalaxyCollection) error {
	if err := validateGalaxyIdentity(c.Namespace, c.Name, c.Version); err != nil {
		return err
	}
	if c.Filename != galaxyFilename(c.Namespace, c.Name, c.Version) {
		return fmt.Errorf("non-canonical filename %s", c.Filename)
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(c.Path))
	if !strings.HasPrefix(c.Path, "galaxy/collections/") || !safeJoin(s.galaxyCollectionsDir(), abs) {
		return fmt.Errorf("unsafe artifact path %s", c.Path)
	}
	info, err := extractGalaxyCollectionInfo(abs)
	if err != nil {
		return err
	}
	if err := galaxyCrossCheckInfo(info, c); err != nil {
		return err
	}
	return s.writeGalaxyStoredVersion(c, abs, info.Dependencies)
}

// galaxyCrossCheckInfo verifies the archive's embedded identity matches the
// manifest record it was transferred under.
func galaxyCrossCheckInfo(info galaxyCollectionInfo, c GalaxyCollection) error {
	if info.Namespace != c.Namespace || info.Name != c.Name {
		return fmt.Errorf("embedded MANIFEST.json names %q.%q", info.Namespace, info.Name)
	}
	if info.Version != c.Version {
		return fmt.Errorf("embedded MANIFEST.json version is %q", info.Version)
	}
	return nil
}

// writeGalaxyStoredVersion records one published version's served metadata,
// with the digest and size recomputed from the verified artifact on disk.
func (s *HighServer) writeGalaxyStoredVersion(c GalaxyCollection, abs string, deps map[string]string) error {
	sum, err := sha256File(abs)
	if err != nil {
		return err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if deps == nil {
		deps = map[string]string{}
	}
	st := galaxyStoredVersion{Filename: c.Filename, SHA256: sum, Size: fi.Size(), Dependencies: deps}
	out := filepath.Join(s.galaxyMetadataDir(), c.Namespace, c.Name, c.Version+".json")
	if !safeJoin(s.galaxyMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s.%s@%s", c.Namespace, c.Name, c.Version)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// extractGalaxyCollectionInfo reads the MANIFEST.json embedded at the top
// level of a collection archive (ansible-galaxy packs it at the archive
// root).
func extractGalaxyCollectionInfo(tgzPath string) (galaxyCollectionInfo, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return galaxyCollectionInfo{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return galaxyCollectionInfo{}, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return galaxyCollectionInfo{}, errors.New("archive has no MANIFEST.json")
		}
		if err != nil {
			return galaxyCollectionInfo{}, err
		}
		if hdr.Typeflag != tar.TypeReg || path.Clean(strings.TrimPrefix(hdr.Name, "./")) != "MANIFEST.json" {
			continue
		}
		return parseGalaxyEmbeddedManifest(tr)
	}
}

// parseGalaxyEmbeddedManifest decodes one MANIFEST.json stream, capped.
func parseGalaxyEmbeddedManifest(r io.Reader) (galaxyCollectionInfo, error) {
	b, err := io.ReadAll(io.LimitReader(r, galaxyMaxManifestBytes))
	if err != nil {
		return galaxyCollectionInfo{}, err
	}
	var m galaxyEmbeddedManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return galaxyCollectionInfo{}, fmt.Errorf("parse MANIFEST.json: %w", err)
	}
	if m.CollectionInfo.Namespace == "" {
		return galaxyCollectionInfo{}, errors.New("MANIFEST.json has no collection_info.namespace")
	}
	return m.CollectionInfo, nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listGalaxyCollections lists the mirrored collections as
// "<namespace>/<name>" with their versions, from the regenerated metadata
// store.
func (s *HighServer) listGalaxyCollections() ([]UIModule, error) {
	nsEntries, err := os.ReadDir(s.galaxyMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIModule
	for _, nsE := range nsEntries {
		if !nsE.IsDir() || validateGalaxyName(nsE.Name()) != nil {
			continue
		}
		out = append(out, s.listGalaxyNamespace(nsE.Name())...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// listGalaxyNamespace lists one namespace's mirrored collections, versions
// oldest first like the other ecosystem trees.
func (s *HighServer) listGalaxyNamespace(namespace string) []UIModule {
	nameEntries, err := os.ReadDir(filepath.Join(s.galaxyMetadataDir(), namespace))
	if err != nil {
		return nil
	}
	var out []UIModule
	for _, e := range nameEntries {
		if !e.IsDir() || validateGalaxyName(e.Name()) != nil {
			continue
		}
		served := s.galaxyServedVersions(namespace, e.Name())
		if len(served) == 0 {
			continue
		}
		versions := make([]string, 0, len(served))
		for i := len(served) - 1; i >= 0; i-- { // served is newest first
			versions = append(versions, served[i].version)
		}
		out = append(out, UIModule{Module: namespace + "/" + e.Name(), Versions: versions})
	}
	return out
}

// galaxyDetail describes one mirrored collection version for the dashboard
// detail panel. spec is "<namespace>/<name>@<version>".
func (s *HighServer) galaxyDetail(spec string) (UIDetail, error) {
	addr, version, ok := strings.Cut(spec, "@")
	namespace, name, ok2 := strings.Cut(addr, "/")
	if !ok || !ok2 || validateGalaxyIdentity(namespace, name, version) != nil {
		return UIDetail{}, errors.New("invalid namespace/name@version")
	}
	st, err := s.readGalaxyStored(namespace, name, version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Collection", Value: namespace + "." + name, Mono: true},
		{Label: "Version", Value: version, Mono: true},
		{Label: "Dependencies", Value: galaxyDepsSummary(st.Dependencies)},
		{Label: "Archive size", Value: formatBytes(st.Size)},
		{Label: "SHA-256", Value: st.SHA256, Mono: true},
		{Label: "Download path", Value: "/galaxy/download/" + st.Filename, Mono: true},
	}
	downloads := []UIDownload{{Label: st.Filename, URL: "/galaxy/download/" + st.Filename}}
	return UIDetail{Title: namespace + "." + name, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// galaxyDepsSummary renders a stored dependency map for the detail panel:
// the count and each "namespace.name constraint" pair, sorted.
func galaxyDepsSummary(deps map[string]string) string {
	if len(deps) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, strings.TrimSpace(k+" "+deps[k]))
	}
	return fmt.Sprintf("%d: %s", len(deps), strings.Join(pairs, ", "))
}

// -----------------------------------------------------------------------------
// Low side: collection collector
// -----------------------------------------------------------------------------

// GalaxyCollectRequest is the body of POST /admin/galaxy/collect.
type GalaxyCollectRequest struct {
	// Collections lists the collections to mirror as "namespace.name"
	// (newest version) or "namespace.name@1.5.4" (pinned). Collection
	// dependencies are mirrored with them.
	Collections []string `json:"collections"`
	NoDeps      bool     `json:"no_deps,omitempty"`
	Force       bool     `json:"force,omitempty"`
}

// parseGalaxySpec splits "namespace.name" or "namespace.name@1.5.4" (an
// "@latest" suffix means the same as no pin).
func parseGalaxySpec(spec string) (namespace, name, version string, err error) {
	addr, ver, _ := strings.Cut(strings.TrimSpace(spec), "@")
	var ok bool
	namespace, name, ok = strings.Cut(addr, ".")
	if !ok {
		return "", "", "", fmt.Errorf("collection %q is not namespace.name", spec)
	}
	if err := validateGalaxyName(namespace); err != nil {
		return "", "", "", err
	}
	if err := validateGalaxyName(name); err != nil {
		return "", "", "", err
	}
	if ver == "" || ver == "latest" {
		return namespace, name, "", nil
	}
	if err := validateGalaxyVersion(ver); err != nil {
		return "", "", "", fmt.Errorf("collection %s.%s: %w", namespace, name, err)
	}
	return namespace, name, ver, nil
}

// validateGalaxyRequest checks the collect request before any network work.
func validateGalaxyRequest(req GalaxyCollectRequest) error {
	if len(req.Collections) == 0 {
		return errors.New("no collections provided")
	}
	for _, spec := range req.Collections {
		if _, _, _, err := parseGalaxySpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// galaxyServerBase resolves the configured Galaxy server base URL.
func (s *LowServer) galaxyServerBase() string {
	base := strings.TrimSuffix(strings.TrimSpace(s.cfg.GalaxyServerURL), "/")
	if base == "" {
		return defaultGalaxyServerURL
	}
	return base
}

// HandleGalaxyCollect parses a JSON collect request from the admin endpoint
// and runs the collection.
func (s *LowServer) HandleGalaxyCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req GalaxyCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse galaxy collect request: %w", err)
		}
	}
	return s.CollectGalaxy(ctx, req)
}

// CollectGalaxy resolves the requested collections (and, unless disabled,
// their declared dependency closure) against the Galaxy v3 API, downloads
// the artifacts — verifying the API-declared SHA-256 and size — and writes
// them into a signed bundle on the galaxy stream. Collections that cannot be
// resolved or fetched are skipped and reported so one of them never blocks
// the rest of the batch.
func (s *LowServer) CollectGalaxy(ctx context.Context, req GalaxyCollectRequest) (ExportResult, error) {
	if err := validateGalaxyRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the galaxy stream's lock for the whole fetch->write->commit
	// so a concurrent galaxy exporter cannot claim the same sequence number
	// between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamGalaxy)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "galaxy", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	base := s.galaxyServerBase()
	emitProgress(ctx, "Resolving %d collection(s) against %s…", len(req.Collections), base)
	dl := &galaxyDownloader{base: base, stageRoot: stageRoot, noDeps: req.NoDeps}
	dl.run(ctx, req.Collections)
	if len(dl.cols) == 0 {
		return ExportResult{}, fmt.Errorf("no collections could be fetched: %s", summarizeFailures(dl.failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(dl.files))

	res, err := s.exportIfNew(ctx, streamGalaxy, stageRoot, dl.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeGalaxyBundle(ctx, seq, stageRoot, dl.files, dl.cols)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = dl.failed
	return res, nil
}

// -----------------------------------------------------------------------------
// Upstream v3 API access
// -----------------------------------------------------------------------------

// galaxyCollectionURL is the upstream v3 collection endpoint for a
// collection, with the trailing slash the API canonicalizes on.
func galaxyCollectionURL(base, namespace, name string) string {
	return base + "/api/v3/collections/" + namespace + "/" + name + "/"
}

// galaxyResolveURL resolves a possibly-relative API link (pagination "next"
// links, download URLs) against the server base, requiring an http(s)
// result.
func galaxyResolveURL(base, ref string) (string, error) {
	b, err := url.Parse(base + "/")
	if err != nil {
		return "", err
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", fmt.Errorf("invalid galaxy URL %q: %w", ref, err)
	}
	u := b.ResolveReference(r)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("galaxy URL %q is not http(s)", u.String())
	}
	return u.String(), nil
}

// galaxyCollectionPage is the subset of an upstream collection endpoint
// response ArtiGate reads: the highest published version.
type galaxyCollectionPage struct {
	HighestVersion struct {
		Version string `json:"version"`
	} `json:"highest_version"`
}

// galaxyFetchHighest resolves a collection's newest version from its
// collection page's highest_version.
func galaxyFetchHighest(ctx context.Context, base, namespace, name string) (string, error) {
	b, err := httpGetBytes(ctx, galaxyCollectionURL(base, namespace, name), maxIndexFetchBytes)
	if err != nil {
		return "", err
	}
	var page galaxyCollectionPage
	if err := json.Unmarshal(b, &page); err != nil {
		return "", fmt.Errorf("parse collection page: %w", err)
	}
	if err := validateGalaxyVersion(page.HighestVersion.Version); err != nil {
		return "", fmt.Errorf("collection page highest_version: %w", err)
	}
	return page.HighestVersion.Version, nil
}

// galaxyVersionListPage is the subset of one paginated version-list response
// ArtiGate reads: the version names and the next-page link.
type galaxyVersionListPage struct {
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Data []struct {
		Version string `json:"version"`
	} `json:"data"`
}

// galaxyFetchVersionPage fetches one version-list page, returning its valid
// versions and the resolved next-page URL ("" on the last page). The API's
// next links may be absolute or server-relative; both resolve against base.
func galaxyFetchVersionPage(ctx context.Context, base, pageURL string) ([]string, string, error) {
	b, err := httpGetBytes(ctx, pageURL, maxIndexFetchBytes)
	if err != nil {
		return nil, "", err
	}
	var page galaxyVersionListPage
	if err := json.Unmarshal(b, &page); err != nil {
		return nil, "", fmt.Errorf("parse version list: %w", err)
	}
	versions := make([]string, 0, len(page.Data))
	for _, d := range page.Data {
		if validateGalaxyVersion(d.Version) == nil {
			versions = append(versions, d.Version)
		}
	}
	next := strings.TrimSpace(page.Links.Next)
	if next == "" {
		return versions, "", nil
	}
	resolved, err := galaxyResolveURL(base, next)
	if err != nil {
		return nil, "", err
	}
	return versions, resolved, nil
}

// galaxyFetchVersions lists every version of a collection, following the v3
// API's pagination links up to galaxyMaxVersionPages pages.
func galaxyFetchVersions(ctx context.Context, base, namespace, name string) ([]string, error) {
	next := galaxyCollectionURL(base, namespace, name) + "versions/?limit=100"
	var out []string
	for page := 0; next != ""; page++ {
		if page >= galaxyMaxVersionPages {
			return nil, fmt.Errorf("version list exceeds %d pages", galaxyMaxVersionPages)
		}
		versions, nextURL, err := galaxyFetchVersionPage(ctx, base, next)
		if err != nil {
			return nil, err
		}
		out = append(out, versions...)
		next = nextURL
	}
	return out, nil
}

// galaxyVersionDetail is the subset of an upstream version endpoint response
// ArtiGate reads: the artifact identity/digest, the download URL, and the
// declared dependencies.
type galaxyVersionDetail struct {
	Artifact struct {
		Filename string `json:"filename"`
		SHA256   string `json:"sha256"`
		Size     int64  `json:"size"`
	} `json:"artifact"`
	DownloadURL string `json:"download_url"`
	Metadata    struct {
		Dependencies map[string]string `json:"dependencies"`
	} `json:"metadata"`
}

// galaxyFetchVersionDetail fetches one version's detail document, requiring
// the artifact digest, size, and download URL a verified mirror needs.
func galaxyFetchVersionDetail(ctx context.Context, base, namespace, name, version string) (galaxyVersionDetail, error) {
	b, err := httpGetBytes(ctx, galaxyCollectionURL(base, namespace, name)+"versions/"+version+"/", maxIndexFetchBytes)
	if err != nil {
		return galaxyVersionDetail{}, err
	}
	var detail galaxyVersionDetail
	if err := json.Unmarshal(b, &detail); err != nil {
		return galaxyVersionDetail{}, fmt.Errorf("parse version detail: %w", err)
	}
	if detail.DownloadURL == "" || detail.Artifact.SHA256 == "" || detail.Artifact.Size <= 0 {
		return galaxyVersionDetail{}, errors.New("version detail lacks artifact digest, size, or download URL")
	}
	return detail, nil
}

// -----------------------------------------------------------------------------
// Dependency-closure download
// -----------------------------------------------------------------------------

// galaxyWant is one queued resolution item: a collection and the version
// requirement that asked for it.
type galaxyWant struct {
	namespace, name string
	// spec is "" for the newest version, an exact version when pinned, or a
	// dependency constraint otherwise.
	spec   string
	pinned bool
}

// galaxyDownloader walks the dependency closure, downloading each collection
// once (the first version requirement to reach a collection wins).
type galaxyDownloader struct {
	base      string
	stageRoot string
	noDeps    bool
	cols      []GalaxyCollection
	files     []ManifestFile
	failed    []FailedModule
	done      map[string]bool
}

// run resolves and downloads the requested specs and, unless disabled, their
// dependency closure.
func (d *galaxyDownloader) run(ctx context.Context, specs []string) {
	d.done = map[string]bool{}
	queue := make([]galaxyWant, 0, len(specs))
	for _, spec := range specs {
		namespace, name, version, _ := parseGalaxySpec(spec)
		queue = append(queue, galaxyWant{namespace: namespace, name: name, spec: version, pinned: version != ""})
	}
	for len(queue) > 0 && len(d.done) < galaxyMaxResolved {
		w := queue[0]
		queue = queue[1:]
		if d.done[w.namespace+"."+w.name] {
			continue
		}
		d.done[w.namespace+"."+w.name] = true
		deps, ok := d.fetchOne(ctx, w)
		if ok && !d.noDeps {
			queue = append(queue, deps...)
		}
	}
}

// fetchOne resolves one queued collection to a concrete version, downloads
// its verified artifact, and returns the dependency wants it introduces.
func (d *galaxyDownloader) fetchOne(ctx context.Context, w galaxyWant) ([]galaxyWant, bool) {
	version, err := d.resolveVersion(ctx, w)
	if err == nil {
		err = validateGalaxyVersion(version)
	}
	if err != nil {
		d.fail(ctx, w, orDefault(w.spec, "latest"), err)
		return nil, false
	}
	emitProgress(ctx, "→ %s.%s@%s", w.namespace, w.name, version)
	detail, err := galaxyFetchVersionDetail(ctx, d.base, w.namespace, w.name, version)
	if err == nil {
		err = d.downloadOne(ctx, w.namespace, w.name, version, detail)
	}
	if err != nil {
		d.fail(ctx, w, version, err)
		return nil, false
	}
	return d.depWants(ctx, detail.Metadata.Dependencies), true
}

// fail records one unfetchable collection and moves on — a single missing
// dependency must never block the rest of the batch.
func (d *galaxyDownloader) fail(ctx context.Context, w galaxyWant, version string, err error) {
	emitProgress(ctx, "  ✗ %s.%s@%s: %s", w.namespace, w.name, version, err)
	d.failed = append(d.failed, FailedModule{Module: w.namespace + "." + w.name, Version: version, Error: err.Error()})
}

// resolveVersion turns one want into a concrete version: the pin itself, the
// collection page's highest version, or — for range constraints — the newest
// version of the full (paginated) version list that satisfies them.
func (d *galaxyDownloader) resolveVersion(ctx context.Context, w galaxyWant) (string, error) {
	if w.pinned {
		return w.spec, nil
	}
	if w.spec == "" {
		return galaxyFetchHighest(ctx, d.base, w.namespace, w.name)
	}
	c, err := galaxyParseConstraint(w.spec)
	if err != nil {
		return "", err
	}
	if exact, ok := c.exact(); ok {
		return exact, nil
	}
	versions, err := galaxyFetchVersions(ctx, d.base, w.namespace, w.name)
	if err != nil {
		return "", err
	}
	if v, ok := galaxyPickVersion(versions, c); ok {
		return v, nil
	}
	return "", fmt.Errorf("no version satisfies %q", w.spec)
}

// downloadOne fetches one resolved version's artifact into the staging tree,
// verifying the API-declared SHA-256 and size, and records it for the
// bundle.
func (d *galaxyDownloader) downloadOne(ctx context.Context, namespace, name, version string, detail galaxyVersionDetail) error {
	filename := galaxyFilename(namespace, name, version)
	if detail.Artifact.Filename != filename {
		return fmt.Errorf("upstream artifact filename %q is not the canonical %q", detail.Artifact.Filename, filename)
	}
	dlURL, err := galaxyResolveURL(d.base, detail.DownloadURL)
	if err != nil {
		return err
	}
	rel := galaxyFileRel(namespace, name, filename)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadVerifiedFile(ctx, dlURL, abs, detail.Artifact.Size, "sha256", detail.Artifact.SHA256)
	if err != nil {
		return err
	}
	d.cols = append(d.cols, GalaxyCollection{Namespace: namespace, Name: name, Version: version, Filename: filename, Path: rel, SHA256: sum})
	d.files = append(d.files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	return nil
}

// depWants turns a version's declared dependencies into queue items in
// deterministic order, reporting (not aborting on) malformed dependency
// keys.
func (d *galaxyDownloader) depWants(ctx context.Context, deps map[string]string) []galaxyWant {
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var wants []galaxyWant
	for _, key := range keys {
		namespace, name, ok := strings.Cut(key, ".")
		if !ok || validateGalaxyName(namespace) != nil || validateGalaxyName(name) != nil {
			emitProgress(ctx, "  ✗ dependency %q: invalid collection name", key)
			d.failed = append(d.failed, FailedModule{Module: key, Version: deps[key], Error: "invalid dependency collection name"})
			continue
		}
		wants = append(wants, galaxyWant{namespace: namespace, name: name, spec: deps[key]})
	}
	return wants
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

// writeGalaxyBundle packs the staged artifacts and their manifest into the
// signed bundle files for the galaxy stream's next sequence.
func (s *LowServer) writeGalaxyBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, cols []GalaxyCollection) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(cols, func(i, j int) bool {
		a, b := cols[i], cols[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	id := bundleIDFor(streamGalaxy, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamGalaxy,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"galaxy"},
		Galaxy:           &GalaxyManifest{Collections: cols},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamGalaxy, Sequence: seq, ExportedModules: len(cols), BundleID: id}, nil
}
