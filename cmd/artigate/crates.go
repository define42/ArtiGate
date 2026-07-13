package main

// Rust crates ecosystem adapter. The low side resolves crates against a sparse
// registry index (index.crates.io by default), downloads the .crate archives —
// verifying each against the index-declared cksum — and packs them into the
// same numbered, signed ArtiGate bundle format used by the other ecosystems.
// The high side serves a sparse index of its own (config.json plus per-crate
// line files) and the .crate downloads.
//
// Like the APT adapter, the manifest carries each version's verbatim upstream
// index line inside the Ed25519-signed manifest. The high side never serves a
// line whose cksum does not equal the byte-verified artifact's SHA-256 (checked
// again at import), and regenerates every served index file from those
// verified records, gated on the .crate actually being present.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const defaultCratesIndex = "https://index.crates.io"

// cratesMaxIndexFileBytes caps one sparse-index line file held in memory. The
// largest real-world crate index files (hundreds of versions with big feature
// tables) are a few MiB.
const cratesMaxIndexFileBytes = 64 << 20

// cratesMaxResolved bounds a dependency resolution so a pathological graph
// cannot grow without limit.
const cratesMaxResolved = 4000

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type CratesManifest struct {
	Crates []CrateVersion `json:"crates"`
}

// CrateVersion records one mirrored crate release. IndexLine is the verbatim
// upstream sparse-index line (JSON object) for the release; it travels inside
// the signed manifest and its cksum must equal the .crate file's SHA-256.
type CrateVersion struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Path      string          `json:"path"`
	SHA256    string          `json:"sha256"`
	IndexLine json.RawMessage `json:"index_line"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// crateNameRE matches a path-safe crate name. crates.io enforces a stricter
// charset; alternative registries allow a leading digit, so accept both. The
// first character excludes "-" and "_", so a name can never be ".."/"-flag".
var crateNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// crateVersionRE matches a semver version, which always starts with a digit,
// so it can never be ".."/"-flag" or contain a path separator.
var crateVersionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

func validateCrateName(name string) error {
	if !crateNameRE.MatchString(name) {
		return fmt.Errorf("invalid crate name %q", name)
	}
	return nil
}

func validateCrateVersion(v string) error {
	if !crateVersionRE.MatchString(v) {
		return fmt.Errorf("invalid crate version %q", v)
	}
	return nil
}

// crateFileRel is the repository-relative path a crate archive is stored
// under. Names are case-insensitively unique in a registry, so the lowercase
// form keeps one canonical path however a dependency spells it.
func crateFileRel(name, version string) string {
	n := strings.ToLower(name)
	return path.Join("crates", "files", n, n+"-"+version+".crate")
}

// crateIndexPath is the registry-defined sparse index location for a crate:
// 1-, 2- and 3-letter names get length-keyed directories, everything else is
// sharded by the first four letters ("serde" -> "se/rd/serde").
func crateIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	default:
		return n[:2] + "/" + n[2:4] + "/" + n
	}
}

// crateIndexLine is the subset of a sparse-index line ArtiGate reads. The
// verbatim line is preserved separately; this parse only drives resolution and
// validation.
type crateIndexLine struct {
	Name   string     `json:"name"`
	Vers   string     `json:"vers"`
	Cksum  string     `json:"cksum"`
	Yanked bool       `json:"yanked"`
	Deps   []crateDep `json:"deps"`
}

type crateDep struct {
	Name     string `json:"name"`
	Req      string `json:"req"`
	Kind     string `json:"kind"`
	Optional bool   `json:"optional"`
	// Package is the crate's real registry name when the dependency is
	// renamed; empty means Name is the registry name.
	Package string `json:"package"`
}

// validateCrateRecord checks one manifest record: path-safe identity, the
// canonical storage path, and that the embedded index line describes exactly
// the artifact the bundle delivers (name/version match, cksum == SHA-256).
func validateCrateRecord(c CrateVersion, seen map[string]bool) error {
	if err := validateCrateName(c.Name); err != nil {
		return err
	}
	if err := validateCrateVersion(c.Version); err != nil {
		return fmt.Errorf("crate %s: %w", c.Name, err)
	}
	if c.Path != crateFileRel(c.Name, c.Version) {
		return fmt.Errorf("crate %s@%s has non-canonical path %s", c.Name, c.Version, c.Path)
	}
	if !seen[c.Path] {
		return fmt.Errorf("crate %s@%s references file not listed in manifest.files: %s", c.Name, c.Version, c.Path)
	}
	var line crateIndexLine
	if err := json.Unmarshal(c.IndexLine, &line); err != nil {
		return fmt.Errorf("crate %s@%s has an unparsable index line: %w", c.Name, c.Version, err)
	}
	if !strings.EqualFold(line.Name, c.Name) || line.Vers != c.Version {
		return fmt.Errorf("crate %s@%s index line names %s@%s", c.Name, c.Version, line.Name, line.Vers)
	}
	if !strings.EqualFold(line.Cksum, c.SHA256) || c.SHA256 == "" {
		return fmt.Errorf("crate %s@%s index cksum does not match the delivered artifact", c.Name, c.Version)
	}
	return nil
}

// validateCrates checks every crate record of a bundle manifest.
func validateCrates(crates []CrateVersion, seen map[string]bool) error {
	for _, c := range crates {
		if err := validateCrateRecord(c, seen); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: sparse index and downloads
// -----------------------------------------------------------------------------

func (s *HighServer) cratesFilesDir() string {
	return filepath.Join(s.downloadDir, "crates", "files")
}

func (s *HighServer) cratesIndexDir() string {
	return filepath.Join(s.downloadDir, "crates", "index")
}

// serveCrates handles the cargo sparse-registry routes under /crates/: the
// registry config, per-crate index files, and .crate downloads. Clients set
// registries.<name>.index = "sparse+<base>/crates/index/". It reports whether
// it wrote a response for the request.
func (s *HighServer) serveCrates(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/crates" && !strings.HasPrefix(p, "/crates/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.TrimPrefix(p, "/crates")
	switch {
	case rest == "/index/config.json":
		// cargo requires absolute URLs here; dl has no {marker}s, so cargo
		// appends /{crate}/{version}/download itself.
		writeJSON(w, map[string]string{"dl": npmBaseURL(r) + "/crates/dl"})
	case strings.HasPrefix(rest, "/index/"):
		s.handleCrateIndexFile(w, r, strings.TrimPrefix(rest, "/index/"))
	case strings.HasPrefix(rest, "/dl/"):
		s.handleCrateDownload(w, r, strings.TrimPrefix(rest, "/dl/"))
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

// handleCrateIndexFile serves one regenerated sparse-index file. cargo
// requests lowercase paths; lowercasing here keeps the route tolerant of
// hand-typed mixed-case names.
func (s *HighServer) handleCrateIndexFile(w http.ResponseWriter, r *http.Request, rel string) {
	rel = strings.ToLower(rel)
	if validateRelPath(rel) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.cratesIndexDir(), filepath.FromSlash(rel))
	if !safeJoin(s.cratesIndexDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// handleCrateDownload serves a .crate archive for the cargo download route
// {name}/{version}/download appended to the config.json dl base.
func (s *HighServer) handleCrateDownload(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(rest, "/")
	if len(segs) != 3 || segs[2] != "download" ||
		validateCrateName(segs[0]) != nil || validateCrateVersion(segs[1]) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(crateFileRel(segs[0], segs[1])))
	if !safeJoin(s.cratesFilesDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// -----------------------------------------------------------------------------
// High side: index regeneration at import
// -----------------------------------------------------------------------------

// publishCrates regenerates the served sparse-index files for every crate in
// an imported bundle. A record that cannot be published is logged and skipped
// (that version 404s) rather than wedging the stream's import forever.
func (s *HighServer) publishCrates(m *CratesManifest) error {
	if m == nil {
		return nil
	}
	byName := map[string][]CrateVersion{}
	for _, c := range m.Crates {
		key := strings.ToLower(c.Name)
		byName[key] = append(byName[key], c)
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := s.publishCrateIndex(name, byName[name]); err != nil {
			log.Printf("crates publish %s: %v", name, err)
		}
	}
	return nil
}

// publishCrateIndex upserts the given releases into one crate's sparse-index
// file, keeping lines from earlier bundles and writing the result atomically.
// Only releases whose verified .crate archive is present are (re)listed.
func (s *HighServer) publishCrateIndex(name string, records []CrateVersion) error {
	if validateCrateName(name) != nil {
		return fmt.Errorf("invalid crate name %q", name)
	}
	out := filepath.Join(s.cratesIndexDir(), filepath.FromSlash(crateIndexPath(name)))
	if !safeJoin(s.cratesIndexDir(), out) {
		return fmt.Errorf("unsafe index path for %q", name)
	}
	lines, err := readCrateIndexLines(out)
	if err != nil {
		return err
	}
	for _, c := range records {
		if !fileExists(filepath.Join(s.downloadDir, filepath.FromSlash(c.Path))) {
			return fmt.Errorf("crate archive missing for %s@%s", c.Name, c.Version)
		}
		lines[c.Version] = append(json.RawMessage(nil), c.IndexLine...)
	}
	return writeBytesAtomic(out, renderCrateIndex(lines), 0o644)
}

// readCrateIndexLines loads an existing sparse-index file into a
// version-keyed map; a missing file is an empty index.
func readCrateIndexLines(p string) (map[string]json.RawMessage, error) {
	lines := map[string]json.RawMessage{}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return lines, nil
	}
	if err != nil {
		return nil, err
	}
	for _, raw := range strings.Split(string(b), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var line crateIndexLine
		if json.Unmarshal([]byte(raw), &line) != nil || line.Vers == "" {
			continue
		}
		lines[line.Vers] = json.RawMessage(raw)
	}
	return lines, nil
}

// renderCrateIndex renders the version-keyed lines back into the newline-
// delimited sparse-index format, oldest version first like the upstream index.
func renderCrateIndex(lines map[string]json.RawMessage) []byte {
	versions := make([]string, 0, len(lines))
	for v := range lines {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return crateVersionLess(versions[i], versions[j]) })
	var b strings.Builder
	for _, v := range versions {
		b.Write(lines[v])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// crateVersionLess orders two crate versions, falling back to lexical order
// when either does not parse as semver.
func crateVersionLess(a, b string) bool {
	av, aerr := parseCrateVer(a)
	bv, berr := parseCrateVer(b)
	if aerr != nil || berr != nil {
		return a < b
	}
	return compareCrateVer(av, bv) < 0
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listCratesPackages groups the mirrored crates by name with their versions,
// from the archive store.
func (s *HighServer) listCratesPackages() ([]UIModule, error) {
	dirs, err := os.ReadDir(s.cratesFilesDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIModule
	for _, d := range dirs {
		name := d.Name()
		if !d.IsDir() || validateCrateName(name) != nil {
			continue
		}
		versions := s.crateVersionsOnDisk(name)
		if len(versions) > 0 {
			out = append(out, UIModule{Module: name, Versions: versions})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// crateVersionsOnDisk lists one crate's mirrored versions, sorted ascending.
func (s *HighServer) crateVersionsOnDisk(name string) []string {
	files, err := os.ReadDir(filepath.Join(s.cratesFilesDir(), name))
	if err != nil {
		return nil
	}
	var versions []string
	for _, f := range files {
		v, ok := strings.CutPrefix(f.Name(), name+"-")
		if !ok {
			continue
		}
		if v, ok = strings.CutSuffix(v, ".crate"); ok && validateCrateVersion(v) == nil {
			versions = append(versions, v)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return crateVersionLess(versions[i], versions[j]) })
	return versions
}

// cratesDetail describes one mirrored crate version for the dashboard detail
// panel. spec is "<name>@<version>".
func (s *HighServer) cratesDetail(spec string) (UIDetail, error) {
	name, version, ok := strings.Cut(spec, "@")
	if !ok || validateCrateName(name) != nil || validateCrateVersion(version) != nil {
		return UIDetail{}, errors.New("invalid crate@version")
	}
	name = strings.ToLower(name)
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(crateFileRel(name, version)))
	st, err := os.Stat(abs)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Crate", Value: name, Mono: true},
		{Label: "Version", Value: version, Mono: true},
		{Label: "Archive size", Value: formatBytes(st.Size())},
	}
	if sum, err := sha256File(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	dl := "/crates/dl/" + name + "/" + version + "/download"
	fields = append(fields,
		UIDetailField{Label: "Index path", Value: "/crates/index/" + crateIndexPath(name), Mono: true},
		UIDetailField{Label: "Download path", Value: dl, Mono: true},
	)
	downloads := []UIDownload{{Label: name + "-" + version + ".crate", URL: dl}}
	return UIDetail{Title: name, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// Semver parsing and cargo requirement matching
// -----------------------------------------------------------------------------

// crateVer is a parsed semver version; build metadata is ignored for ordering
// and matching, as semver specifies.
type crateVer struct {
	major, minor, patch int64
	pre                 string
}

func parseCrateVer(v string) (crateVer, error) {
	v, _, _ = strings.Cut(v, "+")
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return crateVer{}, fmt.Errorf("invalid semver %q", v)
	}
	nums := make([]int64, 3)
	for i, p := range parts {
		n, err := parseVersionInt(p)
		if err != nil {
			return crateVer{}, fmt.Errorf("invalid semver %q", v)
		}
		nums[i] = n
	}
	return crateVer{major: nums[0], minor: nums[1], patch: nums[2], pre: pre}, nil
}

// parseVersionInt parses one numeric version component without accepting
// signs, spaces, or other strconv laxness.
func parseVersionInt(s string) (int64, error) {
	if s == "" || len(s) > 18 {
		return 0, fmt.Errorf("invalid version number %q", s)
	}
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid version number %q", s)
		}
		n = n*10 + int64(r-'0')
	}
	return n, nil
}

// compareCrateVer orders two parsed versions per semver: numeric components,
// then a release outranks any pre-release, then the shared pre-release
// identifier ordering.
func compareCrateVer(a, b crateVer) int {
	switch {
	case a.major != b.major:
		return cmpInt64(a.major, b.major)
	case a.minor != b.minor:
		return cmpInt64(a.minor, b.minor)
	case a.patch != b.patch:
		return cmpInt64(a.patch, b.patch)
	case a.pre == "" && b.pre != "":
		return 1
	case a.pre != "" && b.pre == "":
		return -1
	}
	return comparePrerelease(a.pre, b.pre)
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cratePartialVer is one predicate's version, which may omit minor/patch
// ("^1.2", "~1") and carry a pre-release tag.
type cratePartialVer struct {
	major              int64
	minor, patch       int64
	hasMinor, hasPatch bool
	pre                string
}

// cratePred is one comparator of a cargo version requirement.
type cratePred struct {
	op string // "^", "~", "=", ">", ">=", "<", "<=", "*"
	v  cratePartialVer
}

// parseCrateReq parses a cargo version requirement: comma-separated
// comparators with ^ (the default), ~, =, ranges, and wildcard forms.
func parseCrateReq(req string) ([]cratePred, error) {
	var preds []cratePred
	for _, part := range strings.Split(req, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid version requirement %q", req)
		}
		p, err := parseCratePred(part)
		if err != nil {
			return nil, err
		}
		preds = append(preds, p)
	}
	return preds, nil
}

func parseCratePred(s string) (cratePred, error) {
	op := "^"
	for _, candidate := range []string{">=", "<=", ">", "<", "=", "~", "^"} {
		if strings.HasPrefix(s, candidate) {
			op = candidate
			s = strings.TrimSpace(strings.TrimPrefix(s, candidate))
			break
		}
	}
	if s == "*" {
		if op != "^" {
			return cratePred{}, fmt.Errorf("invalid version requirement %q", s)
		}
		return cratePred{op: "*"}, nil
	}
	v, wildcard, err := parseCratePartial(s)
	if err != nil {
		return cratePred{}, err
	}
	// "1.2.*" behaves like "~1.2": everything with that prefix.
	if wildcard && op == "^" {
		op = "~"
	}
	return cratePred{op: op, v: v}, nil
}

// parseCratePartial parses a possibly-partial version ("1", "1.2", "1.2.3",
// "1.2.x", "1.*"), reporting whether a wildcard truncated it.
func parseCratePartial(s string) (cratePartialVer, bool, error) {
	s, _, _ = strings.Cut(s, "+")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return cratePartialVer{}, false, fmt.Errorf("invalid version %q", s)
	}
	var v cratePartialVer
	v.pre = pre
	wildcard := false
	for i, p := range parts {
		if p == "*" || p == "x" || p == "X" {
			wildcard = true
			break
		}
		n, err := parseVersionInt(p)
		if err != nil {
			return cratePartialVer{}, false, fmt.Errorf("invalid version %q", s)
		}
		switch i {
		case 0:
			v.major = n
		case 1:
			v.minor, v.hasMinor = n, true
		case 2:
			v.patch, v.hasPatch = n, true
		}
	}
	return v, wildcard, nil
}

func (p cratePartialVer) filled() crateVer {
	return crateVer{major: p.major, minor: p.minor, patch: p.patch, pre: p.pre}
}

// crateReqMatches reports whether version v satisfies every comparator of the
// requirement. Pre-release versions match only when some comparator names the
// same major.minor.patch with a pre-release tag, mirroring cargo.
func crateReqMatches(preds []cratePred, v crateVer) bool {
	for _, p := range preds {
		if !cratePredMatches(p, v) {
			return false
		}
	}
	if v.pre == "" {
		return true
	}
	for _, p := range preds {
		if p.v.pre != "" && p.v.major == v.major && p.v.minor == v.minor && p.v.patch == v.patch {
			return true
		}
	}
	return false
}

func cratePredMatches(p cratePred, v crateVer) bool {
	switch p.op {
	case "*":
		return true
	case "=":
		return crateEqMatches(p.v, v)
	case ">", ">=", "<", "<=":
		return crateCmpMatches(p.op, p.v.filled(), v)
	case "~":
		return crateVerBetween(v, p.v.filled(), crateTildeUpper(p.v))
	default: // "^"
		return crateVerBetween(v, p.v.filled(), crateCaretUpper(p.v))
	}
}

// crateEqMatches implements "=" with partial versions: "=1.2" accepts any
// 1.2.x release.
func crateEqMatches(p cratePartialVer, v crateVer) bool {
	if !p.hasMinor {
		return v.major == p.major
	}
	if !p.hasPatch {
		return v.major == p.major && v.minor == p.minor
	}
	return compareCrateVer(v, p.filled()) == 0
}

func crateCmpMatches(op string, bound, v crateVer) bool {
	c := compareCrateVer(v, bound)
	switch op {
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "<":
		return c < 0
	}
	return c <= 0
}

// crateVerBetween reports lower <= v < upper.
func crateVerBetween(v, lower, upper crateVer) bool {
	return compareCrateVer(v, lower) >= 0 && compareCrateVer(v, upper) < 0
}

// crateTildeUpper is the exclusive upper bound of a "~" requirement: the next
// minor when a minor is given, otherwise the next major.
func crateTildeUpper(p cratePartialVer) crateVer {
	if p.hasMinor {
		return crateVer{major: p.major, minor: p.minor + 1}
	}
	return crateVer{major: p.major + 1}
}

// crateCaretUpper is the exclusive upper bound of a "^" requirement: the next
// increment of the leftmost non-zero component (with cargo's rules for the
// partial 0.x forms).
func crateCaretUpper(p cratePartialVer) crateVer {
	switch {
	case p.major > 0:
		return crateVer{major: p.major + 1}
	case p.hasMinor && p.minor > 0:
		return crateVer{minor: p.minor + 1}
	case p.hasMinor && p.hasPatch:
		return crateVer{patch: p.patch + 1}
	case p.hasMinor:
		return crateVer{minor: 1}
	}
	return crateVer{major: 1}
}

// -----------------------------------------------------------------------------
// Low side: sparse-index resolver/collector
// -----------------------------------------------------------------------------

// CratesCollectRequest is the body of POST /admin/crates/collect.
//
// Crates is a list of specs ("serde" for the newest release, "serde@1.0.203"
// to pin). By default the transitive dependency graph (normal and build
// dependencies) of the listed crates is resolved against the sparse index and
// bundled too; ResolveDeps=false mirrors only the listed crates, and
// IncludeOptional additionally follows optional dependencies.
type CratesCollectRequest struct {
	Crates          []string `json:"crates"`
	ResolveDeps     *bool    `json:"resolve_deps,omitempty"`
	IncludeOptional bool     `json:"include_optional,omitempty"`
	// Force disables export dedup for this collect: every crate is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseCrateSpec splits "name" or "name@version".
func parseCrateSpec(spec string) (name, version string, err error) {
	name, version, _ = strings.Cut(spec, "@")
	if err := validateCrateName(name); err != nil {
		return "", "", err
	}
	if version != "" && version != "latest" {
		if err := validateCrateVersion(version); err != nil {
			return "", "", fmt.Errorf("crate %s: %w", name, err)
		}
		return name, version, nil
	}
	return name, "", nil
}

func validateCratesRequest(req CratesCollectRequest) error {
	if len(req.Crates) == 0 {
		return errors.New("no crates provided")
	}
	for _, spec := range req.Crates {
		if _, _, err := parseCrateSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// HandleCratesCollect parses a JSON collect request from the admin endpoint
// and runs the collection.
func (s *LowServer) HandleCratesCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req CratesCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse crates collect request: %w", err)
		}
	}
	return s.CollectCrates(ctx, req)
}

// cratesIndexBase is the sparse index crates are resolved from.
func (s *LowServer) cratesIndexBase() string {
	if s.cfg.CratesIndex != "" {
		return strings.TrimSuffix(s.cfg.CratesIndex, "/")
	}
	return defaultCratesIndex
}

// CollectCrates resolves the requested crates (and by default their
// dependency graph) against the sparse index, downloads every .crate archive
// with its index-declared checksum verified, and writes them into a signed
// bundle on the crates stream. Crates that cannot be resolved or fetched are
// skipped and reported so one of them never blocks the rest of the batch.
func (s *LowServer) CollectCrates(ctx context.Context, req CratesCollectRequest) (ExportResult, error) {
	if err := validateCratesRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the crates stream's lock for the whole resolve->download->
	// write->commit so a concurrent crates exporter cannot claim the same
	// sequence number between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamCrates)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "crates", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	emitProgress(ctx, "Resolving %d crate(s) against %s…", len(req.Crates), s.cratesIndexBase())
	res := newCrateResolver(s, req)
	selected, skipped := res.resolve(ctx, req.Crates)
	if len(selected) == 0 {
		return ExportResult{}, fmt.Errorf("no crates could be resolved: %s", summarizeFailures(skipped))
	}
	emitProgress(ctx, "Downloading %d crate archive(s)…", len(selected))
	records, files, failed, err := s.downloadCrates(ctx, stageRoot, res.dl, selected)
	if err != nil {
		return ExportResult{}, err
	}
	failed = append(skipped, failed...)
	if len(records) == 0 {
		return ExportResult{}, fmt.Errorf("no crates could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	out, err := s.exportIfNew(ctx, streamCrates, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeCratesBundle(ctx, seq, stageRoot, files, records)
	})
	if err != nil {
		return ExportResult{}, err
	}
	out.SkippedModules = failed
	return out, nil
}

// crateSelection is one release picked for mirroring, with its verbatim index
// line retained for the bundle manifest.
type crateSelection struct {
	name    string // registry-cased name from the index line
	version string
	cksum   string
	yanked  bool
	raw     json.RawMessage
	deps    []crateDep
}

// crateResolver walks the sparse index, selecting a version per requested
// crate and (optionally) the transitive dependency graph.
type crateResolver struct {
	s               *LowServer
	index           string
	dl              string
	resolveDeps     bool
	includeOptional bool
	cache           map[string][]crateSelection // lowercase name -> parsed index entries
	picked          map[string]bool             // lowercase name@version already selected
	byName          map[string][]crateVer       // versions already selected per crate
}

func newCrateResolver(s *LowServer, req CratesCollectRequest) *crateResolver {
	return &crateResolver{
		s:               s,
		index:           s.cratesIndexBase(),
		resolveDeps:     req.ResolveDeps == nil || *req.ResolveDeps,
		includeOptional: req.IncludeOptional,
		cache:           map[string][]crateSelection{},
		picked:          map[string]bool{},
		byName:          map[string][]crateVer{},
	}
}

// resolve selects the requested crates and their dependency closure, in
// breadth-first order. Failures are reported per crate, never fatal for the
// batch.
func (r *crateResolver) resolve(ctx context.Context, specs []string) ([]crateSelection, []FailedModule) {
	if err := r.loadConfig(ctx); err != nil {
		return nil, []FailedModule{{Module: "config.json", Error: err.Error()}}
	}
	var out []crateSelection
	var failed []FailedModule
	queue := make([]crateWant, 0, len(specs))
	for _, spec := range specs {
		name, version, _ := parseCrateSpec(spec)
		queue = append(queue, crateWant{name: name, exact: version})
	}
	for len(queue) > 0 && len(out) < cratesMaxResolved {
		want := queue[0]
		queue = queue[1:]
		sel, err := r.pick(ctx, want)
		if err != nil {
			failed = append(failed, FailedModule{Module: want.name, Version: want.describe(), Error: err.Error()})
			continue
		}
		if sel == nil {
			continue // already satisfied
		}
		out = append(out, *sel)
		queue = append(queue, r.depWants(ctx, *sel)...)
	}
	return out, failed
}

// crateWant is one resolution demand: a crate pinned to an exact version, or
// constrained by a cargo requirement (dependency edges).
type crateWant struct {
	name  string
	exact string
	req   string
}

func (w crateWant) describe() string {
	if w.exact != "" {
		return w.exact
	}
	if w.req != "" {
		return w.req
	}
	return "latest"
}

// loadConfig reads the upstream registry's config.json for the download URL
// template.
func (r *crateResolver) loadConfig(ctx context.Context) error {
	b, err := httpGetBytes(ctx, r.index+"/config.json", 1<<20)
	if err != nil {
		return err
	}
	var cfg struct {
		DL string `json:"dl"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("parse registry config.json: %w", err)
	}
	if !strings.HasPrefix(cfg.DL, "http://") && !strings.HasPrefix(cfg.DL, "https://") {
		return fmt.Errorf("registry config.json dl %q is not an http(s) URL", cfg.DL)
	}
	r.dl = cfg.DL
	return nil
}

// entries returns the parsed index lines for a crate, fetching and caching the
// sparse-index file on first use.
func (r *crateResolver) entries(ctx context.Context, name string) ([]crateSelection, error) {
	key := strings.ToLower(name)
	if got, ok := r.cache[key]; ok {
		return got, nil
	}
	b, err := httpGetBytes(ctx, r.index+"/"+crateIndexPath(name), cratesMaxIndexFileBytes)
	if err != nil {
		return nil, err
	}
	entries := parseCrateIndexFile(b)
	if len(entries) == 0 {
		return nil, errors.New("index file lists no valid releases")
	}
	r.cache[key] = entries
	return entries, nil
}

// parseCrateIndexFile parses a sparse-index file into per-release selections,
// dropping lines that do not parse (the rest of the file stays usable).
// Yanked releases are kept — an exact pin may still name one — and excluded
// from "newest"/requirement selection instead.
func parseCrateIndexFile(b []byte) []crateSelection {
	var out []crateSelection
	for _, raw := range strings.Split(string(b), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var line crateIndexLine
		if json.Unmarshal([]byte(raw), &line) != nil {
			continue
		}
		if validateCrateName(line.Name) != nil || validateCrateVersion(line.Vers) != nil || len(line.Cksum) != 64 {
			continue
		}
		out = append(out, crateSelection{
			name: line.Name, version: line.Vers, cksum: strings.ToLower(line.Cksum),
			yanked: line.Yanked, raw: json.RawMessage(raw), deps: line.Deps,
		})
	}
	return out
}

// pick chooses the release satisfying one want, or nil when an already
// selected version of the crate satisfies it.
func (r *crateResolver) pick(ctx context.Context, want crateWant) (*crateSelection, error) {
	if want.req != "" && r.satisfied(want) {
		return nil, nil
	}
	entries, err := r.entries(ctx, want.name)
	if err != nil {
		return nil, err
	}
	sel, err := selectCrateRelease(entries, want)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(sel.name) + "@" + sel.version
	if r.picked[key] {
		return nil, nil
	}
	r.picked[key] = true
	if v, err := parseCrateVer(sel.version); err == nil {
		r.byName[strings.ToLower(sel.name)] = append(r.byName[strings.ToLower(sel.name)], v)
	}
	return sel, nil
}

// satisfied reports whether an already-selected version of the crate meets a
// dependency requirement, so shared dependencies resolve once like cargo does.
func (r *crateResolver) satisfied(want crateWant) bool {
	preds, err := parseCrateReq(want.req)
	if err != nil {
		return false
	}
	for _, v := range r.byName[strings.ToLower(want.name)] {
		if crateReqMatches(preds, v) {
			return true
		}
	}
	return false
}

// selectCrateRelease picks the release for a want: the exact pin (which may
// name a yanked release, like a lockfile can), the highest non-yanked release
// matching a requirement, or the highest non-yanked release overall (stable
// preferred) for a bare name.
func selectCrateRelease(entries []crateSelection, want crateWant) (*crateSelection, error) {
	if want.exact != "" {
		for i := range entries {
			if entries[i].version == want.exact {
				return &entries[i], nil
			}
		}
		return nil, fmt.Errorf("version %s not found in the index", want.exact)
	}
	var preds []cratePred
	if want.req != "" {
		var err error
		if preds, err = parseCrateReq(want.req); err != nil {
			return nil, err
		}
	}
	best := pickBestCrate(entries, preds)
	if best == nil {
		return nil, fmt.Errorf("no release satisfies %q", want.describe())
	}
	return best, nil
}

// pickBestCrate returns the highest release matching preds; with no preds it
// prefers the highest stable release and falls back to the highest
// pre-release.
func pickBestCrate(entries []crateSelection, preds []cratePred) *crateSelection {
	if preds != nil {
		return maxCrateWhere(entries, func(v crateVer) bool { return crateReqMatches(preds, v) })
	}
	if best := maxCrateWhere(entries, func(v crateVer) bool { return v.pre == "" }); best != nil {
		return best
	}
	return maxCrateWhere(entries, func(crateVer) bool { return true })
}

// maxCrateWhere returns the non-yanked entry with the highest version among
// those whose parsed version satisfies keep.
func maxCrateWhere(entries []crateSelection, keep func(crateVer) bool) *crateSelection {
	var best *crateSelection
	var bestV crateVer
	for i := range entries {
		if entries[i].yanked {
			continue
		}
		v, err := parseCrateVer(entries[i].version)
		if err != nil || !keep(v) {
			continue
		}
		if best == nil || compareCrateVer(v, bestV) > 0 {
			best, bestV = &entries[i], v
		}
	}
	return best
}

// depWants expands one selection's dependency edges into new wants: normal and
// build dependencies always, dev dependencies never, optional dependencies
// only when requested. Renamed dependencies resolve under their registry name.
func (r *crateResolver) depWants(_ context.Context, sel crateSelection) []crateWant {
	if !r.resolveDeps {
		return nil
	}
	var out []crateWant
	for _, d := range sel.deps {
		if d.Kind == "dev" || (d.Optional && !r.includeOptional) {
			continue
		}
		name := d.Name
		if d.Package != "" {
			name = d.Package
		}
		if validateCrateName(name) != nil {
			continue
		}
		out = append(out, crateWant{name: name, req: d.Req})
	}
	return out
}

// crateDlURL renders the registry's download URL for one release: explicit
// {marker}s are substituted; a template without markers gets the standard
// /{crate}/{version}/download suffix.
func crateDlURL(dl, name, version, cksum string) string {
	if !strings.Contains(dl, "{crate}") && !strings.Contains(dl, "{version}") &&
		!strings.Contains(dl, "{prefix}") && !strings.Contains(dl, "{lowerprefix}") &&
		!strings.Contains(dl, "{sha256-checksum}") {
		return dl + "/" + name + "/" + version + "/download"
	}
	prefix := path.Dir(crateIndexPath(name)) // e.g. "se/rd"
	repl := strings.NewReplacer(
		"{crate}", name,
		"{version}", version,
		"{prefix}", prefix,
		"{lowerprefix}", prefix,
		"{sha256-checksum}", cksum,
	)
	return repl.Replace(dl)
}

// downloadCrates fetches every selected .crate into the staging tree,
// verifying each against its index-declared cksum. A failed download is
// collected rather than aborting the batch.
func (s *LowServer) downloadCrates(ctx context.Context, stageRoot, dl string, selected []crateSelection) ([]CrateVersion, []ManifestFile, []FailedModule, error) {
	var records []CrateVersion
	var files []ManifestFile
	var failed []FailedModule
	for i, sel := range selected {
		emitProgress(ctx, "→ [%d/%d] %s@%s", i+1, len(selected), sel.name, sel.version)
		rel := crateFileRel(sel.name, sel.version)
		abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
		sum, size, err := downloadVerifiedFile(ctx, crateDlURL(dl, sel.name, sel.version, sel.cksum), abs, 0, "sha256", sel.cksum)
		if err != nil {
			emitProgress(ctx, "  ✗ %s@%s: %s", sel.name, sel.version, err)
			failed = append(failed, FailedModule{Module: sel.name, Version: sel.version, Error: err.Error()})
			continue
		}
		files = append(files, ManifestFile{Path: rel, SHA256: sum, Size: size})
		records = append(records, CrateVersion{
			Name: sel.name, Version: sel.version, Path: rel, SHA256: sum, IndexLine: sel.raw,
		})
	}
	return records, files, failed, nil
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeCratesBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, records []CrateVersion) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name == records[j].Name {
			return records[i].Version < records[j].Version
		}
		return records[i].Name < records[j].Name
	})
	id := bundleIDFor(streamCrates, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamCrates,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"crates"},
		Crates:           &CratesManifest{Crates: records},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamCrates, Sequence: seq, ExportedModules: len(records), BundleID: id}, nil
}
