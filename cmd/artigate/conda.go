package main

// Conda channel ecosystem adapter. The low side fetches a channel's
// per-subdir repodata.json (preferring the compressed .zst/.bz2 forms),
// greedily resolves the requested package specs and their dependency closure
// against it, downloads each package file verified against the SHA-256 its
// repodata entry declares, and packs the files — together with the verbatim
// entries — into the same numbered, signed ArtiGate bundle format used by the
// other ecosystems. The high side re-verifies every artifact against its
// entry and regenerates per-subdir repodata.json documents from the artifacts
// actually present (never serving a transferred index), so `conda install` /
// `micromamba create` against <base>/conda/<mirror> works.
//
// Memory note: a subdir's repodata is decompressed and parsed fully in
// memory. Big channels are genuinely large — conda-forge's linux-64
// repodata.json exceeds 1 GiB plain — so mirroring such channels needs a
// correspondingly generous RAM budget on the low side.

import (
	"bytes"
	"compress/bzip2"
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
	"strings"
	"time"
)

// condaEcosystem is the Conda package stream's registry entry (see ecosystems
// in ecosystem.go).
func condaEcosystem() ecosystem {
	return ecosystem{
		stream:       streamConda,
		label:        "Conda",
		title:        "Conda packages",
		collect:      (*LowServer).HandleCondaCollect,
		watchCollect: watchAdapter((*LowServer).CollectConda),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.CondaChannelBase, "conda-channel-base", "", "base URL bare conda channel names resolve under (default "+defaultCondaChannelBase+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.Conda != nil && len(m.Conda.Channels) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateCondaChannels(m.Conda.Channels, seen, m.Files)
		},
		contentDesc: "conda packages",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishConda(m.Conda) },
		serve:       (*HighServer).serveConda,
		scanTree:    segmentTreeScan((*HighServer).listCondaPackages),
		detail:      (*HighServer).condaDetail,
	}
}

// defaultCondaChannelBase hosts the public anaconda.org channels; a bare
// channel name in a collect request resolves under it.
const defaultCondaChannelBase = "https://conda.anaconda.org"

// condaMaxRepodataBytes caps one decompressed repodata.json held in memory
// for parsing. The cap is deliberately huge because real indexes are:
// conda-forge's linux-64 repodata.json is over 1 GiB plain — the price is
// paid in RAM (see the package comment), never unboundedly.
const condaMaxRepodataBytes = 8 << 30

// condaMaxResolved bounds a dependency resolution so a pathological repodata
// cannot grow a request without limit.
const condaMaxResolved = 4000

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type CondaManifest struct {
	Channels []CondaChannel `json:"channels"`
}

// CondaChannel is one mirrored conda channel (named like an APT mirror, so
// several upstreams can coexist under /conda/<name>).
type CondaChannel struct {
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Packages []CondaPackage `json:"packages"`
}

// CondaPackage records one mirrored package file. RepodataEntry is the
// verbatim upstream repodata.json entry for the file; it travels inside the
// signed manifest and its sha256 must equal the package file's SHA-256.
type CondaPackage struct {
	Subdir        string          `json:"subdir"`
	Filename      string          `json:"filename"`
	Path          string          `json:"path"`
	SHA256        string          `json:"sha256"`
	RepodataEntry json.RawMessage `json:"repodata_entry"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// condaChannelNameRE matches a bare channel name resolvable under the
// configured channel base ("conda-forge"); anything else must be a full
// http(s) URL. The first character excludes "." "_" "-" so a name can never
// be ".."/"-flag".
var condaChannelNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// condaPackageNameRE matches a conda package name. Conda normalizes names to
// lowercase; the first character excludes "." and "-" so a name can never be
// ".."/"-flag".
var condaPackageNameRE = regexp.MustCompile(`^[a-z0-9_][a-z0-9._-]*$`)

// condaSubdirRE matches a platform subdirectory ("linux-64", "osx-arm64",
// "noarch"). The first character excludes "." "_" "-" so it is path-safe.
var condaSubdirRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// condaVersionRE matches a conda version, including an "N!" epoch prefix. No
// "-", "/", or spaces, so it is path-safe and splits unambiguously from a
// build string in a "<version>-<build>" pair.
var condaVersionRE = regexp.MustCompile(`^[0-9!][0-9A-Za-z._+!]*$`)

// condaBuildRE matches a build string ("py310h5eee18b_0"). Like a version it
// carries no "-", keeping "<name>-<version>-<build>" filenames parseable.
var condaBuildRE = regexp.MustCompile(`^[0-9A-Za-z._]+$`)

// condaFilenameRE matches a package archive filename: exactly the two
// formats conda has used, starting path-safe (never "."/"-").
var condaFilenameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]*\.(conda|tar\.bz2)$`)

func validateCondaPackageName(name string) error {
	if !condaPackageNameRE.MatchString(name) {
		return fmt.Errorf("invalid conda package name %q", name)
	}
	return nil
}

func validateCondaSubdir(subdir string) error {
	if !condaSubdirRE.MatchString(subdir) {
		return fmt.Errorf("invalid conda subdir %q", subdir)
	}
	return nil
}

// condaFileRel is the repository-relative path of one package archive. The
// bundle path and the served path are the same tree, so the importer's
// byte-verified install already places files where serveConda reads them.
func condaFileRel(mirror, subdir, filename string) string {
	return path.Join("conda", mirror, subdir, filename)
}

// condaFilenameStem strips the package-format extension, reporting whether
// the filename carried one.
func condaFilenameStem(filename string) (string, bool) {
	if s, ok := strings.CutSuffix(filename, ".conda"); ok {
		return s, true
	}
	if s, ok := strings.CutSuffix(filename, ".tar.bz2"); ok {
		return s, true
	}
	return "", false
}

// condaRepodataEntry is the subset of a repodata entry ArtiGate reads. The
// verbatim entry is preserved separately; this parse only drives resolution,
// validation, and the dashboard detail.
type condaRepodataEntry struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Build       string   `json:"build"`
	BuildNumber int64    `json:"build_number"`
	Depends     []string `json:"depends"`
	License     string   `json:"license"`
	SHA256      string   `json:"sha256"`
	MD5         string   `json:"md5"`
	Size        int64    `json:"size"`
}

// condaEntryForFilename parses a package's verbatim repodata entry and checks
// the filename is exactly "<name>-<version>-<build>.<ext>" for the entry's
// own identity — so a manifest (or a stale metadata store) can never smuggle
// an artifact under a mismatched metadata record.
func condaEntryForFilename(filename string, raw json.RawMessage) (condaRepodataEntry, error) {
	if !condaFilenameRE.MatchString(filename) {
		return condaRepodataEntry{}, fmt.Errorf("invalid conda package filename %q", filename)
	}
	var entry condaRepodataEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return condaRepodataEntry{}, fmt.Errorf("conda package %s has an unparsable repodata entry: %w", filename, err)
	}
	if err := validateCondaEntryIdentity(entry); err != nil {
		return condaRepodataEntry{}, fmt.Errorf("conda package %s: %w", filename, err)
	}
	stem, _ := condaFilenameStem(filename)
	if stem != entry.Name+"-"+entry.Version+"-"+entry.Build {
		return condaRepodataEntry{}, fmt.Errorf("conda package %s does not match its repodata identity %s-%s-%s",
			filename, entry.Name, entry.Version, entry.Build)
	}
	return entry, nil
}

// validateCondaEntryIdentity checks a repodata entry's identity fields
// against the path-safe charsets everything downstream relies on.
func validateCondaEntryIdentity(e condaRepodataEntry) error {
	if err := validateCondaPackageName(e.Name); err != nil {
		return err
	}
	if !condaVersionRE.MatchString(e.Version) {
		return fmt.Errorf("invalid conda version %q", e.Version)
	}
	if !condaBuildRE.MatchString(e.Build) {
		return fmt.Errorf("invalid conda build %q", e.Build)
	}
	return nil
}

// validateCondaPackage checks one manifest package record: path-safe
// identity, the canonical storage path, and that the embedded repodata entry
// describes exactly the artifact the bundle delivers — the filename encodes
// the entry's own name/version/build, and the entry's sha256 equals both the
// record's hash and the manifest.files hash the importer byte-verifies for
// that path, so a served index entry can never disagree with its artifact.
func validateCondaPackage(mirror string, p CondaPackage, seen map[string]bool, fileSHA map[string]string) error {
	if err := validateCondaSubdir(p.Subdir); err != nil {
		return err
	}
	entry, err := condaEntryForFilename(p.Filename, p.RepodataEntry)
	if err != nil {
		return err
	}
	if p.Path != condaFileRel(mirror, p.Subdir, p.Filename) || !seen[p.Path] {
		return fmt.Errorf("conda package %s references file not listed in manifest.files: %s", p.Filename, p.Path)
	}
	if p.SHA256 == "" || strings.ToLower(entry.SHA256) != p.SHA256 || fileSHA[p.Path] != p.SHA256 {
		return fmt.Errorf("conda package %s repodata sha256 does not match the delivered artifact", p.Filename)
	}
	return nil
}

// validateCondaChannels checks every channel of a bundle manifest.
func validateCondaChannels(channels []CondaChannel, seen map[string]bool, files []ManifestFile) error {
	fileSHA := manifestFileSHAs(files)
	for _, ch := range channels {
		if err := validateCondaChannel(ch, seen, fileSHA); err != nil {
			return err
		}
	}
	return nil
}

// validateCondaChannel checks one channel: a safe mirror name and complete,
// self-consistent package records.
func validateCondaChannel(ch CondaChannel, seen map[string]bool, fileSHA map[string]string) error {
	if err := validateMirrorName(ch.Name); err != nil {
		return err
	}
	if ch.URL == "" {
		return fmt.Errorf("conda channel %s has no url", ch.Name)
	}
	if len(ch.Packages) == 0 {
		return fmt.Errorf("conda channel %s has no packages", ch.Name)
	}
	for _, p := range ch.Packages {
		if err := validateCondaPackage(ch.Name, p, seen, fileSHA); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Version ordering
// -----------------------------------------------------------------------------

// condaCompareVersions orders two conda version strings. It is a pragmatic
// subset of conda's VersionOrder — enough to pick "the newest" and evaluate
// range constraints:
//
//   - an optional "N!" epoch prefix compares first (missing epoch is 0);
//   - the remainder splits into segments on ".", "_" and "-", compared
//     pairwise with missing segments reading as 0 ("1.2" == "1.2.0");
//   - each segment splits into alternating numeric/alphabetic runs; numeric
//     runs compare numerically, alphabetic runs case-insensitively, and
//     "dev" orders below every other alphabetic run;
//   - an alphabetic run orders below a numeric (or missing) one, so a
//     trailing tag sorts before the release: "1.2.3a" < "1.2.3".
//
// Not implemented from the full VersionOrder: the "post" = +infinity special
// case and dedicated "+local" handling — those compare by the rules above.
func condaCompareVersions(a, b string) int {
	aEpoch, aRest := condaSplitEpoch(a)
	bEpoch, bRest := condaSplitEpoch(b)
	if c := condaCompareNumericRuns(aEpoch, bEpoch); c != 0 {
		return c
	}
	aSegs := condaVersionSegments(aRest)
	bSegs := condaVersionSegments(bRest)
	for i := 0; i < len(aSegs) || i < len(bSegs); i++ {
		if c := condaCompareSegments(condaAt(aSegs, i), condaAt(bSegs, i)); c != 0 {
			return c
		}
	}
	return 0
}

// condaSplitEpoch splits an optional "N!" epoch prefix off a version string;
// a version without one has epoch 0.
func condaSplitEpoch(v string) (epoch, rest string) {
	if e, r, ok := strings.Cut(v, "!"); ok {
		return e, r
	}
	return "0", v
}

// condaVersionSegments splits a version body on the separators conda treats
// alike, lowercased because conda compares case-insensitively.
func condaVersionSegments(v string) []string {
	return strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	})
}

// condaAt returns element i of a segment or run list, with missing elements
// reading as the numeric zero that pads shorter versions.
func condaAt(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return "0"
}

// condaCompareSegments compares one segment pair run by run; a missing run
// reads as numeric zero, which places "3a" before "3" (alpha < number).
func condaCompareSegments(a, b string) int {
	ar := condaSegmentRuns(a)
	br := condaSegmentRuns(b)
	for i := 0; i < len(ar) || i < len(br); i++ {
		if c := condaCompareRuns(condaAt(ar, i), condaAt(br, i)); c != 0 {
			return c
		}
	}
	return 0
}

// condaSegmentRuns splits a segment into maximal numeric and non-numeric
// runs ("12rc3" -> "12", "rc", "3").
func condaSegmentRuns(seg string) []string {
	var runs []string
	start := 0
	for i := 1; i <= len(seg); i++ {
		if i == len(seg) || condaIsDigit(seg[i]) != condaIsDigit(seg[start]) {
			runs = append(runs, seg[start:i])
			start = i
		}
	}
	return runs
}

func condaIsDigit(c byte) bool { return c >= '0' && c <= '9' }

// condaCompareRuns orders two runs: numbers numerically; an alphabetic run
// below any number (a tag marks a pre-release of the plain version); "dev"
// below every other alphabetic run; other alphabetic runs lexically.
func condaCompareRuns(a, b string) int {
	aNum, bNum := condaIsDigit(a[0]), condaIsDigit(b[0])
	switch {
	case aNum && bNum:
		return condaCompareNumericRuns(a, b)
	case aNum:
		return 1
	case bNum:
		return -1
	case a == b:
		return 0
	case a == "dev":
		return -1
	case b == "dev":
		return 1
	case a < b:
		return -1
	}
	return 1
}

// condaCompareNumericRuns compares two digit runs numerically without
// parsing: leading zeros are stripped, then a longer run is larger and
// equal-length runs compare lexically. This never overflows, whatever an
// upstream puts in a version.
func condaCompareNumericRuns(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// -----------------------------------------------------------------------------
// MatchSpec subset: specs, constraints, dependency edges
// -----------------------------------------------------------------------------

// condaConstraint is one comparator of a version constraint expression.
type condaConstraint struct {
	// op is one of "==", "!=", ">=", "<=", ">", "<", "=" (prefix match), or
	// "" for "match anything".
	op      string
	version string
}

// condaParseSpec splits a requested package spec — "name", "name==1.2.3",
// "name=1.2", "name>=1.2,<2.0", ... — into the validated name and its
// constraints.
func condaParseSpec(spec string) (string, []condaConstraint, error) {
	spec = strings.TrimSpace(spec)
	i := strings.IndexAny(spec, "=<>!")
	if i < 0 {
		return spec, nil, validateCondaPackageName(spec)
	}
	name := spec[:i]
	if err := validateCondaPackageName(name); err != nil {
		return "", nil, err
	}
	cs, err := condaParseConstraints(spec[i:])
	if err != nil {
		return "", nil, fmt.Errorf("package %s: %w", name, err)
	}
	return name, cs, nil
}

// condaParseConstraints parses a version constraint expression:
// comma-separated (AND) comparators. It is a pragmatic subset of conda's
// MatchSpec version grammar — "|" alternation and mid-string wildcards are
// rejected, so an unsupported constraint is reported instead of mis-resolved.
func condaParseConstraints(expr string) ([]condaConstraint, error) {
	var out []condaConstraint
	for _, tok := range strings.Split(expr, ",") {
		c, err := condaParseConstraint(strings.TrimSpace(tok))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// condaParseConstraint parses one comparator: "*" (any), "==1.2.3" (exact),
// "=1.2" / "1.2" / "1.2.*" / "2.7*" (prefix), or ">=", "<=", ">", "<", "!="
// comparisons.
func condaParseConstraint(tok string) (condaConstraint, error) {
	if tok == "*" {
		return condaConstraint{}, nil
	}
	op, rest := condaCutOperator(tok)
	if op == "" || op == "=" {
		// A bare or "="-prefixed version means prefix match; a trailing
		// ".*" or "*" spells the same thing explicitly.
		op = "="
		rest = strings.TrimSuffix(strings.TrimSuffix(rest, ".*"), "*")
	}
	if rest == "" || !condaVersionRE.MatchString(rest) {
		return condaConstraint{}, fmt.Errorf("unsupported version constraint %q", tok)
	}
	return condaConstraint{op: op, version: rest}, nil
}

// condaCutOperator splits a leading comparison operator off one constraint
// token; op is "" when the token is a bare version.
func condaCutOperator(tok string) (op, rest string) {
	for _, cand := range []string{"==", ">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(tok, cand) {
			return cand, strings.TrimSpace(strings.TrimPrefix(tok, cand))
		}
	}
	return "", tok
}

// condaConstraintsMatch reports whether version v satisfies every comparator
// (an empty list matches anything).
func condaConstraintsMatch(cs []condaConstraint, v string) bool {
	for _, c := range cs {
		if !condaConstraintMatches(c, v) {
			return false
		}
	}
	return true
}

// condaConstraintMatches evaluates one comparator. Prefix ("=") matches the
// version itself or any longer version under it: "=1.2" accepts 1.2 and
// 1.2.9, never 1.20. Every other operator compares by condaCompareVersions,
// so "==1.2" also accepts 1.2.0.
func condaConstraintMatches(c condaConstraint, v string) bool {
	switch c.op {
	case "":
		return true
	case "=":
		return v == c.version || strings.HasPrefix(v, c.version+".")
	case "==":
		return condaCompareVersions(v, c.version) == 0
	case "!=":
		return condaCompareVersions(v, c.version) != 0
	case ">":
		return condaCompareVersions(v, c.version) > 0
	case ">=":
		return condaCompareVersions(v, c.version) >= 0
	case "<":
		return condaCompareVersions(v, c.version) < 0
	}
	return condaCompareVersions(v, c.version) <= 0 // "<="
}

// condaParseDepend parses one repodata "depends" edge: "name",
// "name <constraints>", or "name <constraints> <build>", space-separated.
// The build part is honored only as an exact string — a wildcard build
// matcher is ignored, so the resolver may over-match a build but never a
// version.
func condaParseDepend(dep string) (name string, cs []condaConstraint, build string, err error) {
	fields := strings.Fields(dep)
	if len(fields) == 0 || len(fields) > 3 {
		return "", nil, "", fmt.Errorf("unsupported dependency %q", dep)
	}
	if err := validateCondaPackageName(fields[0]); err != nil {
		return "", nil, "", err
	}
	name = fields[0]
	if len(fields) >= 2 {
		if cs, err = condaParseConstraints(fields[1]); err != nil {
			return "", nil, "", fmt.Errorf("dependency %s: %w", name, err)
		}
	}
	if len(fields) == 3 && !strings.ContainsRune(fields[2], '*') {
		build = fields[2]
	}
	return name, cs, build, nil
}

// -----------------------------------------------------------------------------
// High side: channel serving
// -----------------------------------------------------------------------------

func (s *HighServer) condaDir() string {
	return filepath.Join(s.downloadDir, "conda")
}

// serveConda handles the conda channel routes under /conda/<mirror>/: the
// regenerated per-subdir repodata.json and the package archives. It reports
// whether it wrote a response for the request.
func (s *HighServer) serveConda(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/conda" && !strings.HasPrefix(p, "/conda/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.Trim(strings.TrimPrefix(p, "/conda"), "/")
	if validateRelPath(rel) != nil || !condaServablePath(rel) {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.condaDir(), filepath.FromSlash(rel))
	if !safeJoin(s.condaDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	if strings.HasSuffix(rel, "/repodata.json") {
		w.Header().Set("Content-Type", "application/json")
	}
	serveFile(w, r, abs)
	return true
}

// condaServablePath restricts the served tree to the two client-facing
// shapes: <mirror>/<subdir>/repodata.json and <mirror>/<subdir>/<package
// file>. The regenerated metadata store under <mirror>/metadata/ stays
// private ("metadata" would otherwise pass the subdir charset).
func condaServablePath(rel string) bool {
	segs := strings.Split(rel, "/")
	if len(segs) != 3 || validateMirrorName(segs[0]) != nil ||
		validateCondaSubdir(segs[1]) != nil || segs[1] == "metadata" {
		return false
	}
	return segs[2] == "repodata.json" || condaFilenameRE.MatchString(segs[2])
}

// -----------------------------------------------------------------------------
// High side: repodata regeneration at import
// -----------------------------------------------------------------------------

// condaRepodataInfo carries the subdir a repodata document describes.
type condaRepodataInfo struct {
	Subdir string `json:"subdir"`
}

// condaRepodata is a repodata.json document: the two maps key package
// filenames to their entries, split by the two archive formats conda has
// used. The same shape parses upstream documents on the low side and renders
// regenerated ones on the high side.
type condaRepodata struct {
	Info            condaRepodataInfo          `json:"info"`
	Packages        map[string]json.RawMessage `json:"packages"`
	PackagesConda   map[string]json.RawMessage `json:"packages.conda"`
	RepodataVersion int                        `json:"repodata_version"`
}

// publishConda regenerates the served channel metadata for every mirror in
// an imported bundle. Per-package failures are logged and skipped (the
// package stays out of repodata.json) rather than wedging the stream's
// import forever; a failed regeneration is fatal so the operator sees it.
func (s *HighServer) publishConda(m *CondaManifest) error {
	if m == nil {
		return nil
	}
	for _, ch := range m.Channels {
		if err := s.publishCondaChannel(ch); err != nil {
			return err
		}
	}
	return nil
}

// publishCondaChannel stores every package's verbatim repodata entry, then
// regenerates repodata.json for each touched subdir — plus noarch always:
// conda clients request a mirror's noarch half unconditionally and a 404
// there fails the whole solve, so at least an empty skeleton must exist even
// when nothing noarch was ever mirrored. Touched subdirs regenerate even when
// their only package failed to store, so clients get a valid (possibly
// empty) document instead of a 404.
func (s *HighServer) publishCondaChannel(ch CondaChannel) error {
	if err := validateMirrorName(ch.Name); err != nil {
		return err
	}
	subdirs := map[string]bool{"noarch": true}
	for _, p := range ch.Packages {
		if validateCondaSubdir(p.Subdir) == nil {
			subdirs[p.Subdir] = true
		}
		if err := s.publishCondaPackage(ch.Name, p); err != nil {
			log.Printf("conda publish %s/%s/%s: %v", ch.Name, p.Subdir, p.Filename, err)
		}
	}
	names := make([]string, 0, len(subdirs))
	for sd := range subdirs {
		names = append(names, sd)
	}
	sort.Strings(names)
	for _, sd := range names {
		if err := s.regenerateCondaRepodata(ch.Name, sd); err != nil {
			return err
		}
	}
	return nil
}

// publishCondaPackage re-verifies one imported package file against its
// repodata entry's sha256 and stores the compacted verbatim entry in the
// mirror's private metadata tree. Compaction matters: the bundle manifest is
// written indented, which spreads the raw entry over several lines, while
// the stored form is one canonical blob ready to embed in repodata.json.
func (s *HighServer) publishCondaPackage(mirror string, p CondaPackage) error {
	if err := validateCondaSubdir(p.Subdir); err != nil {
		return err
	}
	entry, err := condaEntryForFilename(p.Filename, p.RepodataEntry)
	if err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(p.Path))
	if !strings.HasPrefix(p.Path, "conda/") || !safeJoin(s.condaDir(), abs) {
		return fmt.Errorf("unsafe package path %s", p.Path)
	}
	sum, err := sha256File(abs)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, entry.SHA256) {
		return fmt.Errorf("artifact sha256 %s does not match the repodata entry", sum)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, p.RepodataEntry); err != nil {
		return fmt.Errorf("compact repodata entry: %w", err)
	}
	out := filepath.Join(s.condaDir(), mirror, "metadata", p.Subdir, p.Filename+".json")
	if !safeJoin(s.condaDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s", p.Filename)
	}
	return writeBytesAtomic(out, compact.Bytes(), 0o644)
}

// regenerateCondaRepodata rebuilds one mirror subdir's served repodata.json
// from the accumulated stored entries, listing only packages whose verified
// archive is still present — regenerated from stored state, never from a
// transferred index. The document is a well-formed skeleton even when the
// subdir holds nothing (noarch must always answer).
func (s *HighServer) regenerateCondaRepodata(mirror, subdir string) error {
	doc := condaRepodata{
		Info:            condaRepodataInfo{Subdir: subdir},
		Packages:        map[string]json.RawMessage{},
		PackagesConda:   map[string]json.RawMessage{},
		RepodataVersion: 1,
	}
	entries, err := os.ReadDir(filepath.Join(s.condaDir(), mirror, "metadata", subdir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		filename, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok {
			continue
		}
		raw, err := s.readCondaStoredRaw(mirror, subdir, filename)
		if err != nil {
			continue // stale, invalid, or pruned: leave it unlisted
		}
		if strings.HasSuffix(filename, ".conda") {
			doc.PackagesConda[filename] = raw
		} else {
			doc.Packages[filename] = raw
		}
	}
	out := filepath.Join(s.condaDir(), mirror, subdir, "repodata.json")
	if !safeJoin(s.condaDir(), out) {
		return fmt.Errorf("unsafe repodata path for %s/%s", mirror, subdir)
	}
	return writeJSONAtomic(out, doc, 0o644)
}

// readCondaStoredRaw loads one stored verbatim entry, gated on the identity
// still checking out and the package file still being present — pruned
// artifacts silently drop out of the regenerated index.
func (s *HighServer) readCondaStoredRaw(mirror, subdir, filename string) (json.RawMessage, error) {
	metaPath := filepath.Join(s.condaDir(), mirror, "metadata", subdir, filename+".json")
	if !safeJoin(s.condaDir(), metaPath) {
		return nil, errors.New("unsafe metadata path")
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	if _, err := condaEntryForFilename(filename, raw); err != nil {
		return nil, err
	}
	abs := filepath.Join(s.condaDir(), mirror, subdir, filename)
	if !safeJoin(s.condaDir(), abs) || !fileExists(abs) {
		return nil, errors.New("package file missing")
	}
	return raw, nil
}

// readCondaStored loads one stored entry in its parsed slim form, with the
// same gating as readCondaStoredRaw.
func (s *HighServer) readCondaStored(mirror, subdir, filename string) (condaRepodataEntry, error) {
	raw, err := s.readCondaStoredRaw(mirror, subdir, filename)
	if err != nil {
		return condaRepodataEntry{}, err
	}
	return condaEntryForFilename(filename, raw)
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listCondaPackages lists the mirrored packages as "<mirror>/<name>" with
// their "<version>-<build>" variants, from the regenerated metadata store.
func (s *HighServer) listCondaPackages() ([]UIModule, error) {
	mirrors, err := os.ReadDir(s.condaDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byPkg := map[string]map[string]bool{}
	for _, m := range mirrors {
		if m.IsDir() && validateMirrorName(m.Name()) == nil {
			s.collectCondaMirror(m.Name(), byPkg)
		}
	}
	out := make([]UIModule, 0, len(byPkg))
	for pkg, versions := range byPkg {
		out = append(out, UIModule{Module: pkg, Versions: condaSortedVersions(versions)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// collectCondaMirror accumulates one mirror's stored entries into the
// package -> version-build set.
func (s *HighServer) collectCondaMirror(mirror string, byPkg map[string]map[string]bool) {
	subdirs, err := os.ReadDir(filepath.Join(s.condaDir(), mirror, "metadata"))
	if err != nil {
		return
	}
	for _, sd := range subdirs {
		if sd.IsDir() && validateCondaSubdir(sd.Name()) == nil {
			s.collectCondaSubdir(mirror, sd.Name(), byPkg)
		}
	}
}

// collectCondaSubdir accumulates one metadata subdir's entries. The values
// form a set because the same version-build may exist in several subdirs
// (and in both archive formats).
func (s *HighServer) collectCondaSubdir(mirror, subdir string, byPkg map[string]map[string]bool) {
	entries, err := os.ReadDir(filepath.Join(s.condaDir(), mirror, "metadata", subdir))
	if err != nil {
		return
	}
	for _, e := range entries {
		filename, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok {
			continue
		}
		entry, err := s.readCondaStored(mirror, subdir, filename)
		if err != nil {
			continue
		}
		key := mirror + "/" + entry.Name
		if byPkg[key] == nil {
			byPkg[key] = map[string]bool{}
		}
		byPkg[key][entry.Version+"-"+entry.Build] = true
	}
}

// condaSortedVersions renders a version-build set ordered oldest first (the
// version part compares like conda; the raw string breaks ties).
func condaSortedVersions(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := condaCompareVersions(out[i], out[j]); c != 0 {
			return c < 0
		}
		return out[i] < out[j]
	})
	return out
}

// condaDetail describes one mirrored package build for the dashboard detail
// panel. spec is "<mirror>/<name>@<version>-<build>", split at the last "@"
// and the first "-" — neither a version nor a build may contain either
// character, so the split is unambiguous.
func (s *HighServer) condaDetail(spec string) (UIDetail, error) {
	at := strings.LastIndex(spec, "@")
	if at < 0 {
		return UIDetail{}, errors.New("invalid mirror/package@version-build")
	}
	mirror, name, okAddr := strings.Cut(spec[:at], "/")
	version, build, okVer := strings.Cut(spec[at+1:], "-")
	if !okAddr || !okVer || validateMirrorName(mirror) != nil || validateCondaPackageName(name) != nil ||
		!condaVersionRE.MatchString(version) || !condaBuildRE.MatchString(build) {
		return UIDetail{}, errors.New("invalid mirror/package@version-build")
	}
	subdir, filename, entry, err := s.findCondaStored(mirror, name+"-"+version+"-"+build)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	return s.condaDetailFor(mirror, subdir, filename, entry), nil
}

// findCondaStored locates one "<name>-<version>-<build>" stem in a mirror's
// metadata store, trying both archive formats in every subdir.
func (s *HighServer) findCondaStored(mirror, stem string) (subdir, filename string, entry condaRepodataEntry, err error) {
	subdirs, err := os.ReadDir(filepath.Join(s.condaDir(), mirror, "metadata"))
	if err != nil {
		return "", "", condaRepodataEntry{}, err
	}
	for _, sd := range subdirs {
		if !sd.IsDir() || validateCondaSubdir(sd.Name()) != nil {
			continue
		}
		for _, fn := range []string{stem + ".conda", stem + ".tar.bz2"} {
			if got, err := s.readCondaStored(mirror, sd.Name(), fn); err == nil {
				return sd.Name(), fn, got, nil
			}
		}
	}
	return "", "", condaRepodataEntry{}, errors.New("not stored")
}

// condaDetailFor renders the detail panel for one stored entry.
func (s *HighServer) condaDetailFor(mirror, subdir, filename string, entry condaRepodataEntry) UIDetail {
	fields := []UIDetailField{
		{Label: "Package", Value: entry.Name, Mono: true},
		{Label: "Version", Value: entry.Version, Mono: true},
		{Label: "Build", Value: entry.Build, Mono: true},
		{Label: "Subdir", Value: subdir, Mono: true},
		{Label: "Channel", Value: "/conda/" + mirror, Mono: true},
	}
	if len(entry.Depends) > 0 {
		fields = append(fields, UIDetailField{Label: "Depends", Value: condaDependsSummary(entry.Depends)})
	}
	if entry.License != "" {
		fields = append(fields, UIDetailField{Label: "License", Value: entry.License})
	}
	abs := filepath.Join(s.condaDir(), mirror, subdir, filename)
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "File size", Value: formatBytes(fi.Size())})
	}
	fields = append(fields, UIDetailField{Label: "SHA-256", Value: strings.ToLower(entry.SHA256), Mono: true})
	dl := "/conda/" + mirror + "/" + subdir + "/" + filename
	downloads := []UIDownload{{Label: filename, URL: dl}}
	return UIDetail{Title: entry.Name, Subtitle: entry.Version + "-" + entry.Build, Fields: fields, Downloads: downloads}
}

// condaDependsSummary shows the first few dependency edges with a count for
// the rest, keeping the panel compact for heavy packages.
func condaDependsSummary(depends []string) string {
	const show = 5
	if len(depends) <= show {
		return strings.Join(depends, ", ")
	}
	return fmt.Sprintf("%s, … (%d total)", strings.Join(depends[:show], ", "), len(depends))
}

// -----------------------------------------------------------------------------
// Low side: collect request
// -----------------------------------------------------------------------------

// CondaCollectRequest is the body of POST /admin/conda/collect.
//
// Channel is a bare channel name ("conda-forge", resolved under the
// configured channel base) or a full http(s) channel URL. Name optionally
// names the mirror under /conda/<name> on the high side; it defaults to the
// bare channel name itself, or to a slug of the URL when Channel is a full
// URL. Subdirs lists the platform subdirectories to
// resolve in ("linux-64", "osx-arm64", ...); "noarch" is always searched too
// because conda clients always pair a platform with noarch, and an empty
// list means just noarch. Packages are MatchSpec-subset specs: "name"
// (newest), "name==1.2.3" (exact), "name=1.2" (prefix), "name>=1.2,<2.0"
// (comma = AND), and the other comparison operators. NoDeps mirrors only the
// listed packages without walking their depends.
type CondaCollectRequest struct {
	Channel  string   `json:"channel"`
	Name     string   `json:"name,omitempty"`
	Subdirs  []string `json:"subdirs,omitempty"`
	Packages []string `json:"packages"`
	NoDeps   bool     `json:"no_deps,omitempty"`
	// Force disables export dedup for this collect: every package is packed
	// even when already forwarded, producing a full self-contained bundle
	// (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// condaChannelBase resolves the configured base URL bare channel names live
// under.
func (s *LowServer) condaChannelBase() string {
	base := strings.TrimSuffix(strings.TrimSpace(s.cfg.CondaChannelBase), "/")
	if base == "" {
		return defaultCondaChannelBase
	}
	return base
}

// condaChannelURL resolves a collect request's channel — a bare name or a
// full URL — to the base URL repodata and packages are fetched under.
func condaChannelURL(channel, base string) (string, error) {
	channel = strings.TrimSpace(channel)
	if condaChannelNameRE.MatchString(channel) {
		return base + "/" + channel, nil
	}
	u, err := url.Parse(channel)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("conda channel %q must be a bare channel name or an http(s) URL", channel)
	}
	return strings.TrimSuffix(channel, "/"), nil
}

// validateCondaRequest checks a collect request, deriving the mirror name,
// the resolved channel URL, and the subdir set to fetch.
func (s *LowServer) validateCondaRequest(req CondaCollectRequest) (mirror, channelURL string, subdirs []string, err error) {
	channelURL, err = condaChannelURL(req.Channel, s.condaChannelBase())
	if err != nil {
		return "", "", nil, err
	}
	if len(req.Packages) == 0 {
		return "", "", nil, errors.New("no conda packages provided")
	}
	for _, spec := range req.Packages {
		if _, _, err := condaParseSpec(spec); err != nil {
			return "", "", nil, err
		}
	}
	if subdirs, err = condaRequestSubdirs(req.Subdirs); err != nil {
		return "", "", nil, err
	}
	mirror = req.Name
	if mirror == "" {
		// A bare channel name is its own natural mirror name — the operator
		// who mirrors "conda-forge" expects /conda/conda-forge on the high
		// side. Only a full channel URL falls back to the URL slug.
		if !strings.Contains(req.Channel, "://") {
			mirror = strings.TrimSpace(req.Channel)
		} else {
			mirror = aptMirrorName(channelURL)
		}
	}
	if err := validateMirrorName(mirror); err != nil {
		return "", "", nil, err
	}
	return mirror, channelURL, subdirs, nil
}

// condaRequestSubdirs validates the requested platform subdirs and appends
// noarch when absent — a mirror without the noarch half would fail every
// client solve.
func condaRequestSubdirs(subdirs []string) ([]string, error) {
	out := make([]string, 0, len(subdirs)+1)
	seen := map[string]bool{}
	for _, sd := range subdirs {
		if err := validateCondaSubdir(sd); err != nil {
			return nil, err
		}
		if !seen[sd] {
			seen[sd] = true
			out = append(out, sd)
		}
	}
	if !seen["noarch"] {
		out = append(out, "noarch")
	}
	return out, nil
}

// HandleCondaCollect parses a JSON collect request from the admin endpoint
// and runs the collection.
func (s *LowServer) HandleCondaCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req CondaCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse conda collect request: %w", err)
		}
	}
	return s.CollectConda(ctx, req)
}

// -----------------------------------------------------------------------------
// Low side: repodata fetching and indexing
// -----------------------------------------------------------------------------

// condaFetchRepodata fetches one subdir's repodata, preferring the smaller
// compressed forms: .zst first (shelling to the zstd binary — a missing
// binary, or a channel without the file, falls through), then .bz2 (standard
// library), then plain repodata.json. Whatever form arrives, the decompressed
// document is capped at condaMaxRepodataBytes.
func condaFetchRepodata(ctx context.Context, subdirURL string) ([]byte, error) {
	doc, zstErr := condaFetchRepodataZst(ctx, subdirURL)
	if zstErr == nil {
		return doc, nil
	}
	doc, bz2Err := condaFetchRepodataBz2(ctx, subdirURL)
	if bz2Err == nil {
		return doc, nil
	}
	doc, plainErr := httpGetBytes(ctx, subdirURL+"/repodata.json", condaMaxRepodataBytes)
	if plainErr == nil {
		return doc, nil
	}
	return nil, fmt.Errorf("repodata unavailable: %w (zst: %w; bz2: %w)", plainErr, zstErr, bz2Err)
}

// condaFetchRepodataZst fetches and decompresses the zstd-compressed
// repodata. Zstd has no standard-library decoder, so this pipes through the
// zstd binary like the RPM adapter does for xz — output-capped, so a hostile
// channel cannot balloon memory past the configured ceiling.
func condaFetchRepodataZst(ctx context.Context, subdirURL string) ([]byte, error) {
	b, err := httpGetBytes(ctx, subdirURL+"/repodata.json.zst", maxIndexFetchBytes)
	if err != nil {
		return nil, err
	}
	return runFilterCmd("zstd", b, condaMaxRepodataBytes, "-d", "-c")
}

// condaFetchRepodataBz2 fetches and decompresses the bzip2-compressed
// repodata, the legacy compressed form older channels carry.
func condaFetchRepodataBz2(ctx context.Context, subdirURL string) ([]byte, error) {
	b, err := httpGetBytes(ctx, subdirURL+"/repodata.json.bz2", maxIndexFetchBytes)
	if err != nil {
		return nil, err
	}
	return condaBunzip2Capped(b, condaMaxRepodataBytes)
}

// condaBunzip2Capped decompresses a bzip2 payload, failing past limit bytes
// (decompression-bomb guard, like gunzipCapped for gzip).
func condaBunzip2Capped(b []byte, limit int64) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(b)), limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("decompressed repodata exceeds the %s cap", formatBytes(limit))
	}
	return out, nil
}

// condaCandidate is one selectable package file: its subdir and filename,
// the parsed slim entry, and the verbatim entry destined for the signed
// manifest.
type condaCandidate struct {
	subdir   string
	filename string
	entry    condaRepodataEntry
	raw      json.RawMessage
}

// condaPackageIndex maps package name -> selectable candidates across every
// fetched subdir.
type condaPackageIndex map[string][]condaCandidate

// condaFetchIndexes fetches and indexes repodata for every subdir. A subdir
// that cannot be fetched fails the collect: a silently missing platform
// would produce a mirror that cannot solve, which is worse than a loud
// error.
func condaFetchIndexes(ctx context.Context, channelURL string, subdirs []string) (condaPackageIndex, error) {
	idx := condaPackageIndex{}
	for _, sd := range subdirs {
		emitProgress(ctx, "Fetching %s/%s/repodata.json…", channelURL, sd)
		doc, err := condaFetchRepodata(ctx, channelURL+"/"+sd)
		if err != nil {
			return nil, fmt.Errorf("subdir %s: %w", sd, err)
		}
		if err := condaIndexRepodata(idx, sd, doc); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// condaIndexRepodata parses one subdir's repodata document into the index.
// When the same (name, version, build) exists in both archive formats only
// the .conda one is kept — it is the current, smaller format, and mirroring
// both would double the transfer for identical content.
func condaIndexRepodata(idx condaPackageIndex, subdir string, doc []byte) error {
	var rd condaRepodata
	if err := json.Unmarshal(doc, &rd); err != nil {
		return fmt.Errorf("parse repodata for %s: %w", subdir, err)
	}
	preferred := condaAddCandidates(idx, subdir, rd.PackagesConda, nil)
	condaAddCandidates(idx, subdir, rd.Packages, preferred)
	return nil
}

// condaAddCandidates indexes one format's entries, returning the
// (name-version-build) identities it added; skip suppresses identities
// already indexed from the preferred format. A malformed entry is dropped so
// it cannot poison the rest of the subdir.
func condaAddCandidates(idx condaPackageIndex, subdir string, entries, skip map[string]json.RawMessage) map[string]json.RawMessage {
	added := map[string]json.RawMessage{}
	for filename, raw := range entries {
		entry, err := condaEntryForFilename(filename, raw)
		if err != nil {
			continue
		}
		key := entry.Name + "-" + entry.Version + "-" + entry.Build
		if _, dup := skip[key]; dup {
			continue
		}
		added[key] = raw
		idx[entry.Name] = append(idx[entry.Name], condaCandidate{subdir: subdir, filename: filename, entry: entry, raw: raw})
	}
	return added
}

// -----------------------------------------------------------------------------
// Low side: greedy resolution
// -----------------------------------------------------------------------------

// condaResolver greedily selects package files from the fetched indexes.
// Greedy means: every requested spec and every dependency edge resolves
// independently to its best-matching candidate, and the first selection of a
// name wins — no backtracking SAT solve like conda's. That can pick a
// combination a real solver would refine, but it is predictable, cheap, and
// the operator can always pin exact versions.
type condaResolver struct {
	idx      condaPackageIndex
	noDeps   bool
	selected []condaCandidate
	byName   map[string]bool
	failed   []FailedModule
}

// condaWant is one resolution demand: a package name with the constraints
// (and optional exact build) that produced it, plus a human-readable origin
// for failure reports.
type condaWant struct {
	name  string
	cs    []condaConstraint
	build string
	desc  string
}

// resolve selects the requested specs and (unless noDeps) their dependency
// closure, breadth-first and capped at condaMaxResolved. Failures are
// reported per package, never fatal for the batch.
func (r *condaResolver) resolve(ctx context.Context, specs []string) ([]condaCandidate, []FailedModule) {
	queue := make([]condaWant, 0, len(specs))
	for _, spec := range specs {
		name, cs, _ := condaParseSpec(spec) // already validated by the request check
		queue = append(queue, condaWant{name: name, cs: cs, desc: orDefault(strings.TrimPrefix(spec, name), "latest")})
	}
	for len(queue) > 0 && len(r.selected) < condaMaxResolved {
		want := queue[0]
		queue = queue[1:]
		if r.byName[want.name] {
			continue // first selection wins
		}
		best, err := r.pick(want)
		if err != nil {
			r.failed = append(r.failed, FailedModule{Module: want.name, Version: want.desc, Error: err.Error()})
			continue
		}
		r.byName[want.name] = true
		r.selected = append(r.selected, *best)
		emitProgress(ctx, "→ %s (%s)", best.filename, best.subdir)
		queue = append(queue, r.depWants(*best)...)
	}
	return r.selected, r.failed
}

// pick chooses the best candidate for one want: the highest version, then
// the highest build number, satisfying every constraint. A winner whose
// repodata entry declares no sha256 fails the want — unverifiable bytes are
// never mirrored, the same policy npm applies to integrity-less tarballs.
func (r *condaResolver) pick(want condaWant) (*condaCandidate, error) {
	cands := r.idx[want.name]
	if len(cands) == 0 {
		return nil, errors.New("not found in the fetched repodata (check subdirs)")
	}
	var best *condaCandidate
	for i := range cands {
		c := &cands[i]
		if !condaConstraintsMatch(want.cs, c.entry.Version) {
			continue
		}
		if want.build != "" && c.entry.Build != want.build {
			continue
		}
		if best == nil || condaCandidateLess(*best, *c) {
			best = c
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no candidate satisfies %q", want.desc)
	}
	if len(best.entry.SHA256) != 64 {
		return nil, fmt.Errorf("repodata entry for %s declares no sha256; refusing to mirror unverifiable bytes", best.filename)
	}
	return best, nil
}

// condaCandidateLess orders two candidates for "pick the best": version,
// then build number, then a stable lexical tie-break so equal candidates
// resolve identically across runs (map iteration feeds them in random
// order).
func condaCandidateLess(a, b condaCandidate) bool {
	if c := condaCompareVersions(a.entry.Version, b.entry.Version); c != 0 {
		return c < 0
	}
	if a.entry.BuildNumber != b.entry.BuildNumber {
		return a.entry.BuildNumber < b.entry.BuildNumber
	}
	if a.subdir != b.subdir {
		return a.subdir > b.subdir
	}
	return a.filename > b.filename
}

// depWants expands one selection's dependency edges into new wants. Virtual
// packages ("__glibc", satisfied by the client's own system) and names
// already selected are skipped; an unparsable edge is reported so the
// operator sees exactly which constraint the pragmatic MatchSpec subset
// could not handle.
func (r *condaResolver) depWants(sel condaCandidate) []condaWant {
	if r.noDeps {
		return nil
	}
	var out []condaWant
	for _, dep := range sel.entry.Depends {
		if strings.HasPrefix(strings.TrimSpace(dep), "__") {
			continue
		}
		name, cs, build, err := condaParseDepend(dep)
		if err != nil {
			r.failed = append(r.failed, FailedModule{Module: sel.entry.Name, Version: dep, Error: err.Error()})
			continue
		}
		if r.byName[name] {
			continue
		}
		out = append(out, condaWant{name: name, cs: cs, build: build, desc: dep})
	}
	return out
}

// -----------------------------------------------------------------------------
// Low side: collection and bundle writing
// -----------------------------------------------------------------------------

// CollectConda fetches the channel's repodata for every requested subdir,
// greedily resolves the requested packages (and by default their dependency
// closure), downloads each package file with its repodata-declared SHA-256
// verified, and writes them into a signed bundle on the conda stream.
// Packages that cannot be resolved or fetched are skipped and reported so
// one of them never blocks the rest of the batch.
func (s *LowServer) CollectConda(ctx context.Context, req CondaCollectRequest) (ExportResult, error) {
	mirror, channelURL, subdirs, err := s.validateCondaRequest(req)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the conda stream's lock for the whole fetch->write->commit
	// so a concurrent conda exporter cannot claim the same sequence number
	// between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamConda)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "conda", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	idx, err := condaFetchIndexes(ctx, channelURL, subdirs)
	if err != nil {
		return ExportResult{}, err
	}
	emitProgress(ctx, "Resolving %d package spec(s)…", len(req.Packages))
	resolver := &condaResolver{idx: idx, noDeps: req.NoDeps, byName: map[string]bool{}}
	selected, skipped := resolver.resolve(ctx, req.Packages)
	if len(selected) == 0 {
		return ExportResult{}, fmt.Errorf("no conda packages could be resolved: %s", summarizeFailures(skipped))
	}
	pkgs, files, failed := s.downloadCondaPackages(ctx, stageRoot, mirror, channelURL, selected)
	failed = append(skipped, failed...)
	if len(pkgs) == 0 {
		return ExportResult{}, fmt.Errorf("no conda packages could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	channel := CondaChannel{Name: mirror, URL: channelURL, Packages: pkgs}
	res, err := s.exportIfNew(ctx, streamConda, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeCondaBundle(ctx, seq, stageRoot, files, channel)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// downloadCondaPackages fetches every selected package file into the staging
// tree, verifying each against its repodata-declared SHA-256. A failed
// download is collected rather than aborting the batch.
func (s *LowServer) downloadCondaPackages(ctx context.Context, stageRoot, mirror, channelURL string, selected []condaCandidate) ([]CondaPackage, []ManifestFile, []FailedModule) {
	var pkgs []CondaPackage
	var files []ManifestFile
	var failed []FailedModule
	for i, sel := range selected {
		emitProgress(ctx, "→ [%d/%d] %s/%s", i+1, len(selected), sel.subdir, sel.filename)
		rel := condaFileRel(mirror, sel.subdir, sel.filename)
		abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
		sum, size, err := downloadVerifiedFile(ctx, channelURL+"/"+sel.subdir+"/"+sel.filename, abs, 0, "sha256", sel.entry.SHA256)
		if err != nil {
			emitProgress(ctx, "  ✗ %s: %s", sel.filename, err)
			failed = append(failed, FailedModule{Module: sel.entry.Name, Version: sel.entry.Version + "-" + sel.entry.Build, Error: err.Error()})
			continue
		}
		pkgs = append(pkgs, CondaPackage{Subdir: sel.subdir, Filename: sel.filename, Path: rel, SHA256: sum, RepodataEntry: sel.raw})
		files = append(files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	}
	return pkgs, files, failed
}

// writeCondaBundle writes one channel's selections as a signed bundle on the
// conda stream.
func (s *LowServer) writeCondaBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, channel CondaChannel) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(channel.Packages, func(i, j int) bool { return channel.Packages[i].Path < channel.Packages[j].Path })
	id := bundleIDFor(streamConda, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamConda,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"conda"},
		Conda:            &CondaManifest{Channels: []CondaChannel{channel}},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamConda, Sequence: seq, ExportedModules: len(channel.Packages), BundleID: id}, nil
}
