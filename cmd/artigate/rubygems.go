package main

// RubyGems ecosystem adapter. The low side resolves gems against the
// compact index (rubygems.org by default), greedily walks each gem's runtime
// dependency closure, downloads the .gem archives — verifying every one
// against the index-declared sha256 checksum — and packs them into the same
// numbered, signed ArtiGate bundle format used by the other ecosystems. The
// high side serves a compact index of its own (/versions, /names,
// /info/<gem>) plus the .gem downloads, so a Gemfile can say
// `source "<base>/rubygems"`.
//
// Like the crates adapter, the manifest carries each release's verbatim
// upstream /info line inside the Ed25519-signed manifest. The high side
// never serves a line whose checksum does not equal the byte-verified
// artifact's SHA-256 (checked again at import), and regenerates every served
// index file from those verified records, gated on the .gem actually being
// present.

import (
	"context"
	"crypto/md5" //nolint:gosec // the compact-index /versions format carries an MD5 content fingerprint, not a security control
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// rubygemsEcosystem is the RubyGems stream's registry entry (see ecosystems
// in ecosystem.go).
func rubygemsEcosystem() ecosystem {
	return ecosystem{
		stream:       streamRubyGems,
		label:        "RubyGems",
		title:        "Ruby gems",
		collect:      (*LowServer).HandleRubyGemsCollect,
		watchCollect: watchAdapter((*LowServer).CollectRubyGems),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.RubyGemsURL, "rubygems-url", "", "gem server gems and their compact index are fetched from (default "+defaultRubyGemsURL+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.RubyGems != nil && len(m.RubyGems.Gems) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateRubyGems(m.RubyGems.Gems, seen, m.Files)
		},
		contentDesc: "gems",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishRubyGems(m.RubyGems) },
		serve:       (*HighServer).serveRubyGems,
		scanTree:    flatTreeScan((*HighServer).listRubyGems),
		detail:      (*HighServer).rubygemsDetail,
	}
}

// defaultRubyGemsURL is the gem server gems and their compact index are
// fetched from when no override is configured.
const defaultRubyGemsURL = "https://rubygems.org"

// rubygemsMaxResolved bounds a dependency closure so a pathological index
// cannot grow a request without limit.
const rubygemsMaxResolved = 2000

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type RubyGemsManifest struct {
	Gems []GemVersion `json:"gems"`
}

// GemVersion records one mirrored gem release. InfoLine is the verbatim
// upstream compact-index /info/<name> line for the release; it travels inside
// the signed manifest and its checksum must equal the .gem file's SHA-256.
type GemVersion struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform,omitempty"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	InfoLine string `json:"info_line"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// gemNameRE matches a path-safe gem name. The first character excludes ".",
// "_", and "-" so a name can never be ".."/"-flag".
var gemNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// gemVersionRE matches a gem version: dotted digits with letter segments for
// prereleases. RubyGems versions never contain "-" — in a filename or a
// compact-index version token the "-" separates the platform — so a version
// always starts with a digit and is path-safe.
var gemVersionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.]{0,63}$`)

// gemPlatformRE matches a gem platform ("x86_64-linux", "java", ...), which
// never starts with "." or "-", so it is path-safe.
var gemPlatformRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

// gemChecksumRE matches the sha256 hex checksum every compact-index info
// line carries.
var gemChecksumRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// validateGemName checks a gem name against gemNameRE.
func validateGemName(name string) error {
	if !gemNameRE.MatchString(name) {
		return fmt.Errorf("invalid gem name %q", name)
	}
	return nil
}

// validateGemVersion checks a gem version against gemVersionRE.
func validateGemVersion(v string) error {
	if !gemVersionRE.MatchString(v) {
		return fmt.Errorf("invalid gem version %q", v)
	}
	return nil
}

// validateGemPlatform checks a non-empty gem platform against gemPlatformRE.
func validateGemPlatform(p string) error {
	if !gemPlatformRE.MatchString(p) {
		return fmt.Errorf("invalid gem platform %q", p)
	}
	return nil
}

// gemVersionFull is the version token of a release: "1.2.3" for the
// pure-ruby gem, "1.2.3-x86_64-linux" for a platform variant.
func gemVersionFull(version, platform string) string {
	if platform == "" {
		return version
	}
	return version + "-" + platform
}

// parseGemVersionToken splits a "version[-platform]" token. RubyGems
// versions never contain "-", so the first "-" starts the platform.
func parseGemVersionToken(token string) (version, platform string, err error) {
	version, platform, _ = strings.Cut(token, "-")
	if err := validateGemVersion(version); err != nil {
		return "", "", err
	}
	if platform != "" {
		if err := validateGemPlatform(platform); err != nil {
			return "", "", err
		}
	}
	return version, platform, nil
}

// gemFilename is the canonical artifact name of a release,
// "<name>-<version>[-<platform>].gem".
func gemFilename(name, version, platform string) string {
	return name + "-" + gemVersionFull(version, platform) + ".gem"
}

// gemFileRel is the repository-relative path of one .gem artifact.
func gemFileRel(filename string) string {
	return path.Join("rubygems", "gems", filename)
}

// -----------------------------------------------------------------------------
// Compact-index info lines
// -----------------------------------------------------------------------------

// gemInfoLine is the parsed form of one compact-index /info line. Raw
// preserves the exact upstream bytes — the signed manifest and the
// regenerated index carry the line verbatim; the parsed fields drive
// resolution and validation only.
type gemInfoLine struct {
	Version  string
	Platform string
	Deps     []gemDep
	Checksum string
	Ruby     string
	RubyGems string
	Raw      string
}

// gemDep is one runtime dependency edge of an info line: the gem's name and
// its "&"-joined requirement constraints.
type gemDep struct {
	Name string
	Reqs []string
}

// parseGemInfoFile parses a compact-index /info payload into its release
// lines, skipping the "---" header and lines that do not parse (the rest of
// the file stays usable).
func parseGemInfoFile(b []byte) ([]gemInfoLine, error) {
	var out []gemInfoLine
	for _, raw := range strings.Split(string(b), "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "" || raw == "---" {
			continue
		}
		line, err := parseGemInfoLine(raw)
		if err != nil {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, errors.New("info file lists no valid releases")
	}
	return out, nil
}

// parseGemInfoLine parses one compact-index info line:
//
//	VERSION[-PLATFORM] [NAME:REQ,NAME:REQ,...]|KEY:VALUE,KEY:VALUE,...
//
// A dependency requirement may join several constraints with "&"
// (">= 1.0&< 2.a"); the section right of the LAST "|" carries checksum
// (always present), ruby, rubygems, and created_at.
func parseGemInfoLine(raw string) (gemInfoLine, error) {
	cut := strings.LastIndexByte(raw, '|')
	if cut < 0 {
		return gemInfoLine{}, fmt.Errorf("info line has no requirement section: %q", raw)
	}
	token, depsField, _ := strings.Cut(strings.TrimSpace(raw[:cut]), " ")
	version, platform, err := parseGemVersionToken(token)
	if err != nil {
		return gemInfoLine{}, fmt.Errorf("info line %q: %w", raw, err)
	}
	deps, err := parseGemDeps(depsField)
	if err != nil {
		return gemInfoLine{}, fmt.Errorf("info line %q: %w", raw, err)
	}
	reqs := parseGemReqs(raw[cut+1:])
	if !gemChecksumRE.MatchString(reqs["checksum"]) {
		return gemInfoLine{}, fmt.Errorf("info line has no sha256 checksum: %q", raw)
	}
	return gemInfoLine{
		Version:  version,
		Platform: platform,
		Deps:     deps,
		Checksum: reqs["checksum"],
		Ruby:     reqs["ruby"],
		RubyGems: reqs["rubygems"],
		Raw:      raw,
	}, nil
}

// parseGemDeps parses an info line's comma-separated dependency list; each
// item is "name:req" split on the first ":".
func parseGemDeps(field string) ([]gemDep, error) {
	if field == "" {
		return nil, nil
	}
	var deps []gemDep
	for _, item := range strings.Split(field, ",") {
		name, req, ok := strings.Cut(strings.TrimSpace(item), ":")
		if !ok || validateGemName(name) != nil {
			return nil, fmt.Errorf("invalid dependency %q", item)
		}
		deps = append(deps, gemDep{Name: name, Reqs: gemSplitReqs(req)})
	}
	return deps, nil
}

// gemSplitReqs splits an "&"-joined constraint list, trimming each part.
func gemSplitReqs(req string) []string {
	parts := strings.Split(req, "&")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// parseGemReqs parses the requirement section right of the last "|":
// comma-separated key:value pairs, each split on the first ":" (values like
// created_at timestamps contain more colons). A comma-separated piece with
// no ":" of its own is folded back into the previous value — defensive only,
// the upstream joins multiple constraints with "&" instead.
func parseGemReqs(field string) map[string]string {
	out := map[string]string{}
	lastKey := ""
	for _, item := range strings.Split(field, ",") {
		key, val, ok := strings.Cut(item, ":")
		if !ok {
			if lastKey != "" {
				out[lastKey] += "," + item
			}
			continue
		}
		lastKey = strings.TrimSpace(key)
		out[lastKey] = strings.TrimSpace(val)
	}
	return out
}

// -----------------------------------------------------------------------------
// Gem::Version ordering and Gem::Requirement matching
// -----------------------------------------------------------------------------

// gemCompareVersions orders two versions with Gem::Version semantics: dotted
// segments compare pairwise (numerically when both are numeric), a missing
// segment counts as zero, and an alphabetic segment — a prerelease marker —
// sorts before any numeric one ("1.0.a" < "1.0.0").
func gemCompareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if c := gemCompareSegment(gemSegmentAt(as, i), gemSegmentAt(bs, i)); c != 0 {
			return c
		}
	}
	return 0
}

// gemSegmentAt returns the i-th dotted segment, padding missing ones with
// "0" so "1.0" equals "1.0.0".
func gemSegmentAt(segs []string, i int) string {
	if i < len(segs) {
		return segs[i]
	}
	return "0"
}

// gemCompareSegment orders one segment pair: numeric vs numeric compares
// numerically, alphabetic vs alphabetic lexically, and an alphabetic segment
// sorts before a numeric one.
func gemCompareSegment(a, b string) int {
	an, aerr := parseVersionInt(a)
	bn, berr := parseVersionInt(b)
	switch {
	case aerr == nil && berr == nil:
		return cmpInt64(an, bn)
	case aerr == nil: // b is alphabetic and sorts first
		return 1
	case berr == nil:
		return -1
	}
	return strings.Compare(a, b)
}

// gemIsPrerelease reports whether a version is a prerelease: RubyGems marks
// prereleases with a letter segment ("1.1.0.beta.1").
func gemIsPrerelease(v string) bool {
	return strings.IndexFunc(v, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}) >= 0
}

// gemTokenLess orders two version tokens for the served index: versions
// ascending, the pure-ruby release before its platform variants, platforms
// lexically.
func gemTokenLess(a, b string) bool {
	av, ap, _ := strings.Cut(a, "-")
	bv, bp, _ := strings.Cut(b, "-")
	if c := gemCompareVersions(av, bv); c != 0 {
		return c < 0
	}
	return ap < bp
}

// gemReqsSatisfied reports whether version v satisfies every constraint of
// an "&"-joined dependency requirement.
func gemReqsSatisfied(reqs []string, v string) bool {
	for _, r := range reqs {
		if !gemReqSatisfied(r, v) {
			return false
		}
	}
	return true
}

// gemReqSatisfied reports whether version v satisfies one Gem::Requirement
// constraint ("= 1.2", ">= 1.0", "~> 3.0.3", ...). ">= 0" accepts anything —
// like the RubyGems default requirement, including prereleases such as
// "0.0.a" that would otherwise compare below "0". A constraint with no
// operator means "=".
func gemReqSatisfied(constraint, v string) bool {
	op, bound := gemCutOperator(constraint)
	if op == ">=" && bound == "0" {
		return true
	}
	if validateGemVersion(bound) != nil {
		return false
	}
	c := gemCompareVersions(v, bound)
	switch op {
	case "=":
		return c == 0
	case "!=":
		return c != 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	}
	// "~>": at least the bound, below the increment of its parent segment.
	upper, ok := gemTildeUpper(bound)
	return ok && c >= 0 && gemCompareVersions(v, upper) < 0
}

// gemCutOperator splits a constraint into its operator and version; a bare
// version means "=".
func gemCutOperator(c string) (op, ver string) {
	c = strings.TrimSpace(c)
	for _, cand := range []string{"~>", ">=", "<=", "!=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(c, cand); ok {
			return cand, strings.TrimSpace(rest)
		}
	}
	return "=", c
}

// gemTildeUpper is the exclusive upper bound of a "~>" constraint: the last
// segment is dropped (when there is more than one) and the new last segment
// incremented, so "~> 3.0" allows < 4 and "~> 3.0.3" allows < 3.1.
func gemTildeUpper(bound string) (string, bool) {
	segs := strings.Split(bound, ".")
	if len(segs) > 1 {
		segs = segs[:len(segs)-1]
	}
	n, err := parseVersionInt(segs[len(segs)-1])
	if err != nil {
		return "", false
	}
	segs[len(segs)-1] = strconv.FormatInt(n+1, 10)
	return strings.Join(segs, "."), true
}

// -----------------------------------------------------------------------------
// Import-side manifest validation
// -----------------------------------------------------------------------------

// validateRubyGems checks every gem record of a bundle manifest.
func validateRubyGems(gems []GemVersion, seen map[string]bool, files []ManifestFile) error {
	fileSHA := manifestFileSHAs(files)
	for _, g := range gems {
		if err := validateGemRecord(g, seen, fileSHA); err != nil {
			return err
		}
	}
	return nil
}

// validateGemRecord checks one manifest record: path-safe identity, the
// canonical storage path, and that the embedded verbatim info line describes
// exactly the artifact the bundle delivers — its version token matches the
// record, and its checksum equals both the record's own claim and the
// manifest.files hash the importer byte-verifies for that path, so a served
// info line can never disagree with its artifact.
func validateGemRecord(g GemVersion, seen map[string]bool, fileSHA map[string]string) error {
	if err := validateGemIdentity(g); err != nil {
		return err
	}
	if g.Filename != gemFilename(g.Name, g.Version, g.Platform) {
		return fmt.Errorf("gem %s@%s has non-canonical filename %s", g.Name, gemVersionFull(g.Version, g.Platform), g.Filename)
	}
	if g.Path != gemFileRel(g.Filename) || !seen[g.Path] {
		return fmt.Errorf("gem %s@%s references file not listed in manifest.files: %s", g.Name, g.Version, g.Path)
	}
	if strings.ContainsAny(g.InfoLine, "\r\n") {
		return fmt.Errorf("gem %s@%s info line is not a single line", g.Name, g.Version)
	}
	line, err := parseGemInfoLine(g.InfoLine)
	if err != nil {
		return fmt.Errorf("gem %s@%s has an unparsable info line: %w", g.Name, g.Version, err)
	}
	if line.Version != g.Version || line.Platform != g.Platform {
		return fmt.Errorf("gem %s@%s info line names version %s", g.Name, gemVersionFull(g.Version, g.Platform), gemVersionFull(line.Version, line.Platform))
	}
	if g.SHA256 == "" || !strings.EqualFold(line.Checksum, g.SHA256) || !strings.EqualFold(fileSHA[g.Path], g.SHA256) {
		return fmt.Errorf("gem %s@%s info line checksum does not match the delivered artifact", g.Name, g.Version)
	}
	return nil
}

// validateGemIdentity checks a record's name, version, and platform charset
// (all three end up in served paths).
func validateGemIdentity(g GemVersion) error {
	if err := validateGemName(g.Name); err != nil {
		return err
	}
	if err := validateGemVersion(g.Version); err != nil {
		return fmt.Errorf("gem %s: %w", g.Name, err)
	}
	if g.Platform != "" {
		if err := validateGemPlatform(g.Platform); err != nil {
			return fmt.Errorf("gem %s: %w", g.Name, err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: compact-index serving
// -----------------------------------------------------------------------------

// rubygemsDir is the root of the mirrored RubyGems repository.
func (s *HighServer) rubygemsDir() string {
	return filepath.Join(s.downloadDir, "rubygems")
}

// rubygemsGemsDir holds the verified .gem artifacts (the bundle paths).
func (s *HighServer) rubygemsGemsDir() string {
	return filepath.Join(s.rubygemsDir(), "gems")
}

// rubygemsMetadataDir holds the private per-gem accumulated info lines.
func (s *HighServer) rubygemsMetadataDir() string {
	return filepath.Join(s.rubygemsDir(), "metadata")
}

// rubygemsIndexDir holds the regenerated, served compact-index files.
func (s *HighServer) rubygemsIndexDir() string {
	return filepath.Join(s.rubygemsDir(), "index")
}

// serveRubyGems handles the compact-index routes under /rubygems/ — the
// regenerated /versions, /names, and /info/<gem> files — plus the .gem
// downloads. The legacy Marshal index (specs.4.8.gz, quick/, and the
// api/v1/dependencies endpoint) is deliberately not served: Bundler and
// modern RubyGems clients use the compact index. It reports whether it wrote
// a response for the request.
func (s *HighServer) serveRubyGems(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/rubygems" && !strings.HasPrefix(p, "/rubygems/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.Trim(strings.TrimPrefix(p, "/rubygems"), "/")
	file, ok := rubygemsServableFile(rel)
	if validateRelPath(rel) != nil || !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.rubygemsDir(), filepath.FromSlash(file))
	if !safeJoin(s.rubygemsDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	if !strings.HasSuffix(file, ".gem") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	serveFile(w, r, abs)
	return true
}

// rubygemsServableFile maps a request path under /rubygems/ to the file
// served from the rubygems tree, restricting it to the client-facing compact
// index and the .gem downloads. The private metadata store and the internal
// index layout stay hidden.
func rubygemsServableFile(rel string) (string, bool) {
	segs := strings.Split(rel, "/")
	switch {
	case len(segs) == 1 && (segs[0] == "versions" || segs[0] == "names"):
		return path.Join("index", segs[0]), true
	case len(segs) == 2 && segs[0] == "info" && validateGemName(segs[1]) == nil:
		return path.Join("index", "info", segs[1]), true
	case len(segs) == 2 && segs[0] == "gems" && gemDownloadName(segs[1]):
		return path.Join("gems", segs[1]), true
	}
	return "", false
}

// gemDownloadName reports whether a download segment is a well-formed
// "<name>-<version>[-<platform>].gem" filename. Gem names may themselves
// contain "-", so the version is the first "-"-separated token that parses
// as a version; everything after it is the platform.
func gemDownloadName(seg string) bool {
	stem, ok := strings.CutSuffix(seg, ".gem")
	if !ok {
		return false
	}
	parts := strings.Split(stem, "-")
	for i := 1; i < len(parts); i++ {
		if validateGemVersion(parts[i]) != nil {
			continue
		}
		name := strings.Join(parts[:i], "-")
		platform := strings.Join(parts[i+1:], "-")
		if validateGemName(name) != nil {
			continue
		}
		if platform == "" || validateGemPlatform(platform) == nil {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// High side: index regeneration at import
// -----------------------------------------------------------------------------

// gemStoredInfo is the per-gem metadata the high side accumulates at import
// time: the verified verbatim info line per version token. Every served
// compact-index file is regenerated from these, gated on the .gem artifact
// actually being present.
type gemStoredInfo struct {
	Lines map[string]string `json:"lines"`
}

// publishRubyGems re-verifies every imported release against its embedded
// info line, folds the verified lines into the per-gem metadata store, and
// regenerates the served compact index. A record that cannot be published is
// logged and skipped (that release stays out of the index) rather than
// wedging the stream's import forever.
func (s *HighServer) publishRubyGems(m *RubyGemsManifest) error {
	if m == nil {
		return nil
	}
	published := 0
	for _, g := range m.Gems {
		if err := s.publishGemRecord(g); err != nil {
			log.Printf("rubygems publish %s@%s: %v", g.Name, gemVersionFull(g.Version, g.Platform), err)
			continue
		}
		published++
	}
	if published == 0 {
		return nil
	}
	return s.regenerateRubyGemsIndex()
}

// publishGemRecord re-verifies one release — the installed artifact's
// SHA-256 must equal its info line's checksum — and upserts the verbatim
// line into the gem's accumulated metadata.
func (s *HighServer) publishGemRecord(g GemVersion) error {
	if err := validateGemIdentity(g); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(g.Path))
	if !strings.HasPrefix(g.Path, "rubygems/gems/") || !safeJoin(s.rubygemsGemsDir(), abs) {
		return fmt.Errorf("unsafe gem path %s", g.Path)
	}
	line, err := parseGemInfoLine(g.InfoLine)
	if err != nil {
		return err
	}
	if line.Version != g.Version || line.Platform != g.Platform {
		return fmt.Errorf("info line names version %s", gemVersionFull(line.Version, line.Platform))
	}
	sum, err := sha256File(abs)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, line.Checksum) {
		return errors.New("info line checksum does not match the installed artifact")
	}
	return s.upsertGemLine(g.Name, gemVersionFull(g.Version, g.Platform), g.InfoLine)
}

// upsertGemLine merges one verified info line into a gem's metadata store,
// keeping the lines earlier bundles delivered.
func (s *HighServer) upsertGemLine(name, token, line string) error {
	st, err := s.readGemStored(name)
	if err != nil {
		return err
	}
	st.Lines[token] = line
	out := filepath.Join(s.rubygemsMetadataDir(), name+".json")
	if !safeJoin(s.rubygemsMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s", name)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// readGemStored loads one gem's accumulated metadata; a missing file is an
// empty store.
func (s *HighServer) readGemStored(name string) (gemStoredInfo, error) {
	st := gemStoredInfo{Lines: map[string]string{}}
	p := filepath.Join(s.rubygemsMetadataDir(), name+".json")
	if !safeJoin(s.rubygemsMetadataDir(), p) {
		return st, errors.New("unsafe metadata path")
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("stored metadata for %s: %w", name, err)
	}
	if st.Lines == nil {
		st.Lines = map[string]string{}
	}
	return st, nil
}

// regenerateRubyGemsIndex rebuilds the whole served compact index — every
// per-gem /info file plus the /versions and /names lists — from the
// accumulated metadata, listing only releases whose verified .gem artifact
// is present. os.ReadDir returns entries sorted by filename, so both lists
// come out sorted by gem name.
func (s *HighServer) regenerateRubyGemsIndex() error {
	entries, err := os.ReadDir(s.rubygemsMetadataDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	names := []string{}
	versionLines := []string{}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok || validateGemName(name) != nil {
			continue
		}
		line, err := s.regenerateGemInfoFile(name)
		if err != nil {
			log.Printf("rubygems index %s: %v", name, err)
			continue
		}
		if line == "" {
			continue // no release with a present artifact
		}
		names = append(names, name)
		versionLines = append(versionLines, line)
	}
	if err := s.writeRubyGemsVersions(versionLines); err != nil {
		return err
	}
	return s.writeRubyGemsNames(names)
}

// regenerateGemInfoFile rebuilds one gem's served /info file from its stored
// verified lines, gated on each release's .gem artifact still being present,
// and returns the gem's /versions entry ("<name> <token,...> <md5>") — ""
// when nothing is present (any stale info file is removed).
func (s *HighServer) regenerateGemInfoFile(name string) (string, error) {
	out := filepath.Join(s.rubygemsIndexDir(), "info", name)
	if !safeJoin(s.rubygemsIndexDir(), out) {
		return "", fmt.Errorf("unsafe info path for %q", name)
	}
	st, err := s.readGemStored(name)
	if err != nil {
		return "", err
	}
	keys := s.gemPresentKeys(name, st)
	if len(keys) == 0 {
		if err := os.Remove(out); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", nil
	}
	var b strings.Builder
	b.WriteString("---\n")
	for _, key := range keys {
		b.WriteString(st.Lines[key])
		b.WriteByte('\n')
	}
	content := []byte(b.String())
	if err := writeBytesAtomic(out, content, 0o644); err != nil {
		return "", err
	}
	return name + " " + strings.Join(keys, ",") + " " + gemMD5Hex(content), nil
}

// gemPresentKeys returns the stored version tokens whose (validated) .gem
// artifact is present on disk, sorted like the served info file: versions
// ascending, the pure-ruby gem before its platform variants.
func (s *HighServer) gemPresentKeys(name string, st gemStoredInfo) []string {
	keys := make([]string, 0, len(st.Lines))
	for token := range st.Lines {
		version, platform, err := parseGemVersionToken(token)
		if err != nil || strings.ContainsAny(st.Lines[token], "\r\n") {
			continue
		}
		abs := filepath.Join(s.rubygemsGemsDir(), gemFilename(name, version, platform))
		if safeJoin(s.rubygemsGemsDir(), abs) && fileExists(abs) {
			keys = append(keys, token)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return gemTokenLess(keys[i], keys[j]) })
	return keys
}

// writeRubyGemsVersions rebuilds the served /versions list from scratch: the
// compact-index header, then one line per gem naming its present version
// tokens (in info-file order) and the MD5 of the served info file content
// that Bundler re-checks.
func (s *HighServer) writeRubyGemsVersions(lines []string) error {
	var b strings.Builder
	b.WriteString("created_at: " + time.Now().UTC().Format(time.RFC3339) + "\n---\n")
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return writeBytesAtomic(filepath.Join(s.rubygemsIndexDir(), "versions"), []byte(b.String()), 0o644)
}

// writeRubyGemsNames rebuilds the served /names list (every mirrored gem,
// one per line) that Bundler fetches occasionally.
func (s *HighServer) writeRubyGemsNames(names []string) error {
	var b strings.Builder
	b.WriteString("---\n")
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte('\n')
	}
	return writeBytesAtomic(filepath.Join(s.rubygemsIndexDir(), "names"), []byte(b.String()), 0o644)
}

// gemMD5Hex is the MD5 content fingerprint the compact-index /versions
// format carries for each info file, computed from the same bytes the file
// was written with.
func gemMD5Hex(b []byte) string {
	h := md5.Sum(b) //nolint:gosec // compact-index content fingerprint, not a security control
	return hex.EncodeToString(h[:])
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listRubyGems groups the mirrored releases by gem name with their
// version[-platform] tokens, from the regenerated metadata store, gated on
// the .gem artifact being present.
func (s *HighServer) listRubyGems() ([]UIModule, error) {
	entries, err := os.ReadDir(s.rubygemsMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIModule
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok || validateGemName(name) != nil {
			continue
		}
		st, err := s.readGemStored(name)
		if err != nil {
			continue
		}
		if keys := s.gemPresentKeys(name, st); len(keys) > 0 {
			out = append(out, UIModule{Module: name, Versions: keys})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// rubygemsDetail describes one mirrored release for the dashboard detail
// panel. spec is "<name>@<version[-platform]>".
func (s *HighServer) rubygemsDetail(spec string) (UIDetail, error) {
	name, token, ok := strings.Cut(spec, "@")
	var version, platform string
	var err error
	if ok {
		version, platform, err = parseGemVersionToken(token)
	}
	if !ok || err != nil || validateGemName(name) != nil {
		return UIDetail{}, errors.New("invalid gem@version")
	}
	st, err := s.readGemStored(name)
	filename := gemFilename(name, version, platform)
	abs := filepath.Join(s.rubygemsGemsDir(), filename)
	if err != nil || st.Lines[token] == "" || !fileExists(abs) {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Gem", Value: name, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	if platform != "" {
		fields = append(fields, UIDetailField{Label: "Platform", Value: platform, Mono: true})
	}
	fields = append(fields, gemLineDetailFields(st.Lines[token])...)
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "File size", Value: formatBytes(fi.Size())})
	}
	if sum, err := s.detailDigests.get(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	fields = append(fields, UIDetailField{Label: "Registry path", Value: "/rubygems/gems/" + filename, Mono: true})
	downloads := []UIDownload{{Label: filename, URL: "/rubygems/gems/" + filename}}
	return UIDetail{Title: name, Subtitle: token, Fields: fields, Downloads: downloads}, nil
}

// gemLineDetailFields renders a stored info line's parsed ruby/rubygems
// requirements and dependency count, when the line parses.
func gemLineDetailFields(raw string) []UIDetailField {
	line, err := parseGemInfoLine(raw)
	if err != nil {
		return nil
	}
	var out []UIDetailField
	if line.Ruby != "" {
		out = append(out, UIDetailField{Label: "Requires ruby", Value: line.Ruby, Mono: true})
	}
	if line.RubyGems != "" {
		out = append(out, UIDetailField{Label: "Requires rubygems", Value: line.RubyGems, Mono: true})
	}
	return append(out, UIDetailField{Label: "Dependencies", Value: strconv.Itoa(len(line.Deps))})
}

// -----------------------------------------------------------------------------
// Low side: compact-index resolver/collector
// -----------------------------------------------------------------------------

// RubyGemsCollectRequest is the body of POST /admin/rubygems/collect.
type RubyGemsCollectRequest struct {
	// Gems lists the gems to mirror: "name" for the newest release or
	// "name@1.2.3" to pin. The runtime dependency closure of each gem is
	// mirrored with it.
	Gems []string `json:"gems"`
	// Platforms additionally mirrors platform-specific variants
	// (e.g. "x86_64-linux") of every selected version when the upstream
	// publishes them; the pure-ruby gem is always mirrored.
	Platforms []string `json:"platforms,omitempty"`
	// NoDeps mirrors only the listed gems, skipping the dependency closure.
	NoDeps bool `json:"no_deps,omitempty"`
	// Force disables export dedup for this collect: every gem is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseGemSpec splits "name" or "name@version".
func parseGemSpec(spec string) (name, version string, err error) {
	name, version, _ = strings.Cut(strings.TrimSpace(spec), "@")
	if err := validateGemName(name); err != nil {
		return "", "", err
	}
	if version != "" && version != "latest" {
		if err := validateGemVersion(version); err != nil {
			return "", "", fmt.Errorf("gem %s: %w", name, err)
		}
		return name, version, nil
	}
	return name, "", nil
}

// validateRubyGemsRequest checks the collect request's gem specs and
// platform names.
func validateRubyGemsRequest(req RubyGemsCollectRequest) error {
	if len(req.Gems) == 0 {
		return errors.New("no gems provided")
	}
	for _, spec := range req.Gems {
		if _, _, err := parseGemSpec(spec); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, p := range req.Platforms {
		if err := validateGemPlatform(p); err != nil {
			return err
		}
		if seen[p] {
			return fmt.Errorf("platform %q listed twice", p)
		}
		seen[p] = true
	}
	return nil
}

// rubygemsBase resolves the configured upstream gem server base URL.
func (s *LowServer) rubygemsBase() string {
	base := strings.TrimSuffix(strings.TrimSpace(s.cfg.RubyGemsURL), "/")
	if base == "" {
		return defaultRubyGemsURL
	}
	return base
}

// HandleRubyGemsCollect parses a JSON collect request from the admin
// endpoint and runs the collection.
func (s *LowServer) HandleRubyGemsCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req RubyGemsCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse rubygems collect request: %w", err)
		}
	}
	return s.CollectRubyGems(ctx, req)
}

// CollectRubyGems resolves the requested gems (and by default their runtime
// dependency closure) against the upstream compact index, downloads every
// .gem with its index-declared checksum verified, and writes them into a
// signed bundle on the rubygems stream. Gems that cannot be resolved or
// fetched are skipped and reported so one of them never blocks the rest of
// the batch.
func (s *LowServer) CollectRubyGems(ctx context.Context, req RubyGemsCollectRequest) (ExportResult, error) {
	if err := validateRubyGemsRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the rubygems stream's lock for the whole resolve->download->
	// write->commit so a concurrent rubygems exporter cannot claim the same
	// sequence number between peek and commit. Other streams export in
	// parallel.
	mu := s.streamLock(streamRubyGems)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "rubygems", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	base := s.rubygemsBase()
	emitProgress(ctx, "Resolving %d gem(s) against %s…", len(req.Gems), base)
	dl := &gemDownloader{base: base, stageRoot: stageRoot, platforms: req.Platforms, noDeps: req.NoDeps}
	dl.run(ctx, req.Gems)
	if len(dl.gems) == 0 {
		return ExportResult{}, fmt.Errorf("no gems could be fetched: %s", summarizeFailures(dl.failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(dl.files))

	res, err := s.exportIfNew(ctx, streamRubyGems, stageRoot, dl.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeRubyGemsBundle(ctx, seq, stageRoot, dl.files, dl.gems)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = dl.failed
	return res, nil
}

// gemDownloader resolves the requested gems against the upstream compact
// index and downloads each selected release once. Resolution is greedy: the
// first version selected for a gem wins, and later dependency edges on the
// same gem are not re-checked against it — trading resolver exactness for
// the simplicity a mirror can afford (Bundler re-resolves against whatever
// set the high side serves).
type gemDownloader struct {
	base      string
	stageRoot string
	platforms []string
	noDeps    bool
	infos     map[string][]gemInfoLine
	selected  map[string]bool
	gems      []GemVersion
	files     []ManifestFile
	failed    []FailedModule
}

// gemWant is one resolution demand: a requested gem (optionally pinned to an
// exact version) or a dependency edge's "&"-joined constraints.
type gemWant struct {
	name string
	pin  string
	reqs []string
}

// describe names the version demand for failure reports.
func (w gemWant) describe() string {
	if w.pin != "" {
		return w.pin
	}
	if len(w.reqs) > 0 {
		return strings.Join(w.reqs, " & ")
	}
	return "latest"
}

// run resolves and downloads the requested specs and their dependency
// closure in breadth-first order, bounded by rubygemsMaxResolved.
func (d *gemDownloader) run(ctx context.Context, specs []string) {
	d.infos = map[string][]gemInfoLine{}
	d.selected = map[string]bool{}
	queue := make([]gemWant, 0, len(specs))
	for _, spec := range specs {
		name, pin, _ := parseGemSpec(spec)
		queue = append(queue, gemWant{name: name, pin: pin})
	}
	for len(queue) > 0 && len(d.selected) < rubygemsMaxResolved {
		want := queue[0]
		queue = queue[1:]
		if d.selected[want.name] {
			continue
		}
		queue = append(queue, d.resolveOne(ctx, want)...)
	}
}

// resolveOne selects one gem's release (greedily — see gemDownloader),
// downloads it with its requested platform variants, and returns the
// dependency edges to resolve next. A gem that cannot be resolved or fetched
// is reported and skipped, never fatal for the batch.
func (d *gemDownloader) resolveOne(ctx context.Context, want gemWant) []gemWant {
	lines, err := d.infoLines(ctx, want.name)
	var line *gemInfoLine
	if err == nil {
		line, err = selectGemLine(lines, want)
	}
	if err != nil {
		emitProgress(ctx, "  ✗ %s: %s", want.name, err)
		d.failed = append(d.failed, FailedModule{Module: want.name, Version: want.describe(), Error: err.Error()})
		return nil
	}
	d.selected[want.name] = true
	emitProgress(ctx, "→ %s@%s", want.name, line.Version)
	if !d.fetchGem(ctx, want.name, *line) {
		return nil
	}
	d.fetchPlatformVariants(ctx, want.name, line.Version, lines)
	if d.noDeps {
		return nil
	}
	wants := make([]gemWant, 0, len(line.Deps))
	for _, dep := range line.Deps {
		if !d.selected[dep.Name] {
			wants = append(wants, gemWant{name: dep.Name, reqs: dep.Reqs})
		}
	}
	return wants
}

// infoLines returns the parsed /info lines for a gem, fetching and caching
// the compact-index file on first use.
func (d *gemDownloader) infoLines(ctx context.Context, name string) ([]gemInfoLine, error) {
	if got, ok := d.infos[name]; ok {
		return got, nil
	}
	b, err := httpGetBytes(ctx, d.base+"/info/"+name, maxIndexFetchBytes)
	if err != nil {
		return nil, err
	}
	lines, err := parseGemInfoFile(b)
	if err != nil {
		return nil, err
	}
	d.infos[name] = lines
	return lines, nil
}

// selectGemLine picks the pure-ruby line one want resolves to: the exact
// pinned version, or the newest release satisfying the constraints — a
// prerelease only when no release does.
func selectGemLine(lines []gemInfoLine, want gemWant) (*gemInfoLine, error) {
	if want.pin != "" {
		for i := range lines {
			if lines[i].Platform == "" && lines[i].Version == want.pin {
				return &lines[i], nil
			}
		}
		return nil, fmt.Errorf("version %s not found in the compact index", want.pin)
	}
	keep := func(gemInfoLine) bool { return true }
	if len(want.reqs) > 0 {
		keep = func(l gemInfoLine) bool { return gemReqsSatisfied(want.reqs, l.Version) }
	}
	if best := maxGemLine(lines, false, keep); best != nil {
		return best, nil
	}
	if best := maxGemLine(lines, true, keep); best != nil {
		return best, nil
	}
	return nil, fmt.Errorf("no version satisfies %q", want.describe())
}

// maxGemLine returns the pure-ruby line with the highest version among those
// satisfying keep; pre selects between releases (false) and prereleases
// (true).
func maxGemLine(lines []gemInfoLine, pre bool, keep func(gemInfoLine) bool) *gemInfoLine {
	var best *gemInfoLine
	for i := range lines {
		l := &lines[i]
		if l.Platform != "" || gemIsPrerelease(l.Version) != pre || !keep(*l) {
			continue
		}
		if best == nil || gemCompareVersions(best.Version, l.Version) < 0 {
			best = l
		}
	}
	return best
}

// fetchGem downloads one selected release into the staging tree, verifying
// the info line's sha256 checksum as the bytes arrive, and records it for
// the bundle manifest with the verbatim line.
func (d *gemDownloader) fetchGem(ctx context.Context, name string, line gemInfoLine) bool {
	filename := gemFilename(name, line.Version, line.Platform)
	rel := gemFileRel(filename)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadVerifiedFile(ctx, d.base+"/gems/"+filename, abs, 0, "sha256", line.Checksum)
	if err != nil {
		token := gemVersionFull(line.Version, line.Platform)
		emitProgress(ctx, "  ✗ %s@%s: %s", name, token, err)
		d.failed = append(d.failed, FailedModule{Module: name, Version: token, Error: err.Error()})
		return false
	}
	d.gems = append(d.gems, GemVersion{
		Name: name, Version: line.Version, Platform: line.Platform,
		Filename: filename, Path: rel, SHA256: sum, InfoLine: line.Raw,
	})
	d.files = append(d.files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	return true
}

// fetchPlatformVariants additionally downloads the requested platform
// variants of an already-selected version when the upstream publishes them;
// a platform with no line for this version is skipped silently (the
// pure-ruby gem is always mirrored).
func (d *gemDownloader) fetchPlatformVariants(ctx context.Context, name, version string, lines []gemInfoLine) {
	for _, platform := range d.platforms {
		for i := range lines {
			if lines[i].Version == version && lines[i].Platform == platform {
				emitProgress(ctx, "→ %s@%s", name, gemVersionFull(version, platform))
				d.fetchGem(ctx, name, lines[i])
				break
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

// writeRubyGemsBundle writes one signed bundle for the rubygems stream from
// the staged files and their manifest records.
func (s *LowServer) writeRubyGemsBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, gems []GemVersion) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(gems, func(i, j int) bool {
		if gems[i].Name != gems[j].Name {
			return gems[i].Name < gems[j].Name
		}
		return gems[i].Path < gems[j].Path
	})
	id := bundleIDFor(streamRubyGems, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamRubyGems,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"rubygems"},
		RubyGems:         &RubyGemsManifest{Gems: gems},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamRubyGems, Sequence: seq, ExportedModules: len(gems), BundleID: id}, nil
}
