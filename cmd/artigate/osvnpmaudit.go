package main

// The npm bulk-audit bridge: the piece that turns a mirrored OSV "npm"
// database (osv.go) into a working `npm audit` on the air-gapped side.
//
// npm clients POST {registry}/-/npm/v1/security/advisories/bulk with a map
// of installed package names to versions and expect advisory records in
// npmjs's bulk format back — the reason clients of a plain mirror had to
// set audit=false. When the osv stream delivers the "npm" database, import
// regenerates a name-keyed advisory index from the zip's own OSV records
// (never from any transferred index), and serveNpm answers the bulk route
// from it. Without a mirrored npm database the route 404s, so npm reports
// the endpoint unavailable instead of a false all-clear.
//
// Version filtering is deliberately left to the client: npm re-checks every
// installed version against vulnerable_versions anyway (its
// metavuln-calculator), so returning a package's full advisory list is
// correct and keeps a second semver-range evaluator off the server. Where
// an upstream record cannot be rendered exactly, the range widens to "*" —
// over-reporting is recoverable noise, under-reporting is a silently missed
// vulnerability.

import (
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// npmAuditBulkRoute is the bulk-advisory route relative to the /npm registry
// root, the one POST endpoint of the served registry surface.
const npmAuditBulkRoute = "-/npm/v1/security/advisories/bulk"

// npmAuditMaxBodyBytes caps a bulk request body on the wire; the inflated
// gzip payload may be 8x that. npm sends one short entry per installed
// package, so even monorepo lockfiles stay far below this.
const npmAuditMaxBodyBytes = 8 << 20

// osvMaxAdvisoryBytes caps one advisory JSON parsed out of a database zip
// (a decompression-bomb guard; real records are a few KiB).
const osvMaxAdvisoryBytes = 32 << 20

// -----------------------------------------------------------------------------
// OSV record subset and its rendering into npm's bulk format
// -----------------------------------------------------------------------------

// osvEntry is the subset of an OSV advisory record
// (https://ossf.github.io/osv-schema/) the audit bridge reads.
type osvEntry struct {
	ID               string           `json:"id"`
	Withdrawn        string           `json:"withdrawn"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Affected         []osvAffected    `json:"affected"`
	DatabaseSpecific osvEntrySpecific `json:"database_specific"`
}

// osvEntrySpecific carries the GitHub-Advisory-sourced extras OSV keeps
// outside the core schema: the qualitative severity npm shows, and CWE ids.
type osvEntrySpecific struct {
	Severity string   `json:"severity"`
	CWEIDs   []string `json:"cwe_ids"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent is one point on a range's version timeline; exactly one field is
// set per event.
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// npmAuditAdvisory is one advisory in the npm bulk-audit response shape
// (what registry.npmjs.org returns from /-/npm/v1/security/advisories/bulk).
// npm needs id, url, title, severity, and vulnerable_versions; cwe is passed
// through when the record carries it. A cvss block is deliberately absent:
// OSV carries only the CVSS vector, and fabricating the score npm would
// print is worse than omitting the block (older registries never sent one).
type npmAuditAdvisory struct {
	ID                 uint32   `json:"id"`
	URL                string   `json:"url"`
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	CWE                []string `json:"cwe,omitempty"`
}

// osvNumericID derives the numeric id npm's bulk format expects from the
// OSV id string. npmjs assigns registry-internal integers; a mirror has
// none, so a stable FNV-1a hash keeps the id deterministic across imports
// (it only has to identify the advisory within npm's report — the url
// carries the real id).
func osvNumericID(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32()
}

// osvAdvisoryURL is the link npm shows for an advisory: GHSA ids have a
// canonical GitHub advisory page (what npmjs itself links); everything else
// links its osv.dev page.
func osvAdvisoryURL(id string) string {
	if strings.HasPrefix(id, "GHSA-") {
		return "https://github.com/advisories/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

// osvAdvisoryTitle is the human title npm prints: the OSV summary, the
// first line of the details as a fallback, the id as a last resort.
func osvAdvisoryTitle(e osvEntry) string {
	if t := strings.TrimSpace(e.Summary); t != "" {
		return t
	}
	details := strings.TrimSpace(e.Details)
	if line, _, _ := strings.Cut(details, "\n"); strings.TrimSpace(line) != "" {
		return clipRunes(strings.TrimSpace(line), 140)
	}
	return e.ID
}

// clipRunes shortens s to at most n runes, marking the cut with an ellipsis.
func clipRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

// osvNpmSeverity maps an OSV record onto npm's severity words. GitHub
// Advisory records carry the level verbatim (CRITICAL/HIGH/MODERATE/LOW);
// malicious-package records (MAL-) carry none and are critical by nature.
// Anything else defaults to "high" — an advisory feed may over-alarm, never
// soft-pedal.
func osvNpmSeverity(e osvEntry) string {
	switch sev := strings.ToLower(e.DatabaseSpecific.Severity); sev {
	case "critical", "high", "moderate", "low":
		return sev
	}
	if strings.HasPrefix(e.ID, "MAL-") {
		return "critical"
	}
	return "high"
}

// cweIDRE matches one CWE identifier as GitHub Advisory records carry them.
var cweIDRE = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)

func osvCWEs(e osvEntry) []string {
	var out []string
	for _, c := range e.DatabaseSpecific.CWEIDs {
		if cweIDRE.MatchString(c) {
			out = append(out, c)
		}
	}
	return out
}

// npmAdvisoriesForEntry renders one OSV record into the bulk-format entries
// it contributes: one per distinct affected npm package, with every
// affected object's coverage merged into a single range. Withdrawn records
// contribute nothing (they were retracted upstream; the raw record stays
// servable from the zip for audit trails).
func npmAdvisoriesForEntry(e osvEntry) map[string]npmAuditAdvisory {
	if e.ID == "" || e.Withdrawn != "" {
		return nil
	}
	byName := map[string][]osvAffected{}
	for _, aff := range e.Affected {
		if aff.Package.Ecosystem != osvNpmEcosystem || validateNpmName(aff.Package.Name) != nil {
			continue
		}
		byName[aff.Package.Name] = append(byName[aff.Package.Name], aff)
	}
	out := make(map[string]npmAuditAdvisory, len(byName))
	for name, affs := range byName {
		out[name] = npmAuditAdvisory{
			ID:                 osvNumericID(e.ID),
			URL:                osvAdvisoryURL(e.ID),
			Title:              osvAdvisoryTitle(e),
			Severity:           osvNpmSeverity(e),
			VulnerableVersions: osvNpmRangeString(affs),
			CWE:                osvCWEs(e),
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// OSV ranges -> npm semver ranges
// -----------------------------------------------------------------------------

// osvNpmRangeString merges every affected object's coverage for one package
// into a single npm range string ("<4.17.12 || >=5.0.0 <5.2.1"). Any part
// that cannot be rendered exactly widens the whole result to "*".
func osvNpmRangeString(affs []osvAffected) string {
	var segs []string
	for _, aff := range affs {
		s, ok := osvAffectedSegments(aff)
		if !ok {
			return "*"
		}
		segs = append(segs, s...)
	}
	if len(segs) == 0 {
		return "*"
	}
	return strings.Join(segs, " || ")
}

// osvAffectedSegments renders one affected object: its SEMVER/ECOSYSTEM
// ranges (npm ecosystem versions are npm semver) plus any explicitly
// enumerated versions. GIT ranges say nothing about npm versions and are
// skipped; an unknown range type or unusable version reports !ok so the
// caller falls back to "*" instead of guessing.
func osvAffectedSegments(aff osvAffected) ([]string, bool) {
	var segs []string
	for _, r := range aff.Ranges {
		switch r.Type {
		case "GIT":
			continue
		case "SEMVER", "ECOSYSTEM":
			s, ok := osvEventSegments(r.Events)
			if !ok {
				return nil, false
			}
			segs = append(segs, s...)
		default:
			return nil, false
		}
	}
	for _, v := range aff.Versions {
		if validateNpmVersion(v) != nil {
			return nil, false
		}
		segs = append(segs, v)
	}
	return segs, true
}

// osvEventSegments converts one range's ordered event timeline into npm
// comparator segments: "introduced" opens a segment ("0" = from the
// beginning of time), "fixed" closes it exclusively, "last_affected"
// inclusively, and a still-open segment at the end is unbounded.
func osvEventSegments(events []osvEvent) ([]string, bool) {
	var b osvRangeBuilder
	for _, ev := range events {
		if !b.apply(ev) {
			return nil, false
		}
	}
	b.finish()
	return b.segs, true
}

// osvRangeBuilder accumulates comparator segments while walking a range's
// events. lower is the open segment's inclusive lower bound ("" once "0" —
// every version — opened it).
type osvRangeBuilder struct {
	segs  []string
	lower string
	open  bool
}

func (b *osvRangeBuilder) apply(ev osvEvent) bool {
	switch {
	case ev.Introduced != "":
		return b.openAt(ev.Introduced)
	case ev.Fixed != "":
		return b.closeAt("<", ev.Fixed)
	case ev.LastAffected != "":
		return b.closeAt("<=", ev.LastAffected)
	}
	// Empty events and "limit" (a git-enumeration bound) never appear in npm
	// data; refuse rather than misrender.
	return false
}

func (b *osvRangeBuilder) openAt(v string) bool {
	if b.open {
		b.finish() // a re-introduction implicitly leaves the prior segment unbounded
	}
	if v != "0" && validateNpmVersion(v) != nil {
		return false
	}
	b.open = true
	if v != "0" {
		b.lower = v
	}
	return true
}

func (b *osvRangeBuilder) closeAt(op, v string) bool {
	if !b.open || validateNpmVersion(v) != nil {
		return false
	}
	seg := op + v
	if b.lower != "" {
		seg = ">=" + b.lower + " " + seg
	}
	b.segs = append(b.segs, seg)
	b.open, b.lower = false, ""
	return true
}

// finish flushes a segment the event list never closed: vulnerable from its
// lower bound onward (or everything, when it opened at "0").
func (b *osvRangeBuilder) finish() {
	if !b.open {
		return
	}
	if b.lower == "" {
		b.segs = append(b.segs, "*")
	} else {
		b.segs = append(b.segs, ">="+b.lower)
	}
	b.open, b.lower = false, ""
}

// -----------------------------------------------------------------------------
// Index regeneration at import
// -----------------------------------------------------------------------------

// npmAuditIndex is the regenerated audit lookup: every advisory of the
// mirrored OSV npm database, keyed by package name, pre-rendered in the
// bulk response shape. It is rebuilt in full on every npm database import —
// advisories update and withdraw, so the fresh zip is the complete truth.
type npmAuditIndex struct {
	Generated time.Time                     `json:"generated"`
	Packages  map[string][]npmAuditAdvisory `json:"packages"`
}

func (s *HighServer) osvNpmAuditIndexPath() string {
	return filepath.Join(s.downloadDir, "osv", "npm-audit.json")
}

// rebuildNpmAuditIndex regenerates the bulk-audit index from the verified
// npm database zip.
func (s *HighServer) rebuildNpmAuditIndex(zipPath string) error {
	packages, parsed, err := npmAuditPackagesFromZip(zipPath)
	if err != nil {
		return err
	}
	idx := npmAuditIndex{Generated: time.Now().UTC(), Packages: packages}
	if err := writeJSONAtomic(s.osvNpmAuditIndexPath(), idx, 0o644); err != nil {
		return err
	}
	// The write replaced whatever bytes a past failed drop may have blocked;
	// the index describes the installed snapshot again.
	s.derivedBlocks.allow(s.osvNpmAuditIndexPath())
	log.Printf("osv: regenerated the npm audit index from %d advisories (%d package(s) affected)", parsed, len(packages))
	return nil
}

// npmAuditPackagesFromZip renders every advisory in the database zip,
// grouped by affected package name, each name's list ordered for
// deterministic output.
func npmAuditPackagesFromZip(zipPath string) (map[string][]npmAuditAdvisory, int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", filepath.Base(zipPath), err)
	}
	defer zr.Close()
	packages := map[string][]npmAuditAdvisory{}
	parsed := 0
	for _, f := range zr.File {
		e, ok := readOsvZipEntry(f)
		if !ok {
			continue
		}
		parsed++
		for name, adv := range npmAdvisoriesForEntry(e) {
			packages[name] = append(packages[name], adv)
		}
	}
	if parsed == 0 {
		return nil, 0, errors.New("npm database zip contains no parsable advisories")
	}
	for _, advs := range packages {
		sort.Slice(advs, func(i, j int) bool { return advs[i].URL < advs[j].URL })
	}
	return packages, parsed, nil
}

// readOsvZipEntry parses one zip entry as an OSV record. Entries that are
// not advisory JSONs — directories, oversized or unparsable files — report
// !ok and are skipped: one malformed upstream record must not block the
// whole index.
func readOsvZipEntry(f *zip.File) (osvEntry, bool) {
	if osvAdvisoryIDFromFilename(f.Name) == "" || f.UncompressedSize64 > osvMaxAdvisoryBytes {
		return osvEntry{}, false
	}
	rc, err := f.Open()
	if err != nil {
		return osvEntry{}, false
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, osvMaxAdvisoryBytes))
	if err != nil {
		return osvEntry{}, false
	}
	var e osvEntry
	if json.Unmarshal(b, &e) != nil {
		return osvEntry{}, false
	}
	return e, true
}

// -----------------------------------------------------------------------------
// Serving the bulk endpoint
// -----------------------------------------------------------------------------

// npmAuditCache memoizes the parsed index; the regenerated file is
// re-loaded when its stat identity changes (writeJSONAtomic renames a fresh
// file into place on every npm database import).
type npmAuditCache struct {
	mu       sync.Mutex
	modTime  time.Time
	size     int64
	packages map[string][]npmAuditAdvisory
}

// npmAuditPackages returns the advisory index keyed by package name.
// ok=false means no npm OSV database has been imported, which the handler
// turns into a 404 — an absent database must read as "audit unavailable",
// never as "no known vulnerabilities".
func (s *HighServer) npmAuditPackages() (map[string][]npmAuditAdvisory, bool) {
	s.npmAudit.mu.Lock()
	defer s.npmAudit.mu.Unlock()
	if s.derivedBlocks.blocked(s.osvNpmAuditIndexPath()) {
		// A failed publish could neither remove nor empty the index; its
		// bytes describe a previous snapshot, so neither they nor the memo
		// built from them may answer (see suppressStaleDerived).
		s.npmAudit.packages = nil
		return nil, false
	}
	fi, err := os.Stat(s.osvNpmAuditIndexPath())
	if err != nil {
		s.npmAudit.packages = nil
		return nil, false
	}
	if s.npmAudit.packages != nil && fi.ModTime().Equal(s.npmAudit.modTime) && fi.Size() == s.npmAudit.size {
		return s.npmAudit.packages, true
	}
	b, err := os.ReadFile(s.osvNpmAuditIndexPath())
	if err != nil {
		return nil, false
	}
	var idx npmAuditIndex
	if err := json.Unmarshal(b, &idx); err != nil || idx.Packages == nil {
		log.Printf("npm audit: unreadable index %s: %v", s.osvNpmAuditIndexPath(), err)
		return nil, false
	}
	s.npmAudit.modTime, s.npmAudit.size, s.npmAudit.packages = fi.ModTime(), fi.Size(), idx.Packages
	return s.npmAudit.packages, true
}

// handleNpmAuditBulk answers npm's bulk advisory endpoint from the mirrored
// OSV npm database. The request maps package names to installed versions;
// the response maps each requested name with known advisories to their
// bulk-format records (a name with none is simply absent, like upstream).
func (s *HighServer) handleNpmAuditBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pkgs, ok := s.npmAuditPackages()
	if !ok {
		http.Error(w, `audit unavailable: no OSV npm advisory database mirrored (collect ecosystem "npm" on the osv stream)`, http.StatusNotFound)
		return
	}
	req, err := readNpmAuditBulkBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := map[string][]npmAuditAdvisory{}
	for name := range req {
		if advs := pkgs[name]; len(advs) > 0 {
			out[name] = advs
		}
	}
	writeJSON(w, out)
}

// readNpmAuditBulkBody decodes a bulk request body, transparently inflating
// the gzip content-encoding npm always sends (npm-registry-fetch compresses
// audit payloads), with both the wire and inflated sizes capped.
func readNpmAuditBulkBody(r *http.Request) (map[string][]string, error) {
	rd := io.LimitReader(r.Body, npmAuditMaxBodyBytes)
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, fmt.Errorf("bad gzip body: %w", err)
		}
		defer gz.Close()
		rd = io.LimitReader(gz, 8*npmAuditMaxBodyBytes)
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		return nil, fmt.Errorf("read audit request: %w", err)
	}
	req := map[string][]string{}
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("parse audit request: %w", err)
	}
	return req, nil
}
