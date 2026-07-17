package main

// OSV vulnerability-advisory ecosystem adapter. The low side fetches
// per-ecosystem databases of the OSV aggregator (https://osv.dev) — one
// all.zip archive of OSV JSON advisories per ecosystem name, the same
// artifacts osv-scanner and friends consume offline — and packs them into
// the same numbered, signed ArtiGate bundle format used by the package
// streams. The high side serves the verified snapshots under /osv/ in the
// upstream bucket's own URL layout (ecosystems.txt, each database zip, and
// any single advisory streamed straight out of the zip), and regenerates an
// npm bulk-audit index from the mirrored "npm" database so `npm audit`
// works against the mirror without the public registry (osvnpmaudit.go).
//
// Unlike package artifacts, an advisory database is a snapshot upstream
// replaces continuously: every collect delivers the current all.zip at the
// same canonical path, and the importer treats osv/ as a mutable subtree
// (see mutableRepoPath). The zips carry no upstream digests, so low-side
// downloads are TLS-trusted like the other index-less fetches; everything
// after that is hash-locked into the signed bundle.

import (
	"archive/zip"
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
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// osvEcosystem is the OSV advisory stream's registry entry (see ecosystems
// in ecosystem.go).
func osvEcosystem() ecosystem {
	return ecosystem{
		stream:       streamOsv,
		label:        "OSV",
		title:        "OSV advisories",
		collect:      (*LowServer).HandleOsvCollect,
		watchCollect: watchAdapter((*LowServer).CollectOsv),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.OsvUpstream, "osv-upstream", "", "base URL OSV vulnerability databases are fetched from (default "+defaultOsvUpstream+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.Osv != nil && len(m.Osv.Databases) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateOsvDatabases(m.Osv.Databases, seen, m.Files)
		},
		contentDesc: "osv databases",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishOsv(m.Osv) },
		serve:       (*HighServer).serveOsv,
		scanTree:    flatTreeScan((*HighServer).listOsvDatabases),
		detail:      (*HighServer).osvDetail,
	}
}

// defaultOsvUpstream is the public OSV bucket serving one all.zip per
// ecosystem (plus ecosystems.txt), the layout the high side mirrors.
const defaultOsvUpstream = "https://osv-vulnerabilities.storage.googleapis.com"

// osvNpmEcosystem is the OSV ecosystem name whose database additionally
// feeds the npm bulk-audit endpoint (see osvnpmaudit.go).
const osvNpmEcosystem = "npm"

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type OsvManifest struct {
	Databases []OsvDatabase `json:"databases"`
}

// OsvDatabase records one mirrored per-ecosystem OSV database snapshot (the
// ecosystem's all.zip). Advisories is informational for operators reading
// the manifest; the high side recounts from the artifact itself at import.
type OsvDatabase struct {
	Ecosystem  string `json:"ecosystem"` // OSV name, e.g. "npm", "PyPI", "Alpine:v3.20"
	Path       string `json:"path"`      // osv/dbs/<slug>/all.zip
	SHA256     string `json:"sha256"`
	Advisories int    `json:"advisories,omitempty"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// osvEcosystemNameRE matches an OSV ecosystem name as osv.dev spells them:
// "npm", "PyPI", "crates.io", "Rocky Linux", "Alpine:v3.20",
// "Ubuntu:22.04:LTS". A name is display identity and URL segment only — the
// storage path uses osvSlug — so spaces, dots, and colons are fine, while
// "/" is excluded entirely and the first character excludes ".", "-", "_",
// ":" and space, so a name can never be ".."/"-flag".
var osvEcosystemNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$`)

// osvAdvisoryIDRE matches a published OSV advisory id ("GHSA-p6mc-m468-83gw",
// "CVE-2024-12345", "MAL-2024-1", "openSUSE-SU-2024:14066-1"). Ids are only
// ever compared against zip entry names, never used as filesystem paths.
var osvAdvisoryIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:_-]{0,127}$`)

func validateOsvEcosystemName(name string) error {
	if !osvEcosystemNameRE.MatchString(name) || strings.HasSuffix(name, " ") {
		return fmt.Errorf("invalid OSV ecosystem name %q", name)
	}
	return nil
}

// osvSlug maps an OSV ecosystem name to the single path-safe segment its
// database is stored under: lowercased, with every character outside
// [a-z0-9._-] replaced by "-" ("Alpine:v3.20" -> "alpine-v3.20",
// "Rocky Linux" -> "rocky-linux"). The first character stays alphanumeric
// (the name validator guarantees it), so a slug can never be ".." or start
// like a flag.
func osvSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// osvDBRel is the repository-relative path an ecosystem's database snapshot
// is stored under.
func osvDBRel(name string) string {
	return "osv/dbs/" + osvSlug(name) + "/all.zip"
}

// osvAdvisoryIDFromFilename extracts the advisory id from a "<ID>.json"
// name (a zip entry, or the filename segment of an advisory URL); "" when
// the name has any other shape.
func osvAdvisoryIDFromFilename(name string) string {
	id, ok := strings.CutSuffix(name, ".json")
	if !ok || !osvAdvisoryIDRE.MatchString(id) {
		return ""
	}
	return id
}

// validateOsvDatabaseRecord checks one manifest record: a well-formed
// ecosystem name, the canonical storage path, a listed file, and that the
// record's own hash claim equals the manifest.files hash the importer
// byte-verifies for that path — so the regenerated metadata can never
// disagree with the artifact it describes.
func validateOsvDatabaseRecord(db OsvDatabase, seen map[string]bool, fileSHA map[string]string) error {
	if err := validateOsvEcosystemName(db.Ecosystem); err != nil {
		return err
	}
	if db.Path != osvDBRel(db.Ecosystem) {
		return fmt.Errorf("osv database %s has non-canonical path %s", db.Ecosystem, db.Path)
	}
	if !seen[db.Path] {
		return fmt.Errorf("osv database %s references file not listed in manifest.files: %s", db.Ecosystem, db.Path)
	}
	if db.SHA256 == "" || !strings.EqualFold(fileSHA[db.Path], db.SHA256) {
		return fmt.Errorf("osv database %s sha256 does not match the delivered artifact", db.Ecosystem)
	}
	return nil
}

// validateOsvDatabases checks every database record of a bundle manifest.
func validateOsvDatabases(dbs []OsvDatabase, seen map[string]bool, files []ManifestFile) error {
	fileSHA := manifestFileSHAs(files)
	for _, db := range dbs {
		if err := validateOsvDatabaseRecord(db, seen, fileSHA); err != nil {
			return err
		}
	}
	return nil
}

// osvZipAdvisoryCount opens a database archive and counts the advisories it
// carries: "<ID>.json" entries with a well-formed OSV id. Both sides derive
// the advisory count from the artifact itself — the low side sanity-checks
// a download before signing it into a bundle, the high side regenerates its
// served metadata at import — and an archive that is not a zip, or holds no
// advisories at all, is a bad fetch rather than a mirrorable database.
func osvZipAdvisoryCount(p string) (int, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return 0, fmt.Errorf("not a readable zip archive: %w", err)
	}
	defer zr.Close()
	count := 0
	for _, f := range zr.File {
		if osvAdvisoryIDFromFilename(f.Name) != "" {
			count++
		}
	}
	if count == 0 {
		return 0, errors.New("zip archive contains no OSV advisories")
	}
	return count, nil
}

// -----------------------------------------------------------------------------
// High side: serving the databases
// -----------------------------------------------------------------------------

func (s *HighServer) osvDBsDir() string {
	return filepath.Join(s.downloadDir, "osv", "dbs")
}

func (s *HighServer) osvMetaDir() string {
	return filepath.Join(s.downloadDir, "osv", "meta")
}

// serveOsv handles the OSV routes under /osv/: the regenerated
// ecosystems.txt, each mirrored database zip, and single advisories served
// straight out of the verified zip. The URL layout mirrors the upstream
// bucket, so a scanner that fetches
// https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip fetches
// <base>/osv/npm/all.zip instead. It reports whether it wrote a response.
func (s *HighServer) serveOsv(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/osv" && !strings.HasPrefix(p, "/osv/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.Trim(strings.TrimPrefix(p, "/osv"), "/")
	if rest == "ecosystems.txt" {
		s.handleOsvEcosystems(w)
		return true
	}
	name, file, ok := strings.Cut(rest, "/")
	if !ok || validateOsvEcosystemName(name) != nil || strings.ContainsRune(file, '/') {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	switch id := osvAdvisoryIDFromFilename(file); {
	case file == "all.zip":
		s.handleOsvDatabaseZip(w, r, name)
	case id != "":
		s.handleOsvAdvisory(w, r, name, id)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

// handleOsvEcosystems serves the mirror's ecosystems.txt: one mirrored
// ecosystem name per line, like the upstream bucket's file. An empty mirror
// 404s — an absent advisory feed must read as unavailable, never as "no
// ecosystems have vulnerabilities".
func (s *HighServer) handleOsvEcosystems(w http.ResponseWriter) {
	names, err := s.osvEcosystemNames()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(names) == 0 {
		http.Error(w, "no OSV databases mirrored", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, strings.Join(names, "\n")+"\n")
}

// osvDatabasePath is the on-disk zip for an ecosystem name, or "" when the
// name maps outside the database tree.
func (s *HighServer) osvDatabasePath(name string) string {
	abs := filepath.Join(s.osvDBsDir(), osvSlug(name), "all.zip")
	if !safeJoin(s.osvDBsDir(), abs) {
		return ""
	}
	return abs
}

func (s *HighServer) handleOsvDatabaseZip(w http.ResponseWriter, r *http.Request, name string) {
	abs := s.osvDatabasePath(name)
	if abs == "" {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	serveFile(w, r, abs)
}

// handleOsvAdvisory streams one advisory's JSON straight out of the
// ecosystem's verified database zip — the mirror serves individual records
// like the upstream bucket does, without ever unpacking 100k-file databases
// onto disk. The id was validated by the router; it is compared against zip
// entry names only.
func (s *HighServer) handleOsvAdvisory(w http.ResponseWriter, r *http.Request, name, id string) {
	abs := s.osvDatabasePath(name)
	if abs == "" {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	zr, err := zip.OpenReader(abs)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == id+".json" {
			serveOsvZipEntry(w, r, f)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func serveOsvZipEntry(w http.ResponseWriter, r *http.Request, f *zip.File) {
	rc, err := f.Open()
	if err != nil {
		http.Error(w, "unreadable advisory", http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.FormatUint(f.UncompressedSize64, 10))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, rc) // client-side aborts are not server errors
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// osvStoredDB is the per-ecosystem metadata the high side regenerates at
// import time from the database zip itself (never from transferred
// numbers): ecosystems.txt and the dashboard are assembled from these.
type osvStoredDB struct {
	Ecosystem  string    `json:"ecosystem"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	Advisories int       `json:"advisories"`
	Imported   time.Time `json:"imported"`
}

// publishOsv regenerates the served metadata for every database in an
// imported bundle. Unlike the per-version publish hooks — where a failed
// record merely 404s, and absence is fail-closed — a database whose derived
// state cannot be regenerated must fail the import: install has already
// replaced the snapshot on disk, so pressing on would commit the sequence
// (never to be retried) while the previous import's metadata — worst of all
// the npm audit index — kept describing bytes that are no longer installed.
// The stale derived state is suppressed before returning (removed, emptied,
// or blocked in memory — see suppressStaleDerived), so while the bundle
// retries (an operational error: it stays in landing and /readyz's
// import-pipeline check reports the failing pass) the audit endpoint
// answers 404 ("audit unavailable"), never stale advisories. The content
// passed collect-time validation and the byte gate, so a failure that
// persists across retries means trusted-side corruption — exactly what
// should stop the stream and page an operator.
func (s *HighServer) publishOsv(m *OsvManifest) error {
	if m == nil {
		return nil
	}
	var errs []error
	for _, db := range m.Databases {
		if err := s.publishOsvDatabase(db); err != nil {
			errs = append(errs, fmt.Errorf("osv publish %s: %w", db.Ecosystem, err))
		}
	}
	return errors.Join(errs...)
}

// publishOsvDatabase re-derives one ecosystem's stored metadata from the
// installed zip (advisory count, hash, size) and, for the npm database,
// rebuilds the npm bulk-audit index (osvnpmaudit.go). On failure every
// piece of derived state that predates the just-installed snapshot is
// suppressed, so nothing ever describes a snapshot other than the one on
// disk.
func (s *HighServer) publishOsvDatabase(db OsvDatabase) error {
	if err := validateOsvEcosystemName(db.Ecosystem); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(db.Path))
	if db.Path != osvDBRel(db.Ecosystem) || !safeJoin(s.osvDBsDir(), abs) {
		return fmt.Errorf("unsafe database path %s", db.Path)
	}
	if err := s.regenerateOsvMeta(db.Ecosystem, abs); err != nil {
		// The metadata on disk (if any) still describes the previous
		// snapshot; suppress it — and npm's audit index with it — rather
		// than serve descriptions of bytes that are no longer installed.
		return errors.Join(err, s.dropOsvMeta(db.Ecosystem), s.dropNpmAuditIndex(db.Ecosystem))
	}
	if db.Ecosystem == osvNpmEcosystem {
		if err := s.rebuildNpmAuditIndex(abs); err != nil {
			// The meta regenerated above is fresh and correct; only the
			// audit index still describes the previous snapshot. Suppressed,
			// the bulk route 404s until a retry rebuilds it (fail closed).
			return errors.Join(err, s.dropNpmAuditIndex(db.Ecosystem))
		}
	}
	return nil
}

// regenerateOsvMeta re-derives one ecosystem's stored metadata from the
// installed database zip.
func (s *HighServer) regenerateOsvMeta(name, abs string) error {
	count, err := osvZipAdvisoryCount(abs)
	if err != nil {
		return err
	}
	sum, err := sha256File(abs)
	if err != nil {
		return err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	st := osvStoredDB{Ecosystem: name, SHA256: sum, Size: fi.Size(), Advisories: count, Imported: time.Now().UTC()}
	out := filepath.Join(s.osvMetaDir(), osvSlug(name)+".json")
	if !safeJoin(s.osvMetaDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s", name)
	}
	if err := writeJSONAtomic(out, st, 0o644); err != nil {
		return err
	}
	// The write replaced whatever bytes a past failed drop may have blocked;
	// the path describes the installed snapshot again.
	s.derivedBlocks.allow(out)
	return nil
}

// dropOsvMeta suppresses one ecosystem's stored metadata, delisting it from
// ecosystems.txt and the dashboard until a publish succeeds again.
func (s *HighServer) dropOsvMeta(name string) error {
	p := filepath.Join(s.osvMetaDir(), osvSlug(name)+".json")
	if !safeJoin(s.osvMetaDir(), p) {
		return nil // regenerateOsvMeta can never have written outside the tree
	}
	return s.suppressStaleDerived(p)
}

// dropNpmAuditIndex suppresses the npm bulk-audit index (a no-op for other
// ecosystems' databases), flipping the bulk route to 404 until a publish
// rebuilds it.
func (s *HighServer) dropNpmAuditIndex(name string) error {
	if name != osvNpmEcosystem {
		return nil
	}
	return s.suppressStaleDerived(s.osvNpmAuditIndexPath())
}

// suppressStaleDerived makes one regenerated-state file unservable after a
// failed publish: removed when possible; truncated in place when the
// directory refuses the unlink (an unwritable directory — the usual reason
// the regeneration itself just failed — still lets the owner empty the
// file, and an empty file is unparsable, so this fails closed across
// restarts too); and failing even that, blocked in memory so the read paths
// treat the path as absent until a publish rewrites it. Only that last
// resort is an error: a purely in-memory block does not survive a restart,
// which an operator must hear about on top of the publish failure already
// failing the import.
func (s *HighServer) suppressStaleDerived(p string) error {
	rmErr := os.Remove(p)
	if rmErr == nil || errors.Is(rmErr, os.ErrNotExist) {
		s.derivedBlocks.allow(p)
		return nil
	}
	if err := os.Truncate(p, 0); err == nil {
		s.derivedBlocks.allow(p)
		log.Printf("osv: emptied stale derived state %s in place (unremovable: %v)", p, rmErr)
		return nil
	}
	s.derivedBlocks.block(p)
	return fmt.Errorf("stale derived state %s can be neither removed nor emptied, suppressing it in memory until a publish regenerates it: %w", p, rmErr)
}

// derivedBlockSet tracks derived-state files a failed publish could neither
// remove nor empty (a fully read-only tree): the osv read paths treat a
// blocked path as absent, so stale bytes that refuse to leave the disk are
// still never served. A path is unblocked the moment it is removed,
// emptied, or rewritten.
type derivedBlockSet struct {
	mu    sync.Mutex
	paths map[string]struct{}
}

func (b *derivedBlockSet) block(p string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.paths == nil {
		b.paths = map[string]struct{}{}
	}
	b.paths[p] = struct{}{}
}

func (b *derivedBlockSet) allow(p string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.paths, p)
}

func (b *derivedBlockSet) blocked(p string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.paths[p]
	return ok
}

// readOsvStored loads one ecosystem's regenerated metadata by slug and
// checks its database zip is still present (only complete databases are
// listed or described).
func (s *HighServer) readOsvStored(slug string) (osvStoredDB, error) {
	p := filepath.Join(s.osvMetaDir(), slug+".json")
	if !safeJoin(s.osvMetaDir(), p) {
		return osvStoredDB{}, errors.New("unsafe path")
	}
	if s.derivedBlocks.blocked(p) {
		return osvStoredDB{}, errors.New("stale metadata suppressed after a failed publish")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return osvStoredDB{}, err
	}
	var st osvStoredDB
	if err := json.Unmarshal(b, &st); err != nil {
		return osvStoredDB{}, err
	}
	if validateOsvEcosystemName(st.Ecosystem) != nil || osvSlug(st.Ecosystem) != slug {
		return osvStoredDB{}, fmt.Errorf("stored metadata %s names ecosystem %q", slug, st.Ecosystem)
	}
	if !fileExists(filepath.Join(s.osvDBsDir(), slug, "all.zip")) {
		return osvStoredDB{}, errors.New("database zip missing")
	}
	return st, nil
}

// osvEcosystemNames lists the mirrored ecosystem names from the regenerated
// metadata, gated on each database zip being present, sorted.
func (s *HighServer) osvEcosystemNames() ([]string, error) {
	entries, err := os.ReadDir(s.osvMetaDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		slug, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok {
			continue
		}
		st, err := s.readOsvStored(slug)
		if err != nil {
			continue
		}
		names = append(names, st.Ecosystem)
	}
	sort.Strings(names)
	return names, nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listOsvDatabases lists the mirrored databases for the dashboard tree: one
// entry per ecosystem, whose single "version" is its all.zip snapshot.
func (s *HighServer) listOsvDatabases() ([]UIModule, error) {
	names, err := s.osvEcosystemNames()
	if err != nil {
		return nil, err
	}
	out := make([]UIModule, 0, len(names))
	for _, name := range names {
		out = append(out, UIModule{Module: name, Versions: []string{"all.zip"}})
	}
	return out, nil
}

// osvDetail describes one mirrored database for the dashboard detail panel.
// spec is "<ecosystem>@all.zip".
func (s *HighServer) osvDetail(spec string) (UIDetail, error) {
	name, file, ok := strings.Cut(spec, "@")
	if !ok || file != "all.zip" || validateOsvEcosystemName(name) != nil {
		return UIDetail{}, errors.New("invalid ecosystem@all.zip")
	}
	st, err := s.readOsvStored(osvSlug(name))
	if err != nil {
		return UIDetail{}, errors.New("database not found")
	}
	dl := "/osv/" + url.PathEscape(st.Ecosystem) + "/all.zip"
	fields := []UIDetailField{
		{Label: "Ecosystem", Value: st.Ecosystem, Mono: true},
		{Label: "Advisories", Value: strconv.Itoa(st.Advisories)},
		{Label: "Database size", Value: formatBytes(st.Size)},
		{Label: "Imported", Value: st.Imported.Format(time.RFC3339)},
		{Label: "SHA-256", Value: st.SHA256, Mono: true},
		{Label: "Download path", Value: dl, Mono: true},
		{Label: "Advisory path", Value: "/osv/" + url.PathEscape(st.Ecosystem) + "/<ID>.json", Mono: true},
	}
	if st.Ecosystem == osvNpmEcosystem {
		fields = append(fields, UIDetailField{
			Label: "npm audit",
			Value: "This database answers POST /npm/-/npm/v1/security/advisories/bulk, so npm clients can drop audit=false.",
		})
	}
	downloads := []UIDownload{{Label: "all.zip", URL: dl}}
	return UIDetail{Title: st.Ecosystem, Subtitle: strconv.Itoa(st.Advisories) + " advisories", Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// Low side: database collector
// -----------------------------------------------------------------------------

// OsvCollectRequest is the body of POST /admin/osv/collect.
//
// Ecosystems lists the OSV ecosystem names to mirror, exactly as
// https://osv.dev spells them ("npm", "PyPI", "Go", "crates.io", "Maven",
// "Alpine:v3.20", "Debian:12", ...). Each name's current all.zip database
// is fetched from the OSV bucket and re-exported as a snapshot.
type OsvCollectRequest struct {
	Ecosystems []string `json:"ecosystems"`
	// Force disables export dedup for this collect: every database is packed
	// even when its content already crossed, producing a full self-contained
	// bundle (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// validateOsvRequest cleans the requested names: trimmed, validated, exact
// duplicates dropped, and two distinct names that would collide on one
// storage slug rejected (they could not both be delivered in one bundle).
func validateOsvRequest(req OsvCollectRequest) ([]string, error) {
	var names []string
	bySlug := map[string]string{}
	for _, raw := range req.Ecosystems {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if err := validateOsvEcosystemName(name); err != nil {
			return nil, err
		}
		if prev, ok := bySlug[osvSlug(name)]; ok {
			if prev == name {
				continue
			}
			return nil, fmt.Errorf("ecosystems %q and %q share the storage path %s", prev, name, osvDBRel(name))
		}
		bySlug[osvSlug(name)] = name
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, errors.New("no OSV ecosystems provided")
	}
	return names, nil
}

// HandleOsvCollect parses a JSON collect request from the admin endpoint
// and runs the collection.
func (s *LowServer) HandleOsvCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req OsvCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse osv collect request: %w", err)
		}
	}
	return s.CollectOsv(ctx, req)
}

// osvUpstreamBase is the bucket OSV databases are fetched from.
func (s *LowServer) osvUpstreamBase() string {
	if s.cfg.OsvUpstream != "" {
		return strings.TrimSuffix(s.cfg.OsvUpstream, "/")
	}
	return defaultOsvUpstream
}

// osvDatabaseURL is the upstream URL of one ecosystem's database. Names may
// carry spaces ("Rocky Linux"), so the segment is path-escaped.
func (s *LowServer) osvDatabaseURL(name string) string {
	return s.osvUpstreamBase() + "/" + url.PathEscape(name) + "/all.zip"
}

// CollectOsv fetches the current database snapshot of every requested OSV
// ecosystem, verifies each is a well-formed advisory archive, and writes
// them into a signed bundle on the osv stream. Databases that cannot be
// fetched are skipped and reported so one of them never blocks the rest;
// unchanged databases dedup to a no-op export, which makes a daily schedule
// cheap.
func (s *LowServer) CollectOsv(ctx context.Context, req OsvCollectRequest) (ExportResult, error) {
	names, err := validateOsvRequest(req)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the osv stream's lock for the whole fetch->write->commit so a
	// concurrent osv exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamOsv)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "osv", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	emitProgress(ctx, "Fetching %d OSV database(s) from %s…", len(names), s.osvUpstreamBase())
	records, files, failed := s.downloadOsvDatabases(ctx, stageRoot, names)
	if len(records) == 0 {
		return ExportResult{}, fmt.Errorf("no OSV databases could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	res, err := s.exportIfNew(ctx, streamOsv, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeOsvBundle(ctx, seq, stageRoot, files, records)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// downloadOsvDatabases fetches every requested database into the staging
// tree and checks each one is a readable advisory archive before it can be
// signed into a bundle. A failed fetch is collected rather than aborting
// the batch.
func (s *LowServer) downloadOsvDatabases(ctx context.Context, stageRoot string, names []string) ([]OsvDatabase, []ManifestFile, []FailedModule) {
	var records []OsvDatabase
	var files []ManifestFile
	var failed []FailedModule
	for i, name := range names {
		emitProgress(ctx, "→ [%d/%d] %s", i+1, len(names), name)
		rel := osvDBRel(name)
		abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
		sum, size, err := downloadFileSHA256(ctx, s.osvDatabaseURL(name), abs)
		var count int
		if err == nil {
			count, err = osvZipAdvisoryCount(abs)
		}
		if err != nil {
			_ = os.Remove(abs)
			emitProgress(ctx, "  ✗ %s: %s", name, err)
			failed = append(failed, FailedModule{Module: name, Version: "all.zip", Error: err.Error()})
			continue
		}
		files = append(files, ManifestFile{Path: rel, SHA256: sum, Size: size})
		records = append(records, OsvDatabase{Ecosystem: name, Path: rel, SHA256: sum, Advisories: count})
	}
	return records, files, failed
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeOsvBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, records []OsvDatabase) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(records, func(i, j int) bool { return records[i].Ecosystem < records[j].Ecosystem })
	id := bundleIDFor(streamOsv, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamOsv,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"osv"},
		Osv:              &OsvManifest{Databases: records},
		Files:            files,
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamOsv, Sequence: seq, ExportedModules: len(records), BundleID: id}, nil
}
