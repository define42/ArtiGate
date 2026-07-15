package main

// Low-side capture of Go checksum-database (sumdb) records and tiles.
//
// The capture drives golang.org/x/mod/sumdb — the same client the go
// toolchain embeds — over the toolchain's own on-disk layout, so `go mod
// download` and this pass share one verified cache: every lookup and tile on
// disk was authenticated against the database's public key before it was
// written. Per collect it runs four phases:
//
//  1. Look up every collected module@version (cache hit or upstream fetch —
//     either way the client re-verifies the record against the merged latest
//     tree head, fetching whatever tiles that needs).
//  2. Normalize: rewrite the tree note embedded in every not-yet-shipped
//     lookup to the merged latest head. Records fetched moments apart carry
//     different heads; a shipped lookup must only ever embed a head this
//     mirror captured full proofs for, because a downstream client that
//     fetches just that one module verifies against exactly that head.
//  3. Re-verify the whole cached corpus under the merged latest head. The
//     client then fetches precisely what any downstream request mix could
//     still need: consistency proofs from every previously shipped head to
//     the current one, and tiles re-clipped to the wider tree (a tile that
//     was partial near the old tree edge exists in full once the log grows
//     past it — clients fall back from partial to full tile requests, never
//     the reverse). Skipped cheaply when nothing changed upstream.
//  4. Stage the latest head as the servable "latest" file and list every
//     file not already forwarded on the go stream for the bundle.
//
// Capture never fails a collect: on any problem the modules still export and
// the gap is reported on the result — clients simply keep needing GOSUMDB=off
// for the affected modules, exactly as before mirroring existed.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// GoSumDBStatus summarizes a go collect's checksum-database capture on the
// export result.
type GoSumDBStatus struct {
	// Name is the checksum database captured from (e.g. "sum.golang.org").
	Name string `json:"name,omitempty"`
	// Records counts the module@version records verified this collect.
	Records int `json:"records"`
	// Failed lists records that could not be captured or re-verified (bounded);
	// their modules still export, but clients cannot checksum-verify them
	// offline until a later collect heals the record.
	Failed []string `json:"failed,omitempty"`
	// Skipped is the reason nothing was captured at all, when set.
	Skipped string `json:"skipped,omitempty"`
}

// goSumDBConfig is the parsed low-side GOSUMDB setting.
type goSumDBConfig struct {
	name string // canonical database name (the verifier key's name)
	key  string // note verifier key
	url  string // the database's own base URL (the non-proxied fallback)
}

// knownGoSumDB returns the built-in verifier key and direct URL for the
// database names the go command also knows without an explicit key.
func knownGoSumDB(name string) (key, url string, ok bool) {
	const sumGolangOrgKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
	switch name {
	case "sum.golang.org":
		return sumGolangOrgKey, "https://sum.golang.org", true
	case "sum.golang.google.cn":
		// Same database and key as sum.golang.org, reachable from mainland
		// China; the canonical name stays sum.golang.org (the key's name).
		return sumGolangOrgKey, "https://sum.golang.google.cn", true
	}
	return "", "", false
}

// parseGoSumDBConfig parses GOSUMDB ("<name>", "<name>+<hash>+<key>", either
// optionally followed by a URL). enabled is false for "off" or empty — the
// operator has turned checksum-database use (and therefore mirroring) off.
func parseGoSumDBConfig(gosumdb string) (cfg goSumDBConfig, enabled bool, err error) {
	v := strings.TrimSpace(gosumdb)
	if v == "" || v == "off" {
		return goSumDBConfig{}, false, nil
	}
	fields := strings.Fields(v)
	if len(fields) > 2 {
		return goSumDBConfig{}, false, fmt.Errorf("invalid GOSUMDB %q", gosumdb)
	}
	key, dbURL := fields[0], ""
	if len(fields) == 2 {
		dbURL = fields[1]
	}
	if !strings.Contains(key, "+") {
		known, knownURL, ok := knownGoSumDB(key)
		if !ok {
			return goSumDBConfig{}, false, fmt.Errorf("GOSUMDB %q names an unknown checksum database; give its full verifier key (name+hash+base64key)", gosumdb)
		}
		if dbURL == "" {
			dbURL = knownURL
		}
		key = known
	}
	verifier, err := note.NewVerifier(key)
	if err != nil {
		return goSumDBConfig{}, false, fmt.Errorf("GOSUMDB %q: %w", gosumdb, err)
	}
	name := verifier.Name()
	if err := validateSumDBName(name); err != nil {
		return goSumDBConfig{}, false, fmt.Errorf("GOSUMDB %q: %w", gosumdb, err)
	}
	if dbURL == "" {
		dbURL = "https://" + name
	}
	if !strings.HasPrefix(dbURL, "https://") && !strings.HasPrefix(dbURL, "http://") {
		return goSumDBConfig{}, false, fmt.Errorf("GOSUMDB %q: database URL must be http(s)", gosumdb)
	}
	return goSumDBConfig{name: name, key: key, url: strings.TrimSuffix(dbURL, "/")}, true, nil
}

// sumdbMaxResponseBytes bounds one checksum-database response; lookups and
// notes are around a kilobyte and a full tile is height·2^height bytes, so
// anything past this is a misbehaving upstream.
const sumdbMaxResponseBytes int64 = 4 << 20

// sumdbClientOps provides golang.org/x/mod/sumdb's external operations over
// the go toolchain's own on-disk layout: lookups and tiles under
// <module-cache>/cache/download/sumdb/<name>/... (exactly the layout bundles
// carry and the high side serves), the merged latest tree head under
// <gopath>/pkg/sumdb/<name>/latest. The client only ever hands these ops
// content it has authenticated against the database key.
type sumdbClientOps struct {
	ctx       context.Context
	base      string // remote base, e.g. https://proxy.golang.org/sumdb/sum.golang.org
	hc        *http.Client
	key       string       // note verifier key
	cacheDir  string       // <downloadDir>/sumdb
	configDir string       // <gopath>/pkg/sumdb
	remote    atomic.Int64 // remote reads performed (0 → nothing new upstream)
	insecure  atomic.Bool  // the client detected a forked timeline
}

func (o *sumdbClientOps) ReadRemote(path string) ([]byte, error) {
	o.remote.Add(1)
	req, err := http.NewRequestWithContext(o.ctx, http.MethodGet, o.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", o.base+path, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, sumdbMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > sumdbMaxResponseBytes {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", o.base+path, sumdbMaxResponseBytes)
	}
	return b, nil
}

// safePath contains a client-derived relative file name inside root.
func safePath(root, file string) (string, error) {
	p := filepath.Join(root, filepath.FromSlash(file))
	if err := validateRelPath(file); err != nil || !safeJoin(root, p) {
		return "", fmt.Errorf("unsafe sumdb file path %q", file)
	}
	return p, nil
}

func (o *sumdbClientOps) ReadConfig(file string) ([]byte, error) {
	if file == "key" {
		return []byte(o.key), nil
	}
	if !strings.HasSuffix(file, "/latest") {
		return nil, fmt.Errorf("unknown sumdb config %q", file)
	}
	p, err := safePath(o.configDir, file)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no saved head yet: start from the empty tree
	}
	return b, err
}

func (o *sumdbClientOps) WriteConfig(file string, old, updated []byte) error {
	p, err := safePath(o.configDir, file)
	if err != nil {
		return err
	}
	cur, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !bytes.Equal(cur, old) {
		return sumdb.ErrWriteConflict
	}
	return writeBytesAtomic(p, updated, 0o644)
}

func (o *sumdbClientOps) ReadCache(file string) ([]byte, error) {
	p, err := safePath(o.cacheDir, file)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (o *sumdbClientOps) WriteCache(file string, data []byte) {
	p, err := safePath(o.cacheDir, file)
	if err == nil {
		err = writeBytesAtomic(p, data, 0o644)
	}
	if err != nil {
		log.Printf("go sumdb: write cache %s: %v", file, err)
	}
}

func (o *sumdbClientOps) Log(msg string) { log.Printf("go sumdb: %s", msg) }

// SecurityError means the database presented a forked timeline — evidence of
// server misbehavior, not a transient fault. It is recorded so the pass ships
// nothing from a poisoned session, and logged loudly for the operator; the
// low side must keep running (it is a long-lived daemon), so no exit here.
func (o *sumdbClientOps) SecurityError(msg string) {
	o.insecure.Store(true)
	log.Printf("go sumdb: SECURITY ERROR: %s", msg)
}

// splitGoProxyList splits a GOPROXY-style list on its separators.
func splitGoProxyList(list string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == '|' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// chooseSumDBBase picks where checksum-database requests go: the first
// upstream GOPROXY entry that proxies this database (per the protocol's
// /supported probe), else the database's own URL — the order the go command
// uses. "direct" and "off" end the proxy portion of the list.
func chooseSumDBBase(ctx context.Context, hc *http.Client, goproxy string, cfg goSumDBConfig) string {
	for _, entry := range splitGoProxyList(goproxy) {
		if entry == "direct" || entry == "off" {
			break
		}
		if !strings.HasPrefix(entry, "https://") && !strings.HasPrefix(entry, "http://") {
			continue
		}
		base := strings.TrimSuffix(entry, "/") + "/sumdb/" + cfg.name
		if probeSumDBSupported(ctx, hc, base) {
			return base
		}
	}
	return cfg.url
}

func probeSumDBSupported(ctx context.Context, hc *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/supported", nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// sumdbSkipPatterns mirrors the go command's default: GONOSUMDB, defaulting
// to GOPRIVATE. Matching modules are never looked up in the database. A
// credentialed collect's hosts join the patterns (see goauth.go), so private
// modules fetched with an injected login are skipped instead of surfacing as
// lookup failures.
func (s *LowServer) sumdbSkipPatterns(ctx context.Context) string {
	// The in-process sumdb client applies no defaulting of its own, so this
	// resolves the effective base (GONOSUMDB, or GOPRIVATE when unset) itself
	// before appending a credentialed collect's hosts — mirroring goEnv.
	return mergePatterns(effectiveGoNoVar(s.cfg.GONOSUMDB, s.cfg.GOPRIVATE), goAuthHostPatterns(ctx))
}

// requestRecordsOf lists the module@version records of successfully fetched
// manifest modules.
func requestRecordsOf(mods []ManifestMod) []RequestRecord {
	out := make([]RequestRecord, 0, len(mods))
	for _, m := range mods {
		out = append(out, RequestRecord{Module: m.Module, Version: m.Version})
	}
	return out
}

// captureGoSumDB captures checksum-database records for the collect's modules
// and returns the sumdb files this bundle should carry plus a summary for the
// export result (nil when GOSUMDB is off). It never fails the collect.
func (s *LowServer) captureGoSumDB(ctx context.Context, records []RequestRecord, force bool) ([]ManifestFile, *GoSumDBStatus) {
	cfg, enabled, err := parseGoSumDBConfig(s.cfg.GOSUMDB)
	if err != nil {
		log.Printf("go sumdb capture skipped: %v", err)
		return nil, &GoSumDBStatus{Skipped: err.Error()}
	}
	if !enabled {
		return nil, nil
	}
	files, status := s.runGoSumDBCapture(ctx, cfg, records, force)
	if status.Skipped != "" {
		log.Printf("go sumdb capture skipped: %s", status.Skipped)
	}
	return files, status
}

func (s *LowServer) runGoSumDBCapture(ctx context.Context, cfg goSumDBConfig, records []RequestRecord, force bool) ([]ManifestFile, *GoSumDBStatus) {
	hc := &http.Client{Timeout: 60 * time.Second}
	ops := &sumdbClientOps{
		ctx:       ctx,
		base:      chooseSumDBBase(ctx, hc, s.cfg.UpstreamGOPROXY, cfg),
		hc:        hc,
		key:       cfg.key,
		cacheDir:  filepath.Join(s.downloadDir, "sumdb"),
		configDir: filepath.Join(s.gopath, "pkg", "sumdb"),
	}
	c := &sumdbCapture{
		srv: s, ctx: ctx, cfg: cfg, ops: ops,
		status:  &GoSumDBStatus{Name: cfg.name},
		bad:     map[string]bool{},
		collect: map[string]bool{},
		failed:  map[string]string{},
	}
	emitProgress(ctx, "Capturing %s records for %d module(s) via %s…", cfg.name, len(records), ops.base)
	c.fetchRecords(records)
	c.normalizeUnshippedLookups()
	c.reverifyCorpus()
	c.finalizeStatus()
	if ops.insecure.Load() {
		c.status.Skipped = "checksum database reported a forked timeline (see log); nothing captured"
		return nil, c.status
	}
	c.stageLatest()
	files, err := c.listFiles(force)
	if err != nil {
		c.status.Skipped = fmt.Sprintf("listing captured files: %v", err)
		return nil, c.status
	}
	emitProgress(ctx, "Checksum database %s: %d record(s) verified, %d file(s) to deliver", cfg.name, c.status.Records, len(files))
	return files, c.status
}

// sumdbCapture is one collect's capture pass.
type sumdbCapture struct {
	srv    *LowServer
	ctx    context.Context
	cfg    goSumDBConfig
	ops    *sumdbClientOps
	status *GoSumDBStatus
	// bad marks database-relative file paths that must not ship this bundle:
	// they could not be (re)verified, or could not be normalized.
	bad map[string]bool
	// collect marks the lookup paths of this collect's own records (the ones
	// Records counts); failed carries the latest failure per key. Both keep a
	// failure healable: a re-verification that succeeds clears it.
	collect map[string]bool
	failed  map[string]string
}

// dbDir is the on-disk directory of this database's captured files.
func (c *sumdbCapture) dbDir() string {
	return filepath.Join(c.ops.cacheDir, filepath.FromSlash(c.cfg.name))
}

// sumdbMaxReportedFailures bounds the failure list carried on the result.
const sumdbMaxReportedFailures = 20

func (c *sumdbCapture) fail(key, msg string) {
	log.Printf("go sumdb: %s", msg)
	c.failed[key] = msg
}

// finalizeStatus fills the result summary once every phase has run: how many
// of this collect's records verified (a record that failed a first look-up
// but re-verified afterwards counts), and the failures that remain.
func (c *sumdbCapture) finalizeStatus() {
	for rel := range c.collect {
		if c.failed[rel] == "" {
			c.status.Records++
		}
	}
	keys := make([]string, 0, len(c.failed))
	for key := range c.failed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if i == sumdbMaxReportedFailures {
			c.status.Failed = append(c.status.Failed, "… more failures; see the low-side log")
			break
		}
		c.status.Failed = append(c.status.Failed, c.failed[key])
	}
}

// sumdbLookupRel is a record's lookup file path relative to the database dir.
func sumdbLookupRel(modPath, version string) (string, bool) {
	escPath, err := module.EscapePath(modPath)
	if err != nil {
		return "", false
	}
	escVers, err := module.EscapeVersion(version)
	if err != nil {
		return "", false
	}
	return "lookup/" + escPath + "@" + escVers, true
}

// fetchRecords looks up — and thereby verifies — each collected
// module@version. Cached records are re-validated too; new ones are fetched
// from upstream and land in the cache only after full verification.
func (c *sumdbCapture) fetchRecords(records []RequestRecord) {
	client := sumdb.NewClient(c.ops)
	client.SetGONOSUMDB(c.srv.sumdbSkipPatterns(c.ctx))
	for _, rec := range records {
		if c.ctx.Err() != nil {
			return
		}
		key, keyIsRel := rec.Module+"@"+rec.Version, false
		if rel, ok := sumdbLookupRel(rec.Module, rec.Version); ok {
			key, keyIsRel = rel, true
		}
		_, err := client.Lookup(rec.Module, rec.Version)
		switch {
		case err == nil:
			c.collect[key] = true
		case errors.Is(err, sumdb.ErrGONOSUMDB):
			// Skipped by policy: not a record of this database at all.
		default:
			c.collect[key] = true
			if keyIsRel {
				c.bad[key] = true
			}
			c.fail(key, err.Error())
		}
	}
}

// walkLookups calls fn for every cached lookup file with its module path,
// version, and database-relative path. Files that do not decode as lookups
// are ignored (listFiles independently refuses to ship them).
func (c *sumdbCapture) walkLookups(fn func(modPath, version, rel string)) {
	dbDir := c.dbDir()
	_ = filepath.WalkDir(filepath.Join(dbDir, "lookup"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// A missing or unreadable subtree just means nothing to visit.
			return nil
		}
		if c.ctx.Err() != nil {
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dbDir, p)
		if rerr != nil || strings.HasSuffix(rel, ".tmp") {
			return nil
		}
		rel = filepath.ToSlash(rel)
		escPath, escVers, ok := strings.Cut(strings.TrimPrefix(rel, "lookup/"), "@")
		if !ok {
			return nil
		}
		modPath, perr := module.UnescapePath(escPath)
		version, verr := module.UnescapeVersion(escVers)
		if perr != nil || verr != nil {
			return nil
		}
		fn(modPath, version, rel)
		return nil
	})
}

func (c *sumdbCapture) readLatestConfig() []byte {
	b, err := c.ops.ReadConfig(c.cfg.name + "/latest")
	if err != nil {
		return nil
	}
	return b
}

// normalizeUnshippedLookups pins the tree note embedded in every lookup this
// stream has not forwarded yet to the merged latest head. Once shipped, a
// lookup's bytes stay stable (no churn); until then it may only embed a head
// the corpus is verified under.
func (c *sumdbCapture) normalizeUnshippedLookups() {
	latest := c.readLatestConfig()
	if len(latest) == 0 {
		return
	}
	var files []ManifestFile
	var rels []string
	c.walkLookups(func(_, _ string, rel string) {
		mf, err := hashManifestFile(filepath.Join(c.dbDir(), filepath.FromSlash(rel)), sumdbPathPrefix+c.cfg.name+"/"+rel)
		if err != nil {
			return
		}
		files = append(files, mf)
		rels = append(rels, rel)
	})
	forwarded := c.forwardedFlags(files)
	for i, rel := range rels {
		if forwarded[i] {
			continue
		}
		if err := normalizeSumDBLookup(filepath.Join(c.dbDir(), filepath.FromSlash(rel)), latest); err != nil {
			log.Printf("go sumdb: normalize %s: %v", rel, err)
			c.bad[rel] = true
		}
	}
}

// forwardedFlags reports which files the go stream already forwarded, failing
// safe to "none" (re-normalizing and re-listing shipped files is harmless —
// their paths are mutable on the high side — while wrongly skipping one would
// leave a gap).
func (c *sumdbCapture) forwardedFlags(files []ManifestFile) []bool {
	flags, err := c.srv.exported.ForwardedFlags(streamGo, files)
	if err != nil {
		log.Printf("go sumdb: export index: %v; treating all files as new", err)
		return make([]bool, len(files))
	}
	return flags
}

// normalizeSumDBLookup replaces the signed tree note embedded in one lookup
// file with the (newer) latest head, preserving the record bytes exactly.
func normalizeSumDBLookup(path string, latest []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	id, text, rest, err := tlog.ParseRecord(data)
	if err != nil {
		return err
	}
	if bytes.Equal(rest, latest) {
		return nil
	}
	msg, err := tlog.FormatRecord(id, text)
	if err != nil {
		return err
	}
	return writeBytesAtomic(path, append(msg, latest...), 0o644)
}

// reverifyCorpus re-verifies every cached lookup — this collect's and all
// earlier ones' — with a fresh client under the merged latest head, fetching
// whatever proofs are still missing (see the file comment). A fully clean
// pass is fingerprinted so quiet collects skip the walk.
func (c *sumdbCapture) reverifyCorpus() {
	if c.canSkipReverify() {
		return
	}
	client := sumdb.NewClient(c.ops)
	client.SetGONOSUMDB(c.srv.sumdbSkipPatterns(c.ctx))
	clean := true
	c.walkLookups(func(modPath, version, rel string) {
		if _, err := client.Lookup(modPath, version); err != nil {
			if errors.Is(err, sumdb.ErrGONOSUMDB) {
				return
			}
			clean = false
			c.bad[rel] = true
			c.fail(rel, err.Error())
			return
		}
		// This pass is the final arbiter: it verified the file's exact bytes
		// under the merged head, so an earlier transient failure (a record
		// looked up before a later one advanced the head past it) is healed.
		delete(c.bad, rel)
		delete(c.failed, rel)
	})
	if clean && c.ctx.Err() == nil && !c.ops.insecure.Load() {
		c.writeReverifyMarker()
	}
}

// reverifyMarkerPath fingerprints the last fully clean re-verification.
func (c *sumdbCapture) reverifyMarkerPath() string {
	return filepath.Join(c.ops.configDir, filepath.FromSlash(c.cfg.name), "artigate-verified")
}

// canSkipReverify reports whether the corpus walk can be skipped: no remote
// reads happened this collect (so the head cannot have moved and no record is
// new to the cache since the marker was written) and the marker matches the
// current head.
func (c *sumdbCapture) canSkipReverify() bool {
	if c.ops.remote.Load() > 0 {
		return false
	}
	cur, err := os.ReadFile(c.reverifyMarkerPath())
	return err == nil && string(bytes.TrimSpace(cur)) == c.latestDigest()
}

func (c *sumdbCapture) writeReverifyMarker() {
	if err := writeBytesAtomic(c.reverifyMarkerPath(), []byte(c.latestDigest()+"\n"), 0o644); err != nil {
		log.Printf("go sumdb: write verify marker: %v", err)
	}
}

func (c *sumdbCapture) latestDigest() string {
	sum := sha256.Sum256(c.readLatestConfig())
	return hex.EncodeToString(sum[:])
}

// stageLatest copies the merged latest head into the database directory as
// the "latest" file bundles deliver and the high side serves.
func (c *sumdbCapture) stageLatest() {
	latest := c.readLatestConfig()
	if len(latest) == 0 {
		return
	}
	dst := filepath.Join(c.dbDir(), "latest")
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, latest) {
		return
	}
	if err := writeBytesAtomic(dst, latest, 0o644); err != nil {
		log.Printf("go sumdb: stage latest: %v", err)
	}
}

// listFiles returns the manifest entries this bundle delivers: every
// protocol-shaped file not already forwarded on the go stream (or everything,
// for a forced full bundle), minus files that failed verification this pass.
func (c *sumdbCapture) listFiles(force bool) ([]ManifestFile, error) {
	out, err := c.walkShippable()
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if force {
		return out, nil
	}
	forwarded := c.forwardedFlags(out)
	kept := out[:0]
	for i, f := range out {
		if !forwarded[i] {
			kept = append(kept, f)
		}
	}
	return kept, nil
}

// walkShippable hashes every file in the database directory that may ship.
func (c *sumdbCapture) walkShippable() ([]ManifestFile, error) {
	var out []ManifestFile
	dbDir := c.dbDir()
	err := filepath.WalkDir(dbDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(dbDir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		manifestPath := sumdbPathPrefix + c.cfg.name + "/" + rel
		if c.bad[rel] || strings.HasSuffix(rel, ".tmp") || validateManifestSumDBPath(manifestPath) != nil {
			return nil
		}
		mf, herr := hashManifestFile(p, manifestPath)
		if herr != nil {
			return herr
		}
		out = append(out, mf)
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return out, nil
}
