package main

// Tests for Go checksum-database (sumdb) mirroring: config and path
// validation, the low-side capture pass against an in-memory reference
// database, high-side import placement and serving, and — the part that
// matters — full downstream verification: a stock golang.org/x/mod client
// that can only reach the high side must be able to verify every mirrored
// record in any fetch order, across bundles captured while the log grew.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestParseGoSumDBConfig(t *testing.T) {
	for _, off := range []string{"", "off", "  off  "} {
		if _, enabled, err := parseGoSumDBConfig(off); err != nil || enabled {
			t.Errorf("parseGoSumDBConfig(%q) = enabled %v, err %v; want disabled", off, enabled, err)
		}
	}

	cfg, enabled, err := parseGoSumDBConfig("sum.golang.org")
	if err != nil || !enabled || cfg.name != "sum.golang.org" || cfg.url != "https://sum.golang.org" {
		t.Fatalf("default database: cfg %+v, enabled %v, err %v", cfg, enabled, err)
	}
	if !strings.HasPrefix(cfg.key, "sum.golang.org+033de0ae+") {
		t.Fatalf("default database key = %q", cfg.key)
	}

	// The China mirror keeps sum.golang.org's key (and canonical name) with
	// its own URL.
	cfg, _, err = parseGoSumDBConfig("sum.golang.google.cn")
	if err != nil || cfg.name != "sum.golang.org" || cfg.url != "https://sum.golang.google.cn" {
		t.Fatalf("cn mirror: cfg %+v, err %v", cfg, err)
	}

	// A custom database needs its full verifier key; a URL may follow.
	skey, vkey, err := note.GenerateKey(rand.Reader, "sums.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_ = skey
	cfg, _, err = parseGoSumDBConfig(vkey + " https://mirror.example.com/sumdb-proxy")
	if err != nil || cfg.name != "sums.example.com" || cfg.url != "https://mirror.example.com/sumdb-proxy" {
		t.Fatalf("custom database: cfg %+v, err %v", cfg, err)
	}

	// A path-qualified verifier name (host/path form, which the go command
	// accepts) is preserved intact, and the default URL derives from it.
	skeyPQ, vkeyPQ, err := note.GenerateKey(rand.Reader, "sums.example.com/dev")
	if err != nil {
		t.Fatal(err)
	}
	_ = skeyPQ
	cfg, _, err = parseGoSumDBConfig(vkeyPQ)
	if err != nil || cfg.name != "sums.example.com/dev" || cfg.url != "https://sums.example.com/dev" {
		t.Fatalf("path-qualified database: cfg %+v, err %v", cfg, err)
	}

	for _, bad := range []string{
		"unknown.example.org",       // no key known for it
		"a b c",                     // too many fields
		vkey + " ftp://example.com", // non-http URL
		"sum.golang.org+deadbeef",   // malformed key
	} {
		if _, _, err := parseGoSumDBConfig(bad); err == nil {
			t.Errorf("parseGoSumDBConfig(%q) succeeded, want error", bad)
		}
	}
}

func TestSumDBPathValidation(t *testing.T) {
	valid := []string{
		"sum.golang.org/latest",
		"sum.golang.org/lookup/example.com/foo/bar@v1.0.0",
		"sum.golang.org/lookup/github.com/!burnt!sushi/toml@v1.2.3",
		"sum.golang.org/tile/8/0/000.p/1",
		"sum.golang.org/tile/8/1/x001/234",
		"sum.golang.org/tile/8/2/005",
		// Path-qualified database names (host[/path] form) keep every segment
		// before the endpoint word.
		"sums.example.com/dev/latest",
		"sums.example.com/dev/lookup/example.com/foo/bar@v1.0.0",
		"registry.example.org/team/sumdb/tile/8/0/000",
		// A module path may reuse an endpoint word after the real endpoint.
		"sum.golang.org/lookup/example.com/tile@v1.0.0",
	}
	for _, p := range valid {
		if _, err := parseSumDBPath(p); err != nil {
			t.Errorf("parseSumDBPath(%q): %v", p, err)
		}
		if err := validateManifestSumDBPath(sumdbPathPrefix + p); err != nil {
			t.Errorf("validateManifestSumDBPath(%q): %v", sumdbPathPrefix+p, err)
		}
	}

	invalid := []string{
		"sum.golang.org",                             // no endpoint
		"sum.golang.org/lookup/noversion",            // missing @version
		"sum.golang.org/lookup/example.com/A@v1.0.0", // uppercase must be bang-escaped
		"sum.golang.org/lookup/example.com/a@v1@v2",  // stray @
		"sum.golang.org/lookup/nodots@v1.0.0",        // not a module path
		"sum.golang.org/tile/8/9zz/000",              // not a tile path
		"sum.golang.org/other",                       // unknown endpoint
		"SUM.golang.org/latest",                      // uppercase database name
		"../escape/latest",                           // path games
		".hidden/latest",                             // dot-prefixed name
		"sum..golang.org/latest",                     // dot-dot inside name
		"sum.golang.org/lookup/example.com/a@v1/no",  // slash in version
		"sums.example.com//latest",                   // empty (double-slash) segment
		"sums.example.com/../secret/latest",          // traversal in a path-qualified name
		"sums.example.com/.hidden/latest",            // dot-file segment mid-name
		"latest",                                     // endpoint word with no database name
		"lookup/example.com/foo@v1.0.0",              // ditto for a lookup
		"sums.example.com/dev/tile",                  // endpoint word with no tile path
	}
	for _, p := range invalid {
		if _, err := parseSumDBPath(p); err == nil {
			t.Errorf("parseSumDBPath(%q) succeeded, want error", p)
		}
	}

	// "supported" is a URL endpoint, never a manifest file.
	if _, err := parseSumDBPath("sum.golang.org/supported"); err != nil {
		t.Errorf("parseSumDBPath(supported): %v", err)
	}
	if err := validateManifestSumDBPath("sumdb/sum.golang.org/supported"); err == nil {
		t.Error("validateManifestSumDBPath accepted the supported endpoint as a file")
	}
	// Non-sumdb paths are not this validator's business.
	if err := validateManifestSumDBPath("example.com/foo/@v/v1.0.0.info"); err != nil {
		t.Errorf("validateManifestSumDBPath(module file): %v", err)
	}
}

func TestMutableSumDBPath(t *testing.T) {
	mutable := []string{
		"sumdb/sum.golang.org/latest",
		"sumdb/sum.golang.org/lookup/example.com/foo@v1.0.0",
	}
	immutable := []string{
		"sumdb/sum.golang.org/tile/8/0/000.p/1",
		"sumdb/sum.golang.org/tile/8/1/x001/234",
		"example.com/foo/@v/v1.0.0.zip",
		"sumdb/../sneaky/latest",
	}
	for _, p := range mutable {
		if !mutableRepoPath(p) {
			t.Errorf("mutableRepoPath(%q) = false, want true", p)
		}
	}
	for _, p := range immutable {
		if mutableRepoPath(p) {
			t.Errorf("mutableRepoPath(%q) = true, want false", p)
		}
	}
}

func TestMigrateLegacyGoSumDBDir(t *testing.T) {
	pub, _ := newTestKeys(t)
	root := t.TempDir()
	legacy := filepath.Join(root, "cache", "download", "sumdb", "sum.golang.org")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(legacy, "latest"), []byte("legacy note"))

	hs, err := NewHighServer(HighConfig{Root: root, Landing: t.TempDir(), ImportInterval: 0}, pub)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(hs.goModuleDir(), "sumdb", "sum.golang.org", "latest")
	b, err := os.ReadFile(moved)
	if err != nil || string(b) != "legacy note" {
		t.Fatalf("legacy sumdb file not migrated to %s: %v", moved, err)
	}
	if dirExists(filepath.Join(root, "cache", "download", "sumdb")) {
		t.Fatal("legacy sumdb dir still present after migration")
	}
}

// -----------------------------------------------------------------------------
// Capture + serve + downstream verification.
// -----------------------------------------------------------------------------

// newTestSumDB builds an in-memory reference checksum database (the x/mod
// test server: a real transparency log with real signatures) behind an HTTP
// server, fabricating go.sum lines on demand.
func newTestSumDB(t *testing.T) (vkey string, ts *sumdb.TestServer, srv *httptest.Server) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, "artigate.test")
	if err != nil {
		t.Fatal(err)
	}
	ts = sumdb.NewTestServer(skey, func(path, vers string) ([]byte, error) {
		return []byte(testGoSumLines(path, vers)), nil
	})
	srv = httptest.NewServer(sumdb.NewServer(ts))
	t.Cleanup(srv.Close)
	return vkey, ts, srv
}

func testGoSumLines(path, vers string) string {
	return fmt.Sprintf("%s %s h1:%s\n%s %s/go.mod h1:%s\n",
		path, vers, fakeH1(path+" "+vers), path, vers, fakeH1(path+" "+vers+" go.mod"))
}

func fakeH1(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// newSumDBTestLow is newFakeLowServerWithGo with a configurable GOSUMDB.
func newSumDBTestLow(t *testing.T, gosumdb string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:            t.TempDir(),
		ExportDir:       filepath.Join(t.TempDir(), "out"),
		GoBinary:        writeFakeGo(t),
		UpstreamGOPROXY: "off",
		GOSUMDB:         gosumdb,
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// importExported moves everything the low side staged in its export dir into
// the high side's landing and runs one import pass.
func importExported(t *testing.T, ls *LowServer, hs *HighServer) {
	t.Helper()
	entries, err := os.ReadDir(ls.cfg.ExportDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := moveFile(filepath.Join(ls.cfg.ExportDir, e.Name()), filepath.Join(hs.cfg.Landing, e.Name()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if !res.Imported || len(res.RejectedBundles) > 0 {
		t.Fatalf("import result: %+v", res)
	}
}

// sumdbDownstreamOps is a downstream client's world: it can reach only the
// high side, and keeps its own state in memory.
type sumdbDownstreamOps struct {
	t    *testing.T
	base string
	key  string

	mu     sync.Mutex
	config map[string][]byte
	cache  map[string][]byte
}

func newDownstreamSumDBClient(t *testing.T, base, vkey string) *sumdb.Client {
	t.Helper()
	return sumdb.NewClient(&sumdbDownstreamOps{
		t: t, base: base, key: vkey,
		config: map[string][]byte{},
		cache:  map[string][]byte{},
	})
}

func (o *sumdbDownstreamOps) ReadRemote(path string) ([]byte, error) {
	resp, err := http.Get(o.base + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s (%s)", path, resp.Status, strings.TrimSpace(buf.String()))
	}
	return buf.Bytes(), nil
}

func (o *sumdbDownstreamOps) ReadConfig(file string) ([]byte, error) {
	if file == "key" {
		return []byte(o.key), nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.config[file], nil
}

func (o *sumdbDownstreamOps) WriteConfig(file string, old, updated []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !bytes.Equal(o.config[file], old) {
		return sumdb.ErrWriteConflict
	}
	o.config[file] = updated
	return nil
}

func (o *sumdbDownstreamOps) ReadCache(file string) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b, ok := o.cache[file]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

func (o *sumdbDownstreamOps) WriteCache(file string, data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cache[file] = data
}

func (o *sumdbDownstreamOps) Log(_ string) {}

func (o *sumdbDownstreamOps) SecurityError(msg string) {
	o.t.Errorf("downstream sumdb client security error: %s", msg)
}

// mustLookup verifies one record through the downstream client and checks the
// returned go.sum line is the reference database's (the client returns the
// lines for exactly the requested version, without the /go.mod variant).
func mustLookup(t *testing.T, client *sumdb.Client, modPath, version string) {
	t.Helper()
	lines, err := client.Lookup(modPath, version)
	if err != nil {
		t.Fatalf("downstream lookup %s@%s: %v", modPath, version, err)
	}
	want := fmt.Sprintf("%s %s h1:%s", modPath, version, fakeH1(modPath+" "+version))
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("lookup %s@%s lines = %q, want [%q]", modPath, version, lines, want)
	}
}

// growSumDB appends n padding records to the reference log, moving its tree
// head the way the real database moves between collects.
func growSumDB(t *testing.T, ts *sumdb.TestServer, n int) {
	t.Helper()
	for i := range n {
		mv := module.Version{Path: fmt.Sprintf("example.com/pad%04d", i), Version: "v1.0.0"}
		if _, err := ts.Lookup(context.Background(), mv); err != nil {
			t.Fatal(err)
		}
	}
}

// seedStaleLookup plants a lookup file in the low side's cache the way a racy
// parallel `go mod download` can: the record exists in the log, but the file
// embeds a signed head from just before the record was added — a head no
// proof for this record can exist under. The capture must repair (normalize)
// it before shipping.
func seedStaleLookup(t *testing.T, ls *LowServer, ts *sumdb.TestServer, dbURL, modPath string) {
	t.Helper()
	staleHead := httpGetBody(t, dbURL+"/latest")
	if _, err := ts.Lookup(context.Background(), module.Version{Path: modPath, Version: "v1.0.0"}); err != nil {
		t.Fatal(err)
	}
	fresh := httpGetBody(t, dbURL+"/lookup/"+modPath+"@v1.0.0")
	id, text, _, err := tlog.ParseRecord(fresh)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tlog.FormatRecord(id, text)
	if err != nil {
		t.Fatal(err)
	}
	rel, ok := sumdbLookupRel(modPath, "v1.0.0")
	if !ok {
		t.Fatalf("cannot escape %s", modPath)
	}
	stale := filepath.Join(ls.downloadDir, "sumdb", "artigate.test", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, stale, append(msg, staleHead...))
}

func httpGetBody(t *testing.T, url string) []byte {
	t.Helper()
	code, body := httpGet(t, url)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d (%s)", url, code, strings.TrimSpace(body))
	}
	return []byte(body)
}

// bundleManifestFromDir loads a staged bundle's manifest from the export dir.
func bundleManifestFromDir(t *testing.T, dir, bundleID string) BundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func countSumDBManifestFiles(m BundleManifest) (lookups, tiles, latest int) {
	for _, f := range m.Files {
		switch {
		case strings.HasPrefix(f.Path, "sumdb/artigate.test/lookup/"):
			lookups++
		case strings.HasPrefix(f.Path, "sumdb/artigate.test/tile/"):
			tiles++
		case f.Path == "sumdb/artigate.test/latest":
			latest++
		}
	}
	return lookups, tiles, latest
}

// TestGoSumDBMirrorEndToEnd drives the whole feature: two collects around a
// growing log, imports across the (simulated) diode, and stock downstream
// clients that verify every record in every fetch order using only the high
// side.
func TestGoSumDBMirrorEndToEnd(t *testing.T) {
	vkey, ts, sumSrv := newTestSumDB(t)
	ls, priv := newSumDBTestLow(t, vkey+" "+sumSrv.URL)
	ctx := context.Background()

	// Collect 1: one module while the log holds a single record.
	res, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/aaa@v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.SumDB == nil || res.SumDB.Name != "artigate.test" || res.SumDB.Records != 1 ||
		len(res.SumDB.Failed) != 0 || res.SumDB.Skipped != "" {
		t.Fatalf("collect 1 sumdb status = %+v", res.SumDB)
	}
	m := bundleManifestFromDir(t, ls.cfg.ExportDir, res.BundleID)
	if lookups, tiles, latest := countSumDBManifestFiles(m); lookups != 1 || tiles < 1 || latest != 1 {
		t.Fatalf("collect 1 sumdb files: %d lookups, %d tiles, %d latest", lookups, tiles, latest)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	importExported(t, ls, hs)

	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)
	base := srv.URL + "/go/sumdb/artigate.test"

	if code, _ := httpGet(t, base+"/supported"); code != http.StatusOK {
		t.Fatalf("supported = %d, want 200", code)
	}
	if code, _ := httpGet(t, srv.URL+"/go/sumdb/unknown.example/supported"); code != http.StatusNotFound {
		t.Fatal("supported must be refused for a database this mirror holds nothing for")
	}
	if code, _ := httpGet(t, base+"/lookup/example.com/zzz@v9.9.9"); code != http.StatusNotFound {
		t.Fatal("missing lookup must 404")
	}
	mustLookup(t, newDownstreamSumDBClient(t, base, vkey), "example.com/aaa", "v1.0.0")

	// The log grows well past the first leaf tile (256 records), so tiles
	// that shipped partial in bundle 1 exist in full form afterwards.
	growSumDB(t, ts, 600)

	// One record is planted with a stale embedded head (see seedStaleLookup);
	// a second is fetched normally and moves the head further.
	seedStaleLookup(t, ls, ts, sumSrv.URL, "example.com/ccc")
	res2, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{"example.com/ccc@v1.0.0", "example.com/ddd@v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.SumDB == nil || res2.SumDB.Records != 2 || len(res2.SumDB.Failed) != 0 {
		t.Fatalf("collect 2 sumdb status = %+v", res2.SumDB)
	}
	importExported(t, ls, hs)

	// The stale record's shipped lookup must now embed the exact served head:
	// the capture normalizes every not-yet-shipped lookup to the merged head.
	latest := httpGetBody(t, base+"/latest")
	ccc := httpGetBody(t, base+"/lookup/example.com/ccc@v1.0.0")
	if !bytes.HasSuffix(ccc, latest) {
		t.Fatal("shipped ccc lookup does not embed the served latest head")
	}

	// Fresh downstream clients, every fetch order: old records under old
	// heads, old records under the new head (full tiles that were partial
	// when first shipped), new records, and every merge direction between
	// bundle-1 and bundle-2 heads.
	orders := [][]string{
		{"aaa", "ccc", "ddd"},
		{"ddd", "aaa", "ccc"},
		{"ccc", "ddd", "aaa"},
		{"aaa"},
		{"ddd"},
	}
	for _, order := range orders {
		client := newDownstreamSumDBClient(t, base, vkey)
		for _, name := range order {
			mustLookup(t, client, "example.com/"+name, "v1.0.0")
		}
	}
}

// TestGoSumDBCaptureUnreachable checks the promise that capture never blocks
// module mirroring: with an unreachable database the collect still exports,
// reporting the records it could not capture.
func TestGoSumDBCaptureUnreachable(t *testing.T) {
	_, vkey, err := note.GenerateKey(rand.Reader, "artigate.test")
	if err != nil {
		t.Fatal(err)
	}
	ls, _ := newSumDBTestLow(t, vkey+" http://127.0.0.1:1")

	res, err := ls.CollectGo(context.Background(), GoCollectRequest{Modules: []string{"example.com/foo/bar@v1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sequence != 1 || res.ExportedModules != 1 {
		t.Fatalf("collect with unreachable sumdb: %+v", res)
	}
	if res.SumDB == nil || res.SumDB.Records != 0 || len(res.SumDB.Failed) == 0 {
		t.Fatalf("sumdb status = %+v, want failed capture", res.SumDB)
	}
	m := bundleManifestFromDir(t, ls.cfg.ExportDir, res.BundleID)
	if lookups, tiles, latest := countSumDBManifestFiles(m); lookups+tiles+latest != 0 {
		t.Fatalf("bundle must carry no sumdb files, got %d/%d/%d", lookups, tiles, latest)
	}
}

// TestGoSumDBCaptureGONOSUMDB checks that modules matching GONOSUMDB (or its
// GOPRIVATE default) are never looked up in the database and never counted as
// failures — the private-module story is unchanged.
func TestGoSumDBCaptureGONOSUMDB(t *testing.T) {
	vkey, _, sumSrv := newTestSumDB(t)
	ls, _ := newSumDBTestLow(t, vkey+" "+sumSrv.URL)
	ls.cfg.GONOSUMDB = "example.com/private/*"

	res, err := ls.CollectGo(context.Background(), GoCollectRequest{
		Modules: []string{"example.com/private/mod@v1.0.0", "example.com/open@v1.0.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.SumDB == nil || res.SumDB.Records != 1 || len(res.SumDB.Failed) != 0 {
		t.Fatalf("sumdb status = %+v, want 1 record and no failures", res.SumDB)
	}
	m := bundleManifestFromDir(t, ls.cfg.ExportDir, res.BundleID)
	for _, f := range m.Files {
		if strings.Contains(f.Path, "private") && strings.HasPrefix(f.Path, sumdbPathPrefix) {
			t.Fatalf("private module leaked into sumdb capture: %s", f.Path)
		}
	}
}

// TestGoSumDBServePathQualifiedName checks the high side serves a database
// whose name is path-qualified (host/path): both the supported probe and a
// stored file resolve through the multi-segment name.
func TestGoSumDBServePathQualifiedName(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	dir := filepath.Join(hs.goModuleDir(), "sumdb", "sums.example.com", "dev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "latest"), []byte("note"))
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)

	if code, _ := httpGet(t, srv.URL+"/go/sumdb/sums.example.com/dev/supported"); code != http.StatusOK {
		t.Fatalf("supported for a path-qualified name should be 200")
	}
	if code, body := httpGet(t, srv.URL+"/go/sumdb/sums.example.com/dev/latest"); code != http.StatusOK || body != "note" {
		t.Fatalf("latest = %d %q, want 200 %q", code, body, "note")
	}
	// A database this mirror holds nothing for still 404s the probe.
	if code, _ := httpGet(t, srv.URL+"/go/sumdb/sums.example.com/other/supported"); code != http.StatusNotFound {
		t.Fatalf("supported for an unmirrored path-qualified name should be 404")
	}
}

func TestGoSumDBServeRejectsTraversal(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	dir := filepath.Join(hs.goModuleDir(), "sumdb", "sum.golang.org")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "latest"), []byte("note"))
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)

	if code, body := httpGet(t, srv.URL+"/go/sumdb/sum.golang.org/latest"); code != http.StatusOK || body != "note" {
		t.Fatalf("latest = %d %q", code, body)
	}
	for _, p := range []string{
		"/go/sumdb/sum.golang.org/lookup/..%2f..%2fsecret@v1",
		"/go/sumdb/sum.golang.org/tile/8/0/../../../../etc/passwd",
		"/go/sumdb/sum.golang.org/weird",
	} {
		code, _ := httpGet(t, srv.URL+p)
		if code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 404/400", p, code)
		}
	}
}
