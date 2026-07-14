package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOsvNamesSlugsAndPaths(t *testing.T) {
	valid := []string{"npm", "PyPI", "Go", "crates.io", "Rocky Linux", "Alpine:v3.20", "Ubuntu:22.04:LTS", "GitHub Actions", "OSS-Fuzz"}
	for _, name := range valid {
		if err := validateOsvEcosystemName(name); err != nil {
			t.Errorf("validateOsvEcosystemName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{"", ".", "..", "-flag", ":v3", " npm", "npm ", "a/b", "a\\b", "café", strings.Repeat("x", 65), "_x", ".hidden"}
	for _, name := range invalid {
		if err := validateOsvEcosystemName(name); err == nil {
			t.Errorf("validateOsvEcosystemName(%q) = nil, want error", name)
		}
	}

	slugs := map[string]string{
		"npm":              "npm",
		"PyPI":             "pypi",
		"crates.io":        "crates.io",
		"Rocky Linux":      "rocky-linux",
		"Alpine:v3.20":     "alpine-v3.20",
		"Ubuntu:22.04:LTS": "ubuntu-22.04-lts",
	}
	for name, want := range slugs {
		if got := osvSlug(name); got != want {
			t.Errorf("osvSlug(%q) = %q, want %q", name, got, want)
		}
	}
	if got := osvDBRel("Alpine:v3.20"); got != "osv/dbs/alpine-v3.20/all.zip" {
		t.Errorf("osvDBRel(Alpine:v3.20) = %q", got)
	}

	ids := map[string]string{
		"GHSA-35jh-r3h4-6jhm.json":      "GHSA-35jh-r3h4-6jhm",
		"CVE-2024-12345.json":           "CVE-2024-12345",
		"MAL-2024-1.json":               "MAL-2024-1",
		"openSUSE-SU-2024:14066-1.json": "openSUSE-SU-2024:14066-1",
		"GHSA-x.json.sig":               "",
		"no-suffix":                     "",
		"-flag.json":                    "",
		"..json":                        "",
		"a/b.json":                      "",
		".json":                         "",
	}
	for name, want := range ids {
		if got := osvAdvisoryIDFromFilename(name); got != want {
			t.Errorf("osvAdvisoryIDFromFilename(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestOsvNpmRangeString(t *testing.T) {
	aff := func(t *testing.T, raw string) osvAffected {
		t.Helper()
		var a osvAffected
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			t.Fatalf("bad affected fixture: %v", err)
		}
		return a
	}
	tests := []struct {
		name, affected, want string
	}{
		{
			"from the beginning until fixed",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}`,
			"<1.2.3",
		},
		{
			"window between introduced and fixed",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.3"}]}]}`,
			">=1.0.0 <1.2.3",
		},
		{
			"inclusive last_affected",
			`{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.2.0"}]}]}`,
			">=1.0.0 <=1.2.0",
		},
		{
			"open-ended introduction",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}]}`,
			">=2.0.0",
		},
		{
			"everything",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`,
			"*",
		},
		{
			"two windows in one range",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"last_affected":"2.1.0"}]}]}`,
			"<1.2.3 || >=2.0.0 <=2.1.0",
		},
		{
			"explicit version list",
			`{"versions":["1.0.0","1.0.1"]}`,
			"1.0.0 || 1.0.1",
		},
		{
			"ranges and versions combine",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"3.0.0"}]}],"versions":["1.0.0"]}`,
			">=3.0.0 || 1.0.0",
		},
		{
			"git ranges are ignored beside semver",
			`{"ranges":[{"type":"GIT","events":[{"introduced":"abc123"}]},{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`,
			"<2.0.0",
		},
		{
			"git only says nothing about npm versions",
			`{"ranges":[{"type":"GIT","events":[{"introduced":"abc123"}]}]}`,
			"*",
		},
		{
			"unknown range type widens",
			`{"ranges":[{"type":"BOGUS","events":[{"introduced":"1.0.0"}]}]}`,
			"*",
		},
		{
			"close without open widens",
			`{"ranges":[{"type":"SEMVER","events":[{"fixed":"1.2.3"}]}]}`,
			"*",
		},
		{
			"unparsable event version widens",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0 || evil"},{"fixed":"2.0.0"}]}]}`,
			"*",
		},
		{
			"limit event widens",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]}`,
			"*",
		},
		{
			"empty event widens",
			`{"ranges":[{"type":"SEMVER","events":[{}]}]}`,
			"*",
		},
		{
			"unparsable listed version widens",
			`{"versions":["not a version"]}`,
			"*",
		},
		{
			"re-introduction leaves the prior window open-ended",
			`{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"introduced":"2.0.0"},{"fixed":"2.5.0"}]}]}`,
			">=1.0.0 || >=2.0.0 <2.5.0",
		},
		{"nothing at all", `{}`, "*"},
	}
	for _, tt := range tests {
		if got := osvNpmRangeString([]osvAffected{aff(t, tt.affected)}); got != tt.want {
			t.Errorf("%s: range = %q, want %q", tt.name, got, tt.want)
		}
	}

	// Several affected objects for one package merge; one bad object widens all.
	merged := osvNpmRangeString([]osvAffected{
		aff(t, `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}`),
		aff(t, `{"versions":["2.0.0"]}`),
	})
	if merged != "<1.0.0 || 2.0.0" {
		t.Errorf("merged range = %q", merged)
	}
	widened := osvNpmRangeString([]osvAffected{
		aff(t, `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}`),
		aff(t, `{"ranges":[{"type":"BOGUS","events":[]}]}`),
	})
	if widened != "*" {
		t.Errorf("range with one bad affected = %q, want *", widened)
	}
}

func TestOsvNpmAdvisoryRendering(t *testing.T) {
	entry := func(raw string) osvEntry {
		var e osvEntry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Fatalf("bad entry fixture: %v", err)
		}
		return e
	}

	// Severity: GitHub's qualitative level verbatim, critical for malware,
	// loud (high) for anything unknown.
	sevs := map[string]string{
		`{"id":"GHSA-1","database_specific":{"severity":"MODERATE"}}`: "moderate",
		`{"id":"GHSA-1","database_specific":{"severity":"CRITICAL"}}`: "critical",
		`{"id":"GHSA-1","database_specific":{"severity":"LOW"}}`:      "low",
		`{"id":"MAL-2024-1"}`: "critical",
		`{"id":"GHSA-1","database_specific":{"severity":"weird"}}`: "high",
		`{"id":"CVE-2024-1"}`: "high",
	}
	for raw, want := range sevs {
		if got := osvNpmSeverity(entry(raw)); got != want {
			t.Errorf("severity of %s = %q, want %q", raw, got, want)
		}
	}

	if got := osvAdvisoryURL("GHSA-35jh-r3h4-6jhm"); got != "https://github.com/advisories/GHSA-35jh-r3h4-6jhm" {
		t.Errorf("GHSA url = %q", got)
	}
	if got := osvAdvisoryURL("MAL-2024-1"); got != "https://osv.dev/vulnerability/MAL-2024-1" {
		t.Errorf("MAL url = %q", got)
	}

	titles := map[string]string{
		`{"id":"X-1","summary":"Prototype pollution"}`:       "Prototype pollution",
		`{"id":"X-1","details":"First line.\nSecond line."}`: "First line.",
		`{"id":"X-1"}`:                        "X-1",
		`{"id":"X-1","summary":"  padded  "}`: "padded",
		`{"id":"X-1","details":"` + strings.Repeat("y", 200) + `"}`: strings.Repeat("y", 139) + "…",
	}
	for raw, want := range titles {
		if got := osvAdvisoryTitle(entry(raw)); got != want {
			t.Errorf("title of %.60s = %q, want %q", raw, got, want)
		}
	}

	if a, b := osvNumericID("GHSA-a"), osvNumericID("GHSA-a"); a != b {
		t.Error("osvNumericID must be stable")
	}
	if osvNumericID("GHSA-a") == osvNumericID("GHSA-b") {
		t.Error("osvNumericID should differ across ids")
	}

	// A record affecting several ecosystems contributes only its npm names;
	// invalid names and withdrawn records contribute nothing.
	multi := entry(`{
		"id": "GHSA-multi", "summary": "s",
		"affected": [
			{"package":{"ecosystem":"npm","name":"testpkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]},
			{"package":{"ecosystem":"npm","name":"@scope/pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}]},
			{"package":{"ecosystem":"PyPI","name":"otherpkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
			{"package":{"ecosystem":"npm","name":"../evil"},"versions":["1.0.0"]}
		],
		"database_specific": {"severity":"HIGH","cwe_ids":["CWE-79","bogus"]}
	}`)
	advs := npmAdvisoriesForEntry(multi)
	if len(advs) != 2 {
		t.Fatalf("npm advisories = %+v, want testpkg and @scope/pkg", advs)
	}
	if got := advs["testpkg"]; got.VulnerableVersions != "<1.0.0" || got.Severity != "high" ||
		got.URL != "https://github.com/advisories/GHSA-multi" || strings.Join(got.CWE, ",") != "CWE-79" {
		t.Errorf("testpkg advisory = %+v", got)
	}
	if got := advs["@scope/pkg"]; got.VulnerableVersions != ">=2.0.0" {
		t.Errorf("@scope/pkg advisory = %+v", got)
	}
	if withdrawn := npmAdvisoriesForEntry(entry(`{"id":"GHSA-w","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"testpkg"}}]}`)); len(withdrawn) != 0 {
		t.Errorf("withdrawn record contributed %+v", withdrawn)
	}
}

func TestOsvValidateRecords(t *testing.T) {
	zipBytes := osvTestZip(t, map[string]string{"GHSA-1.json": `{"id":"GHSA-1"}`})
	sum := aptSHA256(zipBytes)
	rel := osvDBRel("npm")
	good := OsvDatabase{Ecosystem: "npm", Path: rel, SHA256: sum, Advisories: 1}
	seen := map[string]bool{rel: true}
	files := []ManifestFile{{Path: rel, SHA256: sum, Size: int64(len(zipBytes))}}

	if err := validateOsvDatabases(nil, nil, nil); err != nil {
		t.Errorf("empty database list = %v, want nil", err)
	}
	if err := validateOsvDatabases([]OsvDatabase{good}, seen, files); err != nil {
		t.Errorf("valid record rejected: %v", err)
	}

	mutate := func(f func(*OsvDatabase)) OsvDatabase {
		db := good
		f(&db)
		return db
	}
	bad := []struct {
		name string
		db   OsvDatabase
		seen map[string]bool
	}{
		{"invalid name", mutate(func(db *OsvDatabase) { db.Ecosystem = "../evil" }), seen},
		{"non-canonical path", mutate(func(db *OsvDatabase) { db.Path = "osv/dbs/NPM/all.zip" }), seen},
		{"path outside osv tree", mutate(func(db *OsvDatabase) { db.Path = "npm/packages/all.zip" }), seen},
		{"file not listed in manifest", good, map[string]bool{}},
		{"empty sha256", mutate(func(db *OsvDatabase) { db.SHA256 = "" }), seen},
		{"record sha disagrees with manifest.files", mutate(func(db *OsvDatabase) { db.SHA256 = aptSHA256([]byte("other")) }), seen},
	}
	for _, tt := range bad {
		if err := validateOsvDatabases([]OsvDatabase{tt.db}, tt.seen, files); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

func TestOsvZipAdvisoryCount(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.zip")
	writeFile(t, good, osvTestZip(t, map[string]string{
		"GHSA-1.json": `{"id":"GHSA-1"}`,
		"CVE-2.json":  `{"id":"CVE-2"}`,
		"README.txt":  "not an advisory",
	}))
	if n, err := osvZipAdvisoryCount(good); err != nil || n != 2 {
		t.Errorf("osvZipAdvisoryCount(good) = %d, %v; want 2, nil", n, err)
	}

	empty := filepath.Join(dir, "empty.zip")
	writeFile(t, empty, osvTestZip(t, map[string]string{"README.txt": "no advisories"}))
	if _, err := osvZipAdvisoryCount(empty); err == nil {
		t.Error("zip without advisories accepted")
	}

	notZip := filepath.Join(dir, "not.zip")
	writeFile(t, notZip, []byte("this is not a zip"))
	if _, err := osvZipAdvisoryCount(notZip); err == nil {
		t.Error("non-zip accepted")
	}
}

// osvTestZip builds an in-memory zip with the given entries, sorted for
// deterministic bytes so hash assertions can reuse the result.
func osvTestZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entries[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Fixture advisories for the pipeline tests. testpkg has a fixed window and
// a scoped sibling; evilpkg is a malicious-package record; the withdrawn
// record must never reach the audit index.
const (
	osvTestGHSA = `{
		"id": "GHSA-aaaa-bbbb-cccc",
		"summary": "Prototype pollution in testpkg",
		"affected": [
			{"package":{"ecosystem":"npm","name":"testpkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]},
			{"package":{"ecosystem":"npm","name":"@scope/pkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"}]}]},
			{"package":{"ecosystem":"PyPI","name":"otherpkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}
		],
		"database_specific": {"severity":"MODERATE","cwe_ids":["CWE-1321"]}
	}`
	osvTestMAL = `{
		"id": "MAL-2024-1",
		"summary": "Malicious code in evilpkg",
		"affected": [
			{"package":{"ecosystem":"npm","name":"evilpkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}
		]
	}`
	osvTestWithdrawn = `{
		"id": "GHSA-gone-gone-gone",
		"withdrawn": "2024-01-01T00:00:00Z",
		"summary": "Retracted advisory",
		"affected": [
			{"package":{"ecosystem":"npm","name":"testpkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}
		]
	}`
	osvTestAlpine = `{
		"id": "CVE-2024-0001",
		"summary": "Alpine package flaw",
		"affected": [
			{"package":{"ecosystem":"Alpine:v3.20","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.3.1-r0"}]}]}
		]
	}`
)

func osvTestNpmZip(t *testing.T) []byte {
	t.Helper()
	return osvTestZip(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc.json": osvTestGHSA,
		"MAL-2024-1.json":          osvTestMAL,
		"GHSA-gone-gone-gone.json": osvTestWithdrawn,
	})
}

// fakeOsvUpstream is an httptest OSV bucket serving one all.zip per
// registered ecosystem name, counting hits per path.
type fakeOsvUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int
	dbs  map[string][]byte // "/<name>/all.zip" -> zip bytes
}

func newFakeOsvUpstream(t *testing.T) *fakeOsvUpstream {
	t.Helper()
	f := &fakeOsvUpstream{hits: map[string]int{}, dbs: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		body, ok := f.dbs[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOsvUpstream) set(name string, zipBytes []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dbs["/"+name+"/all.zip"] = zipBytes
}

func osvTestSetup(t *testing.T) (*fakeOsvUpstream, *LowServer, ed25519.PrivateKey) {
	t.Helper()
	up := newFakeOsvUpstream(t)
	up.set("npm", osvTestNpmZip(t))
	up.set("Alpine:v3.20", osvTestZip(t, map[string]string{"CVE-2024-0001.json": osvTestAlpine}))
	_, priv := newTestKeys(t)
	cfg := LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), OsvUpstream: up.srv.URL}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return up, ls, priv
}

// postAuditBulk POSTs a bulk audit query, optionally gzip-encoded like the
// real npm client, and decodes the response map.
func postAuditBulk(t *testing.T, base, body string, gzipped bool) (int, map[string][]npmAuditAdvisory) {
	t.Helper()
	payload := []byte(body)
	if gzipped {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		payload = buf.Bytes()
	}
	req, err := http.NewRequest(http.MethodPost, base+"/npm/-/npm/v1/security/advisories/bulk", bytes.NewReader(payload)) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string][]npmAuditAdvisory
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("bulk response is not JSON: %v", err)
		}
	}
	return resp.StatusCode, out
}

// TestOsvLowToHighPipeline is the full round-trip: fetch two databases from
// a fake OSV bucket, export a signed bundle, import it on the high side,
// serve the bucket layout, and answer npm bulk audits from the regenerated
// index — then refresh the database and prove the snapshot is replaced.
func TestOsvLowToHighPipeline(t *testing.T) {
	up, ls, priv := osvTestSetup(t)
	ctx := context.Background()
	npmZip := osvTestNpmZip(t)

	res, err := ls.CollectOsv(ctx, OsvCollectRequest{Ecosystems: []string{"npm", "Alpine:v3.20"}})
	if err != nil {
		t.Fatalf("CollectOsv: %v", err)
	}
	if res.BundleID != "osv-bundle-000001" || res.ExportedModules != 2 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if m.Osv == nil || len(m.Osv.Databases) != 2 {
		t.Fatalf("bundle manifest osv = %+v", m.Osv)
	}
	alpine, npmDB := m.Osv.Databases[0], m.Osv.Databases[1] // sorted by name
	if alpine.Ecosystem != "Alpine:v3.20" || alpine.Path != "osv/dbs/alpine-v3.20/all.zip" || alpine.Advisories != 1 {
		t.Errorf("alpine record = %+v", alpine)
	}
	if npmDB.Ecosystem != "npm" || npmDB.Path != "osv/dbs/npm/all.zip" || npmDB.SHA256 != aptSHA256(npmZip) || npmDB.Advisories != 3 {
		t.Errorf("npm record = %+v", npmDB)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	imp, err := hs.ImportNext()
	if err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
	if !imp.Imported || len(imp.ImportedBundles) != 1 {
		t.Fatalf("unexpected import result: %+v", imp)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, body := httpGet(t, srv.URL+"/osv/ecosystems.txt")
	if code != http.StatusOK || body != "Alpine:v3.20\nnpm\n" {
		t.Errorf("ecosystems.txt = %d %q", code, body)
	}
	code, body = httpGet(t, srv.URL+"/osv/npm/all.zip")
	if code != http.StatusOK || body != string(npmZip) {
		t.Errorf("npm all.zip: status %d, %d byte(s), want the collected zip", code, len(body))
	}
	// The name-addressed and slug-addressed routes serve the same database.
	for _, p := range []string{"/osv/Alpine:v3.20/all.zip", "/osv/alpine-v3.20/all.zip", "/osv/Alpine%3Av3.20/all.zip"} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, code)
		}
	}
	code, body = httpGet(t, srv.URL+"/osv/npm/GHSA-aaaa-bbbb-cccc.json")
	if code != http.StatusOK || body != osvTestGHSA {
		t.Errorf("advisory fetch = %d %q", code, body)
	}
	if code, _ := httpGet(t, srv.URL+"/osv/npm/GHSA-none.json"); code != http.StatusNotFound {
		t.Errorf("unknown advisory = %d, want 404", code)
	}

	// The bulk audit endpoint answers plain and gzip queries identically:
	// the vulnerable packages come back with their rendered ranges, the
	// withdrawn advisory stays gone, unknown names are simply absent.
	for _, gzipped := range []bool{false, true} {
		code, out := postAuditBulk(t, srv.URL, `{"testpkg":["1.0.0"],"@scope/pkg":["2.0.0"],"evilpkg":["0.0.1"],"cleanpkg":["1.0.0"]}`, gzipped)
		if code != http.StatusOK {
			t.Fatalf("bulk audit (gzip=%v) = %d", gzipped, code)
		}
		if len(out) != 3 {
			t.Fatalf("bulk audit (gzip=%v) returned %d name(s): %+v", gzipped, len(out), out)
		}
		tp := out["testpkg"]
		if len(tp) != 1 || tp[0].VulnerableVersions != "<1.2.3" || tp[0].Severity != "moderate" ||
			tp[0].Title != "Prototype pollution in testpkg" || tp[0].URL != "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" ||
			tp[0].ID == 0 || strings.Join(tp[0].CWE, ",") != "CWE-1321" {
			t.Errorf("testpkg advisories = %+v", tp)
		}
		if sp := out["@scope/pkg"]; len(sp) != 1 || sp[0].VulnerableVersions != ">=1.0.0" {
			t.Errorf("@scope/pkg advisories = %+v", sp)
		}
		if ep := out["evilpkg"]; len(ep) != 1 || ep[0].VulnerableVersions != "*" || ep[0].Severity != "critical" {
			t.Errorf("evilpkg advisories = %+v", ep)
		}
	}

	// An unchanged upstream dedups to a no-op export that burns no sequence.
	res2, err := ls.CollectOsv(ctx, OsvCollectRequest{Ecosystems: []string{"npm", "Alpine:v3.20"}})
	if err != nil {
		t.Fatalf("second CollectOsv: %v", err)
	}
	if !res2.Skipped || res2.BundleID != "" {
		t.Fatalf("unchanged collect = %+v, want skipped", res2)
	}
	if seq := ls.peekSequence(streamOsv); seq != 2 {
		t.Errorf("next sequence = %d, want 2", seq)
	}

	// Upstream refreshed: the withdrawn advisory is dropped and a new one
	// appears. The re-collect replaces the snapshot at the same canonical
	// path (the one mutable mirrored subtree) and the regenerated index
	// follows — the fixed package no longer reports, the new one does.
	updated := osvTestZip(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc.json": osvTestGHSA,
		"GHSA-dddd-eeee-ffff.json": `{"id":"GHSA-dddd-eeee-ffff","summary":"New flaw in newpkg","affected":[{"package":{"ecosystem":"npm","name":"newpkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.5.0"}]}]}],"database_specific":{"severity":"CRITICAL"}}`,
	})
	up.set("npm", updated)
	res3, err := ls.CollectOsv(ctx, OsvCollectRequest{Ecosystems: []string{"npm", "Alpine:v3.20"}})
	if err != nil {
		t.Fatalf("third CollectOsv: %v", err)
	}
	if res3.Skipped || res3.ExportedModules != 2 || res3.PriorFiles != 1 {
		t.Fatalf("refresh collect = %+v, want the npm snapshot delivered and the alpine one prior", res3)
	}
	transferAptBundle(t, ls, hs, res3.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("refresh import: %v", err)
	}
	code, body = httpGet(t, srv.URL+"/osv/npm/all.zip")
	if code != http.StatusOK || body != string(updated) {
		t.Errorf("refreshed all.zip: status %d, %d byte(s), want the new snapshot", code, len(body))
	}
	code, out := postAuditBulk(t, srv.URL, `{"newpkg":["0.1.0"],"evilpkg":["0.0.1"]}`, false)
	if code != http.StatusOK || len(out["newpkg"]) != 1 || len(out["evilpkg"]) != 0 {
		t.Errorf("refreshed bulk audit = %d %+v, want newpkg only", code, out)
	}

	// A 404ing ecosystem is reported, never fatal for the batch.
	res4, err := ls.CollectOsv(ctx, OsvCollectRequest{Ecosystems: []string{"NoSuchEco", "npm"}, Force: true})
	if err != nil {
		t.Fatalf("partial-failure collect: %v", err)
	}
	if len(res4.SkippedModules) != 1 || res4.SkippedModules[0].Module != "NoSuchEco" || res4.ExportedModules != 1 {
		t.Fatalf("partial-failure result = %+v", res4)
	}
	// All ecosystems failing is an error.
	if _, err := ls.CollectOsv(ctx, OsvCollectRequest{Ecosystems: []string{"NoSuchEco"}}); err == nil ||
		!strings.Contains(err.Error(), "no OSV databases could be fetched") {
		t.Fatalf("all-failed collect = %v", err)
	}
}

func TestOsvCollectRequestValidation(t *testing.T) {
	if _, err := validateOsvRequest(OsvCollectRequest{}); err == nil {
		t.Error("empty request accepted")
	}
	if _, err := validateOsvRequest(OsvCollectRequest{Ecosystems: []string{"  ", ""}}); err == nil {
		t.Error("blank names accepted")
	}
	if _, err := validateOsvRequest(OsvCollectRequest{Ecosystems: []string{"a/b"}}); err == nil {
		t.Error("invalid name accepted")
	}
	// Distinct names colliding on one storage slug cannot share a bundle.
	if _, err := validateOsvRequest(OsvCollectRequest{Ecosystems: []string{"PyPI", "pypi"}}); err == nil {
		t.Error("slug collision accepted")
	}
	names, err := validateOsvRequest(OsvCollectRequest{Ecosystems: []string{" npm ", "npm", "PyPI"}})
	if err != nil || strings.Join(names, ",") != "npm,PyPI" {
		t.Errorf("cleaned names = %v, %v", names, err)
	}
}

// TestOsvAuditUnavailableWithoutDatabase pins the fail-loud contract: a high
// side that never imported the npm OSV database answers the audit endpoint
// with 404 (npm reports "audit unavailable"), never with an empty all-clear.
func TestOsvAuditUnavailableWithoutDatabase(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	code, _ := postAuditBulk(t, srv.URL, `{"lodash":["4.17.20"]}`, false)
	if code != http.StatusNotFound {
		t.Errorf("bulk audit without database = %d, want 404", code)
	}
	if code, _ := httpGet(t, srv.URL+"/osv/ecosystems.txt"); code != http.StatusNotFound {
		t.Errorf("ecosystems.txt without databases = %d, want 404", code)
	}
}

func TestOsvBulkBodyParsing(t *testing.T) {
	plain, err := readNpmAuditBulkBody(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"a":["1.0.0"]}`)))
	if err != nil || len(plain["a"]) != 1 {
		t.Errorf("plain body = %+v, %v", plain, err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(`{"b":[]}`))
	_ = gz.Close()
	req := httptest.NewRequest(http.MethodPost, "/x", &buf)
	req.Header.Set("Content-Encoding", "GZIP") // header value is case-insensitive
	if body, err := readNpmAuditBulkBody(req); err != nil {
		t.Errorf("gzip body: %v", err)
	} else if _, ok := body["b"]; !ok {
		t.Errorf("gzip body = %+v", body)
	}
	req = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("not gzip"))
	req.Header.Set("Content-Encoding", "gzip")
	if _, err := readNpmAuditBulkBody(req); err == nil {
		t.Error("bad gzip accepted")
	}
	if _, err := readNpmAuditBulkBody(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("not json"))); err == nil {
		t.Error("non-JSON accepted")
	}
}

// TestOsvRouteHardening checks the /osv/ routes reject traversal, odd
// shapes, and non-read methods without serving anything.
func TestOsvRouteHardening(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	for _, p := range []string{
		"/osv",
		"/osv/",
		"/osv/npm",
		"/osv/npm/",
		"/osv/..%2f..%2fimport-state.json",
		"/osv/npm/..%2f..%2fall.zip",
		"/osv/npm/GHSA-1.json%2fmore",
		"/osv/npm/steal.txt",
		"/osv/npm/all.zip.sig",
		"/osv/-flag/all.zip",
		"/osv/npm/all.zip/extra",
	} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("GET %s = 200, want rejection", p)
		}
	}
	resp, err := http.Post(srv.URL+"/osv/npm/all.zip", "application/zip", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST all.zip = %d, want 405", resp.StatusCode)
	}
	resp, err = http.Get(srv.URL + "/npm/-/npm/v1/security/advisories/bulk") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET bulk audit = %d, want 405", resp.StatusCode)
	}
}

// osvWriteSignedBundle assembles a signed osv bundle in landing from raw
// records and payloads, reusing the production tar/sign helpers, so tests
// can craft inconsistent manifests.
func osvWriteSignedBundle(t *testing.T, landing string, priv ed25519.PrivateKey, seq int64, records []OsvDatabase, payloads map[string][]byte) {
	t.Helper()
	src := t.TempDir()
	var files []ManifestFile
	for rel, content := range payloads {
		abs := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, abs, content)
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, mf)
	}
	bundleID := bundleIDFor(streamOsv, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamOsv,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Unix(0, 0).UTC(),
		Generator:        "test",
		BundleID:         bundleID,
		Ecosystems:       []string{"osv"},
		Osv:              &OsvManifest{Databases: records},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifestBytes)
	if err := os.MkdirAll(landing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createTarGzAtomic(context.Background(), filepath.Join(landing, bundleID+".tar.gz"), src, files); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json"), manifestBytes)
	writeFile(t, filepath.Join(landing, bundleID+".manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"))
}

// TestOsvImportRejectsTamperedRecord proves the import-side validator is
// wired in: a signed bundle whose record hash disagrees with the delivered
// artifact — or whose path is not the ecosystem's canonical one — is
// rejected as a whole, and nothing from it is served.
func TestOsvImportRejectsTamperedRecord(t *testing.T) {
	zipBytes := osvTestZip(t, map[string]string{"GHSA-1.json": `{"id":"GHSA-1"}`})
	rel := osvDBRel("npm")
	tampered := []struct {
		name string
		rec  OsvDatabase
	}{
		{"sha mismatch", OsvDatabase{Ecosystem: "npm", Path: rel, SHA256: aptSHA256([]byte("other")), Advisories: 1}},
		{"non-canonical path", OsvDatabase{Ecosystem: "PyPI", Path: rel, SHA256: aptSHA256(zipBytes), Advisories: 1}},
	}
	for _, tt := range tampered {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			osvWriteSignedBundle(t, hs.cfg.Landing, priv, 1, []OsvDatabase{tt.rec}, map[string][]byte{rel: zipBytes})
			res, err := hs.ImportNext()
			if err != nil {
				t.Fatalf("ImportNext: %v", err)
			}
			if res.Imported || len(res.RejectedBundles) != 1 {
				t.Fatalf("import result = %+v, want the bundle rejected", res)
			}
			srv := httptest.NewServer(hs)
			defer srv.Close()
			if code, _ := httpGet(t, srv.URL+"/osv/npm/all.zip"); code == http.StatusOK {
				t.Error("rejected bundle's database must not be served")
			}
		})
	}
}

// TestOsvDashboardListAndDetail covers the high-side dashboard helpers over
// an imported bundle.
func TestOsvDashboardListAndDetail(t *testing.T) {
	_, ls, priv := osvTestSetup(t)
	res, err := ls.CollectOsv(context.Background(), OsvCollectRequest{Ecosystems: []string{"npm", "Alpine:v3.20"}})
	if err != nil {
		t.Fatalf("CollectOsv: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	transferAptBundle(t, ls, hs, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import: %v", err)
	}

	dbs, err := hs.listOsvDatabases()
	if err != nil {
		t.Fatalf("listOsvDatabases: %v", err)
	}
	if len(dbs) != 2 || dbs[0].Module != "Alpine:v3.20" || dbs[1].Module != "npm" ||
		strings.Join(dbs[1].Versions, " ") != "all.zip" {
		t.Fatalf("listOsvDatabases = %+v", dbs)
	}

	det, err := hs.osvDetail("npm@all.zip")
	if err != nil {
		t.Fatalf("osvDetail: %v", err)
	}
	if det.Title != "npm" || det.Subtitle != "3 advisories" {
		t.Errorf("detail identity = %q %q", det.Title, det.Subtitle)
	}
	fields := map[string]string{}
	for _, f := range det.Fields {
		fields[f.Label] = f.Value
	}
	if fields["SHA-256"] != aptSHA256(osvTestNpmZip(t)) {
		t.Errorf("detail SHA-256 = %q", fields["SHA-256"])
	}
	if fields["Download path"] != "/osv/npm/all.zip" || fields["npm audit"] == "" {
		t.Errorf("detail fields = %+v", fields)
	}
	if len(det.Downloads) != 1 || det.Downloads[0].URL != "/osv/npm/all.zip" {
		t.Errorf("detail downloads = %+v", det.Downloads)
	}
	if det, err := hs.osvDetail("Alpine:v3.20@all.zip"); err != nil || det.Title != "Alpine:v3.20" {
		t.Errorf("alpine detail = %+v, %v", det, err)
	}

	for _, spec := range []string{"npm", "npm@other", "nosuch@all.zip", "../x@all.zip"} {
		if _, err := hs.osvDetail(spec); err == nil {
			t.Errorf("osvDetail(%q) = nil error, want error", spec)
		}
	}
}
