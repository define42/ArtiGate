package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// java.go: pure version ordering and diagnostics helpers
// -----------------------------------------------------------------------------

// TestCovLang_MavenVersionLess pins the best-effort ordering rules: numeric
// tokens compare numerically (not lexically), a numeric token sorts before an
// alphabetic one, shorter-but-equal-prefix versions sort first, and equal
// versions are not "less".
func TestCovLang_MavenVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", false},
		{"1.0", "1.0.1", true},           // shorter equal prefix sorts first
		{"1.10", "1.9", false},           // numeric compare, not lexical
		{"1.9", "1.10", true},            // numeric compare, not lexical
		{"1.0-alpha", "1.0-beta", true},  // alphabetic tokens compared lexically
		{"1.0-beta", "1.0-alpha", false}, // alphabetic tokens compared lexically
		{"1.0", "1.Final", true},         // numeric token sorts before alphabetic
		{"1.Final", "1.0", false},        // alphabetic token sorts after numeric
		{"1.0.0", "1.0.0", false},        // equal is not less
	}
	for _, tc := range cases {
		if got := mavenVersionLess(tc.a, tc.b); got != tc.want {
			t.Errorf("mavenVersionLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}

	// sortMavenVersions must produce ascending order under those same rules.
	vs := []string{"1.10", "2.0", "1.0", "1.9"}
	sortMavenVersions(vs)
	if got := strings.Join(vs, ","); got != "1.0,1.9,1.10,2.0" {
		t.Errorf("sortMavenVersions = %q, want 1.0,1.9,1.10,2.0", got)
	}
}

// TestCovLang_TailBytes covers the mvn error-diagnostic tail helper: it keeps
// only the last n bytes and trims surrounding whitespace.
func TestCovLang_TailBytes(t *testing.T) {
	if got := tailBytes([]byte("0123456789"), 4); got != "6789" {
		t.Errorf("tailBytes tail = %q, want 6789", got)
	}
	if got := tailBytes([]byte("  short body  "), 1024); got != "short body" {
		t.Errorf("tailBytes short = %q, want \"short body\"", got)
	}
	if got := tailBytes(nil, 8); got != "" {
		t.Errorf("tailBytes(nil) = %q, want empty", got)
	}
}

// covLangWritePom creates an empty .pom under the artifact's version directory
// so buildMavenMetadata counts that version.
func covLangWritePom(t *testing.T, root, artifactPath, version string) {
	t.Helper()
	segs := strings.Split(artifactPath, "/")
	artifactID := segs[len(segs)-1]
	dir := filepath.Join(root, filepath.FromSlash(artifactPath), version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, artifactID+"-"+version+".pom"),
		[]byte("<project><modelVersion>4.0.0</modelVersion></project>"))
}

// TestCovLang_MavenMetadataServe drives serveMaven/serveMavenMetadata for the
// generated maven-metadata.xml and BOTH legacy checksum forms (.sha1 and .md5),
// plus the directly-served .pom, the empty-directory 404, and the
// method-not-allowed branch.
func TestCovLang_MavenMetadataServe(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	root := hs.mavenDir()

	const art = "com/example/lib"
	for _, v := range []string{"1.0.0", "1.9.0", "1.10.0", "2.0.0"} {
		covLangWritePom(t, root, art, v)
	}
	// A version directory with no .pom is ignored by buildMavenMetadata.
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(art), "9.9-empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(art), "9.9-empty", "note.txt"), []byte("x"))

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// The generated metadata lists every version and points latest/release at the
	// highest (numeric-aware) version.
	code, body := httpGet(t, srv.URL+"/maven/com/example/lib/maven-metadata.xml")
	if code != http.StatusOK {
		t.Fatalf("metadata.xml status %d", code)
	}
	for _, want := range []string{
		"<groupId>com.example</groupId>", "<artifactId>lib</artifactId>",
		"<latest>2.0.0</latest>", "<release>2.0.0</release>",
		"<version>1.9.0</version>", "<version>1.10.0</version>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata.xml missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "9.9-empty") {
		t.Errorf("metadata.xml listed a version dir with no .pom:\n%s", body)
	}

	// Both checksum forms are computed from the generated XML.
	if _, sha := httpGet(t, srv.URL+"/maven/com/example/lib/maven-metadata.xml.sha1"); len(strings.TrimSpace(sha)) != 40 {
		t.Errorf("metadata sha1 = %q, want 40 hex chars", sha)
	}
	if _, md5 := httpGet(t, srv.URL+"/maven/com/example/lib/maven-metadata.xml.md5"); len(strings.TrimSpace(md5)) != 32 {
		t.Errorf("metadata md5 = %q, want 32 hex chars", md5)
	}

	// A stored .pom is served directly.
	assertServed(t, srv.URL+"/maven/com/example/lib/1.0.0/lib-1.0.0.pom", "modelVersion")

	// A group/artifact directory with no versions yields 404.
	if code, _ := httpGet(t, srv.URL+"/maven/com/example/absent/maven-metadata.xml"); code != http.StatusNotFound {
		t.Errorf("absent artifact metadata status %d, want 404", code)
	}

	// serveMaven only answers GET/HEAD.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/maven/com/example/lib/maven-metadata.xml", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /maven status %d, want 405", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// npm.go: registry serving error routes and pure resolver helpers
// -----------------------------------------------------------------------------

// TestCovLang_NpmServeRoutes publishes one package straight through
// publishNpmPackage (regenerating served metadata from the tarball's embedded
// package.json), then exercises the packument, version-manifest, and tarball
// routes plus every not-found/bad-input branch of serveNpm.
func TestCovLang_NpmServeRoutes(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	tgz := makeNpmTgz(t, "package", "lodash", "4.17.21")
	rel := "npm/packages/lodash/lodash-4.17.21.tgz"
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, abs, tgz)
	if err := hs.publishNpmPackage(NpmPackage{Name: "lodash", Version: "4.17.21", Path: rel}); err != nil {
		t.Fatalf("publishNpmPackage: %v", err)
	}

	// Junk beside the real metadata: a non-version filename and a version whose
	// tarball is absent must both be skipped when assembling the packument.
	metaDir := filepath.Join(hs.npmMetadataDir(), "lodash")
	writeFile(t, filepath.Join(metaDir, "garbage.json"), []byte(`{"filename":"x"}`))
	writeFile(t, filepath.Join(metaDir, "5.0.0.json"), []byte(`{"filename":"lodash-5.0.0.tgz"}`))

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Packument advertises only the complete version and flags the install script
	// (makeNpmTgz embeds a postinstall).
	code, body := httpGet(t, srv.URL+"/npm/lodash")
	if code != http.StatusOK {
		t.Fatalf("packument status %d", code)
	}
	for _, want := range []string{`"4.17.21"`, `"latest": "4.17.21"`, `"hasInstallScript": true`} {
		if !strings.Contains(body, want) {
			t.Errorf("packument missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `"5.0.0"`) {
		t.Errorf("packument advertised a version with a missing tarball:\n%s", body)
	}

	// Version manifest and tarball both resolve.
	assertServed(t, srv.URL+"/npm/lodash/4.17.21", `"version": "4.17.21"`)
	if code, got := httpGet(t, srv.URL+"/npm/lodash/-/lodash-4.17.21.tgz"); code != http.StatusOK || got != string(tgz) {
		t.Errorf("tarball download: status %d, %d bytes (want %d)", code, len(got), len(tgz))
	}

	// Error branches.
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/npm/lodash/notaversion", http.StatusNotFound},          // handleNpmVersion: bad version
		{"/npm/lodash/9.9.9", http.StatusNotFound},                // handleNpmVersion: no stored manifest
		{"/npm/lodash/-/lodash-4.17.21.txt", http.StatusNotFound}, // handleNpmTarball: not .tgz
		{"/npm/-bad/-/x.tgz", http.StatusNotFound},                // handleNpmTarball: invalid name
		{"/npm/a/b/c/d", http.StatusNotFound},                     // splitNpmPackagePath: too many segments
	} {
		if code, _ := httpGet(t, srv.URL+tc.path); code != tc.want {
			t.Errorf("GET %s status %d, want %d", tc.path, code, tc.want)
		}
	}

	// serveNpm only answers read methods.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/npm/lodash", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /npm status %d, want 405", resp.StatusCode)
	}
}

// TestCovLang_NpmProjectAndArgs covers the pure project-materialization and
// argument-building helpers for the resolving npm run.
func TestCovLang_NpmProjectAndArgs(t *testing.T) {
	// Explicit packages: a synthetic package.json is written and the specs are
	// returned for `npm install`.
	dir := t.TempDir()
	specs, err := writeNpmProject(dir, NpmCollectRequest{Packages: []string{"lodash", "react"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Errorf("specs = %v, want the two packages", specs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "package.json")); !strings.Contains(string(b), "artigate-collect") {
		t.Errorf("synthetic package.json = %s", b)
	}

	// Uploaded project (with a lock): the caller's files are written verbatim and
	// no specs are passed to npm.
	dir2 := t.TempDir()
	specs, err = writeNpmProject(dir2, NpmCollectRequest{
		PackageJSON: `{"name":"app","version":"1.2.3"}`,
		PackageLock: `{"lockfileVersion":3}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 0 {
		t.Errorf("uploaded project should pass no specs, got %v", specs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "package.json")); !strings.Contains(string(b), `"app"`) {
		t.Errorf("uploaded package.json not written verbatim: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir2, "package-lock.json")); !strings.Contains(string(b), "lockfileVersion") {
		t.Errorf("uploaded package-lock.json not written")
	}

	// npmInstallArgs always resolves lock-only with scripts disabled, and only
	// appends --registry when one is configured.
	base := npmInstallArgs("", []string{"lodash"})
	joined := strings.Join(base, " ")
	for _, want := range []string{"install", "--package-lock-only", "--ignore-scripts"} {
		if !strings.Contains(joined, want) {
			t.Errorf("npmInstallArgs missing %q: %v", want, base)
		}
	}
	if strings.Contains(joined, "--registry") {
		t.Errorf("npmInstallArgs added a registry flag with no registry set: %v", base)
	}
	if base[len(base)-1] != "lodash" {
		t.Errorf("spec not appended last: %v", base)
	}
	withReg := npmInstallArgs("http://reg.example", nil)
	if !strings.Contains(strings.Join(withReg, " "), "--registry=http://reg.example") {
		t.Errorf("npmInstallArgs dropped the registry flag: %v", withReg)
	}
}

// TestCovLang_NpmLockEntryFor covers validating one lockfile package into a
// fetchable entry and each reason it is skipped.
func TestCovLang_NpmLockEntryFor(t *testing.T) {
	ok, fail := npmLockEntryFor("lodash", npmLockPackage{Version: "4.17.21", Resolved: "https://reg.example/lodash/-/lodash-4.17.21.tgz", Integrity: "sha512-x"})
	if fail != nil {
		t.Fatalf("valid entry rejected: %+v", fail)
	}
	if ok.Name != "lodash" || ok.Version != "4.17.21" || ok.Integrity != "sha512-x" {
		t.Errorf("unexpected entry: %+v", ok)
	}

	bad := []struct {
		name string
		p    npmLockPackage
	}{
		{"-flag", npmLockPackage{Version: "1.0.0", Resolved: "https://x/y.tgz"}},         // invalid name
		{"pkg", npmLockPackage{Version: "", Resolved: "https://x/y.tgz"}},                // empty version
		{"pkg", npmLockPackage{Version: "bad ver", Resolved: "https://x/y.tgz"}},         // invalid version
		{"pkg", npmLockPackage{Version: "1.0.0", Resolved: ""}},                          // no resolved URL
		{"pkg", npmLockPackage{Version: "1.0.0", Resolved: "git+ssh://git@h/x.git#abc"}}, // non-http scheme
	}
	for _, tc := range bad {
		if _, fail := npmLockEntryFor(tc.name, tc.p); fail == nil {
			t.Errorf("npmLockEntryFor(%q, %+v) accepted an unfetchable entry", tc.name, tc.p)
		}
	}
}

// -----------------------------------------------------------------------------
// python.go: PyPI serving routes and pure filename helpers
// -----------------------------------------------------------------------------

// TestCovLang_PyServeRoutes places a wheel directly in the store and exercises
// the simple root, project page (with its sha256 fragment), tarball download,
// and the handlePyPackage/servePython error branches.
func TestCovLang_PyServeRoutes(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if err := os.MkdirAll(hs.pythonDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hs.pythonDir(), "requests-2.32.4-py3-none-any.whl"), []byte("wheel-bytes"))

	srv := httptest.NewServer(hs)
	defer srv.Close()

	assertServed(t, srv.URL+"/simple/", "/simple/requests/")
	assertServed(t, srv.URL+"/simple/requests/", "/packages/requests-2.32.4-py3-none-any.whl#sha256=")
	if code, body := httpGet(t, srv.URL+"/packages/requests-2.32.4-py3-none-any.whl"); code != http.StatusOK || body != "wheel-bytes" {
		t.Errorf("wheel download: status %d body %q", code, body)
	}

	// handlePyPackage rejects an empty filename and any embedded slash.
	if code, _ := httpGet(t, srv.URL+"/packages/"); code != http.StatusNotFound {
		t.Errorf("empty package name status %d, want 404", code)
	}

	// servePython only answers GET/HEAD.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/simple/", nil) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /simple/ status %d, want 405", resp.StatusCode)
	}
}

// TestCovLang_PyFilenameParsers covers the remaining branches of the wheel and
// sdist filename parsers and of collectPythonDist's classification.
func TestCovLang_PyFilenameParsers(t *testing.T) {
	// A wheel with an empty version field does not parse.
	if _, _, ok := parseWheelFilename("pkg--py3-none-any.whl"); ok {
		t.Error("parseWheelFilename accepted a wheel with an empty version")
	}
	// An sdist whose stem has no hyphen yields a name with an empty version.
	name, version, ok := parseSdistFilename("noversion.tar.gz")
	if !ok || name != "noversion" || version != "" {
		t.Errorf("parseSdistFilename(noversion.tar.gz) = (%q,%q,%v)", name, version, ok)
	}

	// collectPythonDist keeps the one real wheel, reports the sdist as skipped,
	// and silently ignores the unparseable wheel and the extension-less file.
	dest := t.TempDir()
	for _, f := range []struct{ name, body string }{
		{"good-1.0-py3-none-any.whl", "w"},
		{"bad.whl", "junk"},        // too few components -> addWheel drops it
		{"legacy-2.5.tar.gz", "s"}, // sdist -> reported skipped
		{"noext", "x"},             // neither wheel nor sdist -> ignored
	} {
		writeFile(t, filepath.Join(dest, f.name), []byte(f.body))
	}
	files, projects, skipped, err := collectPythonDist(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || len(projects) != 1 || projects[0].NormalizedName != "good" {
		t.Errorf("collectPythonDist wheels = %+v (%d files)", projects, len(files))
	}
	if len(skipped) != 1 || skipped[0].Module != "legacy" || skipped[0].Version != "2.5" {
		t.Errorf("collectPythonDist skipped = %+v, want the legacy sdist", skipped)
	}
}

// TestCovLang_ValidatePythonRequestTarget covers the target-selector validation
// arms of validatePythonRequest that the wheels-only test does not reach.
func TestCovLang_ValidatePythonRequestTarget(t *testing.T) {
	yes := true
	good := PythonCollectRequest{
		Requirements: []string{"numpy"},
		Target: &PythonTarget{
			OnlyBinary:     &yes,
			PythonVersion:  "3.12",
			Implementation: "cp",
			ABI:            "cp312",
			Platforms:      []string{"manylinux_2_28_x86_64"},
		},
	}
	if err := validatePythonRequest(good); err != nil {
		t.Errorf("valid targeted request rejected: %v", err)
	}

	bad := []PythonCollectRequest{
		{Requirements: []string{"numpy"}, Target: &PythonTarget{ABI: "-inject"}},
		{Requirements: []string{"numpy"}, Target: &PythonTarget{Platforms: []string{"-inject"}}},
		{Requirements: []string{"numpy"}, Target: &PythonTarget{Implementation: "bad\nimpl"}},
	}
	for i, req := range bad {
		if err := validatePythonRequest(req); err == nil {
			t.Errorf("bad target request %d accepted", i)
		}
	}
}

// -----------------------------------------------------------------------------
// diodewire.go: wire validation and receive-side landing/failure/logging
// -----------------------------------------------------------------------------

// TestCovLang_DiodePacketValidate hits every arm of the wire sanity bounds by
// mutating one field of an otherwise-valid packet.
func TestCovLang_DiodePacketValidate(t *testing.T) {
	valid := func() diodePacket {
		return diodePacket{
			DataShards: 4, ParityShards: 2, ShardSize: 100, ShardIndex: 0,
			Shard:      make([]byte, 100),
			BlockCount: 2, BlockIndex: 0, FileSize: 150, BlockLen: 100, BlockOffset: 0,
		}
	}
	base := valid()
	if err := base.validate(); err != nil {
		t.Fatalf("baseline packet rejected: %v", err)
	}
	mutations := map[string]func(*diodePacket){
		"zero data shards":     func(p *diodePacket) { p.DataShards = 0 },
		"zero parity shards":   func(p *diodePacket) { p.ParityShards = 0 },
		"oversized total":      func(p *diodePacket) { p.DataShards = 255; p.ParityShards = 255 },
		"shard payload len":    func(p *diodePacket) { p.Shard = make([]byte, 99) },
		"oversized shard":      func(p *diodePacket) { p.ShardSize = diodeMaxShardSize + 1; p.Shard = make([]byte, diodeMaxShardSize+1) },
		"shard index oob":      func(p *diodePacket) { p.ShardIndex = 6 },
		"zero block count":     func(p *diodePacket) { p.BlockCount = 0 },
		"block index oob":      func(p *diodePacket) { p.BlockIndex = 5 },
		"empty file":           func(p *diodePacket) { p.FileSize = 0 },
		"more blocks than len": func(p *diodePacket) { p.FileSize = 1; p.BlockCount = 2 },
		"zero block len":       func(p *diodePacket) { p.BlockLen = 0 },
		"block len too big":    func(p *diodePacket) { p.BlockLen = 500 },
		"negative offset":      func(p *diodePacket) { p.BlockOffset = -1 },
		"offset past end":      func(p *diodePacket) { p.BlockOffset = 100 },
	}
	for name, mutate := range mutations {
		p := valid()
		mutate(&p)
		if err := p.validate(); err == nil {
			t.Errorf("%s: validate accepted an out-of-bounds packet", name)
		}
	}
}

// covLangTransfer builds a diodeTransfer whose temp file already holds content,
// registered as active on asm, so landFile/finishTransfer can run against it.
func covLangTransfer(t *testing.T, asm *diodeAssembler, id byte, name string, content []byte, sha [32]byte, written int64) *diodeTransfer {
	t.Helper()
	if err := os.MkdirAll(asm.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(asm.dir, name+".udp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	var tid [16]byte
	tid[0] = id
	tr := &diodeTransfer{
		id: tid, name: name, fileSize: int64(len(content)), sha: sha,
		blockCount: 1, tmp: f, blocks: map[uint32]*diodeBlock{},
		written: written, started: time.Now(), lastSeen: time.Now(),
	}
	asm.active[tid] = tr
	asm.activeSize += tr.fileSize
	return tr
}

// TestCovLang_DiodeLandFile covers landFile's three outcomes directly: a
// short-coverage error, a SHA-256 mismatch, and a clean atomic landing.
func TestCovLang_DiodeLandFile(t *testing.T) {
	const name = "go-bundle-000001.tar.gz"
	content := []byte("the reassembled bundle bytes")
	sha := sha256.Sum256(content)

	// written != fileSize is caught before the hash pass.
	asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
	tr := covLangTransfer(t, asm, 1, name, content, sha, 0)
	if err := asm.landFile(tr); err == nil || !strings.Contains(err.Error(), "blocks cover") {
		t.Errorf("landFile short coverage = %v, want a blocks-cover error", err)
	}
	_ = tr.tmp.Close()

	// A hash mismatch is rejected.
	asm = newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
	var wrong [32]byte
	tr = covLangTransfer(t, asm, 2, name, content, wrong, int64(len(content)))
	if err := asm.landFile(tr); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("landFile hash mismatch = %v, want a SHA-256 error", err)
	}
	_ = tr.tmp.Close()

	// A correct hash lands the file atomically under its bundle name.
	asm = newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
	tr = covLangTransfer(t, asm, 3, name, content, sha, int64(len(content)))
	if err := asm.landFile(tr); err != nil {
		t.Fatalf("landFile clean = %v, want nil", err)
	}
	got, err := os.ReadFile(filepath.Join(asm.dir, name))
	if err != nil || string(got) != string(content) {
		t.Fatalf("landed file = %q, %v", got, err)
	}
}

// TestCovLang_DiodeFinishFailAndExpire covers finishTransfer's verification
// failure (through failed landFile), failTransfer, expireStale forgetting a
// remembered done record, and logStats' change/no-change branches.
func TestCovLang_DiodeFinishFailAndExpire(t *testing.T) {
	const name = "npm-bundle-000002.tar.gz"
	content := []byte("bytes that will not match the sha")
	var wrong [32]byte

	// finishTransfer with a bad sha routes through landFile's error path:
	// filesFailed is counted, the temp file is removed, onComplete is not called.
	var completed int
	asm := newDiodeAssembler(t.TempDir(), validBundleFileName, func(string) { completed++ })
	tr := covLangTransfer(t, asm, 1, name, content, wrong, int64(len(content)))
	asm.finishTransfer(tr, time.Now())
	if asm.stats.filesFailed != 1 || completed != 0 {
		t.Errorf("finishTransfer failure: filesFailed=%d completed=%d", asm.stats.filesFailed, completed)
	}
	if _, ok := asm.active[tr.id]; ok {
		t.Error("failed transfer left active state")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(asm.dir, "*.udp-*")); len(leftovers) != 0 {
		t.Errorf("failed landing left temp files: %v", leftovers)
	}

	// failTransfer abandons a still-open transfer directly.
	tr2 := covLangTransfer(t, asm, 2, name, content, wrong, int64(len(content)))
	asm.failTransfer(tr2, time.Now(), errFakeCovLangDisk)
	if asm.stats.filesFailed != 2 {
		t.Errorf("failTransfer filesFailed = %d, want 2", asm.stats.filesFailed)
	}

	// expireStale forgets a done record once diodeDoneRemember has elapsed.
	now := time.Now()
	var doneID [16]byte
	doneID[0] = 9
	asm.rememberDone(doneID, now)
	asm.expireStale(now.Add(diodeDoneRemember + time.Second))
	if _, ok := asm.done[doneID]; ok {
		t.Error("expireStale did not forget an aged done record")
	}

	// logStats emits when the counters changed and is a no-op when unchanged.
	asm.logStats()
	before := asm.lastLogged
	asm.logStats()
	if asm.lastLogged != before {
		t.Error("logStats mutated state on an unchanged second call")
	}
}

// errFakeCovLangDisk stands in for an unrecoverable write error passed to
// failTransfer.
var errFakeCovLangDisk = &covLangError{"simulated disk failure"}

type covLangError struct{ msg string }

func (e *covLangError) Error() string { return e.msg }
