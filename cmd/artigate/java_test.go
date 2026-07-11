package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeMvnScript stands in for `mvn`. It parses "-f <pom>" and
// "-Dmaven.repo.local=<repo>", materializes every single-line <dependency> from
// the pom into the local repository in Maven 2 layout (with legacy .sha1
// checksums), and always emits one extra transitive dependency plus the
// bookkeeping files a real local repo carries (which the collector must skip).
const fakeMvnScript = `#!/usr/bin/env bash
set -eu
pom=""; repo=""; prev=""
for a in "$@"; do
  case "$a" in -Dmaven.repo.local=*) repo="${a#-Dmaven.repo.local=}";; esac
  if [ "$prev" = "-f" ]; then pom="$a"; fi
  prev="$a"
done
[ -n "$pom" ] || pom="pom.xml"
[ -n "$repo" ] || repo="repo"
emit() {
  local g="$1" a="$2" v="$3"
  local d="$repo/${g//.//}/$a/$v"
  mkdir -p "$d"
  printf '<project><modelVersion>4.0.0</modelVersion><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></project>\n' "$g" "$a" "$v" > "$d/$a-$v.pom"
  printf 'JAR(%s:%s:%s)' "$g" "$a" "$v" > "$d/$a-$v.jar"
  ( cd "$d" && sha1sum "$a-$v.pom" | cut -d" " -f1 > "$a-$v.pom.sha1" && sha1sum "$a-$v.jar" | cut -d" " -f1 > "$a-$v.jar.sha1" )
  : > "$d/_remote.repositories"
  printf '<metadata/>' > "$d/maven-metadata-central.xml"
}
grep -o "<dependency>.*</dependency>" "$pom" 2>/dev/null | while IFS= read -r line; do
  g=$(printf '%s' "$line" | sed -n "s/.*<groupId>\([^<]*\)<.*/\1/p")
  a=$(printf '%s' "$line" | sed -n "s/.*<artifactId>\([^<]*\)<.*/\1/p")
  v=$(printf '%s' "$line" | sed -n "s/.*<version>\([^<]*\)<.*/\1/p")
  if [ -n "$g" ] && [ -n "$a" ] && [ -n "$v" ]; then emit "$g" "$a" "$v"; fi
done
emit "com.example.transitive" "helper" "1.0.0"
`

func writeFakeMvn(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake mvn shell script is not portable to Windows")
	}
	for _, tool := range []string{"bash", "sha1sum", "sed", "grep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available for fake mvn script", tool)
		}
	}
	p := filepath.Join(t.TempDir(), "mvn")
	if err := os.WriteFile(p, []byte(fakeMvnScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newMavenLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	cfg := LowConfig{
		Root:        t.TempDir(),
		ExportDir:   filepath.Join(t.TempDir(), "out"),
		MavenBinary: writeFakeMvn(t),
	}
	ls, err := NewLowServer(cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

func TestValidateMavenVersion(t *testing.T) {
	valid := []string{"2.0.16", "1.0.0", "v1.2.3", "3.4.1.Final", "1.0.0-rc1"}
	invalid := []string{"", "9.9.9-SNAPSHOT", "LATEST", "RELEASE", "1.+", "[1.0,2.0)", "(,1.0]", "1,2"}
	for _, v := range valid {
		if err := validateMavenVersion(v); err != nil {
			t.Errorf("validateMavenVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalid {
		if err := validateMavenVersion(v); err == nil {
			t.Errorf("validateMavenVersion(%q) = nil, want error", v)
		}
	}
}

func TestParseMavenCoord(t *testing.T) {
	c, err := parseMavenCoord("org.slf4j:slf4j-api:2.0.16")
	if err != nil || c.GroupID != "org.slf4j" || c.ArtifactID != "slf4j-api" || c.Version != "2.0.16" {
		t.Fatalf("parseMavenCoord = %+v, %v", c, err)
	}
	bad := []string{
		"org.slf4j:slf4j-api", // too few parts
		"a:b:c:d",             // too many parts
		"org/evil:a:1.0",      // slash in groupId
		"org.slf4j:slf4j-api:1-SNAPSHOT",
		"org.slf4j:slf4j-api:[1,2)",
	}
	for _, spec := range bad {
		if _, err := parseMavenCoord(spec); err == nil {
			t.Errorf("parseMavenCoord(%q) = nil error, want error", spec)
		}
	}
}

// collectAndImportMaven resolves req on a fake-mvn low server, transfers the
// signed bundle to a fresh high server, and imports it.
func collectAndImportMaven(t *testing.T, req MavenCollectRequest) (*HighServer, ExportResult) {
	t.Helper()
	ls, priv := newMavenLowServer(t)
	res, err := ls.CollectMaven(context.Background(), req)
	if err != nil {
		t.Fatalf("CollectMaven: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of maven bundle failed: %v", err)
	}
	return hs, res
}

// TestLowToHighMavenPipeline is the full round-trip: resolve a coordinate on the
// low side (fake mvn), transfer the signed bundle to a high server, import it,
// and confirm the Maven 2 repository — files, checksums, transitive closure,
// and generated maven-metadata.xml — is served.
func TestLowToHighMavenPipeline(t *testing.T) {
	hs, res := collectAndImportMaven(t, MavenCollectRequest{
		Coordinates: []string{"org.slf4j:slf4j-api:2.0.16"},
	})
	// slf4j-api plus the transitive helper the fake mvn resolved.
	if res.BundleID != "maven-bundle-000001" || res.ExportedModules < 2 {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	srv := httptest.NewServer(hs)
	defer srv.Close()

	// The jar/pom/checksum and the transitive closure are served at Maven 2 paths.
	assertServed(t, srv.URL+"/maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar", "JAR(org.slf4j:slf4j-api:2.0.16)")
	assertServed(t, srv.URL+"/maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.pom", "")
	assertServed(t, srv.URL+"/maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar.sha1", "")
	assertServed(t, srv.URL+"/maven/com/example/transitive/helper/1.0.0/helper-1.0.0.jar", "")

	// maven-metadata.xml is generated from the versions present.
	assertServed(t, srv.URL+"/maven/org/slf4j/slf4j-api/maven-metadata.xml", "<artifactId>slf4j-api</artifactId>")
	assertServed(t, srv.URL+"/maven/org/slf4j/slf4j-api/maven-metadata.xml", "<version>2.0.16</version>")
	// Its checksum is a 40-char sha1 hex of that generated XML.
	if _, sha := httpGet(t, srv.URL+"/maven/org/slf4j/slf4j-api/maven-metadata.xml.sha1"); len(strings.TrimSpace(sha)) != 40 {
		t.Errorf("metadata sha1 = %q, want 40 hex chars", sha)
	}

	// Maven's internal bookkeeping files were not bundled.
	if c, _ := httpGet(t, srv.URL+"/maven/org/slf4j/slf4j-api/2.0.16/_remote.repositories"); c == http.StatusOK {
		t.Error("_remote.repositories must not be mirrored")
	}
}

// assertServed checks a URL returns 200 and (when wantSub is non-empty) that the
// body contains it.
func assertServed(t *testing.T, url, wantSub string) {
	t.Helper()
	code, body := httpGet(t, url)
	if code != http.StatusOK {
		t.Errorf("GET %s status %d, want 200", url, code)
		return
	}
	if wantSub != "" && !strings.Contains(body, wantSub) {
		t.Errorf("GET %s body missing %q", url, wantSub)
	}
}

// TestCollectMavenRejectsSnapshot proves an uploaded pom declaring a SNAPSHOT
// dependency is refused at sanitization time, before mvn ever runs.
func TestCollectMavenRejectsSnapshot(t *testing.T) {
	ls, _ := newMavenLowServer(t)
	pom := `<project><groupId>t</groupId><artifactId>t</artifactId><version>1</version><dependencies>` +
		`<dependency><groupId>com.acme</groupId><artifactId>widget</artifactId><version>9.9.9-SNAPSHOT</version></dependency>` +
		`</dependencies></project>`
	_, err := ls.CollectMaven(context.Background(), MavenCollectRequest{PomXML: pom})
	if err == nil || !strings.Contains(err.Error(), "SNAPSHOT") {
		t.Fatalf("CollectMaven with a SNAPSHOT dep = %v, want a SNAPSHOT rejection", err)
	}
}

// TestRejectMavenSnapshots covers the post-resolution backstop that catches
// SNAPSHOTs arriving transitively (input validation cannot see those).
func TestRejectMavenSnapshots(t *testing.T) {
	ok := []MavenArtifact{{GroupID: "a", ArtifactID: "b", Version: "1.0"}}
	if err := rejectMavenSnapshots(ok); err != nil {
		t.Errorf("rejectMavenSnapshots(release) = %v, want nil", err)
	}
	bad := append(ok, MavenArtifact{GroupID: "c", ArtifactID: "d", Version: "2.0-SNAPSHOT"})
	if err := rejectMavenSnapshots(bad); err == nil || !strings.Contains(err.Error(), "c:d:2.0-SNAPSHOT") {
		t.Errorf("rejectMavenSnapshots(snapshot) = %v, want error naming c:d:2.0-SNAPSHOT", err)
	}
}

// TestSanitizeUploadedPom exercises the accept path: dependency information
// (parent as BOM import, interpolated properties, dependencyManagement,
// exclusions, versionless deps) survives, everything else is dropped.
func TestSanitizeUploadedPom(t *testing.T) {
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.3.1</version>
    <relativePath/>
  </parent>
  <groupId>com.acme</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <name>Acme App</name>
  <description>demo</description>
  <url>https://acme.example</url>
  <licenses><license><name>MIT</name></license></licenses>
  <scm><url>https://git.acme.example/app</url></scm>
  <properties>
    <slf4j.version>2.0.16</slf4j.version>
    <guava.base>33.2.1</guava.base>
    <guava.version>${guava.base}-jre</guava.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>com.acme</groupId><artifactId>bom</artifactId><version>${project.version}</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
      <scope>runtime</scope>
      <exclusions><exclusion><groupId>*</groupId><artifactId>*</artifactId></exclusion></exclusions>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
    </dependency>
  </dependencies>
</project>`
	out, err := sanitizeUploadedPom(pom)
	if err != nil {
		t.Fatalf("sanitizeUploadedPom: %v", err)
	}
	for _, want := range []string{
		"<groupId>local.artigate</groupId>",
		"<groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.16</version>",
		"<version>33.2.1-jre</version>",
		"<scope>runtime</scope>",
		"<exclusion><groupId>*</groupId><artifactId>*</artifactId></exclusion>",
		// A versionless dep stays versionless; the parent BOM supplies it.
		"<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter</artifactId></dependency>",
		// ${project.version} resolved to the pom's own version.
		"<artifactId>bom</artifactId><version>1.0.0</version><type>pom</type><scope>import</scope>",
		// The parent became an import BOM.
		"<artifactId>spring-boot-starter-parent</artifactId><version>3.3.1</version><type>pom</type><scope>import</scope>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sanitized pom missing %q:\n%s", want, out)
		}
	}
	for _, banned := range []string{"<parent>", "<name>", "<licenses>", "<scm>", "acme.example", "<properties>", "${"} {
		if strings.Contains(out, banned) {
			t.Errorf("sanitized pom must not contain %q:\n%s", banned, out)
		}
	}
	// The pom's own dependencyManagement must take precedence over (come
	// before) the parent-derived BOM import.
	if strings.Index(out, "spring-boot-starter-parent") < strings.Index(out, "<artifactId>bom</artifactId>") {
		t.Errorf("parent BOM import must come after explicit dependencyManagement entries:\n%s", out)
	}
}

// TestSanitizeUploadedPomRejects proves every construct that could execute
// code, redirect resolution, or dodge the version policy is refused.
func TestSanitizeUploadedPomRejects(t *testing.T) {
	dep := `<dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version></dependency></dependencies>`
	wrap := func(inner string) string {
		return `<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>t</artifactId><version>1.0</version>` +
			inner + dep + `</project>`
	}
	cases := []struct{ name, pom, wantErr string }{
		{"build extensions", wrap(`<build><extensions><extension><groupId>e</groupId><artifactId>evil</artifactId><version>1</version></extension></extensions></build>`), "<build>"},
		{"build plugins", wrap(`<build><plugins><plugin><groupId>e</groupId><artifactId>evil</artifactId><extensions>true</extensions></plugin></plugins></build>`), "<build>"},
		{"profiles", wrap(`<profiles><profile><id>p</id></profile></profiles>`), "<profiles>"},
		{"repositories", wrap(`<repositories><repository><id>r</id><url>https://evil.example</url></repository></repositories>`), "<repositories>"},
		{"pluginRepositories", wrap(`<pluginRepositories></pluginRepositories>`), "<pluginRepositories>"},
		{"modules", wrap(`<modules><module>sub</module></modules>`), "<modules>"},
		{"reporting", wrap(`<reporting></reporting>`), "<reporting>"},
		{"unknown element fails closed", wrap(`<somethingNew>x</somethingNew>`), "unsupported element"},
		{"doctype directive", `<!DOCTYPE project [<!ENTITY x "y">]>` + wrap(``), "directive"},
		{"system scope", strings.Replace(wrap(``), "</dependency>", "<scope>system</scope><systemPath>/etc/passwd</systemPath></dependency>", 1), "system"},
		{"snapshot version", strings.Replace(wrap(``), "<version>1.0</version></dependency>", "<version>2-SNAPSHOT</version></dependency>", 1), "SNAPSHOT"},
		{"range version", strings.Replace(wrap(``), "<version>1.0</version></dependency>", "<version>[1.0,2.0)</version></dependency>", 1), "pin an exact version"},
		{"unresolvable property", strings.Replace(wrap(``), "<version>1.0</version></dependency>", "<version>${nope}</version></dependency>", 1), "unresolvable property"},
		{"import outside management", strings.Replace(wrap(``), "</dependency>", "<scope>import</scope></dependency>", 1), "only valid in <dependencyManagement>"},
		{"custom packaging", wrap(`<packaging>bundle</packaging>`), "not supported"},
		{"no dependencies", `<project><groupId>t</groupId><artifactId>t</artifactId><version>1.0</version></project>`, "no <dependencies>"},
		{"management missing version", wrap(`<dependencyManagement><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId></dependency></dependencies></dependencyManagement>`), "missing a version"},
		{"root not project", `<settings></settings>`, "want <project>"},
		{"malformed xml", `<project><dependencies>`, "parse pom.xml"},
	}
	for _, tc := range cases {
		if _, err := sanitizeUploadedPom(tc.pom); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: sanitizeUploadedPom = %v, want error containing %q", tc.name, err, tc.wantErr)
		}
	}
}

// TestCollectMavenSanitizedPomEndToEnd uploads a full pom (parent, properties,
// metadata) and confirms the collector resolves the interpolated dependency —
// i.e. mvn saw the sanitized regeneration, not the raw upload (the fake mvn
// only materializes single-line dependencies, which only the regenerated pom
// contains).
func TestCollectMavenSanitizedPomEndToEnd(t *testing.T) {
	pom := `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.0.0</version></parent>
  <artifactId>app</artifactId>
  <name>App</name>
  <properties><widget.version>1.2.3</widget.version></properties>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>widget</artifactId>
      <version>${widget.version}</version>
    </dependency>
  </dependencies>
</project>`
	hs, res := collectAndImportMaven(t, MavenCollectRequest{PomXML: pom})
	if res.ExportedModules < 2 {
		t.Fatalf("unexpected collect result: %+v", res)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()
	// The property-versioned dependency resolved as a pinned release …
	assertServed(t, srv.URL+"/maven/com/acme/widget/1.2.3/widget-1.2.3.jar", "JAR(com.acme:widget:1.2.3)")
	// … and the parent was resolved as an import BOM.
	assertServed(t, srv.URL+"/maven/com/acme/parent/2.0.0/parent-2.0.0.jar", "")
}

func TestServeMavenRejectsTraversal(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	for _, p := range []string{
		"/maven/../import-state.json",
		"/maven/..%2f..%2fimport-state.json",
		"/maven/org/../../../etc/passwd",
	} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("traversal %s returned 200, want rejection", p)
		}
	}
}

func TestCollectMavenEmptyRequest(t *testing.T) {
	ls, _ := newMavenLowServer(t)
	if _, err := ls.CollectMaven(context.Background(), MavenCollectRequest{}); err == nil {
		t.Error("empty CollectMaven should error")
	}
}

// TestLowServerUIMavenCollectFlow drives the request the coordinates form issues:
// POST {coordinates} to /admin/maven/collect and confirm a bundle is produced.
func TestLowServerUIMavenCollectFlow(t *testing.T) {
	ls, _ := newMavenLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	body := strings.NewReader(`{"coordinates":["org.slf4j:slf4j-api:2.0.16"]}`)
	resp, err := http.Post(srv.URL+"/admin/maven/collect", "application/json", body) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("maven collect status = %d, want 200", resp.StatusCode)
	}
	var res ExportResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.BundleID != "maven-bundle-000001" || res.ExportedModules < 2 {
		t.Errorf("unexpected maven collect result: %+v", res)
	}
}

// TestHighServerUIMavenTree confirms the dashboard exposes the imported Maven
// artifacts through the tree and detail APIs.
func TestHighServerUIMavenTree(t *testing.T) {
	hs, _ := collectAndImportMaven(t, MavenCollectRequest{
		Coordinates: []string{"org.slf4j:slf4j-api:2.0.16"},
	})
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Tree root has the top-level group segment.
	if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=maven&path="); !strings.Contains(body, `"org"`) {
		t.Errorf("maven tree root missing org segment: %s", body)
	}
	// Expanding the artifact yields its version as a leaf.
	if _, body := httpGet(t, srv.URL+"/ui/api/tree?eco=maven&path="+url.QueryEscape("org/slf4j/slf4j-api")); !strings.Contains(body, `"2.0.16"`) {
		t.Errorf("maven tree versions missing 2.0.16: %s", body)
	}
	// The detail panel shows the coordinate.
	assertServed(t, srv.URL+"/ui/api/detail?eco=maven&path="+url.QueryEscape("org/slf4j/slf4j-api@2.0.16"), "org.slf4j:slf4j-api:2.0.16")
}
