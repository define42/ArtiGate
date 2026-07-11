package main

// Java (Maven 2) ecosystem adapter. The low side delegates to
// `mvn dependency:go-offline`, which resolves a project's full dependency and
// plugin closure into an isolated local repository; that repository is already
// in Maven 2 layout, so it is packed directly into the same numbered, signed
// ArtiGate bundle used for Go and Python. The high side serves the artifacts as
// a static Maven 2 repository under /maven/ and generates maven-metadata.xml on
// the fly (never trusting a transferred metadata file).
//
// Policy: release artifacts only. SNAPSHOT and dynamic/range versions are
// rejected because they do not resolve reproducibly, which defeats the point of
// an air-gapped mirror.
//
// Uploaded pom.xml input is never handed to Maven verbatim: a full POM can
// carry build extensions/plugins (code Maven loads and executes in-process)
// and repository overrides (resolution from caller-chosen hosts). It is
// reduced to a validated dependency-only project first — see
// sanitizeUploadedPom.

import (
	"context"
	"crypto/ed25519"
	"crypto/md5"  //nolint:gosec // md5 is only a legacy Maven checksum, not a security control
	"crypto/sha1" //nolint:gosec // sha1 is only a legacy Maven checksum, not a security control
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type MavenManifest struct {
	Artifacts []MavenArtifact `json:"artifacts"`
}

type MavenArtifact struct {
	GroupID    string   `json:"group_id"`
	ArtifactID string   `json:"artifact_id"`
	Version    string   `json:"version"`
	Files      []string `json:"files"` // manifest paths, e.g. maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar
}

// -----------------------------------------------------------------------------
// Coordinate parsing and version policy
// -----------------------------------------------------------------------------

var mavenTokenRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type mavenCoord struct {
	GroupID, ArtifactID, Version string
}

// parseMavenCoord parses a "groupId:artifactId:version" coordinate and applies
// the release-only version policy.
func parseMavenCoord(spec string) (mavenCoord, error) {
	parts := strings.Split(strings.TrimSpace(spec), ":")
	if len(parts) != 3 {
		return mavenCoord{}, fmt.Errorf("invalid coordinate %q: want groupId:artifactId:version", spec)
	}
	c := mavenCoord{
		GroupID:    strings.TrimSpace(parts[0]),
		ArtifactID: strings.TrimSpace(parts[1]),
		Version:    strings.TrimSpace(parts[2]),
	}
	if !mavenTokenRE.MatchString(c.GroupID) {
		return mavenCoord{}, fmt.Errorf("invalid groupId %q in %q", c.GroupID, spec)
	}
	if !mavenTokenRE.MatchString(c.ArtifactID) {
		return mavenCoord{}, fmt.Errorf("invalid artifactId %q in %q", c.ArtifactID, spec)
	}
	if err := validateMavenVersion(c.Version); err != nil {
		return mavenCoord{}, fmt.Errorf("%w (in %q)", err, spec)
	}
	return c, nil
}

// validateMavenVersion enforces release-only, reproducible versions. SNAPSHOT
// builds change over time, and dynamic/range versions (1.+, [1.0,2.0), LATEST,
// RELEASE) resolve differently over time, so a mirror can never be reproducible
// with them.
func validateMavenVersion(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("empty version")
	}
	if strings.Contains(v, "SNAPSHOT") {
		return fmt.Errorf("SNAPSHOT version %q is not allowed (not reproducible)", v)
	}
	if v == "LATEST" || v == "RELEASE" {
		return fmt.Errorf("dynamic version %q is not allowed; pin an exact version", v)
	}
	if strings.ContainsAny(v, "[](),+*") {
		return fmt.Errorf("dynamic/range version %q is not allowed; pin an exact version", v)
	}
	if !mavenTokenRE.MatchString(v) {
		return fmt.Errorf("invalid version %q", v)
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: static Maven 2 repository
// -----------------------------------------------------------------------------

func (s *HighServer) mavenDir() string {
	return filepath.Join(s.downloadDir, "maven")
}

var mavenMetadataRE = regexp.MustCompile(`^maven-metadata\.xml(\.(sha1|md5))?$`)

// serveMaven handles the Maven 2 repository routes under /maven/. It reports
// whether it wrote a response for the request. Stored files (.pom/.jar/.module
// and their checksums) are served directly; maven-metadata.xml and its
// checksums are computed from the versions actually present.
func (s *HighServer) serveMaven(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/maven" && !strings.HasPrefix(p, "/maven/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, "/maven"), "/")
	if rel == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	if err := validateRelPath(rel); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	if mavenMetadataRE.MatchString(path.Base(rel)) {
		s.serveMavenMetadata(w, rel)
		return true
	}
	abs := filepath.Join(s.mavenDir(), filepath.FromSlash(rel))
	if !safeJoin(s.mavenDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	serveFile(w, r, abs)
	return true
}

// serveMavenMetadata computes maven-metadata.xml (or its .sha1/.md5) for the
// group/artifact directory that contains the requested file.
func (s *HighServer) serveMavenMetadata(w http.ResponseWriter, rel string) {
	base := path.Base(rel)
	dirRel := path.Dir(rel)
	dir := filepath.Join(s.mavenDir(), filepath.FromSlash(dirRel))
	if !safeJoin(s.mavenDir(), dir) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	xmlBytes, ok := buildMavenMetadata(dirRel, dir)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch {
	case strings.HasSuffix(base, ".sha1"):
		writeText(w, sha1Hex(xmlBytes))
	case strings.HasSuffix(base, ".md5"):
		writeText(w, md5Hex(xmlBytes))
	default:
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(xmlBytes)
	}
}

// buildMavenMetadata renders maven-metadata.xml for a group/artifact directory
// from the version subdirectories present (a version dir counts only if it
// holds a .pom). It returns false when the directory has no versions.
func buildMavenMetadata(dirRel, dir string) ([]byte, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	var versions []string
	var newest time.Time
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pom := firstPomIn(filepath.Join(dir, e.Name()))
		if pom == "" {
			continue
		}
		versions = append(versions, e.Name())
		if info, err := os.Stat(pom); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if len(versions) == 0 {
		return nil, false
	}
	sortMavenVersions(versions)
	segs := strings.Split(dirRel, "/")
	artifactID := segs[len(segs)-1]
	groupID := strings.Join(segs[:len(segs)-1], ".")
	latest := versions[len(versions)-1]

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString("<metadata>\n")
	fmt.Fprintf(&b, "  <groupId>%s</groupId>\n", html.EscapeString(groupID))
	fmt.Fprintf(&b, "  <artifactId>%s</artifactId>\n", html.EscapeString(artifactID))
	b.WriteString("  <versioning>\n")
	fmt.Fprintf(&b, "    <latest>%s</latest>\n", html.EscapeString(latest))
	fmt.Fprintf(&b, "    <release>%s</release>\n", html.EscapeString(latest))
	b.WriteString("    <versions>\n")
	for _, v := range versions {
		fmt.Fprintf(&b, "      <version>%s</version>\n", html.EscapeString(v))
	}
	b.WriteString("    </versions>\n")
	if !newest.IsZero() {
		fmt.Fprintf(&b, "    <lastUpdated>%s</lastUpdated>\n", newest.UTC().Format("20060102150405"))
	}
	b.WriteString("  </versioning>\n</metadata>\n")
	return []byte(b.String()), true
}

// firstPomIn returns the absolute path of the first .pom file in dir, or "".
func firstPomIn(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pom") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

var mavenVerSepRE = regexp.MustCompile(`[.-]`)

func sortMavenVersions(vs []string) {
	sort.Slice(vs, func(i, j int) bool { return mavenVersionLess(vs[i], vs[j]) })
}

// mavenVersionLess is a best-effort version ordering: dot/dash-separated tokens
// are compared numerically when both are numbers, otherwise lexically, with
// numeric tokens sorting before alphabetic ones. It only drives the
// latest/release hints in generated metadata; clients pin exact versions.
func mavenVersionLess(a, b string) bool {
	at, bt := mavenVerSepRE.Split(a, -1), mavenVerSepRE.Split(b, -1)
	for k := 0; k < len(at) && k < len(bt); k++ {
		x, y := at[k], bt[k]
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				return nx < ny
			}
		case ex == nil:
			return true // numeric token sorts before alphabetic
		case ey == nil:
			return false
		default:
			if x != y {
				return x < y
			}
		}
	}
	return len(at) < len(bt)
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listMavenArtifacts groups the mirrored files by group/artifact path. The
// returned UIModule.Module is the slash-separated coordinate path (e.g.
// org/slf4j/slf4j-api) so the generic segment-tree builder renders it, and
// Versions are the version directories present.
func (s *HighServer) listMavenArtifacts() ([]UIModule, error) {
	root := s.mavenDir()
	byArtifact := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() || firstPomIn(p) == "" {
			return nil // only version directories (those holding a .pom) count
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		idx := strings.LastIndex(relSlash, "/")
		if idx < 0 {
			return nil
		}
		artifactPath, version := relSlash[:idx], relSlash[idx+1:]
		byArtifact[artifactPath] = append(byArtifact[artifactPath], version)
		return nil
	})
	if err != nil {
		return nil, err
	}
	mods := make([]UIModule, 0, len(byArtifact))
	for a, vs := range byArtifact {
		sortMavenVersions(vs)
		mods = append(mods, UIModule{Module: a, Versions: vs})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Module < mods[j].Module })
	return mods, nil
}

// mavenDetail describes one artifact version for the dashboard detail panel.
// spec is "<group/artifact path>@<version>", e.g. org/slf4j/slf4j-api@2.0.16.
func (s *HighServer) mavenDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid artifact@version")
	}
	artifactPath, version := spec[:i], spec[i+1:]
	if err := validateRelPath(artifactPath); err != nil {
		return UIDetail{}, errors.New("invalid artifact path")
	}
	if strings.ContainsRune(version, '/') || strings.Contains(version, "..") {
		return UIDetail{}, errors.New("invalid version")
	}
	dir := filepath.Join(s.mavenDir(), filepath.FromSlash(artifactPath), version)
	if !safeJoin(s.mavenDir(), dir) {
		return UIDetail{}, errors.New("unsafe path")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return UIDetail{}, errors.New("artifact not found")
	}
	segs := strings.Split(artifactPath, "/")
	artifactID := segs[len(segs)-1]
	groupID := strings.Join(segs[:len(segs)-1], ".")

	fields := []UIDetailField{
		{Label: "Coordinate", Value: groupID + ":" + artifactID + ":" + version, Mono: true},
		{Label: "Repo path", Value: "/maven/" + artifactPath + "/" + version + "/", Mono: true},
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || skipMavenFile(name) || isMavenChecksum(name) {
			continue // list only primary artifacts (jar/pom/module/...), not checksums
		}
		info, statErr := e.Info()
		if statErr != nil {
			continue
		}
		fields = append(fields, UIDetailField{Label: name, Value: formatBytes(info.Size())})
	}
	if sum, err := sha256File(filepath.Join(dir, artifactID+"-"+version+".jar")); err == nil {
		fields = append(fields, UIDetailField{Label: "JAR SHA-256", Value: sum, Mono: true})
	}
	return UIDetail{Title: groupID + ":" + artifactID, Subtitle: version, Fields: fields}, nil
}

func isMavenChecksum(name string) bool {
	for _, ext := range []string{".sha1", ".md5", ".sha256", ".sha512"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func writeText(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, s)
}

func sha1Hex(b []byte) string {
	h := sha1.Sum(b) //nolint:gosec // legacy Maven checksum, not a security control
	return hex.EncodeToString(h[:])
}

func md5Hex(b []byte) string {
	h := md5.Sum(b) //nolint:gosec // legacy Maven checksum, not a security control
	return hex.EncodeToString(h[:])
}

// -----------------------------------------------------------------------------
// Import-side manifest validation
// -----------------------------------------------------------------------------

// validateMavenArtifacts checks that every artifact names a coordinate and lists
// files that appear in the manifest's overall file set.
func validateMavenArtifacts(arts []MavenArtifact, seen map[string]bool) error {
	for _, a := range arts {
		if a.GroupID == "" || a.ArtifactID == "" || a.Version == "" {
			return errors.New("maven artifact missing group/artifact/version")
		}
		if len(a.Files) == 0 {
			return fmt.Errorf("maven artifact %s:%s:%s has no files", a.GroupID, a.ArtifactID, a.Version)
		}
		for _, f := range a.Files {
			if !seen[f] {
				return fmt.Errorf("maven artifact %s:%s:%s references file not listed in manifest.files: %s",
					a.GroupID, a.ArtifactID, a.Version, f)
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Low side: Maven resolver/collector
// -----------------------------------------------------------------------------

// MavenCollectRequest is the body of POST /admin/maven/collect. Provide either
// an explicit coordinate list ("groupId:artifactId:version" each) or a full
// pom.xml; when PomXML is set, Coordinates is ignored.
type MavenCollectRequest struct {
	Coordinates []string `json:"coordinates"`
	// PomXML is a complete pom.xml. It is never resolved as-is: only its
	// dependency information (parent, properties, dependencies,
	// dependencyManagement) is extracted into a sanitized synthetic project,
	// and elements that could execute code or redirect resolution (build,
	// profiles, repositories, ...) are rejected. See sanitizeUploadedPom.
	PomXML string `json:"pom_xml"`
	// Force disables export dedup for this collect: every artifact is packed
	// even when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// HandleMavenCollect parses a JSON collect request and runs the collection.
func (s *LowServer) HandleMavenCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req MavenCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse maven collect request: %w", err)
		}
	}
	return s.CollectMaven(ctx, req)
}

// CollectMaven resolves the requested Maven closure with `mvn
// dependency:go-offline` into an isolated local repository and packs it into a
// signed bundle on the shared ArtiGate sequence stream.
func (s *LowServer) CollectMaven(ctx context.Context, req MavenCollectRequest) (ExportResult, error) {
	pom, err := mavenProjectPom(req)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the maven stream's lock for the whole resolve->write->commit so
	// a concurrent maven exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamMaven)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "maven", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	pomPath := filepath.Join(stageRoot, "pom.xml")
	if err := os.WriteFile(pomPath, []byte(pom), 0o644); err != nil {
		return ExportResult{}, err
	}
	// The local repo lives at <stageRoot>/maven so its Maven 2 layout maps
	// directly onto the "maven/..." manifest paths the high side serves.
	localRepo := filepath.Join(stageRoot, "maven")
	if err := os.MkdirAll(localRepo, 0o755); err != nil {
		return ExportResult{}, err
	}

	emitProgress(ctx, "Running mvn dependency:go-offline to resolve the closure…")
	if _, err := s.runMaven(ctx, stageRoot, "-B", "-f", pomPath,
		"dependency:go-offline", "-Dmaven.repo.local="+localRepo); err != nil {
		return ExportResult{}, err
	}

	files, artifacts, err := collectMavenRepo(localRepo)
	if err != nil {
		return ExportResult{}, err
	}
	if len(files) == 0 {
		return ExportResult{}, errors.New("maven resolution produced no artifacts")
	}
	if err := rejectMavenSnapshots(artifacts); err != nil {
		return ExportResult{}, err
	}

	emitProgress(ctx, "Packing %d artifact file(s) into a signed bundle…", len(files))
	return s.exportIfNew(ctx, streamMaven, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeMavenBundle(ctx, seq, stageRoot, files, artifacts)
	})
}

// mavenProjectPom returns the pom.xml to resolve: a sanitized regeneration of
// the caller's uploaded pom, or a synthetic project whose dependencies are the
// requested coordinates. Both paths end in renderCollectPom, so Maven only
// ever parses XML that ArtiGate generated itself.
func mavenProjectPom(req MavenCollectRequest) (string, error) {
	if strings.TrimSpace(req.PomXML) != "" {
		return sanitizeUploadedPom(req.PomXML)
	}
	if len(req.Coordinates) == 0 {
		return "", errors.New("no maven coordinates or pom_xml provided")
	}
	deps := make([]pomDependency, 0, len(req.Coordinates))
	for _, spec := range req.Coordinates {
		c, err := parseMavenCoord(spec)
		if err != nil {
			return "", err
		}
		deps = append(deps, pomDependency{GroupID: c.GroupID, ArtifactID: c.ArtifactID, Version: c.Version})
	}
	return renderCollectPom("pom", nil, deps), nil
}

// -----------------------------------------------------------------------------
// Uploaded pom.xml sanitization
// -----------------------------------------------------------------------------
//
// A full POM is a build program, not just a dependency list: <build>
// extensions and plugins are loaded and executed inside the mvn process during
// resolution, and <repositories>/<pluginRepositories> would pull artifacts
// from caller-chosen hosts into the signed bundle. Neither is acceptable for
// input crossing into an air-gap gateway, so an uploaded pom.xml is reduced to
// a strict dependency-only subset:
//
//   - extracted: packaging, <properties> (used to interpolate ${...} in the
//     fields below, then discarded), <dependencies>, <dependencyManagement>,
//     and <parent> (translated into a scope=import BOM entry, which supplies
//     the parent's dependencyManagement without inheriting its build).
//   - ignored:   purely informational elements (name, licenses, scm, ...).
//   - rejected:  anything that executes code or changes resolution sources
//     (build, profiles, repositories, ...) and any element not on the lists
//     above (fail closed).
//
// Every extracted value is re-validated against the same token and
// release-only version policy as the coordinates path, then a fresh project is
// generated with renderCollectPom — Maven never parses caller-supplied bytes.

type pomDependency struct {
	GroupID    string         `xml:"groupId"`
	ArtifactID string         `xml:"artifactId"`
	Version    string         `xml:"version"`
	Type       string         `xml:"type"`
	Classifier string         `xml:"classifier"`
	Scope      string         `xml:"scope"`
	SystemPath string         `xml:"systemPath"`
	Optional   string         `xml:"optional"`
	Exclusions []pomExclusion `xml:"exclusions>exclusion"`
}

type pomExclusion struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	// relativePath is deliberately dropped: parents resolve from repositories.
}

// uploadedPom is the dependency-only model parsed from an uploaded pom.xml.
type uploadedPom struct {
	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string
	Parent     *pomParent
	Properties map[string]string
	Management []pomDependency
	Deps       []pomDependency
}

// pomElementIgnored reports whether a top-level <project> element has no
// resolution or execution semantics and can be dropped from the regenerated
// project. distributionManagement only affects deploy, which never runs here.
func pomElementIgnored(name string) bool {
	switch name {
	case "modelVersion", "name", "description", "url", "inceptionYear",
		"organization", "licenses", "developers", "contributors", "mailingLists",
		"scm", "issueManagement", "ciManagement", "distributionManagement", "prerequisites":
		return true
	}
	return false
}

// pomElementRejection returns the reason a forbidden top-level <project>
// element is rejected, and ok=false for elements that are not on the reject
// list.
func pomElementRejection(name string) (string, bool) {
	switch name {
	case "build":
		return "build plugins and extensions execute code inside Maven during resolution", true
	case "reporting":
		return "reporting plugins execute code inside Maven", true
	case "profiles":
		return "profiles can conditionally activate plugins, repositories, and modules", true
	case "repositories", "pluginRepositories":
		return "resolution sources are fixed by the low side's Maven settings", true
	case "modules":
		return "multi-module builds are not supported; collect each module separately", true
	}
	return "", false
}

// pomPackagingAllowed reports whether a packaging's default lifecycle plugins
// Maven resolves without loading custom extensions.
func pomPackagingAllowed(packaging string) bool {
	switch packaging {
	case "pom", "jar", "war", "ear", "ejb", "maven-plugin":
		return true
	}
	return false
}

// sanitizeUploadedPom parses an uploaded pom.xml, keeps only validated
// dependency information, and regenerates the project Maven will actually
// resolve. See the section comment above for the allow/ignore/reject split.
func sanitizeUploadedPom(pomXML string) (string, error) {
	p, err := parseUploadedPom(pomXML)
	if err != nil {
		return "", err
	}
	props := p.effectiveProperties()

	packaging, err := expandPomProps(strings.TrimSpace(p.Packaging), props)
	if err != nil {
		return "", fmt.Errorf("packaging: %w", err)
	}
	if packaging = strings.TrimSpace(packaging); packaging == "" {
		packaging = "jar"
	}
	if !pomPackagingAllowed(packaging) {
		return "", fmt.Errorf("packaging %q is not supported for collection (custom packagings require build extensions)", packaging)
	}

	var mgmt []pomDependency
	for _, d := range p.Management {
		vd, err := validatePomDependency(d, props, true)
		if err != nil {
			return "", err
		}
		mgmt = append(mgmt, vd)
	}
	if p.Parent != nil {
		imp, err := parentAsBOMImport(*p.Parent, props)
		if err != nil {
			return "", err
		}
		// Appended after the explicit entries so the pom's own
		// dependencyManagement wins, matching Maven's inheritance precedence.
		mgmt = append(mgmt, imp)
	}

	if len(p.Deps) == 0 {
		return "", errors.New("uploaded pom.xml declares no <dependencies>; nothing to collect")
	}
	deps := make([]pomDependency, 0, len(p.Deps))
	for _, d := range p.Deps {
		vd, err := validatePomDependency(d, props, false)
		if err != nil {
			return "", err
		}
		deps = append(deps, vd)
	}
	return renderCollectPom(packaging, mgmt, deps), nil
}

// parseUploadedPom token-walks the uploaded pom.xml and extracts the
// dependency-only subset, failing closed on anything else.
func parseUploadedPom(pomXML string) (*uploadedPom, error) {
	dec := xml.NewDecoder(strings.NewReader(pomXML))
	root, err := pomRootElement(dec)
	if err != nil {
		return nil, err
	}
	if root.Name.Local != "project" {
		return nil, fmt.Errorf("pom.xml root element is <%s>, want <project>", root.Name.Local)
	}
	p := &uploadedPom{Properties: map[string]string{}}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("parse pom.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement: // </project>; trailing tokens are never read
			return p, nil
		case xml.Directive:
			return nil, errors.New("pom.xml must not contain <!...> directives")
		case xml.StartElement:
			if err := p.readProjectChild(dec, t); err != nil {
				return nil, err
			}
		}
	}
}

// pomRootElement returns the document's root start element, rejecting
// DOCTYPE/entity directives on the way there.
func pomRootElement(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, fmt.Errorf("parse pom.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return xml.StartElement{}, errors.New("pom.xml must not contain <!...> directives (DOCTYPE)")
		case xml.StartElement:
			return t, nil
		}
	}
}

// readProjectChild consumes one direct child element of <project>, either
// extracting it into p, skipping it, or rejecting it.
func (p *uploadedPom) readProjectChild(dec *xml.Decoder, se xml.StartElement) error {
	name := se.Name.Local
	switch name {
	case "groupId":
		return decodePomText(dec, &se, &p.GroupID)
	case "artifactId":
		return decodePomText(dec, &se, &p.ArtifactID)
	case "version":
		return decodePomText(dec, &se, &p.Version)
	case "packaging":
		return decodePomText(dec, &se, &p.Packaging)
	case "parent":
		var par pomParent
		if err := dec.DecodeElement(&par, &se); err != nil {
			return fmt.Errorf("parse pom.xml <parent>: %w", err)
		}
		p.Parent = &par
		return nil
	case "properties":
		return decodePomProperties(dec, p.Properties)
	case "dependencies":
		var wrap struct {
			Deps []pomDependency `xml:"dependency"`
		}
		if err := dec.DecodeElement(&wrap, &se); err != nil {
			return fmt.Errorf("parse pom.xml <dependencies>: %w", err)
		}
		p.Deps = append(p.Deps, wrap.Deps...)
		return nil
	case "dependencyManagement":
		var wrap struct {
			Deps []pomDependency `xml:"dependencies>dependency"`
		}
		if err := dec.DecodeElement(&wrap, &se); err != nil {
			return fmt.Errorf("parse pom.xml <dependencyManagement>: %w", err)
		}
		p.Management = append(p.Management, wrap.Deps...)
		return nil
	}
	if pomElementIgnored(name) {
		return dec.Skip()
	}
	if reason, ok := pomElementRejection(name); ok {
		return fmt.Errorf("<%s> is not allowed in an uploaded pom.xml: %s", name, reason)
	}
	return fmt.Errorf("unsupported element <%s> in uploaded pom.xml: only dependency information (parent, properties, dependencies, dependencyManagement) is honored", name)
}

// decodePomText decodes an element's trimmed character data.
func decodePomText(dec *xml.Decoder, se *xml.StartElement, into *string) error {
	var s string
	if err := dec.DecodeElement(&s, se); err != nil {
		return fmt.Errorf("parse pom.xml <%s>: %w", se.Name.Local, err)
	}
	*into = strings.TrimSpace(s)
	return nil
}

// decodePomProperties reads <properties>, mapping each child element's name to
// its trimmed character data.
func decodePomProperties(dec *xml.Decoder, into map[string]string) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("parse pom.xml <properties>: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return nil
		case xml.StartElement:
			var v string
			if err := dec.DecodeElement(&v, &t); err != nil {
				return fmt.Errorf("parse pom.xml property <%s>: %w", t.Name.Local, err)
			}
			into[t.Name.Local] = strings.TrimSpace(v)
		}
	}
}

// effectiveProperties returns the pom's <properties> plus the project.*/pom.*
// coordinate references Maven would supply, so versions like
// <version>${project.version}</version> interpolate. Missing project
// coordinates fall back to the parent's, mirroring inheritance.
func (p *uploadedPom) effectiveProperties() map[string]string {
	props := make(map[string]string, len(p.Properties)+6)
	for k, v := range p.Properties {
		props[k] = v
	}
	group, version := p.GroupID, p.Version
	if p.Parent != nil {
		if group == "" {
			group = strings.TrimSpace(p.Parent.GroupID)
		}
		if version == "" {
			version = strings.TrimSpace(p.Parent.Version)
		}
	}
	for _, prefix := range []string{"project.", "pom."} {
		props[prefix+"groupId"] = group
		props[prefix+"artifactId"] = p.ArtifactID
		props[prefix+"version"] = version
	}
	return props
}

// expandPomProps substitutes ${...} property references, iterating so property
// values may reference other properties, with a hard cap against cycles.
// Unknown references (including ${env.*} and ${settings.*}, which must not
// leak low-side state into resolution) are errors.
func expandPomProps(s string, props map[string]string) (string, error) {
	for i := 0; i < 32; i++ {
		start := strings.Index(s, "${")
		if start < 0 {
			return s, nil
		}
		rest := s[start+2:]
		end := strings.Index(rest, "}")
		if end < 0 {
			return "", fmt.Errorf("unterminated ${ property reference in %q", s)
		}
		val, ok := props[rest[:end]]
		if !ok {
			return "", fmt.Errorf("unresolvable property ${%s}: define it in <properties> or pin the value", rest[:end])
		}
		s = s[:start] + val + rest[end+1:]
	}
	return "", fmt.Errorf("property expansion did not converge in %q (reference cycle?)", s)
}

// pomScopeAllowed reports whether a plain (non-import) dependency scope is one
// ArtiGate resolves. The empty scope means Maven's default (compile).
func pomScopeAllowed(scope string) bool {
	switch scope {
	case "", "compile", "provided", "runtime", "test":
		return true
	}
	return false
}

// validatePomDependency interpolates and validates one dependency. management
// entries (<dependencyManagement>) additionally allow scope=import BOMs and
// must pin a version; plain dependencies may omit the version and let
// dependencyManagement or an imported BOM supply it.
func validatePomDependency(d pomDependency, props map[string]string, management bool) (pomDependency, error) {
	// Checked before expansion: systemPath values conventionally reference
	// ${basedir}-style properties, which would otherwise fail with a less
	// helpful "unresolvable property" error.
	if strings.TrimSpace(d.SystemPath) != "" {
		return d, errors.New("dependency with <systemPath> is not allowed (system dependencies read files from the low-side host)")
	}
	var err error
	for _, f := range []*string{&d.GroupID, &d.ArtifactID, &d.Version, &d.Type, &d.Classifier, &d.Scope, &d.Optional} {
		if *f, err = expandPomProps(strings.TrimSpace(*f), props); err != nil {
			return d, fmt.Errorf("dependency: %w", err)
		}
		*f = strings.TrimSpace(*f)
	}
	if !mavenTokenRE.MatchString(d.GroupID) {
		return d, fmt.Errorf("invalid dependency groupId %q", d.GroupID)
	}
	where := d.GroupID + ":" + d.ArtifactID
	if !mavenTokenRE.MatchString(d.ArtifactID) {
		return d, fmt.Errorf("invalid dependency artifactId %q (groupId %s)", d.ArtifactID, d.GroupID)
	}
	if err := validatePomScope(d, where, management); err != nil {
		return d, err
	}
	if err := validatePomVersion(d, where, management); err != nil {
		return d, err
	}
	if err := validatePomDependencyFields(d, where); err != nil {
		return d, err
	}
	if err := validatePomExclusions(&d, props, where); err != nil {
		return d, err
	}
	return d, nil
}

// validatePomDependencyFields checks the optional token-shaped fields (type,
// classifier) and the boolean <optional> flag of an interpolated dependency.
func validatePomDependencyFields(d pomDependency, where string) error {
	if d.Type != "" && !mavenTokenRE.MatchString(d.Type) {
		return fmt.Errorf("dependency %s: invalid type %q", where, d.Type)
	}
	if d.Classifier != "" && !mavenTokenRE.MatchString(d.Classifier) {
		return fmt.Errorf("dependency %s: invalid classifier %q", where, d.Classifier)
	}
	if d.Optional != "" && d.Optional != "true" && d.Optional != "false" {
		return fmt.Errorf("dependency %s: invalid <optional> value %q", where, d.Optional)
	}
	return nil
}

// validatePomScope enforces the scope rules: system is forbidden, import is
// valid only in <dependencyManagement> and only as a pom BOM, and every other
// scope must be a recognized one.
func validatePomScope(d pomDependency, where string, management bool) error {
	switch {
	case d.Scope == "system":
		return fmt.Errorf("dependency %s: system-scoped dependencies are not allowed (they read files from the low-side host)", where)
	case d.Scope == "import":
		if !management {
			return fmt.Errorf("dependency %s: scope \"import\" is only valid in <dependencyManagement>", where)
		}
		if d.Type != "pom" {
			return fmt.Errorf("BOM import %s must have <type>pom</type>", where)
		}
	case !pomScopeAllowed(d.Scope):
		return fmt.Errorf("dependency %s: unsupported scope %q", where, d.Scope)
	}
	return nil
}

// validatePomVersion applies the release-only policy: a management entry must
// pin a version, a plain dependency may omit it (dependencyManagement or a BOM
// supplies it), and any present version must satisfy validateMavenVersion.
func validatePomVersion(d pomDependency, where string, management bool) error {
	if d.Version == "" {
		if management {
			return fmt.Errorf("dependencyManagement entry %s is missing a version", where)
		}
		return nil
	}
	if err := validateMavenVersion(d.Version); err != nil {
		return fmt.Errorf("dependency %s: %w", where, err)
	}
	return nil
}

// validatePomExclusions interpolates and validates each <exclusion>, writing
// the normalized values back into d. "*" wildcards are allowed on either side.
func validatePomExclusions(d *pomDependency, props map[string]string, where string) error {
	for i, ex := range d.Exclusions {
		g, gErr := expandPomProps(strings.TrimSpace(ex.GroupID), props)
		a, aErr := expandPomProps(strings.TrimSpace(ex.ArtifactID), props)
		if gErr != nil || aErr != nil {
			return fmt.Errorf("dependency %s: exclusion: %w", where, errors.Join(gErr, aErr))
		}
		g, a = strings.TrimSpace(g), strings.TrimSpace(a)
		if (g != "*" && !mavenTokenRE.MatchString(g)) || (a != "*" && !mavenTokenRE.MatchString(a)) {
			return fmt.Errorf("dependency %s: invalid exclusion %q:%q", where, g, a)
		}
		d.Exclusions[i] = pomExclusion{GroupID: g, ArtifactID: a}
	}
	return nil
}

// parentAsBOMImport converts <parent> into a scope=import BOM entry. Importing
// supplies the parent's dependencyManagement — what versionless dependencies
// need — without inheriting its <build>, so a hostile parent pom cannot
// smuggle extensions into the resolution.
func parentAsBOMImport(par pomParent, props map[string]string) (pomDependency, error) {
	c := mavenCoord{GroupID: par.GroupID, ArtifactID: par.ArtifactID, Version: par.Version}
	var err error
	for _, f := range []*string{&c.GroupID, &c.ArtifactID, &c.Version} {
		if *f, err = expandPomProps(strings.TrimSpace(*f), props); err != nil {
			return pomDependency{}, fmt.Errorf("<parent>: %w", err)
		}
		*f = strings.TrimSpace(*f)
	}
	if !mavenTokenRE.MatchString(c.GroupID) || !mavenTokenRE.MatchString(c.ArtifactID) {
		return pomDependency{}, fmt.Errorf("invalid <parent> coordinate %q:%q", c.GroupID, c.ArtifactID)
	}
	if err := validateMavenVersion(c.Version); err != nil {
		return pomDependency{}, fmt.Errorf("<parent> version: %w", err)
	}
	return pomDependency{GroupID: c.GroupID, ArtifactID: c.ArtifactID, Version: c.Version, Type: "pom", Scope: "import"}, nil
}

// renderCollectPom generates the synthetic project Maven resolves for a
// collect. Every value has already been token-validated; escaping is belt and
// braces.
func renderCollectPom(packaging string, mgmt, deps []pomDependency) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString("<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n")
	b.WriteString("  <modelVersion>4.0.0</modelVersion>\n")
	b.WriteString("  <groupId>local.artigate</groupId>\n")
	b.WriteString("  <artifactId>artigate-collect</artifactId>\n")
	b.WriteString("  <version>0.0.0</version>\n")
	fmt.Fprintf(&b, "  <packaging>%s</packaging>\n", html.EscapeString(packaging))
	if len(mgmt) > 0 {
		b.WriteString("  <dependencyManagement>\n    <dependencies>\n")
		for _, d := range mgmt {
			b.WriteString("      " + pomDependencyXML(d) + "\n")
		}
		b.WriteString("    </dependencies>\n  </dependencyManagement>\n")
	}
	b.WriteString("  <dependencies>\n")
	for _, d := range deps {
		b.WriteString("    " + pomDependencyXML(d) + "\n")
	}
	b.WriteString("  </dependencies>\n</project>\n")
	return b.String()
}

// pomDependencyXML renders one validated dependency on a single line.
func pomDependencyXML(d pomDependency) string {
	esc := html.EscapeString
	var b strings.Builder
	fmt.Fprintf(&b, "<dependency><groupId>%s</groupId><artifactId>%s</artifactId>", esc(d.GroupID), esc(d.ArtifactID))
	if d.Version != "" {
		fmt.Fprintf(&b, "<version>%s</version>", esc(d.Version))
	}
	if d.Type != "" {
		fmt.Fprintf(&b, "<type>%s</type>", esc(d.Type))
	}
	if d.Classifier != "" {
		fmt.Fprintf(&b, "<classifier>%s</classifier>", esc(d.Classifier))
	}
	if d.Scope != "" {
		fmt.Fprintf(&b, "<scope>%s</scope>", esc(d.Scope))
	}
	if d.Optional == "true" {
		b.WriteString("<optional>true</optional>")
	}
	if len(d.Exclusions) > 0 {
		b.WriteString("<exclusions>")
		for _, ex := range d.Exclusions {
			fmt.Fprintf(&b, "<exclusion><groupId>%s</groupId><artifactId>%s</artifactId></exclusion>", esc(ex.GroupID), esc(ex.ArtifactID))
		}
		b.WriteString("</exclusions>")
	}
	b.WriteString("</dependency>")
	return b.String()
}

func (s *LowServer) runMaven(ctx context.Context, dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	bin := s.cfg.MavenBinary
	if bin == "" {
		bin = "mvn"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	// mvn output is only used for error diagnostics (the resolved files are read
	// from the local repo afterward), so combined output is fine here.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("mvn %s failed: %w\n%s", strings.Join(args, " "), err, tailBytes(out, 4096))
	}
	return out, nil
}

func tailBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(string(b))
}

// collectMavenRepo walks a resolved local repository and returns the manifest
// files (paths prefixed with "maven/") plus the per-coordinate grouping,
// skipping Maven's internal bookkeeping files.
func collectMavenRepo(repoRoot string) ([]ManifestFile, []MavenArtifact, error) {
	byGAV := map[string]*MavenArtifact{}
	var order []string
	var files []ManifestFile
	err := filepath.WalkDir(repoRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || skipMavenFile(d.Name()) {
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, p)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		segs := strings.Split(relSlash, "/")
		if len(segs) < 4 { // need group.../artifactId/version/file
			return nil
		}
		version := segs[len(segs)-2]
		artifactID := segs[len(segs)-3]
		groupID := strings.Join(segs[:len(segs)-3], ".")
		manifestPath := path.Join("maven", relSlash)
		mf, mfErr := hashManifestFile(p, manifestPath)
		if mfErr != nil {
			return mfErr
		}
		files = append(files, mf)
		key := groupID + ":" + artifactID + ":" + version
		a, ok := byGAV[key]
		if !ok {
			a = &MavenArtifact{GroupID: groupID, ArtifactID: artifactID, Version: version}
			byGAV[key] = a
			order = append(order, key)
		}
		a.Files = append(a.Files, manifestPath)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	artifacts := make([]MavenArtifact, 0, len(order))
	for _, k := range order {
		artifacts = append(artifacts, *byGAV[k])
	}
	return files, artifacts, nil
}

// skipMavenFile reports whether a local-repo file is Maven bookkeeping rather
// than a mirrorable artifact. Remote-repository metadata is regenerated on the
// high side, so it is never bundled.
func skipMavenFile(name string) bool {
	switch {
	case strings.HasPrefix(name, "_"): // _remote.repositories
		return true
	case strings.HasPrefix(name, "maven-metadata"): // per-remote metadata, regenerated high-side
		return true
	case name == "resolver-status.properties":
		return true
	case strings.HasSuffix(name, ".lastUpdated"):
		return true
	case strings.HasSuffix(name, ".part") || strings.HasSuffix(name, ".tmp"):
		return true
	}
	return false
}

func rejectMavenSnapshots(arts []MavenArtifact) error {
	var bad []string
	for _, a := range arts {
		if strings.Contains(a.Version, "SNAPSHOT") {
			bad = append(bad, a.GroupID+":"+a.ArtifactID+":"+a.Version)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("refusing SNAPSHOT artifacts (not reproducible): %s", strings.Join(bad, ", "))
	}
	return nil
}

func (s *LowServer) writeMavenBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, artifacts []MavenArtifact) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamMaven, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamMaven,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"maven"},
		Maven:            &MavenManifest{Artifacts: artifacts},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	sig := ed25519.Sign(s.privateKey, manifestBytes)
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, sig, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamMaven, Sequence: seq, ExportedModules: len(artifacts), BundleID: id}, nil
}
