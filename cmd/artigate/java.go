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

import (
	"context"
	"crypto/ed25519"
	"crypto/md5"  //nolint:gosec // md5 is only a legacy Maven checksum, not a security control
	"crypto/sha1" //nolint:gosec // sha1 is only a legacy Maven checksum, not a security control
	"encoding/hex"
	"encoding/json"
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
	PomXML      string   `json:"pom_xml"`
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
	// Hold exportMu for the whole resolve->write->commit so a concurrent
	// exporter cannot claim the same sequence number between peek and commit.
	s.exportMu.Lock()
	defer s.exportMu.Unlock()

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

	seq := s.peekSequence()
	res, err := s.writeMavenBundle(seq, stageRoot, files, artifacts)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(seq); err != nil {
		return ExportResult{}, err
	}
	return res, nil
}

// mavenProjectPom returns the pom.xml to resolve: the caller's uploaded pom, or
// a synthetic project whose dependencies are the requested coordinates.
func mavenProjectPom(req MavenCollectRequest) (string, error) {
	if strings.TrimSpace(req.PomXML) != "" {
		return req.PomXML, nil
	}
	if len(req.Coordinates) == 0 {
		return "", errors.New("no maven coordinates or pom_xml provided")
	}
	var deps strings.Builder
	for _, spec := range req.Coordinates {
		c, err := parseMavenCoord(spec)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&deps, "    <dependency><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></dependency>\n",
			html.EscapeString(c.GroupID), html.EscapeString(c.ArtifactID), html.EscapeString(c.Version))
	}
	return syntheticMavenPom(deps.String()), nil
}

func syntheticMavenPom(deps string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>local.artigate</groupId>
  <artifactId>artigate-collect</artifactId>
  <version>0.0.0</version>
  <packaging>pom</packaging>
  <dependencies>
` + deps + `  </dependencies>
</project>
`
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

func (s *LowServer) writeMavenBundle(seq int64, stageRoot string, files []ManifestFile, artifacts []MavenArtifact) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	bundleID := bundleIDForSequence(seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         bundleID,
		Ecosystems:       []string{"maven"},
		Maven:            &MavenManifest{Artifacts: artifacts},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	sig := ed25519.Sign(s.privateKey, manifestBytes)
	if err := s.writeBundleArtifacts(bundleID, stageRoot, manifestBytes, sig, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Sequence: seq, ExportedModules: len(artifacts), BundleID: bundleID}, nil
}
