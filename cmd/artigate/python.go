package main

// Python (PyPI) ecosystem adapter. The low side runs `pip download` to collect
// wheels, then packs them into the same numbered, signed ArtiGate bundle format
// used for Go modules. The high side imports those wheels and serves them
// through the PyPI Simple Repository API — PEP 503 HTML and PEP 691 JSON,
// selected by content negotiation.

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
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

type PythonManifest struct {
	Projects []PythonProject `json:"projects"`
}

type PythonProject struct {
	Name           string       `json:"name"`
	NormalizedName string       `json:"normalized_name"`
	Version        string       `json:"version"`
	Files          []PythonFile `json:"files"`
}

type PythonFile struct {
	Filename       string `json:"filename"`
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	RequiresPython string `json:"requires_python,omitempty"`
	Yanked         bool   `json:"yanked"`
}

// -----------------------------------------------------------------------------
// Naming and filename parsing
// -----------------------------------------------------------------------------

var pyNameSepRE = regexp.MustCompile(`[-_.]+`)

// normalizePyName applies PEP 503 normalization: lowercase and collapse runs of
// ".", "-", and "_" into a single "-". So My_Package, my.package, and
// my-package all normalize to "my-package".
func normalizePyName(name string) string {
	return strings.ToLower(pyNameSepRE.ReplaceAllString(name, "-"))
}

// parseWheelFilename extracts the normalized project name and version from a
// wheel filename of the form
// {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl.
func parseWheelFilename(filename string) (project, version string, ok bool) {
	if !strings.HasSuffix(filename, ".whl") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
	// name, version, python, abi, platform (build tag is an optional 6th field).
	if len(parts) < 5 {
		return "", "", false
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return normalizePyName(parts[0]), parts[1], true
}

// maxWheelMetadataBytes caps the decompressed METADATA bytes read from a
// wheel, so a hostile zip entry cannot balloon in memory; the Requires-Python
// header sits in the leading header block, far below this.
const maxWheelMetadataBytes = 4 << 20

// wheelRequiresPython returns the Requires-Python specifier embedded in the
// wheel at path, or "" when the wheel, its METADATA, or the header is absent
// or unreadable (serving then simply omits the attribute). Reading it from
// the wheel itself follows the high side's rule of regenerating all index
// metadata from the verified artifacts actually present.
func wheelRequiresPython(path string) string {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return ""
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !isWheelMetadataPath(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return ""
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxWheelMetadataBytes))
		_ = rc.Close()
		if err != nil {
			return ""
		}
		return metadataRequiresPython(data)
	}
	return ""
}

// isWheelMetadataPath reports whether a zip entry is the wheel's top-level
// {name}-{version}.dist-info/METADATA core metadata file.
func isWheelMetadataPath(name string) bool {
	dir, file, ok := strings.Cut(name, "/")
	return ok && file == "METADATA" && strings.HasSuffix(dir, ".dist-info")
}

// metadataRequiresPython scans the RFC 822-style header block of a core
// metadata file for Requires-Python, stopping at the blank line that starts
// the description body. Folded continuation lines are skipped.
func metadataRequiresPython(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			return ""
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if key, val, ok := strings.Cut(line, ":"); ok && strings.EqualFold(key, "Requires-Python") {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

// validatePythonProjects checks that every project names a version and lists
// files that appear in the manifest's overall file set.
func validatePythonProjects(projects []PythonProject, seen map[string]bool) error {
	for _, p := range projects {
		if p.NormalizedName == "" || p.Version == "" {
			return errors.New("python project missing name or version")
		}
		if len(p.Files) == 0 {
			return fmt.Errorf("python project %s has no files", p.NormalizedName)
		}
		for _, f := range p.Files {
			if !seen[f.Path] {
				return fmt.Errorf("python project %s references file not listed in manifest.files: %s", p.NormalizedName, f.Path)
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: PyPI Simple Repository API (PEP 503 HTML, PEP 691 JSON)
// -----------------------------------------------------------------------------

// PEP 691 media types for the Simple API. Legacy text/html serves browsers
// and older clients; the versioned types are selected by content negotiation.
const (
	pySimpleJSONType   = "application/vnd.pypi.simple.v1+json"
	pySimpleHTMLType   = "application/vnd.pypi.simple.v1+html"
	pySimpleLegacyType = "text/html"

	// pySimpleAPIVersion is the PEP 691 api-version advertised in JSON meta.
	pySimpleAPIVersion = "1.0"
)

type pyFileEntry struct {
	filename string
	project  string
	version  string
}

// pySimpleServable maps one Accept media range to the Simple API
// representation it selects, or "" when it selects none.
func pySimpleServable(mediaType string) string {
	switch mediaType {
	case pySimpleJSONType:
		return pySimpleJSONType
	case pySimpleHTMLType:
		return pySimpleHTMLType
	case pySimpleLegacyType, "text/*", "*/*":
		return pySimpleLegacyType
	}
	return ""
}

// acceptMediaRange splits one Accept header element into its lowercased media
// type and q-value (1 when absent or unparsable).
func acceptMediaRange(part string) (string, float64) {
	fields := strings.Split(part, ";")
	q := 1.0
	for _, param := range fields[1:] {
		if v, ok := strings.CutPrefix(strings.TrimSpace(param), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
	}
	return strings.ToLower(strings.TrimSpace(fields[0])), q
}

// negotiatePySimple picks the Simple API representation (PEP 691 JSON,
// versioned HTML, or legacy text/html) the Accept header ranks highest. An
// absent or unmatched Accept falls back to legacy HTML so browsers and older
// pip keep working; a q=0 range is never selected, and ties keep the range
// listed first.
func negotiatePySimple(accept string) string {
	best, bestQ := "", 0.0
	for _, part := range strings.Split(accept, ",") {
		mediaType, q := acceptMediaRange(part)
		serve := pySimpleServable(mediaType)
		if serve == "" || q <= bestQ {
			continue
		}
		best, bestQ = serve, q
	}
	if best == "" {
		return pySimpleLegacyType
	}
	return best
}

// pySimpleMeta is the PEP 691 response meta object.
type pySimpleMeta struct {
	APIVersion string `json:"api-version"`
}

// pySimpleProjectRef is one project entry of the JSON root index.
type pySimpleProjectRef struct {
	Name string `json:"name"`
}

// pySimpleRoot is the PEP 691 JSON root index.
type pySimpleRoot struct {
	Meta     pySimpleMeta         `json:"meta"`
	Projects []pySimpleProjectRef `json:"projects"`
}

// pySimpleFile is one file entry of a PEP 691 JSON project page. Yanked is
// omitted deliberately: ArtiGate never yanks a mirrored wheel.
type pySimpleFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"`
	RequiresPython string            `json:"requires-python,omitempty"`
}

// pySimpleProject is the PEP 691 JSON project page.
type pySimpleProject struct {
	Meta  pySimpleMeta   `json:"meta"`
	Name  string         `json:"name"`
	Files []pySimpleFile `json:"files"`
}

func (s *HighServer) pythonDir() string {
	return filepath.Join(s.downloadDir, "python", "packages")
}

// scanPyFiles lists every wheel present in the high-side package store.
func (s *HighServer) scanPyFiles() ([]pyFileEntry, error) {
	entries, err := os.ReadDir(s.pythonDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []pyFileEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if project, version, ok := parseWheelFilename(e.Name()); ok {
			out = append(out, pyFileEntry{filename: e.Name(), project: project, version: version})
		}
	}
	return out, nil
}

// servePython handles the PyPI Simple Repository routes. It reports whether it
// wrote a response for the request.
func (s *HighServer) servePython(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/simple" && !strings.HasPrefix(p, "/simple/") && !strings.HasPrefix(p, "/packages/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	switch {
	case p == "/simple" || p == "/simple/":
		s.handlePySimpleRoot(w, r)
	case strings.HasPrefix(p, "/simple/"):
		s.handlePySimpleProject(w, r, p)
	default:
		s.handlePyPackage(w, r, p)
	}
	return true
}

func (s *HighServer) handlePySimpleRoot(w http.ResponseWriter, r *http.Request) {
	files, err := s.scanPyFiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	seen := map[string]bool{}
	var projects []string
	for _, f := range files {
		if !seen[f.project] {
			seen[f.project] = true
			projects = append(projects, f.project)
		}
	}
	sort.Strings(projects)

	contentType := negotiatePySimple(r.Header.Get("Accept"))
	if contentType == pySimpleJSONType {
		root := pySimpleRoot{Meta: pySimpleMeta{APIVersion: pySimpleAPIVersion}, Projects: make([]pySimpleProjectRef, 0, len(projects))}
		for _, p := range projects {
			root.Projects = append(root.Projects, pySimpleProjectRef{Name: p})
		}
		writePySimpleJSON(w, root)
		return
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html>\n  <body>\n")
	for _, p := range projects {
		fmt.Fprintf(&b, "    <a href=\"/simple/%s/\">%s</a>\n", url.PathEscape(p), html.EscapeString(p))
	}
	b.WriteString("  </body>\n</html>\n")
	writeHTMLAs(w, contentType, b.String())
}

// pyProjectFile is one wheel served on a project page. Its hash and its
// Requires-Python both come from the verified artifact on disk — the wheel's
// own embedded metadata — never from transferred index data.
type pyProjectFile struct {
	filename       string
	sha256         string
	requiresPython string
}

// pyProjectFiles hashes and reads the metadata of every wheel of one project,
// sorted by filename.
func (s *HighServer) pyProjectFiles(project string) ([]pyProjectFile, error) {
	files, err := s.scanPyFiles()
	if err != nil {
		return nil, err
	}
	var out []pyProjectFile
	for _, f := range files {
		if f.project != project {
			continue
		}
		abs := filepath.Join(s.pythonDir(), f.filename)
		sum, err := sha256File(abs)
		if err != nil {
			return nil, err
		}
		out = append(out, pyProjectFile{filename: f.filename, sha256: sum, requiresPython: wheelRequiresPython(abs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].filename < out[j].filename })
	return out, nil
}

func (s *HighServer) handlePySimpleProject(w http.ResponseWriter, r *http.Request, urlPath string) {
	project := normalizePyName(strings.Trim(strings.TrimPrefix(urlPath, "/simple/"), "/"))
	matched, err := s.pyProjectFiles(project)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(matched) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	contentType := negotiatePySimple(r.Header.Get("Accept"))
	if contentType == pySimpleJSONType {
		writePySimpleJSON(w, pySimpleProjectJSON(project, matched))
		return
	}
	writeHTMLAs(w, contentType, pySimpleProjectHTML(project, matched))
}

// pySimpleProjectJSON renders a project's PEP 691 JSON page.
func pySimpleProjectJSON(project string, files []pyProjectFile) pySimpleProject {
	out := pySimpleProject{
		Meta:  pySimpleMeta{APIVersion: pySimpleAPIVersion},
		Name:  project,
		Files: make([]pySimpleFile, 0, len(files)),
	}
	for _, f := range files {
		out.Files = append(out.Files, pySimpleFile{
			Filename:       f.filename,
			URL:            "/packages/" + url.PathEscape(f.filename),
			Hashes:         map[string]string{"sha256": f.sha256},
			RequiresPython: f.requiresPython,
		})
	}
	return out
}

// pySimpleProjectHTML renders a project's PEP 503 HTML page, carrying each
// wheel's requires-python in the data-requires-python attribute so pip can
// skip releases that do not support the client's interpreter.
func pySimpleProjectHTML(project string, files []pyProjectFile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!DOCTYPE html>\n<html>\n  <body>\n    <h1>Links for %s</h1>\n", html.EscapeString(project))
	for _, f := range files {
		attr := ""
		if f.requiresPython != "" {
			attr = " data-requires-python=\"" + html.EscapeString(f.requiresPython) + "\""
		}
		fmt.Fprintf(&b, "    <a href=\"/packages/%s#sha256=%s\"%s>%s</a>\n", url.PathEscape(f.filename), f.sha256, attr, html.EscapeString(f.filename))
	}
	b.WriteString("  </body>\n</html>\n")
	return b.String()
}

func (s *HighServer) handlePyPackage(w http.ResponseWriter, r *http.Request, urlPath string) {
	filename := strings.TrimPrefix(urlPath, "/packages/")
	if filename == "" || strings.ContainsRune(filename, '/') {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.pythonDir(), filename)
	if !safeJoin(s.pythonDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, body)
}

// writeHTMLAs writes an HTML body under the negotiated Simple API content
// type (the PEP 691 versioned HTML type, or legacy text/html).
func writeHTMLAs(w http.ResponseWriter, contentType, body string) {
	if contentType == pySimpleLegacyType {
		writeHTML(w, body)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = io.WriteString(w, body)
}

func writePySimpleJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", pySimpleJSONType)
	_ = json.NewEncoder(w).Encode(v)
}

// -----------------------------------------------------------------------------
// Low side: pip download collector
// -----------------------------------------------------------------------------

type PythonTarget struct {
	PythonVersion  string   `json:"python_version,omitempty"`
	Implementation string   `json:"implementation,omitempty"`
	ABI            string   `json:"abi,omitempty"`
	Platforms      []string `json:"platforms,omitempty"`
	// OnlyBinary is retained for API compatibility. Omission and true both use
	// the mandatory wheels-only policy; false is rejected at validation.
	OnlyBinary *bool `json:"only_binary,omitempty"`
}

type PythonCollectRequest struct {
	Requirements []string      `json:"requirements"`
	Target       *PythonTarget `json:"target,omitempty"`
	// Force disables export dedup for this collect: every wheel is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// validatePipArg rejects a user-supplied pip argument that pip would otherwise
// reparse as an option. Requirement specifiers and target selectors never
// legitimately begin with '-', so refusing that closes argument injection such
// as a requirement of "-r/etc/passwd" or "--index-url=http://attacker/". Spaces
// are allowed because PEP 508 environment markers contain them; only control
// characters are rejected.
func validatePipArg(kind, val string) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("empty %s", kind)
	}
	if strings.HasPrefix(val, "-") {
		return fmt.Errorf("%s %q must not start with '-' (would be parsed as a pip flag)", kind, val)
	}
	for _, r := range val {
		if r < ' ' || r == 0x7f {
			return fmt.Errorf("%s %q contains a control character", kind, val)
		}
	}
	// ArtiGate mirrors wheels pip resolves from the index. A direct URL or local
	// path bypasses that resolution and would have pip fetch (and the low side
	// sign) an artifact from an operator-named host with no index checksum, so
	// reject those forms — pin a versioned package from the index instead.
	if strings.Contains(val, "://") {
		return fmt.Errorf("%s %q must not be a URL; mirror a version resolved from the index instead", kind, val)
	}
	if kind == "requirement" && (strings.ContainsAny(val, "/\\") || strings.HasPrefix(val, ".")) {
		return fmt.Errorf("requirement %q must be a package specifier, not a path or URL", val)
	}
	return nil
}

// validatePythonRequest validates every caller-supplied string that becomes a
// pip argument (requirements and target selectors).
func validatePythonRequest(req PythonCollectRequest) error {
	for _, r := range req.Requirements {
		if err := validatePipArg("requirement", r); err != nil {
			return err
		}
	}
	if req.Target == nil {
		return nil
	}
	if req.Target.OnlyBinary != nil && !*req.Target.OnlyBinary {
		return errors.New("target.only_binary=false is not supported; Python collection is wheels-only")
	}
	for _, f := range []struct{ kind, val string }{
		{"python_version", req.Target.PythonVersion},
		{"implementation", req.Target.Implementation},
		{"abi", req.Target.ABI},
	} {
		if f.val == "" {
			continue
		}
		if err := validatePipArg(f.kind, f.val); err != nil {
			return err
		}
	}
	for _, p := range req.Target.Platforms {
		if err := validatePipArg("platform", p); err != nil {
			return err
		}
	}
	return nil
}

// pipDownloadArgs builds the argument list for `python -m pip download`.
func pipDownloadArgs(dest string, req PythonCollectRequest) []string {
	args := []string{"-m", "pip", "download", "--dest", dest}
	args = append(args, pipTargetArgs(req.Target)...)
	return append(args, req.Requirements...)
}

// pipTargetArgs renders the mandatory wheels-only flag and any cross-target
// selectors for `pip download`. This invariant keeps package-controlled source
// build hooks away from the process that holds ArtiGate signing credentials.
func pipTargetArgs(t *PythonTarget) []string {
	args := []string{"--only-binary=:all:"}
	if t == nil {
		return args
	}
	if t.PythonVersion != "" {
		args = append(args, "--python-version", t.PythonVersion)
	}
	if t.Implementation != "" {
		args = append(args, "--implementation", t.Implementation)
	}
	if t.ABI != "" {
		args = append(args, "--abi", t.ABI)
	}
	for _, p := range t.Platforms {
		args = append(args, "--platform", p)
	}
	return args
}

func (s *LowServer) runPip(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	bin := s.cfg.PipBinary
	if bin == "" {
		bin = "python3"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = s.cfg.Root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("pip %s failed: %w\n%s", strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

// HandlePythonCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandlePythonCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req PythonCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse python collect request: %w", err)
		}
	}
	return s.CollectPython(ctx, req)
}

// CollectPython downloads the requested wheels with pip and writes them into a
// signed bundle on the shared ArtiGate sequence stream.
func (s *LowServer) CollectPython(ctx context.Context, req PythonCollectRequest) (ExportResult, error) {
	if len(req.Requirements) == 0 {
		return ExportResult{}, errors.New("no python requirements provided")
	}
	if err := validatePythonRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the python stream's lock for the whole download->write->commit
	// so a concurrent python exporter cannot claim the same sequence number
	// between peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamPython)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "python", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)
	dest := filepath.Join(stageRoot, "python", "packages")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return ExportResult{}, err
	}

	emitProgress(ctx, "Running pip download for %d requirement(s)…", len(req.Requirements))
	if _, err := s.runPip(ctx, pipDownloadArgs(dest, req)...); err != nil {
		return ExportResult{}, err
	}

	files, projects, skipped, err := collectPythonDist(dest)
	if err != nil {
		return ExportResult{}, err
	}
	emitProgress(ctx, "Packing %d wheel file(s) into a signed bundle…", len(files))
	if len(files) == 0 {
		if len(skipped) > 0 {
			return ExportResult{}, fmt.Errorf("no wheels to mirror; %d package(s) publish only a source distribution: %s",
				len(skipped), summarizeFailures(skipped))
		}
		return ExportResult{}, errors.New("pip download produced no wheels")
	}

	// exportIfNew peeks/commits the sequence around the write (so a failed
	// collection never burns a number) and skips entirely when every wheel was
	// already forwarded.
	res, err := s.exportIfNew(ctx, streamPython, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writePythonBundle(ctx, seq, stageRoot, files, projects)
	})
	if err != nil {
		return ExportResult{}, err
	}
	// Report source-only packages that could not be mirrored, like the other
	// ecosystems report their unfetchable items.
	res.SkippedModules = append(res.SkippedModules, skipped...)
	return res, nil
}

// parseSdistFilename does a best-effort split of a source-distribution filename
// ("{name}-{version}.tar.gz") into its normalized project name and version. It
// is used only to report a package that cannot be mirrored (ArtiGate serves
// wheels only), so an imperfect split on a hyphenated name is acceptable.
func parseSdistFilename(filename string) (name, version string, ok bool) {
	for _, ext := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip"} {
		stem, cut := strings.CutSuffix(filename, ext)
		if !cut {
			continue
		}
		if i := strings.LastIndex(stem, "-"); i > 0 && i < len(stem)-1 {
			return normalizePyName(stem[:i]), stem[i+1:], true
		}
		return normalizePyName(stem), "", true
	}
	return "", "", false
}

// pyDist accumulates the wheels (and the source-only packages skipped) found in
// a pip download directory.
type pyDist struct {
	byProject map[string]*PythonProject
	order     []string
	files     []ManifestFile
	skipped   []FailedModule
}

// addWheel hashes one wheel and records it under its project, together with
// the Requires-Python specifier read from the wheel's own metadata. A filename
// that does not parse as a wheel is ignored.
func (d *pyDist) addWheel(dest, name string) error {
	project, version, ok := parseWheelFilename(name)
	if !ok {
		return nil
	}
	rel := path.Join("python", "packages", name)
	abs := filepath.Join(dest, name)
	mf, err := hashManifestFile(abs, rel)
	if err != nil {
		return err
	}
	d.files = append(d.files, mf)
	key := project + "@" + version
	p := d.byProject[key]
	if p == nil {
		p = &PythonProject{Name: project, NormalizedName: project, Version: version}
		d.byProject[key] = p
		d.order = append(d.order, key)
	}
	p.Files = append(p.Files, PythonFile{
		Filename: name, Path: rel, SHA256: mf.SHA256,
		RequiresPython: wheelRequiresPython(abs),
	})
	return nil
}

func (d *pyDist) projects() []PythonProject {
	out := make([]PythonProject, 0, len(d.order))
	for _, k := range d.order {
		out = append(out, *d.byProject[k])
	}
	return out
}

// collectPythonDist scans a pip download directory and returns the manifest
// files and per-project grouping for the wheels found, plus any source
// distributions pip downloaded. A source distribution means the package
// published no wheel; ArtiGate serves wheels only, so it cannot be mirrored and
// is reported as skipped rather than silently dropped.
func collectPythonDist(dest string) ([]ManifestFile, []PythonProject, []FailedModule, error) {
	entries, err := os.ReadDir(dest)
	if err != nil {
		return nil, nil, nil, err
	}
	d := &pyDist{byProject: map[string]*PythonProject{}}
	for _, e := range entries {
		switch {
		case e.IsDir():
			continue
		case strings.HasSuffix(e.Name(), ".whl"):
			if err := d.addWheel(dest, e.Name()); err != nil {
				return nil, nil, nil, err
			}
		default:
			if name, version, ok := parseSdistFilename(e.Name()); ok {
				d.skipped = append(d.skipped, FailedModule{Module: name, Version: version, Error: "no wheel available (source distribution only); not mirrored"})
			}
		}
	}
	return d.files, d.projects(), d.skipped, nil
}

func (s *LowServer) writePythonBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, projects []PythonProject) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamPython, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamPython,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"python"},
		Python:           &PythonManifest{Projects: projects},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamPython, Sequence: seq, ExportedModules: len(projects), BundleID: id}, nil
}
