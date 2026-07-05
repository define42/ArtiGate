package main

// Python (PyPI) ecosystem adapter. The low side runs `pip download` to collect
// wheels, then packs them into the same numbered, signed ArtiGate bundle format
// used for Go modules. The high side imports those wheels and serves them
// through the PyPI Simple Repository API (PEP 503).

import (
	"context"
	"crypto/ed25519"
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
// High side: PyPI Simple Repository API
// -----------------------------------------------------------------------------

type pyFileEntry struct {
	filename string
	project  string
	version  string
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
		s.handlePySimpleRoot(w)
	case strings.HasPrefix(p, "/simple/"):
		s.handlePySimpleProject(w, p)
	default:
		s.handlePyPackage(w, r, p)
	}
	return true
}

func (s *HighServer) handlePySimpleRoot(w http.ResponseWriter) {
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

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html>\n  <body>\n")
	for _, p := range projects {
		fmt.Fprintf(&b, "    <a href=\"/simple/%s/\">%s</a>\n", url.PathEscape(p), html.EscapeString(p))
	}
	b.WriteString("  </body>\n</html>\n")
	writeHTML(w, b.String())
}

func (s *HighServer) handlePySimpleProject(w http.ResponseWriter, urlPath string) {
	project := normalizePyName(strings.Trim(strings.TrimPrefix(urlPath, "/simple/"), "/"))
	files, err := s.scanPyFiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var matched []pyFileEntry
	for _, f := range files {
		if f.project == project {
			matched = append(matched, f)
		}
	}
	if len(matched) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].filename < matched[j].filename })

	var b strings.Builder
	fmt.Fprintf(&b, "<!DOCTYPE html>\n<html>\n  <body>\n    <h1>Links for %s</h1>\n", html.EscapeString(project))
	for _, f := range matched {
		sum, err := sha256File(filepath.Join(s.pythonDir(), f.filename))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(&b, "    <a href=\"/packages/%s#sha256=%s\">%s</a>\n", url.PathEscape(f.filename), sum, html.EscapeString(f.filename))
	}
	b.WriteString("  </body>\n</html>\n")
	writeHTML(w, b.String())
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

// -----------------------------------------------------------------------------
// Low side: pip download collector
// -----------------------------------------------------------------------------

type PythonTarget struct {
	PythonVersion  string   `json:"python_version,omitempty"`
	Implementation string   `json:"implementation,omitempty"`
	ABI            string   `json:"abi,omitempty"`
	Platforms      []string `json:"platforms,omitempty"`
	OnlyBinary     bool     `json:"only_binary,omitempty"`
}

type PythonCollectRequest struct {
	Requirements []string      `json:"requirements"`
	Target       *PythonTarget `json:"target,omitempty"`
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

// pipDownloadArgs builds the argument list for `python -m pip download`. When a
// cross-target is requested pip requires --only-binary=:all:.
func pipDownloadArgs(dest string, req PythonCollectRequest) []string {
	args := []string{"-m", "pip", "download", "--dest", dest}
	args = append(args, pipTargetArgs(req.Target)...)
	return append(args, req.Requirements...)
}

// pipTargetArgs renders the cross-target flags for `pip download`. pip requires
// --only-binary=:all: whenever any target selector is supplied.
func pipTargetArgs(t *PythonTarget) []string {
	if t == nil {
		return nil
	}
	var args []string
	if t.OnlyBinary || len(t.Platforms) > 0 || t.ABI != "" || t.PythonVersion != "" {
		args = append(args, "--only-binary=:all:")
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

	if _, err := s.runPip(ctx, pipDownloadArgs(dest, req)...); err != nil {
		return ExportResult{}, err
	}

	files, projects, err := collectPythonDist(dest)
	if err != nil {
		return ExportResult{}, err
	}
	if len(files) == 0 {
		return ExportResult{}, errors.New("pip download produced no wheels")
	}

	// exportIfNew peeks/commits the sequence around the write (so a failed
	// collection never burns a number) and skips entirely when every wheel was
	// already forwarded.
	return s.exportIfNew(streamPython, files, func(seq int64) (ExportResult, error) {
		return s.writePythonBundle(seq, stageRoot, files, projects)
	})
}

// collectPythonDist scans a pip download directory and returns the manifest
// files plus the per-project grouping for the manifest's python section.
func collectPythonDist(dest string) ([]ManifestFile, []PythonProject, error) {
	entries, err := os.ReadDir(dest)
	if err != nil {
		return nil, nil, err
	}
	byProject := map[string]*PythonProject{}
	var order []string
	var files []ManifestFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".whl") {
			continue
		}
		project, version, ok := parseWheelFilename(e.Name())
		if !ok {
			continue
		}
		rel := path.Join("python", "packages", e.Name())
		mf, err := hashManifestFile(filepath.Join(dest, e.Name()), rel)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, mf)

		key := project + "@" + version
		p, ok := byProject[key]
		if !ok {
			p = &PythonProject{Name: project, NormalizedName: project, Version: version}
			byProject[key] = p
			order = append(order, key)
		}
		p.Files = append(p.Files, PythonFile{Filename: e.Name(), Path: rel, SHA256: mf.SHA256})
	}
	projects := make([]PythonProject, 0, len(order))
	for _, k := range order {
		projects = append(projects, *byProject[k])
	}
	return files, projects, nil
}

func (s *LowServer) writePythonBundle(seq int64, stageRoot string, files []ManifestFile, projects []PythonProject) (ExportResult, error) {
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
	sig := ed25519.Sign(s.privateKey, manifestBytes)
	if err := s.writeBundleArtifacts(id, stageRoot, manifestBytes, sig, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamPython, Sequence: seq, ExportedModules: len(projects), BundleID: id}, nil
}
