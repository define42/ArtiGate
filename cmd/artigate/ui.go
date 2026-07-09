package main

// High-side dashboard UI. A self-contained page (no external assets, so it works
// air-gapped) served at "/", backed by a JSON overview endpoint. It shows import
// status — prominently flagging any missing bundles — and a tree of every
// mirrored Go module and Python project. The front-end is written in TypeScript
// (ui/app.ts); its compiled output (ui/app.js) is embedded below. Rebuild it
// with `make ui`.

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed ui/index.html
var uiIndexHTML string

//go:embed ui/app.js
var uiAppJS string

// UIOverview is the initial payload rendered by the dashboard: just the import
// status. The package trees are fetched lazily, level by level, from
// /ui/api/tree.
type UIOverview struct {
	Status ImportStatus `json:"status"`
}

type UIModule struct {
	Module   string   `json:"module"`
	Versions []string `json:"versions"`
}

type UIProject struct {
	Project string     `json:"project"`
	Files   []UIPyFile `json:"files"`
}

type UIPyFile struct {
	Filename string `json:"filename"`
	Version  string `json:"version"`
}

// UITreeNode is one node in a lazily loaded package tree. Expandable nodes are
// fetched again by Path when the user opens them; leaf nodes (versions, files)
// are not.
type UITreeNode struct {
	Label      string `json:"label"`
	Path       string `json:"path"`
	Kind       string `json:"kind"` // dir | module | version | project | file
	Expandable bool   `json:"expandable"`
	Count      int    `json:"count,omitempty"`
}

// treeCache memoizes the (relatively expensive) filesystem scans for a short
// window so that lazily expanding many nodes does not re-walk the repository on
// every request.
type treeCache struct {
	mu         sync.Mutex
	expiry     time.Time
	mods       []UIModule
	python     []UIProject
	maven      []UIModule
	apt        []UIModule
	rpm        []UIModule
	containers []UIModule
	npm        []UIModule
	hf         []UIModule
	uploads    []UploadedFolder
}

func (s *HighServer) serveUI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/", "/ui", "/ui/":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		// The dashboard shell and its script change across versions; never let
		// a browser cache serve a stale copy of either.
		w.Header().Set("Cache-Control", "no-store")
		writeHTML(w, uiIndexHTML)
	case "/ui/app.js":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, uiAppJS)
	case "/ui/api/overview":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		s.handleUIOverview(w)
	case "/ui/api/tree":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		s.handleUITree(w, r)
	case "/ui/api/detail":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		s.handleUIDetail(w, r)
	case "/ui/api/repos":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		s.handleUIRepos(w, r)
	default:
		return false
	}
	return true
}

func isReadMethod(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

func (s *HighServer) handleUIOverview(w http.ResponseWriter) {
	status, err := s.ImportStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, UIOverview{Status: status})
}

// UIRepo describes one mirrored APT/RPM/container/AI-model repository for the
// "Set me up" guide. Suites (with each suite's own components/architectures)
// is set for APT only, so the guide can offer a per-release picker; Tags is
// set for container repositories and AI models. Signed is true when the high
// side publishes the repository with its own GPG signature (so clients should
// verify it). Kind distinguishes an AI-model full repository snapshot
// ("repo", consumed via HF_ENDPOINT) from a GGUF model (empty, pulled with
// Ollama).
type UIRepo struct {
	Name   string     `json:"name"`
	Suites []AptSuite `json:"suites,omitempty"`
	Tags   []string   `json:"tags,omitempty"`
	Signed bool       `json:"signed"`
	Kind   string     `json:"kind,omitempty"`
}

// UIReposResponse is the body of GET /ui/api/repos.
type UIReposResponse struct {
	Repos []UIRepo `json:"repos"`
}

// handleUIRepos lists the mirrored repositories of an ecosystem so the "Set me
// up" guide can render correct per-repository client config.
func (s *HighServer) handleUIRepos(w http.ResponseWriter, r *http.Request) {
	var (
		repos []UIRepo
		err   error
	)
	switch r.URL.Query().Get("eco") {
	case "apt":
		repos, err = s.aptRepoList()
	case "rpm":
		repos, err = s.rpmRepoList()
	case "containers":
		repos, err = s.containerRepoList()
	case "hf":
		repos, err = s.hfRepoList()
	default:
		http.Error(w, "repos are only available for apt, rpm, containers, and hf", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, UIReposResponse{Repos: repos})
}

// handleUITree returns the immediate children of a node in a package tree.
// eco selects the ecosystem ("go" or "python"); path is the parent node's path
// (empty for the tree root).
func (s *HighServer) handleUITree(w http.ResponseWriter, r *http.Request) {
	eco := r.URL.Query().Get("eco")
	path := r.URL.Query().Get("path")

	lists, err := s.cachedLists()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var nodes []UITreeNode
	switch eco {
	case "python":
		nodes = pythonTreeChildren(lists.python, path)
	case "maven":
		// Maven coordinates and APT mirror/package keys form slash-separated path
		// trees just like Go module paths, so the same segment-tree builder applies.
		nodes = goTreeChildren(lists.maven, path)
	case "apt":
		nodes = goTreeChildren(lists.apt, path)
	case "rpm":
		nodes = goTreeChildren(lists.rpm, path)
	case "containers":
		nodes = goTreeChildren(lists.containers, path)
	case "hf":
		// Model names are "<org>/<name>", so the segment-tree builder groups
		// them by organization, with the variant tags as version leaves.
		nodes = goTreeChildren(lists.hf, path)
	case "npm":
		// npm names are flat (a scope is part of the name, not a directory), so
		// the two-level package -> versions tree applies.
		nodes = npmTreeChildren(lists.npm, path)
	case "uploads":
		nodes = uploadsTreeChildren(lists.uploads, path)
	default:
		nodes = goTreeChildren(lists.mods, path)
	}
	writeJSON(w, map[string][]UITreeNode{"nodes": nodes})
}

// ecoLists holds the mirrored inventory for each ecosystem's dashboard tree.
type ecoLists struct {
	mods       []UIModule
	python     []UIProject
	maven      []UIModule
	apt        []UIModule
	rpm        []UIModule
	containers []UIModule
	npm        []UIModule
	hf         []UIModule
	uploads    []UploadedFolder
}

// cachedLists returns the mirrored inventory across ecosystems, memoized for a
// few seconds so a burst of lazy expand requests reuses one scan.
func (s *HighServer) cachedLists() (ecoLists, error) {
	s.tree.mu.Lock()
	defer s.tree.mu.Unlock()
	if time.Now().Before(s.tree.expiry) {
		return ecoLists{mods: s.tree.mods, python: s.tree.python, maven: s.tree.maven, apt: s.tree.apt, rpm: s.tree.rpm, containers: s.tree.containers, npm: s.tree.npm, hf: s.tree.hf, uploads: s.tree.uploads}, nil
	}
	mods, err := s.listGoModules()
	if err != nil {
		return ecoLists{}, err
	}
	python, err := s.listPythonProjects()
	if err != nil {
		return ecoLists{}, err
	}
	maven, err := s.listMavenArtifacts()
	if err != nil {
		return ecoLists{}, err
	}
	apt, err := s.listAptMirrors()
	if err != nil {
		return ecoLists{}, err
	}
	rpm, err := s.listRpmMirrors()
	if err != nil {
		return ecoLists{}, err
	}
	containers, err := s.listContainerRepos()
	if err != nil {
		return ecoLists{}, err
	}
	npm, err := s.listNpmPackages()
	if err != nil {
		return ecoLists{}, err
	}
	hf, err := s.listHFModels()
	if err != nil {
		return ecoLists{}, err
	}
	uploads, err := s.listUploadedFolders()
	if err != nil {
		return ecoLists{}, err
	}
	s.tree.mods, s.tree.python, s.tree.maven, s.tree.apt, s.tree.rpm, s.tree.containers, s.tree.npm, s.tree.hf, s.tree.uploads = mods, python, maven, apt, rpm, containers, npm, hf, uploads
	s.tree.expiry = time.Now().Add(3 * time.Second)
	return ecoLists{mods: mods, python: python, maven: maven, apt: apt, rpm: rpm, containers: containers, npm: npm, hf: hf, uploads: uploads}, nil
}

// goTreeChildren returns the immediate children of prefix in the Go module path
// tree. The root ("") yields the distinct first path segments (github.com,
// golang.org, ...); each deeper level yields the next segment, and an exact
// module's children are its versions.
func goTreeChildren(mods []UIModule, prefix string) []UITreeNode {
	segs := goImmediateSegments(mods, prefix)
	nodes := make([]UITreeNode, 0, len(segs))
	for _, sg := range segs {
		kind := "dir"
		if sg.module {
			kind = "module"
		}
		count := sg.descendants
		if sg.module && !sg.hasDeeper {
			count = sg.versions
		}
		nodes = append(nodes, UITreeNode{Label: sg.label, Path: sg.path, Kind: kind, Expandable: true, Count: count})
	}
	// If prefix is itself an exact module, its versions are leaf children.
	for _, m := range mods {
		if m.Module == prefix {
			for _, v := range m.Versions {
				nodes = append(nodes, UITreeNode{Label: v, Path: prefix + "@" + v, Kind: "version"})
			}
		}
	}
	return nodes
}

type goSeg struct {
	label       string
	path        string
	module      bool // an exact module exists at path
	hasDeeper   bool // modules exist below path
	descendants int  // number of modules at or below path
	versions    int  // versions if path is an exact module
}

func goImmediateSegments(mods []UIModule, prefix string) []goSeg {
	byPath := map[string]*goSeg{}
	order := []string{}
	for _, m := range mods {
		rest, ok := remainderUnder(m.Module, prefix)
		if !ok || rest == "" {
			continue
		}
		seg, deeper := rest, false
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			seg, deeper = rest[:i], true
		}
		childPath := seg
		if prefix != "" {
			childPath = prefix + "/" + seg
		}
		g, exists := byPath[childPath]
		if !exists {
			g = &goSeg{label: seg, path: childPath}
			byPath[childPath] = g
			order = append(order, childPath)
		}
		g.descendants++
		if deeper {
			g.hasDeeper = true
		} else {
			g.module = true
			g.versions = len(m.Versions)
		}
	}
	out := make([]goSeg, 0, len(order))
	for _, p := range order {
		out = append(out, *byPath[p])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out
}

// remainderUnder reports the portion of module below prefix, and whether module
// is under prefix at all.
func remainderUnder(module, prefix string) (string, bool) {
	if prefix == "" {
		return module, true
	}
	if strings.HasPrefix(module, prefix+"/") {
		return module[len(prefix)+1:], true
	}
	return "", false
}

// pythonTreeChildren returns the two-level Python tree: the root ("") yields the
// projects, and expanding a project yields its wheel files.
func pythonTreeChildren(projects []UIProject, path string) []UITreeNode {
	if path == "" {
		nodes := make([]UITreeNode, 0, len(projects))
		for _, p := range projects {
			nodes = append(nodes, UITreeNode{Label: p.Project, Path: p.Project, Kind: "project", Expandable: true, Count: len(p.Files)})
		}
		return nodes
	}
	for _, p := range projects {
		if p.Project == path {
			nodes := make([]UITreeNode, 0, len(p.Files))
			for _, f := range p.Files {
				nodes = append(nodes, UITreeNode{Label: f.Filename, Path: f.Filename, Kind: "file"})
			}
			return nodes
		}
	}
	return []UITreeNode{}
}

// listGoModules walks the go/ subtree and returns every module that has at
// least one complete version, with its versions sorted ascending.
func (s *HighServer) listGoModules() ([]UIModule, error) {
	root := s.goModuleDir()
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil // no Go modules mirrored yet
	}
	var mods []UIModule
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || d.Name() != "@v" {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(p))
		if relErr != nil {
			return nil
		}
		if mod, ok := s.goModuleAt(filepath.ToSlash(rel)); ok {
			mods = append(mods, mod)
		}
		return filepath.SkipDir
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Module < mods[j].Module })
	return mods, nil
}

func (s *HighServer) goModuleAt(moduleEsc string) (UIModule, bool) {
	versions, err := s.completeVersions(moduleEsc)
	if err != nil || len(versions) == 0 {
		return UIModule{}, false
	}
	module, err := unescapeModulePath(moduleEsc)
	if err != nil {
		return UIModule{}, false
	}
	sortVersionsAsc(versions)
	return UIModule{Module: module, Versions: versions}, true
}

// listPythonProjects groups the mirrored wheels by normalized project name.
func (s *HighServer) listPythonProjects() ([]UIProject, error) {
	files, err := s.scanPyFiles()
	if err != nil {
		return nil, err
	}
	byProject := map[string][]UIPyFile{}
	var order []string
	for _, f := range files {
		if _, ok := byProject[f.project]; !ok {
			order = append(order, f.project)
		}
		byProject[f.project] = append(byProject[f.project], UIPyFile{Filename: f.filename, Version: f.version})
	}
	sort.Strings(order)

	projects := make([]UIProject, 0, len(order))
	for _, name := range order {
		fs := byProject[name]
		sort.Slice(fs, func(i, j int) bool { return fs[i].Filename < fs[j].Filename })
		projects = append(projects, UIProject{Project: name, Files: fs})
	}
	return projects, nil
}

// -----------------------------------------------------------------------------
// Leaf detail panel
// -----------------------------------------------------------------------------

// UIDetailField is one label/value row in the detail panel.
type UIDetailField struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Mono  bool   `json:"mono,omitempty"`
}

// UIDetail describes a selected leaf (a Go module version or a Python wheel).
// CopyRef, when set, is a host-relative reference (used for a container's full
// pull reference): the dashboard prepends its own host — known only
// client-side, honoring any reverse proxy — and renders a prominent
// click-to-copy control, so the operator copies exactly what `docker pull`
// takes.
type UIDetail struct {
	Title    string          `json:"title"`
	Subtitle string          `json:"subtitle,omitempty"`
	Fields   []UIDetailField `json:"fields"`
	GoMod    string          `json:"go_mod,omitempty"`
	CopyRef  string          `json:"copy_ref,omitempty"`
	// Layers is a container image's build-history breakdown (the command each
	// step ran, and the filesystem layer it produced), rendered as a box below
	// the detail panel. Empty for non-container leaves.
	Layers []UIImageLayer `json:"layers,omitempty"`
}

// UIImageLayer is one build step of a container image, from its config
// history: the command it ran and, for steps that created a filesystem layer,
// the stored layer's size and digest. Empty steps (ENV, CMD, LABEL, …) carry
// no layer.
type UIImageLayer struct {
	Command string `json:"command"`
	Size    string `json:"size,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Empty   bool   `json:"empty,omitempty"`
}

// handleUIDetail returns details for a selected leaf. path is "module@version"
// for Go and a wheel filename for Python.
func (s *HighServer) handleUIDetail(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	var (
		detail UIDetail
		err    error
	)
	switch r.URL.Query().Get("eco") {
	case "python":
		detail, err = s.pythonDetail(path)
	case "maven":
		detail, err = s.mavenDetail(path)
	case "apt":
		detail, err = s.aptDetail(path)
	case "rpm":
		detail, err = s.rpmDetail(path)
	case "containers":
		detail, err = s.containerDetail(path)
	case "npm":
		detail, err = s.npmDetail(path)
	case "hf":
		detail, err = s.hfDetail(path)
	case "uploads":
		detail, err = s.uploadsDetail(path)
	default:
		detail, err = s.goDetail(path)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, detail)
}

func (s *HighServer) goDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid module@version")
	}
	module, version := spec[:i], spec[i+1:]
	moduleEsc, versionEsc := escapePathApprox(module), escapeVersionApprox(version)
	// The escape helpers only remap uppercase runes; they do not strip "/" or
	// "..", so validate before building any filesystem path (the other proxy
	// handlers do the same). Without this a spec like "../../etc@x" would escape
	// the module cache root.
	if err := validateRelPath(moduleEsc); err != nil {
		return UIDetail{}, errors.New("invalid module path")
	}
	if strings.ContainsRune(versionEsc, '/') || strings.Contains(versionEsc, "..") {
		return UIDetail{}, errors.New("invalid version")
	}
	base := filepath.Join(s.goModuleDir(), filepath.FromSlash(moduleEsc), "@v")
	if !safeJoin(s.goModuleDir(), base) {
		return UIDetail{}, errors.New("unsafe path")
	}
	if !s.isComplete(moduleEsc, versionEsc) {
		return UIDetail{}, errors.New("version not found")
	}

	fields := []UIDetailField{
		{Label: "Module", Value: module, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	if t := goInfoTime(filepath.Join(base, versionEsc+".info")); t != "" {
		fields = append(fields, UIDetailField{Label: "Published", Value: t})
	}
	if st, err := os.Stat(filepath.Join(base, versionEsc+".zip")); err == nil {
		fields = append(fields, UIDetailField{Label: "Zip size", Value: formatBytes(st.Size())})
	}
	if sum, err := sha256File(filepath.Join(base, versionEsc+".zip")); err == nil {
		fields = append(fields, UIDetailField{Label: "Zip SHA-256", Value: sum, Mono: true})
	}
	fields = append(fields, UIDetailField{Label: "Proxy path", Value: "/go/" + moduleEsc + "/@v/" + versionEsc + ".zip", Mono: true})

	goMod, _ := os.ReadFile(filepath.Join(base, versionEsc+".mod"))
	return UIDetail{Title: module, Subtitle: version, Fields: fields, GoMod: string(goMod)}, nil
}

func goInfoTime(infoPath string) string {
	b, err := os.ReadFile(infoPath)
	if err != nil {
		return ""
	}
	var mi ModuleInfo
	if json.Unmarshal(b, &mi) != nil || mi.Time.IsZero() {
		return ""
	}
	return mi.Time.UTC().Format(time.RFC3339)
}

func (s *HighServer) pythonDetail(filename string) (UIDetail, error) {
	if filename == "" || strings.ContainsRune(filename, '/') {
		return UIDetail{}, errors.New("invalid filename")
	}
	abs := filepath.Join(s.pythonDir(), filename)
	if !safeJoin(s.pythonDir(), abs) {
		return UIDetail{}, errors.New("unsafe path")
	}
	st, err := os.Stat(abs)
	if err != nil {
		return UIDetail{}, errors.New("wheel not found")
	}
	project, version, _ := parseWheelFilename(filename)
	fields := []UIDetailField{
		{Label: "Filename", Value: filename, Mono: true},
		{Label: "Version", Value: version},
		{Label: "Size", Value: formatBytes(st.Size())},
		{Label: "Download", Value: "/packages/" + filename, Mono: true},
	}
	if sum, err := sha256File(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	title := project
	if title == "" {
		title = filename
	}
	return UIDetail{Title: title, Subtitle: version, Fields: fields}, nil
}

// formatBytes renders a byte count in human-readable units.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
