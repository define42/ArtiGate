package main

// High-side dashboard UI. A self-contained page (no external assets, so it works
// air-gapped) served at "/", backed by a JSON overview endpoint. It shows import
// status — prominently flagging any missing bundles — and a tree of every
// mirrored Go module and Python project. The front-end is written in TypeScript
// (ui/app.ts); its compiled output (ui/app.js) is embedded below. Rebuild it
// with `make ui`.

import (
	_ "embed"
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
	mu     sync.Mutex
	expiry time.Time
	mods   []UIModule
	python []UIProject
}

func (s *HighServer) serveUI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/", "/ui", "/ui/":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		writeHTML(w, uiIndexHTML)
	case "/ui/app.js":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
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

// handleUITree returns the immediate children of a node in a package tree.
// eco selects the ecosystem ("go" or "python"); path is the parent node's path
// (empty for the tree root).
func (s *HighServer) handleUITree(w http.ResponseWriter, r *http.Request) {
	eco := r.URL.Query().Get("eco")
	path := r.URL.Query().Get("path")

	mods, python, err := s.cachedLists()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var nodes []UITreeNode
	if eco == "python" {
		nodes = pythonTreeChildren(python, path)
	} else {
		nodes = goTreeChildren(mods, path)
	}
	writeJSON(w, map[string][]UITreeNode{"nodes": nodes})
}

// cachedLists returns the mirrored Go modules and Python projects, memoized for
// a few seconds so a burst of lazy expand requests reuses one scan.
func (s *HighServer) cachedLists() ([]UIModule, []UIProject, error) {
	s.tree.mu.Lock()
	defer s.tree.mu.Unlock()
	if time.Now().Before(s.tree.expiry) {
		return s.tree.mods, s.tree.python, nil
	}
	mods, err := s.listGoModules()
	if err != nil {
		return nil, nil, err
	}
	python, err := s.listPythonProjects()
	if err != nil {
		return nil, nil, err
	}
	s.tree.mods = mods
	s.tree.python = python
	s.tree.expiry = time.Now().Add(3 * time.Second)
	return mods, python, nil
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

// listGoModules walks the module cache and returns every module that has at
// least one complete version, with its versions sorted ascending.
func (s *HighServer) listGoModules() ([]UIModule, error) {
	var mods []UIModule
	err := filepath.WalkDir(s.downloadDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || d.Name() != "@v" {
			return nil
		}
		rel, relErr := filepath.Rel(s.downloadDir, filepath.Dir(p))
		if relErr != nil {
			return nil
		}
		moduleEsc := filepath.ToSlash(rel)
		if moduleEsc == "python" || strings.HasPrefix(moduleEsc, "python/") {
			return filepath.SkipDir
		}
		if mod, ok := s.goModuleAt(moduleEsc); ok {
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
