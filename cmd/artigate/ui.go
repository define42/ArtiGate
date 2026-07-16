package main

// High-side dashboard UI. A self-contained page (no external assets, so it works
// air-gapped) served at "/", backed by a JSON overview endpoint. It shows import
// status — prominently flagging any missing bundles — a tree of every mirrored
// package, and a cross-ecosystem package search (/ui/api/search). The front-end
// is written in TypeScript (ui/app.ts); its compiled output (ui/app.js) is
// embedded below. Rebuild it with `make ui`.

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
	mu     sync.Mutex
	expiry time.Time
	trees  map[string]uiTree
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
	default:
		return s.serveUIAPI(w, r)
	}
	return true
}

// serveUIAPI routes the dashboard's read-only JSON endpoints (/ui/api/*). It
// reports whether it wrote a response for the request.
func (s *HighServer) serveUIAPI(w http.ResponseWriter, r *http.Request) bool {
	var handle func(http.ResponseWriter, *http.Request)
	switch r.URL.Path {
	case "/ui/api/overview":
		handle = func(w http.ResponseWriter, _ *http.Request) { s.handleUIOverview(w) }
	case "/ui/api/tree":
		handle = s.handleUITree
	case "/ui/api/detail":
		handle = s.handleUIDetail
	case "/ui/api/repos":
		handle = s.handleUIRepos
	case "/ui/api/search":
		handle = s.handleUISearch
	default:
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	handle(w, r)
	return true
}

func isReadMethod(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

func (s *HighServer) handleUIOverview(w http.ResponseWriter) {
	// Read-only: this endpoint is unauthenticated and polled by every open
	// dashboard, so it must not run the quarantine sweep (which moves files and
	// fires webhooks). The background import loop and diode kick own that sweep.
	status, err := s.importStatusReadOnly()
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
	eco, ok := ecosystemFor(r.URL.Query().Get("eco"))
	if !ok || eco.repoList == nil {
		http.Error(w, "repos are only available for "+joinWithAnd(repoListStreams()), http.StatusBadRequest)
		return
	}
	repos, err := eco.repoList(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, UIReposResponse{Repos: repos})
}

// repoListStreams names the streams whose ecosystems publish a repository
// list for the "Set me up" guide.
func repoListStreams() []string {
	var out []string
	for _, e := range ecosystems() {
		if e.repoList != nil {
			out = append(out, e.stream)
		}
	}
	return out
}

// joinWithAnd renders a list as prose: "a", "a and b", "a, b, and c".
func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

// handleUITree returns the immediate children of a node in a package tree.
// eco selects the ecosystem ("go" or "python"); path is the parent node's path
// (empty for the tree root).
func (s *HighServer) handleUITree(w http.ResponseWriter, r *http.Request) {
	eco := r.URL.Query().Get("eco")
	path := r.URL.Query().Get("path")

	trees, err := s.cachedTrees()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string][]UITreeNode{"nodes": ecoTreeChildren(trees, eco, path)})
}

// ecoTreeChildren renders one node's children from an ecosystem's scanned
// tree. An unknown eco key keeps rendering the Go tree, as it did before the
// dashboard grew per-ecosystem views.
func ecoTreeChildren(trees map[string]uiTree, eco, path string) []UITreeNode {
	if t, ok := trees[eco]; ok {
		return t.children(path)
	}
	return trees[streamGo].children(path)
}

// uiTree is one ecosystem's scanned dashboard inventory; it renders the
// immediate children of a node in the lazily-loaded package tree, and searches
// its package names for the dashboard's cross-ecosystem search. The concrete
// shape is the tree builder the ecosystem's names call for: slash-separated
// names (Go modules, Maven coordinates, mirror/package keys, terraform
// addresses) use segmentTree; flat names (npm — a scope is part of the name —
// crates, nuget) use the two-level flatTree; Python wheels and uploaded
// folders have trees of their own.
type uiTree interface {
	children(path string) []UITreeNode
	// search returns the nodes whose package name contains query
	// (case-insensitively), capped at limit, plus the total match count.
	// Hits carry their canonical tree path, so the dashboard expands and
	// selects them exactly like nodes browsed to by hand.
	search(query string, limit int) ([]UITreeNode, int)
}

type (
	segmentTree []UIModule
	flatTree    []UIModule
	pythonTree  []UIProject
	uploadsTree []UploadedFolder
)

func (t segmentTree) children(path string) []UITreeNode { return goTreeChildren(t, path) }
func (t flatTree) children(path string) []UITreeNode    { return npmTreeChildren(t, path) }
func (t pythonTree) children(path string) []UITreeNode  { return pythonTreeChildren(t, path) }
func (t uploadsTree) children(path string) []UITreeNode { return uploadsTreeChildren(t, path) }

func (t segmentTree) search(query string, limit int) ([]UITreeNode, int) {
	return searchModules(t, query, limit)
}

func (t flatTree) search(query string, limit int) ([]UITreeNode, int) {
	return searchModules(t, query, limit)
}

func (t pythonTree) search(query string, limit int) ([]UITreeNode, int) {
	h := newSearchHits(query, limit)
	for _, p := range t {
		h.add(p.Project, UITreeNode{Label: p.Project, Path: p.Project, Kind: "project", Expandable: true, Count: len(p.Files)})
	}
	return h.nodes, h.total
}

// search on the uploads tree matches folder names and file names; a file hit
// is a selectable leaf labeled with its folder so same-named files in
// different folders stay distinguishable.
func (t uploadsTree) search(query string, limit int) ([]UITreeNode, int) {
	h := newSearchHits(query, limit)
	for _, f := range t {
		h.add(f.Folder, UITreeNode{Label: f.Folder, Path: f.Folder, Kind: "project", Expandable: true, Count: len(f.Files)})
		for _, file := range f.Files {
			leaf := f.Folder + "/" + file.Name
			h.add(file.Name, UITreeNode{Label: leaf, Path: leaf, Kind: "file"})
		}
	}
	return h.nodes, h.total
}

// searchModules searches both module-shaped trees (segmentTree, flatTree): a
// hit is the module's own tree node, so expanding it lazily loads its versions.
func searchModules(mods []UIModule, query string, limit int) ([]UITreeNode, int) {
	h := newSearchHits(query, limit)
	for _, m := range mods {
		h.add(m.Module, UITreeNode{Label: m.Module, Path: m.Module, Kind: "module", Expandable: true, Count: len(m.Versions)})
	}
	return h.nodes, h.total
}

// searchHits accumulates matching tree nodes up to a cap while counting every
// match, so a search response stays bounded but still reports the full total.
type searchHits struct {
	query string // lowercased once; matching lowercases each candidate
	limit int
	nodes []UITreeNode
	total int
}

func newSearchHits(query string, limit int) *searchHits {
	return &searchHits{query: strings.ToLower(query), limit: limit}
}

// add records node as a hit when name contains the query case-insensitively.
func (h *searchHits) add(name string, node UITreeNode) {
	if !strings.Contains(strings.ToLower(name), h.query) {
		return
	}
	h.total++
	if len(h.nodes) < h.limit {
		h.nodes = append(h.nodes, node)
	}
}

// cachedTrees returns the mirrored inventory across ecosystems, memoized for a
// few seconds so a burst of lazy expand requests reuses one scan.
func (s *HighServer) cachedTrees() (map[string]uiTree, error) {
	s.tree.mu.Lock()
	defer s.tree.mu.Unlock()
	if time.Now().Before(s.tree.expiry) {
		return s.tree.trees, nil
	}
	fresh, err := s.scanEcoTrees()
	if err != nil {
		return nil, err
	}
	s.tree.trees = fresh
	s.tree.expiry = time.Now().Add(3 * time.Second)
	return fresh, nil
}

// scanEcoTrees walks every registered ecosystem's repository tree once.
func (s *HighServer) scanEcoTrees() (map[string]uiTree, error) {
	ecos := ecosystems()
	trees := make(map[string]uiTree, len(ecos))
	for _, e := range ecos {
		t, err := e.scanTree(s)
		if err != nil {
			return nil, err
		}
		trees[e.stream] = t
	}
	return trees, nil
}

// -----------------------------------------------------------------------------
// Cross-ecosystem package search
// -----------------------------------------------------------------------------

const (
	// maxUISearchQueryLen bounds the untrusted search query; nothing longer
	// than a real package name is worth scanning the inventory for.
	maxUISearchQueryLen = 200
	// uiSearchHitLimit caps how many matching nodes one ecosystem contributes
	// to a search response; Total still reports the full match count so the
	// dashboard can say "first N of M".
	uiSearchHitLimit = 20
)

// UISearchGroup is one ecosystem's matches in a search response: its first
// uiSearchHitLimit matching tree nodes plus the total match count.
type UISearchGroup struct {
	Eco   string       `json:"eco"`
	Label string       `json:"label"`
	Total int          `json:"total"`
	Nodes []UITreeNode `json:"nodes"`
}

// UISearchResponse is the body of GET /ui/api/search.
type UISearchResponse struct {
	Query  string          `json:"query"`
	Groups []UISearchGroup `json:"groups"`
}

// handleUISearch searches every ecosystem's mirrored inventory for package
// names containing q (case-insensitively), so the dashboard can find a package
// without knowing its ecosystem. Groups follow registry order — the sidebar's
// stream order — and an empty query returns no groups rather than everything.
func (s *HighServer) handleUISearch(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) > maxUISearchQueryLen {
		http.Error(w, "query too long", http.StatusBadRequest)
		return
	}
	resp := UISearchResponse{Query: query, Groups: []UISearchGroup{}}
	if query == "" {
		writeJSON(w, resp)
		return
	}
	trees, err := s.cachedTrees()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, e := range ecosystems() {
		tree, ok := trees[e.stream]
		if !ok {
			continue
		}
		nodes, total := tree.search(query, uiSearchHitLimit)
		if total == 0 {
			continue
		}
		resp.Groups = append(resp.Groups, UISearchGroup{Eco: e.stream, Label: e.title, Total: total, Nodes: nodes})
	}
	writeJSON(w, resp)
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
	// CloneURL, when set (git mirrors), is a host-relative repository path
	// ("git/<name>.git"); the dashboard prepends its own origin — scheme and
	// host known only client-side, honoring any reverse proxy — and renders a
	// copyable "git clone <origin>/git/<name>.git" command, so the operator
	// gets a full URL rather than a root-relative path.
	CloneURL string `json:"clone_url,omitempty"`
	// Downloads are the artifact files behind the selected leaf, rendered as
	// direct-download buttons. Empty when the leaf is not a plain file
	// (container images and full HF repository snapshots are consumed through
	// their registry/Hub protocols instead).
	Downloads []UIDownload `json:"downloads,omitempty"`
	// Layers is a container image's build-history breakdown (the command each
	// step ran, and the filesystem layer it produced), rendered as a box below
	// the detail panel. Empty for non-container leaves.
	Layers []UIImageLayer `json:"layers,omitempty"`
}

// UIDownload is one direct-download button in the detail panel: the artifact's
// host-relative URL (the same path clients fetch) and the filename the browser
// should save it as.
type UIDownload struct {
	Label string `json:"label"`
	URL   string `json:"url"`
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

// detailDigestCache memoizes artifact SHA-256 digests for the dashboard's
// detail panel. /ui/api/detail is unauthenticated and nearly every
// ecosystem's hook shows the selected artifact's digest; recomputing it per
// request would be O(artifact bytes) per hit, so repeated GETs against the
// largest mirrored artifact (an unbounded upload, a multi-GB zip) could
// saturate the host. An artifact is immutable once imported and only ever
// replaced atomically, so (size, modtime) is a sound key: any content change
// moves at least one of them, and a mismatch re-hashes. (Same pattern as
// pyDigestCache, which additionally memoizes wheel metadata.)
type detailDigestCache struct {
	mu      sync.Mutex
	entries map[string]detailDigestEntry
}

type detailDigestEntry struct {
	size    int64
	modTime time.Time
	sha256  string
}

// get returns the file's cached SHA-256, recomputing it only when the file is
// new or its size/modtime changed since last seen.
func (c *detailDigestCache) get(abs string) (string, error) {
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if e, ok := c.entries[abs]; ok && e.size == fi.Size() && e.modTime.Equal(fi.ModTime()) {
		c.mu.Unlock()
		return e.sha256, nil
	}
	c.mu.Unlock()

	sum, err := sha256File(abs)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]detailDigestEntry)
	}
	c.entries[abs] = detailDigestEntry{size: fi.Size(), modTime: fi.ModTime(), sha256: sum}
	c.mu.Unlock()
	return sum, nil
}

// handleUIDetail returns details for a selected leaf. path is "module@version"
// for Go and a wheel filename for Python. An unknown eco key keeps describing
// Go modules, as it did before the dashboard grew per-ecosystem views.
func (s *HighServer) handleUIDetail(w http.ResponseWriter, r *http.Request) {
	describe := (*HighServer).goDetail
	if e, ok := ecosystemFor(r.URL.Query().Get("eco")); ok {
		describe = e.detail
	}
	detail, err := describe(s, r.URL.Query().Get("path"))
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
	if sum, err := s.detailDigests.get(filepath.Join(base, versionEsc+".zip")); err == nil {
		fields = append(fields, UIDetailField{Label: "Zip SHA-256", Value: sum, Mono: true})
	}
	fields = append(fields, UIDetailField{Label: "Proxy path", Value: "/go/" + moduleEsc + "/@v/" + versionEsc + ".zip", Mono: true})

	goMod, _ := os.ReadFile(filepath.Join(base, versionEsc+".mod"))
	downloads := []UIDownload{{Label: version + ".zip", URL: "/go/" + moduleEsc + "/@v/" + versionEsc + ".zip"}}
	return UIDetail{Title: module, Subtitle: version, Fields: fields, GoMod: string(goMod), Downloads: downloads}, nil
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
	// The wheel's digest comes from the same cache the /simple project pages
	// use, so a wheel is hashed at most once across both endpoints.
	if sum, _, err := s.pyDigests.get(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	title := project
	if title == "" {
		title = filename
	}
	downloads := []UIDownload{{Label: filename, URL: "/packages/" + filename}}
	return UIDetail{Title: title, Subtitle: version, Fields: fields, Downloads: downloads}, nil
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
