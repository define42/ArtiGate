package main

// Helm classic-repository ecosystem adapter. The low side fetches a repo's
// index.yaml, picks the requested charts, downloads the .tgz archives —
// verifying each against the index-declared digest when the index carries one
// — and packs them into the same numbered, signed ArtiGate bundle format used
// by the other ecosystems. The high side regenerates a repository of its own
// per mirror — index.yaml built from each chart archive's embedded Chart.yaml
// (never trusting a transferred index) — and serves it with the chart
// archives, so `helm repo add` works against <base>/helm/<mirror>.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// helmEcosystem is the Helm chart stream's registry entry (see ecosystems in
// ecosystem.go).
func helmEcosystem() ecosystem {
	return ecosystem{
		stream:          streamHelm,
		label:           "Helm",
		title:           "Helm charts",
		collect:         (*LowServer).HandleHelmCollect,
		watchCollect:    watchAdapter((*LowServer).CollectHelm),
		manifestContent: func(m BundleManifest) bool { return m.Helm != nil && len(m.Helm.Repos) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateHelmRepos(m.Helm.Repos, seen)
		},
		contentDesc: "helm charts",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishHelm(m.Helm) },
		serve:       (*HighServer).serveHelm,
		scanTree:    segmentTreeScan((*HighServer).listHelmCharts),
		detail:      (*HighServer).helmDetail,
	}
}

// helmMaxChartYAMLBytes caps one Chart.yaml parsed from a chart archive.
const helmMaxChartYAMLBytes = 8 << 20

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type HelmManifest struct {
	Repos []HelmRepo `json:"repos"`
}

// HelmRepo is one mirrored chart repository (named like an APT mirror, so
// several upstreams can coexist under /helm/<name>).
type HelmRepo struct {
	Name   string      `json:"name"`
	URL    string      `json:"url"`
	Charts []HelmChart `json:"charts"`
}

type HelmChart struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// helmChartNameRE matches a path-safe chart name. The first character excludes
// ".", "_", and "-" so a name can never be ".."/"-flag".
var helmChartNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validateHelmChartName(name string) error {
	if !helmChartNameRE.MatchString(name) {
		return fmt.Errorf("invalid chart name %q", name)
	}
	return nil
}

// helmVersionRE matches a chart version: semver, optionally "v"-prefixed like
// many repos publish. Always starts alphanumeric, so it is path-safe.
var helmVersionRE = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.+-]*$`)

func validateHelmVersion(v string) error {
	if !helmVersionRE.MatchString(v) {
		return fmt.Errorf("invalid chart version %q", v)
	}
	return nil
}

// helmChartFilename is the canonical archive name a mirrored chart is stored
// under, whatever the upstream download URL looked like.
func helmChartFilename(name, version string) string {
	return name + "-" + version + ".tgz"
}

// helmChartRel is the repository-relative path of one chart archive.
func helmChartRel(mirror, filename string) string {
	return path.Join("helm", mirror, "charts", filename)
}

// validateHelmChart checks one manifest chart record: path-safe identity, the
// canonical storage path, and that the referenced file is listed.
func validateHelmChart(mirror string, c HelmChart, seen map[string]bool) error {
	if err := validateHelmChartName(c.Name); err != nil {
		return err
	}
	if err := validateHelmVersion(c.Version); err != nil {
		return fmt.Errorf("chart %s: %w", c.Name, err)
	}
	if c.Filename != helmChartFilename(c.Name, c.Version) {
		return fmt.Errorf("chart %s@%s has non-canonical filename %s", c.Name, c.Version, c.Filename)
	}
	if c.Path != helmChartRel(mirror, c.Filename) || !seen[c.Path] {
		return fmt.Errorf("chart %s@%s references file not listed in manifest.files: %s", c.Name, c.Version, c.Path)
	}
	return nil
}

// validateHelmRepos checks every repo of a bundle manifest: safe mirror names
// and complete chart file references.
func validateHelmRepos(repos []HelmRepo, seen map[string]bool) error {
	for _, repo := range repos {
		if err := validateMirrorName(repo.Name); err != nil {
			return err
		}
		if repo.URL == "" {
			return fmt.Errorf("helm repo %s has no url", repo.Name)
		}
		if len(repo.Charts) == 0 {
			return fmt.Errorf("helm repo %s has no charts", repo.Name)
		}
		for _, c := range repo.Charts {
			if err := validateHelmChart(repo.Name, c, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: repository serving
// -----------------------------------------------------------------------------

func (s *HighServer) helmDir() string {
	return filepath.Join(s.downloadDir, "helm")
}

// serveHelm handles the Helm repository routes under /helm/<mirror>/: the
// regenerated index.yaml and the chart archives. It reports whether it wrote a
// response for the request.
func (s *HighServer) serveHelm(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/helm" && !strings.HasPrefix(p, "/helm/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.Trim(strings.TrimPrefix(p, "/helm"), "/")
	if validateRelPath(rel) != nil || !helmServablePath(rel) {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.helmDir(), filepath.FromSlash(rel))
	if !safeJoin(s.helmDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	if strings.HasSuffix(rel, "/index.yaml") {
		w.Header().Set("Content-Type", "application/yaml")
	}
	serveFile(w, r, abs)
	return true
}

// helmServablePath restricts the served tree to the two client-facing shapes:
// <mirror>/index.yaml and <mirror>/charts/<file>.tgz. The regenerated metadata
// store stays private.
func helmServablePath(rel string) bool {
	segs := strings.Split(rel, "/")
	switch {
	case len(segs) == 2 && segs[1] == "index.yaml":
		return validateMirrorName(segs[0]) == nil
	case len(segs) == 3 && segs[1] == "charts" && strings.HasSuffix(segs[2], ".tgz"):
		return validateMirrorName(segs[0]) == nil
	}
	return false
}

// -----------------------------------------------------------------------------
// High side: index regeneration at import
// -----------------------------------------------------------------------------

// helmStoredChart is the per-version metadata the high side regenerates at
// import time from the chart archive's own embedded Chart.yaml (plus the
// digest it computes from the artifact bytes). index.yaml is assembled from
// these.
type helmStoredChart struct {
	Filename string         `json:"filename"`
	Digest   string         `json:"digest"`
	Metadata map[string]any `json:"metadata"`
}

// publishHelm regenerates the served repository for every mirror in an
// imported bundle. A chart whose archive cannot be parsed is logged and
// skipped (it stays out of index.yaml) rather than wedging the stream's
// import forever.
// publishHelm regenerates index.yaml from each chart's own embedded
// Chart.yaml (never trusting a transferred repository index).
func (s *HighServer) publishHelm(m *HelmManifest) error {
	if m == nil {
		return nil
	}
	for _, repo := range m.Repos {
		if err := s.publishHelmRepo(repo); err != nil {
			return err
		}
	}
	return nil
}

func (s *HighServer) publishHelmRepo(repo HelmRepo) error {
	if err := validateMirrorName(repo.Name); err != nil {
		return err
	}
	for _, c := range repo.Charts {
		if err := s.publishHelmChart(repo.Name, c); err != nil {
			log.Printf("helm publish %s/%s@%s: %v", repo.Name, c.Name, c.Version, err)
		}
	}
	return s.regenerateHelmIndex(repo.Name)
}

// publishHelmChart regenerates one chart's stored metadata from the archive's
// embedded Chart.yaml.
func (s *HighServer) publishHelmChart(mirror string, c HelmChart) error {
	if err := validateHelmChartName(c.Name); err != nil {
		return err
	}
	if err := validateHelmVersion(c.Version); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(c.Path))
	if !strings.HasPrefix(c.Path, "helm/") || !safeJoin(s.helmDir(), abs) {
		return fmt.Errorf("unsafe chart path %s", c.Path)
	}
	meta, err := extractChartYAML(abs)
	if err != nil {
		return err
	}
	if name, _ := meta["name"].(string); name != c.Name {
		return fmt.Errorf("embedded Chart.yaml names %q", meta["name"])
	}
	if version, _ := meta["version"].(string); version != c.Version {
		return fmt.Errorf("embedded Chart.yaml version is %q", meta["version"])
	}
	digest, err := sha256File(abs)
	if err != nil {
		return err
	}
	st := helmStoredChart{Filename: c.Filename, Digest: digest, Metadata: meta}
	out := filepath.Join(s.helmDir(), mirror, "metadata", c.Name+"-"+c.Version+".json")
	if !safeJoin(s.helmDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s@%s", c.Name, c.Version)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// extractChartYAML reads the Chart.yaml embedded in a chart archive (helm
// requires <chart>/Chart.yaml at depth one) into a JSON-compatible map.
func extractChartYAML(tgzPath string) (map[string]any, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("archive has no Chart.yaml")
		}
		if err != nil {
			return nil, err
		}
		parts := strings.Split(path.Clean(strings.TrimPrefix(hdr.Name, "./")), "/")
		if hdr.Typeflag != tar.TypeReg || len(parts) != 2 || parts[1] != "Chart.yaml" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, helmMaxChartYAMLBytes))
		if err != nil {
			return nil, err
		}
		return parseChartYAML(b)
	}
}

// parseChartYAML decodes Chart.yaml, requiring a JSON-compatible result (the
// stored metadata and the packument-style detail views are JSON).
func parseChartYAML(b []byte) (map[string]any, error) {
	meta := map[string]any{}
	if err := yaml.Unmarshal(b, &meta); err != nil {
		return nil, fmt.Errorf("parse Chart.yaml: %w", err)
	}
	if _, err := json.Marshal(meta); err != nil {
		return nil, fmt.Errorf("Chart.yaml is not JSON-compatible: %w", err)
	}
	return meta, nil
}

// helmIndex is the served index.yaml document.
type helmIndex struct {
	APIVersion string                      `yaml:"apiVersion"`
	Generated  string                      `yaml:"generated"`
	Entries    map[string][]map[string]any `yaml:"entries"`
}

// regenerateHelmIndex rebuilds one mirror's index.yaml from the accumulated
// stored chart metadata, listing only charts whose archive is present.
func (s *HighServer) regenerateHelmIndex(mirror string) error {
	entries, err := s.helmIndexEntries(mirror)
	if err != nil {
		return err
	}
	idx := helmIndex{
		APIVersion: "v1",
		Generated:  time.Now().UTC().Format(time.RFC3339),
		Entries:    entries,
	}
	b, err := yaml.Marshal(idx)
	if err != nil {
		return err
	}
	return writeBytesAtomic(filepath.Join(s.helmDir(), mirror, "index.yaml"), b, 0o644)
}

// helmIndexEntries assembles the index entries per chart name from the stored
// metadata, newest version first like helm's own generated indexes.
func (s *HighServer) helmIndexEntries(mirror string) (map[string][]map[string]any, error) {
	metaDir := filepath.Join(s.helmDir(), mirror, "metadata")
	files, err := os.ReadDir(metaDir)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries := map[string][]map[string]any{}
	for _, e := range files {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name, entry, ok := s.helmIndexEntry(mirror, filepath.Join(metaDir, e.Name()))
		if ok {
			entries[name] = append(entries[name], entry)
		}
	}
	for name := range entries {
		sortHelmEntries(entries[name])
	}
	return entries, nil
}

// helmIndexEntry renders one stored chart into an index.yaml entry, gated on
// its archive still being present.
func (s *HighServer) helmIndexEntry(mirror, metaPath string) (string, map[string]any, bool) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return "", nil, false
	}
	var st helmStoredChart
	if json.Unmarshal(b, &st) != nil || st.Filename == "" || strings.ContainsRune(st.Filename, '/') {
		return "", nil, false
	}
	abs := filepath.Join(s.helmDir(), mirror, "charts", st.Filename)
	fi, err := os.Stat(abs)
	if err != nil || !safeJoin(s.helmDir(), abs) {
		return "", nil, false
	}
	name, _ := st.Metadata["name"].(string)
	if validateHelmChartName(name) != nil {
		return "", nil, false
	}
	entry := make(map[string]any, len(st.Metadata)+3)
	for k, v := range st.Metadata {
		entry[k] = v
	}
	// Relative URLs resolve against the repo base, so the index needs no
	// absolute self-URL and survives being served under any host name.
	entry["urls"] = []string{"charts/" + st.Filename}
	entry["digest"] = st.Digest
	entry["created"] = fi.ModTime().UTC().Format(time.RFC3339)
	return name, entry, true
}

// sortHelmEntries orders one chart's index entries newest version first.
func sortHelmEntries(entries []map[string]any) {
	version := func(m map[string]any) string {
		v, _ := m["version"].(string)
		return "v" + strings.TrimPrefix(v, "v")
	}
	sort.Slice(entries, func(i, j int) bool {
		return compareVersions(version(entries[i]), version(entries[j])) > 0
	})
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listHelmCharts lists the mirrored charts as "<mirror>/<chart>" with their
// versions, from the regenerated metadata store.
func (s *HighServer) listHelmCharts() ([]UIModule, error) {
	mirrors, err := os.ReadDir(s.helmDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byChart := map[string][]string{}
	for _, m := range mirrors {
		if !m.IsDir() || validateMirrorName(m.Name()) != nil {
			continue
		}
		s.collectHelmMirrorCharts(m.Name(), byChart)
	}
	out := make([]UIModule, 0, len(byChart))
	for chart, versions := range byChart {
		sort.Slice(versions, func(i, j int) bool { return helmVersionLess(versions[i], versions[j]) })
		out = append(out, UIModule{Module: chart, Versions: versions})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

func (s *HighServer) collectHelmMirrorCharts(mirror string, byChart map[string][]string) {
	entries, err := os.ReadDir(filepath.Join(s.helmDir(), mirror, "metadata"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		st, err := s.readHelmStored(mirror, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		name, _ := st.Metadata["name"].(string)
		version, _ := st.Metadata["version"].(string)
		if validateHelmChartName(name) != nil || validateHelmVersion(version) != nil {
			continue
		}
		key := mirror + "/" + name
		byChart[key] = append(byChart[key], version)
	}
}

// readHelmStored loads one chart's stored metadata by its "<name>-<version>"
// stem and checks the archive is still present.
func (s *HighServer) readHelmStored(mirror, stem string) (helmStoredChart, error) {
	p := filepath.Join(s.helmDir(), mirror, "metadata", stem+".json")
	if !safeJoin(s.helmDir(), p) {
		return helmStoredChart{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return helmStoredChart{}, err
	}
	var st helmStoredChart
	if err := json.Unmarshal(b, &st); err != nil {
		return helmStoredChart{}, err
	}
	if st.Filename == "" || strings.ContainsRune(st.Filename, '/') {
		return helmStoredChart{}, errors.New("invalid stored filename")
	}
	abs := filepath.Join(s.helmDir(), mirror, "charts", st.Filename)
	if !safeJoin(s.helmDir(), abs) || !fileExists(abs) {
		return helmStoredChart{}, errors.New("chart archive missing")
	}
	return st, nil
}

// helmDetail describes one mirrored chart version for the dashboard detail
// panel. spec is "<mirror>/<chart>@<version>".
func (s *HighServer) helmDetail(spec string) (UIDetail, error) {
	addr, version, ok := strings.Cut(spec, "@")
	mirror, chart, ok2 := strings.Cut(addr, "/")
	if !ok || !ok2 || validateMirrorName(mirror) != nil ||
		validateHelmChartName(chart) != nil || validateHelmVersion(version) != nil {
		return UIDetail{}, errors.New("invalid mirror/chart@version")
	}
	st, err := s.readHelmStored(mirror, chart+"-"+version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Chart", Value: chart, Mono: true},
		{Label: "Version", Value: version, Mono: true},
		{Label: "Repository", Value: "/helm/" + mirror, Mono: true},
	}
	for _, key := range []string{"appVersion", "description", "apiVersion"} {
		if v, _ := st.Metadata[key].(string); v != "" {
			fields = append(fields, UIDetailField{Label: key, Value: v})
		}
	}
	abs := filepath.Join(s.helmDir(), mirror, "charts", st.Filename)
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Archive size", Value: formatBytes(fi.Size())})
	}
	fields = append(fields, UIDetailField{Label: "Digest", Value: st.Digest, Mono: true})
	downloads := []UIDownload{{Label: st.Filename, URL: "/helm/" + mirror + "/charts/" + st.Filename}}
	return UIDetail{Title: chart, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// Low side: chart collector
// -----------------------------------------------------------------------------

// HelmCollectRequest is the body of POST /admin/helm/collect.
//
// URL is the upstream chart repository (the URL `helm repo add` would use).
// Charts lists the charts to mirror: "name" for the newest version, or
// "name@1.2.3" to pin. Name optionally names the mirror under /helm/<name> on
// the high side; it defaults to a slug of the URL.
type HelmCollectRequest struct {
	Name   string   `json:"name,omitempty"`
	URL    string   `json:"url"`
	Charts []string `json:"charts"`
	// Force disables export dedup for this collect: every chart is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseHelmChartSpec splits "name" or "name@version".
func parseHelmChartSpec(spec string) (name, version string, err error) {
	name, version, _ = strings.Cut(spec, "@")
	if err := validateHelmChartName(name); err != nil {
		return "", "", err
	}
	if version != "" && version != "latest" {
		if err := validateHelmVersion(version); err != nil {
			return "", "", fmt.Errorf("chart %s: %w", name, err)
		}
		return name, version, nil
	}
	return name, "", nil
}

// validateHelmRequest checks the collect request and derives the mirror name.
func validateHelmRequest(req HelmCollectRequest) (mirror string, err error) {
	u, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("helm repo url %q must be an http(s) URL", req.URL)
	}
	if len(req.Charts) == 0 {
		return "", errors.New("no charts provided")
	}
	for _, spec := range req.Charts {
		if _, _, err := parseHelmChartSpec(spec); err != nil {
			return "", err
		}
	}
	mirror = req.Name
	if mirror == "" {
		mirror = aptMirrorName(req.URL)
	}
	if err := validateMirrorName(mirror); err != nil {
		return "", err
	}
	return mirror, nil
}

// HandleHelmCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandleHelmCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req HelmCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse helm collect request: %w", err)
		}
	}
	return s.CollectHelm(ctx, req)
}

// CollectHelm fetches the upstream repo index, downloads the requested chart
// archives (verifying the index digest when one is declared), and writes them
// into a signed bundle on the helm stream. Charts that cannot be resolved or
// fetched are skipped and reported so one of them never blocks the rest of
// the batch.
func (s *LowServer) CollectHelm(ctx context.Context, req HelmCollectRequest) (ExportResult, error) {
	mirror, err := validateHelmRequest(req)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the helm stream's lock for the whole fetch->write->commit so a
	// concurrent helm exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamHelm)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "helm", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	repoURL := strings.TrimSuffix(strings.TrimSpace(req.URL), "/")
	emitProgress(ctx, "Fetching %s/index.yaml…", repoURL)
	idx, err := fetchHelmIndex(ctx, repoURL)
	if err != nil {
		return ExportResult{}, err
	}
	charts, files, failed := s.downloadHelmCharts(ctx, stageRoot, mirror, repoURL, idx, req.Charts)
	if len(charts) == 0 {
		return ExportResult{}, fmt.Errorf("no charts could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	repo := HelmRepo{Name: mirror, URL: repoURL, Charts: charts}
	res, err := s.exportIfNew(ctx, streamHelm, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeHelmBundle(ctx, seq, stageRoot, files, repo)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// helmUpstreamEntry is the subset of an upstream index.yaml entry ArtiGate
// reads for resolution.
type helmUpstreamEntry struct {
	Name    string   `yaml:"name"`
	Version string   `yaml:"version"`
	Digest  string   `yaml:"digest"`
	URLs    []string `yaml:"urls"`
}

type helmUpstreamIndex struct {
	Entries map[string][]helmUpstreamEntry `yaml:"entries"`
}

// fetchHelmIndex downloads and parses the upstream repository index.
func fetchHelmIndex(ctx context.Context, repoURL string) (*helmUpstreamIndex, error) {
	b, err := httpGetBytes(ctx, repoURL+"/index.yaml", maxIndexFetchBytes)
	if err != nil {
		return nil, err
	}
	var idx helmUpstreamIndex
	if err := yaml.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("parse index.yaml: %w", err)
	}
	if len(idx.Entries) == 0 {
		return nil, errors.New("index.yaml lists no charts")
	}
	return &idx, nil
}

// downloadHelmCharts resolves and fetches every requested chart into the
// staging tree. A chart that cannot be resolved or downloaded is collected
// rather than aborting the batch.
func (s *LowServer) downloadHelmCharts(ctx context.Context, stageRoot, mirror, repoURL string, idx *helmUpstreamIndex, specs []string) ([]HelmChart, []ManifestFile, []FailedModule) {
	var charts []HelmChart
	var files []ManifestFile
	var failed []FailedModule
	seen := map[string]bool{}
	for i, spec := range specs {
		name, version, _ := parseHelmChartSpec(spec)
		emitProgress(ctx, "→ [%d/%d] %s@%s", i+1, len(specs), name, orDefault(version, "latest"))
		entry, err := selectHelmChart(idx, name, version)
		if err == nil && seen[entry.Name+"@"+entry.Version] {
			continue
		}
		var chart HelmChart
		var mf ManifestFile
		if err == nil {
			chart, mf, err = s.downloadHelmChart(ctx, stageRoot, mirror, repoURL, entry)
		}
		if err != nil {
			emitProgress(ctx, "  ✗ %s: %s", spec, err)
			failed = append(failed, FailedModule{Module: name, Version: orDefault(version, "latest"), Error: err.Error()})
			continue
		}
		seen[entry.Name+"@"+entry.Version] = true
		charts = append(charts, chart)
		files = append(files, mf)
	}
	return charts, files, failed
}

// selectHelmChart picks the index entry for a chart spec: the exact version,
// or the newest (stable preferred) when none is pinned.
func selectHelmChart(idx *helmUpstreamIndex, name, version string) (*helmUpstreamEntry, error) {
	entries := idx.Entries[name]
	if len(entries) == 0 {
		return nil, errors.New("chart not found in the repository index")
	}
	if version != "" {
		for i := range entries {
			if entries[i].Version == version && validateHelmVersion(version) == nil {
				return &entries[i], nil
			}
		}
		return nil, fmt.Errorf("version %s not found in the repository index", version)
	}
	if best := maxHelmEntry(entries, false); best != nil {
		return best, nil
	}
	if best := maxHelmEntry(entries, true); best != nil {
		return best, nil
	}
	return nil, errors.New("no usable version in the repository index")
}

// maxHelmEntry returns the entry with the highest version; pre selects between
// stable releases (false) and pre-releases (true).
func maxHelmEntry(entries []helmUpstreamEntry, pre bool) *helmUpstreamEntry {
	var best *helmUpstreamEntry
	for i := range entries {
		e := &entries[i]
		if e.Version == "" || validateHelmVersion(e.Version) != nil {
			continue
		}
		if (parseSemver("v"+strings.TrimPrefix(e.Version, "v")).pre != "") != pre {
			continue
		}
		if best == nil || helmVersionLess(best.Version, e.Version) {
			best = e
		}
	}
	return best
}

func helmVersionLess(a, b string) bool {
	return compareVersions("v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")) < 0
}

// downloadHelmChart fetches one chart archive, verifying the index digest when
// the index declares one (upstream indexes carry a plain or sha256-prefixed
// hex digest of the archive).
func (s *LowServer) downloadHelmChart(ctx context.Context, stageRoot, mirror, repoURL string, entry *helmUpstreamEntry) (HelmChart, ManifestFile, error) {
	dlURL, err := helmChartURL(repoURL, entry)
	if err != nil {
		return HelmChart{}, ManifestFile{}, err
	}
	filename := helmChartFilename(entry.Name, entry.Version)
	rel := helmChartRel(mirror, filename)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	digest := strings.TrimPrefix(strings.TrimSpace(entry.Digest), "sha256:")
	var sum string
	var size int64
	if digest != "" {
		sum, size, err = downloadVerifiedFile(ctx, dlURL, abs, 0, "sha256", digest)
	} else {
		// Some repositories publish no digest; integrity then rests on TLS to
		// the operator-configured upstream, like the other index-less fetches.
		sum, size, err = downloadFileSHA256(ctx, dlURL, abs)
	}
	if err != nil {
		return HelmChart{}, ManifestFile{}, err
	}
	chart := HelmChart{Name: entry.Name, Version: entry.Version, Filename: filename, Path: rel, SHA256: sum}
	return chart, ManifestFile{Path: rel, SHA256: sum, Size: size}, nil
}

// helmChartURL resolves a chart's download URL: the index's first URL, which
// may be absolute or relative to the repository base.
func helmChartURL(repoURL string, entry *helmUpstreamEntry) (string, error) {
	if len(entry.URLs) == 0 || strings.TrimSpace(entry.URLs[0]) == "" {
		return "", errors.New("index entry has no download URL")
	}
	base, err := url.Parse(repoURL + "/")
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(strings.TrimSpace(entry.URLs[0]))
	if err != nil {
		return "", fmt.Errorf("invalid chart URL: %w", err)
	}
	u := base.ResolveReference(ref)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("chart URL %q is not http(s)", u.String())
	}
	return u.String(), nil
}

// downloadFileSHA256 streams rawURL to abs with no upstream checksum to check
// against, returning the SHA-256 and size for the bundle manifest. Payloads
// are capped like every other mirrored file; on any failure the partial file
// is removed.
func downloadFileSHA256(ctx context.Context, rawURL, abs string) (string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", 0, err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	r := newProgressReader(ctx, resp.Body, dlNameFromURL(rawURL), resp.ContentLength)
	n, copyErr := io.Copy(io.MultiWriter(h, f), io.LimitReader(r, maxMirroredFileBytes+1))
	if err := errors.Join(copyErr, f.Close()); err != nil {
		_ = os.Remove(abs)
		return "", 0, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if n > maxMirroredFileBytes {
		_ = os.Remove(abs)
		return "", 0, fmt.Errorf("GET %s: response exceeds the %s cap", rawURL, formatBytes(maxMirroredFileBytes))
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeHelmBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, repo HelmRepo) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(repo.Charts, func(i, j int) bool {
		if repo.Charts[i].Name == repo.Charts[j].Name {
			return repo.Charts[i].Version < repo.Charts[j].Version
		}
		return repo.Charts[i].Name < repo.Charts[j].Name
	})
	id := bundleIDFor(streamHelm, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamHelm,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"helm"},
		Helm:             &HelmManifest{Repos: []HelmRepo{repo}},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamHelm, Sequence: seq, ExportedModules: len(repo.Charts), BundleID: id}, nil
}
