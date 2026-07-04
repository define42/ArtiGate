package main

// RPM (YUM/DNF) ecosystem adapter — full mirror mode for a single upstream
// repository, parallel to the APT adapter.
//
// Low side: fetch repodata/repomd.xml, optionally GPG-verify repomd.xml.asc
// against a caller-supplied key, read the primary metadata location + checksum,
// download and verify primary.xml(.gz/.xz), parse every <package> entry, then
// download every referenced .rpm and verify its SHA256 against the index. The
// .rpm files are packed into the standard signed ArtiGate bundle; each
// package's raw <package> XML block is stored in the manifest.
//
// High side: on import, regenerate primary.xml(.gz) and repomd.xml from the
// stored <package> blocks of the .rpm files actually present (never trusting
// the transferred metadata), optionally detach-signing repomd.xml.asc with a
// high-side key; the repository is then served as static files under /rpm/.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
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

type RpmManifest struct {
	Mirrors []RpmMirror `json:"mirrors"`
}

type RpmMirror struct {
	Name     string       `json:"name"`
	BaseURL  string       `json:"base_url"`
	GPGKey   string       `json:"gpg_key,omitempty"`
	Packages []RpmPackage `json:"packages"`
}

type RpmPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Location string `json:"location"` // href relative to the repo base, e.g. Packages/foo.rpm
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	XML      string `json:"xml"` // the raw <package> block, for high-side regeneration
}

// rpmFileRel returns the bundle/repository-relative path of a package's .rpm.
func rpmFileRel(mirror, location string) string {
	return path.Join("rpm", mirror, location)
}

// -----------------------------------------------------------------------------
// repomd.xml / primary.xml parsing
// -----------------------------------------------------------------------------

type rpmRepomd struct {
	Data []rpmRepomdData `xml:"data"`
}

type rpmRepomdData struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

type rpmPrimaryDoc struct {
	Packages []rpmPrimaryPackage `xml:"package"`
}

type rpmPrimaryPackage struct {
	Name    string `xml:"name"`
	Arch    string `xml:"arch"`
	Version struct {
		Epoch string `xml:"epoch,attr"`
		Ver   string `xml:"ver,attr"`
		Rel   string `xml:"rel,attr"`
	} `xml:"version"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Size struct {
		Package int64 `xml:"package,attr"`
	} `xml:"size"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

var rpmPackageBlockRE = regexp.MustCompile(`(?s)<package\b.*?</package>`)

// parseRpmPrimary parses a decompressed primary.xml into RpmPackage records,
// keeping each raw <package> block (matched in document order) for high-side
// regeneration.
func parseRpmPrimary(data []byte) ([]RpmPackage, error) {
	var doc rpmPrimaryDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse primary.xml: %w", err)
	}
	blocks := rpmPackageBlockRE.FindAllString(string(data), -1)
	if len(blocks) != len(doc.Packages) {
		return nil, fmt.Errorf("primary.xml package count mismatch: %d parsed, %d raw blocks", len(doc.Packages), len(blocks))
	}
	out := make([]RpmPackage, 0, len(doc.Packages))
	for i, p := range doc.Packages {
		version := p.Version.Ver
		if p.Version.Rel != "" {
			version += "-" + p.Version.Rel
		}
		out = append(out, RpmPackage{
			Name:     p.Name,
			Version:  version,
			Arch:     p.Arch,
			Location: p.Location.Href,
			SHA256:   strings.ToLower(strings.TrimSpace(p.Checksum.Value)),
			Size:     p.Size.Package,
			XML:      strings.TrimSpace(blocks[i]),
		})
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Low side: RPM mirror collector
// -----------------------------------------------------------------------------

// RpmCollectRequest is the body of POST /admin/rpm/collect. Provide either a
// .repo file (one or more [sections]) in RepoFile, or the fields explicitly.
type RpmCollectRequest struct {
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	GPGKey   string `json:"gpg_key"` // local keyring path for gpgv (optional)
	RepoFile string `json:"repo_file"`
}

type rpmMirrorConfig struct {
	Name    string
	BaseURL string
	GPGKey  string
}

func (s *LowServer) HandleRpmCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req RpmCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse rpm collect request: %w", err)
		}
	}
	return s.CollectRpm(ctx, req)
}

// CollectRpm mirrors one or more upstream RPM repositories into a signed bundle.
func (s *LowServer) CollectRpm(ctx context.Context, req RpmCollectRequest) (ExportResult, error) {
	configs, err := resolveRpmMirrors(req)
	if err != nil {
		return ExportResult{}, err
	}
	s.exportMu.Lock()
	defer s.exportMu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "rpm", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	var mirrors []RpmMirror
	var files []ManifestFile
	seenFile := map[string]bool{}
	for _, cfg := range configs {
		mirror, mf, err := s.mirrorRpmRepo(ctx, cfg, stageRoot)
		if err != nil {
			return ExportResult{}, err
		}
		for _, f := range mf {
			if !seenFile[f.Path] {
				files = append(files, f)
				seenFile[f.Path] = true
			}
		}
		mirrors = append(mirrors, mirror)
	}
	if len(files) == 0 {
		return ExportResult{}, errors.New("rpm mirror produced no packages")
	}

	seq := s.peekSequence()
	res, err := s.writeRpmBundle(seq, stageRoot, files, mirrors)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(seq); err != nil {
		return ExportResult{}, err
	}
	return res, nil
}

// mirrorRpmRepo downloads and verifies repomd, primary, and every .rpm for one
// mirror, staging the .rpm files under stageRoot.
func (s *LowServer) mirrorRpmRepo(ctx context.Context, cfg rpmMirrorConfig, stageRoot string) (RpmMirror, []ManifestFile, error) {
	base := strings.TrimRight(cfg.BaseURL, "/")

	pkgs, err := s.fetchRpmPrimary(ctx, base, cfg.GPGKey)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	mirror := RpmMirror{Name: cfg.Name, BaseURL: base, GPGKey: filepath.Base(cfg.GPGKey), Packages: pkgs}

	var files []ManifestFile
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		mf, err := s.downloadRpm(ctx, base, cfg.Name, pkg, stageRoot)
		if err != nil {
			return RpmMirror{}, nil, err
		}
		if !seen[mf.Path] {
			files = append(files, mf)
			seen[mf.Path] = true
		}
	}
	return mirror, files, nil
}

// fetchRpmPrimary fetches repomd.xml (verifying repomd.xml.asc when a key is
// given), then downloads, verifies, and parses the primary metadata.
func (s *LowServer) fetchRpmPrimary(ctx context.Context, base, gpgKey string) ([]RpmPackage, error) {
	repomd, err := httpDownload(ctx, base+"/repodata/repomd.xml")
	if err != nil {
		return nil, fmt.Errorf("fetch repomd.xml: %w", err)
	}
	if gpgKey != "" {
		sig, err := httpDownload(ctx, base+"/repodata/repomd.xml.asc")
		if err != nil {
			return nil, fmt.Errorf("fetch repomd.xml.asc: %w", err)
		}
		if err := gpgVerifyDetached(ctx, repomd, sig, gpgKey); err != nil {
			return nil, fmt.Errorf("verify repomd.xml: %w", err)
		}
	}
	var md rpmRepomd
	if err := xml.Unmarshal(repomd, &md); err != nil {
		return nil, fmt.Errorf("parse repomd.xml: %w", err)
	}
	primary, ok := rpmPrimaryData(md)
	if !ok {
		return nil, errors.New("repomd.xml has no primary metadata")
	}
	if primary.Checksum.Type != "sha256" {
		return nil, fmt.Errorf("unsupported primary checksum type %q (need sha256)", primary.Checksum.Type)
	}
	raw, err := httpDownload(ctx, base+"/"+primary.Location.Href)
	if err != nil {
		return nil, err
	}
	if err := verifySHA256(raw, primary.Checksum.Value); err != nil {
		return nil, fmt.Errorf("primary index: %w", err)
	}
	plain, err := decompressByExt(primary.Location.Href, raw)
	if err != nil {
		return nil, err
	}
	return parseRpmPrimary(plain)
}

func rpmPrimaryData(md rpmRepomd) (rpmRepomdData, bool) {
	for _, d := range md.Data {
		if d.Type == "primary" {
			return d, true
		}
	}
	return rpmRepomdData{}, false
}

// downloadRpm fetches one .rpm, verifies its SHA256, and stages it under
// rpm/<mirror>/<location>.
func (s *LowServer) downloadRpm(ctx context.Context, base, mirror string, pkg RpmPackage, stageRoot string) (ManifestFile, error) {
	if err := validateRelPath(pkg.Location); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe package location %q: %w", pkg.Location, err)
	}
	data, err := httpDownload(ctx, base+"/"+pkg.Location)
	if err != nil {
		return ManifestFile{}, err
	}
	if err := verifySHA256(data, pkg.SHA256); err != nil {
		return ManifestFile{}, fmt.Errorf("%s: %w", pkg.Location, err)
	}
	rel := rpmFileRel(mirror, pkg.Location)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: rel, SHA256: pkg.SHA256, Size: int64(len(data))}, nil
}

func (s *LowServer) writeRpmBundle(seq int64, stageRoot string, files []ManifestFile, mirrors []RpmMirror) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	bundleID := bundleIDForSequence(seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         bundleID,
		Ecosystems:       []string{"rpm"},
		Rpm:              &RpmManifest{Mirrors: mirrors},
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
	total := 0
	for _, m := range mirrors {
		total += len(m.Packages)
	}
	return ExportResult{Sequence: seq, ExportedModules: total, BundleID: bundleID}, nil
}

// -----------------------------------------------------------------------------
// Helpers (HTTP, decompression)
// -----------------------------------------------------------------------------

// httpDownload GETs a URL with a timeout and a size cap.
func httpDownload(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<30))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return body, nil
}

// decompressByExt decompresses data according to href's extension: .gz via the
// standard library, .xz by shelling to xz, and plain otherwise. Zchunk (.zck)
// is not supported.
func decompressByExt(href string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(href, ".gz"):
		return gunzip(data)
	case strings.HasSuffix(href, ".xz"):
		return xzDecompress(data)
	case strings.HasSuffix(href, ".zck"):
		return nil, fmt.Errorf("zchunk (.zck) metadata is not supported: %s", href)
	default:
		return data, nil
	}
}

func xzDecompress(data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "xz", "--decompress", "--stdout")
	cmd.Stdin = strings.NewReader(string(data))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("xz decompress: %w", err)
	}
	return out, nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// -----------------------------------------------------------------------------
// Config resolution + .repo parsing
// -----------------------------------------------------------------------------

func resolveRpmMirrors(req RpmCollectRequest) ([]rpmMirrorConfig, error) {
	var configs []rpmMirrorConfig
	if strings.TrimSpace(req.RepoFile) != "" {
		parsed, err := parseRepoFile(req.RepoFile)
		if err != nil {
			return nil, err
		}
		configs = parsed
		if req.GPGKey != "" { // an explicit local keyring applies to all sections
			for i := range configs {
				configs[i].GPGKey = req.GPGKey
			}
		}
	} else {
		configs = []rpmMirrorConfig{{Name: req.Name, BaseURL: req.BaseURL, GPGKey: req.GPGKey}}
	}
	names := map[string]bool{}
	out := make([]rpmMirrorConfig, 0, len(configs))
	for _, c := range configs {
		vc, err := validateRpmMirrorConfig(c)
		if err != nil {
			return nil, err
		}
		if names[vc.Name] {
			return nil, fmt.Errorf("duplicate mirror name %q; give each repo a distinct name", vc.Name)
		}
		names[vc.Name] = true
		out = append(out, vc)
	}
	return out, nil
}

// parseRepoFile parses a yum/dnf .repo (INI) file into one config per [section].
func parseRepoFile(text string) ([]rpmMirrorConfig, error) {
	var configs []rpmMirrorConfig
	var cur *rpmMirrorConfig
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if name, ok := iniSection(line); ok {
			if cur != nil {
				configs = append(configs, *cur)
			}
			cur = &rpmMirrorConfig{Name: name}
			continue
		}
		if cur != nil {
			applyRepoField(cur, line)
		}
	}
	if cur != nil {
		configs = append(configs, *cur)
	}
	if len(configs) == 0 {
		return nil, errors.New("no [section] found in repo file")
	}
	return configs, nil
}

func iniSection(line string) (string, bool) {
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return strings.TrimSpace(line[1 : len(line)-1]), true
	}
	return "", false
}

// applyRepoField sets the mirror fields ArtiGate uses from one key=value line;
// unrecognized keys (enabled, gpgcheck, …) are ignored.
func applyRepoField(cur *rpmMirrorConfig, line string) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return
	}
	key, val := strings.TrimSpace(line[:eq]), strings.TrimSpace(line[eq+1:])
	switch key {
	case "baseurl":
		cur.BaseURL = val
	case "gpgkey":
		if p, ok := localKeyringPath(val); ok {
			cur.GPGKey = p
		}
	}
}

// localKeyringPath returns a filesystem path for a gpgkey= value that names a
// local file (absolute path or file:// URL); remote key URLs return ok=false so
// low-side verification is simply skipped.
func localKeyringPath(gpgkey string) (string, bool) {
	gpgkey = firstField(gpgkey)
	switch {
	case strings.HasPrefix(gpgkey, "file://"):
		return strings.TrimPrefix(gpgkey, "file://"), true
	case strings.HasPrefix(gpgkey, "/"):
		return gpgkey, true
	default:
		return "", false
	}
}

func validateRpmMirrorConfig(cfg rpmMirrorConfig) (rpmMirrorConfig, error) {
	if cfg.BaseURL == "" {
		return rpmMirrorConfig{}, errors.New("rpm mirror requires a base_url")
	}
	if strings.Contains(cfg.BaseURL, "$") {
		return rpmMirrorConfig{}, fmt.Errorf("base_url %q has unresolved variables ($releasever/$basearch); pin a concrete URL", cfg.BaseURL)
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return rpmMirrorConfig{}, fmt.Errorf("invalid rpm base_url %q (need http/https)", cfg.BaseURL)
	}
	if cfg.Name == "" {
		cfg.Name = aptMirrorName(cfg.BaseURL)
	}
	if validateRelPath(cfg.Name) != nil || strings.ContainsRune(cfg.Name, '/') {
		return rpmMirrorConfig{}, fmt.Errorf("invalid mirror name %q", cfg.Name)
	}
	return cfg, nil
}

// -----------------------------------------------------------------------------
// Import-side validation
// -----------------------------------------------------------------------------

func validateRpmMirrors(mirrors []RpmMirror, seen map[string]bool) error {
	for _, m := range mirrors {
		if m.Name == "" || m.BaseURL == "" {
			return errors.New("rpm mirror missing name or base_url")
		}
		if strings.ContainsRune(m.Name, '/') {
			return fmt.Errorf("invalid rpm mirror name %q", m.Name)
		}
		for _, p := range m.Packages {
			if p.Location == "" || p.SHA256 == "" || strings.TrimSpace(p.XML) == "" {
				return fmt.Errorf("rpm package %s missing location, sha256, or xml", p.Name)
			}
			rel := rpmFileRel(m.Name, p.Location)
			if !seen[rel] {
				return fmt.Errorf("rpm package references file not listed in manifest.files: %s", rel)
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: regenerate + publish repodata (called on import)
// -----------------------------------------------------------------------------

func (s *HighServer) rpmDir() string {
	return filepath.Join(s.downloadDir, "rpm")
}

// publishRpm regenerates repodata for every mirror in a freshly imported
// bundle, rebuilding primary.xml/repomd.xml from the stored <package> blocks of
// the .rpm files actually present.
func (s *HighServer) publishRpm(m *RpmManifest) error {
	if m == nil {
		return nil
	}
	for _, mirror := range m.Mirrors {
		if err := s.publishRpmMirror(mirror); err != nil {
			return fmt.Errorf("publish rpm mirror %s: %w", mirror.Name, err)
		}
	}
	return nil
}

func (s *HighServer) mergeRpmMirror(mirror RpmMirror) (RpmMirror, error) {
	indexPath := filepath.Join(s.rpmDir(), mirror.Name, "index.json")
	merged := RpmMirror{Name: mirror.Name, BaseURL: mirror.BaseURL}
	if b, err := os.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(b, &merged); err != nil {
			return RpmMirror{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return RpmMirror{}, err
	}
	merged.BaseURL = mirror.BaseURL
	byLoc := map[string]int{}
	for i, p := range merged.Packages {
		byLoc[p.Location] = i
	}
	for _, p := range mirror.Packages {
		if i, ok := byLoc[p.Location]; ok {
			merged.Packages[i] = p
		} else {
			byLoc[p.Location] = len(merged.Packages)
			merged.Packages = append(merged.Packages, p)
		}
	}
	sort.Slice(merged.Packages, func(i, j int) bool { return merged.Packages[i].Location < merged.Packages[j].Location })
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return RpmMirror{}, err
	}
	if err := writeBytesAtomic(indexPath, out, 0o644); err != nil {
		return RpmMirror{}, err
	}
	return merged, nil
}

func (s *HighServer) publishRpmMirror(mirror RpmMirror) error {
	merged, err := s.mergeRpmMirror(mirror)
	if err != nil {
		return err
	}
	mirrorRoot := filepath.Join(s.rpmDir(), merged.Name)
	repodata := filepath.Join(mirrorRoot, "repodata")

	primary := buildRpmPrimary(mirrorRoot, merged.Packages)
	primaryGz, err := gzipBytes(primary)
	if err != nil {
		return err
	}
	if err := writeBytesAtomic(filepath.Join(repodata, "primary.xml.gz"), primaryGz, 0o644); err != nil {
		return err
	}
	repomd := buildRpmRepomd(primary, primaryGz)
	if err := writeBytesAtomic(filepath.Join(repodata, "repomd.xml"), repomd, 0o644); err != nil {
		return err
	}
	return s.signRpmRepomd(repodata, repomd)
}

// buildRpmPrimary concatenates the stored <package> blocks (for .rpm files
// present on disk) into a primary.xml document.
func buildRpmPrimary(mirrorRoot string, pkgs []RpmPackage) []byte {
	var blocks []string
	for _, p := range pkgs {
		if fileExists(filepath.Join(mirrorRoot, filepath.FromSlash(p.Location))) {
			blocks = append(blocks, strings.TrimSpace(p.XML))
		}
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="%d">`+"\n", len(blocks))
	for _, blk := range blocks {
		b.WriteString(blk)
		b.WriteString("\n")
	}
	b.WriteString("</metadata>\n")
	return []byte(b.String())
}

func buildRpmRepomd(primary, primaryGz []byte) []byte {
	now := time.Now().UTC().Unix()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">` + "\n")
	fmt.Fprintf(&b, "  <revision>%d</revision>\n", now)
	b.WriteString(`  <data type="primary">` + "\n")
	fmt.Fprintf(&b, `    <checksum type="sha256">%s</checksum>`+"\n", sha256Hex(primaryGz))
	fmt.Fprintf(&b, `    <open-checksum type="sha256">%s</open-checksum>`+"\n", sha256Hex(primary))
	b.WriteString(`    <location href="repodata/primary.xml.gz"/>` + "\n")
	fmt.Fprintf(&b, "    <timestamp>%d</timestamp>\n", now)
	fmt.Fprintf(&b, "    <size>%d</size>\n", len(primaryGz))
	fmt.Fprintf(&b, "    <open-size>%d</open-size>\n", len(primary))
	b.WriteString("  </data>\n</repomd>\n")
	return []byte(b.String())
}

// signRpmRepomd writes a detached repomd.xml.asc when a high-side RPM signing
// key is configured; otherwise it removes any stale signature (unsigned repo).
func (s *HighServer) signRpmRepomd(repodata string, _ []byte) error {
	key := s.cfg.RpmGPGKey
	sigPath := filepath.Join(repodata, "repomd.xml.asc")
	if key == "" {
		_ = os.Remove(sigPath)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gpg", "--batch", "--yes", "--armor", "--local-user", key,
		"--detach-sign", "--output", sigPath, filepath.Join(repodata, "repomd.xml"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gpg sign repomd.xml: %w\n%s", err, tailBytes(out, 2048))
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: serve the static RPM repository under /rpm/
// -----------------------------------------------------------------------------

func (s *HighServer) serveRpm(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/rpm" && !strings.HasPrefix(p, "/rpm/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, "/rpm"), "/")
	if rel == "" || validateRelPath(rel) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.rpmDir(), filepath.FromSlash(rel))
	if !safeJoin(s.rpmDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	serveFile(w, r, abs)
	return true
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

func (s *HighServer) listRpmMirrors() ([]UIModule, error) {
	entries, err := os.ReadDir(s.rpmDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byKey := map[string]map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			s.collectRpmVersions(e.Name(), byKey)
		}
	}
	mods := make([]UIModule, 0, len(byKey))
	for key, vers := range byKey {
		vs := make([]string, 0, len(vers))
		for v := range vers {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		mods = append(mods, UIModule{Module: key, Versions: vs})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Module < mods[j].Module })
	return mods, nil
}

func (s *HighServer) collectRpmVersions(name string, byKey map[string]map[string]bool) {
	mirror, err := s.loadRpmIndex(name)
	if err != nil {
		return
	}
	for _, p := range mirror.Packages {
		if !fileExists(filepath.Join(s.rpmDir(), name, filepath.FromSlash(p.Location))) {
			continue
		}
		key := name + "/" + p.Name
		if byKey[key] == nil {
			byKey[key] = map[string]bool{}
		}
		byKey[key][p.Version] = true
	}
}

func (s *HighServer) loadRpmIndex(name string) (RpmMirror, error) {
	b, err := os.ReadFile(filepath.Join(s.rpmDir(), name, "index.json"))
	if err != nil {
		return RpmMirror{}, err
	}
	var m RpmMirror
	if err := json.Unmarshal(b, &m); err != nil {
		return RpmMirror{}, err
	}
	return m, nil
}

// rpmDetail describes one package version for the dashboard. spec is
// "<mirror>/<package>@<version>".
func (s *HighServer) rpmDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid package@version")
	}
	key, version := spec[:i], spec[i+1:]
	slash := strings.IndexByte(key, '/')
	if slash <= 0 {
		return UIDetail{}, errors.New("invalid package path")
	}
	mirrorName, pkgName := key[:slash], key[slash+1:]
	if strings.ContainsRune(mirrorName, '/') || validateRelPath(mirrorName) != nil {
		return UIDetail{}, errors.New("invalid mirror")
	}
	mirror, err := s.loadRpmIndex(mirrorName)
	if err != nil {
		return UIDetail{}, errors.New("mirror not found")
	}
	fields := []UIDetailField{
		{Label: "Mirror", Value: mirrorName, Mono: true},
		{Label: "Package", Value: pkgName, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	found := false
	for _, p := range mirror.Packages {
		if p.Name != pkgName || p.Version != version {
			continue
		}
		found = true
		fields = append(fields,
			UIDetailField{Label: p.Arch + " file", Value: path.Base(p.Location), Mono: true},
			UIDetailField{Label: "Size", Value: formatBytes(p.Size)},
			UIDetailField{Label: "SHA-256", Value: p.SHA256, Mono: true},
			UIDetailField{Label: "Path", Value: "/rpm/" + mirrorName + "/" + p.Location, Mono: true})
	}
	if !found {
		return UIDetail{}, errors.New("version not found")
	}
	return UIDetail{Title: pkgName, Subtitle: version, Fields: fields}, nil
}
