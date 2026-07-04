package main

// RPM (YUM/DNF) ecosystem adapter — full repository mirror, parallel to the APT
// adapter. It mirrors an entire upstream repository at full metadata fidelity,
// suitable for full distro mirroring (Fedora/RHEL/EPEL), not just small vendor
// repos.
//
// Low side: fetch repodata/repomd.xml, optionally GPG-verify repomd.xml.asc
// against a caller-supplied key, then download and verify EVERY metadata file
// repomd references (primary, filelists, other, updateinfo, comps, modules,
// zchunk variants, …) against its recorded checksum. It parses the primary
// index to enumerate packages, downloads every .rpm, and verifies each against
// the index. The .rpm files and all metadata files are packed into the standard
// signed ArtiGate bundle, along with the repomd <data> entries.
//
// High side: on import, it serves the mirrored metadata files verbatim (they are
// integrity-locked by the ArtiGate manifest and were signature-verified on the
// low side) and regenerates repomd.xml from the recorded entries whose files are
// present — so the high side owns and (optionally) re-signs the repository's
// entry point without ever trusting a transferred repomd/signature as final.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // used only to verify legacy repo checksums, not as a security primitive
	"crypto/sha256"
	"crypto/sha512"
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
	Repodata []RpmData    `json:"repodata"` // repomd.xml <data> entries, for high-side regeneration
	Packages []RpmPackage `json:"packages"` // enumerated from primary.xml, for UI + validation
}

// RpmData is one repomd.xml <data> entry (primary, filelists, other, …).
type RpmData struct {
	Type             string `json:"type"`
	Href             string `json:"href"`
	ChecksumType     string `json:"checksum_type"`
	Checksum         string `json:"checksum"`
	OpenChecksumType string `json:"open_checksum_type,omitempty"`
	OpenChecksum     string `json:"open_checksum,omitempty"`
	Size             int64  `json:"size,omitempty"`
	OpenSize         int64  `json:"open_size,omitempty"`
	Timestamp        string `json:"timestamp,omitempty"`
}

type RpmPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Location string `json:"location"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

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
	OpenChecksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"open-checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
	Size      int64  `xml:"size"`
	OpenSize  int64  `xml:"open-size"`
	Timestamp string `xml:"timestamp"`
}

func (d rpmRepomdData) toRpmData() RpmData {
	return RpmData{
		Type:             d.Type,
		Href:             d.Location.Href,
		ChecksumType:     d.Checksum.Type,
		Checksum:         strings.TrimSpace(d.Checksum.Value),
		OpenChecksumType: d.OpenChecksum.Type,
		OpenChecksum:     strings.TrimSpace(d.OpenChecksum.Value),
		Size:             d.Size,
		OpenSize:         d.OpenSize,
		Timestamp:        strings.TrimSpace(d.Timestamp),
	}
}

type rpmPrimaryDoc struct {
	Packages []rpmPrimaryPackage `xml:"package"`
}

type rpmPrimaryPackage struct {
	Name    string `xml:"name"`
	Arch    string `xml:"arch"`
	Version struct {
		Ver string `xml:"ver,attr"`
		Rel string `xml:"rel,attr"`
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

// parseRpmPrimary parses a decompressed primary.xml into package records used to
// download/verify the .rpm files and to populate the dashboard.
func parseRpmPrimary(data []byte) ([]RpmPackage, error) {
	var doc rpmPrimaryDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse primary.xml: %w", err)
	}
	out := make([]RpmPackage, 0, len(doc.Packages))
	for _, p := range doc.Packages {
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

	seq := s.peekSequence(streamRpm)
	res, err := s.writeRpmBundle(seq, stageRoot, files, mirrors)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(streamRpm, seq); err != nil {
		return ExportResult{}, err
	}
	return res, nil
}

// mirrorRpmRepo downloads and verifies repomd, every metadata file it lists, and
// every .rpm, staging them under stageRoot.
func (s *LowServer) mirrorRpmRepo(ctx context.Context, cfg rpmMirrorConfig, stageRoot string) (RpmMirror, []ManifestFile, error) {
	base := strings.TrimRight(cfg.BaseURL, "/")

	repomdRaw, err := s.fetchRepomd(ctx, base, cfg.GPGKey)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	var md rpmRepomd
	if err := xml.Unmarshal(repomdRaw, &md); err != nil {
		return RpmMirror{}, nil, fmt.Errorf("parse repomd.xml: %w", err)
	}

	mirror := RpmMirror{Name: cfg.Name, BaseURL: base, GPGKey: filepath.Base(cfg.GPGKey)}
	var files []ManifestFile

	// Download and verify every metadata file repomd references.
	var primaryRel string
	for _, d := range md.Data {
		entry := d.toRpmData()
		mf, err := s.downloadRpmFile(ctx, base, cfg.Name, entry.Href, entry.ChecksumType, entry.Checksum, stageRoot)
		if err != nil {
			return RpmMirror{}, nil, fmt.Errorf("metadata %s: %w", entry.Type, err)
		}
		files = append(files, mf)
		mirror.Repodata = append(mirror.Repodata, entry)
		if entry.Type == "primary" {
			primaryRel = entry.Href
		}
	}
	if primaryRel == "" {
		return RpmMirror{}, nil, errors.New("repomd.xml has no primary metadata")
	}

	// Parse the staged primary to enumerate and fetch every .rpm.
	primaryPlain, err := readStagedMetadata(stageRoot, cfg.Name, primaryRel)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	pkgs, err := parseRpmPrimary(primaryPlain)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	mirror.Packages = pkgs
	for _, pkg := range pkgs {
		mf, err := s.downloadRpmFile(ctx, base, cfg.Name, pkg.Location, "sha256", pkg.SHA256, stageRoot)
		if err != nil {
			return RpmMirror{}, nil, fmt.Errorf("package %s: %w", pkg.Name, err)
		}
		files = append(files, mf)
	}
	return mirror, files, nil
}

// fetchRepomd downloads repodata/repomd.xml and verifies repomd.xml.asc against
// the caller's keyring when one is supplied.
func (s *LowServer) fetchRepomd(ctx context.Context, base, gpgKey string) ([]byte, error) {
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
	return repomd, nil
}

// downloadRpmFile fetches one repository file (metadata or .rpm), verifies it
// against the repo-declared checksum, and stages it under rpm/<mirror>/<rel>.
func (s *LowServer) downloadRpmFile(ctx context.Context, base, mirror, relHref, checksumType, checksum string, stageRoot string) (ManifestFile, error) {
	if err := validateRelPath(relHref); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe location %q: %w", relHref, err)
	}
	data, err := httpDownload(ctx, base+"/"+relHref)
	if err != nil {
		return ManifestFile{}, err
	}
	if err := verifyChecksum(data, checksumType, checksum); err != nil {
		return ManifestFile{}, fmt.Errorf("%s: %w", relHref, err)
	}
	rel := rpmFileRel(mirror, relHref)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: rel, SHA256: sha256Hex(data), Size: int64(len(data))}, nil
}

// readStagedMetadata reads a staged metadata file and decompresses it by
// extension.
func readStagedMetadata(stageRoot, mirror, relHref string) ([]byte, error) {
	abs := filepath.Join(stageRoot, filepath.FromSlash(rpmFileRel(mirror, relHref)))
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return decompressByExt(relHref, raw)
}

func (s *LowServer) writeRpmBundle(seq int64, stageRoot string, files []ManifestFile, mirrors []RpmMirror) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamRpm, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamRpm,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"rpm"},
		Rpm:              &RpmManifest{Mirrors: mirrors},
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
	total := 0
	for _, m := range mirrors {
		total += len(m.Packages)
	}
	return ExportResult{Stream: streamRpm, Sequence: seq, ExportedModules: total, BundleID: id}, nil
}

// -----------------------------------------------------------------------------
// Helpers (HTTP, decompression, checksums)
// -----------------------------------------------------------------------------

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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<30))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return body, nil
}

// decompressByExt decompresses by href extension: .gz via the standard library,
// .xz by shelling to xz, and plain otherwise.
func decompressByExt(href string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(href, ".gz"):
		return gunzip(data)
	case strings.HasSuffix(href, ".xz"):
		return xzDecompress(data)
	case strings.HasSuffix(href, ".zck"):
		return nil, fmt.Errorf("zchunk (.zck) index cannot be parsed: %s", href)
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

// verifyChecksum verifies data against a repo-declared checksum of the named
// type (sha256/sha512/sha1). ArtiGate's own bundle integrity always uses
// sha256; this only mirrors what the upstream repomd declares.
func verifyChecksum(data []byte, algo, want string) error {
	var got string
	switch strings.ToLower(algo) {
	case "sha256", "":
		got = sha256Hex(data)
	case "sha512":
		h := sha512.Sum512(data)
		got = hex.EncodeToString(h[:])
	case "sha1", "sha":
		h := sha1.Sum(data) //nolint:gosec // verifying a legacy repo-declared checksum
		got = hex.EncodeToString(h[:])
	default:
		return fmt.Errorf("unsupported checksum type %q", algo)
	}
	if !strings.EqualFold(got, strings.TrimSpace(want)) {
		return fmt.Errorf("%s mismatch: got %s want %s", algo, got, want)
	}
	return nil
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
		if req.GPGKey != "" {
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
		cur.BaseURL = firstField(val)
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
		if err := validateRpmMirror(m, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateRpmMirror(m RpmMirror, seen map[string]bool) error {
	if m.Name == "" || m.BaseURL == "" {
		return errors.New("rpm mirror missing name or base_url")
	}
	if strings.ContainsRune(m.Name, '/') {
		return fmt.Errorf("invalid rpm mirror name %q", m.Name)
	}
	if len(m.Repodata) == 0 {
		return fmt.Errorf("rpm mirror %s has no repodata", m.Name)
	}
	for _, d := range m.Repodata {
		if !seen[rpmFileRel(m.Name, d.Href)] {
			return fmt.Errorf("rpm mirror %s references metadata not in manifest.files: %s", m.Name, d.Href)
		}
	}
	for _, p := range m.Packages {
		if !seen[rpmFileRel(m.Name, p.Location)] {
			return fmt.Errorf("rpm mirror %s references package not in manifest.files: %s", m.Name, p.Location)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: regenerate + publish repomd (called on import)
// -----------------------------------------------------------------------------

func (s *HighServer) rpmDir() string {
	return filepath.Join(s.downloadDir, "rpm")
}

// publishRpm regenerates repomd.xml for every mirror in a freshly imported
// bundle. Each mirror's newest snapshot wins (metadata files are content-named
// and immutable; repomd is high-side-owned and re-signed).
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

func (s *HighServer) publishRpmMirror(mirror RpmMirror) error {
	// Persist the latest snapshot's state (repodata entries + package list) so
	// the dashboard and repomd reflect the current repository.
	indexPath := filepath.Join(s.rpmDir(), mirror.Name, "index.json")
	out, err := json.MarshalIndent(mirror, "", "  ")
	if err != nil {
		return err
	}
	if err := writeBytesAtomic(indexPath, out, 0o644); err != nil {
		return err
	}

	mirrorRoot := filepath.Join(s.rpmDir(), mirror.Name)
	repomd := buildRpmRepomd(mirrorRoot, mirror.Repodata)
	if err := writeBytesAtomic(filepath.Join(mirrorRoot, "repodata", "repomd.xml"), repomd, 0o644); err != nil {
		return err
	}
	return s.signRpmRepomd(filepath.Join(mirrorRoot, "repodata"))
}

// buildRpmRepomd renders repomd.xml from the recorded <data> entries whose files
// are present on disk. It preserves the upstream checksums/open-checksums (the
// files are carried verbatim and integrity-locked), so it never has to
// decompress or re-hash the potentially large or zchunk-only metadata.
func buildRpmRepomd(mirrorRoot string, entries []RpmData) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">` + "\n")
	fmt.Fprintf(&b, "  <revision>%d</revision>\n", time.Now().UTC().Unix())
	for _, d := range entries {
		if !fileExists(filepath.Join(mirrorRoot, filepath.FromSlash(d.Href))) {
			continue
		}
		writeRepomdData(&b, d)
	}
	b.WriteString("</repomd>\n")
	return []byte(b.String())
}

func writeRepomdData(b *strings.Builder, d RpmData) {
	fmt.Fprintf(b, "  <data type=%q>\n", d.Type)
	fmt.Fprintf(b, "    <checksum type=%q>%s</checksum>\n", orDefault(d.ChecksumType, "sha256"), d.Checksum)
	if d.OpenChecksum != "" {
		fmt.Fprintf(b, "    <open-checksum type=%q>%s</open-checksum>\n", orDefault(d.OpenChecksumType, "sha256"), d.OpenChecksum)
	}
	fmt.Fprintf(b, "    <location href=%q/>\n", d.Href)
	if d.Timestamp != "" {
		fmt.Fprintf(b, "    <timestamp>%s</timestamp>\n", d.Timestamp)
	}
	if d.Size > 0 {
		fmt.Fprintf(b, "    <size>%d</size>\n", d.Size)
	}
	if d.OpenSize > 0 {
		fmt.Fprintf(b, "    <open-size>%d</open-size>\n", d.OpenSize)
	}
	b.WriteString("  </data>\n")
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// signRpmRepomd writes a detached repomd.xml.asc when a high-side RPM signing
// key is configured; otherwise it removes any stale signature (unsigned repo).
func (s *HighServer) signRpmRepomd(repodata string) error {
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
