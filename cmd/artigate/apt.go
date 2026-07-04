package main

// APT (Debian/Ubuntu deb) ecosystem adapter — full mirror mode for a single
// upstream repository (one suite / components / architectures).
//
// Low side: fetch dists/<suite>/InRelease (optionally GPG-verify it against a
// caller-supplied keyring via gpgv), read the Release checksums, download and
// verify the binary Packages index for each component/architecture, then
// download every referenced .deb and verify its SHA256 against the index. The
// .deb files are packed into the standard signed ArtiGate bundle; each package's
// Packages stanza is stored in the manifest.
//
// High side: on import, regenerate Packages/Packages.gz and a Release file from
// the accumulated stanzas (only for .deb files actually present) and write them
// to disk, optionally clearsigning InRelease with a high-side APT key; the
// repository is then served as static files. The high side never trusts the
// transferred Release/Packages as final — it rebuilds them from what it holds.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/md5"  //nolint:gosec // APT metadata carries MD5Sum for legacy clients, not a security control
	"crypto/sha1" //nolint:gosec // APT metadata carries SHA1 for legacy clients, not a security control
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"strconv"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type AptManifest struct {
	Mirrors []AptMirror `json:"mirrors"`
}

type AptMirror struct {
	Name          string       `json:"name"`
	URI           string       `json:"uri"`
	Suite         string       `json:"suite"`
	Components    []string     `json:"components"`
	Architectures []string     `json:"architectures"`
	SignedBy      string       `json:"signed_by,omitempty"`
	Packages      []AptPackage `json:"packages"`
}

type AptPackage struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Component    string `json:"component"`
	Filename     string `json:"filename"` // pool/... relative to the archive root
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Stanza       string `json:"stanza"` // the raw Packages stanza, for high-side regeneration
}

// aptFileRel returns the bundle/repository-relative path of a package's .deb,
// e.g. apt/microsoft-code/pool/main/c/code/code_..._amd64.deb.
func aptFileRel(mirror, filename string) string {
	return path.Join("apt", mirror, filename)
}

// -----------------------------------------------------------------------------
// deb822 parsing
// -----------------------------------------------------------------------------

// parseDeb822 splits deb822 text into stanzas of field->value. Continuation
// lines (leading space/tab) are folded into the previous field's value joined
// by newlines, which preserves the multi-line SHA256 section of a Release file.
func parseDeb822(data []byte) []map[string]string {
	var stanzas []map[string]string
	cur := map[string]string{}
	last := ""
	flush := func() {
		if len(cur) > 0 {
			stanzas = append(stanzas, cur)
			cur = map[string]string{}
		}
		last = ""
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				cur[last] += "\n" + strings.TrimSpace(line)
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		cur[key] = strings.TrimSpace(line[i+1:])
		last = key
	}
	flush()
	return stanzas
}

type aptChecksum struct {
	sha256 string
	size   int64
}

// releaseIndexChecksums extracts the path->{sha256,size} map from a Release
// stanza's SHA256 section.
func releaseIndexChecksums(release map[string]string) map[string]aptChecksum {
	out := map[string]aptChecksum{}
	for _, line := range strings.Split(release["SHA256"], "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		out[fields[2]] = aptChecksum{sha256: fields[0], size: size}
	}
	return out
}

// -----------------------------------------------------------------------------
// Low side: APT mirror collector
// -----------------------------------------------------------------------------

// AptCollectRequest is the body of POST /admin/apt/collect. Provide either a
// deb822 source stanza in SourceList or the fields explicitly.
type AptCollectRequest struct {
	Name          string   `json:"name"`
	URI           string   `json:"uri"`
	Suite         string   `json:"suite"`
	Components    []string `json:"components"`
	Architectures []string `json:"architectures"`
	SignedBy      string   `json:"signed_by"`
	SourceList    string   `json:"source_list"`
}

// aptMirrorConfig is the resolved, validated mirror to collect.
type aptMirrorConfig struct {
	Name          string
	URI           string
	Suite         string
	Components    []string
	Architectures []string
	SignedBy      string
}

func (s *LowServer) HandleAptCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req AptCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse apt collect request: %w", err)
		}
	}
	return s.CollectApt(ctx, req)
}

// CollectApt mirrors one upstream APT repository into a signed bundle.
func (s *LowServer) CollectApt(ctx context.Context, req AptCollectRequest) (ExportResult, error) {
	configs, err := resolveAptMirrors(req)
	if err != nil {
		return ExportResult{}, err
	}
	s.exportMu.Lock()
	defer s.exportMu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "apt", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	// Each source is mirrored into its own namespace (apt/<name>/...); one
	// bundle can carry several mirrors, which the high side publishes as
	// separate repositories on import.
	var mirrors []AptMirror
	var files []ManifestFile
	seenFile := map[string]bool{}
	for _, cfg := range configs {
		mirror, mf, err := s.mirrorAptRepo(ctx, cfg, stageRoot)
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
		return ExportResult{}, errors.New("apt mirror produced no packages")
	}

	seq := s.peekSequence(streamApt)
	res, err := s.writeAptBundle(seq, stageRoot, files, mirrors)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(streamApt, seq); err != nil {
		return ExportResult{}, err
	}
	return res, nil
}

// mirrorAptRepo downloads and verifies the Release, indexes, and every .deb for
// one mirror, staging the .deb files under stageRoot and returning the mirror
// metadata plus the manifest file list.
func (s *LowServer) mirrorAptRepo(ctx context.Context, cfg aptMirrorConfig, stageRoot string) (AptMirror, []ManifestFile, error) {
	base := strings.TrimRight(cfg.URI, "/")
	distBase := base + "/dists/" + cfg.Suite

	releaseBytes, err := s.fetchAptRelease(ctx, distBase, cfg.SignedBy)
	if err != nil {
		return AptMirror{}, nil, err
	}
	stanzas := parseDeb822(releaseBytes)
	if len(stanzas) == 0 {
		return AptMirror{}, nil, errors.New("empty Release file")
	}
	checksums := releaseIndexChecksums(stanzas[0])

	mirror := AptMirror{
		Name: cfg.Name, URI: base, Suite: cfg.Suite,
		Components: cfg.Components, Architectures: cfg.Architectures, SignedBy: filepath.Base(cfg.SignedBy),
	}
	var files []ManifestFile
	seenFile := map[string]bool{}

	for _, comp := range cfg.Components {
		for _, arch := range cfg.Architectures {
			cf, pkgs, err := s.collectAptIndex(ctx, base, distBase, cfg.Name, comp, arch, checksums, stageRoot, seenFile)
			if err != nil {
				return AptMirror{}, nil, err
			}
			files = append(files, cf...)
			mirror.Packages = append(mirror.Packages, pkgs...)
		}
	}
	return mirror, files, nil
}

// collectAptIndex fetches one component/architecture Packages index and
// downloads every referenced .deb, returning the new manifest files (deduped
// via seenFile) and the parsed package records.
func (s *LowServer) collectAptIndex(ctx context.Context, base, distBase, name, comp, arch string, checksums map[string]aptChecksum, stageRoot string, seenFile map[string]bool) ([]ManifestFile, []AptPackage, error) {
	pkgs, err := s.fetchAptPackagesIndex(ctx, distBase, comp, arch, checksums)
	if err != nil {
		return nil, nil, err
	}
	var files []ManifestFile
	for _, pkg := range pkgs {
		mf, err := s.downloadAptDeb(ctx, base, name, pkg, stageRoot)
		if err != nil {
			return nil, nil, err
		}
		if !seenFile[mf.Path] {
			files = append(files, mf)
			seenFile[mf.Path] = true
		}
	}
	return files, pkgs, nil
}

// fetchAptRelease downloads dists/<suite>/InRelease (preferred) or Release and,
// when a keyring is supplied, verifies the signature with gpg. It returns the
// Release payload (clearsign markers stripped).
func (s *LowServer) fetchAptRelease(ctx context.Context, distBase, signedBy string) ([]byte, error) {
	inrelease, inErr := s.aptGet(ctx, distBase+"/InRelease")
	if inErr == nil {
		if signedBy != "" {
			if err := gpgVerifyClearsigned(ctx, inrelease, signedBy); err != nil {
				return nil, fmt.Errorf("verify InRelease: %w", err)
			}
		}
		return stripClearsign(inrelease), nil
	}
	// Fall back to detached Release + Release.gpg.
	release, err := s.aptGet(ctx, distBase+"/Release")
	if err != nil {
		return nil, fmt.Errorf("fetch InRelease/Release: %w", err)
	}
	if signedBy != "" {
		sig, err := s.aptGet(ctx, distBase+"/Release.gpg")
		if err != nil {
			return nil, fmt.Errorf("fetch Release.gpg: %w", err)
		}
		if err := gpgVerifyDetached(ctx, release, sig, signedBy); err != nil {
			return nil, fmt.Errorf("verify Release: %w", err)
		}
	}
	return release, nil
}

// fetchAptPackagesIndex downloads and verifies the binary Packages index for a
// component/architecture and parses its stanzas into AptPackage records.
func (s *LowServer) fetchAptPackagesIndex(ctx context.Context, distBase, comp, arch string, checksums map[string]aptChecksum) ([]AptPackage, error) {
	dir := comp + "/binary-" + arch
	// Prefer gzip (stdlib) then plain; the index path is validated against the
	// signed Release checksums.
	candidates := []struct {
		rel        string
		decompress func([]byte) ([]byte, error)
	}{
		{dir + "/Packages.gz", gunzip},
		{dir + "/Packages", func(b []byte) ([]byte, error) { return b, nil }},
	}
	for _, c := range candidates {
		want, ok := checksums[c.rel]
		if !ok {
			continue
		}
		raw, err := s.aptGet(ctx, distBase+"/"+c.rel)
		if err != nil {
			return nil, err
		}
		if err := verifySHA256(raw, want.sha256); err != nil {
			return nil, fmt.Errorf("%s index: %w", c.rel, err)
		}
		plain, err := c.decompress(raw)
		if err != nil {
			return nil, fmt.Errorf("decompress %s: %w", c.rel, err)
		}
		return parseAptPackages(plain, comp), nil
	}
	return nil, fmt.Errorf("no Packages index for %s in Release", dir)
}

// downloadAptDeb fetches one .deb, verifies its SHA256 against the index, and
// stages it under the bundle's apt/<mirror>/<filename> path.
func (s *LowServer) downloadAptDeb(ctx context.Context, base, mirror string, pkg AptPackage, stageRoot string) (ManifestFile, error) {
	if err := validateRelPath(pkg.Filename); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe package Filename %q: %w", pkg.Filename, err)
	}
	data, err := s.aptGet(ctx, base+"/"+pkg.Filename)
	if err != nil {
		return ManifestFile{}, err
	}
	if err := verifySHA256(data, pkg.SHA256); err != nil {
		return ManifestFile{}, fmt.Errorf("%s: %w", pkg.Filename, err)
	}
	rel := aptFileRel(mirror, pkg.Filename)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: rel, SHA256: pkg.SHA256, Size: int64(len(data))}, nil
}

// parseAptPackages turns a decompressed Packages index into AptPackage records,
// keeping the raw stanza for high-side regeneration. Each package's own
// Architecture comes from its stanza (it may be "all").
func parseAptPackages(data []byte, comp string) []AptPackage {
	var pkgs []AptPackage
	for _, block := range splitStanzaBlocks(data) {
		st := parseDeb822([]byte(block))
		if len(st) == 0 {
			continue
		}
		m := st[0]
		if m["Filename"] == "" || m["SHA256"] == "" {
			continue
		}
		size, _ := strconv.ParseInt(m["Size"], 10, 64)
		pkgs = append(pkgs, AptPackage{
			Package:      m["Package"],
			Version:      m["Version"],
			Architecture: m["Architecture"],
			Component:    comp,
			Filename:     m["Filename"],
			SHA256:       m["SHA256"],
			Size:         size,
			Stanza:       strings.TrimSpace(block) + "\n",
		})
	}
	return pkgs
}

// splitStanzaBlocks splits deb822 text into raw stanza blocks on blank lines,
// preserving each block's original text (needed to store verbatim stanzas).
func splitStanzaBlocks(data []byte) []string {
	var blocks []string
	var cur []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				blocks = append(blocks, strings.Join(cur, "\n"))
				cur = nil
			}
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		blocks = append(blocks, strings.Join(cur, "\n"))
	}
	return blocks
}

func (s *LowServer) writeAptBundle(seq int64, stageRoot string, files []ManifestFile, mirrors []AptMirror) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamApt, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamApt,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"apt"},
		Apt:              &AptManifest{Mirrors: mirrors},
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
	return ExportResult{Stream: streamApt, Sequence: seq, ExportedModules: total, BundleID: id}, nil
}

// -----------------------------------------------------------------------------
// HTTP + hashing + gpg helpers
// -----------------------------------------------------------------------------

func (s *LowServer) aptGet(ctx context.Context, rawURL string) ([]byte, error) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<30)) // 2 GiB cap per file
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return body, nil
}

func verifySHA256(data []byte, want string) error {
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != strings.ToLower(strings.TrimSpace(want)) {
		return fmt.Errorf("sha256 mismatch: got %x want %s", got, want)
	}
	return nil
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// stripClearsign removes the OpenPGP clearsign header/footer from an InRelease
// payload, leaving the Release body that the checksums describe.
func stripClearsign(b []byte) []byte {
	s := string(b)
	i := strings.Index(s, "\n\n")
	if !strings.HasPrefix(s, "-----BEGIN PGP SIGNED MESSAGE-----") || i < 0 {
		return b // not clearsigned; use as-is
	}
	body := s[i+2:]
	if j := strings.Index(body, "\n-----BEGIN PGP SIGNATURE-----"); j >= 0 {
		body = body[:j+1]
	}
	return []byte(body)
}

func gpgVerifyClearsigned(ctx context.Context, inrelease []byte, keyring string) error {
	return runGPGVerify(ctx, keyring, inrelease, nil)
}

func gpgVerifyDetached(ctx context.Context, release, sig []byte, keyring string) error {
	return runGPGVerify(ctx, keyring, release, sig)
}

// runGPGVerify verifies data (clearsigned when sig is nil, detached otherwise)
// against the given keyring using gpgv.
func runGPGVerify(ctx context.Context, keyring string, data, sig []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "artigate-gpgv-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dataPath := filepath.Join(dir, "data")
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		return err
	}
	args := []string{"--keyring", keyring}
	if sig != nil {
		sigPath := filepath.Join(dir, "data.sig")
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			return err
		}
		args = append(args, sigPath)
	}
	args = append(args, dataPath)
	cmd := exec.CommandContext(ctx, "gpgv", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gpgv failed: %w\n%s", err, tailBytes(out, 2048))
	}
	return nil
}

// -----------------------------------------------------------------------------
// Config resolution + deb822 source parsing
// -----------------------------------------------------------------------------

// resolveAptMirrors returns the validated set of mirrors to collect. A
// source_list may contain several deb822 stanzas (several repositories);
// otherwise the explicit request fields describe a single mirror. Mirror names
// must be distinct so each keeps its own namespace on the high side.
func resolveAptMirrors(req AptCollectRequest) ([]aptMirrorConfig, error) {
	var configs []aptMirrorConfig
	if strings.TrimSpace(req.SourceList) != "" {
		parsed, err := parseAptSources(req.SourceList)
		if err != nil {
			return nil, err
		}
		configs = parsed
	} else {
		configs = []aptMirrorConfig{{
			Name: req.Name, URI: req.URI, Suite: req.Suite,
			Components: req.Components, Architectures: req.Architectures, SignedBy: req.SignedBy,
		}}
	}
	names := map[string]bool{}
	out := make([]aptMirrorConfig, 0, len(configs))
	for _, c := range configs {
		vc, err := validateAptMirrorConfig(c)
		if err != nil {
			return nil, err
		}
		if names[vc.Name] {
			return nil, fmt.Errorf("duplicate mirror name %q; give each source a distinct name", vc.Name)
		}
		names[vc.Name] = true
		out = append(out, vc)
	}
	return out, nil
}

// parseAptSources parses every deb822 (.sources) stanza in text into a mirror
// config, so a multi-repository sources file mirrors each repository.
func parseAptSources(text string) ([]aptMirrorConfig, error) {
	stanzas := parseDeb822([]byte(text))
	var out []aptMirrorConfig
	for _, m := range stanzas {
		if m["URIs"] == "" && m["Suites"] == "" {
			continue // not a source stanza (e.g. a comment-only block)
		}
		if types := m["Types"]; types != "" && !containsField(types, "deb") {
			return nil, fmt.Errorf("unsupported source Types %q (need binary \"deb\")", types)
		}
		out = append(out, aptMirrorConfig{
			URI:           firstField(m["URIs"]),
			Suite:         firstField(m["Suites"]),
			Components:    strings.Fields(m["Components"]),
			Architectures: strings.Fields(m["Architectures"]),
			SignedBy:      strings.TrimSpace(m["Signed-By"]),
		})
	}
	if len(out) == 0 {
		return nil, errors.New("no deb source stanzas found")
	}
	return out, nil
}

// firstField returns the first whitespace-separated token of s (deb822 list
// fields such as URIs/Suites usually carry a single value for a mirror).
func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// containsField reports whether want is one of the whitespace-separated tokens
// of s (so "deb-src" does not satisfy a check for "deb").
func containsField(s, want string) bool {
	for _, f := range strings.Fields(s) {
		if f == want {
			return true
		}
	}
	return false
}

func validateAptMirrorConfig(cfg aptMirrorConfig) (aptMirrorConfig, error) {
	if cfg.URI == "" {
		return aptMirrorConfig{}, errors.New("apt mirror requires a URI")
	}
	u, err := url.Parse(cfg.URI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return aptMirrorConfig{}, fmt.Errorf("invalid apt URI %q (need http/https)", cfg.URI)
	}
	if cfg.Suite == "" {
		return aptMirrorConfig{}, errors.New("apt mirror requires a suite")
	}
	if len(cfg.Components) == 0 {
		cfg.Components = []string{"main"}
	}
	if len(cfg.Architectures) == 0 {
		cfg.Architectures = []string{"amd64"}
	}
	if cfg.Name == "" {
		cfg.Name = aptMirrorName(cfg.URI)
	}
	if err := validateRelPath(cfg.Name); err != nil || strings.ContainsRune(cfg.Name, '/') {
		return aptMirrorConfig{}, fmt.Errorf("invalid mirror name %q", cfg.Name)
	}
	for _, tok := range append(append([]string{cfg.Suite}, cfg.Components...), cfg.Architectures...) {
		if !mavenTokenRE.MatchString(tok) {
			return aptMirrorConfig{}, fmt.Errorf("invalid suite/component/architecture token %q", tok)
		}
	}
	return cfg, nil
}

// aptMirrorName derives a filesystem-safe mirror name from a repository URI,
// e.g. https://packages.microsoft.com/repos/code -> packages-microsoft-com-repos-code.
func aptMirrorName(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return "mirror"
	}
	slug := u.Host + u.Path
	var b strings.Builder
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(strings.ReplaceAll(b.String(), "--", "-"), "-")
}

// -----------------------------------------------------------------------------
// Import-side validation
// -----------------------------------------------------------------------------

// validateAptMirrors checks that every mirror names packages whose .deb files
// appear in the manifest's overall file set.
func validateAptMirrors(mirrors []AptMirror, seen map[string]bool) error {
	for _, m := range mirrors {
		if m.Name == "" || m.Suite == "" {
			return errors.New("apt mirror missing name or suite")
		}
		if strings.ContainsRune(m.Name, '/') {
			return fmt.Errorf("invalid apt mirror name %q", m.Name)
		}
		for _, p := range m.Packages {
			if p.Filename == "" || p.SHA256 == "" {
				return fmt.Errorf("apt package %s missing filename or sha256", p.Package)
			}
			rel := aptFileRel(m.Name, p.Filename)
			if !seen[rel] {
				return fmt.Errorf("apt package references file not listed in manifest.files: %s", rel)
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: regenerate + publish APT metadata (called on import)
// -----------------------------------------------------------------------------

func (s *HighServer) aptDir() string {
	return filepath.Join(s.downloadDir, "apt")
}

// publishApt regenerates and republishes the APT repository metadata for every
// mirror in a freshly imported bundle. It is called after the bundle's files
// are installed. Metadata is rebuilt from the accumulated stanzas of packages
// whose .deb is actually present — the transferred Release/Packages are never
// served as-is.
func (s *HighServer) publishApt(m *AptManifest) error {
	if m == nil {
		return nil
	}
	for _, mirror := range m.Mirrors {
		if err := s.publishAptMirror(mirror); err != nil {
			return fmt.Errorf("publish apt mirror %s: %w", mirror.Name, err)
		}
	}
	return nil
}

// mergeAptMirror merges a newly imported mirror's packages into the persistent
// per-mirror index on disk (deduplicated by Filename) and returns the union.
func (s *HighServer) mergeAptMirror(mirror AptMirror) (AptMirror, error) {
	indexPath := filepath.Join(s.aptDir(), mirror.Name, "index.json")
	merged := AptMirror{Name: mirror.Name, URI: mirror.URI, Suite: mirror.Suite}
	if b, err := os.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(b, &merged); err != nil {
			return AptMirror{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return AptMirror{}, err
	}
	merged.URI, merged.Suite = mirror.URI, mirror.Suite
	merged.Components = unionStrings(merged.Components, mirror.Components)
	merged.Architectures = unionStrings(merged.Architectures, mirror.Architectures)

	byFile := map[string]int{}
	for i, p := range merged.Packages {
		byFile[p.Filename] = i
	}
	for _, p := range mirror.Packages {
		if i, ok := byFile[p.Filename]; ok {
			merged.Packages[i] = p
		} else {
			byFile[p.Filename] = len(merged.Packages)
			merged.Packages = append(merged.Packages, p)
		}
	}
	sort.Slice(merged.Packages, func(i, j int) bool { return merged.Packages[i].Filename < merged.Packages[j].Filename })
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return AptMirror{}, err
	}
	if err := writeBytesAtomic(indexPath, out, 0o644); err != nil {
		return AptMirror{}, err
	}
	return merged, nil
}

func (s *HighServer) publishAptMirror(mirror AptMirror) error {
	merged, err := s.mergeAptMirror(mirror)
	if err != nil {
		return err
	}
	mirrorRoot := filepath.Join(s.aptDir(), merged.Name)
	distDir := filepath.Join(mirrorRoot, "dists", merged.Suite)

	var metas []aptMeta
	for _, comp := range merged.Components {
		for _, arch := range merged.Architectures {
			pkgs := s.presentAptStanzas(mirrorRoot, merged.Packages, comp, arch)
			if len(pkgs) == 0 {
				continue
			}
			plain := []byte(strings.Join(pkgs, "\n") + "\n")
			gz, err := gzipBytes(plain)
			if err != nil {
				return err
			}
			metas = append(metas,
				aptMeta{rel: comp + "/binary-" + arch + "/Packages", data: plain},
				aptMeta{rel: comp + "/binary-" + arch + "/Packages.gz", data: gz})
		}
	}
	for _, me := range metas {
		if err := writeBytesAtomic(filepath.Join(distDir, filepath.FromSlash(me.rel)), me.data, 0o644); err != nil {
			return err
		}
	}
	release := buildAptRelease(merged, metas)
	if err := writeBytesAtomic(filepath.Join(distDir, "Release"), release, 0o644); err != nil {
		return err
	}
	return s.signAptRelease(distDir)
}

// presentAptStanzas returns the Packages stanzas for the given component and
// architecture whose .deb file is present in the pool (arch "all" packages are
// included in every architecture's index).
func (s *HighServer) presentAptStanzas(mirrorRoot string, pkgs []AptPackage, comp, arch string) []string {
	var out []string
	for _, p := range pkgs {
		if p.Component != comp {
			continue
		}
		if p.Architecture != arch && p.Architecture != "all" {
			continue
		}
		if !fileExists(filepath.Join(mirrorRoot, filepath.FromSlash(p.Filename))) {
			continue
		}
		out = append(out, strings.TrimSpace(p.Stanza))
	}
	return out
}

// aptMeta is one regenerated repository metadata file (its archive-relative
// path and bytes) awaiting checksum entries in the Release file.
type aptMeta struct {
	rel  string
	data []byte
}

// buildAptRelease renders a Release file with MD5Sum/SHA1/SHA256 sections over
// the regenerated index files.
func buildAptRelease(mirror AptMirror, metas []aptMeta) []byte {
	var b strings.Builder
	b.WriteString("Origin: ArtiGate\n")
	fmt.Fprintf(&b, "Label: %s\n", mirror.Name)
	fmt.Fprintf(&b, "Suite: %s\n", mirror.Suite)
	fmt.Fprintf(&b, "Codename: %s\n", mirror.Suite)
	fmt.Fprintf(&b, "Components: %s\n", strings.Join(mirror.Components, " "))
	fmt.Fprintf(&b, "Architectures: %s\n", strings.Join(mirror.Architectures, " "))
	fmt.Fprintf(&b, "Date: %s\n", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC"))
	writeReleaseHashes(&b, "MD5Sum", metas, func(d []byte) string { h := md5.Sum(d); return hex.EncodeToString(h[:]) }) //nolint:gosec // legacy APT checksum
	writeReleaseHashes(&b, "SHA1", metas, func(d []byte) string { h := sha1.Sum(d); return hex.EncodeToString(h[:]) })  //nolint:gosec // legacy APT checksum
	writeReleaseHashes(&b, "SHA256", metas, func(d []byte) string { h := sha256.Sum256(d); return hex.EncodeToString(h[:]) })
	return []byte(b.String())
}

func writeReleaseHashes(b *strings.Builder, name string, metas []aptMeta, sum func([]byte) string) {
	fmt.Fprintf(b, "%s:\n", name)
	for _, me := range metas {
		fmt.Fprintf(b, " %s %d %s\n", sum(me.data), len(me.data), me.rel)
	}
}

// signAptRelease clearsigns Release into InRelease and writes a detached
// Release.gpg when a high-side APT signing key is configured. Without a key the
// repository is published unsigned (clients use [trusted=yes] or Signed-By-less
// sources); this keeps ArtiGate's ed25519 bundle signature as the transfer
// integrity guarantee.
func (s *HighServer) signAptRelease(distDir string) error {
	key := s.cfg.AptGPGKey
	if key == "" {
		// No high-side APT key: remove any stale signatures and publish unsigned.
		_ = os.Remove(filepath.Join(distDir, "InRelease"))
		_ = os.Remove(filepath.Join(distDir, "Release.gpg"))
		return nil
	}
	relPath := filepath.Join(distDir, "Release")
	inrel := filepath.Join(distDir, "InRelease")
	relgpg := filepath.Join(distDir, "Release.gpg")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	clearCmd := exec.CommandContext(ctx, "gpg", "--batch", "--yes", "--armor", "--local-user", key,
		"--clearsign", "--output", inrel, relPath)
	if out, err := clearCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gpg clearsign Release: %w\n%s", err, tailBytes(out, 2048))
	}
	detach := exec.CommandContext(ctx, "gpg", "--batch", "--yes", "--armor", "--local-user", key,
		"--detach-sign", "--output", relgpg, relPath)
	if out, err := detach.CombinedOutput(); err != nil {
		return fmt.Errorf("gpg detach-sign Release: %w\n%s", err, tailBytes(out, 2048))
	}
	return nil
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------------
// High side: serve the static APT repository under /apt/
// -----------------------------------------------------------------------------

func (s *HighServer) serveApt(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/apt" && !strings.HasPrefix(p, "/apt/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, "/apt"), "/")
	if rel == "" || validateRelPath(rel) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.aptDir(), filepath.FromSlash(rel))
	if !safeJoin(s.aptDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	serveFile(w, r, abs)
	return true
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listAptMirrors reads each mirror's persistent index and returns UIModule
// entries keyed by "<mirror>/<package>", so the generic segment-tree builder
// renders mirror -> package -> versions.
func (s *HighServer) listAptMirrors() ([]UIModule, error) {
	entries, err := os.ReadDir(s.aptDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byKey := map[string]map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			s.collectAptVersions(e.Name(), byKey)
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

// collectAptVersions records, into byKey ("<mirror>/<package>" -> versions),
// every package in a mirror's index whose .deb is present on disk.
func (s *HighServer) collectAptVersions(name string, byKey map[string]map[string]bool) {
	mirror, err := s.loadAptIndex(name)
	if err != nil {
		return
	}
	for _, p := range mirror.Packages {
		if !fileExists(filepath.Join(s.aptDir(), name, filepath.FromSlash(p.Filename))) {
			continue
		}
		key := name + "/" + p.Package
		if byKey[key] == nil {
			byKey[key] = map[string]bool{}
		}
		byKey[key][p.Version] = true
	}
}

func (s *HighServer) loadAptIndex(name string) (AptMirror, error) {
	b, err := os.ReadFile(filepath.Join(s.aptDir(), name, "index.json"))
	if err != nil {
		return AptMirror{}, err
	}
	var m AptMirror
	if err := json.Unmarshal(b, &m); err != nil {
		return AptMirror{}, err
	}
	return m, nil
}

// aptDetail describes one package version for the dashboard. spec is
// "<mirror>/<package>@<version>".
func (s *HighServer) aptDetail(spec string) (UIDetail, error) {
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
	mirror, err := s.loadAptIndex(mirrorName)
	if err != nil {
		return UIDetail{}, errors.New("mirror not found")
	}
	fields := []UIDetailField{
		{Label: "Mirror", Value: mirrorName, Mono: true},
		{Label: "Package", Value: pkgName, Mono: true},
		{Label: "Version", Value: version, Mono: true},
		{Label: "Suite", Value: mirror.Suite},
	}
	found := false
	for _, p := range mirror.Packages {
		if p.Package != pkgName || p.Version != version {
			continue
		}
		found = true
		fields = append(fields,
			UIDetailField{Label: p.Architecture + " file", Value: path.Base(p.Filename), Mono: true},
			UIDetailField{Label: "Size", Value: formatBytes(p.Size)},
			UIDetailField{Label: "SHA-256", Value: p.SHA256, Mono: true},
			UIDetailField{Label: "Path", Value: "/apt/" + mirrorName + "/" + p.Filename, Mono: true})
	}
	if !found {
		return UIDetail{}, errors.New("version not found")
	}
	return UIDetail{Title: pkgName, Subtitle: version, Fields: fields}, nil
}
