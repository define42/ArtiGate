package main

// APT (Debian/Ubuntu deb) ecosystem adapter — full mirror mode for a single
// upstream archive root (one URI carrying one or more suites, like a real APT
// archive: "noble noble-updates noble-security").
//
// Low side: for each suite, fetch dists/<suite>/InRelease (optionally
// GPG-verify it against a caller-supplied keyring via gpgv), read the Release
// checksums, download and verify the binary Packages index for each
// component/architecture, then download every referenced .deb and verify its
// SHA256 against the index. Suites share the archive's pool/, so a .deb listed
// in several suites is staged once. The .deb files are packed into the standard
// signed ArtiGate bundle; each package's Packages stanza is stored in the
// manifest together with the suite it belongs to.
//
// High side: on import, regenerate Packages/Packages.gz and a Release file per
// suite from the accumulated stanzas (only for .deb files actually present) and
// write them under dists/<suite>, optionally clearsigning InRelease with a
// high-side APT key; the repository is then served as static files. The high
// side never trusts the transferred Release/Packages as final — it rebuilds
// them from what it holds.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"  //nolint:gosec // APT metadata carries MD5Sum for legacy clients, not a security control
	"crypto/sha1" //nolint:gosec // APT metadata carries SHA1 for legacy clients, not a security control
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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
	Name     string       `json:"name"`
	URI      string       `json:"uri"`
	Suites   []AptSuite   `json:"suites"`
	SignedBy string       `json:"signed_by,omitempty"`
	Packages []AptPackage `json:"packages"`
}

// AptSuite is one suite of a mirror together with the components and
// architectures it was collected with. They are recorded per suite — not
// mirror-wide — so suites collected with different settings each publish and
// advertise exactly what they hold, and the "Set me up" guide can emit an
// exact stanza for whichever release the user picks.
type AptSuite struct {
	Name          string   `json:"name"`
	Components    []string `json:"components"`
	Architectures []string `json:"architectures"`
}

type AptPackage struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Suite        string `json:"suite"`
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
	Suites        []string `json:"suites"`
	Components    []string `json:"components"`
	Architectures []string `json:"architectures"`
	SignedBy      string   `json:"signed_by"`
	SourceList    string   `json:"source_list"`
	// NewestOnly keeps only the highest version of each package (default true
	// when the field is absent); set it false to mirror every version in the
	// index.
	NewestOnly *bool `json:"newest_only,omitempty"`
	// Force disables export dedup for this collect: every .deb is downloaded
	// and packed even when already forwarded, producing a full self-contained
	// bundle (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// defaultTrue resolves an optional bool flag that defaults to true when absent.
func defaultTrue(p *bool) bool { return p == nil || *p }

// aptMirrorConfig is the resolved, validated mirror to collect.
type aptMirrorConfig struct {
	Name          string
	URI           string
	Suites        []string
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
	newest := defaultTrue(req.NewestOnly)
	// Hold only the apt stream's lock across the whole mirror->write->commit, so
	// a long APT fetch does not block Python/Go/Maven/RPM collects.
	mu := s.streamLock(streamApt)
	mu.Lock()
	defer mu.Unlock()

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
	prior := s.priorFileCheck(streamApt, req.Force)
	emitProgress(ctx, "Mirroring %d APT source(s)…", len(configs))
	for _, cfg := range configs {
		mirror, mf, err := s.mirrorAptRepo(ctx, cfg, stageRoot, newest, prior)
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

	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	return s.exportIfNew(ctx, streamApt, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeAptBundle(ctx, seq, stageRoot, files, mirrors)
	})
}

// mirrorAptRepo downloads and verifies the Release, indexes, and every .deb of
// every suite of one mirror, staging the .deb files under stageRoot and
// returning the mirror metadata plus the manifest file list. Suites share the
// archive pool, so seenFile dedupes .debs listed in more than one suite.
func (s *LowServer) mirrorAptRepo(ctx context.Context, cfg aptMirrorConfig, stageRoot string, newestOnly bool, prior func(path, sha256 string) bool) (AptMirror, []ManifestFile, error) {
	base := strings.TrimRight(cfg.URI, "/")
	mirror := AptMirror{Name: cfg.Name, URI: base, SignedBy: filepath.Base(cfg.SignedBy)}
	var files []ManifestFile
	seenFile := map[string]bool{}

	for _, suite := range cfg.Suites {
		mirror.Suites = append(mirror.Suites, AptSuite{
			Name: suite, Components: cfg.Components, Architectures: cfg.Architectures,
		})
		distBase := base + "/dists/" + suite

		emitProgress(ctx, "→ %s %s: fetching Release and Packages indexes…", cfg.Name, suite)
		releaseBytes, err := s.fetchAptRelease(ctx, distBase, cfg.SignedBy)
		if err != nil {
			return AptMirror{}, nil, fmt.Errorf("suite %s: %w", suite, err)
		}
		stanzas := parseDeb822(releaseBytes)
		if len(stanzas) == 0 {
			return AptMirror{}, nil, fmt.Errorf("suite %s: empty Release file", suite)
		}
		checksums := releaseIndexChecksums(stanzas[0])

		for _, comp := range cfg.Components {
			for _, arch := range cfg.Architectures {
				cf, pkgs, err := s.collectAptIndex(ctx, base, distBase, cfg.Name, suite, comp, arch, checksums, stageRoot, seenFile, newestOnly, prior)
				if err != nil {
					return AptMirror{}, nil, err
				}
				files = append(files, cf...)
				mirror.Packages = append(mirror.Packages, pkgs...)
			}
		}
	}
	return mirror, files, nil
}

// collectAptIndex fetches one suite/component/architecture Packages index and
// downloads every referenced .deb, returning the new manifest files (deduped
// via seenFile) and the parsed package records.
func (s *LowServer) collectAptIndex(ctx context.Context, base, distBase, name, suite, comp, arch string, checksums map[string]aptChecksum, stageRoot string, seenFile map[string]bool, newestOnly bool, prior func(path, sha256 string) bool) ([]ManifestFile, []AptPackage, error) {
	pkgs, err := s.fetchAptPackagesIndex(ctx, distBase, suite, comp, arch, checksums)
	if err != nil {
		return nil, nil, err
	}
	if newestOnly {
		pkgs = filterNewestApt(pkgs)
	}
	emitProgress(ctx, "  %s %s/%s/%s: %d package(s)", name, suite, comp, arch, len(pkgs))
	var files []ManifestFile
	for _, pkg := range pkgs {
		mf, err := s.downloadAptDeb(ctx, base, name, pkg, stageRoot, prior)
		if err != nil {
			return nil, nil, err
		}
		if !seenFile[mf.Path] {
			if mf.Prior {
				emitProgress(ctx, "    ≡ %s already forwarded (download skipped)", path.Base(mf.Path))
			} else {
				emitProgress(ctx, "    ↓ %s (%s)", path.Base(mf.Path), formatBytes(mf.Size))
			}
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
	inrelease, inErr := httpGetBytes(ctx, distBase+"/InRelease", maxSignedMetaBytes)
	if inErr == nil {
		if signedBy != "" {
			if err := gpgVerifyClearsigned(ctx, inrelease, signedBy); err != nil {
				return nil, fmt.Errorf("verify InRelease: %w", err)
			}
		}
		return stripClearsign(inrelease), nil
	}
	// Fall back to detached Release + Release.gpg.
	release, err := httpGetBytes(ctx, distBase+"/Release", maxSignedMetaBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch InRelease/Release: %w", err)
	}
	if signedBy != "" {
		sig, err := httpGetBytes(ctx, distBase+"/Release.gpg", maxSignedMetaBytes)
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
// suite/component/architecture and parses its stanzas into AptPackage records.
func (s *LowServer) fetchAptPackagesIndex(ctx context.Context, distBase, suite, comp, arch string, checksums map[string]aptChecksum) ([]AptPackage, error) {
	dir := comp + "/binary-" + arch
	// Prefer gzip (stdlib) then plain; the index path is validated against the
	// signed Release checksums.
	candidates := []struct {
		rel        string
		decompress func([]byte) ([]byte, error)
	}{
		{dir + "/Packages.gz", func(b []byte) ([]byte, error) { return gunzip(b, maxIndexPlainBytes) }},
		{dir + "/Packages", func(b []byte) ([]byte, error) { return b, nil }},
	}
	for _, c := range candidates {
		want, ok := checksums[c.rel]
		if !ok {
			continue
		}
		raw, err := httpGetBytes(ctx, distBase+"/"+c.rel, maxIndexFetchBytes)
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
		return parseAptPackages(plain, suite, comp), nil
	}
	return nil, fmt.Errorf("no Packages index for %s/%s in Release", suite, dir)
}

// downloadAptDeb fetches one .deb, verifying its SHA256 against the index as
// it streams to the bundle's apt/<mirror>/<filename> staging path (a .deb is
// never buffered in memory). A .deb whose index-declared SHA256 and size this
// stream has already forwarded is not downloaded at all — it becomes a prior
// manifest reference (the signed index supplies everything the manifest entry
// needs).
func (s *LowServer) downloadAptDeb(ctx context.Context, base, mirror string, pkg AptPackage, stageRoot string, prior func(path, sha256 string) bool) (ManifestFile, error) {
	if err := validateRelPath(pkg.Filename); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe package Filename %q: %w", pkg.Filename, err)
	}
	if pkg.Size > 0 && prior(aptFileRel(mirror, pkg.Filename), pkg.SHA256) {
		return ManifestFile{Path: aptFileRel(mirror, pkg.Filename), SHA256: pkg.SHA256, Size: pkg.Size, Prior: true}, nil
	}
	rel := aptFileRel(mirror, pkg.Filename)
	if err := validateRelPath(rel); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe staging path %q: %w", rel, err)
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadVerifiedFile(ctx, base+"/"+pkg.Filename, abs, pkg.Size, "sha256", pkg.SHA256)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("%s: %w", pkg.Filename, err)
	}
	return ManifestFile{Path: rel, SHA256: sum, Size: size}, nil
}

// parseAptPackages turns a decompressed Packages index into AptPackage records,
// keeping the raw stanza for high-side regeneration. Each package's own
// Architecture comes from its stanza (it may be "all").
func parseAptPackages(data []byte, suite, comp string) []AptPackage {
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
			Suite:        suite,
			Component:    comp,
			Filename:     m["Filename"],
			SHA256:       m["SHA256"],
			Size:         size,
			Stanza:       strings.TrimSpace(block) + "\n",
		})
	}
	return pkgs
}

// filterNewestApt keeps only the highest-versioned package per (Package,
// Architecture), by Debian version ordering. The first occurrence position of
// each kept package is preserved.
func filterNewestApt(pkgs []AptPackage) []AptPackage {
	idx := map[string]int{}
	out := make([]AptPackage, 0, len(pkgs))
	for _, p := range pkgs {
		key := p.Package + "\x00" + p.Architecture
		if i, ok := idx[key]; ok {
			if debVersionCompare(p.Version, out[i].Version) > 0 {
				out[i] = p
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, p)
	}
	return out
}

// debVersionCompare compares two Debian package versions, returning -1, 0, or 1.
// It follows dpkg's ordering: numeric epoch first, then upstream version, then
// the Debian revision, each compared with debVerRevCmp.
func debVersionCompare(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		return cmpSign(ea - eb)
	}
	if c := debVerRevCmp(ua, ub); c != 0 {
		return c
	}
	return debVerRevCmp(ra, rb)
}

// splitDebVersion splits "[epoch:]upstream[-revision]". A missing epoch is 0 and
// a missing revision is empty.
func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			epoch = e
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// debCharOrder maps a byte to its dpkg sort weight: '~' sorts before everything
// (including end-of-string, weight 0), letters keep ASCII order, and any other
// non-digit sorts after letters. Digits are handled separately (weight 0).
func debCharOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// debOrderAt returns the sort weight of a[i], or the end-of-string weight (0).
func debOrderAt(a string, i int) int {
	if i >= len(a) {
		return 0
	}
	return debCharOrder(a[i])
}

// debVerRevCmp compares two version parts with dpkg's verrevcmp algorithm.
func debVerRevCmp(a, b string) int {
	ai, bi := 0, 0
	for ai < len(a) || bi < len(b) {
		if c := debCmpNonDigits(a, b, &ai, &bi); c != 0 {
			return c
		}
		if c := debCmpDigits(a, b, &ai, &bi); c != 0 {
			return c
		}
	}
	return 0
}

// debCmpNonDigits advances over the leading non-digit run of both strings,
// comparing by dpkg order, and returns non-zero on the first difference.
func debCmpNonDigits(a, b string, ai, bi *int) int {
	for (*ai < len(a) && !asciiDigit(a[*ai])) || (*bi < len(b) && !asciiDigit(b[*bi])) {
		if ac, bc := debOrderAt(a, *ai), debOrderAt(b, *bi); ac != bc {
			return cmpSign(ac - bc)
		}
		*ai++
		*bi++
	}
	return 0
}

// debCmpDigits compares the leading digit run of both strings: leading zeros are
// skipped, then the longer number wins, else the first differing digit.
func debCmpDigits(a, b string, ai, bi *int) int {
	for *ai < len(a) && a[*ai] == '0' {
		*ai++
	}
	for *bi < len(b) && b[*bi] == '0' {
		*bi++
	}
	firstDiff := 0
	for *ai < len(a) && asciiDigit(a[*ai]) && *bi < len(b) && asciiDigit(b[*bi]) {
		if firstDiff == 0 {
			firstDiff = int(a[*ai]) - int(b[*bi])
		}
		*ai++
		*bi++
	}
	if *ai < len(a) && asciiDigit(a[*ai]) {
		return 1
	}
	if *bi < len(b) && asciiDigit(b[*bi]) {
		return -1
	}
	return cmpSign(firstDiff)
}

func asciiDigit(c byte) bool { return c >= '0' && c <= '9' }

func cmpSign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
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

func (s *LowServer) writeAptBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, mirrors []AptMirror) (ExportResult, error) {
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
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
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

// Memory-bound caps for APT/RPM mirror fetches. Package payloads and staged
// metadata files stream to disk through downloadVerifiedFile — the multi-GiB
// cap below bounds disk, never memory. Only small, parsed metadata is fetched
// into memory, and every decompression is output-capped so a hostile index
// cannot balloon into an OOM (decompression bomb).
const (
	maxMirroredFileBytes = 8 << 30  // a streamed file with no index-declared size (disk-bound backstop)
	maxSignedMetaBytes   = 16 << 20 // Release/InRelease/Release.gpg and repomd.xml(.asc), parsed in memory
	maxIndexFetchBytes   = 1 << 30  // a (compressed) Packages/primary index held in memory for parsing
	maxIndexPlainBytes   = 2 << 30  // decompressed index bytes — gzip/xz decompression-bomb guard
)

// httpGetBytes fetches rawURL fully into memory, failing beyond limit. Only
// small metadata that must be parsed goes through here; package payloads use
// downloadVerifiedFile, which streams to disk.
func httpGetBytes(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	r := newProgressReader(ctx, resp.Body, dlNameFromURL(rawURL), resp.ContentLength)
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: response exceeds the %s cap", rawURL, formatBytes(limit))
	}
	return body, nil
}

// downloadVerifiedFile streams rawURL to abs while hashing, so a multi-GiB
// package never has to fit in memory (the same discipline as
// writeVerifiedBlob for container layers). The repo-declared checksum
// (checksumType: sha256/sha512/sha1) is verified as the bytes arrive; when the
// index declares a size (wantSize > 0) the byte count must match it exactly,
// otherwise the stream is capped at maxMirroredFileBytes. On any failure the
// partial file is removed. It returns the file's SHA-256 and size for the
// bundle manifest.
func downloadVerifiedFile(ctx context.Context, rawURL, abs string, wantSize int64, checksumType, checksum string) (string, int64, error) {
	verifier, manifestSHA, writers, err := newDownloadHashers(checksumType)
	if err != nil {
		return "", 0, err
	}

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
	limit := wantSize
	if limit <= 0 {
		limit = maxMirroredFileBytes
	}
	total := wantSize
	if total <= 0 {
		total = resp.ContentLength
	}
	r := newProgressReader(ctx, resp.Body, dlNameFromURL(rawURL), total)
	n, copyErr := io.Copy(io.MultiWriter(append(writers, f)...), io.LimitReader(r, limit+1))
	if err := errors.Join(copyErr, f.Close()); err != nil {
		_ = os.Remove(abs)
		return "", 0, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if err := checkDownloadResult(n, wantSize, limit, verifier, checksumType, checksum); err != nil {
		_ = os.Remove(abs)
		return "", 0, err
	}
	return hex.EncodeToString(manifestSHA.Sum(nil)), n, nil
}

// newDownloadHashers builds the hashers a streamed download writes through: a
// verifier for the repo-declared checksum type, and the SHA-256 recorded in
// the bundle manifest. When the repo checksum already is SHA-256 the two are
// the same hasher; otherwise a second SHA-256 is added.
func newDownloadHashers(checksumType string) (verifier, manifestSHA hash.Hash, writers []io.Writer, err error) {
	verifier, err = newRepoHash(checksumType)
	if err != nil {
		return nil, nil, nil, err
	}
	manifestSHA = verifier
	writers = []io.Writer{verifier}
	if algo := strings.ToLower(strings.TrimSpace(checksumType)); algo != "" && algo != "sha256" {
		manifestSHA = sha256.New()
		writers = append(writers, manifestSHA)
	}
	return verifier, manifestSHA, writers, nil
}

// checkDownloadResult validates a completed stream: the byte count against the
// index-declared size (or the cap when none was declared), then the accumulated
// checksum against the repo-declared value.
func checkDownloadResult(n, wantSize, limit int64, verifier hash.Hash, checksumType, checksum string) error {
	switch {
	case wantSize > 0 && n != wantSize:
		return fmt.Errorf("size mismatch: got %d want %d", n, wantSize)
	case wantSize <= 0 && n > limit:
		return fmt.Errorf("response exceeds the %s cap", formatBytes(limit))
	}
	if got := hex.EncodeToString(verifier.Sum(nil)); !strings.EqualFold(got, strings.TrimSpace(checksum)) {
		return fmt.Errorf("%s mismatch: got %s want %s", orDefault(strings.ToLower(checksumType), "sha256"), got, checksum)
	}
	return nil
}

// newRepoHash returns the hash implementing a repo-declared checksum type.
// ArtiGate's own bundle integrity always uses SHA-256; sha1 is accepted only
// because legacy repositories still declare it.
func newRepoHash(algo string) (hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "sha256", "":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	case "sha1", "sha":
		return sha1.New(), nil //nolint:gosec // verifying a legacy repo-declared checksum
	default:
		return nil, fmt.Errorf("unsupported checksum type %q", algo)
	}
}

func verifySHA256(data []byte, want string) error {
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != strings.ToLower(strings.TrimSpace(want)) {
		return fmt.Errorf("sha256 mismatch: got %x want %s", got, want)
	}
	return nil
}

// gunzip decompresses b, refusing to expand beyond limit bytes — repo indexes
// are parsed in memory, so a decompression bomb must fail instead of OOMing.
func gunzip(b []byte, limit int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("decompressed data exceeds the %s cap", formatBytes(limit))
	}
	return out, nil
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
			Name: req.Name, URI: req.URI, Suites: req.Suites,
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
			return nil, fmt.Errorf("duplicate mirror name %q; combine the suites of same-URI stanzas into one stanza (Suites: a b c), or give each source a distinct name", vc.Name)
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
			Suites:        strings.Fields(m["Suites"]),
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

// firstField returns the first whitespace-separated token of s (a deb822 URIs
// field usually carries a single archive root for a mirror).
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
	cfg.Suites = dedupeStrings(cfg.Suites)
	if len(cfg.Suites) == 0 {
		return aptMirrorConfig{}, errors.New("apt mirror requires at least one suite")
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
	for _, tok := range append(append(append([]string{}, cfg.Suites...), cfg.Components...), cfg.Architectures...) {
		if !validRepoToken(tok) {
			return aptMirrorConfig{}, fmt.Errorf("invalid suite/component/architecture token %q", tok)
		}
	}
	return cfg, nil
}

// validRepoToken reports whether tok is a safe single path segment for an APT
// suite/component/architecture. mavenTokenRE already excludes '/' and the empty
// string; this additionally rejects "." and ".." so a token can never traverse
// out of the dists/<suite>/<component> tree when the high side turns it into a
// filesystem path while regenerating repository metadata.
func validRepoToken(tok string) bool {
	return mavenTokenRE.MatchString(tok) && tok != "." && tok != ".."
}

// dedupeStrings drops empty and repeated tokens, keeping first-occurrence order
// (unlike unionStrings, which sorts).
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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

// validateAptMirrors checks that every mirror carries publishable suites (safe
// path tokens, since they become dists/<suite> directories), that every package
// belongs to one of them, and that every named .deb appears in the manifest's
// overall file set.
func validateAptMirrors(mirrors []AptMirror, seen map[string]bool) error {
	for _, m := range mirrors {
		if err := validateAptMirror(m, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateAptMirror(m AptMirror, seen map[string]bool) error {
	if m.Name == "" || len(m.Suites) == 0 {
		return errors.New("apt mirror missing name or suites")
	}
	// The mirror name becomes a path component under aptDir() on publish, so it
	// must be a single safe segment. Validate it here — on the untrusted import
	// side — exactly as the low side does at collect time (validateRelPath plus
	// no separator); a bundle whose name is ".." must never reach a filepath.Join
	// that would place regenerated metadata (or an os.RemoveAll) above aptDir().
	if err := validateRelPath(m.Name); err != nil || strings.ContainsRune(m.Name, '/') {
		return fmt.Errorf("invalid apt mirror name %q", m.Name)
	}
	suites := map[string]bool{}
	for _, suite := range m.Suites {
		if len(suite.Components) == 0 || len(suite.Architectures) == 0 {
			return fmt.Errorf("apt suite %q missing components or architectures", suite.Name)
		}
		for _, tok := range append(append([]string{suite.Name}, suite.Components...), suite.Architectures...) {
			if !validRepoToken(tok) {
				return fmt.Errorf("invalid apt suite/component/architecture token %q", tok)
			}
		}
		suites[suite.Name] = true
	}
	for _, p := range m.Packages {
		if err := validateAptPackage(m.Name, p, suites, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateAptPackage(mirrorName string, p AptPackage, suites, seen map[string]bool) error {
	if p.Filename == "" || p.SHA256 == "" {
		return fmt.Errorf("apt package %s missing filename or sha256", p.Package)
	}
	if !suites[p.Suite] {
		return fmt.Errorf("apt package %s: suite %q not among the mirror's suites", p.Package, p.Suite)
	}
	if rel := aptFileRel(mirrorName, p.Filename); !seen[rel] {
		return fmt.Errorf("apt package references file not listed in manifest.files: %s", rel)
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
// per-mirror index on disk and returns the union. Suites accumulate like
// packages do (per-suite components/architectures are unioned); package entries
// are keyed by (suite, filename) since one .deb can legitimately be listed in
// several suites, while its pool file is stored once.
func (s *HighServer) mergeAptMirror(mirror AptMirror) (AptMirror, error) {
	indexPath := filepath.Join(s.aptDir(), mirror.Name, "index.json")
	merged := AptMirror{Name: mirror.Name, URI: mirror.URI}
	if b, err := os.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(b, &merged); err != nil {
			return AptMirror{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return AptMirror{}, err
	}
	merged.URI = mirror.URI
	merged.Suites = mergeAptSuites(merged.Suites, mirror.Suites)

	pkgKey := func(p AptPackage) string { return p.Suite + "\x00" + p.Filename }
	byKey := map[string]int{}
	for i, p := range merged.Packages {
		byKey[pkgKey(p)] = i
	}
	for _, p := range mirror.Packages {
		if i, ok := byKey[pkgKey(p)]; ok {
			merged.Packages[i] = p
		} else {
			byKey[pkgKey(p)] = len(merged.Packages)
			merged.Packages = append(merged.Packages, p)
		}
	}
	sort.Slice(merged.Packages, func(i, j int) bool {
		a, b := merged.Packages[i], merged.Packages[j]
		if a.Suite != b.Suite {
			return a.Suite < b.Suite
		}
		return a.Filename < b.Filename
	})
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return AptMirror{}, err
	}
	if err := writeBytesAtomic(indexPath, out, 0o644); err != nil {
		return AptMirror{}, err
	}
	return merged, nil
}

// mergeAptSuites unions two suite lists by suite name, unioning each suite's
// components and architectures, and returns them sorted by name.
func mergeAptSuites(a, b []AptSuite) []AptSuite {
	byName := map[string]int{}
	out := append([]AptSuite{}, a...)
	for i, s := range out {
		byName[s.Name] = i
	}
	for _, s := range b {
		if i, ok := byName[s.Name]; ok {
			out[i].Components = unionStrings(out[i].Components, s.Components)
			out[i].Architectures = unionStrings(out[i].Architectures, s.Architectures)
		} else {
			byName[s.Name] = len(out)
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *HighServer) publishAptMirror(mirror AptMirror) error {
	merged, err := s.mergeAptMirror(mirror)
	if err != nil {
		return err
	}
	mirrorRoot := filepath.Join(s.aptDir(), merged.Name)
	// Containment backstop, independent of validateAptMirror: the mirror name is
	// a path component here, and publishAptSuite/pruneAptDists both write files
	// and os.RemoveAll under mirrorRoot, so refuse a name that escapes aptDir().
	if !safeJoin(s.aptDir(), mirrorRoot) {
		return fmt.Errorf("unsafe apt mirror name %q", merged.Name)
	}
	names := make([]string, 0, len(merged.Suites))
	for _, suite := range merged.Suites {
		if err := s.publishAptSuite(mirrorRoot, merged, suite); err != nil {
			return fmt.Errorf("suite %s: %w", suite.Name, err)
		}
		names = append(names, suite.Name)
	}
	return pruneAptDists(mirrorRoot, names)
}

// publishAptSuite regenerates dists/<suite> (Packages, Packages.gz, Release,
// optional signatures) for one suite of a merged mirror, over the suite's own
// components and architectures.
func (s *HighServer) publishAptSuite(mirrorRoot string, merged AptMirror, suite AptSuite) error {
	distDir := filepath.Join(mirrorRoot, "dists", suite.Name)

	var metas []aptMeta
	for _, comp := range suite.Components {
		for _, arch := range suite.Architectures {
			pkgs := s.presentAptStanzas(mirrorRoot, merged.Packages, suite.Name, comp, arch)
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
	release := buildAptRelease(merged, suite, metas)
	if err := writeBytesAtomic(filepath.Join(distDir, "Release"), release, 0o644); err != nil {
		return err
	}
	return s.signAptRelease(distDir)
}

// pruneAptDists removes dists/<x> trees that are not among the mirror's suites.
// Everything under dists/ is regenerated from the index on every publish, so
// anything else is stale (e.g. left over from an older layout or a renamed
// suite) and would otherwise be served frozen forever.
func pruneAptDists(mirrorRoot string, suites []string) error {
	distsRoot := filepath.Join(mirrorRoot, "dists")
	entries, err := os.ReadDir(distsRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, suite := range suites {
		keep[suite] = true
	}
	for _, e := range entries {
		if !keep[e.Name()] {
			if err := os.RemoveAll(filepath.Join(distsRoot, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// presentAptStanzas returns the Packages stanzas for the given suite, component,
// and architecture whose .deb file is present in the pool (arch "all" packages
// are included in every architecture's index).
func (s *HighServer) presentAptStanzas(mirrorRoot string, pkgs []AptPackage, suite, comp, arch string) []string {
	var out []string
	for _, p := range pkgs {
		if p.Suite != suite || p.Component != comp {
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

// buildAptRelease renders one suite's Release file with MD5Sum/SHA1/SHA256
// sections over the regenerated index files. Components/Architectures are the
// suite's own, so clients are never pointed at indexes the suite doesn't have.
func buildAptRelease(mirror AptMirror, suite AptSuite, metas []aptMeta) []byte {
	var b strings.Builder
	b.WriteString("Origin: ArtiGate\n")
	fmt.Fprintf(&b, "Label: %s\n", mirror.Name)
	fmt.Fprintf(&b, "Suite: %s\n", suite.Name)
	fmt.Fprintf(&b, "Codename: %s\n", suite.Name)
	fmt.Fprintf(&b, "Components: %s\n", strings.Join(suite.Components, " "))
	fmt.Fprintf(&b, "Architectures: %s\n", strings.Join(suite.Architectures, " "))
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
// entries keyed by "<mirror>/<suite>/<component>/<package>", so the generic
// segment-tree builder renders mirror -> suite -> component -> package ->
// versions and packages from different suites/components are never mixed.
// aptRepoList returns each mirrored APT repository with the per-suite fields a
// client needs (suite name, components, architectures), for the "Set me up"
// guide's release picker.
func (s *HighServer) aptRepoList() ([]UIRepo, error) {
	entries, err := os.ReadDir(s.aptDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var repos []UIRepo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := s.loadAptIndex(e.Name())
		if err != nil {
			continue
		}
		// Signed when the high side clearsigned InRelease for every suite (one
		// signing key covers the whole mirror, so all-or-nothing in practice).
		signed := len(m.Suites) > 0
		for _, suite := range m.Suites {
			if !fileExists(filepath.Join(s.aptDir(), e.Name(), "dists", suite.Name, "InRelease")) {
				signed = false
				break
			}
		}
		repos = append(repos, UIRepo{Name: e.Name(), Suites: m.Suites, Signed: signed})
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Name < repos[j].Name })
	return repos, nil
}

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

// collectAptVersions records, into byKey
// ("<mirror>/<suite>/<component>/<package>" -> versions), every package in a
// mirror's index whose .deb is present on disk.
func (s *HighServer) collectAptVersions(name string, byKey map[string]map[string]bool) {
	mirror, err := s.loadAptIndex(name)
	if err != nil {
		return
	}
	for _, p := range mirror.Packages {
		if !fileExists(filepath.Join(s.aptDir(), name, filepath.FromSlash(p.Filename))) {
			continue
		}
		key := name + "/" + p.Suite + "/" + p.Component + "/" + p.Package
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
// "<mirror>/<suite>/<component>/<package>@<version>", matching the tree's
// per-suite/per-component nesting.
func (s *HighServer) aptDetail(spec string) (UIDetail, error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return UIDetail{}, errors.New("invalid package@version")
	}
	key, version := spec[:i], spec[i+1:]
	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		return UIDetail{}, errors.New("invalid package path")
	}
	mirrorName, suite, comp, pkgName := parts[0], parts[1], parts[2], parts[3]
	if validateRelPath(mirrorName) != nil {
		return UIDetail{}, errors.New("invalid mirror")
	}
	mirror, err := s.loadAptIndex(mirrorName)
	if err != nil {
		return UIDetail{}, errors.New("mirror not found")
	}
	var fileFields []UIDetailField
	for _, p := range mirror.Packages {
		if p.Suite != suite || p.Component != comp || p.Package != pkgName || p.Version != version {
			continue
		}
		fileFields = append(fileFields,
			UIDetailField{Label: p.Architecture + " file", Value: path.Base(p.Filename), Mono: true},
			UIDetailField{Label: "Size", Value: formatBytes(p.Size)},
			UIDetailField{Label: "SHA-256", Value: p.SHA256, Mono: true},
			UIDetailField{Label: "Path", Value: "/apt/" + mirrorName + "/" + p.Filename, Mono: true})
	}
	if len(fileFields) == 0 {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Mirror", Value: mirrorName, Mono: true},
		{Label: "Suite", Value: suite},
		{Label: "Component", Value: comp},
		{Label: "Package", Value: pkgName, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	fields = append(fields, fileFields...)
	return UIDetail{Title: pkgName, Subtitle: version, Fields: fields}, nil
}
