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
	"bytes"
	"context"
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
	"sort"
	"strconv"
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
	Epoch    string `json:"epoch,omitempty"`
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
			Epoch:    p.Version.Epoch,
			Version:  version,
			Arch:     p.Arch,
			Location: p.Location.Href,
			SHA256:   strings.ToLower(strings.TrimSpace(p.Checksum.Value)),
			Size:     p.Size.Package,
		})
	}
	return out, nil
}

// filterNewestRpm keeps only the highest-EVR package per (Name, Arch). The first
// occurrence position of each kept package is preserved.
func filterNewestRpm(pkgs []RpmPackage) []RpmPackage {
	idx := map[string]int{}
	out := make([]RpmPackage, 0, len(pkgs))
	for _, p := range pkgs {
		key := p.Name + "\x00" + p.Arch
		if i, ok := idx[key]; ok {
			if rpmEVRCompare(p, out[i]) > 0 {
				out[i] = p
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, p)
	}
	return out
}

// rpmEVRCompare compares two packages by RPM EVR ordering: numeric epoch first
// (missing = 0), then version, then release, each via rpmVerCmp.
func rpmEVRCompare(a, b RpmPackage) int {
	if ea, eb := rpmEpoch(a.Epoch), rpmEpoch(b.Epoch); ea != eb {
		return cmpSign(ea - eb)
	}
	va, ra := splitRpmVerRel(a.Version)
	vb, rb := splitRpmVerRel(b.Version)
	if c := rpmVerCmp(va, vb); c != 0 {
		return c
	}
	return rpmVerCmp(ra, rb)
}

func rpmEpoch(e string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(e)); err == nil {
		return n
	}
	return 0
}

// splitRpmVerRel splits the stored "ver[-rel]"; RPM versions and releases never
// contain '-', so the last '-' is the separator.
func splitRpmVerRel(v string) (ver, rel string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func asciiAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func asciiAlnum(c byte) bool { return asciiDigit(c) || asciiAlpha(c) }
func isRpmSep(c byte) bool   { return !asciiAlnum(c) && c != '~' && c != '^' }

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// rpmVerCmp compares two RPM version (or release) strings, returning -1, 0, or 1.
// It implements rpm's rpmvercmp, including the '~' (pre-release) and '^'
// (post-release) separators.
func rpmVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	ai, bi := 0, 0
	for ai < len(a) || bi < len(b) {
		ai, bi = skipRpmSeps(a, ai), skipRpmSeps(b, bi)
		r, decided, advanced := rpmCmpSep(a, b, &ai, &bi)
		if decided {
			return r
		}
		if advanced {
			continue
		}
		if ai >= len(a) || bi >= len(b) {
			break
		}
		if c := rpmCmpSegment(a, b, &ai, &bi); c != 0 {
			return c
		}
	}
	return rpmLeftover(len(a)-ai, len(b)-bi)
}

// skipRpmSeps advances past a run of separator bytes starting at i.
func skipRpmSeps(s string, i int) int {
	for i < len(s) && isRpmSep(s[i]) {
		i++
	}
	return i
}

// rpmLeftover resolves the comparison once one string is exhausted: whichever
// still has characters left is the newer.
func rpmLeftover(aLeft, bLeft int) int {
	switch {
	case aLeft <= 0 && bLeft <= 0:
		return 0
	case aLeft > 0:
		return 1
	default:
		return -1
	}
}

// rpmCmpSep handles the '~' and '^' separators at the current positions. It
// returns a decisive result (decided=true), or reports that a matching separator
// was consumed on both sides (advanced=true) so the caller re-loops.
func rpmCmpSep(a, b string, ai, bi *int) (result int, decided, advanced bool) {
	if r, d, adv := rpmCmpTilde(a, b, ai, bi); d || adv {
		return r, d, adv
	}
	return rpmCmpCaret(a, b, ai, bi)
}

// rpmCmpTilde handles the '~' separator, which sorts before everything.
func rpmCmpTilde(a, b string, ai, bi *int) (result int, decided, advanced bool) {
	ac, bc := byteAt(a, *ai), byteAt(b, *bi)
	if ac != '~' && bc != '~' {
		return 0, false, false
	}
	if ac != '~' {
		return 1, true, false
	}
	if bc != '~' {
		return -1, true, false
	}
	*ai++
	*bi++
	return 0, false, true
}

// rpmCmpCaret handles the '^' separator: like '~', but if one side has ended the
// side carrying the caret is the newer (post-release).
func rpmCmpCaret(a, b string, ai, bi *int) (result int, decided, advanced bool) {
	ac, bc := byteAt(a, *ai), byteAt(b, *bi)
	if ac != '^' && bc != '^' {
		return 0, false, false
	}
	if *ai >= len(a) {
		return -1, true, false
	}
	if *bi >= len(b) {
		return 1, true, false
	}
	if ac != '^' {
		return 1, true, false
	}
	if bc != '^' {
		return -1, true, false
	}
	*ai++
	*bi++
	return 0, false, true
}

// rpmCmpSegment compares the next all-numeric or all-alpha segment of both
// strings, advancing past it. A numeric segment outranks an alpha one.
func rpmCmpSegment(a, b string, ai, bi *int) int {
	numeric := asciiDigit(a[*ai])
	sa := scanRpmSegment(a, ai, numeric)
	sb := scanRpmSegment(b, bi, numeric)
	if sb == "" { // b's segment is the other class: numeric beats alpha
		if numeric {
			return 1
		}
		return -1
	}
	if numeric {
		sa = strings.TrimLeft(sa, "0")
		sb = strings.TrimLeft(sb, "0")
		if len(sa) != len(sb) {
			return cmpSign(len(sa) - len(sb))
		}
	}
	return cmpSign(strings.Compare(sa, sb))
}

// scanRpmSegment consumes and returns the run at *i of the requested class
// (numeric or alpha), advancing *i past it.
func scanRpmSegment(s string, i *int, numeric bool) string {
	start := *i
	for *i < len(s) && ((numeric && asciiDigit(s[*i])) || (!numeric && asciiAlpha(s[*i]))) {
		*i++
	}
	return s[start:*i]
}

// rpmPkgidSet returns the set of package checksums (pkgids) to keep.
func rpmPkgidSet(pkgs []RpmPackage) map[string]bool {
	set := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		set[strings.ToLower(p.SHA256)] = true
	}
	return set
}

// filterPrimaryXML rewrites a primary.xml, keeping only <package> elements whose
// pkgid is in keep, and updates the root packages="N" count. Each kept package's
// XML is preserved verbatim, so no metadata fields are lost.
func filterPrimaryXML(plain []byte, keep map[string]bool) []byte {
	s := string(plain)
	const open, closeTag = "<package", "</package>"
	first := strings.Index(s, open)
	if first < 0 {
		return plain
	}
	var kept []string
	i, lastEnd := first, first
	for {
		start := strings.Index(s[i:], open)
		if start < 0 {
			break
		}
		start += i
		rel := strings.Index(s[start:], closeTag)
		if rel < 0 {
			break
		}
		end := start + rel + len(closeTag)
		block := s[start:end]
		if id := primaryPkgid(block); id == "" || keep[id] {
			kept = append(kept, block)
		}
		i, lastEnd = end, end
	}
	return []byte(setPrimaryCount(s[:first], len(kept)) + strings.Join(kept, "") + s[lastEnd:])
}

// primaryPkgid extracts a <package> block's pkgid (its own SHA256), lowercased.
func primaryPkgid(block string) string {
	i := strings.Index(block, `pkgid="YES"`)
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(block[i:], '>')
	if gt < 0 {
		return ""
	}
	rest := block[i+gt+1:]
	lt := strings.IndexByte(rest, '<')
	if lt < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(rest[:lt]))
}

// setPrimaryCount replaces the packages="N" attribute in a primary.xml header.
func setPrimaryCount(header string, n int) string {
	const key = `packages="`
	i := strings.Index(header, key)
	if i < 0 {
		return header
	}
	j := i + len(key)
	end := strings.IndexByte(header[j:], '"')
	if end < 0 {
		return header
	}
	return header[:j] + strconv.Itoa(n) + header[j+end:]
}

// applyRpmFilters drops packages outside the requested architectures and (when
// newestOnly) older EVRs; when anything was dropped, it rewrites the staged
// primary index (and its manifest and repodata entries) so the served repo
// advertises only the kept packages.
func applyRpmFilters(stageRoot, name, primaryRel string, primaryPlain []byte, pkgs []RpmPackage, files []ManifestFile, repodata []RpmData, arches []string, newestOnly bool) ([]RpmPackage, error) {
	kept := filterRpmArch(pkgs, arches)
	if newestOnly {
		kept = filterNewestRpm(kept)
	}
	if len(kept) == len(pkgs) {
		return pkgs, nil
	}
	newPlain := filterPrimaryXML(primaryPlain, rpmPkgidSet(kept))
	if err := restagePrimary(stageRoot, name, primaryRel, newPlain, files, repodata); err != nil {
		return nil, err
	}
	return kept, nil
}

// filterRpmArch keeps only packages whose architecture is in arches, preserving
// order.
func filterRpmArch(pkgs []RpmPackage, arches []string) []RpmPackage {
	keep := map[string]bool{}
	for _, a := range arches {
		keep[a] = true
	}
	out := make([]RpmPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if keep[p.Arch] {
			out = append(out, p)
		}
	}
	return out
}

// defaultRpmArches resolves a collect's architecture filter: x86_64 plus
// noarch when unset. noarch always belongs next to a hardware architecture —
// x86_64 packages routinely depend on noarch ones.
func defaultRpmArches(arches []string) []string {
	arches = dedupeStrings(arches)
	if len(arches) == 0 {
		return []string{"x86_64", "noarch"}
	}
	return arches
}

// restagePrimary overwrites the staged primary index with the rewritten XML
// (recompressed to match the original href) and updates the matching manifest
// file and the primary <data> entry to the rewritten file's checksums/sizes, so
// the bundle manifest and the high side's regenerated repomd stay consistent.
func restagePrimary(stageRoot, name, primaryRel string, newPlain []byte, files []ManifestFile, repodata []RpmData) error {
	compressed, err := compressByExt(primaryRel, newPlain)
	if err != nil {
		return err
	}
	rel := rpmFileRel(name, primaryRel)
	if err := validateRelPath(rel); err != nil {
		return fmt.Errorf("unsafe staging path %q: %w", rel, err)
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.WriteFile(abs, compressed, 0o644); err != nil {
		return fmt.Errorf("write rewritten primary: %w", err)
	}
	sum, size := sha256Hex(compressed), int64(len(compressed))
	openSum, openSize := sha256Hex(newPlain), int64(len(newPlain))
	for i := range files {
		if files[i].Path == rel {
			files[i].SHA256, files[i].Size = sum, size
		}
	}
	for i := range repodata {
		if repodata[i].Type == "primary" {
			repodata[i].ChecksumType, repodata[i].Checksum = "sha256", sum
			repodata[i].OpenChecksumType, repodata[i].OpenChecksum = "sha256", openSum
			if repodata[i].Size > 0 {
				repodata[i].Size = size
			}
			if repodata[i].OpenSize > 0 {
				repodata[i].OpenSize = openSize
			}
		}
	}
	return nil
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
	// NewestOnly keeps only the highest EVR of each package (default true when
	// absent); set it false to mirror every version in the index.
	NewestOnly *bool `json:"newest_only,omitempty"`
	// Architectures filters which package architectures are mirrored; when
	// empty it defaults to x86_64 plus noarch (noarch packages are
	// dependencies of hardware-arch packages, so x86_64 alone would not
	// resolve). List architectures explicitly to override, e.g. add "i686".
	// The filter applies to every repo in the collect.
	Architectures []string `json:"architectures,omitempty"`
	// Force disables export dedup for this collect: every .rpm is downloaded
	// and packed even when already forwarded, producing a full self-contained
	// bundle (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
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
	newest := defaultTrue(req.NewestOnly)
	arches := defaultRpmArches(req.Architectures)
	// Hold only the rpm stream's lock across the whole mirror->write->commit, so
	// a long RPM fetch does not block Python/Go/Maven/APT collects.
	mu := s.streamLock(streamRpm)
	mu.Lock()
	defer mu.Unlock()

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
	prior := s.priorFileCheck(streamRpm, req.Force)
	emitProgress(ctx, "Mirroring %d RPM repo(s)…", len(configs))
	for _, cfg := range configs {
		mirror, mf, err := s.mirrorRpmRepo(ctx, cfg, stageRoot, arches, newest, prior)
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

	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	return s.exportIfNew(ctx, streamRpm, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeRpmBundle(ctx, seq, stageRoot, files, mirrors)
	})
}

// mirrorRpmRepo downloads and verifies repomd, every metadata file it lists, and
// every .rpm, staging them under stageRoot.
// downloadRpmMetadata downloads and verifies every metadata file repomd
// references, returning the manifest files, the <data> entries, and the primary
// index's href.
func (s *LowServer) downloadRpmMetadata(ctx context.Context, base, name string, data []rpmRepomdData, stageRoot string) ([]ManifestFile, []RpmData, string, error) {
	var files []ManifestFile
	var repodata []RpmData
	var primaryRel string
	for _, d := range data {
		entry := d.toRpmData()
		mf, err := s.downloadRpmFile(ctx, base, name, entry.Href, entry.ChecksumType, entry.Checksum, entry.Size, stageRoot)
		if err != nil {
			return nil, nil, "", fmt.Errorf("metadata %s: %w", entry.Type, err)
		}
		files = append(files, mf)
		repodata = append(repodata, entry)
		if entry.Type == "primary" {
			primaryRel = entry.Href
		}
	}
	return files, repodata, primaryRel, nil
}

func (s *LowServer) mirrorRpmRepo(ctx context.Context, cfg rpmMirrorConfig, stageRoot string, arches []string, newestOnly bool, prior func(path, sha256 string) bool) (RpmMirror, []ManifestFile, error) {
	base := strings.TrimRight(cfg.BaseURL, "/")

	emitProgress(ctx, "→ %s: fetching repomd.xml and primary index…", cfg.Name)
	repomdRaw, err := s.fetchRepomd(ctx, base, cfg.GPGKey)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	var md rpmRepomd
	if err := xml.Unmarshal(repomdRaw, &md); err != nil {
		return RpmMirror{}, nil, fmt.Errorf("parse repomd.xml: %w", err)
	}

	mirror := RpmMirror{Name: cfg.Name, BaseURL: base, GPGKey: filepath.Base(cfg.GPGKey)}
	files, repodata, primaryRel, err := s.downloadRpmMetadata(ctx, base, cfg.Name, md.Data, stageRoot)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	mirror.Repodata = repodata
	if primaryRel == "" {
		return RpmMirror{}, nil, errors.New("repomd.xml has no primary metadata")
	}

	// Parse the staged primary to enumerate and fetch every .rpm of the
	// requested architectures.
	primaryPlain, err := readStagedMetadata(stageRoot, cfg.Name, primaryRel)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	pkgs, err := parseRpmPrimary(primaryPlain)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	pkgs, err = applyRpmFilters(stageRoot, cfg.Name, primaryRel, primaryPlain, pkgs, files, mirror.Repodata, arches, newestOnly)
	if err != nil {
		return RpmMirror{}, nil, err
	}
	mirror.Packages = pkgs
	emitProgress(ctx, "  %s: %d package(s) [%s]", cfg.Name, len(pkgs), strings.Join(arches, " "))
	for i, pkg := range pkgs {
		// primary.xml already declares each .rpm's SHA-256 and size (the
		// download below is verified against the same values), so packages
		// this stream has already forwarded are not downloaded at all — they
		// become prior manifest references. The metadata files above are
		// always fetched: they are parsed (and possibly rewritten) locally.
		if err := validateRelPath(pkg.Location); err != nil {
			return RpmMirror{}, nil, fmt.Errorf("package %s: unsafe location %q: %w", pkg.Name, pkg.Location, err)
		}
		if rel := rpmFileRel(cfg.Name, pkg.Location); pkg.Size > 0 && prior(rel, pkg.SHA256) {
			emitProgress(ctx, "    ≡ [%d/%d] %s already forwarded (download skipped)", i+1, len(pkgs), path.Base(pkg.Location))
			files = append(files, ManifestFile{Path: rel, SHA256: pkg.SHA256, Size: pkg.Size, Prior: true})
			continue
		}
		mf, err := s.downloadRpmFile(ctx, base, cfg.Name, pkg.Location, "sha256", pkg.SHA256, pkg.Size, stageRoot)
		if err != nil {
			return RpmMirror{}, nil, fmt.Errorf("package %s: %w", pkg.Name, err)
		}
		emitProgress(ctx, "    ↓ [%d/%d] %s (%s)", i+1, len(pkgs), path.Base(pkg.Location), formatBytes(mf.Size))
		files = append(files, mf)
	}
	return mirror, files, nil
}

// fetchRepomd downloads repodata/repomd.xml and verifies repomd.xml.asc against
// the caller's keyring when one is supplied.
func (s *LowServer) fetchRepomd(ctx context.Context, base, gpgKey string) ([]byte, error) {
	repomd, err := httpGetBytes(ctx, base+"/repodata/repomd.xml", maxSignedMetaBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch repomd.xml: %w", err)
	}
	if gpgKey != "" {
		sig, err := httpGetBytes(ctx, base+"/repodata/repomd.xml.asc", maxSignedMetaBytes)
		if err != nil {
			return nil, fmt.Errorf("fetch repomd.xml.asc: %w", err)
		}
		if err := gpgVerifyDetached(ctx, repomd, sig, gpgKey); err != nil {
			return nil, fmt.Errorf("verify repomd.xml: %w", err)
		}
	}
	return repomd, nil
}

// downloadRpmFile fetches one repository file (metadata or .rpm), verifying it
// against the repo-declared checksum as it streams to rpm/<mirror>/<rel> under
// stageRoot — a multi-GiB .rpm is never buffered in memory. wantSize is the
// repo-declared byte count (0 when the repo does not declare one).
func (s *LowServer) downloadRpmFile(ctx context.Context, base, mirror, relHref, checksumType, checksum string, wantSize int64, stageRoot string) (ManifestFile, error) {
	if err := validateRelPath(relHref); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe location %q: %w", relHref, err)
	}
	rel := rpmFileRel(mirror, relHref)
	if err := validateRelPath(rel); err != nil {
		return ManifestFile{}, fmt.Errorf("unsafe staging path %q: %w", rel, err)
	}
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadVerifiedFile(ctx, base+"/"+relHref, abs, wantSize, checksumType, checksum)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("%s: %w", relHref, err)
	}
	return ManifestFile{Path: rel, SHA256: sum, Size: size}, nil
}

// readStagedMetadata reads a staged metadata file and decompresses it by
// extension. Both the compressed bytes and the decompressed result are held in
// memory for parsing, so each is capped.
func readStagedMetadata(stageRoot, mirror, relHref string) ([]byte, error) {
	abs := filepath.Join(stageRoot, filepath.FromSlash(rpmFileRel(mirror, relHref)))
	if info, err := os.Stat(abs); err == nil && info.Size() > maxIndexFetchBytes {
		return nil, fmt.Errorf("%s: %s index exceeds the %s parse cap", relHref, formatBytes(info.Size()), formatBytes(maxIndexFetchBytes))
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return decompressByExt(relHref, raw)
}

func (s *LowServer) writeRpmBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, mirrors []RpmMirror) (ExportResult, error) {
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
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	total := 0
	for _, m := range mirrors {
		total += len(m.Packages)
	}
	return ExportResult{Stream: streamRpm, Sequence: seq, ExportedModules: total, BundleID: id}, nil
}

// -----------------------------------------------------------------------------
// Helpers (decompression, checksums) — HTTP fetching is shared with the APT
// adapter: httpGetBytes for small in-memory metadata, downloadVerifiedFile for
// streamed packages.
// -----------------------------------------------------------------------------

// decompressByExt decompresses by href extension: .gz via the standard library,
// .xz by shelling to xz, and plain otherwise. Output is capped at
// maxIndexPlainBytes (the result is parsed in memory).
func decompressByExt(href string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(href, ".gz"):
		return gunzip(data, maxIndexPlainBytes)
	case strings.HasSuffix(href, ".xz"):
		return xzDecompress(data)
	case strings.HasSuffix(href, ".zck"):
		return nil, fmt.Errorf("zchunk (.zck) index cannot be parsed: %s", href)
	default:
		return data, nil
	}
}

func xzDecompress(data []byte) ([]byte, error) {
	return runXZ(data, maxIndexPlainBytes, "--decompress", "--stdout")
}

// compressByExt recompresses plain to match an href's extension: .gz via the
// standard library, .xz by shelling to xz, plain otherwise. Zchunk (.zck)
// cannot be produced, so filtered (arch/newest-only) rewriting is unsupported
// for a zchunk-only index.
func compressByExt(href string, plain []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(href, ".gz"):
		return gzipBytes(plain)
	case strings.HasSuffix(href, ".xz"):
		return xzCompress(plain)
	case strings.HasSuffix(href, ".zck"):
		return nil, fmt.Errorf("cannot rewrite zchunk (.zck) index %s after filtering; disable newest_only and list every architecture the repo carries", href)
	default:
		return plain, nil
	}
}

func xzCompress(data []byte) ([]byte, error) {
	return runXZ(data, maxMirroredFileBytes, "--compress", "--stdout")
}

// runXZ pipes data through the xz binary, failing once the output exceeds
// limit rather than buffering an unbounded expansion (decompression-bomb
// guard; the input is never copied, unlike a string round-trip).
func runXZ(data []byte, limit int64, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "xz", args...)
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("xz %s: %w", strings.Join(args, " "), err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(out)) > limit {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("xz %s: output exceeds the %s cap", strings.Join(args, " "), formatBytes(limit))
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("xz %s: %w\n%s", strings.Join(args, " "), err, tailBytes(stderr.Bytes(), 2048))
	}
	if readErr != nil {
		return nil, readErr
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
			return nil, fmt.Errorf("duplicate mirror name %q; two sections point at the same baseurl — drop the duplicate, or use the explicit name/base_url fields to name a mirror yourself", vc.Name)
		}
		names[vc.Name] = true
		out = append(out, vc)
	}
	return out, nil
}

// parseRepoFile parses a yum/dnf .repo (INI) file into one config per
// [section]. Section headers are structural only — the mirror name always
// derives from the section's baseurl (APT-style), because distro repo files
// ship generic ids ([baseos], [appstream]) that would collide across distros
// and releases on the high side.
func parseRepoFile(text string) ([]rpmMirrorConfig, error) {
	var configs []rpmMirrorConfig
	var cur *rpmMirrorConfig
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if _, ok := iniSection(line); ok {
			if cur != nil {
				configs = append(configs, *cur)
			}
			cur = &rpmMirrorConfig{}
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

// rpmRepoList returns each mirrored RPM repository's name, for the "Set me up"
// guide (a client only needs the baseurl, which is derived from the name).
func (s *HighServer) rpmRepoList() ([]UIRepo, error) {
	entries, err := os.ReadDir(s.rpmDir())
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
		if _, err := s.loadRpmIndex(e.Name()); err != nil {
			continue
		}
		repos = append(repos, UIRepo{
			Name: e.Name(),
			// Signed when the high side wrote a repomd.xml.asc for this repo.
			Signed: fileExists(filepath.Join(s.rpmDir(), e.Name(), "repodata", "repomd.xml.asc")),
		})
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Name < repos[j].Name })
	return repos, nil
}

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
