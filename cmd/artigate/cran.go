package main

// CRAN (R) ecosystem adapter. The low side fetches a CRAN mirror's
// src/contrib PACKAGES index, resolves the requested packages' runtime
// dependency closure (Depends/Imports/LinkingTo, minus R itself and the base
// packages every R ships), downloads the source tarballs — verifying the
// index-declared MD5 — and packs them into the same numbered, signed ArtiGate
// bundle format used by the other ecosystems. The high side regenerates a
// src/contrib PACKAGES index of its own from each tarball's embedded
// DESCRIPTION (never trusting a transferred index) and serves it with the
// tarballs, so `install.packages(repos = "<base>/cran")` works.
//
// Policy: source packages only (type = "source"), the portable form every
// CRAN mirror carries; clients build them locally like they do against CRAN.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5" //nolint:gosec // MD5sum is the only checksum CRAN indexes carry; artifact integrity rests on the verified bundle hash
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cranEcosystem is the CRAN package stream's registry entry (see ecosystems
// in ecosystem.go).
func cranEcosystem() ecosystem {
	return ecosystem{
		stream:       streamCRAN,
		label:        "CRAN",
		title:        "R packages (CRAN)",
		collect:      (*LowServer).HandleCRANCollect,
		watchCollect: watchAdapter((*LowServer).CollectCRAN),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.CRANMirror, "cran-mirror", "", "CRAN mirror R packages are fetched from (default "+defaultCRANMirror+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.CRAN != nil && len(m.CRAN.Packages) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateCRANPackages(m.CRAN.Packages, seen)
		},
		contentDesc: "r packages",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishCRAN(m.CRAN) },
		serve:       (*HighServer).serveCRAN,
		scanTree:    flatTreeScan((*HighServer).listCRANPackages),
		detail:      (*HighServer).cranDetail,
	}
}

const defaultCRANMirror = "https://cloud.r-project.org"

// cranMaxResolved bounds a dependency closure so a pathological index cannot
// grow a request without limit.
const cranMaxResolved = 2000

// cranMaxDescriptionBytes caps one DESCRIPTION file parsed from a package
// tarball.
const cranMaxDescriptionBytes = 4 << 20

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type CRANManifest struct {
	Packages []CRANPackage `json:"packages"`
}

// CRANPackage records one mirrored source package.
type CRANPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// cranNameRE matches an R package name: letters, digits, and dots, starting
// with a letter ("Writing R Extensions" rules), so it is always path-safe and
// never contains the "_" that separates name from version in a filename.
var cranNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,127}$`)

// cranVersionRE matches an R package version: integer segments separated by
// "." or "-", so it always starts with a digit and is path-safe.
var cranVersionRE = regexp.MustCompile(`^[0-9][0-9.\-]{0,63}$`)

func validateCRANName(name string) error {
	if !cranNameRE.MatchString(name) {
		return fmt.Errorf("invalid R package name %q", name)
	}
	return nil
}

func validateCRANVersion(v string) error {
	if !cranVersionRE.MatchString(v) {
		return fmt.Errorf("invalid R package version %q", v)
	}
	return nil
}

// cranFilename is the canonical source tarball name of a package release.
func cranFilename(name, version string) string {
	return name + "_" + version + ".tar.gz"
}

// cranFileRel is the repository-relative path of one source tarball.
func cranFileRel(filename string) string {
	return path.Join("cran", "src", "contrib", filename)
}

// validateCRANPackages checks every package record of a bundle manifest:
// path-safe identity, the canonical storage path, and that the referenced
// file is listed in the manifest's file set.
func validateCRANPackages(pkgs []CRANPackage, seen map[string]bool) error {
	for _, p := range pkgs {
		if err := validateCRANName(p.Name); err != nil {
			return err
		}
		if err := validateCRANVersion(p.Version); err != nil {
			return fmt.Errorf("r package %s: %w", p.Name, err)
		}
		if p.Filename != cranFilename(p.Name, p.Version) {
			return fmt.Errorf("r package %s@%s has non-canonical filename %s", p.Name, p.Version, p.Filename)
		}
		if p.Path != cranFileRel(p.Filename) || !seen[p.Path] {
			return fmt.Errorf("r package %s@%s references file not listed in manifest.files: %s", p.Name, p.Version, p.Path)
		}
	}
	return nil
}

// cranVersionLess orders two R versions: integer segments split on "." and
// "-" compare numerically, a missing segment counts as zero.
func cranVersionLess(a, b string) bool {
	return compareCRANVersions(a, b) < 0
}

func compareCRANVersions(a, b string) int {
	as := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' })
	bs := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' })
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// -----------------------------------------------------------------------------
// DCF (Debian control file) records, the format of PACKAGES and DESCRIPTION
// -----------------------------------------------------------------------------

// parseDCFRecords splits DCF text into records (blank-line separated) of
// folded "Field: value" lines, the format R uses for PACKAGES and
// DESCRIPTION. Continuation lines (leading whitespace) fold into the previous
// field with a single space.
func parseDCFRecords(b []byte) []map[string]string {
	var records []map[string]string
	cur := map[string]string{}
	lastKey := ""
	flush := func() {
		if len(cur) > 0 {
			records = append(records, cur)
			cur = map[string]string{}
		}
		lastKey = ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case (line[0] == ' ' || line[0] == '\t') && lastKey != "":
			cur[lastKey] += " " + strings.TrimSpace(line)
		default:
			key, val, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			lastKey = strings.TrimSpace(key)
			cur[lastKey] = strings.TrimSpace(val)
		}
	}
	flush()
	return records
}

// cranDepNames extracts the package names from a DCF dependency field like
// "jsonlite (>= 1.7), R (>= 3.5), methods": version constraints are dropped
// (ArtiGate mirrors the index's current version), R itself and empty entries
// are skipped.
func cranDepNames(field string) []string {
	var names []string
	for _, dep := range strings.Split(field, ",") {
		name := dep
		if i := strings.IndexByte(name, '('); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "R" {
			continue
		}
		names = append(names, name)
	}
	return names
}

// isCRANBasePackage reports whether name is one of the base packages every R
// installation ships (priority "base"): they are never on CRAN, so dependency
// resolution must not try to mirror them.
func isCRANBasePackage(name string) bool {
	switch name {
	case "base", "compiler", "datasets", "grDevices", "graphics", "grid",
		"methods", "parallel", "splines", "stats", "stats4", "tcltk", "tools",
		"utils":
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// High side: repository serving
// -----------------------------------------------------------------------------

func (s *HighServer) cranDir() string {
	return filepath.Join(s.downloadDir, "cran")
}

func (s *HighServer) cranContribDir() string {
	return filepath.Join(s.cranDir(), "src", "contrib")
}

func (s *HighServer) cranMetadataDir() string {
	return filepath.Join(s.cranDir(), "metadata")
}

// serveCRAN handles the CRAN repository routes under /cran/: the regenerated
// src/contrib PACKAGES index (plain and gzipped) and the source tarballs,
// including the src/contrib/Archive/<name>/ form remotes::install_version
// requests for older releases. It reports whether it wrote a response.
func (s *HighServer) serveCRAN(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/cran" && !strings.HasPrefix(p, "/cran/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.Trim(strings.TrimPrefix(p, "/cran"), "/")
	file, ok := cranServableFile(rel)
	if validateRelPath(rel) != nil || !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.cranContribDir(), file)
	if !safeJoin(s.cranContribDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	if file == "PACKAGES" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	serveFile(w, r, abs)
	return true
}

// cranServableFile maps a request path under /cran/ to the flat file served
// from src/contrib, restricting the tree to the client-facing shapes: the
// PACKAGES index (plain or .gz) and source tarballs, flat or under
// Archive/<name>/. The regenerated metadata store stays private.
func cranServableFile(rel string) (string, bool) {
	segs := strings.Split(rel, "/")
	if len(segs) < 3 || segs[0] != "src" || segs[1] != "contrib" {
		return "", false
	}
	switch {
	case len(segs) == 3 && (segs[2] == "PACKAGES" || segs[2] == "PACKAGES.gz"):
		return segs[2], true
	case len(segs) == 3 && cranTarballName(segs[2]):
		return segs[2], true
	case len(segs) == 5 && segs[2] == "Archive" && validateCRANName(segs[3]) == nil && cranTarballName(segs[4]):
		return segs[4], true
	}
	return "", false
}

// cranTarballName reports whether a path segment is a well-formed
// <name>_<version>.tar.gz source tarball name.
func cranTarballName(seg string) bool {
	stem, ok := strings.CutSuffix(seg, ".tar.gz")
	if !ok {
		return false
	}
	name, version, ok := strings.Cut(stem, "_")
	return ok && validateCRANName(name) == nil && validateCRANVersion(version) == nil
}

// -----------------------------------------------------------------------------
// High side: index regeneration at import
// -----------------------------------------------------------------------------

// cranStoredPackage is the per-release metadata the high side regenerates at
// import time from the tarball's own embedded DESCRIPTION. PACKAGES is
// assembled from these.
type cranStoredPackage struct {
	Filename string            `json:"filename"`
	Fields   map[string]string `json:"fields"`
}

// cranIndexFields are the DESCRIPTION fields carried into the regenerated
// PACKAGES index, in the order R's own tools write them.
func cranIndexFields() []string {
	return []string{"Depends", "Imports", "LinkingTo", "Suggests", "Enhances", "License", "Priority", "NeedsCompilation"}
}

// publishCRAN regenerates the served metadata for every package in an
// imported bundle from the tarball's own embedded DESCRIPTION. A package
// whose tarball cannot be parsed is logged and skipped (it stays out of
// PACKAGES) rather than wedging the stream's import forever.
func (s *HighServer) publishCRAN(m *CRANManifest) error {
	if m == nil {
		return nil
	}
	for _, p := range m.Packages {
		if err := s.publishCRANPackage(p); err != nil {
			log.Printf("cran publish %s@%s: %v", p.Name, p.Version, err)
		}
	}
	if len(m.Packages) == 0 {
		return nil
	}
	return s.regenerateCRANIndex()
}

// publishCRANPackage regenerates one release's stored metadata from the
// tarball's embedded DESCRIPTION, cross-checking the embedded identity
// against the manifest record.
func (s *HighServer) publishCRANPackage(p CRANPackage) error {
	if err := validateCRANName(p.Name); err != nil {
		return err
	}
	if err := validateCRANVersion(p.Version); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(p.Path))
	if !strings.HasPrefix(p.Path, "cran/src/contrib/") || !safeJoin(s.cranContribDir(), abs) {
		return fmt.Errorf("unsafe tarball path %s", p.Path)
	}
	desc, err := extractCRANDescription(abs, p.Name)
	if err != nil {
		return err
	}
	if desc["Package"] != p.Name {
		return fmt.Errorf("embedded DESCRIPTION names %q", desc["Package"])
	}
	if desc["Version"] != p.Version {
		return fmt.Errorf("embedded DESCRIPTION version is %q", desc["Version"])
	}
	st := cranStoredPackage{Filename: p.Filename, Fields: desc}
	out := filepath.Join(s.cranMetadataDir(), p.Name+"_"+p.Version+".json")
	if !safeJoin(s.cranMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s@%s", p.Name, p.Version)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// extractCRANDescription reads the DESCRIPTION embedded in a source tarball
// (R requires <name>/DESCRIPTION at depth one) into its DCF fields.
func extractCRANDescription(tgzPath, name string) (map[string]string, error) {
	return extractCRANDescriptionBounded(tgzPath, name, tarScanMaxDecompressedBytes)
}

// extractCRANDescriptionBounded is extractCRANDescription with the scan's
// total-decompression budget as a parameter, so the gzip-bomb bound is
// regression-testable without a multi-GiB fixture.
func extractCRANDescriptionBounded(tgzPath, name string, scanBudget int64) (map[string]string, error) {
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
	// Bound total decompression: tr.Next() inflates every skipped entry, so a
	// gzip bomb with DESCRIPTION last (or absent) would otherwise inflate wholesale.
	tr := tar.NewReader(io.LimitReader(gz, scanBudget))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("tarball has no DESCRIPTION")
		}
		if err != nil {
			return nil, err
		}
		parts := strings.Split(path.Clean(strings.TrimPrefix(hdr.Name, "./")), "/")
		if hdr.Typeflag != tar.TypeReg || len(parts) != 2 || parts[0] != name || parts[1] != "DESCRIPTION" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, cranMaxDescriptionBytes))
		if err != nil {
			return nil, err
		}
		records := parseDCFRecords(b)
		if len(records) == 0 || records[0]["Package"] == "" {
			return nil, errors.New("embedded DESCRIPTION has no Package field")
		}
		return records[0], nil
	}
}

// regenerateCRANIndex rebuilds src/contrib/PACKAGES (and PACKAGES.gz) from
// the accumulated stored metadata, listing the newest present release of each
// package like CRAN itself does; superseded tarballs stay downloadable under
// Archive/.
func (s *HighServer) regenerateCRANIndex() error {
	newest, err := s.cranNewestStored()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(newest))
	for name := range newest {
		names = append(names, name)
	}
	sort.Strings(names)
	var plain bytes.Buffer
	for _, name := range names {
		s.writeCRANIndexRecord(&plain, name, newest[name])
	}
	if err := writeBytesAtomic(filepath.Join(s.cranContribDir(), "PACKAGES"), plain.Bytes(), 0o644); err != nil {
		return err
	}
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	if _, err := zw.Write(plain.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return writeBytesAtomic(filepath.Join(s.cranContribDir(), "PACKAGES.gz"), zipped.Bytes(), 0o644)
}

// cranNewestStored loads every stored release whose tarball is still present
// and keeps the newest version per package.
func (s *HighServer) cranNewestStored() (map[string]cranStoredPackage, error) {
	entries, err := os.ReadDir(s.cranMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]cranStoredPackage{}, nil
	}
	if err != nil {
		return nil, err
	}
	newest := map[string]cranStoredPackage{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		st, err := s.readCRANStored(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		name := st.Fields["Package"]
		cur, ok := newest[name]
		if !ok || cranVersionLess(cur.Fields["Version"], st.Fields["Version"]) {
			newest[name] = st
		}
	}
	return newest, nil
}

// writeCRANIndexRecord renders one package's PACKAGES entry: identity, the
// dependency fields from its own DESCRIPTION, and the MD5 R clients verify,
// computed from the artifact on disk.
func (s *HighServer) writeCRANIndexRecord(b *bytes.Buffer, name string, st cranStoredPackage) {
	fmt.Fprintf(b, "Package: %s\nVersion: %s\n", name, st.Fields["Version"])
	for _, key := range cranIndexFields() {
		if v := st.Fields[key]; v != "" {
			fmt.Fprintf(b, "%s: %s\n", key, v)
		}
	}
	if sum, err := md5File(filepath.Join(s.cranContribDir(), st.Filename)); err == nil {
		fmt.Fprintf(b, "MD5sum: %s\n", sum)
	}
	b.WriteByte('\n')
}

// md5File returns the hex MD5 of a file, the checksum R clients verify
// downloads against (the regenerated index recomputes it from the verified
// artifact on disk).
func md5File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New() //nolint:gosec // legacy CRAN index checksum, not a security control
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readCRANStored loads one release's stored metadata by its "<name>_<version>"
// stem and checks the tarball is still present.
func (s *HighServer) readCRANStored(stem string) (cranStoredPackage, error) {
	p := filepath.Join(s.cranMetadataDir(), stem+".json")
	if !safeJoin(s.cranMetadataDir(), p) {
		return cranStoredPackage{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return cranStoredPackage{}, err
	}
	var st cranStoredPackage
	if err := json.Unmarshal(b, &st); err != nil {
		return cranStoredPackage{}, err
	}
	if !cranTarballName(st.Filename) ||
		validateCRANName(st.Fields["Package"]) != nil || validateCRANVersion(st.Fields["Version"]) != nil {
		return cranStoredPackage{}, errors.New("invalid stored metadata")
	}
	abs := filepath.Join(s.cranContribDir(), st.Filename)
	if !safeJoin(s.cranContribDir(), abs) || !fileExists(abs) {
		return cranStoredPackage{}, errors.New("tarball missing")
	}
	return st, nil
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listCRANPackages groups the mirrored releases by package name with their
// versions, from the regenerated metadata store.
func (s *HighServer) listCRANPackages() ([]UIModule, error) {
	entries, err := os.ReadDir(s.cranMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byName := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		st, err := s.readCRANStored(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		byName[st.Fields["Package"]] = append(byName[st.Fields["Package"]], st.Fields["Version"])
	}
	out := make([]UIModule, 0, len(byName))
	for name, versions := range byName {
		sort.Slice(versions, func(i, j int) bool { return cranVersionLess(versions[i], versions[j]) })
		out = append(out, UIModule{Module: name, Versions: versions})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// cranDetail describes one mirrored release for the dashboard detail panel.
// spec is "<name>@<version>".
func (s *HighServer) cranDetail(spec string) (UIDetail, error) {
	name, version, ok := strings.Cut(spec, "@")
	if !ok || validateCRANName(name) != nil || validateCRANVersion(version) != nil {
		return UIDetail{}, errors.New("invalid package@version")
	}
	st, err := s.readCRANStored(name + "_" + version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Package", Value: name, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	for _, key := range []string{"Title", "License", "Depends", "Imports", "NeedsCompilation"} {
		if v := st.Fields[key]; v != "" {
			fields = append(fields, UIDetailField{Label: key, Value: v})
		}
	}
	abs := filepath.Join(s.cranContribDir(), st.Filename)
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Tarball size", Value: formatBytes(fi.Size())})
	}
	if sum, err := s.detailDigests.get(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	fields = append(fields, UIDetailField{Label: "Repository path", Value: "/cran/src/contrib/" + st.Filename, Mono: true})
	downloads := []UIDownload{{Label: st.Filename, URL: "/cran/src/contrib/" + st.Filename}}
	return UIDetail{Title: name, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// Low side: package collector
// -----------------------------------------------------------------------------

// CRANCollectRequest is the body of POST /admin/cran/collect.
//
// Packages lists the packages to mirror: "name" for the mirror's current
// version, or "name@1.2-3" to pin (older releases come from the mirror's
// Archive). The runtime dependency closure (Depends/Imports/LinkingTo) of
// every requested package is mirrored with it.
type CRANCollectRequest struct {
	Packages []string `json:"packages"`
	// Force disables export dedup for this collect: every tarball is packed
	// even when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseCRANSpec splits "name" or "name@version".
func parseCRANSpec(spec string) (name, version string, err error) {
	name, version, _ = strings.Cut(strings.TrimSpace(spec), "@")
	if err := validateCRANName(name); err != nil {
		return "", "", err
	}
	if version != "" && version != "latest" {
		if err := validateCRANVersion(version); err != nil {
			return "", "", fmt.Errorf("package %s: %w", name, err)
		}
		return name, version, nil
	}
	return name, "", nil
}

func validateCRANRequest(req CRANCollectRequest) error {
	if len(req.Packages) == 0 {
		return errors.New("no r packages provided")
	}
	for _, spec := range req.Packages {
		if _, _, err := parseCRANSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// cranMirrorBase resolves the configured CRAN mirror base URL.
func (s *LowServer) cranMirrorBase() string {
	base := strings.TrimSuffix(strings.TrimSpace(s.cfg.CRANMirror), "/")
	if base == "" {
		return defaultCRANMirror
	}
	return base
}

// HandleCRANCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandleCRANCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req CRANCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse cran collect request: %w", err)
		}
	}
	return s.CollectCRAN(ctx, req)
}

// CollectCRAN fetches the mirror's PACKAGES index, resolves the requested
// packages and their runtime dependency closure, downloads the source
// tarballs (verifying the index MD5 when one is declared), and writes them
// into a signed bundle on the cran stream. Packages that cannot be resolved
// or fetched are skipped and reported so one of them never blocks the rest.
func (s *LowServer) CollectCRAN(ctx context.Context, req CRANCollectRequest) (ExportResult, error) {
	if err := validateCRANRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the cran stream's lock for the whole fetch->write->commit so a
	// concurrent cran exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamCRAN)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "cran", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	base := s.cranMirrorBase()
	emitProgress(ctx, "Fetching %s/src/contrib/PACKAGES…", base)
	index, err := fetchCRANIndex(ctx, base)
	if err != nil {
		return ExportResult{}, err
	}
	dl := &cranDownloader{base: base, stageRoot: stageRoot, index: index}
	dl.run(ctx, req.Packages)
	if len(dl.pkgs) == 0 {
		return ExportResult{}, fmt.Errorf("no r packages could be fetched: %s", summarizeFailures(dl.failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(dl.files))

	res, err := s.exportIfNew(ctx, streamCRAN, stageRoot, dl.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeCRANBundle(ctx, seq, stageRoot, dl.files, dl.pkgs)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = dl.failed
	return res, nil
}

// cranIndexEntry is the subset of a PACKAGES record ArtiGate reads for
// resolution.
type cranIndexEntry struct {
	Version string
	MD5     string
	Deps    []string
}

// fetchCRANIndex downloads and parses the mirror's src/contrib PACKAGES index
// (the gzipped form, falling back to plain).
func fetchCRANIndex(ctx context.Context, base string) (map[string]cranIndexEntry, error) {
	b, err := httpGetBytes(ctx, base+"/src/contrib/PACKAGES.gz", maxIndexFetchBytes)
	if err == nil {
		b, err = gunzipCapped(b, maxIndexFetchBytes)
	}
	if err != nil {
		if b, err = httpGetBytes(ctx, base+"/src/contrib/PACKAGES", maxIndexFetchBytes); err != nil {
			return nil, err
		}
	}
	index := map[string]cranIndexEntry{}
	for _, rec := range parseDCFRecords(b) {
		name := rec["Package"]
		if validateCRANName(name) != nil || validateCRANVersion(rec["Version"]) != nil {
			continue
		}
		var deps []string
		for _, field := range []string{"Depends", "Imports", "LinkingTo"} {
			deps = append(deps, cranDepNames(rec[field])...)
		}
		index[name] = cranIndexEntry{Version: rec["Version"], MD5: rec["MD5sum"], Deps: deps}
	}
	if len(index) == 0 {
		return nil, errors.New("PACKAGES index lists no packages")
	}
	return index, nil
}

// gunzipCapped decompresses a gzip payload, failing past limit bytes
// (decompression-bomb guard).
func gunzipCapped(b []byte, limit int64) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	out, err := io.ReadAll(io.LimitReader(gz, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("decompressed index exceeds the %s cap", formatBytes(limit))
	}
	return out, nil
}

// cranDownloader walks the dependency closure, downloading each release once.
type cranDownloader struct {
	base      string
	stageRoot string
	index     map[string]cranIndexEntry
	pkgs      []CRANPackage
	files     []ManifestFile
	failed    []FailedModule
	done      map[string]bool
}

// run resolves and downloads the requested specs and their dependency
// closure. Requested packages may pin a version (fetched from the Archive
// when superseded, with the dependency names read from that release's own
// DESCRIPTION); dependencies always resolve to the index's current version,
// like a fresh install.packages does.
func (d *cranDownloader) run(ctx context.Context, specs []string) {
	d.done = map[string]bool{}
	queue := make([]string, 0, len(specs))
	for _, spec := range specs {
		name, version, _ := parseCRANSpec(spec)
		if entry, ok := d.index[name]; version == "" || (ok && version == entry.Version) {
			queue = append(queue, name)
			continue
		}
		queue = append(queue, d.fetchArchivedPin(ctx, name, version)...)
	}
	for len(queue) > 0 && len(d.done) < cranMaxResolved {
		name := queue[0]
		queue = queue[1:]
		if d.done[name] || isCRANBasePackage(name) {
			continue
		}
		d.done[name] = true
		entry, ok := d.index[name]
		if !ok {
			d.failed = append(d.failed, FailedModule{Module: name, Version: "latest", Error: "not in the mirror's PACKAGES index"})
			continue
		}
		emitProgress(ctx, "→ %s@%s", name, entry.Version)
		if d.fetchOne(ctx, name, entry.Version, entry.MD5) {
			queue = append(queue, entry.Deps...)
		}
	}
}

// fetchArchivedPin downloads one superseded pinned release and returns the
// dependency names to queue, read from the downloaded tarball's own
// DESCRIPTION — the index only describes the current release, so the archive
// itself is the authority on what the old release needs. The pinned name is
// marked done so the closure never adds the current release on top of it.
func (d *cranDownloader) fetchArchivedPin(ctx context.Context, name, version string) []string {
	emitProgress(ctx, "→ %s@%s (archived release)", name, version)
	if !d.fetchOne(ctx, name, version, "") {
		return nil
	}
	d.done[name] = true
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(cranFileRel(cranFilename(name, version))))
	desc, err := extractCRANDescription(abs, name)
	if err != nil {
		emitProgress(ctx, "  ! %s@%s: cannot read dependencies from the archived release: %s", name, version, err)
		return nil
	}
	var deps []string
	for _, field := range []string{"Depends", "Imports", "LinkingTo"} {
		deps = append(deps, cranDepNames(desc[field])...)
	}
	return deps
}

// fetchOne downloads one release into the staging tree, trying the current
// src/contrib location first and the Archive for superseded versions.
func (d *cranDownloader) fetchOne(ctx context.Context, name, version, wantMD5 string) bool {
	filename := cranFilename(name, version)
	rel := cranFileRel(filename)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	current := d.base + "/src/contrib/" + filename
	archived := d.base + "/src/contrib/Archive/" + name + "/" + filename
	var sum string
	var size int64
	var err error
	if wantMD5 != "" {
		sum, size, err = downloadVerifiedFile(ctx, current, abs, 0, "md5", wantMD5)
	} else {
		// The Archive (and indexes without MD5sum) declare no checksum;
		// integrity then rests on TLS to the operator-configured mirror, like
		// the other index-less fetches.
		if sum, size, err = downloadFileSHA256(ctx, current, abs); err != nil {
			sum, size, err = downloadFileSHA256(ctx, archived, abs)
		}
	}
	if err != nil {
		emitProgress(ctx, "  ✗ %s@%s: %s", name, version, err)
		d.failed = append(d.failed, FailedModule{Module: name, Version: version, Error: err.Error()})
		return false
	}
	d.pkgs = append(d.pkgs, CRANPackage{Name: name, Version: version, Filename: filename, Path: rel, SHA256: sum})
	d.files = append(d.files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	return true
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeCRANBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, pkgs []CRANPackage) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	id := bundleIDFor(streamCRAN, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamCRAN,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"cran"},
		CRAN:             &CRANManifest{Packages: pkgs},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamCRAN, Sequence: seq, ExportedModules: len(pkgs), BundleID: id}, nil
}
