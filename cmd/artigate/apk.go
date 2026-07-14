package main

// Alpine APK ecosystem adapter. The low side fetches an Alpine mirror's
// APKINDEX per branch/repository/architecture, downloads the .apk packages —
// verifying each against the index-declared size and control-segment checksum
// — and packs them into the same numbered, signed ArtiGate bundle format used
// by the other ecosystems. Like the APT adapter, the verbatim index stanzas
// travel inside the Ed25519-signed manifest; the high side regenerates
// APKINDEX.tar.gz per branch/repository/architecture from the accumulated
// stanzas of the .apk files actually present (never trusting a transferred
// index), optionally signing it with an operator-held RSA key so stock apk
// clients accept it without --allow-untrusted.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // sha1 is the checksum apk's index format mandates, not our choice of security control
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// apkEcosystem is the Alpine package stream's registry entry (see ecosystems
// in ecosystem.go).
func apkEcosystem() ecosystem {
	return ecosystem{
		stream:          streamApk,
		label:           "Alpine",
		title:           "Alpine packages",
		collect:         (*LowServer).HandleApkCollect,
		watchCollect:    watchAdapter((*LowServer).CollectApk),
		manifestContent: func(m BundleManifest) bool { return m.Apk != nil && len(m.Apk.Mirrors) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateApkMirrors(m.Apk.Mirrors, seen)
		},
		contentDesc: "apk mirrors",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishApk(m.Apk) },
		serve:       (*HighServer).serveApk,
		scanTree:    segmentTreeScan((*HighServer).listApkPackages),
		detail:      (*HighServer).apkDetail,
		repoList:    (*HighServer).apkRepoList,
	}
}

// apkMaxControlBytes caps one decompressed signature/control segment read
// while locating a package's control checksum (decompression-bomb guard).
const apkMaxControlBytes = 16 << 20

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type ApkManifest struct {
	Mirrors []ApkMirror `json:"mirrors"`
}

type ApkMirror struct {
	Name     string       `json:"name"`
	URI      string       `json:"uri"`
	Branches []ApkBranch  `json:"branches"`
	Packages []ApkPackage `json:"packages"`
}

type ApkBranch struct {
	Name          string   `json:"name"`
	Repositories  []string `json:"repositories"`
	Architectures []string `json:"architectures"`
}

// ApkPackage records one mirrored package with the verbatim APKINDEX stanza
// the served index is regenerated from.
type ApkPackage struct {
	Name       string `json:"package"`
	Version    string `json:"version"`
	Arch       string `json:"architecture"`
	Branch     string `json:"branch"`
	Repository string `json:"repository"`
	Filename   string `json:"filename"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Stanza     string `json:"stanza"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// apkNameRE matches an Alpine package name (which may contain "+", e.g.
// libstdc++). The first character excludes ".", "_", "+", and "-" so a name
// can never be ".."/"-flag".
var apkNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// apkVersionValidRE matches an Alpine package version, which always starts
// with a digit, so it can never be ".."/"-flag" or contain a path separator.
var apkVersionValidRE = regexp.MustCompile(`^[0-9][0-9A-Za-z._+-]*$`)

func validateApkName(name string) error {
	if !apkNameRE.MatchString(name) {
		return fmt.Errorf("invalid apk package name %q", name)
	}
	return nil
}

func validateApkVersion(v string) error {
	if !apkVersionValidRE.MatchString(v) {
		return fmt.Errorf("invalid apk version %q", v)
	}
	return nil
}

// apkFileRel is the repository-relative path of one package (or the
// regenerated index) inside a mirror's tree.
func apkFileRel(mirror, branch, repo, arch, filename string) string {
	return path.Join("apk", mirror, branch, repo, arch, filename)
}

// validateApkStanza checks a manifest-carried index stanza: every line must be
// a single-letter field, so a hostile stanza cannot embed a blank line and
// forge extra index entries when the high side concatenates stanzas back into
// an APKINDEX.
func validateApkStanza(stanza string) error {
	if strings.TrimSpace(stanza) == "" {
		return errors.New("empty stanza")
	}
	for _, line := range strings.Split(strings.TrimRight(stanza, "\n"), "\n") {
		if len(line) < 2 || line[1] != ':' || !isASCIILetter(line[0]) {
			return fmt.Errorf("malformed stanza line %q", line)
		}
	}
	return nil
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// validateApkPackage checks one package record against its mirror's declared
// branches and the manifest file set.
func validateApkPackage(m ApkMirror, p ApkPackage, seen map[string]bool) error {
	if err := validateApkName(p.Name); err != nil {
		return err
	}
	if err := validateApkVersion(p.Version); err != nil {
		return fmt.Errorf("apk package %s: %w", p.Name, err)
	}
	if p.Filename != p.Name+"-"+p.Version+".apk" {
		return fmt.Errorf("apk package %s-%s has non-canonical filename %s", p.Name, p.Version, p.Filename)
	}
	if !apkBranchListed(m.Branches, p) {
		return fmt.Errorf("apk package %s-%s names branch/repo/arch outside the mirror's set", p.Name, p.Version)
	}
	rel := apkFileRel(m.Name, p.Branch, p.Repository, p.Arch, p.Filename)
	if !seen[rel] {
		return fmt.Errorf("apk package %s-%s references file not listed in manifest.files: %s", p.Name, p.Version, rel)
	}
	if err := validateApkStanza(p.Stanza); err != nil {
		return fmt.Errorf("apk package %s-%s: %w", p.Name, p.Version, err)
	}
	st := parseApkStanza(p.Stanza)
	if st.Name != p.Name || st.Version != p.Version {
		return fmt.Errorf("apk package %s-%s stanza names %s-%s", p.Name, p.Version, st.Name, st.Version)
	}
	return nil
}

func apkBranchListed(branches []ApkBranch, p ApkPackage) bool {
	for _, b := range branches {
		if b.Name == p.Branch && containsString(b.Repositories, p.Repository) && containsString(b.Architectures, p.Arch) {
			return true
		}
	}
	return false
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// validateApkMirrors checks every mirror of a bundle manifest: safe names,
// well-formed branch selections, and complete package references.
func validateApkMirrors(mirrors []ApkMirror, seen map[string]bool) error {
	for _, m := range mirrors {
		if err := validateApkMirror(m, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateApkMirror(m ApkMirror, seen map[string]bool) error {
	if err := validateMirrorName(m.Name); err != nil {
		return err
	}
	if m.URI == "" || len(m.Branches) == 0 {
		return fmt.Errorf("apk mirror %s is missing uri or branches", m.Name)
	}
	for _, b := range m.Branches {
		if !validRepoToken(b.Name) || len(b.Repositories) == 0 || len(b.Architectures) == 0 {
			return fmt.Errorf("apk mirror %s has an invalid branch selection", m.Name)
		}
		for _, tok := range append(append([]string{}, b.Repositories...), b.Architectures...) {
			if !validRepoToken(tok) {
				return fmt.Errorf("apk mirror %s has invalid repository/architecture %q", m.Name, tok)
			}
		}
	}
	for _, p := range m.Packages {
		if err := validateApkPackage(m, p, seen); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// APKINDEX parsing
// -----------------------------------------------------------------------------

// apkStanza is one parsed APKINDEX entry with its verbatim text.
type apkStanza struct {
	Text     string
	Name     string
	Version  string
	Arch     string
	Checksum string // C: field, "Q1" + base64(SHA-1 of the control segment)
	Size     int64  // S: field, the .apk byte size
}

// parseApkStanza extracts the fields ArtiGate reads from one stanza.
func parseApkStanza(text string) apkStanza {
	st := apkStanza{Text: text}
	for _, line := range strings.Split(text, "\n") {
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'P':
			st.Name = val
		case 'V':
			st.Version = val
		case 'A':
			st.Arch = val
		case 'C':
			st.Checksum = val
		case 'S':
			if n, err := parseVersionInt(val); err == nil {
				st.Size = n
			}
		}
	}
	return st
}

// parseApkIndex splits an APKINDEX into its blank-line-separated stanzas.
func parseApkIndex(text string) []apkStanza {
	var out []apkStanza
	for _, block := range strings.Split(text, "\n\n") {
		block = strings.Trim(block, "\n")
		if strings.TrimSpace(block) == "" {
			continue
		}
		st := parseApkStanza(block)
		if st.Name != "" && st.Version != "" {
			out = append(out, st)
		}
	}
	return out
}

// apkIndexFromArchive extracts the APKINDEX member from an APKINDEX.tar.gz
// (a signature segment, when present, is a concatenated leading gzip stream
// that the multistream reader walks straight through).
func apkIndexFromArchive(b []byte, limit int64) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", errors.New("archive has no APKINDEX member")
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(path.Clean(hdr.Name)) != "APKINDEX" {
			continue
		}
		text, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return "", err
		}
		if int64(len(text)) > limit {
			return "", fmt.Errorf("APKINDEX exceeds the %s cap", formatBytes(limit))
		}
		return string(text), nil
	}
}

// -----------------------------------------------------------------------------
// apk version comparison
// -----------------------------------------------------------------------------

// apkSuffixRank ranks a version suffix: pre-release suffixes sort before the
// bare version (rank 0), post-release suffixes after.
func apkSuffixRank(name string) (int, bool) {
	switch name {
	case "alpha":
		return -5, true
	case "beta":
		return -4, true
	case "pre":
		return -3, true
	case "rc":
		return -2, true
	case "cvs":
		return 1, true
	case "svn":
		return 2, true
	case "git":
		return 3, true
	case "hg":
		return 4, true
	case "p":
		return 5, true
	}
	return 0, false
}

type apkParsedVersion struct {
	nums     []string
	letter   byte
	suffixes []apkVersionSuffix
	rel      int64
	ok       bool
}

type apkVersionSuffix struct {
	rank int
	num  int64
}

var apkVersionRE = regexp.MustCompile(`^(\d+(?:\.\d+)*)([a-z])?((?:_[a-z]+\d*)*)(?:-r(\d+))?$`)

func parseApkVersion(v string) apkParsedVersion {
	m := apkVersionRE.FindStringSubmatch(v)
	if m == nil {
		return apkParsedVersion{}
	}
	out := apkParsedVersion{nums: strings.Split(m[1], "."), ok: true}
	if m[2] != "" {
		out.letter = m[2][0]
	}
	for _, tok := range strings.Split(m[3], "_") {
		if tok == "" {
			continue
		}
		name := strings.TrimRight(tok, "0123456789")
		rank, known := apkSuffixRank(name)
		if !known {
			return apkParsedVersion{}
		}
		num, _ := parseVersionInt(strings.TrimPrefix(tok, name))
		out.suffixes = append(out.suffixes, apkVersionSuffix{rank: rank, num: num})
	}
	if m[4] != "" {
		out.rel, _ = parseVersionInt(m[4])
	}
	return out
}

// apkVersionCompare orders two Alpine package versions with apk's rules:
// dotted numeric components, an optional trailing letter, ordered _suffixes
// (alpha < beta < pre < rc < <none> < cvs < svn < git < hg < p), and the -rN
// package release. Unparsable versions fall back to lexical order.
func apkVersionCompare(a, b string) int {
	pa, pb := parseApkVersion(a), parseApkVersion(b)
	if !pa.ok || !pb.ok {
		return strings.Compare(a, b)
	}
	if c := apkCompareNums(pa.nums, pb.nums); c != 0 {
		return c
	}
	if c := cmpInt64(int64(pa.letter), int64(pb.letter)); c != 0 {
		return c
	}
	if c := apkCompareSuffixes(pa.suffixes, pb.suffixes); c != 0 {
		return c
	}
	return cmpInt64(pa.rel, pb.rel)
}

// apkCompareNums compares dotted numeric components. The first component is
// always numeric; later components with a leading zero compare as fractional
// strings (trailing zeros trimmed), matching apk/Gentoo ordering.
func apkCompareNums(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		var c int
		if i > 0 && (strings.HasPrefix(a[i], "0") || strings.HasPrefix(b[i], "0")) {
			c = strings.Compare(strings.TrimRight(a[i], "0"), strings.TrimRight(b[i], "0"))
		} else {
			an, _ := parseVersionInt(a[i])
			bn, _ := parseVersionInt(b[i])
			c = cmpInt64(an, bn)
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt64(int64(len(a)), int64(len(b)))
}

func apkCompareSuffixes(a, b []apkVersionSuffix) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmpInt64(int64(a[i].rank), int64(b[i].rank)); c != 0 {
			return c
		}
		if c := cmpInt64(a[i].num, b[i].num); c != 0 {
			return c
		}
	}
	switch {
	case len(a) == len(b):
		return 0
	case len(a) > len(b):
		return cmpInt64(int64(a[len(b)].rank), 0)
	}
	return -cmpInt64(int64(b[len(a)].rank), 0)
}

// -----------------------------------------------------------------------------
// Package verification: the C: control-segment checksum
// -----------------------------------------------------------------------------

// countingByteReader tracks how many bytes the wrapped reader consumed. It
// implements io.ByteReader so flate reads exactly one gzip stream and never
// over-buffers past a stream boundary.
type countingByteReader struct {
	r *bufio.Reader
	n int64
}

func (c *countingByteReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingByteReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// apkControlSegment locates the compressed byte range of a package's control
// segment: an .apk is two or three concatenated gzip streams (optional
// signature, control, data), and the control stream is the one whose tar
// holds .PKGINFO. The data stream is never decompressed.
func apkControlSegment(f *os.File) (start, end int64, err error) {
	cbr := &countingByteReader{r: bufio.NewReader(f)}
	var offset int64
	for segment := 0; segment < 2; segment++ {
		first, segEnd, err := apkReadSegment(cbr)
		if err != nil {
			return 0, 0, err
		}
		if first == ".PKGINFO" {
			return offset, segEnd, nil
		}
		if !strings.HasPrefix(first, ".SIGN.") {
			return 0, 0, fmt.Errorf("unexpected leading segment member %q", first)
		}
		offset = segEnd
	}
	return 0, 0, errors.New("no control segment found")
}

// apkReadSegment decompresses one gzip stream, returning its first tar member
// name and the compressed end offset.
func apkReadSegment(cbr *countingByteReader) (first string, end int64, err error) {
	gz, err := gzip.NewReader(cbr)
	if err != nil {
		return "", 0, err
	}
	gz.Multistream(false)
	tr := tar.NewReader(io.LimitReader(gz, apkMaxControlBytes))
	if hdr, err := tr.Next(); err == nil {
		first = path.Clean(hdr.Name)
	}
	// Drain the stream so the counter lands exactly on the segment boundary.
	if _, err := io.Copy(io.Discard, io.LimitReader(gz, apkMaxControlBytes)); err != nil {
		return "", 0, err
	}
	if err := gz.Close(); err != nil {
		return "", 0, err
	}
	return first, cbr.n, nil
}

// apkVerifyControlChecksum checks a downloaded .apk against the index's C:
// pull checksum: "Q1" + base64(SHA-1 of the compressed control segment).
func apkVerifyControlChecksum(apkPath, want string) error {
	b64, ok := strings.CutPrefix(strings.TrimSpace(want), "Q1")
	if !ok {
		return fmt.Errorf("unsupported checksum %q (only Q1 SHA-1 pull checksums are supported)", want)
	}
	wantSum, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("invalid checksum %q", want)
	}
	f, err := os.Open(apkPath)
	if err != nil {
		return err
	}
	defer f.Close()
	start, end, err := apkControlSegment(f)
	if err != nil {
		return err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	h := sha1.New() //nolint:gosec // apk's index format mandates SHA-1 here
	if _, err := io.CopyN(h, f, end-start); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), wantSum) {
		return errors.New("control checksum mismatch between the index and the downloaded package")
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: serving
// -----------------------------------------------------------------------------

func (s *HighServer) apkDir() string {
	return filepath.Join(s.downloadDir, "apk")
}

// serveApk handles the Alpine repository routes under /apk/: the regenerated
// APKINDEX.tar.gz, the .apk packages, and (when index signing is configured)
// the public key clients install. Clients list the repository as
// <base>/apk/<mirror>/<branch>/<repo>. It reports whether it wrote a response
// for the request.
func (s *HighServer) serveApk(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/apk" && !strings.HasPrefix(p, "/apk/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.Trim(strings.TrimPrefix(p, "/apk"), "/")
	if rel == "keys/"+s.cfg.ApkKeyName && s.cfg.ApkRSAKey != "" {
		s.handleApkPublicKey(w)
		return true
	}
	if validateRelPath(rel) != nil || !apkServablePath(rel) {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.apkDir(), filepath.FromSlash(rel))
	if !safeJoin(s.apkDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	serveFile(w, r, abs)
	return true
}

// apkServablePath restricts the served tree to the client-facing shape:
// <mirror>/<branch>/<repo>/<arch>/(APKINDEX.tar.gz|*.apk).
func apkServablePath(rel string) bool {
	segs := strings.Split(rel, "/")
	if len(segs) != 5 || validateMirrorName(segs[0]) != nil {
		return false
	}
	for _, tok := range segs[1:4] {
		if !validRepoToken(tok) {
			return false
		}
	}
	return segs[4] == "APKINDEX.tar.gz" || strings.HasSuffix(segs[4], ".apk")
}

// handleApkPublicKey serves the PEM public key matching the configured index
// signing key, for /etc/apk/keys/<name>.
func (s *HighServer) handleApkPublicKey(w http.ResponseWriter) {
	key, err := loadApkRSAKey(s.cfg.ApkRSAKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_ = pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// readApkMirrorIndex loads one mirror's persistent merged index.
func (s *HighServer) readApkMirrorIndex(mirror string) (ApkMirror, error) {
	if validateMirrorName(mirror) != nil {
		return ApkMirror{}, errors.New("invalid mirror name")
	}
	b, err := os.ReadFile(filepath.Join(s.apkDir(), mirror, "index.json"))
	if err != nil {
		return ApkMirror{}, err
	}
	var m ApkMirror
	if err := json.Unmarshal(b, &m); err != nil {
		return ApkMirror{}, err
	}
	return m, nil
}

// listApkPackages lists the mirrored packages as
// "<mirror>/<branch>/<repo>/<arch>/<package>" with their versions, gated on
// the .apk being present.
func (s *HighServer) listApkPackages() ([]UIModule, error) {
	mirrors, err := os.ReadDir(s.apkDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byName := map[string][]string{}
	for _, d := range mirrors {
		if !d.IsDir() {
			continue
		}
		m, err := s.readApkMirrorIndex(d.Name())
		if err != nil {
			continue
		}
		for _, p := range m.Packages {
			rel := apkFileRel(m.Name, p.Branch, p.Repository, p.Arch, p.Filename)
			abs := filepath.Join(s.downloadDir, filepath.FromSlash(rel))
			if !safeJoin(s.apkDir(), abs) || !fileExists(abs) {
				continue
			}
			key := m.Name + "/" + p.Branch + "/" + p.Repository + "/" + p.Arch + "/" + p.Name
			byName[key] = append(byName[key], p.Version)
		}
	}
	out := make([]UIModule, 0, len(byName))
	for name, versions := range byName {
		sort.Slice(versions, func(i, j int) bool { return apkVersionCompare(versions[i], versions[j]) < 0 })
		out = append(out, UIModule{Module: name, Versions: versions})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// apkDetail describes one mirrored package for the dashboard detail panel.
// spec is "<mirror>/<branch>/<repo>/<arch>/<package>@<version>".
func (s *HighServer) apkDetail(spec string) (UIDetail, error) {
	addr, version, ok := strings.Cut(spec, "@")
	segs := strings.Split(addr, "/")
	if !ok || len(segs) != 5 || validateApkVersion(version) != nil {
		return UIDetail{}, errors.New("invalid package spec")
	}
	m, err := s.readApkMirrorIndex(segs[0])
	if err != nil {
		return UIDetail{}, errors.New("mirror not found")
	}
	for _, p := range m.Packages {
		if p.Branch == segs[1] && p.Repository == segs[2] && p.Arch == segs[3] && p.Name == segs[4] && p.Version == version {
			return s.apkPackageDetail(m.Name, p), nil
		}
	}
	return UIDetail{}, errors.New("package not found")
}

func (s *HighServer) apkPackageDetail(mirror string, p ApkPackage) UIDetail {
	fields := []UIDetailField{
		{Label: "Package", Value: p.Name, Mono: true},
		{Label: "Version", Value: p.Version, Mono: true},
		{Label: "Repository", Value: p.Branch + "/" + p.Repository + " (" + p.Arch + ")", Mono: true},
	}
	for _, f := range []struct{ key, label string }{{"T", "Description"}, {"U", "URL"}, {"L", "License"}, {"m", "Maintainer"}} {
		if v := apkStanzaField(p.Stanza, f.key); v != "" {
			fields = append(fields, UIDetailField{Label: f.label, Value: v})
		}
	}
	fields = append(fields,
		UIDetailField{Label: "Package size", Value: formatBytes(p.Size)},
		UIDetailField{Label: "SHA-256", Value: p.SHA256, Mono: true},
	)
	rel := apkFileRel(mirror, p.Branch, p.Repository, p.Arch, p.Filename)
	downloads := []UIDownload{{Label: p.Filename, URL: "/" + rel}}
	return UIDetail{Title: p.Name, Subtitle: p.Version, Fields: fields, Downloads: downloads}
}

// apkStanzaField extracts one single-letter field from a stanza.
func apkStanzaField(stanza, key string) string {
	for _, line := range strings.Split(stanza, "\n") {
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return v
		}
	}
	return ""
}

// apkRepoList lists the mirrored Alpine repositories for the "Set me up"
// guide: one entry per mirror, its branch/repo selections rendered as suites.
func (s *HighServer) apkRepoList() ([]UIRepo, error) {
	mirrors, err := os.ReadDir(s.apkDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIRepo
	for _, d := range mirrors {
		if !d.IsDir() {
			continue
		}
		m, err := s.readApkMirrorIndex(d.Name())
		if err != nil {
			continue
		}
		repo := UIRepo{Name: m.Name, Signed: s.cfg.ApkRSAKey != "", Kind: "apk"}
		for _, b := range m.Branches {
			repo.Suites = append(repo.Suites, AptSuite{Name: b.Name, Components: b.Repositories, Architectures: b.Architectures})
		}
		out = append(out, repo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// -----------------------------------------------------------------------------
// High side: index regeneration at import
// -----------------------------------------------------------------------------

// publishApk merges each imported mirror into its persistent per-mirror index
// and regenerates every touched APKINDEX from the accumulated stanzas of the
// packages actually present.
func (s *HighServer) publishApk(m *ApkManifest) error {
	if m == nil {
		return nil
	}
	for _, mirror := range m.Mirrors {
		merged, err := s.mergeApkMirror(mirror)
		if err != nil {
			return err
		}
		if err := s.publishApkMirror(merged); err != nil {
			return err
		}
	}
	return nil
}

// mergeApkMirror unions an incoming mirror into the persistent index at
// apk/<mirror>/index.json, keyed by branch/repository/architecture/filename,
// so delta bundles republish indexes covering everything accumulated so far.
func (s *HighServer) mergeApkMirror(m ApkMirror) (ApkMirror, error) {
	if err := validateMirrorName(m.Name); err != nil {
		return ApkMirror{}, err
	}
	idxPath := filepath.Join(s.apkDir(), m.Name, "index.json")
	if !safeJoin(s.apkDir(), idxPath) {
		return ApkMirror{}, fmt.Errorf("unsafe mirror name %q", m.Name)
	}
	merged := m
	if b, err := os.ReadFile(idxPath); err == nil {
		var prev ApkMirror
		if json.Unmarshal(b, &prev) == nil && prev.Name == m.Name {
			merged = mergeApkMirrors(prev, m)
		}
	}
	if err := writeJSONAtomic(idxPath, merged, 0o644); err != nil {
		return ApkMirror{}, err
	}
	return merged, nil
}

// mergeApkMirrors unions two snapshots of the same mirror: the newer wins per
// package file, branch selections are unioned.
func mergeApkMirrors(prev, next ApkMirror) ApkMirror {
	out := next
	out.Branches = mergeApkBranches(prev.Branches, next.Branches)
	byKey := map[string]bool{}
	for _, p := range next.Packages {
		byKey[apkPackageKey(p)] = true
	}
	for _, p := range prev.Packages {
		if !byKey[apkPackageKey(p)] {
			out.Packages = append(out.Packages, p)
		}
	}
	sort.Slice(out.Packages, func(i, j int) bool { return apkPackageKey(out.Packages[i]) < apkPackageKey(out.Packages[j]) })
	return out
}

func apkPackageKey(p ApkPackage) string {
	return p.Branch + "/" + p.Repository + "/" + p.Arch + "/" + p.Filename
}

func mergeApkBranches(prev, next []ApkBranch) []ApkBranch {
	byName := map[string]*ApkBranch{}
	var order []string
	for _, list := range [][]ApkBranch{prev, next} {
		for _, b := range list {
			if got, ok := byName[b.Name]; ok {
				got.Repositories = unionStrings(got.Repositories, b.Repositories)
				got.Architectures = unionStrings(got.Architectures, b.Architectures)
				continue
			}
			cp := b
			byName[b.Name] = &cp
			order = append(order, b.Name)
		}
	}
	sort.Strings(order)
	out := make([]ApkBranch, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// publishApkMirror regenerates the APKINDEX for every branch/repo/arch of the
// merged mirror.
func (s *HighServer) publishApkMirror(m ApkMirror) error {
	for _, b := range m.Branches {
		for _, repo := range b.Repositories {
			for _, arch := range b.Architectures {
				if err := s.regenerateApkIndex(m, b.Name, repo, arch); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// regenerateApkIndex rebuilds one APKINDEX.tar.gz from the accumulated
// stanzas whose package files are present.
func (s *HighServer) regenerateApkIndex(m ApkMirror, branch, repo, arch string) error {
	var stanzas []string
	for _, p := range m.Packages {
		if p.Branch != branch || p.Repository != repo || p.Arch != arch {
			continue
		}
		if validateApkStanza(p.Stanza) != nil {
			continue
		}
		rel := apkFileRel(m.Name, p.Branch, p.Repository, p.Arch, p.Filename)
		abs := filepath.Join(s.downloadDir, filepath.FromSlash(rel))
		if safeJoin(s.apkDir(), abs) && fileExists(abs) {
			stanzas = append(stanzas, strings.Trim(p.Stanza, "\n"))
		}
	}
	sort.Strings(stanzas)
	archive, err := s.buildApkIndexArchive(stanzas)
	if err != nil {
		return err
	}
	out := filepath.Join(s.apkDir(), m.Name, branch, repo, arch, "APKINDEX.tar.gz")
	if !safeJoin(s.apkDir(), out) {
		return fmt.Errorf("unsafe index path for %s/%s/%s/%s", m.Name, branch, repo, arch)
	}
	return writeBytesAtomic(out, archive, 0o644)
}

// buildApkIndexArchive renders an APKINDEX.tar.gz: the index and DESCRIPTION
// in one gzip stream, preceded — when index signing is configured — by a
// "cut" signature segment carrying the RSA signature apk verifies against
// /etc/apk/keys/<name>.
func (s *HighServer) buildApkIndexArchive(stanzas []string) ([]byte, error) {
	var index strings.Builder
	for _, st := range stanzas {
		index.WriteString(st)
		index.WriteString("\n\n")
	}
	control, err := apkTarGzSegment([]apkTarFile{
		{name: "DESCRIPTION", data: []byte("ArtiGate mirror")},
		{name: "APKINDEX", data: []byte(index.String())},
	}, false)
	if err != nil {
		return nil, err
	}
	if s.cfg.ApkRSAKey == "" {
		return control, nil
	}
	sig, err := signApkIndex(s.cfg.ApkRSAKey, control)
	if err != nil {
		return nil, err
	}
	sigSeg, err := apkTarGzSegment([]apkTarFile{{name: ".SIGN.RSA." + s.cfg.ApkKeyName, data: sig}}, true)
	if err != nil {
		return nil, err
	}
	return append(sigSeg, control...), nil
}

type apkTarFile struct {
	name string
	data []byte
}

// apkTarGzSegment writes one gzip stream holding a tar of the given files.
// cut leaves off the tar end-of-archive blocks — the format of an .apk/index
// signature segment, designed so concatenated segments read as one tar.
func apkTarGzSegment(files []apkTarFile, cut bool) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	var err error
	if cut {
		err = tw.Flush()
	} else {
		err = tw.Close()
	}
	if err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// signApkIndex signs the index segment bytes the way apk verifies a
// .SIGN.RSA.<name> member: an RSA PKCS#1 v1.5 signature over the segment's
// SHA-1 digest.
func signApkIndex(keyPath string, segment []byte) ([]byte, error) {
	key, err := loadApkRSAKey(keyPath)
	if err != nil {
		return nil, err
	}
	digest := sha1.Sum(segment) //nolint:gosec // apk's .SIGN.RSA format mandates SHA-1
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
}

// loadApkRSAKey reads a PEM RSA private key (PKCS#1 or PKCS#8).
func loadApkRSAKey(p string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", p)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA private key", p)
	}
	return key, nil
}

// -----------------------------------------------------------------------------
// Low side: mirror collector
// -----------------------------------------------------------------------------

// ApkCollectRequest is the body of POST /admin/apk/collect. Provide either the
// URI/Branches/Repositories/Architectures fields, or paste an
// /etc/apk/repositories file whose lines name <uri>/<branch>/<repo>.
type ApkCollectRequest struct {
	Name          string   `json:"name,omitempty"`
	URI           string   `json:"uri"`
	Branches      []string `json:"branches"`
	Repositories  []string `json:"repositories,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	// RepositoriesFile is the pasted content of an /etc/apk/repositories file,
	// an alternative to URI+Branches+Repositories.
	RepositoriesFile string `json:"repositories_file,omitempty"`
	// NewestOnly keeps only each package's highest version (the usual state of
	// an Alpine index); nil defaults to true.
	NewestOnly *bool `json:"newest_only,omitempty"`
	// Force disables export dedup for this collect: every package is packed
	// even when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// apkMirrorPlan is a validated collect request.
type apkMirrorPlan struct {
	name       string
	uri        string
	branches   []ApkBranch
	newestOnly bool
}

// parseApkRepositoriesFile extracts the shared mirror base and the
// branch->repositories selection from /etc/apk/repositories lines
// ("https://mirror/alpine/v3.20/main", optionally "@tag"-prefixed).
func parseApkRepositoriesFile(text string) (uri string, branchRepos map[string][]string, err error) {
	branchRepos = map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@") { // tagged repository: "@tag url"
			_, line, _ = strings.Cut(line, " ")
			line = strings.TrimSpace(line)
		}
		base, branch, repo, err := splitApkRepoURL(line)
		if err != nil {
			return "", nil, err
		}
		if uri == "" {
			uri = base
		} else if uri != base {
			return "", nil, fmt.Errorf("repositories name different mirrors (%s and %s); collect them separately", uri, base)
		}
		if !containsString(branchRepos[branch], repo) {
			branchRepos[branch] = append(branchRepos[branch], repo)
		}
	}
	if uri == "" {
		return "", nil, errors.New("repositories file lists no repositories")
	}
	return uri, branchRepos, nil
}

// splitApkRepoURL splits ".../alpine/v3.20/main" into the mirror base, the
// branch, and the repository.
func splitApkRepoURL(line string) (base, branch, repo string, err error) {
	u, uerr := url.Parse(line)
	if uerr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", "", fmt.Errorf("repository %q must be an http(s) URL", line)
	}
	trimmed := strings.TrimRight(u.Path, "/")
	segs := strings.Split(trimmed, "/")
	if len(segs) < 3 {
		return "", "", "", fmt.Errorf("repository %q must end in <branch>/<repo>", line)
	}
	branch, repo = segs[len(segs)-2], segs[len(segs)-1]
	u.Path = strings.Join(segs[:len(segs)-2], "/")
	u.RawQuery, u.Fragment = "", ""
	return strings.TrimRight(u.String(), "/"), branch, repo, nil
}

// resolveApkRequest validates a collect request into a concrete plan.
func resolveApkRequest(req ApkCollectRequest) (apkMirrorPlan, error) {
	plan := apkMirrorPlan{newestOnly: req.NewestOnly == nil || *req.NewestOnly}
	arches := req.Architectures
	if len(arches) == 0 {
		arches = []string{"x86_64"}
	}
	if err := apkPlanSelection(&plan, req, arches); err != nil {
		return apkMirrorPlan{}, err
	}
	if u, err := url.Parse(plan.uri); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return apkMirrorPlan{}, fmt.Errorf("apk mirror uri %q must be an http(s) URL", plan.uri)
	}
	plan.name = req.Name
	if plan.name == "" {
		plan.name = aptMirrorName(plan.uri)
	}
	if err := validateMirrorName(plan.name); err != nil {
		return apkMirrorPlan{}, err
	}
	return plan, validateApkPlanTokens(plan)
}

// apkPlanSelection fills the plan's mirror URI and branch selections from
// either the pasted repositories file or the structured fields.
func apkPlanSelection(plan *apkMirrorPlan, req ApkCollectRequest, arches []string) error {
	if strings.TrimSpace(req.RepositoriesFile) != "" {
		uri, branchRepos, err := parseApkRepositoriesFile(req.RepositoriesFile)
		if err != nil {
			return err
		}
		plan.uri = uri
		branches := make([]string, 0, len(branchRepos))
		for b := range branchRepos {
			branches = append(branches, b)
		}
		sort.Strings(branches)
		for _, b := range branches {
			plan.branches = append(plan.branches, ApkBranch{Name: b, Repositories: branchRepos[b], Architectures: arches})
		}
		return nil
	}
	if strings.TrimSpace(req.URI) == "" || len(req.Branches) == 0 {
		return errors.New("provide uri and branches (or a repositories file)")
	}
	repos := req.Repositories
	if len(repos) == 0 {
		repos = []string{"main"}
	}
	plan.uri = strings.TrimRight(strings.TrimSpace(req.URI), "/")
	for _, b := range dedupeStrings(req.Branches) {
		plan.branches = append(plan.branches, ApkBranch{Name: b, Repositories: dedupeStrings(repos), Architectures: dedupeStrings(arches)})
	}
	return nil
}

func validateApkPlanTokens(plan apkMirrorPlan) error {
	for _, b := range plan.branches {
		toks := append([]string{b.Name}, b.Repositories...)
		for _, tok := range append(toks, b.Architectures...) {
			if !validRepoToken(tok) {
				return fmt.Errorf("invalid branch/repository/architecture %q", tok)
			}
		}
	}
	return nil
}

// HandleApkCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandleApkCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req ApkCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse apk collect request: %w", err)
		}
	}
	return s.CollectApk(ctx, req)
}

// CollectApk mirrors the selected branches/repositories/architectures of an
// Alpine mirror: it fetches each APKINDEX, downloads every listed package —
// verified against the index's size and control checksum — and writes them
// into a signed bundle on the apk stream. The upstream index publishes no
// whole-file hash, so unchanged packages are re-downloaded on every collect
// and deduplicated at export time (the bundle carries only new content).
func (s *LowServer) CollectApk(ctx context.Context, req ApkCollectRequest) (ExportResult, error) {
	plan, err := resolveApkRequest(req)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the apk stream's lock for the whole mirror->write->commit so a
	// concurrent apk exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamApk)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "apk", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	mirror := ApkMirror{Name: plan.name, URI: plan.uri, Branches: plan.branches}
	var files []ManifestFile
	var failed []FailedModule
	for _, b := range plan.branches {
		for _, repo := range b.Repositories {
			for _, arch := range b.Architectures {
				pkgs, mfs, skipped, err := s.mirrorApkRepo(ctx, stageRoot, plan, b.Name, repo, arch)
				if err != nil {
					return ExportResult{}, err
				}
				mirror.Packages = append(mirror.Packages, pkgs...)
				files = append(files, mfs...)
				failed = append(failed, skipped...)
			}
		}
	}
	if len(mirror.Packages) == 0 {
		return ExportResult{}, fmt.Errorf("no apk packages could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))

	res, err := s.exportIfNew(ctx, streamApk, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeApkBundle(ctx, seq, stageRoot, files, mirror)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// mirrorApkRepo fetches one branch/repo/arch index and downloads its packages
// into the staging tree. Per-package failures are collected rather than
// aborting the batch; an unreachable index fails the collect (a selection
// error the operator should see).
func (s *LowServer) mirrorApkRepo(ctx context.Context, stageRoot string, plan apkMirrorPlan, branch, repo, arch string) ([]ApkPackage, []ManifestFile, []FailedModule, error) {
	repoURL := plan.uri + "/" + branch + "/" + repo + "/" + arch
	emitProgress(ctx, "Fetching %s/APKINDEX.tar.gz…", repoURL)
	raw, err := httpGetBytes(ctx, repoURL+"/APKINDEX.tar.gz", maxIndexFetchBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	text, err := apkIndexFromArchive(raw, maxIndexPlainBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", repoURL, err)
	}
	stanzas := parseApkIndex(text)
	if plan.newestOnly {
		stanzas = filterNewestApk(stanzas)
	}
	emitProgress(ctx, "%s/%s/%s lists %d package(s)", branch, repo, arch, len(stanzas))
	return s.downloadApkPackages(ctx, stageRoot, plan.name, repoURL, branch, repo, arch, stanzas)
}

// filterNewestApk keeps each package's highest version.
func filterNewestApk(stanzas []apkStanza) []apkStanza {
	best := map[string]apkStanza{}
	var order []string
	for _, st := range stanzas {
		got, ok := best[st.Name]
		if !ok {
			best[st.Name] = st
			order = append(order, st.Name)
			continue
		}
		if apkVersionCompare(st.Version, got.Version) > 0 {
			best[st.Name] = st
		}
	}
	out := make([]apkStanza, 0, len(order))
	for _, name := range order {
		out = append(out, best[name])
	}
	return out
}

// downloadApkPackages fetches every stanza's package into the staging tree.
func (s *LowServer) downloadApkPackages(ctx context.Context, stageRoot, mirror, repoURL, branch, repo, arch string, stanzas []apkStanza) ([]ApkPackage, []ManifestFile, []FailedModule, error) {
	var pkgs []ApkPackage
	var files []ManifestFile
	var failed []FailedModule
	seen := map[string]bool{}
	for i, st := range stanzas {
		emitProgress(ctx, "→ [%d/%d] %s-%s (%s)", i+1, len(stanzas), st.Name, st.Version, arch)
		pkg, mf, err := s.downloadApkPackage(ctx, stageRoot, mirror, repoURL, branch, repo, arch, st)
		if err != nil {
			emitProgress(ctx, "  ✗ %s-%s: %s", st.Name, st.Version, err)
			failed = append(failed, FailedModule{Module: st.Name, Version: st.Version, Error: err.Error()})
			continue
		}
		if seen[mf.Path] {
			continue
		}
		seen[mf.Path] = true
		pkgs = append(pkgs, pkg)
		files = append(files, mf)
	}
	return pkgs, files, failed, nil
}

// downloadApkPackage fetches one .apk and verifies it against the index
// stanza: the exact declared size and the C: control checksum.
func (s *LowServer) downloadApkPackage(ctx context.Context, stageRoot, mirror, repoURL, branch, repo, arch string, st apkStanza) (ApkPackage, ManifestFile, error) {
	if err := validateApkName(st.Name); err != nil {
		return ApkPackage{}, ManifestFile{}, err
	}
	if err := validateApkVersion(st.Version); err != nil {
		return ApkPackage{}, ManifestFile{}, err
	}
	if err := validateApkStanza(st.Text); err != nil {
		return ApkPackage{}, ManifestFile{}, err
	}
	filename := st.Name + "-" + st.Version + ".apk"
	rel := apkFileRel(mirror, branch, repo, arch, filename)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadFileSHA256(ctx, repoURL+"/"+filename, abs)
	if err != nil {
		return ApkPackage{}, ManifestFile{}, err
	}
	if st.Size > 0 && size != st.Size {
		_ = os.Remove(abs)
		return ApkPackage{}, ManifestFile{}, fmt.Errorf("size mismatch: got %d want %d", size, st.Size)
	}
	if st.Checksum != "" {
		if err := apkVerifyControlChecksum(abs, st.Checksum); err != nil {
			_ = os.Remove(abs)
			return ApkPackage{}, ManifestFile{}, err
		}
	}
	pkg := ApkPackage{
		Name: st.Name, Version: st.Version, Arch: arch, Branch: branch, Repository: repo,
		Filename: filename, SHA256: sum, Size: size, Stanza: strings.Trim(st.Text, "\n"),
	}
	return pkg, ManifestFile{Path: rel, SHA256: sum, Size: size}, nil
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeApkBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, mirror ApkMirror) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(mirror.Packages, func(i, j int) bool {
		return apkPackageKey(mirror.Packages[i]) < apkPackageKey(mirror.Packages[j])
	})
	id := bundleIDFor(streamApk, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamApk,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"apk"},
		Apk:              &ApkManifest{Mirrors: []ApkMirror{mirror}},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamApk, Sequence: seq, ExportedModules: len(mirror.Packages), BundleID: id}, nil
}
