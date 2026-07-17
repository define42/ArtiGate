package main

// Snap package ecosystem adapter. The low side resolves snaps against the
// Snap Store API (GET /v2/snaps/info/<name> with the Snap-Device-Series
// header), picks the requested channel and architecture from the channel map,
// downloads the .snap squashfs verified against the store-declared SHA3-384,
// and fetches the store's signed assertion chain — account-key, account,
// snap-declaration, snap-revision — composing the same .assert document
// `snap download` writes. Both files pack into the same numbered, signed
// ArtiGate bundle format used by the other ecosystems. The high side
// re-verifies every imported snap independently: it recomputes the archive's
// SHA3-384 and requires the .assert's snap-revision assertion to match it
// (digest, size, revision, snap-id) and the snap-declaration to bind that
// snap-id to the snap's name, then regenerates the served metadata. Clients
// consume the mirror with snapd's supported offline flow — download the pair,
// `snap ack <name>_<rev>.assert`, `snap install <name>_<rev>.snap` — so the
// assertions pass through verbatim and snapd's own built-in root of trust,
// not the mirror, decides whether they are genuine.

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
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
	"strconv"
	"strings"
	"time"
)

// snapEcosystem is the snap package stream's registry entry (see ecosystems
// in ecosystem.go).
func snapEcosystem() ecosystem {
	return ecosystem{
		stream:       streamSnap,
		label:        "Snap",
		title:        "Snap packages",
		collect:      (*LowServer).HandleSnapCollect,
		watchCollect: watchAdapter((*LowServer).CollectSnap),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.SnapStoreURL, "snap-store", "", "Snap Store API base URL snaps and assertions are fetched from (default "+defaultSnapStoreURL+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.Snap != nil && len(m.Snap.Snaps) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateSnapPackages(m.Snap.Snaps, seen)
		},
		contentDesc: "snap packages",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishSnap(m.Snap) },
		serve:       (*HighServer).serveSnap,
		scanTree:    flatTreeScan((*HighServer).listSnapPackages),
		detail:      (*HighServer).snapDetail,
	}
}

// defaultSnapStoreURL is the public Snap Store API.
const defaultSnapStoreURL = "https://api.snapcraft.io"

const (
	// snapDeviceSeries is the store series every request declares; 16 is the
	// only series that exists.
	snapDeviceSeries = "16"
	// snapAssertionAccept is the Accept type that makes the assertion
	// endpoints answer with the signed assertion text instead of JSON.
	snapAssertionAccept = "application/x.ubuntu.assertion"
	// snapInfoFields is the field list requested from /v2/snaps/info; every
	// name is from snapd's own request so the store accepts them all.
	snapInfoFields = "architectures,base,confinement,created-at,download,license,publisher,revision,snap-id,summary,title,type,version"
	// snapMaxInfoBytes caps one snap-info response held in memory.
	snapMaxInfoBytes = 8 << 20
	// snapMaxAssertionBytes caps one fetched assertion document.
	snapMaxAssertionBytes = 1 << 20
	// snapMaxAssertFileBytes caps a stored .assert file parsed at import.
	snapMaxAssertFileBytes = 4 << 20
	// snapMaxAssertions bounds how many assertions one stream may carry.
	snapMaxAssertions = 100
	// snapMaxResolved bounds one collect's snap count (requests plus the
	// bases pulled in with them).
	snapMaxResolved = 100
	// snapMaxRevision keeps revisions inside int32 like snapd does.
	snapMaxRevision = 1<<31 - 1
	// snapDefaultChannel is used when a spec pins no channel.
	snapDefaultChannel = "stable"
	// snapDefaultArch is used when a collect names no architecture.
	snapDefaultArch = "amd64"
)

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type SnapManifest struct {
	Snaps []SnapPackage `json:"snaps"`
}

// SnapPackage records one mirrored snap revision: the .snap archive plus its
// .assert assertion chain. Version, channel, and the descriptive fields are
// informational (they come from the store's metadata and feed the dashboard);
// the identity the high side verifies against the assertions is name, snap-id,
// revision, and the SHA3-384 digest.
type SnapPackage struct {
	Name         string `json:"name"`
	SnapID       string `json:"snap_id"`
	Revision     int    `json:"revision"`
	Channel      string `json:"channel"`
	Architecture string `json:"architecture"`
	Version      string `json:"version,omitempty"`
	Base         string `json:"base,omitempty"`
	Confinement  string `json:"confinement,omitempty"`
	Type         string `json:"type,omitempty"`
	Summary      string `json:"summary,omitempty"`
	Publisher    string `json:"publisher,omitempty"`
	License      string `json:"license,omitempty"`
	Filename     string `json:"filename"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	// SHA3384 is the store-declared hex SHA3-384 of the archive — the digest
	// the snap-revision assertion is keyed by.
	SHA3384 string `json:"sha3_384"`
	// AssertPath is the mirrored .assert file, always beside the archive.
	AssertPath string `json:"assert_path"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// snapNameRE matches snapd's snap naming rule: lowercase alphanumerics and
// single inner hyphens. At least one letter and the length cap are checked
// separately.
var snapNameRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// snapLetterRE requires the letter a snap name must contain.
var snapLetterRE = regexp.MustCompile(`[a-z]`)

func validateSnapName(name string) error {
	if len(name) > 40 || !snapNameRE.MatchString(name) || !snapLetterRE.MatchString(name) {
		return fmt.Errorf("invalid snap name %q", name)
	}
	return nil
}

// snapChannelRE matches a channel spec: a risk ("stable"), track/risk
// ("latest/edge", "22.04/stable"), or track/risk/branch. Segments start
// alphanumeric, so a channel is never path- or flag-shaped.
var snapChannelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,40}(?:/[a-z0-9][a-z0-9.-]{0,40}){0,2}$`)

func validateSnapChannel(ch string) error {
	if !snapChannelRE.MatchString(ch) {
		return fmt.Errorf("invalid snap channel %q", ch)
	}
	return nil
}

// snapArchRE matches a debian-style architecture name (amd64, arm64, armhf,
// ppc64el, s390x, riscv64, ...).
var snapArchRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,19}$`)

func validateSnapArch(arch string) error {
	if !snapArchRE.MatchString(arch) {
		return fmt.Errorf("invalid snap architecture %q", arch)
	}
	return nil
}

// snapIDRE matches a store snap-id (32 base62 characters today; the bound is
// generous so a format change does not break imports).
var snapIDRE = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)

func validateSnapID(id string) error {
	if !snapIDRE.MatchString(id) {
		return fmt.Errorf("invalid snap-id %q", id)
	}
	return nil
}

// snapSHA3384HexRE matches the store's hex SHA3-384 digest of an archive.
var snapSHA3384HexRE = regexp.MustCompile(`^[0-9a-f]{96}$`)

// snapAccountRefRE matches the identifiers assertion fetches embed in store
// URLs: account ids and base64url key digests.
var snapAccountRefRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validateSnapRevision(rev int) error {
	if rev < 1 || rev > snapMaxRevision {
		return fmt.Errorf("invalid snap revision %d", rev)
	}
	return nil
}

// validateSnapFreeText bounds the informational store metadata carried in a
// manifest record (version, summary, ...): printable and short. These fields
// never name files — they only feed regenerated metadata and the dashboard.
func validateSnapFreeText(field, v string, maxLen int) error {
	if len(v) > maxLen {
		return fmt.Errorf("snap %s longer than %d bytes", field, maxLen)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("snap %s contains control characters", field)
		}
	}
	return nil
}

// snapFilename is the canonical archive name a mirrored snap revision is
// stored under — the same "<name>_<revision>.snap" that `snap download`
// writes, so the served pair feeds `snap ack` + `snap install` verbatim.
func snapFilename(name string, revision int) string {
	return fmt.Sprintf("%s_%d.snap", name, revision)
}

// snapAssertFilename is the canonical assertion-file name for a revision.
func snapAssertFilename(name string, revision int) string {
	return fmt.Sprintf("%s_%d.assert", name, revision)
}

// snapFileRel is the repository-relative path of one stored snap file.
func snapFileRel(name, filename string) string {
	return path.Join("snap", "files", name, filename)
}

// validateSnapPackage checks one manifest record: path-safe identity, the
// canonical storage paths, and that both referenced files are listed.
func validateSnapPackage(p SnapPackage, seen map[string]bool) error {
	if err := errors.Join(
		validateSnapName(p.Name),
		validateSnapID(p.SnapID),
		validateSnapRevision(p.Revision),
		validateSnapChannel(p.Channel),
		validateSnapArch(p.Architecture),
		validateSnapFreeText("version", p.Version, 128),
		validateSnapFreeText("metadata", p.Base+p.Confinement+p.Type+p.Publisher+p.License, 512),
		validateSnapFreeText("summary", p.Summary, 1024),
	); err != nil {
		return fmt.Errorf("snap %s: %w", p.Name, err)
	}
	if !snapSHA3384HexRE.MatchString(p.SHA3384) {
		return fmt.Errorf("snap %s@%d has no usable sha3-384 digest", p.Name, p.Revision)
	}
	if p.Filename != snapFilename(p.Name, p.Revision) {
		return fmt.Errorf("snap %s@%d has non-canonical filename %s", p.Name, p.Revision, p.Filename)
	}
	if p.Path != snapFileRel(p.Name, p.Filename) || !seen[p.Path] {
		return fmt.Errorf("snap %s@%d references file not listed in manifest.files: %s", p.Name, p.Revision, p.Path)
	}
	if p.AssertPath != snapFileRel(p.Name, snapAssertFilename(p.Name, p.Revision)) || !seen[p.AssertPath] {
		return fmt.Errorf("snap %s@%d references assertions not listed in manifest.files: %s", p.Name, p.Revision, p.AssertPath)
	}
	return nil
}

// validateSnapPackages checks every snap record of a bundle manifest.
func validateSnapPackages(pkgs []SnapPackage, seen map[string]bool) error {
	for _, p := range pkgs {
		if err := validateSnapPackage(p, seen); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Assertion parsing (shared by both sides)
// -----------------------------------------------------------------------------

// snapAssertion is one parsed store assertion: its scalar headers plus the
// verbatim text (headers, body, signature) it arrived as.
type snapAssertion struct {
	headers map[string]string
	text    []byte
}

func (a snapAssertion) header(k string) string { return a.headers[k] }

// parseSnapAssertionHeaders reads the scalar "name: value" headers of an
// assertion's header block. Multiline values (continuation lines indented
// with spaces) are skipped — every header ArtiGate reads is a scalar.
func parseSnapAssertionHeaders(b []byte) map[string]string {
	h := map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, " ") {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			h[k] = strings.TrimSpace(v)
		}
	}
	return h
}

// splitSnapAssertions splits a stream of store assertions. Each assertion is
// a header block, a blank line, an optional body of exactly body-length bytes
// followed by a blank line, and a base64 signature block; assertions in a
// stream are separated by blank lines.
func splitSnapAssertions(stream []byte) ([]snapAssertion, error) {
	var out []snapAssertion
	rest := stream
	for {
		rest = bytes.TrimLeft(rest, "\n")
		if len(rest) == 0 {
			return out, nil
		}
		if len(out) == snapMaxAssertions {
			return nil, fmt.Errorf("assertion stream carries more than %d assertions", snapMaxAssertions)
		}
		a, tail, err := cutSnapAssertion(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
		rest = tail
	}
}

// cutSnapAssertion parses the stream's first assertion and returns the rest.
func cutSnapAssertion(rest []byte) (snapAssertion, []byte, error) {
	head, tail, ok := bytes.Cut(rest, []byte("\n\n"))
	if !ok {
		return snapAssertion{}, nil, errors.New("truncated assertion: no header/signature separator")
	}
	headers := parseSnapAssertionHeaders(head)
	if headers["type"] == "" {
		return snapAssertion{}, nil, errors.New("assertion has no type header")
	}
	bodyLen, err := snapAssertionBodyLength(headers)
	if err != nil {
		return snapAssertion{}, nil, err
	}
	if bodyLen > 0 {
		if len(tail) < bodyLen+2 || tail[bodyLen] != '\n' || tail[bodyLen+1] != '\n' {
			return snapAssertion{}, nil, errors.New("truncated assertion body")
		}
		tail = tail[bodyLen+2:]
	}
	sig, next, _ := bytes.Cut(tail, []byte("\n\n"))
	if len(bytes.TrimSpace(sig)) == 0 {
		return snapAssertion{}, nil, errors.New("assertion has an empty signature")
	}
	textLen := len(rest) - len(next)
	text := bytes.Trim(rest[:textLen], "\n")
	return snapAssertion{headers: headers, text: text}, next, nil
}

// snapAssertionBodyLength reads the optional body-length header.
func snapAssertionBodyLength(headers map[string]string) (int, error) {
	raw := headers["body-length"]
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > snapMaxAssertFileBytes {
		return 0, fmt.Errorf("invalid assertion body-length %q", raw)
	}
	return n, nil
}

// findSnapAssertion returns the stream's first assertion of the given type
// whose key header carries the wanted value.
func findSnapAssertion(as []snapAssertion, typ, key, want string) (snapAssertion, bool) {
	for _, a := range as {
		if a.header("type") == typ && a.header(key) == want {
			return a, true
		}
	}
	return snapAssertion{}, false
}

// hasSnapAssertionType reports whether the stream carries an assertion of the
// given type.
func hasSnapAssertionType(as []snapAssertion, typ string) bool {
	for _, a := range as {
		if a.header("type") == typ {
			return true
		}
	}
	return false
}

// composeSnapAssertions joins fetched assertion documents into one stream in
// the order given, normalizing separators to a single blank line — the same
// layout `snap download` writes and `snap ack` consumes.
func composeSnapAssertions(docs [][]byte) []byte {
	parts := make([]string, 0, len(docs))
	for _, d := range docs {
		parts = append(parts, strings.Trim(string(d), "\n"))
	}
	return []byte(strings.Join(parts, "\n\n") + "\n")
}

// snapDigestBase64 converts the store's hex SHA3-384 to the unpadded
// base64url form assertions (and the assertion endpoints) key snaps by.
func snapDigestBase64(hexDigest string) (string, error) {
	if !snapSHA3384HexRE.MatchString(hexDigest) {
		return "", fmt.Errorf("invalid sha3-384 digest %q", hexDigest)
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// -----------------------------------------------------------------------------
// High side: serving
// -----------------------------------------------------------------------------

func (s *HighServer) snapDir() string {
	return filepath.Join(s.downloadDir, "snap")
}

func (s *HighServer) snapFilesDir() string {
	return filepath.Join(s.snapDir(), "files")
}

func (s *HighServer) snapMetadataDir() string {
	return filepath.Join(s.snapDir(), "metadata")
}

// snapArtifactAbs is the on-disk location of one stored snap file.
func (s *HighServer) snapArtifactAbs(name, filename string) string {
	return filepath.Join(s.snapFilesDir(), name, filename)
}

// serveSnap handles the snap routes under /snap/: direct downloads of the
// .snap/.assert pairs and a per-snap JSON summary of the mirrored revisions.
// It reports whether it wrote a response for the request.
func (s *HighServer) serveSnap(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/snap" && !strings.HasPrefix(p, "/snap/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	segs := strings.Split(strings.Trim(strings.TrimPrefix(p, "/snap"), "/"), "/")
	switch {
	case len(segs) == 3 && segs[0] == "files":
		s.handleSnapFile(w, r, segs[1], segs[2])
	case len(segs) == 2 && segs[0] == "info":
		s.handleSnapInfo(w, segs[1])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

// handleSnapFile serves one stored .snap or .assert file.
func (s *HighServer) handleSnapFile(w http.ResponseWriter, r *http.Request, name, file string) {
	if validateSnapName(name) != nil ||
		(!strings.HasSuffix(file, ".snap") && !strings.HasSuffix(file, ".assert")) ||
		!strings.HasPrefix(file, name+"_") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := s.snapArtifactAbs(name, file)
	if !safeJoin(s.snapFilesDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	if strings.HasSuffix(file, ".assert") {
		w.Header().Set("Content-Type", snapAssertionAccept)
	}
	serveFile(w, r, abs)
}

// snapInfoResponse is the body of GET /snap/info/<name>.
type snapInfoResponse struct {
	Name      string             `json:"name"`
	Revisions []snapInfoRevision `json:"revisions"`
}

// snapInfoRevision is one mirrored revision in an info response, newest
// (highest revision) first.
type snapInfoRevision struct {
	snapStoredRevision

	Files map[string]string `json:"files"`
}

// handleSnapInfo answers with the regenerated metadata of one snap's
// mirrored revisions, so scripted clients can find the files to download.
func (s *HighServer) handleSnapInfo(w http.ResponseWriter, name string) {
	if validateSnapName(name) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	stored := s.snapServedRevisions(name)
	if len(stored) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp := snapInfoResponse{Name: name, Revisions: make([]snapInfoRevision, 0, len(stored))}
	for _, st := range stored {
		base := "/snap/files/" + name + "/"
		resp.Revisions = append(resp.Revisions, snapInfoRevision{
			snapStoredRevision: st,
			Files: map[string]string{
				"snap":   base + st.Filename,
				"assert": base + snapAssertFilename(name, st.Revision),
			},
		})
	}
	writeJSON(w, resp)
}

// -----------------------------------------------------------------------------
// High side: verification and metadata regeneration at import
// -----------------------------------------------------------------------------

// snapStoredRevision is the per-revision metadata the high side regenerates
// at import time: the identity fields it verified against the .assert's
// snap-revision and snap-declaration assertions, plus the store's descriptive
// metadata from the signed bundle record.
type snapStoredRevision struct {
	Filename     string `json:"filename"`
	Revision     int    `json:"revision"`
	SnapID       string `json:"snap_id"`
	Version      string `json:"version,omitempty"`
	Channel      string `json:"channel,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Base         string `json:"base,omitempty"`
	Confinement  string `json:"confinement,omitempty"`
	Type         string `json:"type,omitempty"`
	Summary      string `json:"summary,omitempty"`
	Publisher    string `json:"publisher,omitempty"`
	License      string `json:"license,omitempty"`
	SHA3384      string `json:"sha3_384"`
	Size         int64  `json:"size"`
}

// publishSnap regenerates the served metadata for every snap in an imported
// bundle after verifying each archive against its assertion chain. A snap
// that fails verification is logged and skipped (it stays out of the served
// metadata) rather than wedging the stream's import forever.
func (s *HighServer) publishSnap(m *SnapManifest) error {
	if m == nil {
		return nil
	}
	for _, p := range m.Snaps {
		if err := s.publishSnapPackage(p); err != nil {
			log.Printf("snap publish %s@%d: %v", p.Name, p.Revision, err)
		}
	}
	return nil
}

// publishSnapPackage verifies one imported revision — the archive's recomputed
// SHA3-384 against the snap-revision assertion, and the snap-declaration's
// name/snap-id binding — then writes its regenerated metadata.
func (s *HighServer) publishSnapPackage(p SnapPackage) error {
	if err := errors.Join(validateSnapName(p.Name), validateSnapRevision(p.Revision), validateSnapID(p.SnapID)); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(p.Path))
	assertAbs := filepath.Join(s.downloadDir, filepath.FromSlash(p.AssertPath))
	if !strings.HasPrefix(p.Path, "snap/files/") || !safeJoin(s.snapFilesDir(), abs) ||
		!strings.HasPrefix(p.AssertPath, "snap/files/") || !safeJoin(s.snapFilesDir(), assertAbs) {
		return fmt.Errorf("unsafe snap path %s", p.Path)
	}
	digestHex, size, err := snapSHA3384File(abs)
	if err != nil {
		return err
	}
	if st, err := os.Stat(assertAbs); err != nil {
		return err
	} else if st.Size() > snapMaxAssertFileBytes {
		return fmt.Errorf("assertion file exceeds the %s cap", formatBytes(snapMaxAssertFileBytes))
	}
	assertText, err := os.ReadFile(assertAbs)
	if err != nil {
		return err
	}
	if err := snapVerifyAssertions(assertText, p, digestHex, size); err != nil {
		return err
	}
	st := snapStoredRevision{
		Filename: p.Filename, Revision: p.Revision, SnapID: p.SnapID,
		Version: p.Version, Channel: p.Channel, Architecture: p.Architecture,
		Base: p.Base, Confinement: p.Confinement, Type: p.Type,
		Summary: p.Summary, Publisher: p.Publisher, License: p.License,
		SHA3384: digestHex, Size: size,
	}
	out := filepath.Join(s.snapMetadataDir(), p.Name, strconv.Itoa(p.Revision)+".json")
	if !safeJoin(s.snapMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s@%d", p.Name, p.Revision)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// snapVerifyAssertions checks a stored .assert against the archive it arrived
// with: the snap-revision assertion must match the recomputed digest, size,
// revision, and snap-id, and the snap-declaration must bind that snap-id to
// the record's name. The assertions' own signatures pass through verbatim for
// snapd to verify against its built-in root of trust at `snap ack` time.
func snapVerifyAssertions(assertText []byte, p SnapPackage, digestHex string, size int64) error {
	digestB64, err := snapDigestBase64(digestHex)
	if err != nil {
		return err
	}
	as, err := splitSnapAssertions(assertText)
	if err != nil {
		return fmt.Errorf("parse assertions: %w", err)
	}
	rev, ok := findSnapAssertion(as, "snap-revision", "snap-sha3-384", digestB64)
	if !ok {
		return errors.New("no snap-revision assertion matches the archive digest")
	}
	if rev.header("snap-size") != strconv.FormatInt(size, 10) {
		return fmt.Errorf("snap-revision assertion declares size %s, archive is %d", rev.header("snap-size"), size)
	}
	if rev.header("snap-revision") != strconv.Itoa(p.Revision) {
		return fmt.Errorf("snap-revision assertion is for revision %s, record says %d", rev.header("snap-revision"), p.Revision)
	}
	if rev.header("snap-id") != p.SnapID {
		return fmt.Errorf("snap-revision assertion is for snap-id %s, record says %s", rev.header("snap-id"), p.SnapID)
	}
	decl, ok := findSnapAssertion(as, "snap-declaration", "snap-id", p.SnapID)
	if !ok {
		return errors.New("no snap-declaration assertion for the snap-id")
	}
	if decl.header("snap-name") != p.Name {
		return fmt.Errorf("snap-declaration names %q, record says %q", decl.header("snap-name"), p.Name)
	}
	// `snap ack` needs the whole prerequisite chain in the stream: the
	// signing keys and the publisher account, not just the two leaves.
	for _, typ := range []string{"account-key", "account"} {
		if !hasSnapAssertionType(as, typ) {
			return fmt.Errorf("assertion file carries no %s assertion", typ)
		}
	}
	return nil
}

// snapSHA3384File computes the hex SHA3-384 and size of a stored archive.
func snapSHA3384File(abs string) (string, int64, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha3.New384()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// readSnapStored loads one revision's regenerated metadata and checks both
// its files are still present (only complete revisions are served).
func (s *HighServer) readSnapStored(name string, revision int) (snapStoredRevision, error) {
	p := filepath.Join(s.snapMetadataDir(), name, strconv.Itoa(revision)+".json")
	if !safeJoin(s.snapMetadataDir(), p) {
		return snapStoredRevision{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return snapStoredRevision{}, err
	}
	var st snapStoredRevision
	if err := json.Unmarshal(b, &st); err != nil {
		return snapStoredRevision{}, err
	}
	if st.Filename != snapFilename(name, revision) {
		return snapStoredRevision{}, fmt.Errorf("invalid stored filename for %s@%d", name, revision)
	}
	for _, f := range []string{st.Filename, snapAssertFilename(name, revision)} {
		abs := s.snapArtifactAbs(name, f)
		if !safeJoin(s.snapFilesDir(), abs) || !fileExists(abs) {
			return snapStoredRevision{}, fmt.Errorf("artifact missing for %s@%d", name, revision)
		}
	}
	return st, nil
}

// snapServedRevisions lists one snap's complete revisions, newest first.
func (s *HighServer) snapServedRevisions(name string) []snapStoredRevision {
	entries, err := os.ReadDir(filepath.Join(s.snapMetadataDir(), name))
	if err != nil {
		return nil
	}
	var out []snapStoredRevision
	for _, e := range entries {
		rev, convErr := strconv.Atoi(strings.TrimSuffix(e.Name(), ".json"))
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || convErr != nil || validateSnapRevision(rev) != nil {
			continue
		}
		st, err := s.readSnapStored(name, rev)
		if err != nil {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Revision > out[j].Revision })
	return out
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listSnapPackages lists the mirrored snaps with their revisions (as version
// strings, newest first) for the dashboard tree.
func (s *HighServer) listSnapPackages() ([]UIModule, error) {
	names, err := os.ReadDir(s.snapMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIModule
	for _, n := range names {
		if !n.IsDir() || validateSnapName(n.Name()) != nil {
			continue
		}
		stored := s.snapServedRevisions(n.Name())
		if len(stored) == 0 {
			continue
		}
		versions := make([]string, 0, len(stored))
		for _, st := range stored {
			versions = append(versions, strconv.Itoa(st.Revision))
		}
		out = append(out, UIModule{Module: n.Name(), Versions: versions})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// snapDetail describes one mirrored revision for the dashboard detail panel.
// spec is "<name>@<revision>".
func (s *HighServer) snapDetail(spec string) (UIDetail, error) {
	name, revStr, ok := strings.Cut(spec, "@")
	rev, convErr := strconv.Atoi(revStr)
	if !ok || convErr != nil || validateSnapName(name) != nil || validateSnapRevision(rev) != nil {
		return UIDetail{}, errors.New("invalid snap@revision")
	}
	st, err := s.readSnapStored(name, rev)
	if err != nil {
		return UIDetail{}, errors.New("revision not found")
	}
	fields := []UIDetailField{
		{Label: "Snap", Value: name, Mono: true},
		{Label: "Revision", Value: revStr, Mono: true},
	}
	for _, f := range []UIDetailField{
		{Label: "Version", Value: st.Version, Mono: true},
		{Label: "Channel", Value: st.Channel, Mono: true},
		{Label: "Architecture", Value: st.Architecture, Mono: true},
		{Label: "Base", Value: st.Base, Mono: true},
		{Label: "Confinement", Value: st.Confinement},
		{Label: "Publisher", Value: st.Publisher},
		{Label: "Summary", Value: st.Summary},
		{Label: "License", Value: st.License},
	} {
		if f.Value != "" {
			fields = append(fields, f)
		}
	}
	fields = append(fields,
		UIDetailField{Label: "Size", Value: formatBytes(st.Size)},
		UIDetailField{Label: "SHA3-384", Value: st.SHA3384, Mono: true},
	)
	assertName := snapAssertFilename(name, rev)
	downloads := []UIDownload{
		{Label: st.Filename, URL: "/snap/files/" + name + "/" + st.Filename},
		{Label: assertName, URL: "/snap/files/" + name + "/" + assertName},
	}
	return UIDetail{Title: name, Subtitle: "revision " + revStr, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// Low side: store client
// -----------------------------------------------------------------------------

// snapStoreBase returns the configured Snap Store API base URL.
func (s *LowServer) snapStoreBase() string {
	base := strings.TrimSpace(s.cfg.SnapStoreURL)
	if base == "" {
		base = defaultSnapStoreURL
	}
	return strings.TrimSuffix(base, "/")
}

// snapStoreGet fetches one store response into memory with the store headers
// set, failing beyond limit. Snap payloads never come through here — they
// stream to disk via downloadVerifiedFile.
func snapStoreGet(ctx context.Context, rawURL, accept string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Snap-Device-Series", snapDeviceSeries)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamHTTPError{Method: http.MethodGet, URL: rawURL, Status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: response exceeds the %s cap", rawURL, formatBytes(limit))
	}
	return body, nil
}

// snapStoreInfo is the subset of a /v2/snaps/info response ArtiGate reads.
type snapStoreInfo struct {
	ChannelMap []snapChannelEntry `json:"channel-map"`
	Name       string             `json:"name"`
	SnapID     string             `json:"snap-id"`
	Snap       snapStoreMeta      `json:"snap"`
}

// snapStoreMeta is the store's descriptive metadata for a snap.
type snapStoreMeta struct {
	Publisher struct {
		DisplayName string `json:"display-name"`
		Username    string `json:"username"`
	} `json:"publisher"`
	Summary string `json:"summary"`
	Title   string `json:"title"`
	License string `json:"license"`
}

// snapChannelEntry is one channel-map entry: a revision as released to one
// channel for one architecture.
type snapChannelEntry struct {
	Channel struct {
		Architecture string `json:"architecture"`
		Name         string `json:"name"`
		Risk         string `json:"risk"`
		Track        string `json:"track"`
	} `json:"channel"`
	Download struct {
		SHA3384 string `json:"sha3-384"`
		Size    int64  `json:"size"`
		URL     string `json:"url"`
	} `json:"download"`
	Revision    int    `json:"revision"`
	Version     string `json:"version"`
	Base        string `json:"base"`
	Confinement string `json:"confinement"`
	Type        string `json:"type"`
}

// snapFetchInfo fetches and validates one snap's store info. The response's
// canonical identity must agree with what was asked for and be path-safe,
// because it names the storage paths.
func snapFetchInfo(ctx context.Context, base, name, arch string) (*snapStoreInfo, error) {
	u := base + "/v2/snaps/info/" + name + "?architecture=" + url.QueryEscape(arch) + "&fields=" + url.QueryEscape(snapInfoFields)
	b, err := snapStoreGet(ctx, u, "", snapMaxInfoBytes)
	if err != nil {
		return nil, err
	}
	var info snapStoreInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("parse snap info: %w", err)
	}
	if info.Name != name {
		return nil, fmt.Errorf("store answered for snap %q, not %q", info.Name, name)
	}
	if err := validateSnapID(info.SnapID); err != nil {
		return nil, err
	}
	return &info, nil
}

// selectSnapChannel picks the channel-map entry for a requested channel and
// architecture. The store names default-track channels by their bare risk
// ("stable") and everything else as "track/risk", so both spellings — plus a
// bare risk against the explicit "latest" track — are matched.
func selectSnapChannel(info *snapStoreInfo, channel, arch string) (*snapChannelEntry, error) {
	for i := range info.ChannelMap {
		e := &info.ChannelMap[i]
		if e.Channel.Architecture == arch && snapChannelMatches(e, channel) {
			return e, nil
		}
	}
	return nil, fmt.Errorf("no %s release in channel %s", arch, channel)
}

// snapChannelMatches reports whether one channel-map entry answers a
// requested channel spec.
func snapChannelMatches(e *snapChannelEntry, want string) bool {
	if e.Channel.Name == want || e.Channel.Track+"/"+e.Channel.Risk == want {
		return true
	}
	return !strings.Contains(want, "/") && e.Channel.Risk == want && e.Channel.Track == "latest"
}

// validateSnapChannelEntry checks the store fields a selected entry must
// carry before it can be mirrored.
func validateSnapChannelEntry(e *snapChannelEntry) error {
	if err := validateSnapRevision(e.Revision); err != nil {
		return err
	}
	if !snapSHA3384HexRE.MatchString(e.Download.SHA3384) {
		return fmt.Errorf("store declares no usable sha3-384 for revision %d", e.Revision)
	}
	if e.Download.Size <= 0 || e.Download.Size > maxMirroredFileBytes {
		return fmt.Errorf("store declares unusable size %d for revision %d", e.Download.Size, e.Revision)
	}
	u, err := url.Parse(e.Download.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("download URL %q is not http(s)", e.Download.URL)
	}
	if e.Base != "" {
		if err := validateSnapName(e.Base); err != nil {
			return fmt.Errorf("store declares unusable base: %w", err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Low side: collector
// -----------------------------------------------------------------------------

// SnapCollectRequest is the body of POST /admin/snap/collect.
type SnapCollectRequest struct {
	// Snaps lists the snaps to mirror as "name" (the stable channel) or
	// "name@channel" ("hello@edge", "firefox@latest/candidate",
	// "blender@4.1/stable"). Each snap's base snap is mirrored with it.
	Snaps []string `json:"snaps"`
	// Architecture selects the store architecture (default amd64).
	Architecture string `json:"architecture,omitempty"`
	// NoBases limits the collect to exactly the listed snaps, skipping the
	// base snaps they run on.
	NoBases bool `json:"no_bases,omitempty"`
	// Force disables export dedup for this collect: every file is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseSnapSpec splits "name" or "name@channel"; "latest" is accepted as an
// alias for the default (stable) channel.
func parseSnapSpec(spec string) (name, channel string, err error) {
	name, channel, _ = strings.Cut(spec, "@")
	if err := validateSnapName(name); err != nil {
		return "", "", err
	}
	if channel == "" || channel == "latest" {
		return name, snapDefaultChannel, nil
	}
	if err := validateSnapChannel(channel); err != nil {
		return "", "", fmt.Errorf("snap %s: %w", name, err)
	}
	return name, channel, nil
}

// validateSnapRequest checks the collect request and resolves the
// architecture before any network work.
func validateSnapRequest(req SnapCollectRequest) (arch string, err error) {
	if len(req.Snaps) == 0 {
		return "", errors.New("no snaps provided")
	}
	for _, spec := range req.Snaps {
		if _, _, err := parseSnapSpec(spec); err != nil {
			return "", err
		}
	}
	arch = strings.TrimSpace(req.Architecture)
	if arch == "" {
		arch = snapDefaultArch
	}
	if err := validateSnapArch(arch); err != nil {
		return "", err
	}
	return arch, nil
}

// HandleSnapCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandleSnapCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req SnapCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse snap collect request: %w", err)
		}
	}
	return s.CollectSnap(ctx, req)
}

// CollectSnap resolves the requested snaps against the Snap Store, downloads
// each channel's current revision with its assertion chain — and, unless the
// request opts out, the base snaps they run on — and writes them into a
// signed bundle on the snap stream. Snaps that cannot be resolved or fetched
// are skipped and reported so one of them never blocks the rest of the batch.
func (s *LowServer) CollectSnap(ctx context.Context, req SnapCollectRequest) (ExportResult, error) {
	arch, err := validateSnapRequest(req)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the snap stream's lock for the whole fetch->write->commit so a
	// concurrent snap exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamSnap)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "snap", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	d := &snapDownloader{base: s.snapStoreBase(), arch: arch, stageRoot: stageRoot, noBases: req.NoBases, done: map[string]bool{}}
	d.run(ctx, req.Snaps)
	if len(d.pkgs) == 0 {
		return ExportResult{}, fmt.Errorf("no snaps could be fetched: %s", summarizeFailures(d.failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(d.files))
	res, err := s.exportIfNew(ctx, streamSnap, stageRoot, d.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeSnapBundle(ctx, seq, stageRoot, d.files, d.pkgs)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = d.failed
	return res, nil
}

// snapWant is one queued snap to mirror.
type snapWant struct {
	name, channel string
}

// snapDownloader mirrors the requested snaps and, unless noBases, the base
// snaps they declare, downloading each snap once.
type snapDownloader struct {
	base      string
	arch      string
	stageRoot string
	noBases   bool
	pkgs      []SnapPackage
	files     []ManifestFile
	failed    []FailedModule
	done      map[string]bool // snap name; first channel selected wins
}

// run resolves and downloads the requested specs and the queued bases. Bases
// always resolve from the stable channel, like a fresh `snap install` does.
func (d *snapDownloader) run(ctx context.Context, specs []string) {
	queue := make([]snapWant, 0, len(specs))
	for _, spec := range specs {
		name, channel, _ := parseSnapSpec(spec) // validated with the request
		queue = append(queue, snapWant{name: name, channel: channel})
	}
	for len(queue) > 0 && len(d.done) < snapMaxResolved {
		w := queue[0]
		queue = queue[1:]
		if d.done[w.name] {
			continue
		}
		d.done[w.name] = true
		emitProgress(ctx, "→ %s@%s (%s)", w.name, w.channel, d.arch)
		base, err := d.fetchOne(ctx, w)
		if err != nil {
			emitProgress(ctx, "  ✗ %s: %s", w.name, err)
			d.failed = append(d.failed, FailedModule{Module: w.name, Version: w.channel, Error: err.Error()})
			continue
		}
		if base != "" && !d.noBases {
			queue = append(queue, snapWant{name: base, channel: snapDefaultChannel})
		}
	}
}

// fetchOne mirrors one snap: store info, the .snap archive, and the .assert
// assertion chain. It returns the base snap to resolve next, if any.
func (d *snapDownloader) fetchOne(ctx context.Context, w snapWant) (string, error) {
	info, err := snapFetchInfo(ctx, d.base, w.name, d.arch)
	if err != nil {
		return "", err
	}
	entry, err := selectSnapChannel(info, w.channel, d.arch)
	if err != nil {
		return "", err
	}
	if err := validateSnapChannelEntry(entry); err != nil {
		return "", err
	}
	pkg, pkgFiles, err := d.downloadSnap(ctx, info, entry)
	if err != nil {
		return "", err
	}
	d.pkgs = append(d.pkgs, pkg)
	d.files = append(d.files, pkgFiles...)
	return entry.Base, nil
}

// downloadSnap fetches one revision's archive (verified against the
// store-declared SHA3-384 and size) and its assertion chain into the staging
// tree under their canonical paths.
func (d *snapDownloader) downloadSnap(ctx context.Context, info *snapStoreInfo, entry *snapChannelEntry) (SnapPackage, []ManifestFile, error) {
	filename := snapFilename(info.Name, entry.Revision)
	rel := snapFileRel(info.Name, filename)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadVerifiedFile(ctx, entry.Download.URL, abs, entry.Download.Size, "sha3-384", entry.Download.SHA3384)
	if err != nil {
		return SnapPackage{}, nil, err
	}
	assertRel := snapFileRel(info.Name, snapAssertFilename(info.Name, entry.Revision))
	assertFile, err := d.fetchSnapAssertions(ctx, info, entry, assertRel)
	if err != nil {
		return SnapPackage{}, nil, fmt.Errorf("assertions: %w", err)
	}
	pkg := SnapPackage{
		Name: info.Name, SnapID: info.SnapID, Revision: entry.Revision,
		Channel: entry.Channel.Track + "/" + entry.Channel.Risk, Architecture: d.arch,
		Version: entry.Version, Base: entry.Base, Confinement: entry.Confinement, Type: entry.Type,
		Summary: info.Snap.Summary, Publisher: info.Snap.Publisher.Username, License: info.Snap.License,
		Filename: filename, Path: rel, SHA256: sum, SHA3384: entry.Download.SHA3384, AssertPath: assertRel,
	}
	return pkg, []ManifestFile{{Path: rel, SHA256: sum, Size: size}, assertFile}, nil
}

// fetchSnapAssertions assembles one revision's .assert document in the order
// `snap download` writes: the account-key(s) that signed the assertions, the
// publisher's account, the snap-declaration, and the snap-revision. The
// snap-revision is cross-checked against the store's channel entry before
// anything is staged, so a store inconsistency fails the snap here rather
// than at import on the high side.
func (d *snapDownloader) fetchSnapAssertions(ctx context.Context, info *snapStoreInfo, entry *snapChannelEntry, rel string) (ManifestFile, error) {
	digestB64, err := snapDigestBase64(entry.Download.SHA3384)
	if err != nil {
		return ManifestFile{}, err
	}
	revDoc, revA, err := d.fetchSnapAssertion(ctx, "snap-revision/"+digestB64)
	if err != nil {
		return ManifestFile{}, err
	}
	if revA.header("snap-id") != info.SnapID || revA.header("snap-revision") != strconv.Itoa(entry.Revision) {
		return ManifestFile{}, errors.New("snap-revision assertion disagrees with the store's channel entry")
	}
	declDoc, declA, err := d.fetchSnapAssertion(ctx, "snap-declaration/"+snapDeviceSeries+"/"+info.SnapID)
	if err != nil {
		return ManifestFile{}, err
	}
	if declA.header("snap-name") != info.Name {
		return ManifestFile{}, fmt.Errorf("snap-declaration names %q, store info says %q", declA.header("snap-name"), info.Name)
	}
	docs, err := d.fetchSnapSignerDocs(ctx, declA, revA)
	if err != nil {
		return ManifestFile{}, err
	}
	docs = append(docs, declDoc, revDoc)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	if err := writeBytesAtomic(abs, composeSnapAssertions(docs), 0o644); err != nil {
		return ManifestFile{}, err
	}
	emitProgress(ctx, "  ⊕ assertions %s", path.Base(rel))
	return hashManifestFile(abs, rel)
}

// fetchSnapSignerDocs fetches the publisher's account assertion and the
// account-key assertion of every key that signed the declaration or the
// revision (usually one store key), key docs first.
func (d *snapDownloader) fetchSnapSignerDocs(ctx context.Context, declA, revA snapAssertion) ([][]byte, error) {
	var docs [][]byte
	seen := map[string]bool{}
	for _, key := range []string{declA.header("sign-key-sha3-384"), revA.header("sign-key-sha3-384")} {
		if seen[key] {
			continue
		}
		seen[key] = true
		if !snapAccountRefRE.MatchString(key) {
			return nil, fmt.Errorf("assertion carries unusable sign-key reference %q", key)
		}
		keyDoc, _, err := d.fetchSnapAssertion(ctx, "account-key/"+key)
		if err != nil {
			return nil, err
		}
		docs = append(docs, keyDoc)
	}
	publisher := declA.header("publisher-id")
	if !snapAccountRefRE.MatchString(publisher) {
		return nil, fmt.Errorf("snap-declaration carries unusable publisher-id %q", publisher)
	}
	acctDoc, _, err := d.fetchSnapAssertion(ctx, "account/"+publisher)
	if err != nil {
		return nil, err
	}
	return append(docs, acctDoc), nil
}

// fetchSnapAssertion fetches one assertion document from the store and
// parses it (a fetch answers with exactly one assertion).
func (d *snapDownloader) fetchSnapAssertion(ctx context.Context, ref string) ([]byte, snapAssertion, error) {
	doc, err := snapStoreGet(ctx, d.base+"/v2/assertions/"+ref, snapAssertionAccept, snapMaxAssertionBytes)
	if err != nil {
		return nil, snapAssertion{}, err
	}
	as, err := splitSnapAssertions(doc)
	if err != nil || len(as) != 1 {
		return nil, snapAssertion{}, fmt.Errorf("assertion %s: unusable response: %w", ref, orErr(err, errors.New("expected exactly one assertion")))
	}
	return doc, as[0], nil
}

// orErr returns err when set, otherwise def.
func orErr(err, def error) error {
	if err != nil {
		return err
	}
	return def
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

// writeSnapBundle writes one signed bundle carrying the collected snaps.
func (s *LowServer) writeSnapBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, pkgs []SnapPackage) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Revision < pkgs[j].Revision
	})
	id := bundleIDFor(streamSnap, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamSnap,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"snap"},
		Snap:             &SnapManifest{Snaps: pkgs},
		Files:            files,
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamSnap, Sequence: seq, ExportedModules: len(pkgs), BundleID: id}, nil
}
