package main

// Raw git repository mirroring ecosystem adapter. The low side speaks git's
// smart HTTP protocol (v0) as a pure-Go client — no git binary is required —
// asking the upstream for every selected ref and receiving one
// self-contained packfile, which it fully verifies (trailer SHA-1, every
// object header and zlib stream, every delta resolved to content) before
// packing it with the ref list into the same numbered, signed ArtiGate
// bundle format used by the other ecosystems. The high side re-runs the very
// same pack verification on the transferred bytes, regenerates the pack
// index (.idx) from the verified pack itself — never trusting a transferred
// index — and serves the repository over git's dumb HTTP protocol
// (info/refs, HEAD, objects/info/packs, and the pack/idx pair), so
// `git clone <base>/git/<name>.git` works with any stock git: the smart
// probe of info/refs is answered as plain text, which makes clients fall
// back to the dumb protocol automatically.
//
// Packs are parsed entirely in memory on both sides: delta resolution needs
// random access to base objects, and holding the bytes is the accepted trade
// for a dependency-free parser. gitMaxPackBytes bounds that memory; a
// repository whose pack exceeds it needs a narrower ref selection, not a
// bigger box.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1" //nolint:gosec // git's object model is SHA-1; this is format fidelity, not a security control
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
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

// gitEcosystem is the raw git mirror stream's registry entry (see ecosystems
// in ecosystem.go).
func gitEcosystem() ecosystem {
	return ecosystem{
		stream:          streamGit,
		label:           "Git",
		title:           "Git repositories",
		collect:         (*LowServer).HandleGitCollect,
		watchCollect:    watchAdapter((*LowServer).CollectGit),
		manifestContent: func(m BundleManifest) bool { return m.Git != nil && len(m.Git.Repos) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateGitRepos(m.Git.Repos, seen, m.Files)
		},
		contentDesc: "git repositories",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishGit(m.Git) },
		serve:       (*HighServer).serveGit,
		scanTree:    flatTreeScan((*HighServer).listGitRepos),
		detail:      (*HighServer).gitDetail,
	}
}

const (
	// gitMaxPackBytes caps a mirrored packfile. Packs are verified and
	// indexed in memory on both sides, so this is also the parser's
	// working-set bound; it additionally keeps every pack offset below the
	// idx v2 large-offset escape (see gitWriteIdx).
	gitMaxPackBytes = 2 << 30
	// gitMaxObjectBytes caps one decompressed object (zlib-bomb guard).
	gitMaxObjectBytes = 512 << 20
	// gitInitialObjectHint caps the object slice's pre-allocated capacity. The
	// pack header's object count is attacker-controlled (a forged 2 GiB pack can
	// claim hundreds of millions of objects), so it must not size an eager
	// allocation; the slice instead grows to the real count as scanObject
	// consumes actual pack bytes.
	gitInitialObjectHint = 1 << 16
	// gitMaxPktBytes is the pkt-line format's maximum packet length: four
	// hex length digits count themselves, so 65520 total.
	gitMaxPktBytes = 65520
	// gitUserAgent identifies the pure-Go client to upstream servers.
	gitUserAgent = "git/artigate"
	// gitFetchTimeout bounds one advertisement+pack exchange, matching the
	// other ecosystems' large-artifact download timeout.
	gitFetchTimeout = 30 * time.Minute
)

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type GitManifest struct {
	Repos []GitRepoMirror `json:"repos"`
}

// GitRepoMirror records one mirrored repository snapshot: the refs it
// advertises and the single self-contained packfile carrying every object.
// The high side regenerates the pack index (.idx) from the verified pack
// itself and serves the repository over git's dumb HTTP protocol.
type GitRepoMirror struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Head       string   `json:"head,omitempty"`
	Refs       []GitRef `json:"refs"`
	PackPath   string   `json:"pack_path"`
	PackSHA256 string   `json:"pack_sha256"`
}

// GitRef is one advertised ref: a full ref name and the object it points at.
type GitRef struct {
	Name string `json:"name"`
	SHA1 string `json:"sha1"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// gitRefNameRE matches the full ref names ArtiGate mirrors: under refs/,
// starting alphanumeric, every character path- and shell-safe. It is
// stricter than git-check-ref-format(1) — names git would allow but the
// mirror's plumbing should never contain (spaces, "@", "^", ...) are out.
var gitRefNameRE = regexp.MustCompile(`^refs/[0-9A-Za-z][0-9A-Za-z._/\-]*$`)

// gitSHA1RE matches a 40-hex object id.
var gitSHA1RE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// gitPackBaseRE matches the canonical basename of a mirrored packfile.
var gitPackBaseRE = regexp.MustCompile(`^pack-[0-9a-f]{40}\.pack$`)

// gitServedPackRE matches the pack/idx pair dumb-protocol clients fetch.
var gitServedPackRE = regexp.MustCompile(`^pack-[0-9a-f]{40}\.(pack|idx)$`)

// validateGitRefName checks one full ref name against the mirror's safe
// subset, re-rejecting the sequences git itself forbids ("..", "//", "@{",
// a trailing "/") even where the character class already excludes them.
func validateGitRefName(name string) error {
	if !gitRefNameRE.MatchString(name) || len(name) > 255 ||
		strings.Contains(name, "..") || strings.Contains(name, "//") ||
		strings.Contains(name, "@{") || strings.HasSuffix(name, "/") {
		return fmt.Errorf("invalid ref name %q", name)
	}
	return nil
}

// gitPackRel is the repository-relative path a mirror's pack is stored
// under; trailer is the pack's 40-hex trailer checksum.
func gitPackRel(name, trailer string) string {
	return path.Join("git", name, "objects", "pack", "pack-"+trailer+".pack")
}

// gitPackTrailerFromBase extracts the 40-hex trailer from a
// "pack-<hex>.pack" basename previously matched by gitPackBaseRE.
func gitPackTrailerFromBase(base string) string {
	return strings.TrimSuffix(strings.TrimPrefix(base, "pack-"), ".pack")
}

// validateGitRepos checks every mirrored repository of a bundle manifest:
// safe names, well-formed refs, a head naming a listed ref, and a pack
// stored at the canonical path whose hash matches the manifest file set.
func validateGitRepos(repos []GitRepoMirror, seen map[string]bool, files []ManifestFile) error {
	fileSHA := manifestFileSHAs(files)
	for _, repo := range repos {
		if err := validateGitRepo(repo, seen, fileSHA); err != nil {
			return err
		}
	}
	return nil
}

func validateGitRepo(repo GitRepoMirror, seen map[string]bool, fileSHA map[string]string) error {
	if err := validateMirrorName(repo.Name); err != nil {
		return err
	}
	if repo.URL == "" {
		return fmt.Errorf("git repo %s has no url", repo.Name)
	}
	if len(repo.Refs) == 0 {
		return fmt.Errorf("git repo %s has no refs", repo.Name)
	}
	headListed := repo.Head == ""
	for _, ref := range repo.Refs {
		if err := validateGitRefName(ref.Name); err != nil {
			return fmt.Errorf("git repo %s: %w", repo.Name, err)
		}
		if !gitSHA1RE.MatchString(ref.SHA1) {
			return fmt.Errorf("git repo %s ref %s has invalid object id %q", repo.Name, ref.Name, ref.SHA1)
		}
		headListed = headListed || ref.Name == repo.Head
	}
	if !headListed {
		return fmt.Errorf("git repo %s head %q is not a listed ref", repo.Name, repo.Head)
	}
	return validateGitRepoPack(repo, seen, fileSHA)
}

// validateGitRepoPack pins the pack reference to the canonical storage path
// and to a file the manifest actually lists, with the same hash.
func validateGitRepoPack(repo GitRepoMirror, seen map[string]bool, fileSHA map[string]string) error {
	base := path.Base(repo.PackPath)
	if !gitPackBaseRE.MatchString(base) ||
		repo.PackPath != gitPackRel(repo.Name, gitPackTrailerFromBase(base)) || !seen[repo.PackPath] {
		return fmt.Errorf("git repo %s references a pack not listed in manifest.files: %s", repo.Name, repo.PackPath)
	}
	if repo.PackSHA256 == "" || repo.PackSHA256 != fileSHA[repo.PackPath] {
		return fmt.Errorf("git repo %s pack sha256 does not match the manifest file set", repo.Name)
	}
	return nil
}

// -----------------------------------------------------------------------------
// pkt-line codec (gitprotocol-common)
// -----------------------------------------------------------------------------

// gitFlushPkt is the length-0000 packet ending a pkt-line section.
const gitFlushPkt = "0000"

// gitPktLine encodes one pkt-line: four hex digits of the total length
// (the payload plus the four length bytes themselves), then the payload.
func gitPktLine(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

// gitPktReader reads a pkt-line stream. It buffers, so once the pkt-line
// section is over, the remaining raw bytes must be read from r (not the
// underlying reader).
type gitPktReader struct {
	r *bufio.Reader
}

func newGitPktReader(r io.Reader) *gitPktReader {
	return &gitPktReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// next returns the next packet's payload, or flush=true for a flush-pkt.
// Lengths 1-3 cannot encode a packet and are rejected (protocol v0 has no
// delim-pkt).
func (p *gitPktReader) next() (payload []byte, flush bool, err error) {
	var lenHex [4]byte
	if _, err := io.ReadFull(p.r, lenHex[:]); err != nil {
		return nil, false, err
	}
	n, err := strconv.ParseUint(string(lenHex[:]), 16, 32)
	if err != nil {
		return nil, false, fmt.Errorf("invalid pkt-line length %q", lenHex)
	}
	if n == 0 {
		return nil, true, nil
	}
	if n < 4 || n > gitMaxPktBytes {
		return nil, false, fmt.Errorf("invalid pkt-line length %d", n)
	}
	payload = make([]byte, n-4)
	if _, err := io.ReadFull(p.r, payload); err != nil {
		return nil, false, fmt.Errorf("truncated pkt-line: %w", err)
	}
	return payload, false, nil
}

// -----------------------------------------------------------------------------
// Low side: ref advertisement (GET <url>/info/refs?service=git-upload-pack)
// -----------------------------------------------------------------------------

// gitAdvertisement is a parsed upload-pack ref advertisement.
type gitAdvertisement struct {
	refs []GitRef        // advertised refs, in server order
	head string          // the symref=HEAD:<target> capability, "" if absent
	caps map[string]bool // advertised capability tokens
}

// gitFetchAdvertisement asks the upstream for its ref advertisement,
// authenticating with cred when the repository has a login configured.
func gitFetchAdvertisement(ctx context.Context, repoURL string, cred *registryCredential) (*gitAdvertisement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoURL+"/info/refs?service=git-upload-pack", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", gitUserAgent)
	// net/http drops Authorization on cross-host redirects, so a redirected
	// upstream never receives the login.
	setBasicAuth(req, cred)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamHTTPError{Method: http.MethodGet, URL: repoURL + "/info/refs", Status: resp.StatusCode}
	}
	adv, err := parseGitAdvertisement(io.LimitReader(resp.Body, maxIndexFetchBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", repoURL, err)
	}
	return adv, nil
}

// parseGitAdvertisement decodes the smart info/refs response: the
// "# service=git-upload-pack" packet, a flush, then one packet per ref
// ("<sha> <name>", the first carrying a NUL-separated capability list),
// ending in a flush.
func parseGitAdvertisement(r io.Reader) (*gitAdvertisement, error) {
	pkts := newGitPktReader(r)
	if err := gitReadServiceHeader(pkts); err != nil {
		return nil, err
	}
	adv := &gitAdvertisement{caps: map[string]bool{}}
	for first := true; ; first = false {
		payload, flush, err := pkts.next()
		if err != nil {
			return nil, fmt.Errorf("reading ref advertisement: %w", err)
		}
		if flush {
			return adv, nil
		}
		if err := adv.addLine(string(payload), first); err != nil {
			return nil, err
		}
	}
}

// gitReadServiceHeader consumes the "# service=" packet and its flush; their
// absence means the URL is not a smart git-upload-pack endpoint at all.
func gitReadServiceHeader(pkts *gitPktReader) error {
	payload, flush, err := pkts.next()
	if err != nil || flush || strings.TrimSuffix(string(payload), "\n") != "# service=git-upload-pack" {
		return errors.New("upstream did not answer as a smart git-upload-pack HTTP server")
	}
	if _, flush, err = pkts.next(); err != nil || !flush {
		return errors.New("malformed ref advertisement: no flush after the service header")
	}
	return nil
}

// addLine folds one advertisement packet into adv. The HEAD pseudo-ref,
// peeled "<tag>^{}" entries, and the empty repository's "capabilities^{}"
// placeholder are not refs and are dropped (an empty repository therefore
// parses to zero refs and fails selection).
func (a *gitAdvertisement) addLine(line string, first bool) error {
	line = strings.TrimSuffix(line, "\n")
	if first {
		var caps string
		line, caps, _ = strings.Cut(line, "\x00")
		a.parseCaps(caps)
	}
	sha, name, ok := strings.Cut(line, " ")
	if !ok || !gitSHA1RE.MatchString(sha) || name == "" {
		return fmt.Errorf("malformed ref advertisement line %q", line)
	}
	if name == "HEAD" || strings.HasSuffix(name, "^{}") {
		return nil
	}
	a.refs = append(a.refs, GitRef{Name: name, SHA1: sha})
	return nil
}

// parseCaps records the advertised capability tokens, extracting the HEAD
// symref target ("symref=HEAD:refs/heads/<x>") when the server declares one.
func (a *gitAdvertisement) parseCaps(caps string) {
	for _, c := range strings.Fields(caps) {
		if target, ok := strings.CutPrefix(c, "symref=HEAD:"); ok {
			a.head = target
			continue
		}
		a.caps[c] = true
	}
}

// gitSelectRefs picks the refs to mirror: the requested full names when the
// request lists any (each must be advertised — missing ones fail the collect
// by name), otherwise every branch and tag. The advertised HEAD target is
// kept only when it names a selected ref, so the manifest always
// self-validates. Results are sorted by name.
func gitSelectRefs(adv *gitAdvertisement, requested []string) (refs []GitRef, head string, err error) {
	if len(adv.refs) == 0 {
		return nil, "", errors.New("repository has no refs")
	}
	if len(requested) > 0 {
		refs, err = gitRequestedRefs(adv.refs, requested)
		if err != nil {
			return nil, "", err
		}
	} else {
		refs = gitDefaultRefs(adv.refs)
	}
	if len(refs) == 0 {
		return nil, "", errors.New("repository advertises no branches or tags to mirror")
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	for _, ref := range refs {
		if ref.Name == adv.head {
			head = adv.head
		}
	}
	return refs, head, nil
}

// gitDefaultRefs keeps the advertised branches and tags. A name the manifest
// validation would reject (git allows a few characters ArtiGate's safe-name
// rule does not, e.g. "@") is skipped rather than poisoning the bundle.
func gitDefaultRefs(all []GitRef) []GitRef {
	var out []GitRef
	for _, ref := range all {
		if !strings.HasPrefix(ref.Name, "refs/heads/") && !strings.HasPrefix(ref.Name, "refs/tags/") {
			continue
		}
		if validateGitRefName(ref.Name) != nil {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// gitRequestedRefs resolves an explicit ref selection against the
// advertisement, failing with every missing name listed.
func gitRequestedRefs(all []GitRef, requested []string) ([]GitRef, error) {
	byName := make(map[string]GitRef, len(all))
	for _, ref := range all {
		byName[ref.Name] = ref
	}
	seen := map[string]bool{}
	var out []GitRef
	var missing []string
	for _, name := range requested {
		if seen[name] {
			continue
		}
		seen[name] = true
		if ref, ok := byName[name]; ok {
			out = append(out, ref)
		} else {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("refs not advertised by the upstream: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Low side: pack fetch (POST <url>/git-upload-pack)
// -----------------------------------------------------------------------------

// gitWantSHAs deduplicates the selected refs' tips in first-seen order (two
// refs at the same commit need — and may send — only one "want").
func gitWantSHAs(refs []GitRef) []string {
	seen := map[string]bool{}
	var out []string
	for _, ref := range refs {
		if !seen[ref.SHA1] {
			seen[ref.SHA1] = true
			out = append(out, ref.SHA1)
		}
	}
	return out
}

// gitUploadPackRequest renders the protocol-v0 fetch request: one "want" per
// tip — capabilities ride only the first — then a flush, then "done". No
// "have" is ever sent, so the server answers with one self-contained pack.
func gitUploadPackRequest(wants []string, sideband bool) []byte {
	caps := "no-progress agent=artigate"
	if sideband {
		caps = "side-band-64k " + caps
	}
	var b bytes.Buffer
	for i, want := range wants {
		line := "want " + want + "\n"
		if i == 0 {
			line = "want " + want + " " + caps + "\n"
		}
		b.WriteString(gitPktLine(line))
	}
	b.WriteString(gitFlushPkt)
	b.WriteString(gitPktLine("done\n"))
	return b.Bytes()
}

// gitFetchPack POSTs the upload-pack request and returns the raw pack,
// authenticating with cred when the repository has a login configured.
// sideband must reflect whether the server advertised side-band-64k: only
// then may the capability be requested, and only then is the response
// multiplexed.
func gitFetchPack(ctx context.Context, repoURL string, wants []string, sideband bool, cred *registryCredential) ([]byte, error) {
	body := gitUploadPackRequest(wants, sideband)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, repoURL+"/git-upload-pack", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", gitUserAgent)
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	// net/http drops Authorization on cross-host redirects, so a redirected
	// upstream never receives the login.
	setBasicAuth(req, cred)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamHTTPError{Method: http.MethodPost, URL: repoURL + "/git-upload-pack", Status: resp.StatusCode}
	}
	r := newProgressReader(ctx, resp.Body, dlNameFromURL(repoURL)+".pack", resp.ContentLength)
	return gitReadPackResponse(r, sideband)
}

// gitReadPackResponse consumes the upload-pack result: a NAK packet (nothing
// was "have"d, so nothing can be ACKed), then the pack — side-band-64k
// frames whose first payload byte selects the band (1 pack data, 2 progress,
// 3 fatal error), or the raw remaining bytes when side-band was not in play.
func gitReadPackResponse(r io.Reader, sideband bool) ([]byte, error) {
	pkts := newGitPktReader(r)
	payload, flush, err := pkts.next()
	if err != nil {
		return nil, fmt.Errorf("reading upload-pack response: %w", err)
	}
	line := strings.TrimSuffix(string(payload), "\n")
	if msg, ok := strings.CutPrefix(line, "ERR "); ok {
		return nil, fmt.Errorf("upstream refused the fetch: %s", msg)
	}
	if flush || line != "NAK" {
		return nil, fmt.Errorf("unexpected upload-pack response packet %q", line)
	}
	if !sideband {
		return gitReadCapped(pkts.r)
	}
	return gitReadSideband(pkts)
}

// gitReadCapped reads a raw (unmultiplexed) pack tail under the size cap,
// draining what the pkt reader already buffered first.
func gitReadCapped(r io.Reader) ([]byte, error) {
	pack, err := io.ReadAll(io.LimitReader(r, gitMaxPackBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(pack)) > gitMaxPackBytes {
		return nil, fmt.Errorf("pack exceeds the %s cap", formatBytes(gitMaxPackBytes))
	}
	return pack, nil
}

// gitReadSideband demultiplexes side-band-64k frames until the closing flush
// (or a clean EOF; a truncated pack cannot pass the trailer check anyway).
func gitReadSideband(pkts *gitPktReader) ([]byte, error) {
	var pack bytes.Buffer
	for {
		payload, flush, err := pkts.next()
		if flush || errors.Is(err, io.EOF) {
			return pack.Bytes(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading pack stream: %w", err)
		}
		if len(payload) == 0 {
			return nil, errors.New("empty side-band packet")
		}
		switch payload[0] {
		case 1:
			if int64(pack.Len())+int64(len(payload)-1) > gitMaxPackBytes {
				return nil, fmt.Errorf("pack exceeds the %s cap", formatBytes(gitMaxPackBytes))
			}
			pack.Write(payload[1:])
		case 2: // remote progress; no-progress was asked for, but tolerate it
		case 3:
			return nil, fmt.Errorf("upstream error: %s", strings.TrimSpace(string(payload[1:])))
		default:
			return nil, fmt.Errorf("unknown side-band channel %d", payload[0])
		}
	}
}

// -----------------------------------------------------------------------------
// Pack parsing, shared by both sides (gitformat-pack)
// -----------------------------------------------------------------------------

// Pack entry type codes: 1-4 are the real object types, 6 and 7 the two
// delta encodings (5 is reserved).
const (
	gitObjCommit   = 1
	gitObjTree     = 2
	gitObjBlob     = 3
	gitObjTag      = 4
	gitObjOfsDelta = 6
	gitObjRefDelta = 7
)

// gitTypeName is the loose-object type name hashed into an object id.
func gitTypeName(t int) string {
	switch t {
	case gitObjCommit:
		return "commit"
	case gitObjTree:
		return "tree"
	case gitObjBlob:
		return "blob"
	case gitObjTag:
		return "tag"
	}
	return ""
}

// gitPackEntry is one object of an indexed pack.
type gitPackEntry struct {
	SHA1   string // 40-hex object id
	CRC32  uint32 // over the entry's raw pack bytes (header through data)
	Offset int64
}

// gitPackIndex is what both sides regenerate from a verified pack: its
// objects sorted by id, plus the pack's trailer checksum.
type gitPackIndex struct {
	Entries  []gitPackEntry
	PackSHA1 string // 40-hex trailer checksum
}

// has reports whether the pack contains the object.
func (x *gitPackIndex) has(sha string) bool {
	i := sort.Search(len(x.Entries), func(i int) bool { return x.Entries[i].SHA1 >= sha })
	return i < len(x.Entries) && x.Entries[i].SHA1 == sha
}

// gitIndexPack verifies and indexes a packfile entirely in memory: the
// header, the SHA-1 trailer, every object's header and zlib stream, and full
// delta resolution, so every object id is computed from reconstructed
// content. The low side runs it to prove a fetched pack is complete and
// self-contained; the high side runs the same function to regenerate the
// .idx from the verified bytes, trusting nothing transferred beyond the
// signed manifest.
func gitIndexPack(pack []byte) (*gitPackIndex, error) {
	count, err := gitParsePackHeader(pack)
	if err != nil {
		return nil, err
	}
	trailer := pack[len(pack)-20:]
	sum := sha1.Sum(pack[:len(pack)-20]) //nolint:gosec // pack trailer is defined as SHA-1
	if !bytes.Equal(sum[:], trailer) {
		return nil, errors.New("pack trailer SHA-1 mismatch")
	}
	objs, err := gitScanPack(pack[:len(pack)-20], count)
	if err != nil {
		return nil, err
	}
	if err := gitResolvePack(objs); err != nil {
		return nil, err
	}
	idx := &gitPackIndex{PackSHA1: hex.EncodeToString(trailer), Entries: make([]gitPackEntry, 0, len(objs))}
	for _, o := range objs {
		idx.Entries = append(idx.Entries, gitPackEntry{
			SHA1:   o.sha,
			CRC32:  crc32.ChecksumIEEE(pack[o.offset:o.end]),
			Offset: o.offset,
		})
	}
	sort.Slice(idx.Entries, func(i, j int) bool { return idx.Entries[i].SHA1 < idx.Entries[j].SHA1 })
	return idx, nil
}

// gitParsePackHeader checks the "PACK" magic and version 2 (version 3 reads
// identically) and returns a plausibility-checked object count.
func gitParsePackHeader(pack []byte) (uint32, error) {
	if int64(len(pack)) > gitMaxPackBytes {
		return 0, fmt.Errorf("pack exceeds the %s cap", formatBytes(gitMaxPackBytes))
	}
	if len(pack) < 12+20 || string(pack[:4]) != "PACK" {
		return 0, errors.New("not a git packfile")
	}
	if v := binary.BigEndian.Uint32(pack[4:8]); v != 2 && v != 3 {
		return 0, fmt.Errorf("unsupported pack version %d", v)
	}
	count := binary.BigEndian.Uint32(pack[8:12])
	// The smallest possible entry (1-byte header + empty zlib stream) is far
	// larger than 3 bytes, so a count past this is a forged header.
	if int64(count)*3 > int64(len(pack)) {
		return 0, fmt.Errorf("pack header declares an implausible %d objects", count)
	}
	return count, nil
}

// gitPackObject is one pack entry while a pack is being indexed.
type gitPackObject struct {
	offset  int64  // where the entry's header starts
	end     int64  // one past its last raw byte (the CRC32 range)
	objType int    // header type code
	baseOff int64  // OFS_DELTA: the base object's offset
	baseSHA string // REF_DELTA: the base object's hex id
	data    []byte // inflated payload (for deltas: the delta stream)
	kind    int    // resolved object type; 0 while an unresolved delta
	content []byte // resolved content
	sha     string // resolved hex object id
}

// gitPackParser walks a pack's entries. body excludes the 20-byte trailer,
// so decompression can never consume checksum bytes as object data.
type gitPackParser struct {
	body []byte
	pos  int64
}

func (p *gitPackParser) readByte() (byte, error) {
	if p.pos >= int64(len(p.body)) {
		return 0, errors.New("pack truncated")
	}
	b := p.body[p.pos]
	p.pos++
	return b, nil
}

// readObjectHeader decodes the entry header varint: the first byte holds the
// type in bits 6-4 and the size's low four bits; each continuation byte (MSB
// set) supplies seven more size bits, least significant first.
func (p *gitPackParser) readObjectHeader() (objType int, size int64, err error) {
	b, err := p.readByte()
	if err != nil {
		return 0, 0, err
	}
	objType = int(b>>4) & 0x7
	size = int64(b & 0x0f)
	for shift := uint(4); b&0x80 != 0; shift += 7 {
		if b, err = p.readByte(); err != nil {
			return 0, 0, err
		}
		if shift > 60 {
			return 0, 0, errors.New("object size varint overflow")
		}
		size |= int64(b&0x7f) << shift
	}
	return objType, size, nil
}

// readOfsDeltaDistance decodes OFS_DELTA's base-offset varint. Unlike the
// size varint it is big-endian, seven bits per byte, and each continuation
// adds one first — value = ((value+1)<<7) | bits — so multi-byte encodings
// have no redundant shorter spelling.
func (p *gitPackParser) readOfsDeltaDistance() (int64, error) {
	b, err := p.readByte()
	if err != nil {
		return 0, err
	}
	dist := int64(b & 0x7f)
	for b&0x80 != 0 {
		if b, err = p.readByte(); err != nil {
			return 0, err
		}
		if dist > gitMaxPackBytes {
			return 0, errors.New("delta base offset overflow")
		}
		dist = (dist+1)<<7 | int64(b&0x7f)
	}
	return dist, nil
}

// inflate decompresses one entry's zlib stream in place. A bytes.Reader
// implements io.ByteReader, so flate consumes exactly the compressed bytes
// it needs and the reader's remaining length reveals where the entry ends.
func (p *gitPackParser) inflate(declared int64) ([]byte, error) {
	if declared < 0 || declared > gitMaxObjectBytes {
		return nil, fmt.Errorf("object size %d exceeds the %s cap", declared, formatBytes(gitMaxObjectBytes))
	}
	br := bytes.NewReader(p.body[p.pos:])
	zr, err := zlib.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("object data at %d: %w", p.pos, err)
	}
	data, err := io.ReadAll(io.LimitReader(zr, declared+1))
	_ = zr.Close()
	if err != nil {
		return nil, fmt.Errorf("object data at %d: %w", p.pos, err)
	}
	if int64(len(data)) != declared {
		return nil, fmt.Errorf("object at %d inflates to %d bytes, header declares %d", p.pos, len(data), declared)
	}
	p.pos = int64(len(p.body)) - int64(br.Len())
	return data, nil
}

// gitScanPack reads every entry of the pack body (magic already validated,
// trailer stripped), leaving deltas unresolved.
func gitScanPack(body []byte, count uint32) ([]*gitPackObject, error) {
	p := &gitPackParser{body: body, pos: 12}
	objs := make([]*gitPackObject, 0, min(count, gitInitialObjectHint))
	for i := uint32(0); i < count; i++ {
		o, err := p.scanObject()
		if err != nil {
			return nil, fmt.Errorf("pack object %d/%d: %w", i+1, count, err)
		}
		objs = append(objs, o)
	}
	if p.pos != int64(len(body)) {
		return nil, errors.New("pack carries bytes after its last object")
	}
	return objs, nil
}

// scanObject reads one entry: the type+size header, the delta base
// reference for delta types, then the zlib payload.
func (p *gitPackParser) scanObject() (*gitPackObject, error) {
	o := &gitPackObject{offset: p.pos}
	objType, size, err := p.readObjectHeader()
	if err != nil {
		return nil, err
	}
	o.objType = objType
	switch objType {
	case gitObjCommit, gitObjTree, gitObjBlob, gitObjTag:
	case gitObjOfsDelta:
		dist, err := p.readOfsDeltaDistance()
		if err != nil {
			return nil, err
		}
		o.baseOff = o.offset - dist
		if dist <= 0 || o.baseOff < 12 {
			return nil, fmt.Errorf("delta base offset %d out of range", o.baseOff)
		}
	case gitObjRefDelta:
		if p.pos+20 > int64(len(p.body)) {
			return nil, errors.New("pack truncated")
		}
		o.baseSHA = hex.EncodeToString(p.body[p.pos : p.pos+20])
		p.pos += 20
	default:
		return nil, fmt.Errorf("unsupported pack object type %d", objType)
	}
	if o.data, err = p.inflate(size); err != nil {
		return nil, err
	}
	o.end = p.pos
	return o, nil
}

// gitResolvePack hashes the non-delta objects, then repeatedly applies
// deltas whose base is already resolved until none remain. One ordered pass
// is not enough: a REF_DELTA may name a base that appears later in the pack,
// so passes repeat to a fixpoint. Leftovers mean the pack is thin (bases
// outside the pack), which a self-contained mirror must reject.
func gitResolvePack(objs []*gitPackObject) error {
	byOff := make(map[int64]*gitPackObject, len(objs))
	bySHA := make(map[string]*gitPackObject, len(objs))
	for _, o := range objs {
		byOff[o.offset] = o
		if o.objType != gitObjOfsDelta && o.objType != gitObjRefDelta {
			o.finish(o.objType, o.data, bySHA)
		}
	}
	for {
		progress, unresolved, err := gitResolvePass(objs, byOff, bySHA)
		if err != nil {
			return err
		}
		if unresolved == 0 {
			return nil
		}
		if !progress {
			return fmt.Errorf("thin pack: %d delta(s) reference bases outside the pack", unresolved)
		}
	}
}

// gitResolvePass tries every still-unresolved delta once, reporting whether
// any progressed and how many remain.
func gitResolvePass(objs []*gitPackObject, byOff map[int64]*gitPackObject, bySHA map[string]*gitPackObject) (progress bool, unresolved int, err error) {
	for _, o := range objs {
		if o.kind != 0 {
			continue
		}
		done, err := o.resolveDelta(byOff, bySHA)
		if err != nil {
			return false, 0, err
		}
		if done {
			progress = true
		} else {
			unresolved++
		}
	}
	return progress, unresolved, nil
}

// finish marks an object resolved: final type, content, and its id — SHA-1
// over the loose-object header "<type> <len>\x00" plus the content.
func (o *gitPackObject) finish(kind int, content []byte, bySHA map[string]*gitPackObject) {
	o.kind = kind
	o.content = content
	h := sha1.New() //nolint:gosec // object ids are defined as SHA-1
	fmt.Fprintf(h, "%s %d\x00", gitTypeName(kind), len(content))
	h.Write(content)
	o.sha = hex.EncodeToString(h.Sum(nil))
	if _, dup := bySHA[o.sha]; !dup {
		bySHA[o.sha] = o
	}
}

// resolveDelta applies o's delta if its base is resolved, reporting whether
// it made progress. A REF_DELTA base may legitimately resolve only on a
// later pass; an OFS_DELTA base offset that starts no entry never can.
func (o *gitPackObject) resolveDelta(byOff map[int64]*gitPackObject, bySHA map[string]*gitPackObject) (bool, error) {
	var base *gitPackObject
	if o.objType == gitObjOfsDelta {
		base = byOff[o.baseOff]
		if base == nil {
			return false, fmt.Errorf("delta at %d references offset %d, which starts no object", o.offset, o.baseOff)
		}
	} else {
		base = bySHA[o.baseSHA]
	}
	if base == nil || base.kind == 0 {
		return false, nil
	}
	content, err := gitApplyDelta(base.content, o.data)
	if err != nil {
		return false, fmt.Errorf("delta at %d: %w", o.offset, err)
	}
	o.data = nil
	o.finish(base.kind, content, bySHA)
	return true, nil
}

// gitApplyDelta reconstructs an object from its base and a delta stream: two
// size varints (base — checked against the actual base — then result), then
// instructions. An opcode with the MSB set copies from the base: its low
// seven bits flag which little-endian offset (bits 0-3) and size (bits 4-6)
// bytes follow, and a zero size means 0x10000. An opcode with the MSB clear
// inserts that many literal bytes; zero is reserved.
func gitApplyDelta(base, delta []byte) ([]byte, error) {
	baseSize, pos, err := gitDeltaSize(delta, 0)
	if err != nil {
		return nil, err
	}
	resultSize, pos, err := gitDeltaSize(delta, pos)
	if err != nil {
		return nil, err
	}
	if baseSize != int64(len(base)) {
		return nil, fmt.Errorf("delta expects a %d-byte base, object is %d", baseSize, len(base))
	}
	if resultSize > gitMaxObjectBytes {
		return nil, fmt.Errorf("delta result %d exceeds the %s cap", resultSize, formatBytes(gitMaxObjectBytes))
	}
	out := make([]byte, 0, resultSize)
	for pos < len(delta) {
		op := delta[pos]
		pos++
		switch {
		case op&0x80 != 0:
			out, pos, err = gitDeltaCopy(out, base, delta, pos, op)
		case op != 0:
			out, pos, err = gitDeltaInsert(out, delta, pos, int(op))
		default:
			return nil, errors.New("reserved delta opcode 0")
		}
		if err != nil {
			return nil, err
		}
		if int64(len(out)) > resultSize {
			return nil, errors.New("delta writes past its declared result size")
		}
	}
	if int64(len(out)) != resultSize {
		return nil, fmt.Errorf("delta produced %d bytes, header declares %d", len(out), resultSize)
	}
	return out, nil
}

// gitDeltaSize decodes a delta header size varint (seven bits per byte,
// least significant first, MSB continues).
func gitDeltaSize(delta []byte, pos int) (int64, int, error) {
	var size int64
	for shift := uint(0); ; shift += 7 {
		if pos >= len(delta) {
			return 0, 0, errors.New("delta header truncated")
		}
		if shift > 60 {
			return 0, 0, errors.New("delta size varint overflow")
		}
		b := delta[pos]
		pos++
		size |= int64(b&0x7f) << shift
		if b&0x80 == 0 {
			return size, pos, nil
		}
	}
}

// gitDeltaCopy executes one copy-from-base instruction.
func gitDeltaCopy(out, base, delta []byte, pos int, op byte) ([]byte, int, error) {
	var off, size int
	for i := 0; i < 4; i++ {
		if op&(1<<i) != 0 {
			if pos >= len(delta) {
				return nil, 0, errors.New("delta copy instruction truncated")
			}
			off |= int(delta[pos]) << (8 * i)
			pos++
		}
	}
	for i := 0; i < 3; i++ {
		if op&(0x10<<i) != 0 {
			if pos >= len(delta) {
				return nil, 0, errors.New("delta copy instruction truncated")
			}
			size |= int(delta[pos]) << (8 * i)
			pos++
		}
	}
	if size == 0 {
		size = 0x10000
	}
	if off+size > len(base) {
		return nil, 0, fmt.Errorf("delta copy [%d,%d) outside the %d-byte base", off, off+size, len(base))
	}
	return append(out, base[off:off+size]...), pos, nil
}

// gitDeltaInsert executes one insert-literal instruction.
func gitDeltaInsert(out, delta []byte, pos, n int) ([]byte, int, error) {
	if pos+n > len(delta) {
		return nil, 0, errors.New("delta insert runs past the stream")
	}
	return append(out, delta[pos:pos+n]...), pos + n, nil
}

// -----------------------------------------------------------------------------
// idx v2 serialization (gitformat-pack)
// -----------------------------------------------------------------------------

// gitWriteIdx renders a version-2 pack index: the \377tOc magic and version,
// a 256-entry fanout of cumulative object counts by leading id byte, the
// sorted ids, their CRC32s, their pack offsets, the pack's trailer SHA-1,
// and finally the SHA-1 of the index content itself. The 2 GiB pack cap
// keeps every offset below the 31-bit large-offset escape (MSB clear), so
// the 8-byte offset table is never needed.
func gitWriteIdx(x *gitPackIndex) ([]byte, error) {
	ids := make([][]byte, len(x.Entries))
	var fanout [256]uint32
	for i, e := range x.Entries {
		raw, err := hex.DecodeString(e.SHA1)
		if err != nil || len(raw) != 20 {
			return nil, fmt.Errorf("invalid object id %q", e.SHA1)
		}
		ids[i] = raw
		fanout[raw[0]]++
	}
	packSHA, err := hex.DecodeString(x.PackSHA1)
	if err != nil || len(packSHA) != 20 {
		return nil, fmt.Errorf("invalid pack checksum %q", x.PackSHA1)
	}
	var b bytes.Buffer
	b.Write([]byte{0xff, 't', 'O', 'c', 0, 0, 0, 2})
	var total uint32
	for _, n := range fanout {
		total += n
		_ = binary.Write(&b, binary.BigEndian, total)
	}
	for _, id := range ids {
		b.Write(id)
	}
	for _, e := range x.Entries {
		_ = binary.Write(&b, binary.BigEndian, e.CRC32)
	}
	for _, e := range x.Entries {
		_ = binary.Write(&b, binary.BigEndian, uint32(e.Offset)) //nolint:gosec // offsets are bounded by the 2 GiB pack cap
	}
	b.Write(packSHA)
	sum := sha1.Sum(b.Bytes()) //nolint:gosec // idx checksums are defined as SHA-1
	b.Write(sum[:])
	return b.Bytes(), nil
}

// -----------------------------------------------------------------------------
// High side: publish (regenerate idx and dumb-protocol plumbing)
// -----------------------------------------------------------------------------

func (s *HighServer) gitDir() string {
	return filepath.Join(s.downloadDir, "git")
}

// publishGit regenerates the served plumbing for every repository in an
// imported bundle. A repository that cannot be published is logged and
// skipped so it neither wedges the stream's import nor takes the bundle's
// other repositories down with it.
func (s *HighServer) publishGit(m *GitManifest) error {
	if m == nil {
		return nil
	}
	for _, repo := range m.Repos {
		if err := s.publishGitRepo(repo); err != nil {
			log.Printf("git publish %s: %v", repo.Name, err)
		}
	}
	return nil
}

// publishGitRepo re-derives everything served for one mirror from the
// verified pack itself: the pack index, the ref list (dropping any manifest
// ref whose object the pack does not actually contain), HEAD, and the pack
// listing.
func (s *HighServer) publishGitRepo(repo GitRepoMirror) error {
	if err := validateMirrorName(repo.Name); err != nil {
		return err
	}
	idx, packBase, err := s.gitRegenerateIdx(repo)
	if err != nil {
		return err
	}
	refs := gitKeptRefs(repo, idx)
	if len(refs) == 0 {
		return errors.New("no listed ref's object is present in the pack")
	}
	return s.writeGitPlumbing(repo.Name, gitHeadTarget(repo.Head, refs), refs, packBase)
}

// gitRegenerateIdx loads the installed pack, re-verifies and re-indexes it
// with the same parser the low side used (no transferred index exists, let
// alone is trusted), and writes pack-<sha1>.idx beside it. The pack is read
// whole — up to gitMaxPackBytes — because delta resolution needs random
// access; that is the import-time memory cost of a mirror.
func (s *HighServer) gitRegenerateIdx(repo GitRepoMirror) (*gitPackIndex, string, error) {
	base := path.Base(repo.PackPath)
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(repo.PackPath))
	if !gitPackBaseRE.MatchString(base) ||
		repo.PackPath != gitPackRel(repo.Name, gitPackTrailerFromBase(base)) || !safeJoin(s.gitDir(), abs) {
		return nil, "", fmt.Errorf("unsafe pack path %s", repo.PackPath)
	}
	pack, err := os.ReadFile(abs)
	if err != nil {
		return nil, "", err
	}
	idx, err := gitIndexPack(pack)
	if err != nil {
		return nil, "", fmt.Errorf("installed pack %s: %w", base, err)
	}
	if idx.PackSHA1 != gitPackTrailerFromBase(base) {
		return nil, "", fmt.Errorf("pack trailer %s does not match its filename", idx.PackSHA1)
	}
	idxBytes, err := gitWriteIdx(idx)
	if err != nil {
		return nil, "", err
	}
	if err := writeBytesAtomic(strings.TrimSuffix(abs, ".pack")+".idx", idxBytes, 0o644); err != nil {
		return nil, "", err
	}
	return idx, strings.TrimSuffix(base, ".pack"), nil
}

// gitKeptRefs filters the manifest refs to the servable ones: safe name,
// well-formed id, and an object actually present in the verified pack. A
// miss is logged and dropped, never served.
func gitKeptRefs(repo GitRepoMirror, idx *gitPackIndex) []GitRef {
	kept := make([]GitRef, 0, len(repo.Refs))
	for _, ref := range repo.Refs {
		if validateGitRefName(ref.Name) != nil || !gitSHA1RE.MatchString(ref.SHA1) || !idx.has(ref.SHA1) {
			log.Printf("git publish %s: dropping ref %q: no such object in the pack", repo.Name, ref.Name)
			continue
		}
		kept = append(kept, ref)
	}
	return kept
}

// gitHeadTarget picks the served HEAD symref target: the manifest head when
// it names a kept ref, else the first kept branch, else the first kept ref.
func gitHeadTarget(head string, refs []GitRef) string {
	branch := ""
	for _, ref := range refs {
		if ref.Name == head {
			return head
		}
		if branch == "" && strings.HasPrefix(ref.Name, "refs/heads/") {
			branch = ref.Name
		}
	}
	if branch != "" {
		return branch
	}
	return refs[0].Name
}

// writeGitPlumbing writes the three files dumb-protocol clients read:
// info/refs ("<sha>\t<refname>", TAB-separated and sorted by name — the
// layout git's dumb walker parses), HEAD as a symref, and
// objects/info/packs naming only the newest pack. Each re-mirror replaces
// the listing wholesale: earlier pack files stay on disk (still fetchable by
// their digest-addressed URLs) but are no longer advertised, so clients walk
// exactly one complete pack.
func (s *HighServer) writeGitPlumbing(name, head string, refs []GitRef, packBase string) error {
	dir := filepath.Join(s.gitDir(), name)
	if !safeJoin(s.gitDir(), dir) {
		return fmt.Errorf("unsafe mirror name %q", name)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	var infoRefs strings.Builder
	for _, ref := range refs {
		fmt.Fprintf(&infoRefs, "%s\t%s\n", ref.SHA1, ref.Name)
	}
	if err := writeBytesAtomic(filepath.Join(dir, "info", "refs"), []byte(infoRefs.String()), 0o644); err != nil {
		return err
	}
	if err := writeBytesAtomic(filepath.Join(dir, "HEAD"), []byte("ref: "+head+"\n"), 0o644); err != nil {
		return err
	}
	packs := "P " + packBase + ".pack\n\n"
	return writeBytesAtomic(filepath.Join(dir, "objects", "info", "packs"), []byte(packs), 0o644)
}

// -----------------------------------------------------------------------------
// High side: dumb-protocol serving
// -----------------------------------------------------------------------------

// serveGit handles the git routes under /git/<name>[.git]/: the dumb HTTP
// protocol files any stock git can clone from. A smart-protocol probe
// (info/refs with a ?service= query) is answered with the same plain-text
// file, which makes clients fall back to the dumb protocol automatically.
// It reports whether it wrote a response for the request.
func (s *HighServer) serveGit(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/git" && !strings.HasPrefix(p, "/git/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rel := strings.Trim(strings.TrimPrefix(p, "/git"), "/")
	name, file, ok := gitServablePath(rel)
	if validateRelPath(rel) != nil || !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return true
	}
	abs := filepath.Join(s.gitDir(), name, filepath.FromSlash(file))
	if !safeJoin(s.gitDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return true
	}
	if file == "info/refs" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	serveFile(w, r, abs)
	return true
}

// gitServablePath splits "<name>[.git]/<rest>" and restricts rest to the
// dumb-protocol files: HEAD, info/refs, objects/info/packs, and the
// pack/idx pair. Everything else — notably loose-object paths, which this
// mirror never has — is not servable, and the walker moves on to the packs.
func gitServablePath(rel string) (name, file string, ok bool) {
	name, rest, found := strings.Cut(rel, "/")
	name = strings.TrimSuffix(name, ".git")
	if !found || validateMirrorName(name) != nil {
		return "", "", false
	}
	switch rest {
	case "HEAD", "info/refs", "objects/info/packs":
		return name, rest, true
	}
	if base, isPack := strings.CutPrefix(rest, "objects/pack/"); isPack && gitServedPackRE.MatchString(base) {
		return name, rest, true
	}
	return "", "", false
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listGitRepos lists the mirrors with their served refs' short names, read
// from the regenerated info/refs files (nothing beyond the served tree is
// stored).
func (s *HighServer) listGitRepos() ([]UIModule, error) {
	entries, err := os.ReadDir(s.gitDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UIModule
	for _, e := range entries {
		if !e.IsDir() || validateMirrorName(e.Name()) != nil {
			continue
		}
		refs, err := s.readGitRefs(e.Name())
		if err != nil || len(refs) == 0 {
			continue
		}
		versions := make([]string, 0, len(refs))
		for _, ref := range refs {
			versions = append(versions, gitShortRef(ref.Name))
		}
		out = append(out, UIModule{Module: e.Name(), Versions: versions})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// gitShortRef renders a ref's display name: branches and tags by their short
// name, anything else in full.
func gitShortRef(name string) string {
	if short, ok := strings.CutPrefix(name, "refs/heads/"); ok {
		return short
	}
	if short, ok := strings.CutPrefix(name, "refs/tags/"); ok {
		return short
	}
	return name
}

// readGitRefs parses a mirror's regenerated info/refs file.
func (s *HighServer) readGitRefs(name string) ([]GitRef, error) {
	p := filepath.Join(s.gitDir(), name, "info", "refs")
	if !safeJoin(s.gitDir(), p) {
		return nil, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var refs []GitRef
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		sha, ref, ok := strings.Cut(line, "\t")
		if !ok || !gitSHA1RE.MatchString(sha) || validateGitRefName(ref) != nil {
			continue
		}
		refs = append(refs, GitRef{Name: ref, SHA1: sha})
	}
	return refs, nil
}

// readGitPackBase reads the mirror's advertised pack stem ("pack-<sha1>")
// from the regenerated objects/info/packs listing.
func (s *HighServer) readGitPackBase(name string) (string, error) {
	p := filepath.Join(s.gitDir(), name, "objects", "info", "packs")
	if !safeJoin(s.gitDir(), p) {
		return "", errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	base, ok := strings.CutPrefix(line, "P ")
	if !ok || !gitPackBaseRE.MatchString(base) {
		return "", errors.New("no pack listed for the mirror")
	}
	return strings.TrimSuffix(base, ".pack"), nil
}

// gitFindRef resolves a short or full ref name against the served refs. On a
// short-name tie a branch wins over a tag (the list is sorted, heads first).
func gitFindRef(refs []GitRef, name string) (GitRef, bool) {
	for _, ref := range refs {
		if ref.Name == name {
			return ref, true
		}
	}
	for _, ref := range refs {
		if gitShortRef(ref.Name) == name {
			return ref, true
		}
	}
	return GitRef{}, false
}

// gitDetail describes one mirrored ref for the dashboard detail panel. spec
// is "<name>@<ref>" with the ref short ("main", "v1.2.3") or in full; mirror
// names cannot contain "@", so splitting at the first "@" is always right.
func (s *HighServer) gitDetail(spec string) (UIDetail, error) {
	name, refName, ok := strings.Cut(spec, "@")
	if !ok || validateMirrorName(name) != nil {
		return UIDetail{}, errors.New("invalid repo@ref")
	}
	refs, err := s.readGitRefs(name)
	if err != nil {
		return UIDetail{}, errors.New("repository not found")
	}
	ref, ok := gitFindRef(refs, refName)
	if !ok {
		return UIDetail{}, errors.New("ref not found")
	}
	packBase, err := s.readGitPackBase(name)
	if err != nil {
		return UIDetail{}, err
	}
	packURL := "/git/" + name + "/objects/pack/" + packBase + ".pack"
	fields := []UIDetailField{
		{Label: "Repository", Value: "/git/" + name + ".git", Mono: true},
		{Label: "Ref", Value: ref.Name, Mono: true},
		{Label: "Commit", Value: ref.SHA1, Mono: true},
	}
	abs := filepath.Join(s.gitDir(), name, "objects", "pack", packBase+".pack")
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Pack size", Value: formatBytes(fi.Size())})
	}
	if sum, err := s.detailDigests.get(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Pack SHA-256", Value: sum, Mono: true})
	}
	downloads := []UIDownload{{Label: packBase + ".pack", URL: packURL}}
	return UIDetail{
		Title:     name,
		Subtitle:  gitShortRef(ref.Name),
		Fields:    fields,
		CloneURL:  "git/" + name + ".git",
		Downloads: downloads,
	}, nil
}

// -----------------------------------------------------------------------------
// Low side: repository collector
// -----------------------------------------------------------------------------

// GitCollectRequest is the body of POST /admin/git/collect.
type GitCollectRequest struct {
	// URL is the upstream repository (the URL `git clone` would use, http(s)
	// smart protocol).
	URL string `json:"url"`
	// Name optionally names the mirror under /git/<name>.git on the high
	// side; it defaults to a slug of the URL (minus a trailing ".git").
	Name string `json:"name,omitempty"`
	// Refs optionally restricts the mirror to specific refs (full names,
	// e.g. "refs/heads/main", "refs/tags/v1.2.3"); the default mirrors every
	// branch and tag.
	Refs []string `json:"refs,omitempty"`
	// Auth optionally authenticates this fetch against a private upstream.
	// It is used for this collect only and never stored; standing credentials
	// belong in ARTIGATE_UPSTREAM_AUTH (watch specs must never carry logins —
	// they are persisted and echoed in plaintext).
	Auth *HostCollectAuth `json:"auth,omitempty"`
	// Force disables export dedup for this collect: the pack is bundled even
	// when an identical one was already forwarded (for disaster recovery or
	// rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// validateGitRequest checks the collect request and derives the mirror name
// and trimmed upstream URL.
func validateGitRequest(req GitCollectRequest) (name, repoURL string, err error) {
	repoURL = strings.TrimSuffix(strings.TrimSpace(req.URL), "/")
	u, err := url.Parse(repoURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", fmt.Errorf("git repo url %q must be an http(s) URL", req.URL)
	}
	// The URL is recorded in the signed manifest and echoed in progress and
	// error text, so it must never carry a login.
	if err := checkNoURLUserinfo(u, "git repo url"); err != nil {
		return "", "", err
	}
	for _, ref := range req.Refs {
		if err := validateGitRefName(ref); err != nil {
			return "", "", err
		}
	}
	name = req.Name
	if name == "" {
		name = aptMirrorName(strings.TrimSuffix(repoURL, ".git"))
	}
	if err := validateMirrorName(name); err != nil {
		return "", "", err
	}
	return name, repoURL, nil
}

// HandleGitCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandleGitCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req GitCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse git collect request: %w", err)
		}
	}
	return s.CollectGit(ctx, req)
}

// CollectGit mirrors one upstream repository: it fetches the ref
// advertisement and one self-contained pack over the smart HTTP protocol,
// verifies and indexes the pack, and writes it with the selected refs into a
// signed bundle on the git stream.
func (s *LowServer) CollectGit(ctx context.Context, req GitCollectRequest) (ExportResult, error) {
	name, repoURL, err := validateGitRequest(req)
	if err != nil {
		return ExportResult{}, err
	}
	creds, err := upstreamCollectCredentials([]string{upstreamURLHost(repoURL)}, req.Auth)
	if err != nil {
		return ExportResult{}, err
	}
	// Hold only the git stream's lock for the whole fetch->write->commit so a
	// concurrent git exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamGit)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "git", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	repo, mf, err := gitMirrorToStaging(ctx, stageRoot, name, repoURL, req.Refs, credentialForHost(creds, upstreamURLHost(repoURL)))
	if err != nil {
		return ExportResult{}, decorateUpstreamAuthError(err, creds)
	}
	files := []ManifestFile{mf}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	return s.exportIfNew(ctx, streamGit, stageRoot, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeGitBundle(ctx, seq, stageRoot, files, repo)
	})
}

// gitMirrorToStaging performs the network fetch and pack verification,
// leaving the pack in the staging tree and returning the manifest record.
// The whole exchange shares one deadline like the other ecosystems' large
// downloads.
func gitMirrorToStaging(ctx context.Context, stageRoot, name, repoURL string, requested []string, cred *registryCredential) (GitRepoMirror, ManifestFile, error) {
	ctx, cancel := context.WithTimeout(ctx, gitFetchTimeout)
	defer cancel()
	emitProgress(ctx, "Fetching %s ref advertisement…", repoURL)
	adv, err := gitFetchAdvertisement(ctx, repoURL, cred)
	if err != nil {
		return GitRepoMirror{}, ManifestFile{}, err
	}
	refs, head, err := gitSelectRefs(adv, requested)
	if err != nil {
		return GitRepoMirror{}, ManifestFile{}, err
	}
	wants := gitWantSHAs(refs)
	emitProgress(ctx, "→ %d ref(s), %d distinct tip(s); fetching pack…", len(refs), len(wants))
	pack, err := gitFetchPack(ctx, repoURL, wants, adv.caps["side-band-64k"], cred)
	if err != nil {
		return GitRepoMirror{}, ManifestFile{}, err
	}
	emitProgress(ctx, "Verifying and indexing the %s pack…", formatBytes(int64(len(pack))))
	idx, err := gitIndexPack(pack)
	if err != nil {
		return GitRepoMirror{}, ManifestFile{}, fmt.Errorf("upstream pack: %w", err)
	}
	if err := gitCheckRefsPresent(refs, idx); err != nil {
		return GitRepoMirror{}, ManifestFile{}, err
	}
	mf, err := gitWritePack(stageRoot, name, idx.PackSHA1, pack)
	if err != nil {
		return GitRepoMirror{}, ManifestFile{}, err
	}
	repo := GitRepoMirror{Name: name, URL: repoURL, Head: head, Refs: refs, PackPath: mf.Path, PackSHA256: mf.SHA256}
	return repo, mf, nil
}

// gitCheckRefsPresent confirms every selected tip made it into the verified
// pack; a miss means the upstream answered the fetch incompletely.
func gitCheckRefsPresent(refs []GitRef, idx *gitPackIndex) error {
	for _, ref := range refs {
		if !idx.has(ref.SHA1) {
			return fmt.Errorf("upstream pack is missing %s (%s)", ref.Name, ref.SHA1)
		}
	}
	return nil
}

// gitWritePack stores the verified pack in the staging tree under its
// canonical trailer-derived name and hashes it for the manifest.
func gitWritePack(stageRoot, name, trailer string, pack []byte) (ManifestFile, error) {
	rel := gitPackRel(name, trailer)
	abs := filepath.Join(stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, pack, 0o644); err != nil {
		return ManifestFile{}, err
	}
	return hashManifestFile(abs, rel)
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeGitBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, repo GitRepoMirror) (ExportResult, error) {
	id := bundleIDFor(streamGit, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamGit,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"git"},
		Git:              &GitManifest{Repos: []GitRepoMirror{repo}},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamGit, Sequence: seq, ExportedModules: 1, BundleID: id}, nil
}
