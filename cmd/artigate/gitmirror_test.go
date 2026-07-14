package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// -----------------------------------------------------------------------------
// Fixtures: a tiny real pack built byte by byte
// -----------------------------------------------------------------------------

func gitTestSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// gitTestObjectSHA computes an object id exactly like git does: SHA-1 over
// "<type> <len>\x00" plus the content.
func gitTestObjectSHA(objType int, content []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", gitTypeName(objType), len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// gitTestDeflate zlib-compresses one object payload.
func gitTestDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gitTestObjHeader encodes a pack entry's type+size varint (the inverse of
// readObjectHeader).
func gitTestObjHeader(objType, size int) []byte {
	b := byte(objType<<4) | byte(size&0x0f)
	size >>= 4
	var out []byte
	for size > 0 {
		out = append(out, b|0x80)
		b = byte(size & 0x7f)
		size >>= 7
	}
	return append(out, b)
}

// gitTestOfsDistance encodes an OFS_DELTA base distance the way git's own
// pack writer does (the inverse of readOfsDeltaDistance).
func gitTestOfsDistance(dist int64) []byte {
	out := []byte{byte(dist & 0x7f)}
	for dist >>= 7; dist > 0; dist >>= 7 {
		dist--
		out = append([]byte{0x80 | byte(dist&0x7f)}, out...)
	}
	return out
}

// gitTestDeltaVarint encodes a delta header size (seven bits per byte, least
// significant first).
func gitTestDeltaVarint(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// gitTestDelta assembles a delta stream from its two sizes and instructions.
func gitTestDelta(baseSize, resultSize int, ops []byte) []byte {
	out := gitTestDeltaVarint(baseSize)
	out = append(out, gitTestDeltaVarint(resultSize)...)
	return append(out, ops...)
}

// gitTestObj is one raw entry fed to gitTestPack.
type gitTestObj struct {
	objType int
	data    []byte // payload (the delta stream for delta types)
	baseIdx int    // OFS_DELTA: index of the base entry
	baseSHA string // REF_DELTA: base object id
}

// gitTestPack assembles a pack from entries, returning the bytes and each
// entry's offset.
func gitTestPack(t *testing.T, objs []gitTestObj) ([]byte, []int64) {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	_ = binary.Write(&b, binary.BigEndian, uint32(2))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(objs)))
	offsets := make([]int64, len(objs))
	for i, o := range objs {
		offsets[i] = int64(b.Len())
		b.Write(gitTestObjHeader(o.objType, len(o.data)))
		switch o.objType {
		case gitObjOfsDelta:
			b.Write(gitTestOfsDistance(offsets[i] - offsets[o.baseIdx]))
		case gitObjRefDelta:
			raw, err := hex.DecodeString(o.baseSHA)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(raw)
		}
		b.Write(gitTestDeflate(t, o.data))
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes(), offsets
}

// gitTestRetrailer replaces a (possibly mutated) trailerless pack body's
// checksum so header corruptions are reachable past the trailer check.
func gitTestRetrailer(body []byte) []byte {
	sum := sha1.Sum(body)
	return append(append([]byte{}, body...), sum[:]...)
}

// gitTestFixture is the canonical test pack: a blob, a tree referencing it,
// a commit referencing the tree, an OFS_DELTA against the blob, and a
// REF_DELTA whose base blob appears later in the pack (exercising the
// resolution fixpoint).
type gitTestFixture struct {
	pack    []byte
	offsets []int64
	kinds   []int
	content [][]byte // resolved content per entry
	shas    []string // per entry, in pack order
}

func (f *gitTestFixture) trailer() string { return hex.EncodeToString(f.pack[len(f.pack)-20:]) }
func (f *gitTestFixture) commitSHA() string {
	return f.shas[2]
}
func (f *gitTestFixture) deltaBlobSHA() string { return f.shas[3] }

func newGitTestFixture(t *testing.T) *gitTestFixture {
	t.Helper()
	blob := []byte("hello, packed world\n")
	rawBlobSHA, err := hex.DecodeString(gitTestObjectSHA(gitObjBlob, blob))
	if err != nil {
		t.Fatal(err)
	}
	tree := append([]byte("100644 hello.txt\x00"), rawBlobSHA...)
	commit := []byte("tree " + gitTestObjectSHA(gitObjTree, tree) +
		"\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\npack fixture\n")
	// OFS_DELTA against the blob: copy all of it, then insert a suffix.
	ofsResult := append(append([]byte{}, blob...), "and more\n"...)
	ofsOps := append([]byte{0x90, byte(len(blob)), 0x09}, "and more\n"...)
	ofsDelta := gitTestDelta(len(blob), len(ofsResult), ofsOps)
	// REF_DELTA whose base appears later in the pack: copy "late", insert.
	lateBlob := []byte("late base object\n")
	refResult := []byte("later base\n")
	refOps := append([]byte{0x90, 0x04, 0x07}, "r base\n"...)
	refDelta := gitTestDelta(len(lateBlob), len(refResult), refOps)

	pack, offsets := gitTestPack(t, []gitTestObj{
		{objType: gitObjBlob, data: blob},
		{objType: gitObjTree, data: tree},
		{objType: gitObjCommit, data: commit},
		{objType: gitObjOfsDelta, data: ofsDelta, baseIdx: 0},
		{objType: gitObjRefDelta, data: refDelta, baseSHA: gitTestObjectSHA(gitObjBlob, lateBlob)},
		{objType: gitObjBlob, data: lateBlob},
	})
	f := &gitTestFixture{
		pack:    pack,
		offsets: offsets,
		kinds:   []int{gitObjBlob, gitObjTree, gitObjCommit, gitObjBlob, gitObjBlob, gitObjBlob},
		content: [][]byte{blob, tree, commit, ofsResult, refResult, lateBlob},
	}
	for i, kind := range f.kinds {
		f.shas = append(f.shas, gitTestObjectSHA(kind, f.content[i]))
	}
	return f
}

// -----------------------------------------------------------------------------
// Fixtures: a fake smart HTTP server
// -----------------------------------------------------------------------------

// fakeGitServer speaks just enough of the smart HTTP protocol (v0) to serve
// one fixture pack: the ref advertisement and a NAK-then-pack upload-pack
// response, side-band-64k framed or raw.
type fakeGitServer struct {
	t        *testing.T
	advLines []string // advertisement payloads; the first carries "\x00<caps>"
	pack     []byte
	sideband bool

	mu      sync.Mutex
	wants   []string
	reqCaps string
}

func (f *fakeGitServer) start() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/repo.git/info/refs", f.handleInfoRefs)
	mux.HandleFunc("/repo.git/git-upload-pack", f.handleUploadPack)
	srv := httptest.NewServer(mux)
	f.t.Cleanup(srv.Close)
	return srv
}

func (f *fakeGitServer) recorded() (wants []string, caps string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wants, f.reqCaps
}

func (f *fakeGitServer) handleInfoRefs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("service") != "git-upload-pack" {
		http.Error(w, "smart protocol only", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	_, _ = io.WriteString(w, gitPktLine("# service=git-upload-pack\n"))
	_, _ = io.WriteString(w, gitFlushPkt)
	for _, line := range f.advLines {
		_, _ = io.WriteString(w, gitPktLine(line+"\n"))
	}
	_, _ = io.WriteString(w, gitFlushPkt)
}

func (f *fakeGitServer) handleUploadPack(w http.ResponseWriter, r *http.Request) {
	wants, caps, err := f.parseUploadPackRequest(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.wants, f.reqCaps = wants, caps
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	_, _ = io.WriteString(w, gitPktLine("NAK\n"))
	if !f.sideband {
		_, _ = w.Write(f.pack)
		return
	}
	half := len(f.pack) / 2
	_, _ = io.WriteString(w, gitPktLine("\x01"+string(f.pack[:half])))
	_, _ = io.WriteString(w, gitPktLine("\x02remote: counting objects\n"))
	_, _ = io.WriteString(w, gitPktLine("\x01"+string(f.pack[half:])))
	_, _ = io.WriteString(w, gitFlushPkt)
}

func (f *fakeGitServer) parseUploadPackRequest(body io.Reader) (wants []string, caps string, err error) {
	pkts := newGitPktReader(body)
	for {
		payload, flush, err := pkts.next()
		if err != nil {
			return nil, "", err
		}
		if flush {
			break
		}
		rest, ok := strings.CutPrefix(strings.TrimSuffix(string(payload), "\n"), "want ")
		if !ok {
			return nil, "", fmt.Errorf("unexpected request packet %q", payload)
		}
		sha, lineCaps, hasCaps := strings.Cut(rest, " ")
		wants = append(wants, sha)
		if hasCaps {
			caps = lineCaps
		}
	}
	payload, _, err := pkts.next()
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(string(payload)) != "done" {
		return nil, "", fmt.Errorf("expected done, got %q", payload)
	}
	return wants, caps, nil
}

func newGitLowServer(t *testing.T) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	return ls, priv
}

// gitRepoFromExport reads the exported bundle manifest back for assertions.
func gitRepoFromExport(t *testing.T, ls *LowServer, bundleID string) (GitRepoMirror, BundleManifest) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Git == nil || len(m.Git.Repos) != 1 {
		t.Fatalf("manifest carries no git repo: %s", b)
	}
	return m.Git.Repos[0], m
}

// -----------------------------------------------------------------------------
// Unit: registry descriptor
// -----------------------------------------------------------------------------

func TestGitEcosystemDescriptor(t *testing.T) {
	e := gitEcosystem()
	if e.stream != streamGit || e.label != "Git" || e.title == "" || e.contentDesc == "" {
		t.Errorf("unexpected descriptor identity: %+v", e)
	}
	if e.collect == nil || e.watchCollect == nil || e.publish == nil || e.serve == nil ||
		e.scanTree == nil || e.detail == nil || e.manifestContent == nil || e.validateContent == nil {
		t.Error("descriptor leaves hooks unset")
	}
	if e.manifestContent(BundleManifest{}) {
		t.Error("empty manifest must not claim git content")
	}
	withGit := BundleManifest{Git: &GitManifest{Repos: []GitRepoMirror{{Name: "x"}}}}
	if !e.manifestContent(withGit) {
		t.Error("manifest with a repo must claim git content")
	}
	if err := e.validateContent(withGit, map[string]bool{}); err == nil {
		t.Error("validateContent must reject an incomplete repo record")
	}
}

// -----------------------------------------------------------------------------
// Unit: pkt-line codec
// -----------------------------------------------------------------------------

func TestGitPktLine(t *testing.T) {
	if got := gitPktLine("abc\n"); got != "0008abc\n" {
		t.Errorf("gitPktLine = %q, want 0008abc\\n", got)
	}
	var b bytes.Buffer
	b.WriteString(gitPktLine("hello\n"))
	b.WriteString(gitFlushPkt)
	b.WriteString(gitPktLine(""))
	r := newGitPktReader(&b)
	if payload, flush, err := r.next(); err != nil || flush || string(payload) != "hello\n" {
		t.Fatalf("first packet = %q/%v/%v", payload, flush, err)
	}
	if _, flush, err := r.next(); err != nil || !flush {
		t.Fatalf("second packet should be a flush (err %v)", err)
	}
	if payload, flush, err := r.next(); err != nil || flush || len(payload) != 0 {
		t.Fatalf("empty packet = %q/%v/%v", payload, flush, err)
	}
	if _, _, err := r.next(); err == nil {
		t.Fatal("EOF expected after the stream")
	}

	for _, bad := range []string{"zzzz", "0001", "0002", "0003", "fff5", "0008ab"} {
		if _, _, err := newGitPktReader(strings.NewReader(bad)).next(); err == nil {
			t.Errorf("pkt %q should be rejected", bad)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: ref advertisement parsing and selection
// -----------------------------------------------------------------------------

func gitTestAdvertisementBytes(lines []string) *bytes.Buffer {
	var b bytes.Buffer
	b.WriteString(gitPktLine("# service=git-upload-pack\n"))
	b.WriteString(gitFlushPkt)
	for _, l := range lines {
		b.WriteString(gitPktLine(l + "\n"))
	}
	b.WriteString(gitFlushPkt)
	return &b
}

func TestGitParseAdvertisement(t *testing.T) {
	shaA, shaB, shaC := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	adv, err := parseGitAdvertisement(gitTestAdvertisementBytes([]string{
		shaA + " HEAD\x00multi_ack side-band-64k no-progress symref=HEAD:refs/heads/main agent=git/2.x",
		shaA + " refs/heads/main",
		shaB + " refs/tags/v1",
		shaB + " refs/tags/v1^{}",
		shaC + " refs/pull/9/head",
		shaC + " refs/heads/odd@name",
	}))
	if err != nil {
		t.Fatalf("parseGitAdvertisement: %v", err)
	}
	if adv.head != "refs/heads/main" || !adv.caps["side-band-64k"] || !adv.caps["no-progress"] {
		t.Errorf("head/caps = %q/%v", adv.head, adv.caps)
	}
	// HEAD and the peeled tag are dropped; everything else is kept verbatim.
	if len(adv.refs) != 4 || adv.refs[0].Name != "refs/heads/main" || adv.refs[3].Name != "refs/heads/odd@name" {
		t.Fatalf("advertised refs = %+v", adv.refs)
	}

	// Default selection: branches and tags only, unsafe names skipped, sorted.
	refs, head, err := gitSelectRefs(adv, nil)
	if err != nil || head != "refs/heads/main" {
		t.Fatalf("default select: %v (head %q)", err, head)
	}
	if len(refs) != 2 || refs[0].Name != "refs/heads/main" || refs[1].Name != "refs/tags/v1" {
		t.Errorf("default refs = %+v", refs)
	}

	// Explicit selection may name any advertised ref; head drops out when it
	// is not selected. Duplicates collapse.
	refs, head, err = gitSelectRefs(adv, []string{"refs/pull/9/head", "refs/pull/9/head"})
	if err != nil || head != "" || len(refs) != 1 || refs[0].SHA1 != shaC {
		t.Errorf("explicit select = %+v head %q err %v", refs, head, err)
	}

	// Missing explicit refs fail the collect, all of them named.
	_, _, err = gitSelectRefs(adv, []string{"refs/heads/main", "refs/heads/gone", "refs/tags/gone2"})
	if err == nil || !strings.Contains(err.Error(), "refs/heads/gone") || !strings.Contains(err.Error(), "refs/tags/gone2") {
		t.Errorf("missing refs error = %v", err)
	}
}

func TestGitParseAdvertisementEdgeCases(t *testing.T) {
	// Empty repository: the zero-id capabilities^{} placeholder is no ref.
	adv, err := parseGitAdvertisement(gitTestAdvertisementBytes([]string{
		strings.Repeat("0", 40) + " capabilities^{}\x00side-band-64k",
	}))
	if err != nil {
		t.Fatalf("empty-repo advertisement should parse: %v", err)
	}
	if _, _, err := gitSelectRefs(adv, nil); err == nil || !strings.Contains(err.Error(), "no refs") {
		t.Errorf("empty repo selection error = %v", err)
	}

	// A dumb (or non-git) server does not send the service header.
	if _, err := parseGitAdvertisement(strings.NewReader("plain text, not pkt-lines")); err == nil {
		t.Error("non-smart response should be rejected")
	}
	// Missing flush after the service header.
	var b bytes.Buffer
	b.WriteString(gitPktLine("# service=git-upload-pack\n"))
	b.WriteString(gitPktLine(strings.Repeat("a", 40) + " refs/heads/x\n"))
	if _, err := parseGitAdvertisement(&b); err == nil {
		t.Error("advertisement without the header flush should be rejected")
	}
	// Malformed ref line.
	if _, err := parseGitAdvertisement(gitTestAdvertisementBytes([]string{"not-a-sha refs/heads/x"})); err == nil {
		t.Error("malformed ref line should be rejected")
	}
}

// -----------------------------------------------------------------------------
// Unit: varint encodings
// -----------------------------------------------------------------------------

func TestGitVarintRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		objType int
		size    int64
	}{
		{gitObjBlob, 0},
		{gitObjCommit, 15},
		{gitObjTree, 16},
		{gitObjTag, 127},
		{gitObjBlob, 12345678},
		{gitObjBlob, 1<<32 + 5},
	} {
		hdr := gitTestObjHeader(tc.objType, int(tc.size))
		p := &gitPackParser{body: hdr}
		objType, size, err := p.readObjectHeader()
		if err != nil || objType != tc.objType || size != tc.size || p.pos != int64(len(hdr)) {
			t.Errorf("object header %d/%d round trip: %d/%d pos %d err %v",
				tc.objType, tc.size, objType, size, p.pos, err)
		}
	}
	for _, dist := range []int64{1, 127, 128, 129, 16383, 16384, 16511, 16512, 1 << 20, 1 << 28} {
		enc := gitTestOfsDistance(dist)
		p := &gitPackParser{body: enc}
		got, err := p.readOfsDeltaDistance()
		if err != nil || got != dist || p.pos != int64(len(enc)) {
			t.Errorf("ofs distance %d round trip: got %d pos %d err %v (enc %x)", dist, got, p.pos, err, enc)
		}
	}
	for _, n := range []int64{0, 1, 127, 128, 300000} {
		enc := gitTestDeltaVarint(int(n))
		got, pos, err := gitDeltaSize(enc, 0)
		if err != nil || got != n || pos != len(enc) {
			t.Errorf("delta size %d round trip: got %d pos %d err %v", n, got, pos, err)
		}
	}
	if _, _, err := (&gitPackParser{body: []byte{0x80}}).readObjectHeader(); err == nil {
		t.Error("truncated object header should be rejected")
	}
	if _, err := (&gitPackParser{body: []byte{0x80}}).readOfsDeltaDistance(); err == nil {
		t.Error("truncated ofs distance should be rejected")
	}
}

// -----------------------------------------------------------------------------
// Unit: delta application
// -----------------------------------------------------------------------------

func TestGitApplyDelta(t *testing.T) {
	base := make([]byte, 70000)
	for i := range base {
		base[i] = byte(i * 7)
	}
	// copy(1, 0x10000) — the no-size-bytes special case — then an insert,
	// then a copy with multi-byte offset and size crossing the base's end
	// region.
	ops := []byte{0x81, 0x01}
	ops = append(ops, 0x03, 'a', 'b', 'c')
	ops = append(ops, 0xb7, 0x00, 0x00, 0x01, 0x70, 0x11) // copy(65536, 0x1170)
	want := append(append(append([]byte{}, base[1:65537]...), 'a', 'b', 'c'), base[65536:65536+0x1170]...)
	delta := gitTestDelta(len(base), len(want), ops)
	got, err := gitApplyDelta(base, delta)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("gitApplyDelta: err %v, %d bytes (want %d)", err, len(got), len(want))
	}

	bad := []struct {
		name  string
		base  []byte
		delta []byte
	}{
		{"base size mismatch", base[:100], delta},
		{"reserved opcode 0", []byte("xy"), gitTestDelta(2, 1, []byte{0x00})},
		{"copy past base end", []byte("xy"), gitTestDelta(2, 3, []byte{0x91, 0x01, 0x03})},
		{"insert past stream end", []byte("xy"), gitTestDelta(2, 5, []byte{0x05, 'a', 'b'})},
		{"result size mismatch", []byte("xy"), gitTestDelta(2, 9, []byte{0x91, 0x00, 0x02})},
		{"result overrun", []byte("xy"), gitTestDelta(2, 1, []byte{0x91, 0x00, 0x02})},
		{"truncated header", []byte("xy"), []byte{0x80}},
		{"truncated copy operands", []byte("xy"), gitTestDelta(2, 2, []byte{0x91, 0x00})},
	}
	for _, tc := range bad {
		if _, err := gitApplyDelta(tc.base, tc.delta); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit: pack indexing
// -----------------------------------------------------------------------------

func TestGitIndexPackFixture(t *testing.T) {
	f := newGitTestFixture(t)
	idx, err := gitIndexPack(f.pack)
	if err != nil {
		t.Fatalf("gitIndexPack: %v", err)
	}
	if idx.PackSHA1 != f.trailer() {
		t.Errorf("PackSHA1 = %s, want %s", idx.PackSHA1, f.trailer())
	}
	if len(idx.Entries) != len(f.shas) {
		t.Fatalf("indexed %d objects, want %d", len(idx.Entries), len(f.shas))
	}
	if !sort.SliceIsSorted(idx.Entries, func(i, j int) bool { return idx.Entries[i].SHA1 < idx.Entries[j].SHA1 }) {
		t.Error("entries are not sorted by id")
	}
	bySHA := map[string]gitPackEntry{}
	for _, e := range idx.Entries {
		bySHA[e.SHA1] = e
	}
	for i, sha := range f.shas {
		e, ok := bySHA[sha]
		if !ok {
			t.Fatalf("object %d (%s %s) missing from the index", i, gitTypeName(f.kinds[i]), sha)
		}
		if e.Offset != f.offsets[i] {
			t.Errorf("object %d offset = %d, want %d", i, e.Offset, f.offsets[i])
		}
		end := int64(len(f.pack) - 20)
		if i+1 < len(f.offsets) {
			end = f.offsets[i+1]
		}
		if want := crc32.ChecksumIEEE(f.pack[f.offsets[i]:end]); e.CRC32 != want {
			t.Errorf("object %d crc32 = %08x, want %08x", i, e.CRC32, want)
		}
	}
	if idx.has(strings.Repeat("e", 40)) {
		t.Error("has() reports an absent object")
	}
}

func TestGitIndexPackRejects(t *testing.T) {
	f := newGitTestFixture(t)
	body := f.pack[:len(f.pack)-20]

	tampered := append([]byte{}, f.pack...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := gitIndexPack(tampered); err == nil || !strings.Contains(err.Error(), "trailer") {
		t.Errorf("trailer mismatch error = %v", err)
	}
	corrupt := append([]byte{}, f.pack...)
	corrupt[f.offsets[1]+3] ^= 0xff
	if _, err := gitIndexPack(corrupt); err == nil {
		t.Error("corrupted body must fail (trailer mismatch)")
	}

	overCount := append([]byte{}, body...)
	binary.BigEndian.PutUint32(overCount[8:12], uint32(len(f.offsets)+1))
	if _, err := gitIndexPack(gitTestRetrailer(overCount)); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated pack error = %v", err)
	}
	underCount := append([]byte{}, body...)
	binary.BigEndian.PutUint32(underCount[8:12], uint32(len(f.offsets)-1))
	if _, err := gitIndexPack(gitTestRetrailer(underCount)); err == nil || !strings.Contains(err.Error(), "after its last object") {
		t.Errorf("trailing-bytes error = %v", err)
	}
	badVersion := append([]byte{}, body...)
	binary.BigEndian.PutUint32(badVersion[4:8], 4)
	if _, err := gitIndexPack(gitTestRetrailer(badVersion)); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("bad version error = %v", err)
	}
	hugeCount := append([]byte{}, body...)
	binary.BigEndian.PutUint32(hugeCount[8:12], 1<<30)
	if _, err := gitIndexPack(gitTestRetrailer(hugeCount)); err == nil || !strings.Contains(err.Error(), "implausible") {
		t.Errorf("implausible count error = %v", err)
	}

	if _, err := gitIndexPack([]byte("JUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNK")); err == nil {
		t.Error("non-pack bytes must be rejected")
	}
	if _, err := gitIndexPack([]byte("PACK")); err == nil {
		t.Error("a too-short pack must be rejected")
	}

	// A REF_DELTA whose base is not in the pack: a thin pack.
	blob := []byte("only object\n")
	delta := gitTestDelta(len(blob), 1, []byte{0x91, 0x00, 0x01})
	thin, _ := gitTestPack(t, []gitTestObj{
		{objType: gitObjBlob, data: blob},
		{objType: gitObjRefDelta, data: delta, baseSHA: strings.Repeat("d", 40)},
	})
	if _, err := gitIndexPack(thin); err == nil || !strings.Contains(err.Error(), "thin pack") {
		t.Errorf("thin pack error = %v", err)
	}

	// Reserved entry type 5.
	badType, _ := gitTestPack(t, []gitTestObj{{objType: 5, data: blob}})
	if _, err := gitIndexPack(badType); err == nil || !strings.Contains(err.Error(), "type 5") {
		t.Errorf("reserved type error = %v", err)
	}
}

// -----------------------------------------------------------------------------
// Unit: idx v2 serialization
// -----------------------------------------------------------------------------

func TestGitWriteIdx(t *testing.T) {
	f := newGitTestFixture(t)
	idx, err := gitIndexPack(f.pack)
	if err != nil {
		t.Fatal(err)
	}
	b, err := gitWriteIdx(idx)
	if err != nil {
		t.Fatal(err)
	}
	n := len(idx.Entries)
	if want := 8 + 1024 + n*28 + 40; len(b) != want {
		t.Fatalf("idx is %d bytes, want %d", len(b), want)
	}
	if !bytes.Equal(b[:8], []byte{0xff, 't', 'O', 'c', 0, 0, 0, 2}) {
		t.Errorf("idx magic/version = %x", b[:8])
	}
	var prev uint32
	for i := 0; i < 256; i++ {
		v := binary.BigEndian.Uint32(b[8+4*i:])
		if v < prev {
			t.Fatalf("fanout not monotonic at byte %02x: %d < %d", i, v, prev)
		}
		prev = v
	}
	if prev != uint32(n) {
		t.Errorf("fanout total = %d, want %d", prev, n)
	}
	shas, crcs, offs := b[1032:], b[1032+20*n:], b[1032+24*n:]
	for i, e := range idx.Entries {
		if hex.EncodeToString(shas[20*i:20*i+20]) != e.SHA1 {
			t.Fatalf("id %d = %x, want %s", i, shas[20*i:20*i+20], e.SHA1)
		}
		if binary.BigEndian.Uint32(crcs[4*i:]) != e.CRC32 {
			t.Errorf("crc %d mismatch", i)
		}
		off := binary.BigEndian.Uint32(offs[4*i:])
		if off&0x80000000 != 0 || int64(off) != e.Offset {
			t.Errorf("offset %d = %d (msb %v), want %d", i, off, off&0x80000000 != 0, e.Offset)
		}
	}
	if hex.EncodeToString(b[len(b)-40:len(b)-20]) != idx.PackSHA1 {
		t.Error("pack checksum not embedded before the idx checksum")
	}
	sum := sha1.Sum(b[:len(b)-20])
	if !bytes.Equal(b[len(b)-20:], sum[:]) {
		t.Error("idx trailer checksum mismatch")
	}

	if _, err := gitWriteIdx(&gitPackIndex{PackSHA1: "zz"}); err == nil {
		t.Error("invalid pack checksum should be rejected")
	}
	if _, err := gitWriteIdx(&gitPackIndex{PackSHA1: f.trailer(), Entries: []gitPackEntry{{SHA1: "short"}}}); err == nil {
		t.Error("invalid entry id should be rejected")
	}
}

// -----------------------------------------------------------------------------
// Unit: request validation and import-side manifest validation
// -----------------------------------------------------------------------------

func TestGitValidateRequest(t *testing.T) {
	name, repoURL, err := validateGitRequest(GitCollectRequest{URL: "https://github.com/octocat/Hello-World.git/"})
	if err != nil || name != "github-com-octocat-Hello-World" || repoURL != "https://github.com/octocat/Hello-World.git" {
		t.Errorf("derived name/url = %q/%q, err %v", name, repoURL, err)
	}
	if name, _, err := validateGitRequest(GitCollectRequest{URL: "https://x.example/r.git", Name: "mine"}); err != nil || name != "mine" {
		t.Errorf("explicit name = %q, err %v", name, err)
	}
	bad := []GitCollectRequest{
		{URL: ""},
		{URL: "ftp://x.example/repo.git"},
		{URL: "https://"},
		{URL: "https://x.example/r.git", Name: "../evil"},
		{URL: "https://x.example/r.git", Refs: []string{"HEAD"}},
		{URL: "https://x.example/r.git", Refs: []string{"refs/heads/../main"}},
		{URL: "https://x.example/r.git", Refs: []string{"refs/heads/a b"}},
	}
	for _, req := range bad {
		if _, _, err := validateGitRequest(req); err == nil {
			t.Errorf("request %+v should be rejected", req)
		}
	}
}

func TestGitValidateRepos(t *testing.T) {
	trailer := strings.Repeat("a", 40)
	canon := gitPackRel("repo", trailer)
	packSHA := strings.Repeat("b", 64)
	files := []ManifestFile{{Path: canon, SHA256: packSHA, Size: 1}}
	seen := map[string]bool{canon: true}
	good := GitRepoMirror{
		Name: "repo", URL: "https://x.example/r.git", Head: "refs/heads/main",
		Refs: []GitRef{
			{Name: "refs/heads/main", SHA1: strings.Repeat("c", 40)},
			{Name: "refs/tags/v1.2.3", SHA1: strings.Repeat("d", 40)},
		},
		PackPath: canon, PackSHA256: packSHA,
	}
	if err := validateGitRepos([]GitRepoMirror{good}, seen, files); err != nil {
		t.Errorf("valid repo rejected: %v", err)
	}
	headless := good
	headless.Head = ""
	if err := validateGitRepos([]GitRepoMirror{headless}, seen, files); err != nil {
		t.Errorf("empty head rejected: %v", err)
	}

	mutate := func(f func(*GitRepoMirror)) GitRepoMirror {
		r := good
		r.Refs = append([]GitRef{}, good.Refs...)
		f(&r)
		return r
	}
	bad := []struct {
		name string
		repo GitRepoMirror
		seen map[string]bool
	}{
		{"bad mirror name", mutate(func(r *GitRepoMirror) { r.Name = "../x" }), seen},
		{"no url", mutate(func(r *GitRepoMirror) { r.URL = "" }), seen},
		{"no refs", mutate(func(r *GitRepoMirror) { r.Refs = nil }), seen},
		{"ref outside refs/", mutate(func(r *GitRepoMirror) { r.Refs[0].Name = "HEAD" }), seen},
		{"ref with ..", mutate(func(r *GitRepoMirror) { r.Refs[0].Name = "refs/heads/a..b" }), seen},
		{"ref with //", mutate(func(r *GitRepoMirror) { r.Refs[0].Name = "refs//x" }), seen},
		{"ref with @{", mutate(func(r *GitRepoMirror) { r.Refs[0].Name = "refs/heads/a@{1}" }), seen},
		{"ref trailing slash", mutate(func(r *GitRepoMirror) { r.Refs[0].Name = "refs/heads/x/" }), seen},
		{"ref with space", mutate(func(r *GitRepoMirror) { r.Refs[0].Name = "refs/heads/a b" }), seen},
		{"uppercase sha", mutate(func(r *GitRepoMirror) { r.Refs[0].SHA1 = strings.Repeat("A", 40) }), seen},
		{"short sha", mutate(func(r *GitRepoMirror) { r.Refs[0].SHA1 = strings.Repeat("c", 39) }), seen},
		{"head not listed", mutate(func(r *GitRepoMirror) { r.Head = "refs/heads/other" }), seen},
		{"pack for another mirror", mutate(func(r *GitRepoMirror) { r.PackPath = gitPackRel("other", trailer) }), seen},
		{"non-canonical pack path", mutate(func(r *GitRepoMirror) { r.PackPath = "git/repo/pack-" + trailer + ".pack" }), seen},
		{"pack basename not hex", mutate(func(r *GitRepoMirror) { r.PackPath = gitPackRel("repo", strings.Repeat("z", 40)) }), seen},
		{"pack not in files", good, map[string]bool{}},
		{"pack sha mismatch", mutate(func(r *GitRepoMirror) { r.PackSHA256 = strings.Repeat("e", 64) }), seen},
	}
	for _, tc := range bad {
		if err := validateGitRepos([]GitRepoMirror{tc.repo}, tc.seen, files); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration: collect against a fake smart server
// -----------------------------------------------------------------------------

// gitTestAdvHead builds the standard fixture advertisement head line.
func gitTestAdvHead(sha, caps string) string {
	return sha + " HEAD\x00" + caps
}

func TestGitCollectRoundTrip(t *testing.T) {
	f := newGitTestFixture(t)
	fake := &fakeGitServer{t: t, pack: f.pack, sideband: true, advLines: []string{
		gitTestAdvHead(f.commitSHA(), "multi_ack side-band-64k no-progress ofs-delta symref=HEAD:refs/heads/main agent=git/2.fake"),
		f.commitSHA() + " refs/heads/main",
		f.deltaBlobSHA() + " refs/tags/blobtag",
		f.commitSHA() + " refs/tags/v1",
		f.commitSHA() + " refs/tags/v1^{}",
		f.commitSHA() + " refs/pull/1/head",
	}}
	srv := fake.start()

	ls, _ := newGitLowServer(t)
	body := fmt.Sprintf(`{"url":%q,"name":"fix"}`, srv.URL+"/repo.git")
	req := httptest.NewRequest(http.MethodPost, "/admin/git/collect", strings.NewReader(body))
	res, err := ls.HandleGitCollect(context.Background(), req)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if res.BundleID != "git-bundle-000001" || res.ExportedModules != 1 || res.Skipped {
		t.Fatalf("unexpected collect result: %+v", res)
	}

	wants, caps := fake.recorded()
	if len(wants) != 2 || wants[0] != f.commitSHA() || wants[1] != f.deltaBlobSHA() {
		t.Errorf("wants = %v (expected the two distinct tips, deduplicated)", wants)
	}
	if caps != "side-band-64k no-progress agent=artigate" {
		t.Errorf("requested caps = %q", caps)
	}

	repo, m := gitRepoFromExport(t, ls, res.BundleID)
	if repo.Name != "fix" || repo.URL != srv.URL+"/repo.git" || repo.Head != "refs/heads/main" {
		t.Errorf("repo record = %+v", repo)
	}
	wantRefs := []GitRef{
		{Name: "refs/heads/main", SHA1: f.commitSHA()},
		{Name: "refs/tags/blobtag", SHA1: f.deltaBlobSHA()},
		{Name: "refs/tags/v1", SHA1: f.commitSHA()},
	}
	if len(repo.Refs) != len(wantRefs) {
		t.Fatalf("refs = %+v", repo.Refs)
	}
	for i, want := range wantRefs {
		if repo.Refs[i] != want {
			t.Errorf("ref %d = %+v, want %+v", i, repo.Refs[i], want)
		}
	}
	if repo.PackPath != gitPackRel("fix", f.trailer()) || repo.PackSHA256 != gitTestSHA256(f.pack) {
		t.Errorf("pack record = %s / %s", repo.PackPath, repo.PackSHA256)
	}
	// The exported manifest passes the high side's own content validation.
	seen := map[string]bool{}
	for _, mf := range m.Files {
		seen[mf.Path] = true
	}
	if err := validateGitRepos(m.Git.Repos, seen, m.Files); err != nil {
		t.Errorf("exported manifest fails import validation: %v", err)
	}
}

func TestGitCollectWithoutSideband(t *testing.T) {
	f := newGitTestFixture(t)
	fake := &fakeGitServer{t: t, pack: f.pack, sideband: false, advLines: []string{
		gitTestAdvHead(f.commitSHA(), "multi_ack ofs-delta no-progress symref=HEAD:refs/heads/main"),
		f.commitSHA() + " refs/heads/main",
	}}
	srv := fake.start()
	ls, _ := newGitLowServer(t)
	res, err := ls.CollectGit(context.Background(), GitCollectRequest{URL: srv.URL + "/repo.git", Name: "raw"})
	if err != nil {
		t.Fatalf("CollectGit: %v", err)
	}
	if res.ExportedModules != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, caps := fake.recorded(); strings.Contains(caps, "side-band") {
		t.Errorf("side-band requested from a server that never advertised it: %q", caps)
	}
	repo, _ := gitRepoFromExport(t, ls, res.BundleID)
	if repo.PackSHA256 != gitTestSHA256(f.pack) {
		t.Error("raw-mode pack differs from the fixture pack")
	}
}

func TestGitCollectFailures(t *testing.T) {
	f := newGitTestFixture(t)
	ghost := strings.Repeat("9", 40)
	fake := &fakeGitServer{t: t, pack: f.pack, sideband: true, advLines: []string{
		gitTestAdvHead(f.commitSHA(), "side-band-64k no-progress symref=HEAD:refs/heads/main"),
		f.commitSHA() + " refs/heads/main",
		ghost + " refs/heads/ghost",
	}}
	srv := fake.start()
	ls, _ := newGitLowServer(t)

	// A selected ref whose object the upstream never packed fails the collect.
	_, err := ls.CollectGit(context.Background(), GitCollectRequest{URL: srv.URL + "/repo.git", Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "refs/heads/ghost") {
		t.Errorf("incomplete pack error = %v", err)
	}
	// Requesting refs the upstream does not advertise names every one of them.
	_, err = ls.CollectGit(context.Background(), GitCollectRequest{
		URL: srv.URL + "/repo.git", Name: "x", Refs: []string{"refs/heads/main", "refs/tags/nope"},
	})
	if err == nil || !strings.Contains(err.Error(), "refs/tags/nope") {
		t.Errorf("missing requested ref error = %v", err)
	}
	// A URL that is not a smart git server at all.
	notGit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>hello</html>")
	}))
	defer notGit.Close()
	if _, err := ls.CollectGit(context.Background(), GitCollectRequest{URL: notGit.URL, Name: "x"}); err == nil {
		t.Error("a non-git upstream should fail the collect")
	}
	// Malformed JSON through the admin handler.
	req := httptest.NewRequest(http.MethodPost, "/admin/git/collect", strings.NewReader("{bad"))
	if _, err := ls.HandleGitCollect(context.Background(), req); err == nil {
		t.Error("malformed JSON should be rejected")
	}
	// An empty body fails request validation, not the network.
	req = httptest.NewRequest(http.MethodPost, "/admin/git/collect", strings.NewReader(""))
	if _, err := ls.HandleGitCollect(context.Background(), req); err == nil {
		t.Error("empty request should be rejected")
	}
}

// -----------------------------------------------------------------------------
// Integration: publish + dumb-protocol serving
// -----------------------------------------------------------------------------

// gitTestPublishedHigh collects the fixture through a fake upstream, lays the
// bundle's payload out like the importer would, and publishes it.
func gitTestPublishedHigh(t *testing.T) (*HighServer, *gitTestFixture) {
	t.Helper()
	f := newGitTestFixture(t)
	fake := &fakeGitServer{t: t, pack: f.pack, sideband: true, advLines: []string{
		gitTestAdvHead(f.commitSHA(), "side-band-64k no-progress symref=HEAD:refs/heads/main"),
		f.commitSHA() + " refs/heads/main",
		f.deltaBlobSHA() + " refs/tags/blobtag",
		f.commitSHA() + " refs/tags/v1",
	}}
	srv := fake.start()
	ls, priv := newGitLowServer(t)
	res, err := ls.CollectGit(context.Background(), GitCollectRequest{URL: srv.URL + "/repo.git", Name: "fix"})
	if err != nil {
		t.Fatalf("CollectGit: %v", err)
	}
	repo, _ := gitRepoFromExport(t, ls, res.BundleID)

	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	archive := filepath.Join(ls.cfg.ExportDir, res.BundleID+".tar.gz")
	if err := extractTarGzTree(archive, hs.downloadDir); err != nil {
		t.Fatalf("extracting the bundle payload: %v", err)
	}
	if err := hs.publishGit(&GitManifest{Repos: []GitRepoMirror{repo}}); err != nil {
		t.Fatalf("publishGit: %v", err)
	}
	return hs, f
}

func gitTestServer(t *testing.T, hs *HighServer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hs.serveGit(w, r) {
			http.Error(w, "unclaimed", http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitPublishAndServe(t *testing.T) {
	hs, f := gitTestPublishedHigh(t)
	srv := gitTestServer(t, hs)

	wantRefs := f.commitSHA() + "\trefs/heads/main\n" +
		f.deltaBlobSHA() + "\trefs/tags/blobtag\n" +
		f.commitSHA() + "\trefs/tags/v1\n"
	code, body := httpGet(t, srv.URL+"/git/fix/info/refs")
	if code != http.StatusOK || body != wantRefs {
		t.Errorf("info/refs = %d %q, want %q", code, body, wantRefs)
	}
	// The smart-protocol probe gets the same bytes as plain text (and the
	// ".git" suffix is accepted), which flips stock git to the dumb protocol.
	resp, err := http.Get(srv.URL + "/git/fix.git/info/refs?service=git-upload-pack") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	probe, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(probe) != wantRefs ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("smart probe = %d %q (%s)", resp.StatusCode, probe, resp.Header.Get("Content-Type"))
	}

	if code, body := httpGet(t, srv.URL+"/git/fix.git/HEAD"); code != http.StatusOK || body != "ref: refs/heads/main\n" {
		t.Errorf("HEAD = %d %q", code, body)
	}
	packBase := "pack-" + f.trailer()
	if code, body := httpGet(t, srv.URL+"/git/fix/objects/info/packs"); code != http.StatusOK || body != "P "+packBase+".pack\n\n" {
		t.Errorf("objects/info/packs = %d %q", code, body)
	}
	if code, body := httpGet(t, srv.URL+"/git/fix/objects/pack/"+packBase+".pack"); code != http.StatusOK || body != string(f.pack) {
		t.Errorf("pack download: %d, %d bytes (want %d)", code, len(body), len(f.pack))
	}
	// The served idx equals a fresh regeneration from the pack — and is
	// readable by the same parser-side expectations gitWriteIdx encodes.
	idx, err := gitIndexPack(f.pack)
	if err != nil {
		t.Fatal(err)
	}
	wantIdx, err := gitWriteIdx(idx)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := httpGet(t, srv.URL+"/git/fix/objects/pack/"+packBase+".idx"); code != http.StatusOK || body != string(wantIdx) {
		t.Errorf("idx download: %d, %d bytes (want %d)", code, len(body), len(wantIdx))
	}
}

func TestGitServeGates(t *testing.T) {
	hs, f := gitTestPublishedHigh(t)
	srv := gitTestServer(t, hs)

	// Anything outside the dumb-protocol file set is 404 — notably loose
	// object paths, which make git's walker move on to the packs.
	for _, p := range []string{
		"/git",
		"/git/",
		"/git/fix",
		"/git/fix/",
		"/git/fix/objects/12/3456789012345678901234567890123456789012",
		"/git/fix/objects/info/alternates",
		"/git/fix/config",
		"/git/fix/info/refs/x",
		"/git/fix/objects/pack/pack-XYZ.pack",
		"/git/fix/objects/pack/pack-" + strings.Repeat("a", 39) + ".pack",
		"/git/fix/objects/pack/pack-" + f.trailer() + ".pack.tmp",
		"/git/other/info/refs",
	} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
	// Traversal is rejected.
	for _, p := range []string{
		"/git/..%2f..%2fimport-state.json",
		"/git/fix/info%2f..%2f..%2f..%2fimport-state.json",
	} {
		if code, _ := httpGet(t, srv.URL+p); code == http.StatusOK {
			t.Errorf("traversal %s returned 200", p)
		}
	}
	// Only read methods pass.
	resp, err := http.Post(srv.URL+"/git/fix/info/refs", "text/plain", nil) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST info/refs = %d, want 405", resp.StatusCode)
	}
	// Paths outside /git are not claimed at all.
	for _, p := range []string{"/gitx/foo", "/helm/x", "/"} {
		if code, _ := httpGet(t, srv.URL+p); code != http.StatusTeapot {
			t.Errorf("GET %s = %d, want unclaimed", p, code)
		}
	}
}

func TestGitPublishDropsMissingRef(t *testing.T) {
	f := newGitTestFixture(t)
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rel := gitPackRel("repo", f.trailer())
	abs := filepath.Join(hs.downloadDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, f.pack, 0o644); err != nil {
		t.Fatal(err)
	}
	repo := GitRepoMirror{
		Name: "repo", URL: "https://x.example/r.git", Head: "refs/heads/ghost",
		Refs: []GitRef{
			{Name: "refs/heads/ghost", SHA1: strings.Repeat("9", 40)}, // not in the pack
			{Name: "refs/heads/main", SHA1: f.commitSHA()},
		},
		PackPath: rel, PackSHA256: gitTestSHA256(f.pack),
	}
	if err := hs.publishGit(&GitManifest{Repos: []GitRepoMirror{repo}}); err != nil {
		t.Fatalf("publishGit: %v", err)
	}
	refs, err := hs.readGitRefs("repo")
	if err != nil || len(refs) != 1 || refs[0].Name != "refs/heads/main" {
		t.Errorf("served refs = %+v (err %v): the ghost ref must be dropped", refs, err)
	}
	// The dropped manifest head falls back to the first served branch.
	head, err := os.ReadFile(filepath.Join(hs.gitDir(), "repo", "HEAD"))
	if err != nil || string(head) != "ref: refs/heads/main\n" {
		t.Errorf("HEAD = %q (err %v)", head, err)
	}
	if !fileExists(strings.TrimSuffix(abs, ".pack") + ".idx") {
		t.Error("regenerated idx missing")
	}

	// With no servable ref at all, nothing is published for the mirror.
	repo2 := repo
	repo2.Name = "repo2"
	repo2.Head = ""
	repo2.Refs = []GitRef{{Name: "refs/heads/ghost", SHA1: strings.Repeat("9", 40)}}
	rel2 := gitPackRel("repo2", f.trailer())
	abs2 := filepath.Join(hs.downloadDir, filepath.FromSlash(rel2))
	if err := os.MkdirAll(filepath.Dir(abs2), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs2, f.pack, 0o644); err != nil {
		t.Fatal(err)
	}
	repo2.PackPath = rel2
	if err := hs.publishGit(&GitManifest{Repos: []GitRepoMirror{repo2}}); err != nil {
		t.Fatalf("publishGit (all refs missing) should log and skip, got %v", err)
	}
	if fileExists(filepath.Join(hs.gitDir(), "repo2", "info", "refs")) {
		t.Error("a mirror with no servable refs must not be published")
	}

	// A pack stored under a name that is not its trailer is refused.
	repo3 := repo
	repo3.Name = "repo3"
	wrong := gitPackRel("repo3", strings.Repeat("a", 40))
	abs3 := filepath.Join(hs.downloadDir, filepath.FromSlash(wrong))
	if err := os.MkdirAll(filepath.Dir(abs3), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs3, f.pack, 0o644); err != nil {
		t.Fatal(err)
	}
	repo3.PackPath = wrong
	repo3.Head = ""
	if err := hs.publishGit(&GitManifest{Repos: []GitRepoMirror{repo3}}); err != nil {
		t.Fatalf("publishGit: %v", err)
	}
	if fileExists(filepath.Join(hs.gitDir(), "repo3", "info", "refs")) {
		t.Error("a mis-named pack must not be published")
	}
}

// -----------------------------------------------------------------------------
// Integration: dashboard tree/detail
// -----------------------------------------------------------------------------

func TestGitTreeAndDetail(t *testing.T) {
	hs, f := gitTestPublishedHigh(t)

	mods, err := hs.listGitRepos()
	if err != nil || len(mods) != 1 || mods[0].Module != "fix" {
		t.Fatalf("listGitRepos = %+v, %v", mods, err)
	}
	if got := strings.Join(mods[0].Versions, " "); got != "main blobtag v1" {
		t.Errorf("versions = %q (short ref names, info/refs order)", got)
	}

	d, err := hs.gitDetail("fix@main")
	if err != nil {
		t.Fatalf("gitDetail: %v", err)
	}
	if d.Title != "fix" || d.Subtitle != "main" {
		t.Errorf("detail title/subtitle = %q/%q", d.Title, d.Subtitle)
	}
	fields := map[string]string{}
	for _, fd := range d.Fields {
		fields[fd.Label] = fd.Value
	}
	packBase := "pack-" + f.trailer()
	if fields["Commit"] != f.commitSHA() || fields["Ref"] != "refs/heads/main" ||
		fields["Repository"] != "/git/fix.git" || !strings.Contains(fields["Clone"], "/git/fix.git") {
		t.Errorf("detail fields = %+v", fields)
	}
	if fields["Pack SHA-256"] != gitTestSHA256(f.pack) || fields["Pack size"] == "" {
		t.Errorf("pack fields = %+v", fields)
	}
	if len(d.Downloads) != 1 || d.Downloads[0].URL != "/git/fix/objects/pack/"+packBase+".pack" {
		t.Errorf("downloads = %+v", d.Downloads)
	}

	// Full ref names resolve too; the tag maps to the delta-resolved blob.
	d2, err := hs.gitDetail("fix@refs/tags/blobtag")
	if err != nil || d2.Subtitle != "blobtag" {
		t.Fatalf("full-name detail = %+v, %v", d2, err)
	}
	for _, spec := range []string{"fix@nope", "nope@main", "fix", "..@main"} {
		if _, err := hs.gitDetail(spec); err == nil {
			t.Errorf("detail %q should fail", spec)
		}
	}
}
