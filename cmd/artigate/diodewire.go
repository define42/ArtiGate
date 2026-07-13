package main

// Built-in UDP data-diode transport ("pitcher" → "catcher"): wire format and
// receive-side reassembly.
//
// A hardware data diode is a one-way fiber: the low side's pitcher can send
// but never hear the high side's catcher — no ARP/NDP (the peer's MAC is
// unresolvable), no ACKs, no retransmission requests. The transport is built
// around that:
//
//   - Datagrams go to an IPv6 link-local multicast group, which maps straight
//     to an Ethernet group MAC, so nothing ever needs neighbor resolution.
//   - Loss is repaired forward (FEC): every block of dataShards×shardSize
//     file bytes is Reed-Solomon-encoded into dataShards+parityShards equal
//     shards, one shard per datagram; ANY dataShards of them rebuild the
//     block, so up to parityShards datagrams per block may vanish.
//   - Every datagram carries the file's full metadata plus a CRC-32, so the
//     catcher can begin from any packet, drop corruption before it poisons a
//     block, and verify the finished file's SHA-256 before it lands.
//
// Files land atomically in the landing directory under their wire-carried
// (strictly validated) bundle file name. Trust is unchanged from the folder
// and HTTP transports: the importer still verifies the Ed25519 manifest
// signature, per-stream sequencing, and every file hash — the wire CRC/SHA
// only keep transport damage out. Loss beyond the parity budget expires the
// transfer; the remedy is the same as for a lost folder-diode bundle:
// /admin/missing on the high side, re-export on the low side. The expired
// transfer's completed blocks are not thrown away, though: they persist
// beside the landing directory (persistPartial) and the re-sent file resumes
// from them, so each retry of a large bundle only has to deliver the blocks
// every earlier attempt lost.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	diodeMagic   = 0x41474431 // "AGD1"
	diodeVersion = 1

	// diodeHeaderSize is the fixed per-datagram header. Carrying the full file
	// metadata in every packet costs ~2.5% of a jumbo frame and buys the
	// catcher statelessness: any packet can open, continue, or finish a
	// transfer.
	diodeHeaderSize = 224
	diodeNameMax    = 128
	diodeCRCOffset  = 220

	// diodeIPUDPOverhead is what the IPv6 and UDP headers take out of the
	// interface MTU when sizing shards so a datagram never fragments.
	diodeIPUDPOverhead = 40 + 8

	// Receive-side hygiene bounds. The fiber is one-way from the low side,
	// but the catcher still refuses to let malformed traffic grow state
	// without limit.
	diodeMaxShardSize   = 60000
	diodeMaxTotalShards = 256 // GF(2^8) Reed-Solomon limit
	// diodeMaxBlockCount must cover a maximum-size archive
	// (diodeMaxArchiveBytes) even at the smallest practical block geometry
	// (small MTU, few data shards): 2^22 blocks reach 64 GiB from 16 KiB
	// blocks up, and cost at most a 512 KiB done-bitset per transfer.
	diodeMaxBlockCount = 1 << 22
	diodeMaxTransfers  = 16
	diodeMaxOpenBlocks = 32

	// Memory and cache budgets apply across all unauthenticated UDP transfers.
	// A block reserves its complete reconstruction geometry up front, including
	// missing shards Reed-Solomon may allocate later.
	diodeMaxBufferedBytes         int64 = 256 << 20
	diodeMaxTransferBufferedBytes int64 = 64 << 20
	diodeMaxRememberedTransfers         = 4096
	diodeMaxEncoders                    = 64

	// diodeStaleAfter is how long a partial transfer may go without a packet
	// before the catcher gives up on it; diodeDoneRemember is how long a
	// finished transfer's ID is remembered so its parity stragglers (packets
	// still in flight when the file completed) don't open a ghost transfer.
	diodeStaleAfter   = 90 * time.Second
	diodeDoneRemember = 10 * time.Minute

	// diodePartialRetention is how long an expired transfer's persisted
	// partial (its completed blocks plus resume state) waits for a re-send of
	// the same file before being reclaimed. Persisted partials count against
	// the unverified storage quota, so an abandoned one must not hold it
	// forever. diodeMaxPartialStateBytes bounds the resume-state sidecar read
	// (a 2^22-block bitset is ~700 KiB base64-encoded).
	diodePartialRetention           = 24 * time.Hour
	diodeMaxPartialStateBytes int64 = 4 << 20
)

// udpPartialSuffix and udpPartialStateSuffix name a persisted partial
// transfer's data and resume-state files in the landing directory. They stay
// inside the ".udp-" temp namespace (so nothing mistakes them for bundle
// files) but are distinguishable from in-progress reassembly temps, whose
// bytes the assembler accounts for as active instead of stored.
const (
	udpPartialSuffix      = ".udp-part"
	udpPartialStateSuffix = ".udp-part.json"
)

func udpPartialPath(dir, name string) string {
	return filepath.Join(dir, name+udpPartialSuffix)
}

func udpPartialStatePath(dir, name string) string {
	return filepath.Join(dir, name+udpPartialStateSuffix)
}

// diodePacket is one decoded datagram: one Reed-Solomon shard of one block of
// one file transfer, plus the transfer's full metadata.
type diodePacket struct {
	TransferID   [16]byte
	SHA256       [32]byte
	Name         string
	FileSize     int64
	BlockCount   uint32
	BlockIndex   uint32
	BlockOffset  int64
	BlockLen     int
	ShardSize    int
	DataShards   int
	ParityShards int
	ShardIndex   int
	Shard        []byte
}

// marshalDiodePacket serializes p into dst (reallocating only if dst is too
// small) and returns the packet bytes. Layout (big-endian):
//
//	0   magic    4   | 4  version 1 | 5  nameLen 1
//	6   dataShards 2 | 8  parityShards 2 | 10 shardIndex 2
//	12  blockIndex 4 | 16 blockCount 4 | 20 shardSize 4 | 24 blockLen 4
//	28  blockOffset 8 | 36 fileSize 8
//	44  transferID 16 | 60 sha256 32 | 92 name 128
//	220 crc32 4 | 224 shard payload
func marshalDiodePacket(dst []byte, p *diodePacket) ([]byte, error) {
	if p.Name == "" || len(p.Name) > diodeNameMax {
		return nil, fmt.Errorf("file name %q does not fit the diode header", p.Name)
	}
	n := diodeHeaderSize + len(p.Shard)
	if cap(dst) < n {
		dst = make([]byte, n)
	}
	b := dst[:n]
	clear(b[:diodeHeaderSize]) // zero padding (name tail) between packets
	binary.BigEndian.PutUint32(b[0:], diodeMagic)
	b[4] = diodeVersion
	b[5] = byte(len(p.Name))
	binary.BigEndian.PutUint16(b[6:], uint16(p.DataShards))
	binary.BigEndian.PutUint16(b[8:], uint16(p.ParityShards))
	binary.BigEndian.PutUint16(b[10:], uint16(p.ShardIndex))
	binary.BigEndian.PutUint32(b[12:], p.BlockIndex)
	binary.BigEndian.PutUint32(b[16:], p.BlockCount)
	binary.BigEndian.PutUint32(b[20:], uint32(p.ShardSize))
	binary.BigEndian.PutUint32(b[24:], uint32(p.BlockLen))
	binary.BigEndian.PutUint64(b[28:], uint64(p.BlockOffset))
	binary.BigEndian.PutUint64(b[36:], uint64(p.FileSize))
	copy(b[44:60], p.TransferID[:])
	copy(b[60:92], p.SHA256[:])
	copy(b[92:], p.Name)
	copy(b[diodeHeaderSize:], p.Shard)
	binary.BigEndian.PutUint32(b[diodeCRCOffset:], diodePacketCRC(b))
	return b, nil
}

// diodePacketCRC covers the whole datagram except the CRC field itself. UDP's
// 16-bit checksum is too weak to trust a shard with: one corrupt shard fed to
// the Reed-Solomon decoder silently corrupts the whole block.
func diodePacketCRC(b []byte) uint32 {
	crc := crc32.Checksum(b[:diodeCRCOffset], crc32.IEEETable)
	return crc32.Update(crc, crc32.IEEETable, b[diodeHeaderSize:])
}

// parseDiodePacket decodes and validates one datagram. The returned Shard
// aliases b — callers that keep it must copy (the read loop reuses its
// buffer).
func parseDiodePacket(b []byte) (diodePacket, error) {
	if len(b) < diodeHeaderSize+1 {
		return diodePacket{}, fmt.Errorf("datagram too short (%d bytes)", len(b))
	}
	if binary.BigEndian.Uint32(b[0:]) != diodeMagic {
		return diodePacket{}, errors.New("not a diode datagram (bad magic)")
	}
	if b[4] != diodeVersion {
		return diodePacket{}, fmt.Errorf("unsupported diode wire version %d", b[4])
	}
	if binary.BigEndian.Uint32(b[diodeCRCOffset:]) != diodePacketCRC(b) {
		return diodePacket{}, errors.New("checksum mismatch")
	}
	nameLen := int(b[5])
	if nameLen < 1 || nameLen > diodeNameMax {
		return diodePacket{}, fmt.Errorf("name length %d out of range", nameLen)
	}
	p := diodePacket{
		Name:         string(b[92 : 92+nameLen]),
		FileSize:     int64(binary.BigEndian.Uint64(b[36:])),
		BlockCount:   binary.BigEndian.Uint32(b[16:]),
		BlockIndex:   binary.BigEndian.Uint32(b[12:]),
		BlockOffset:  int64(binary.BigEndian.Uint64(b[28:])),
		BlockLen:     int(binary.BigEndian.Uint32(b[24:])),
		ShardSize:    int(binary.BigEndian.Uint32(b[20:])),
		DataShards:   int(binary.BigEndian.Uint16(b[6:])),
		ParityShards: int(binary.BigEndian.Uint16(b[8:])),
		ShardIndex:   int(binary.BigEndian.Uint16(b[10:])),
		Shard:        b[diodeHeaderSize:],
	}
	copy(p.TransferID[:], b[44:60])
	copy(p.SHA256[:], b[60:92])
	return p, p.validate()
}

// validate applies the wire-level sanity bounds. Anything violating them is a
// corrupt or hostile datagram and is dropped before it can touch state.
func (p *diodePacket) validate() error {
	if err := p.validateShards(); err != nil {
		return err
	}
	switch {
	case p.BlockCount < 1 || p.BlockCount > diodeMaxBlockCount || p.BlockIndex >= p.BlockCount:
		return fmt.Errorf("bad block index %d/%d", p.BlockIndex, p.BlockCount)
	case p.FileSize < 1 || int64(p.BlockCount) > p.FileSize:
		return fmt.Errorf("bad file size %d for %d block(s)", p.FileSize, p.BlockCount)
	case p.BlockLen < 1 || p.BlockLen > p.DataShards*p.ShardSize:
		return fmt.Errorf("bad block length %d", p.BlockLen)
	case p.BlockOffset < 0 || p.BlockOffset > p.FileSize-int64(p.BlockLen):
		return fmt.Errorf("block at %d with length %d outside file of %d bytes", p.BlockOffset, p.BlockLen, p.FileSize)
	}
	return nil
}

func (p *diodePacket) validateShards() error {
	switch {
	case p.DataShards < 1 || p.ParityShards < 1 || p.DataShards+p.ParityShards > diodeMaxTotalShards:
		return fmt.Errorf("bad shard geometry %d+%d", p.DataShards, p.ParityShards)
	case p.ShardSize < 1 || p.ShardSize > diodeMaxShardSize || len(p.Shard) != p.ShardSize:
		return fmt.Errorf("bad shard size %d (payload %d)", p.ShardSize, len(p.Shard))
	case p.ShardIndex >= p.DataShards+p.ParityShards:
		return fmt.Errorf("shard index %d outside %d+%d", p.ShardIndex, p.DataShards, p.ParityShards)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Send side: cutting a file into FEC-coded datagrams
// -----------------------------------------------------------------------------

// diodeFileMeta describes one file crossing the diode. Every datagram carries
// all of it.
type diodeFileMeta struct {
	TransferID [16]byte
	SHA256     [32]byte
	Name       string
	FileSize   int64
}

func newDiodeTransferID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}

// diodePlan fixes how files are cut into Reed-Solomon blocks: dataShards data
// datagrams plus parityShards repair datagrams per block, each carrying
// shardSize file bytes (sized to the MTU so nothing fragments).
type diodePlan struct {
	dataShards   int
	parityShards int
	shardSize    int
}

func newDiodePlan(mtu, dataShards, parityShards int) (diodePlan, error) {
	if dataShards < 1 || parityShards < 1 || dataShards+parityShards > diodeMaxTotalShards {
		return diodePlan{}, fmt.Errorf("FEC geometry %d data + %d parity shards is invalid (each ≥ 1, sum ≤ %d)",
			dataShards, parityShards, diodeMaxTotalShards)
	}
	shardSize := mtu - diodeIPUDPOverhead - diodeHeaderSize
	if shardSize < 128 {
		return diodePlan{}, fmt.Errorf("MTU %d leaves no room for a shard (need ≥ %d)", mtu, diodeIPUDPOverhead+diodeHeaderSize+128)
	}
	shardSize = min(shardSize, diodeMaxShardSize)
	return diodePlan{dataShards: dataShards, parityShards: parityShards, shardSize: shardSize}, nil
}

func (pl diodePlan) totalShards() int   { return pl.dataShards + pl.parityShards }
func (pl diodePlan) blockDataSize() int { return pl.dataShards * pl.shardSize }

// packetCount reports how many datagrams a file of the given size becomes.
func (pl diodePlan) packetCount(fileSize int64) int64 {
	bds := int64(pl.blockDataSize())
	blocks := max((fileSize+bds-1)/bds, 1)
	return blocks * int64(pl.totalShards())
}

// sendDiodeFile reads fileSize bytes from r and emits one marshalled datagram
// per shard. The packet buffer is reused between emit calls — emit must not
// retain it (a socket write copies to the kernel, which is the point).
func sendDiodeFile(r io.Reader, meta diodeFileMeta, pl diodePlan, enc reedsolomon.Encoder, emit func([]byte) error) error {
	if meta.FileSize < 1 {
		return fmt.Errorf("%s is empty", meta.Name)
	}
	bds := int64(pl.blockDataSize())
	blockCount := (meta.FileSize + bds - 1) / bds
	// The catcher drops every packet of a transfer beyond its block-count
	// bound, so sending one would stream the whole file into a black hole —
	// fail it here instead, with the knob that fixes it.
	if blockCount > diodeMaxBlockCount {
		return fmt.Errorf("%s needs %d FEC blocks of %s, above the wire limit of %d — raise ARTIGATE_PITCHER_MTU or ARTIGATE_PITCHER_FEC_DATA so each block carries more",
			meta.Name, blockCount, formatBytes(bds), diodeMaxBlockCount)
	}
	pkt := diodePacket{
		TransferID:   meta.TransferID,
		SHA256:       meta.SHA256,
		Name:         meta.Name,
		FileSize:     meta.FileSize,
		BlockCount:   uint32(blockCount),
		DataShards:   pl.dataShards,
		ParityShards: pl.parityShards,
	}
	buf := make([]byte, pl.blockDataSize())
	out := make([]byte, diodeHeaderSize+pl.shardSize)
	var offset int64
	for bi := range pkt.BlockCount {
		blockLen := int(min(bds, meta.FileSize-offset))
		if _, err := io.ReadFull(r, buf[:blockLen]); err != nil {
			return fmt.Errorf("read %s: %w", meta.Name, err)
		}
		shards, shardSize := splitDiodeBlock(buf[:blockLen], pl)
		if err := enc.Encode(shards); err != nil {
			return fmt.Errorf("encode parity: %w", err)
		}
		pkt.BlockIndex, pkt.BlockOffset, pkt.BlockLen, pkt.ShardSize = bi, offset, blockLen, shardSize
		for si, shard := range shards {
			pkt.ShardIndex, pkt.Shard = si, shard
			b, err := marshalDiodePacket(out, &pkt)
			if err != nil {
				return err
			}
			if err := emit(b); err != nil {
				return err
			}
		}
		offset += int64(blockLen)
	}
	return nil
}

// splitDiodeBlock cuts one block's data into equal-size zero-padded data
// shards and appends zeroed parity shards for the encoder to fill. A short
// (last, or only) block shrinks the shard size so small files — a bundle's
// manifest and signature — don't ship a block of padding.
func splitDiodeBlock(data []byte, pl diodePlan) (shards [][]byte, shardSize int) {
	shardSize = max((len(data)+pl.dataShards-1)/pl.dataShards, 1)
	backing := make([]byte, pl.totalShards()*shardSize)
	shards = make([][]byte, pl.totalShards())
	for i := range shards {
		shards[i] = backing[i*shardSize : (i+1)*shardSize]
	}
	for i := 0; i < pl.dataShards && len(data) > 0; i++ {
		data = data[copy(shards[i], data):]
	}
	return shards, shardSize
}

// -----------------------------------------------------------------------------
// Receive side: reassembling files from datagrams
// -----------------------------------------------------------------------------

// diodeAssembler rebuilds files from diode datagrams and lands them atomically
// in dir. It is driven by a single goroutine (the catcher's read loop) and is
// deliberately unlocked.
type diodeAssembler struct {
	dir        string
	validName  func(string) bool
	onComplete func(name string)
	// measureStored, when set, returns the bytes of already-landed unverified
	// transport data that must count against the quota (landing + quarantine +
	// rejected, excluding this assembler's in-progress temp files). When nil it
	// falls back to measuring only the landing directory. Wired by the catcher
	// so the UDP path shares the HTTP ingest's single quota rather than seeing
	// only what currently sits in landing.
	measureStored func() (int64, error)
	encoders      map[uint32]reedsolomon.Encoder
	active        map[[16]byte]*diodeTransfer
	done          map[[16]byte]time.Time
	doneOrder     []diodeDoneRecord
	doneNext      int
	buffered      int64
	activeSize    int64
	stats         diodeCatchStats
	lastLogged    diodeCatchStats
}

type diodeDoneRecord struct {
	id [16]byte
	at time.Time
}

// diodeCatchStats are the catcher's operational counters, logged periodically.
type diodeCatchStats struct {
	packets      int64
	bytes        int64
	dropped      int64
	repairs      int64 // blocks that needed Reed-Solomon reconstruction
	evictions    int64 // open blocks given up on to keep a lossy transfer moving
	filesLanded  int64
	filesExpired int64
	filesFailed  int64
	filesResumed int64 // transfers that adopted a persisted partial
}

type diodeTransfer struct {
	id         [16]byte
	name       string
	fileSize   int64
	sha        [32]byte
	blockCount uint32
	tmp        *os.File
	blocks     map[uint32]*diodeBlock
	blocksDone []uint64 // bitset, blockCount bits
	doneCount  uint32
	written    int64 // sum of landed block lengths; must equal fileSize
	started    time.Time
	lastSeen   time.Time
	buffered   int64
}

type diodeBlock struct {
	dataShards   int
	parityShards int
	shardSize    int
	blockLen     int
	offset       int64
	shards       [][]byte
	have         int
	reserved     int64
}

func newDiodeAssembler(dir string, validName func(string) bool, onComplete func(string)) *diodeAssembler {
	return &diodeAssembler{
		dir:        dir,
		validName:  validName,
		onComplete: onComplete,
		encoders:   map[uint32]reedsolomon.Encoder{},
		active:     map[[16]byte]*diodeTransfer{},
		done:       map[[16]byte]time.Time{},
	}
}

// storedUnverifiedBytes reports the already-landed unverified transport bytes
// that count against the quota. It prefers measureStored (the shared landing +
// quarantine + rejected total) so a bundle swept out of landing into quarantine
// or rejected still counts; without it, it measures the landing directory alone
// (used by unit tests that construct an assembler directly). Persisted
// partials count either way — only in-progress reassembly temps are excluded,
// being accounted for as active transfers.
func (a *diodeAssembler) storedUnverifiedBytes() (int64, error) {
	if a.measureStored != nil {
		return a.measureStored()
	}
	return directoryRegularFileBytesExcept(a.dir, isUDPActiveTempName)
}

// handleDatagram feeds one received datagram through parse → transfer → block
// → (reconstruct) → write, landing the file when its last block completes.
func (a *diodeAssembler) handleDatagram(b []byte, now time.Time) {
	a.stats.packets++
	a.stats.bytes += int64(len(b))
	p, err := parseDiodePacket(b)
	if err != nil {
		a.drop(err.Error())
		return
	}
	if _, ok := a.done[p.TransferID]; ok {
		return // parity straggler of a file that already completed — expected
	}
	t, err := a.transferFor(&p, now)
	if err != nil {
		a.drop(err.Error())
		return
	}
	t.lastSeen = now
	if t.blockDone(p.BlockIndex) {
		return
	}
	blk, err := a.blockFor(t, &p)
	if err != nil {
		a.drop(err.Error())
		return
	}
	if !blk.addShard(&p) || blk.have < blk.dataShards {
		return
	}
	if err := a.completeBlock(t, p.BlockIndex, blk); err != nil {
		a.failTransfer(t, now, err)
		return
	}
	if t.doneCount == t.blockCount {
		a.finishTransfer(t, now)
	}
}

// drop counts a rejected datagram and logs the first few (then every 1024th)
// so a persistent problem is visible without flooding the log.
func (a *diodeAssembler) drop(reason string) {
	a.stats.dropped++
	if a.stats.dropped <= 3 || a.stats.dropped%1024 == 0 {
		log.Printf("diode catch: dropped datagram: %s (%d dropped so far)", reason, a.stats.dropped)
	}
}

// transferFor finds or opens the transfer a packet belongs to. A new transfer
// is only opened for a strictly valid bundle file name — the wire can never
// plant an arbitrary file in the landing directory (mirroring the HTTP
// ingest's rule). When a persisted partial of the same content exists (an
// earlier attempt at this file that expired mid-way), the new transfer adopts
// it and resumes instead of starting over.
func (a *diodeAssembler) transferFor(p *diodePacket, now time.Time) (*diodeTransfer, error) {
	if t, ok := a.active[p.TransferID]; ok {
		if t.name != p.Name || t.fileSize != p.FileSize || t.blockCount != p.BlockCount || t.sha != p.SHA256 {
			return nil, errors.New("metadata mismatch within a transfer")
		}
		return t, nil
	}
	resume := a.probePartial(p)
	if err := a.admitNewTransfer(p, resume); err != nil {
		return nil, err
	}
	t, err := a.openTransfer(p, resume, now)
	if err != nil {
		return nil, err
	}
	a.active[p.TransferID] = t
	a.activeSize += t.fileSize
	if t.doneCount > 0 {
		a.stats.filesResumed++
		log.Printf("diode catch: resuming %s (%s, %d/%d block(s) already held)", t.name, formatBytes(t.fileSize), t.doneCount, t.blockCount)
	} else {
		log.Printf("diode catch: receiving %s (%s, %d block(s))", t.name, formatBytes(t.fileSize), t.blockCount)
	}
	return t, nil
}

// admitNewTransfer applies the hygiene gates for opening a transfer: name
// validity, the per-file size limit, the transfer-count cap, and the shared
// unverified storage quota. A partial about to be adopted is credited against
// the quota — its bytes move from stored to active rather than counting
// twice.
func (a *diodeAssembler) admitNewTransfer(p *diodePacket, resume *diodeResume) error {
	if !a.validName(p.Name) {
		return fmt.Errorf("not a bundle file name: %q", p.Name)
	}
	fileLimit, ok := bundleFileSizeLimit(p.Name)
	if !ok || p.FileSize > fileLimit {
		return fmt.Errorf("%s is %d bytes; transport limit is %d", p.Name, p.FileSize, fileLimit)
	}
	if len(a.active) >= diodeMaxTransfers {
		return fmt.Errorf("more than %d transfers in flight", diodeMaxTransfers)
	}
	stored, err := a.storedUnverifiedBytes()
	if err != nil {
		return fmt.Errorf("measure landing quota: %w", err)
	}
	if resume != nil {
		stored = max(stored-resume.diskSize, 0)
	}
	if stored > diodeMaxUnverifiedBytes-a.activeSize || p.FileSize > diodeMaxUnverifiedBytes-stored-a.activeSize {
		return fmt.Errorf("unverified transport quota of %d bytes would be exceeded", diodeMaxUnverifiedBytes)
	}
	return nil
}

// openTransfer creates the transfer's reassembly temp file — adopting the
// probed partial's bytes and progress when possible — and its tracking state.
func (a *diodeAssembler) openTransfer(p *diodePacket, resume *diodeResume, now time.Time) (*diodeTransfer, error) {
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		return nil, err
	}
	tmp, adopted, err := a.openTransferFile(p.Name, resume)
	if err != nil {
		return nil, err
	}
	t := &diodeTransfer{
		id:         p.TransferID,
		name:       p.Name,
		fileSize:   p.FileSize,
		sha:        p.SHA256,
		blockCount: p.BlockCount,
		tmp:        tmp,
		blocks:     map[uint32]*diodeBlock{},
		blocksDone: make([]uint64, (p.BlockCount+63)/64),
		started:    now,
	}
	if adopted {
		t.blocksDone, t.doneCount, t.written = resume.bits, resume.done, resume.written
	}
	return t, nil
}

// openTransferFile returns the file the transfer reassembles into: the
// adopted partial, moved to a fresh temp name, or a new empty temp. Adoption
// failures fall back to a fresh start — the partial stays where it is for its
// retention reaping.
func (a *diodeAssembler) openTransferFile(name string, resume *diodeResume) (*os.File, bool, error) {
	if resume != nil {
		if f, ok := a.adoptPartialFile(name); ok {
			return f, true, nil
		}
	}
	tmp, err := os.CreateTemp(a.dir, name+".udp-*")
	if err != nil {
		return nil, false, fmt.Errorf("create landing temp file: %w", err)
	}
	return tmp, false, nil
}

// adoptPartialFile moves a persisted partial under a fresh reassembly temp
// name (so a second transfer of the same file can never collide with it, and
// the quota accounting sees it as active again) and consumes its resume
// state.
func (a *diodeAssembler) adoptPartialFile(name string) (*os.File, bool) {
	tmp, err := os.CreateTemp(a.dir, name+".udp-*")
	if err != nil {
		return nil, false
	}
	tmpName := tmp.Name()
	// The rename below replaces the just-created empty inode, which this
	// handle would keep writing into unseen — close it and reopen the path
	// once the partial's bytes are behind it.
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, false
	}
	if err := os.Rename(udpPartialPath(a.dir, name), tmpName); err != nil {
		_ = os.Remove(tmpName)
		return nil, false
	}
	_ = os.Remove(udpPartialStatePath(a.dir, name))
	f, err := os.OpenFile(tmpName, os.O_RDWR, 0o600)
	if err != nil {
		_ = os.Remove(tmpName)
		return nil, false
	}
	return f, true
}

func (t *diodeTransfer) blockDone(bi uint32) bool {
	return t.blocksDone[bi/64]&(1<<(bi%64)) != 0
}

func (t *diodeTransfer) setBlockDone(bi uint32) {
	t.blocksDone[bi/64] |= 1 << (bi % 64)
	t.doneCount++
}

// blockFor finds or opens the in-progress block a packet belongs to, holding
// every packet of a block to the geometry its first packet declared. New
// blocks reserve their full reconstruction footprint before retaining data.
func (a *diodeAssembler) blockFor(t *diodeTransfer, p *diodePacket) (*diodeBlock, error) {
	if blk, ok := t.blocks[p.BlockIndex]; ok {
		if blk.dataShards != p.DataShards || blk.parityShards != p.ParityShards ||
			blk.shardSize != p.ShardSize || blk.blockLen != p.BlockLen || blk.offset != p.BlockOffset {
			return nil, errors.New("shard geometry mismatch within a block")
		}
		return blk, nil
	}
	if len(t.blocks) >= diodeMaxOpenBlocks && !a.evictOpenBlock(t, p.BlockIndex) {
		return nil, fmt.Errorf("more than %d half-received blocks in %s", diodeMaxOpenBlocks, t.name)
	}
	reserved := int64(p.DataShards+p.ParityShards) * int64(p.ShardSize)
	if reserved > diodeMaxTransferBufferedBytes-t.buffered {
		return nil, fmt.Errorf("transfer %s exceeds the %d-byte reassembly budget", t.name, diodeMaxTransferBufferedBytes)
	}
	if reserved > diodeMaxBufferedBytes-a.buffered {
		return nil, fmt.Errorf("UDP reassembly exceeds the %d-byte global budget", diodeMaxBufferedBytes)
	}
	blk := &diodeBlock{
		dataShards:   p.DataShards,
		parityShards: p.ParityShards,
		shardSize:    p.ShardSize,
		blockLen:     p.BlockLen,
		offset:       p.BlockOffset,
		shards:       make([][]byte, p.DataShards+p.ParityShards),
		reserved:     reserved,
	}
	t.blocks[p.BlockIndex] = blk
	t.buffered += reserved
	a.buffered += reserved
	return blk, nil
}

// evictOpenBlock frees the open block least likely to ever complete — the
// lowest-index one, since the pitcher sends blocks in order, so its missing
// shards are almost certainly lost rather than late. Without eviction, a
// transfer on a link losing more than the parity budget stalls once
// diodeMaxOpenBlocks dead blocks accumulate and every later packet is
// dropped; with it, all still-recoverable blocks keep completing and only the
// truly lost ones wait for the next re-send (blocksDone tracks completion, so
// correctness never rests on this heuristic). It refuses only when the new
// block is older than everything open — then the newcomer is the least likely
// to complete.
func (a *diodeAssembler) evictOpenBlock(t *diodeTransfer, newIndex uint32) bool {
	var oldest uint32
	found := false
	for bi := range t.blocks {
		if !found || bi < oldest {
			oldest, found = bi, true
		}
	}
	if !found || newIndex <= oldest {
		return false
	}
	blk := t.blocks[oldest]
	delete(t.blocks, oldest)
	a.releaseBlock(t, blk)
	a.stats.evictions++
	return true
}

// addShard stores a shard copy (the read buffer is reused) and reports whether
// it was new.
func (b *diodeBlock) addShard(p *diodePacket) bool {
	if b.shards[p.ShardIndex] != nil {
		return false
	}
	b.shards[p.ShardIndex] = append([]byte(nil), p.Shard...)
	b.have++
	return true
}

// completeBlock reconstructs missing data shards if needed and writes the
// block's bytes to their offset in the temp file, then frees the block.
func (a *diodeAssembler) completeBlock(t *diodeTransfer, bi uint32, blk *diodeBlock) error {
	if err := a.reconstruct(blk); err != nil {
		return fmt.Errorf("reconstruct block %d of %s: %w", bi, t.name, err)
	}
	remaining, off := blk.blockLen, blk.offset
	for i := 0; i < blk.dataShards && remaining > 0; i++ {
		n := min(blk.shardSize, remaining)
		if _, err := t.tmp.WriteAt(blk.shards[i][:n], off); err != nil {
			return fmt.Errorf("write block %d of %s: %w", bi, t.name, err)
		}
		off += int64(n)
		remaining -= n
	}
	delete(t.blocks, bi)
	a.releaseBlock(t, blk)
	t.setBlockDone(bi)
	t.written += int64(blk.blockLen)
	return nil
}

func (a *diodeAssembler) releaseBlock(t *diodeTransfer, blk *diodeBlock) {
	if blk.reserved == 0 {
		return
	}
	t.buffered -= blk.reserved
	a.buffered -= blk.reserved
	blk.reserved = 0
}

// reconstruct fills in missing data shards from parity. With all data shards
// present it is free — parity is only decoded when packets were actually lost.
func (a *diodeAssembler) reconstruct(blk *diodeBlock) error {
	complete := true
	for _, s := range blk.shards[:blk.dataShards] {
		if s == nil {
			complete = false
			break
		}
	}
	if complete {
		return nil
	}
	enc, err := a.encoder(blk.dataShards, blk.parityShards)
	if err != nil {
		return err
	}
	if err := enc.ReconstructData(blk.shards); err != nil {
		return err
	}
	a.stats.repairs++
	return nil
}

func (a *diodeAssembler) encoder(dataShards, parityShards int) (reedsolomon.Encoder, error) {
	key := uint32(dataShards)<<16 | uint32(parityShards)
	if enc, ok := a.encoders[key]; ok {
		return enc, nil
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	if len(a.encoders) < diodeMaxEncoders {
		a.encoders[key] = enc
	}
	return enc, nil
}

// -----------------------------------------------------------------------------
// Partial-transfer persistence: per-block recovery across re-sends
// -----------------------------------------------------------------------------

// diodePartialState is the resume-state sidecar kept beside a persisted
// partial transfer: which blocks of the reassembled file are already valid on
// disk. A later re-send of the same file (a re-export replays the exact
// signed bytes, so name, size, and SHA-256 all match) adopts the partial and
// only needs the blocks every earlier attempt lost — recovery is per block,
// not per transfer, which is what makes multi-gigabyte bundles converge on a
// lossy link instead of demanding one perfect pass. The state is advisory:
// a wrong or stale bitset can only produce a file that fails the final
// SHA-256 gate, exactly like transport damage.
type diodePartialState struct {
	Name       string `json:"name"`
	FileSize   int64  `json:"file_size"`
	SHA256     string `json:"sha256"`
	BlockCount uint32 `json:"block_count"`
	Written    int64  `json:"written"`
	DoneCount  uint32 `json:"done_count"`
	BlocksDone string `json:"blocks_done"` // base64 of the little-endian done-block bitset
}

// diodeResume carries a probed partial's progress into the transfer adopting
// it.
type diodeResume struct {
	bits     []uint64
	done     uint32
	written  int64
	diskSize int64
}

// probePartial reads and validates the persisted resume state for p's file,
// returning its progress when — and only when — it describes exactly this
// content: same name, size, block count, and SHA-256. Anything else (no
// partial, unreadable or inconsistent state, mismatched content) yields nil
// and a fresh start. A mismatched partial is left in place for its retention
// reaping rather than deleted: a hostile datagram must never be able to
// destroy real accumulated progress.
func (a *diodeAssembler) probePartial(p *diodePacket) *diodeResume {
	st, ok := loadPartialState(udpPartialStatePath(a.dir, p.Name))
	if !ok || st.Name != p.Name || st.FileSize != p.FileSize || st.BlockCount != p.BlockCount ||
		st.SHA256 != hex.EncodeToString(p.SHA256[:]) {
		return nil
	}
	bits, done, err := decodeBlockBitset(st.BlocksDone, st.BlockCount)
	if err != nil || done != st.DoneCount || done == 0 || done >= st.BlockCount {
		return nil
	}
	if st.Written < 1 || st.Written > st.FileSize {
		return nil
	}
	info, err := os.Stat(udpPartialPath(a.dir, p.Name))
	if err != nil || !info.Mode().IsRegular() || info.Size() > p.FileSize {
		return nil
	}
	return &diodeResume{bits: bits, done: done, written: st.Written, diskSize: info.Size()}
}

func loadPartialState(path string) (diodePartialState, bool) {
	var st diodePartialState
	b, err := readFileLimit(path, diodeMaxPartialStateBytes)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return diodePartialState{}, false
	}
	return st, true
}

// persistPartial keeps an expired transfer's completed blocks for a later
// resume: the reassembly temp is renamed to the file's partial name and the
// resume-state sidecar records which blocks it holds. It reports whether the
// partial was kept; anything not kept is the caller's to remove.
func (a *diodeAssembler) persistPartial(t *diodeTransfer) bool {
	if t.tmp == nil || t.doneCount == 0 || t.doneCount >= t.blockCount || a.betterPartialExists(t) {
		return false
	}
	tmpPath := t.tmp.Name()
	if firstErr(t.tmp.Sync(), t.tmp.Close()) != nil {
		_ = os.Remove(tmpPath)
		t.tmp = nil
		return false
	}
	t.tmp = nil
	state := diodePartialState{
		Name: t.name, FileSize: t.fileSize, SHA256: hex.EncodeToString(t.sha[:]),
		BlockCount: t.blockCount, Written: t.written, DoneCount: t.doneCount,
		BlocksDone: encodeBlockBitset(t.blocksDone),
	}
	// State first, then data: a crash between the two leaves a state file
	// whose partial is missing (probe fails cleanly), never a partial with
	// stale state describing other bytes. A failure discards both halves —
	// a partial without state is unreachable and would only pin quota.
	if err := writeJSONAtomic(udpPartialStatePath(a.dir, t.name), state, 0o644); err != nil {
		removePartial(a.dir, t.name)
		_ = os.Remove(tmpPath)
		return false
	}
	if err := os.Rename(tmpPath, udpPartialPath(a.dir, t.name)); err != nil {
		removePartial(a.dir, t.name)
		_ = os.Remove(tmpPath)
		return false
	}
	return true
}

// betterPartialExists reports whether an already-persisted partial for the
// same content holds at least as many blocks, in which case the expiring
// transfer's copy is dropped in its favor. State whose data file is missing
// (a crash between the two writes) never counts.
func (a *diodeAssembler) betterPartialExists(t *diodeTransfer) bool {
	st, ok := loadPartialState(udpPartialStatePath(a.dir, t.name))
	if !ok || st.Name != t.name || st.FileSize != t.fileSize || st.BlockCount != t.blockCount ||
		st.SHA256 != hex.EncodeToString(t.sha[:]) || st.DoneCount < t.doneCount {
		return false
	}
	_, err := os.Stat(udpPartialPath(a.dir, t.name))
	return err == nil
}

// removePartial drops a file's persisted partial and resume state, if any.
func removePartial(dir, name string) {
	_ = os.Remove(udpPartialPath(dir, name))
	_ = os.Remove(udpPartialStatePath(dir, name))
}

// reapPartials removes persisted partials whose resume state is older than
// the retention: a partial only helps while the low side still re-sends the
// same bundle, and an abandoned one must not hold the unverified storage
// quota forever.
func (a *diodeAssembler) reapPartials(now time.Time) {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return
	}
	cutoff := now.Add(-diodePartialRetention)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), udpPartialStateSuffix) {
			continue
		}
		if removeIfOlder(filepath.Join(a.dir, e.Name()), cutoff) {
			name := strings.TrimSuffix(e.Name(), udpPartialStateSuffix)
			_ = os.Remove(udpPartialPath(a.dir, name))
			log.Printf("diode catch: dropped resume state for %s after %v without a re-send", name, diodePartialRetention)
		}
	}
}

// encodeBlockBitset serializes the done-block bitset for the resume state.
func encodeBlockBitset(bitset []uint64) string {
	raw := make([]byte, 8*len(bitset))
	for i, w := range bitset {
		binary.LittleEndian.PutUint64(raw[8*i:], w)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// decodeBlockBitset parses a resume-state bitset, enforcing the exact length
// the block count dictates and no bits beyond it, and returns it with its
// population count.
func decodeBlockBitset(enc string, blockCount uint32) ([]uint64, uint32, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, 0, err
	}
	words := int((blockCount + 63) / 64)
	if len(raw) != 8*words {
		return nil, 0, fmt.Errorf("bitset has %d bytes, want %d", len(raw), 8*words)
	}
	bitset := make([]uint64, words)
	var done uint32
	for i := range bitset {
		bitset[i] = binary.LittleEndian.Uint64(raw[8*i:])
		done += uint32(bits.OnesCount64(bitset[i]))
	}
	if tail := blockCount % 64; tail != 0 && bitset[words-1]>>tail != 0 {
		return nil, 0, errors.New("bitset has bits beyond the block count")
	}
	return bitset, done, nil
}

// finishTransfer verifies and lands a fully reassembled file, remembering the
// transfer ID so its still-in-flight parity tail is ignored quietly.
func (a *diodeAssembler) finishTransfer(t *diodeTransfer, now time.Time) {
	a.removeActive(t)
	a.rememberDone(t.id, now)
	if err := a.landFile(t); err != nil {
		a.stats.filesFailed++
		a.removeTemp(t)
		log.Printf("diode catch: %s failed verification: %v — discarded; re-export it from the low side", t.name, err)
		return
	}
	a.stats.filesLanded++
	// Any partial still persisted for this name is from an attempt this
	// landing supersedes — drop it rather than let it hold quota.
	removePartial(a.dir, t.name)
	log.Printf("diode catch: landed %s (%s in %s)", t.name, formatBytes(t.fileSize), now.Sub(t.started).Round(time.Millisecond))
	if a.onComplete != nil {
		a.onComplete(t.name)
	}
}

// landFile checks the reassembled bytes against the wire-carried SHA-256 and
// atomically renames the temp file to its final landing name, so the importer
// only ever sees whole, transport-clean files.
func (a *diodeAssembler) landFile(t *diodeTransfer) error {
	// The blocks must tile the file exactly. This is also the cheap gate that
	// stops a forged huge fileSize before the hash pass would grind through it.
	if t.written != t.fileSize {
		return fmt.Errorf("blocks cover %d of %d bytes", t.written, t.fileSize)
	}
	if err := t.tmp.Truncate(t.fileSize); err != nil {
		return err
	}
	if _, err := t.tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, t.tmp); err != nil {
		return err
	}
	if got := h.Sum(nil); [32]byte(got) != t.sha {
		return fmt.Errorf("SHA-256 mismatch (got %x)", got)
	}
	if err := t.tmp.Sync(); err != nil {
		return err
	}
	tmpPath := t.tmp.Name()
	if err := t.tmp.Close(); err != nil {
		return err
	}
	t.tmp = nil
	if err := os.Rename(tmpPath, filepath.Join(a.dir, t.name)); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// failTransfer drops a transfer whose temp file can no longer be written
// (disk full, reconstruction error) — its remaining packets will be ignored.
func (a *diodeAssembler) failTransfer(t *diodeTransfer, now time.Time, err error) {
	a.removeActive(t)
	a.rememberDone(t.id, now)
	a.stats.filesFailed++
	a.removeTemp(t)
	log.Printf("diode catch: abandoned %s: %v", t.name, err)
}

func (a *diodeAssembler) removeActive(t *diodeTransfer) {
	delete(a.active, t.id)
	a.activeSize -= t.fileSize
	for _, blk := range t.blocks {
		a.releaseBlock(t, blk)
	}
	t.blocks = nil
}

func (a *diodeAssembler) rememberDone(id [16]byte, now time.Time) {
	if _, exists := a.done[id]; exists {
		a.done[id] = now
		return
	}
	if len(a.doneOrder) < diodeMaxRememberedTransfers {
		a.doneOrder = append(a.doneOrder, diodeDoneRecord{id: id, at: now})
	} else {
		old := a.doneOrder[a.doneNext]
		if a.done[old.id] == old.at {
			delete(a.done, old.id)
		}
		a.doneOrder[a.doneNext] = diodeDoneRecord{id: id, at: now}
		a.doneNext = (a.doneNext + 1) % diodeMaxRememberedTransfers
	}
	a.done[id] = now
}

func (a *diodeAssembler) removeTemp(t *diodeTransfer) {
	if t.tmp == nil {
		return
	}
	name := t.tmp.Name()
	_ = t.tmp.Close()
	_ = os.Remove(name)
	t.tmp = nil
}

// expireStale abandons transfers that stopped receiving packets (loss beyond
// the parity budget, or a pitcher that died mid-file), keeping their
// completed blocks for a resume, reaps abandoned partials, and forgets old
// completed-transfer IDs.
func (a *diodeAssembler) expireStale(now time.Time) {
	for _, t := range a.active {
		if now.Sub(t.lastSeen) <= diodeStaleAfter {
			continue
		}
		a.removeActive(t)
		a.stats.filesExpired++
		if a.persistPartial(t) {
			log.Printf("diode catch: gave up on %s after %s of silence — kept %d/%d block(s); a re-send resumes from them (re-export it from the low side)",
				t.name, diodeStaleAfter, t.doneCount, t.blockCount)
		} else {
			a.removeTemp(t)
			log.Printf("diode catch: gave up on %s after %s of silence (%d/%d blocks received) — re-export it from the low side",
				t.name, diodeStaleAfter, t.doneCount, t.blockCount)
		}
	}
	a.reapPartials(now)
	for id, ts := range a.done {
		if now.Sub(ts) > diodeDoneRemember {
			delete(a.done, id)
		}
	}
}

// logStats emits one operational summary line, but only when something
// happened since the last one.
func (a *diodeAssembler) logStats() {
	if a.stats == a.lastLogged {
		return
	}
	a.lastLogged = a.stats
	log.Printf("diode catch: %d datagram(s) (%s), %d dropped, %d block(s) repaired, %d evicted, %d file(s) landed, %d expired, %d failed, %d resumed, %d in flight",
		a.stats.packets, formatBytes(a.stats.bytes), a.stats.dropped, a.stats.repairs, a.stats.evictions,
		a.stats.filesLanded, a.stats.filesExpired, a.stats.filesFailed, a.stats.filesResumed, len(a.active))
}
