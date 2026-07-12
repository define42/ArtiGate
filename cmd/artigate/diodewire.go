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
// /admin/missing on the high side, re-export on the low side.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
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
	diodeMaxBlockCount  = 1 << 20
	diodeMaxTransfers   = 16
	diodeMaxOpenBlocks  = 32

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
)

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
	pkt := diodePacket{
		TransferID:   meta.TransferID,
		SHA256:       meta.SHA256,
		Name:         meta.Name,
		FileSize:     meta.FileSize,
		BlockCount:   uint32((meta.FileSize + bds - 1) / bds),
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
	filesLanded  int64
	filesExpired int64
	filesFailed  int64
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
// (used by unit tests that construct an assembler directly).
func (a *diodeAssembler) storedUnverifiedBytes() (int64, error) {
	if a.measureStored != nil {
		return a.measureStored()
	}
	return directoryRegularFileBytesExcept(a.dir, isUDPTempName)
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
// ingest's rule).
func (a *diodeAssembler) transferFor(p *diodePacket, now time.Time) (*diodeTransfer, error) {
	if t, ok := a.active[p.TransferID]; ok {
		if t.name != p.Name || t.fileSize != p.FileSize || t.blockCount != p.BlockCount || t.sha != p.SHA256 {
			return nil, errors.New("metadata mismatch within a transfer")
		}
		return t, nil
	}
	if !a.validName(p.Name) {
		return nil, fmt.Errorf("not a bundle file name: %q", p.Name)
	}
	fileLimit, ok := bundleFileSizeLimit(p.Name)
	if !ok || p.FileSize > fileLimit {
		return nil, fmt.Errorf("%s is %d bytes; transport limit is %d", p.Name, p.FileSize, fileLimit)
	}
	if len(a.active) >= diodeMaxTransfers {
		return nil, fmt.Errorf("more than %d transfers in flight", diodeMaxTransfers)
	}
	stored, err := a.storedUnverifiedBytes()
	if err != nil {
		return nil, fmt.Errorf("measure landing quota: %w", err)
	}
	if stored > diodeMaxUnverifiedBytes-a.activeSize || p.FileSize > diodeMaxUnverifiedBytes-stored-a.activeSize {
		return nil, fmt.Errorf("unverified transport quota of %d bytes would be exceeded", diodeMaxUnverifiedBytes)
	}
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(a.dir, p.Name+".udp-*")
	if err != nil {
		return nil, fmt.Errorf("create landing temp file: %w", err)
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
	a.active[p.TransferID] = t
	a.activeSize += t.fileSize
	log.Printf("diode catch: receiving %s (%s, %d block(s))", t.name, formatBytes(t.fileSize), t.blockCount)
	return t, nil
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
	if len(t.blocks) >= diodeMaxOpenBlocks {
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
// the parity budget, or a pitcher that died mid-file) and forgets old
// completed-transfer IDs.
func (a *diodeAssembler) expireStale(now time.Time) {
	for _, t := range a.active {
		if now.Sub(t.lastSeen) <= diodeStaleAfter {
			continue
		}
		a.removeActive(t)
		a.stats.filesExpired++
		a.removeTemp(t)
		log.Printf("diode catch: gave up on %s after %s of silence (%d/%d blocks received) — re-export it from the low side",
			t.name, diodeStaleAfter, t.doneCount, t.blockCount)
	}
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
	log.Printf("diode catch: %d datagram(s) (%s), %d dropped, %d block(s) repaired, %d file(s) landed, %d expired, %d failed, %d in flight",
		a.stats.packets, formatBytes(a.stats.bytes), a.stats.dropped, a.stats.repairs,
		a.stats.filesLanded, a.stats.filesExpired, a.stats.filesFailed, len(a.active))
}
