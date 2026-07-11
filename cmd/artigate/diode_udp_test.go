package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"math/rand"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/reedsolomon"
)

// testDiodePlan is small enough that unit tests exercise multi-block files
// with a few kilobytes instead of megabytes.
func testDiodePlan(t *testing.T) diodePlan {
	t.Helper()
	pl, err := newDiodePlan(1500, 8, 3)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

// collectDiodePackets runs the send side over content and returns every
// datagram (copied — the sender reuses its buffer).
func collectDiodePackets(t *testing.T, name string, content []byte, pl diodePlan) [][]byte {
	t.Helper()
	enc, err := reedsolomon.New(pl.dataShards, pl.parityShards)
	if err != nil {
		t.Fatal(err)
	}
	meta := diodeFileMeta{Name: name, FileSize: int64(len(content)), SHA256: sha256.Sum256(content)}
	if meta.TransferID, err = newDiodeTransferID(); err != nil {
		t.Fatal(err)
	}
	var pkts [][]byte
	err = sendDiodeFile(bytes.NewReader(content), meta, pl, enc, func(b []byte) error {
		pkts = append(pkts, append([]byte(nil), b...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := int64(len(pkts)), pl.packetCount(int64(len(content))); got != want {
		t.Fatalf("emitted %d packets, packetCount says %d", got, want)
	}
	return pkts
}

func testContent(n int) []byte {
	b := make([]byte, n)
	rnd := rand.New(rand.NewSource(7)) //nolint:gosec // deterministic test data
	rnd.Read(b)
	return b
}

func TestDiodePacketRoundtrip(t *testing.T) {
	in := diodePacket{
		Name:         "go-bundle-000042.tar.gz",
		FileSize:     1 << 30,
		BlockCount:   4096,
		BlockIndex:   17,
		BlockOffset:  17 * 9824,
		BlockLen:     9824,
		ShardSize:    1228,
		DataShards:   8,
		ParityShards: 3,
		ShardIndex:   9,
		Shard:        testContent(1228),
	}
	copy(in.TransferID[:], "0123456789abcdef")
	in.SHA256 = sha256.Sum256([]byte("x"))

	b, err := marshalDiodePacket(nil, &in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseDiodePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != in.Name || out.FileSize != in.FileSize || out.BlockCount != in.BlockCount ||
		out.BlockIndex != in.BlockIndex || out.BlockOffset != in.BlockOffset || out.BlockLen != in.BlockLen ||
		out.ShardSize != in.ShardSize || out.DataShards != in.DataShards || out.ParityShards != in.ParityShards ||
		out.ShardIndex != in.ShardIndex || out.TransferID != in.TransferID || out.SHA256 != in.SHA256 {
		t.Fatalf("roundtrip mismatch:\n in: %+v\nout: %+v", in, out)
	}
	if !bytes.Equal(out.Shard, in.Shard) {
		t.Fatal("shard bytes differ")
	}

	for name, breakIt := range map[string]func([]byte) []byte{
		"flipped payload byte": func(b []byte) []byte { b[diodeHeaderSize+5] ^= 1; return b },
		"flipped header byte":  func(b []byte) []byte { b[30] ^= 1; return b },
		"truncated":            func(b []byte) []byte { return b[:diodeHeaderSize-1] },
		"bad magic":            func(b []byte) []byte { b[0] = 'X'; return b },
		"future version":       func(b []byte) []byte { b[4] = 99; return b },
	} {
		dup := append([]byte(nil), b...)
		if _, err := parseDiodePacket(breakIt(dup)); err == nil {
			t.Errorf("%s: parse accepted a broken packet", name)
		}
	}

	if _, err := marshalDiodePacket(nil, &diodePacket{Name: strings.Repeat("n", diodeNameMax+1)}); err == nil {
		t.Error("marshal accepted an oversized name")
	}
	hostile := in
	hostile.FileSize = 1
	hostile.BlockCount = diodeMaxBlockCount
	hostile.BlockIndex = 0
	hostile.BlockOffset = 0
	hostile.BlockLen = 1
	if err := hostile.validate(); err == nil {
		t.Error("packet with more blocks than file bytes was accepted")
	}
	hostile = in
	hostile.FileSize = int64(^uint64(0) >> 1)
	hostile.BlockOffset = hostile.FileSize - 1
	hostile.BlockLen = 10
	if err := hostile.validate(); err == nil {
		t.Error("overflowing block extent was accepted")
	}
}

func TestSplitDiodeBlock(t *testing.T) {
	pl := diodePlan{dataShards: 4, parityShards: 2, shardSize: 100}
	data := testContent(98) // not divisible by 4: last data shard is padded
	shards, sz := splitDiodeBlock(data, pl)
	if sz != 25 || len(shards) != 6 {
		t.Fatalf("got %d shards of %d bytes", len(shards), sz)
	}
	var joined []byte
	for _, s := range shards[:4] {
		if len(s) != sz {
			t.Fatalf("uneven shard %d", len(s))
		}
		joined = append(joined, s...)
	}
	if !bytes.Equal(joined[:98], data) {
		t.Fatal("data shards do not carry the block")
	}
	if joined[98] != 0 || joined[99] != 0 {
		t.Fatal("padding is not zeroed")
	}
}

// TestDiodeLossRecovery drops the full parity budget from every block —
// replacing one drop with in-flight corruption — shuffles what is left, and
// expects a byte-exact landing.
func TestDiodeLossRecovery(t *testing.T) {
	dir := t.TempDir()
	pl := testDiodePlan(t)
	content := testContent(4*pl.blockDataSize() + 517) // 5 blocks, short tail
	const name = "go-bundle-000042.tar.gz"
	pkts := collectDiodePackets(t, name, content, pl)

	total := pl.totalShards()
	var kept [][]byte
	for i, pkt := range pkts {
		block, shard := i/total, i%total
		// Per block: drop two shards outright, corrupt a third (the CRC must
		// catch it) — exactly the parityShards=3 budget, at rotating indexes.
		switch shard {
		case block % total, (block + 3) % total:
			continue
		case (block + 6) % total:
			pkt[diodeHeaderSize] ^= 0xff
		}
		kept = append(kept, pkt)
	}
	rand.New(rand.NewSource(42)).Shuffle(len(kept), func(i, j int) { kept[i], kept[j] = kept[j], kept[i] }) //nolint:gosec // deterministic shuffle

	var landed []string
	asm := newDiodeAssembler(dir, validBundleFileName, func(n string) { landed = append(landed, n) })
	now := time.Now()
	for _, pkt := range kept {
		asm.handleDatagram(pkt, now)
	}

	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("file did not land: %v (stats %+v)", err, asm.stats)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("landed bytes differ from the sent file")
	}
	if len(landed) != 1 || landed[0] != name {
		t.Fatalf("onComplete calls = %v", landed)
	}
	if asm.stats.repairs == 0 {
		t.Error("expected Reed-Solomon repairs to be counted")
	}
	if asm.stats.dropped == 0 {
		t.Error("expected the corrupted datagrams to be counted as dropped")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, "*.udp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

// TestDiodeAssemblerHostileAndLossyInput drives the receive side through the
// paths that must NOT land a file.
func TestDiodeAssemblerHostileAndLossyInput(t *testing.T) {
	pl := testDiodePlan(t)

	t.Run("invalid file name opens nothing", func(t *testing.T) {
		dir := t.TempDir()
		asm := newDiodeAssembler(dir, validBundleFileName, nil)
		for _, pkt := range collectDiodePackets(t, "exported.db", testContent(100), pl) {
			asm.handleDatagram(pkt, time.Now())
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatal("a non-bundle name touched the landing directory")
		}
		if asm.stats.dropped == 0 {
			t.Fatal("packets for an invalid name must count as dropped")
		}
	})

	t.Run("loss beyond parity expires, never lands", func(t *testing.T) {
		dir := t.TempDir()
		const name = "npm-bundle-000007.tar.gz"
		asm := newDiodeAssembler(dir, validBundleFileName, nil)
		now := time.Now()
		total := pl.totalShards()
		for i, pkt := range collectDiodePackets(t, name, testContent(2*pl.blockDataSize()), pl) {
			if i%total < pl.parityShards+1 { // one more than FEC can repair, every block
				continue
			}
			asm.handleDatagram(pkt, now)
		}
		if fileExists(filepath.Join(dir, name)) {
			t.Fatal("underdelivered file landed")
		}
		asm.expireStale(now.Add(diodeStaleAfter + time.Second))
		if asm.stats.filesExpired != 1 {
			t.Fatalf("filesExpired = %d, want 1", asm.stats.filesExpired)
		}
		if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.udp-*")); len(leftovers) != 0 {
			t.Fatalf("expiry left temp files: %v", leftovers)
		}
	})

	t.Run("metadata forgery within a transfer is dropped", func(t *testing.T) {
		dir := t.TempDir()
		const name = "apt-bundle-000009.tar.gz"
		asm := newDiodeAssembler(dir, validBundleFileName, nil)
		pkts := collectDiodePackets(t, name, testContent(pl.blockDataSize()), pl)
		asm.handleDatagram(pkts[0], time.Now())
		forged, err := parseDiodePacket(pkts[1])
		if err != nil {
			t.Fatal(err)
		}
		forged.FileSize++ // same transfer ID, different claimed size
		forged.Shard = append([]byte(nil), forged.Shard...)
		reb, err := marshalDiodePacket(nil, &forged)
		if err != nil {
			t.Fatal(err)
		}
		before := asm.stats.dropped
		asm.handleDatagram(reb, time.Now())
		if asm.stats.dropped != before+1 {
			t.Fatal("forged metadata was not dropped")
		}
	})

	t.Run("stragglers of a finished transfer stay quiet", func(t *testing.T) {
		dir := t.TempDir()
		const name = "rpm-bundle-000004.tar.gz"
		var completions int
		asm := newDiodeAssembler(dir, validBundleFileName, func(string) { completions++ })
		pkts := collectDiodePackets(t, name, testContent(pl.blockDataSize()/2), pl)
		now := time.Now()
		for _, pkt := range pkts[:pl.dataShards] { // data shards alone complete it
			asm.handleDatagram(pkt, now)
		}
		for _, pkt := range pkts[pl.dataShards:] { // late parity tail
			asm.handleDatagram(pkt, now)
		}
		if completions != 1 {
			t.Fatalf("completions = %d, want 1", completions)
		}
		if len(asm.active) != 0 {
			t.Fatal("stragglers reopened the transfer")
		}
	})
}

func TestDiodeAssemblerResourceBounds(t *testing.T) {
	t.Run("suffix file limit", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		p := diodePacket{
			Name:       "go-bundle-000001.manifest.json",
			FileSize:   diodeMaxManifestBytes + 1,
			BlockCount: 1,
		}
		if _, err := asm.transferFor(&p, time.Now()); err == nil || !strings.Contains(err.Error(), "transport limit") {
			t.Fatalf("oversized manifest transfer = %v, want transport-limit error", err)
		}
		if len(asm.active) != 0 {
			t.Fatal("oversized transfer allocated active state")
		}
	})

	t.Run("global reassembly memory", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		var bounded bool
		for ti := 0; ti < diodeMaxTransfers && !bounded; ti++ {
			tx := &diodeTransfer{name: "go-bundle-000001.tar.gz", blocks: map[uint32]*diodeBlock{}}
			for bi := range uint32(4) {
				p := diodePacket{
					BlockIndex: bi, DataShards: 255, ParityShards: 1,
					ShardSize: diodeMaxShardSize, BlockLen: 255 * diodeMaxShardSize,
				}
				if _, err := asm.blockFor(tx, &p); err != nil {
					if !strings.Contains(err.Error(), "global budget") {
						t.Fatalf("blockFor failed for the wrong bound: %v", err)
					}
					bounded = true
					break
				}
			}
		}
		if !bounded {
			t.Fatal("hostile block geometries did not reach the global reassembly bound")
		}
		if asm.buffered > diodeMaxBufferedBytes {
			t.Fatalf("reserved %d bytes, above %d-byte global bound", asm.buffered, diodeMaxBufferedBytes)
		}
	})

	t.Run("completed transfer cache", func(t *testing.T) {
		asm := newDiodeAssembler(t.TempDir(), validBundleFileName, nil)
		now := time.Now()
		for i := 0; i < diodeMaxRememberedTransfers+1000; i++ {
			var id [16]byte
			id[0], id[1], id[2] = byte(i), byte(i>>8), byte(i>>16)
			asm.rememberDone(id, now)
		}
		if len(asm.done) != diodeMaxRememberedTransfers || len(asm.doneOrder) != diodeMaxRememberedTransfers {
			t.Fatalf("done cache sizes = %d/%d, want %d", len(asm.done), len(asm.doneOrder), diodeMaxRememberedTransfers)
		}
	})
}

func TestRatePacer(t *testing.T) {
	// 8 Mbit/s = 1 MB/s. Push 512 KiB beyond the 256 KiB burst allowance:
	// must take roughly a quarter second, and certainly more than 100 ms.
	pacer := newRatePacer(8)
	start := time.Now()
	for range 512 {
		pacer.wait(1024)
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("pacer let 512 KiB through in %s at 1 MB/s", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("pacer overslept: %s", elapsed)
	}
}

func TestDiodeEnvConfigs(t *testing.T) {
	t.Run("unset means disabled", func(t *testing.T) {
		if cfg, err := pitcherConfigFromEnv(); err != nil || cfg.Interface != "" {
			t.Fatalf("pitcher = %+v, %v", cfg, err)
		}
		if cfg, err := catcherConfigFromEnv(); err != nil || cfg.Interface != "" {
			t.Fatalf("catcher = %+v, %v", cfg, err)
		}
	})

	t.Run("pitcher defaults and overrides", func(t *testing.T) {
		t.Setenv("ARTIGATE_PITCHER_INTERFACE", "eth1")
		t.Setenv("ARTIGATE_PITCHER_RATE_MBIT", "2500")
		cfg, err := pitcherConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		want := PitcherConfig{
			Interface: "eth1", MTU: diodeDefaultMTU, TxQueueLen: diodeDefaultTxQueueLen,
			RateMbit: 2500, Group: diodeDefaultGroup, Port: diodeDefaultPort,
			DataShards: diodeDefaultDataShards, ParityShards: diodeDefaultParityShards, NetSetup: true,
		}
		if cfg != want {
			t.Fatalf("cfg = %+v, want %+v", cfg, want)
		}
	})

	t.Run("catcher defaults and overrides", func(t *testing.T) {
		t.Setenv("ARTIGATE_CATCHER_INTERFACE", "enp5s0")
		t.Setenv("ARTIGATE_CATCHER_RCVBUF_MB", "256")
		t.Setenv("ARTIGATE_CATCHER_NETSETUP", "off")
		cfg, err := catcherConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		want := CatcherConfig{
			Interface: "enp5s0", MTU: diodeDefaultMTU, Group: diodeDefaultGroup,
			Port: diodeDefaultPort, RcvBufMB: 256, NetSetup: false,
		}
		if cfg != want {
			t.Fatalf("cfg = %+v, want %+v", cfg, want)
		}
	})

	for name, set := range map[string]func(*testing.T){
		"rate not a number":  func(t *testing.T) { t.Setenv("ARTIGATE_PITCHER_RATE_MBIT", "fast") },
		"MTU out of range":   func(t *testing.T) { t.Setenv("ARTIGATE_PITCHER_MTU", "900") },
		"group not v6":       func(t *testing.T) { t.Setenv("ARTIGATE_PITCHER_GROUP", "224.0.0.1") },
		"group not mcast":    func(t *testing.T) { t.Setenv("ARTIGATE_PITCHER_GROUP", "2001:db8::1") },
		"netsetup gibberish": func(t *testing.T) { t.Setenv("ARTIGATE_PITCHER_NETSETUP", "maybe") },
		"FEC too wide":       func(t *testing.T) { t.Setenv("ARTIGATE_PITCHER_FEC_DATA", "255") },
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Setenv("ARTIGATE_PITCHER_INTERFACE", "eth1")
			set(t)
			if cfg, err := pitcherConfigFromEnv(); err == nil {
				t.Fatalf("accepted bad config: %+v", cfg)
			}
		})
	}
}

// TestJoinDiodeGroupOnLoopback exercises the real multicast join path. The
// loopback device accepts IPv6 group joins on Linux; environments where it
// does not merely skip.
func TestJoinDiodeGroupOnLoopback(t *testing.T) {
	conn, err := joinDiodeGroup(CatcherConfig{Interface: "lo", Group: diodeDefaultGroup, Port: 0})
	if err != nil {
		t.Skipf("multicast join on loopback unavailable here: %v", err)
	}
	_ = conn.Close()
}

// newLoopbackDiodePair wires a real pitcher socket to a real catcher socket
// over ::1. Link-local multicast cannot route across loopback (no fe80 source
// address there), so the transport tests run the identical datagram path over
// unicast; the group join itself is covered above and on real fiber.
//
// The second result reports a constrained environment: without CAP_NET_ADMIN,
// SO_RCVBUFFORCE fails and rmem_max caps the receive buffer far below one
// bundle, so a scheduling stall of the catcher goroutine during a 200 Mbit/s
// blast tail-drops longer runs of datagrams than any parity budget repairs.
// There the pitcher is paced down until the send outlasts realistic stalls —
// the same "stay below what the catcher can absorb" rule the production rate
// limit exists for — and callers may re-pitch once on loss beyond parity,
// mirroring the documented re-export remedy.
func newLoopbackDiodePair(t *testing.T, landing string, onComplete func(string)) (*diodePitcher, bool) {
	t.Helper()
	rc, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	const wantRcvBuf = 4 << 20
	rateMbit := 200
	granted, err := forceUDPBuffer(rc, true, wantRcvBuf)
	constrained := err != nil || granted < wantRcvBuf
	if constrained {
		rateMbit = 16
		t.Logf("receive buffer %d of %d bytes (%v): pacing at %d Mbit/s and tolerating one re-pitch", granted, wantRcvBuf, err, rateMbit)
	}
	catcher := &diodeCatcher{conn: rc, asm: newDiodeAssembler(landing, validBundleFileName, onComplete)}
	go catcher.run()
	t.Cleanup(func() { _ = catcher.Close() })

	cfg := PitcherConfig{
		MTU: 1500, RateMbit: rateMbit, Group: "::1",
		Port:       rc.LocalAddr().(*net.UDPAddr).Port,
		DataShards: 8, ParityShards: 2,
	}
	p, err := newDiodePitcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, constrained
}

// TestPitcherToCatcherOverLoopback sends a whole bundle through real sockets
// and waits for all three files to land byte-exact.
func TestPitcherToCatcherOverLoopback(t *testing.T) {
	outDir, landing := t.TempDir(), t.TempDir()
	var mu sync.Mutex
	var landed []string
	p, constrained := newLoopbackDiodePair(t, landing, func(n string) { mu.Lock(); landed = append(landed, n); mu.Unlock() })

	const bundleID = "go-bundle-000042"
	files := map[string][]byte{
		bundleID + ".tar.gz":            testContent(300 << 10),
		bundleID + ".manifest.json":     testContent(2 << 10),
		bundleID + ".manifest.json.sig": testContent(89),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(outDir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.SendBundle(context.Background(), outDir, bundleID); err != nil {
		t.Fatalf("SendBundle: %v", err)
	}

	// With forced buffers the whole bundle fits the receive queue, so a single
	// send must land everything. In a constrained environment the kernel may
	// still drop beyond the parity budget under full-suite load; the diode's
	// remedy for that is a re-export, so allow exactly one re-pitch there
	// before calling it a failure.
	deadline := time.Now().Add(10 * time.Second)
	resent := false
	for {
		allThere := true
		for name, content := range files {
			got, err := os.ReadFile(filepath.Join(landing, name))
			if err != nil || !bytes.Equal(got, content) {
				allThere = false
				break
			}
		}
		if allThere {
			break
		}
		if time.Now().After(deadline) {
			mu.Lock()
			snapshot := append([]string(nil), landed...)
			mu.Unlock()
			if !constrained || resent {
				t.Fatalf("bundle did not land; completed so far: %v", snapshot)
			}
			t.Logf("loss beyond parity in a constrained environment; re-pitching once (completed so far: %v)", snapshot)
			if err := p.SendBundle(context.Background(), outDir, bundleID); err != nil {
				t.Fatalf("SendBundle (re-pitch): %v", err)
			}
			resent = true
			deadline = time.Now().Add(15 * time.Second)
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if resent {
		// A re-pitch can land a file a second time; every file must still
		// have completed at least once.
		seen := map[string]bool{}
		for _, n := range landed {
			seen[n] = true
		}
		if len(seen) != len(files) {
			t.Fatalf("onComplete covered %d files, want %d (%v)", len(seen), len(files), landed)
		}
	} else if len(landed) != len(files) {
		t.Fatalf("onComplete ran %d times, want %d (%v)", len(landed), len(files), landed)
	}
}

// TestLowToHighOverUDPDiode runs the whole loop over the built-in diode: the
// low side collects and pitches, the catcher lands into the high side's
// landing dir and kicks the import (signature, sequence, hashes — trust is
// unchanged by the transport), and the model serves.
func TestLowToHighOverUDPDiode(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-over-udp")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")

	ls, priv := newHFLowServer(t, hub.URL)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	high := httptest.NewServer(hs)
	t.Cleanup(high.Close)

	ls.pitcher, _ = newLoopbackDiodePair(t, hs.cfg.Landing, hs.onDiodeFileLanded)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"unsloth/gpt-oss-20b-GGUF:Q4_0"}})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.DiodeError != "" {
		t.Fatalf("diode send failed: %s", res.DiodeError)
	}
	if res.Message != "sent over the UDP diode" {
		t.Errorf("message = %q", res.Message)
	}
	for _, suffix := range bundleSuffixes() {
		if fileExists(filepath.Join(ls.cfg.ExportDir, res.BundleID+suffix)) {
			t.Errorf("%s still staged after a successful send", res.BundleID+suffix)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := hs.ImportNext(); err != nil {
			t.Fatalf("ImportNext: %v", err)
		}
		st, err := hs.ImportStatus()
		if err != nil {
			t.Fatal(err)
		}
		if st.Stream(streamHF).LastImportedSequence >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	st, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.Stream(streamHF).LastImportedSequence != 1 {
		t.Fatalf("hf stream not imported over the UDP diode: %+v", st.Stream(streamHF))
	}
	assertHTTPBody(t, high.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", string(model.manifest))
}
