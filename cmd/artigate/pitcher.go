package main

// The pitcher: the low side of the built-in UDP data diode. Where the HTTP
// transport (diode.go) PUTs bundles to an endpoint, the pitcher throws them
// down a one-way fiber as rate-limited, Reed-Solomon-coded IPv6 multicast
// datagrams (wire format in diodewire.go), configured entirely through
// environment variables:
//
//	ARTIGATE_PITCHER_INTERFACE   dedicated diode NIC (e.g. eth1); setting it
//	                             enables the pitcher
//	ARTIGATE_PITCHER_MTU         interface MTU, default 9000 (jumbo frames)
//	ARTIGATE_PITCHER_TXQUEUELEN  interface TX queue length, default 10000
//	ARTIGATE_PITCHER_RATE_MBIT   max send rate in Mbit/s ON THE WIRE, default
//	                             800 — a one-way link has no congestion
//	                             control, so this must stay below what the
//	                             catcher can absorb
//	ARTIGATE_PITCHER_GROUP       IPv6 multicast group, default ff02::4147
//	ARTIGATE_PITCHER_PORT        UDP port, default 4147
//	ARTIGATE_PITCHER_FEC_DATA    data shards per FEC block, default 32
//	ARTIGATE_PITCHER_FEC_PARITY  parity shards per FEC block, default 8 (any
//	                             8 of every 40 datagrams may be lost)
//	ARTIGATE_PITCHER_NETSETUP    on (default) lets ArtiGate configure the
//	                             interface itself (MTU, queues, EUI-64
//	                             link-local, link up; needs CAP_NET_ADMIN);
//	                             off expects a pre-configured interface
//
// The pitcher also carries the periodic signed stream-index heartbeat, which
// is transport-independent and configured by ARTIGATE_DIODE_HEARTBEAT — see
// diodeheartbeat.go.
//
// Multicast is not an implementation detail: the fiber is one-way, so the
// pitcher can never resolve the catcher's MAC address (NDP needs an answer).
// An IPv6 multicast destination maps directly onto an Ethernet group MAC and
// needs no resolution at all.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	diodeDefaultMTU          = 9000
	diodeDefaultTxQueueLen   = 10000
	diodeDefaultRateMbit     = 800
	diodeDefaultGroup        = "ff02::4147" // unassigned link-scope group; 0x4147 = "AG"
	diodeDefaultPort         = 4147
	diodeDefaultDataShards   = 32
	diodeDefaultParityShards = 8

	// diodeWirePacketOverhead approximates the per-datagram bytes on the
	// fiber beyond the UDP payload: IPv6 (40) + UDP (8) plus Ethernet framing
	// (14 header + 4 FCS + 8 preamble + 12 interframe gap). Counting them
	// makes ARTIGATE_PITCHER_RATE_MBIT the actual line rate the catcher must
	// absorb, which is the number that matters on a one-way link.
	diodeWirePacketOverhead = 40 + 8 + 14 + 4 + 8 + 12

	// A healthy diode still produces transient send errors — ENOBUFS when the
	// qdisc fills faster than the NIC drains (UDP has no backpressure),
	// EADDRNOTAVAIL while the link-local address finishes DAD after a link
	// bounce. Retrying briefly is correct; anything longer is a real fault.
	diodeSendRetries    = 50
	diodeSendRetryDelay = 100 * time.Millisecond

	diodeSendBufBytes = 8 << 20
)

// PitcherConfig is the built-in UDP diode sender's configuration, parsed from
// ARTIGATE_PITCHER_* environment variables. A zero Interface means disabled.
type PitcherConfig struct {
	Interface    string
	MTU          int
	TxQueueLen   int
	RateMbit     int
	Group        string
	Port         int
	DataShards   int
	ParityShards int
	NetSetup     bool
}

// pitcherConfigFromEnv reads and validates the pitcher's environment
// configuration. Every value fails fast at startup — a diode misconfiguration
// must never surface as a failed export at 3am.
func pitcherConfigFromEnv() (PitcherConfig, error) {
	cfg := PitcherConfig{Interface: strings.TrimSpace(os.Getenv("ARTIGATE_PITCHER_INTERFACE"))}
	if cfg.Interface == "" {
		return PitcherConfig{}, nil
	}
	var err error
	if cfg.MTU, err = envIntInRange("ARTIGATE_PITCHER_MTU", diodeDefaultMTU, 1280, 65536); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.TxQueueLen, err = envIntInRange("ARTIGATE_PITCHER_TXQUEUELEN", diodeDefaultTxQueueLen, 1, 1<<20); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.RateMbit, err = envIntInRange("ARTIGATE_PITCHER_RATE_MBIT", diodeDefaultRateMbit, 1, 100000); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.Port, err = envIntInRange("ARTIGATE_PITCHER_PORT", diodeDefaultPort, 1, 65535); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.DataShards, err = envIntInRange("ARTIGATE_PITCHER_FEC_DATA", diodeDefaultDataShards, 1, diodeMaxTotalShards-1); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.ParityShards, err = envIntInRange("ARTIGATE_PITCHER_FEC_PARITY", diodeDefaultParityShards, 1, diodeMaxTotalShards-1); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.Group, err = envMulticastGroup("ARTIGATE_PITCHER_GROUP"); err != nil {
		return PitcherConfig{}, err
	}
	if cfg.NetSetup, err = envOnOffDefault("ARTIGATE_PITCHER_NETSETUP", true); err != nil {
		return PitcherConfig{}, err
	}
	if _, err := newDiodePlan(cfg.MTU, cfg.DataShards, cfg.ParityShards); err != nil {
		return PitcherConfig{}, err
	}
	return cfg, nil
}

func envIntInRange(name string, def, minV, maxV int) (int, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", name, v)
	}
	if n < minV || n > maxV {
		return 0, fmt.Errorf("%s must be between %d and %d, got %d", name, minV, maxV, n)
	}
	return n, nil
}

func envOnOffDefault(name string, def bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	on, err := parseOnOff(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return on, nil
}

// envMulticastGroup reads and validates an IPv6 multicast group address.
func envMulticastGroup(name string) (string, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return diodeDefaultGroup, nil
	}
	ip := net.ParseIP(v)
	if ip == nil || ip.To4() != nil || !ip.IsMulticast() {
		return "", fmt.Errorf("%s: %q is not an IPv6 multicast address (want something like %s)", name, v, diodeDefaultGroup)
	}
	return v, nil
}

// -----------------------------------------------------------------------------
// The sender
// -----------------------------------------------------------------------------

// mustPitcherConfig parses the pitcher environment at startup and enforces
// that only one diode transport carries bundles.
func mustPitcherConfig(diodeURL string) PitcherConfig {
	cfg, err := pitcherConfigFromEnv()
	must(err)
	if cfg.Interface != "" && diodeURL != "" {
		log.Fatal("ARTIGATE_DIODE_URL and ARTIGATE_PITCHER_INTERFACE are mutually exclusive — bundles leave over one diode transport")
	}
	return cfg
}

// attachPitcher opens the UDP diode sender on the low server when configured;
// failures are fatal at startup, like every other misconfiguration.
func attachPitcher(ls *LowServer, cfg PitcherConfig) {
	if cfg.Interface == "" {
		return
	}
	p, err := setupPitcher(cfg)
	must(err)
	ls.pitcher = p
}

// diodePitcher owns the diode TX socket. Sends are serialized under mu: the
// fiber is one shared medium and the rate limit governs the sum of all
// streams, so concurrent exports take turns rather than interleave.
type diodePitcher struct {
	cfg  PitcherConfig
	plan diodePlan
	enc  reedsolomon.Encoder
	conn *net.UDPConn
	rate *ratePacer
	mu   sync.Mutex
}

// setupPitcher configures the diode interface (unless the host already did)
// and opens the sender.
func setupPitcher(cfg PitcherConfig) (*diodePitcher, error) {
	if cfg.NetSetup {
		err := applyDiodeIfaceSetup(diodeIfaceSetup{
			Name:          cfg.Interface,
			MTU:           cfg.MTU,
			TxQueueLen:    cfg.TxQueueLen,
			MaxTXRing:     true,
			WaitLinkLocal: true,
		})
		if err != nil {
			return nil, fmt.Errorf("configure diode interface %s: %w (needs CAP_NET_ADMIN over the host network namespace — network_mode: host, cap_add: NET_ADMIN, root — or preconfigure the NIC and set ARTIGATE_PITCHER_NETSETUP=off)", cfg.Interface, err)
		}
	}
	return newDiodePitcher(cfg)
}

func newDiodePitcher(cfg PitcherConfig) (*diodePitcher, error) {
	plan, err := newDiodePlan(cfg.MTU, cfg.DataShards, cfg.ParityShards)
	if err != nil {
		return nil, err
	}
	enc, err := reedsolomon.New(cfg.DataShards, cfg.ParityShards)
	if err != nil {
		return nil, err
	}
	conn, err := dialDiode(cfg)
	if err != nil {
		return nil, err
	}
	if granted, err := forceUDPBuffer(conn, false, diodeSendBufBytes); err != nil {
		log.Printf("diode pitch: send buffer left at kernel default (%v)", err)
	} else if granted < diodeSendBufBytes {
		log.Printf("diode pitch: send buffer %s (asked %s; SO_SNDBUFFORCE needs CAP_NET_ADMIN)", formatBytes(int64(granted)), formatBytes(int64(diodeSendBufBytes)))
	}
	return &diodePitcher{cfg: cfg, plan: plan, enc: enc, conn: conn, rate: newRatePacer(cfg.RateMbit)}, nil
}

// dialDiode connects the multicast TX socket. Connecting pins the source to
// the interface's link-local address, which right after a link bounce may
// still be completing duplicate address detection — so this retries briefly.
func dialDiode(cfg PitcherConfig) (*net.UDPConn, error) {
	dst := &net.UDPAddr{IP: net.ParseIP(cfg.Group), Port: cfg.Port, Zone: cfg.Interface}
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialUDP("udp6", nil, dst)
		if err == nil {
			return conn, nil
		}
		if !errors.Is(err, syscall.EADDRNOTAVAIL) || time.Now().After(deadline) {
			return nil, fmt.Errorf("open diode socket to [%s%%%s]:%d: %w", cfg.Group, cfg.Interface, cfg.Port, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (p *diodePitcher) Close() error {
	return p.conn.Close()
}

// target renders the destination for logs.
func (p *diodePitcher) target() string {
	return fmt.Sprintf("[%s%%%s]:%d", p.cfg.Group, p.cfg.Interface, p.cfg.Port)
}

// maxWireFileBytes is the largest file this pitcher's block geometry can
// carry: the wire format bounds a transfer at diodeMaxBlockCount blocks, so a
// small geometry (low MTU, few data shards) caps a transfer well below the
// archive limit. Bundle production consults it so nothing is ever committed
// that sendDiodeFile would refuse.
func (p *diodePitcher) maxWireFileBytes() int64 {
	return int64(p.plan.blockDataSize()) * diodeMaxBlockCount
}

// SendBundle throws one bundle's three files down the fiber, the archive
// first — the same ordering rule as every other transport, so the catcher can
// never land a manifest whose archive never arrives and look complete.
func (p *diodePitcher) SendBundle(ctx context.Context, dir, bundleID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, suffix := range bundleSuffixes() {
		if err := p.sendFile(ctx, filepath.Join(dir, bundleID+suffix)); err != nil {
			return fmt.Errorf("%s%s: %w", bundleID, suffix, err)
		}
	}
	return nil
}

// sendHeartbeat transmits one already-marshalled heartbeat datagram
// immediately. It deliberately takes neither the bundle lock (a heartbeat must
// not wait hours behind a large transfer — reporting indexes while a bundle
// crosses is half its point) nor the pacer (one datagram every interval is
// noise next to the configured rate, and the pacer is not safe for concurrent
// use); the socket itself is safe for concurrent writes.
func (p *diodePitcher) sendHeartbeat(pkt []byte) error {
	return p.writeRetry(pkt)
}

// sendFile transmits one file: a hashing pass (the wire header carries the
// SHA-256 so the catcher can verify before landing), then the FEC-coded,
// rate-paced datagrams.
func (p *diodePitcher) sendFile(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	meta := diodeFileMeta{Name: filepath.Base(path), FileSize: st.Size()}
	if meta.TransferID, err = newDiodeTransferID(); err != nil {
		return err
	}
	if meta.SHA256, err = hashDiodeFile(f); err != nil {
		return err
	}
	start := time.Now()
	body := newProgressReader(ctx, f, "diode ↑ "+meta.Name, meta.FileSize)
	err = sendDiodeFile(body, meta, p.plan, p.enc, func(pkt []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.rate.wait(len(pkt) + diodeWirePacketOverhead)
		return p.writeRetry(pkt)
	})
	if err != nil {
		return err
	}
	log.Printf("diode pitch: sent %s (%s, %d datagram(s), %s)",
		meta.Name, formatBytes(meta.FileSize), p.plan.packetCount(meta.FileSize), time.Since(start).Round(time.Millisecond))
	return nil
}

// hashDiodeFile hashes the already-open file and rewinds it for the send
// pass.
func hashDiodeFile(f *os.File) ([32]byte, error) {
	var sum [32]byte
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// writeRetry sends one datagram, absorbing the transient errors described at
// diodeSendRetries.
func (p *diodePitcher) writeRetry(pkt []byte) error {
	for attempt := 0; ; attempt++ {
		_, err := p.conn.Write(pkt)
		if err == nil {
			return nil
		}
		if attempt >= diodeSendRetries || !isTransientSendErr(err) {
			return err
		}
		time.Sleep(diodeSendRetryDelay)
	}
}

func isTransientSendErr(err error) bool {
	return errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// -----------------------------------------------------------------------------
// Rate pacing
// -----------------------------------------------------------------------------

// ratePacer is a token bucket over wire bytes. UDP has no congestion control
// and a one-way fiber cannot ask the sender to slow down, so pacing to what
// the catcher provisioned is the only thing standing between a big bundle and
// a receive queue overflowing faster than parity can repair.
type ratePacer struct {
	bytesPerSec float64
	burst       float64
	credit      float64
	last        time.Time
}

func newRatePacer(mbit int) *ratePacer {
	return &ratePacer{
		bytesPerSec: float64(mbit) * 1e6 / 8,
		// A quarter-megabyte burst keeps the sleep granularity coarse enough
		// for the OS timer while staying well inside a forced receive buffer.
		burst: 256 << 10,
		last:  time.Now(),
	}
}

// wait blocks until n more bytes fit under the configured rate.
func (r *ratePacer) wait(n int) {
	need := float64(n)
	for {
		now := time.Now()
		r.credit = min(r.credit+now.Sub(r.last).Seconds()*r.bytesPerSec, r.burst)
		r.last = now
		if r.credit >= need {
			r.credit -= need
			return
		}
		time.Sleep(time.Duration((need - r.credit) / r.bytesPerSec * float64(time.Second)))
	}
}

// -----------------------------------------------------------------------------
// Export-flow hook
// -----------------------------------------------------------------------------

// pitchBundle is the UDP twin of the HTTP upload in uploadBundleIfConfigured:
// best-effort by design. The bundle is committed and archived before this
// runs, so a failed send loses nothing — it is reported (result, progress,
// log) and the staged files stay in the export dir for a re-transmit. On
// success the spool is cleared; only the fire-and-forget nature differs (a
// one-way fiber acknowledges nothing — loss beyond the parity budget shows up
// on the high side's /admin/missing and is fixed by a re-export).
func (s *LowServer) pitchBundle(ctx context.Context, res *ExportResult) {
	emitProgress(ctx, "Sending %s over the UDP diode…", res.BundleID)
	if err := s.pitcher.SendBundle(ctx, s.cfg.ExportDir, res.BundleID); err != nil {
		log.Printf("diode pitch %s: %v", res.BundleID, err)
		emitProgress(ctx, "  ✗ diode send failed: %s", err)
		res.DiodeError = err.Error()
		return
	}
	emitProgress(ctx, "  ✓ %s sent", res.BundleID)
	if res.Message == "" {
		res.Message = "sent over the UDP diode"
	}
	s.clearOutboundBundle(res.BundleID)
}
