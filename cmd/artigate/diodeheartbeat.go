package main

// The diode heartbeat. A diode gives the high side no way to ask "what
// should I have?": it only learns a bundle exists when (part of) it arrives,
// so a bundle lost in its entirety — or a low side that stopped exporting —
// is invisible to /admin/missing, which can only report gaps behind bundles
// that did arrive. The low side therefore periodically emits a tiny signed
// heartbeat carrying each stream's newest committed sequence number; the high
// side verifies it and compares the reported indexes against what it has
// imported or holds in landing/quarantine, surfacing bundles that left the
// low side but never arrived (the dashboard's "awaiting" column,
// /admin/status, and /metrics).
//
// One signed artifact rides every diode transport (ARTIGATE_DIODE_HEARTBEAT
// sets the interval, default 30s):
//
//   - built-in UDP diode: the pitcher broadcasts it as a datagram, the
//     catcher verifies it off the wire;
//   - HTTP diode endpoint: it is PUT to <ARTIGATE_DIODE_URL>/artigate.heartbeat;
//     the high side's ingest records it directly (and a diode proxy that only
//     moves files just deposits it in the landing directory, which works too);
//   - folder diode: it is written to <export-dir>/artigate.heartbeat for the
//     carrier to move across; the high side's import pass consumes it from
//     the landing directory.
//
// Heartbeats are trusted only as far as their signature: the payload is
// signed with the low side's Ed25519 key (Ed25519ph with a dedicated context
// string, so a heartbeat signature can never be replayed as a manifest
// signature or vice versa), and the high side verifies before recording. A
// replayed old heartbeat is refused while a newer one is fresh, so an on-wire
// attacker cannot mask progress; the guard relaxes once the last accepted
// heartbeat goes stale, so a low-side clock reset cannot blind monitoring
// forever. Heartbeats influence monitoring only — never what is imported or
// served.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	diodeHeartbeatMagic   = 0x41474842 // "AGHB"
	diodeHeartbeatVersion = 1
	// diodeHeartbeatHeaderSize is magic (4) + version (1) + Ed25519 signature.
	diodeHeartbeatHeaderSize = 5 + ed25519.SignatureSize
	// diodeMaxHeartbeatBytes bounds the JSON payload — far above what every
	// registered stream's index needs, far below one datagram at any legal MTU
	// doing harm, and the cap on unauthenticated verification work per packet.
	diodeMaxHeartbeatBytes = 4 << 10

	// diodeHeartbeatType must match in the signed payload, so signed bytes of
	// any other future control message can never be read as a heartbeat.
	diodeHeartbeatType = "artigate-diode-heartbeat"
	// diodeHeartbeatSignatureContext domain-separates heartbeat signatures
	// from manifest signatures (signed by the same key, without a context).
	diodeHeartbeatSignatureContext = "ArtiGate diode heartbeat v1"

	// diodeDefaultHeartbeatInterval is how often the low side emits a
	// heartbeat when ARTIGATE_DIODE_HEARTBEAT is unset.
	diodeDefaultHeartbeatInterval = 30 * time.Second
	// diodeHeartbeatReplayWindow is how long the created-time monotonicity
	// guard holds: within it an older heartbeat is a replay and is dropped;
	// past it the stored heartbeat is stale anyway, so a re-send — even one
	// stamped by a reset low-side clock — is better than staying blind.
	diodeHeartbeatReplayWindow = 10 * time.Minute

	// diodeHeartbeatFileName is the fixed name a heartbeat travels under on
	// the file-shaped transports: written into the export dir for a folder
	// carrier, PUT to the HTTP diode endpoint, consumed from the landing
	// directory. It has no bundle suffix, so no bundle-file scan can ever
	// mistake it for content.
	diodeHeartbeatFileName = "artigate.heartbeat"
	// diodeMaxHeartbeatPacketBytes bounds a whole heartbeat artifact (header,
	// signature, payload) wherever it is read from disk or an HTTP body.
	diodeMaxHeartbeatPacketBytes int64 = diodeHeartbeatHeaderSize + diodeMaxHeartbeatBytes
	// diodeHeartbeatFileGrace is how long an unverifiable heartbeat file may
	// sit in the landing directory before it is removed: long enough for the
	// slowest sane folder carrier to finish writing it, short enough that
	// junk cannot squat there.
	diodeHeartbeatFileGrace = 10 * time.Minute
	// diodeHeartbeatSendTimeout bounds one heartbeat's HTTP upload.
	diodeHeartbeatSendTimeout = 30 * time.Second
)

// diodeHeartbeat is the signed heartbeat payload: for every stream that has
// exported at least one bundle, the newest committed sequence number. The high
// side subtracts what it holds to find bundles still crossing — or lost on —
// the diode.
type diodeHeartbeat struct {
	Type    string    `json:"type"`
	Created time.Time `json:"created"`
	// Generator is the low-side binary's version, informational only.
	Generator string           `json:"generator,omitempty"`
	Streams   map[string]int64 `json:"streams"`
}

func diodeHeartbeatSignOpts() *ed25519.Options {
	return &ed25519.Options{Hash: crypto.SHA512, Context: diodeHeartbeatSignatureContext}
}

// marshalDiodeHeartbeatPacket renders one signed heartbeat datagram:
// magic, version, Ed25519ph signature, JSON payload.
func marshalDiodeHeartbeatPacket(priv ed25519.PrivateKey, hb diodeHeartbeat) ([]byte, error) {
	payload, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > diodeMaxHeartbeatBytes {
		return nil, fmt.Errorf("heartbeat payload is %d bytes, above the %d-byte wire limit", len(payload), diodeMaxHeartbeatBytes)
	}
	digest := sha512.Sum512(payload)
	sig, err := priv.Sign(nil, digest[:], diodeHeartbeatSignOpts())
	if err != nil {
		return nil, err
	}
	b := make([]byte, diodeHeartbeatHeaderSize+len(payload))
	binary.BigEndian.PutUint32(b[0:], diodeHeartbeatMagic)
	b[4] = diodeHeartbeatVersion
	copy(b[5:], sig)
	copy(b[diodeHeartbeatHeaderSize:], payload)
	return b, nil
}

// isDiodeHeartbeatDatagram routes a received datagram: heartbeat magic goes to
// the verifier, everything else to the file reassembler.
func isDiodeHeartbeatDatagram(b []byte) bool {
	return len(b) >= 4 && binary.BigEndian.Uint32(b) == diodeHeartbeatMagic
}

// parseDiodeHeartbeatPacket validates and verifies one heartbeat datagram.
// Nothing it returns is trusted beyond the signature: stream entries are still
// filtered to known streams with positive sequences, exactly as strictly as
// the bundle path treats names.
func parseDiodeHeartbeatPacket(pub ed25519.PublicKey, b []byte) (diodeHeartbeat, error) {
	if len(b) <= diodeHeartbeatHeaderSize {
		return diodeHeartbeat{}, fmt.Errorf("heartbeat datagram too short (%d bytes)", len(b))
	}
	if !isDiodeHeartbeatDatagram(b) {
		return diodeHeartbeat{}, errors.New("not a heartbeat datagram (bad magic)")
	}
	if b[4] != diodeHeartbeatVersion {
		return diodeHeartbeat{}, fmt.Errorf("unsupported heartbeat wire version %d", b[4])
	}
	payload := b[diodeHeartbeatHeaderSize:]
	if int64(len(payload)) > diodeMaxHeartbeatBytes {
		return diodeHeartbeat{}, fmt.Errorf("heartbeat payload is %d bytes, above the %d-byte wire limit", len(payload), diodeMaxHeartbeatBytes)
	}
	digest := sha512.Sum512(payload)
	if err := ed25519.VerifyWithOptions(pub, digest[:], b[5:5+ed25519.SignatureSize], diodeHeartbeatSignOpts()); err != nil {
		return diodeHeartbeat{}, errors.New("heartbeat signature verification failed")
	}
	var hb diodeHeartbeat
	if err := json.Unmarshal(payload, &hb); err != nil {
		return diodeHeartbeat{}, fmt.Errorf("decode heartbeat payload: %w", err)
	}
	if hb.Type != diodeHeartbeatType {
		return diodeHeartbeat{}, fmt.Errorf("wrong heartbeat type %q", hb.Type)
	}
	if hb.Created.IsZero() {
		return diodeHeartbeat{}, errors.New("heartbeat has no created time")
	}
	hb.Streams = filterHeartbeatStreams(hb.Streams)
	return hb, nil
}

// filterHeartbeatStreams keeps only known streams with positive sequences. A
// newer low side reporting a stream this binary does not know must not
// invalidate the whole heartbeat — the other streams' indexes are still good —
// so unknown entries are dropped, not refused.
func filterHeartbeatStreams(streams map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(streams))
	for stream, seq := range streams {
		if seq >= 1 && isKnownStream(stream) {
			out[stream] = seq
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Low side: the periodic sender
// -----------------------------------------------------------------------------

// lastExportedSequences snapshots each stream's newest committed sequence
// (the next-sequence counter minus one); streams that never exported are
// omitted, so the heartbeat stays one small datagram.
func (s *LowServer) lastExportedSequences() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.state.Sequences))
	for stream, next := range s.state.Sequences {
		if next > 1 && isKnownStream(stream) {
			out[stream] = next - 1
		}
	}
	return out
}

// buildDiodeHeartbeat assembles the heartbeat the pitcher broadcasts.
func (s *LowServer) buildDiodeHeartbeat(now time.Time) diodeHeartbeat {
	return diodeHeartbeat{
		Type:      diodeHeartbeatType,
		Created:   now,
		Generator: versionString(),
		Streams:   s.lastExportedSequences(),
	}
}

// sendDiodeHeartbeat signs one heartbeat and hands it to whichever diode
// transport is configured: the built-in UDP pitcher, the HTTP endpoint, or —
// with neither — the export dir, where it is one more file for the folder
// carrier to move across.
func (s *LowServer) sendDiodeHeartbeat(ctx context.Context, now time.Time) error {
	pkt, err := marshalDiodeHeartbeatPacket(s.privateKey, s.buildDiodeHeartbeat(now))
	if err != nil {
		return err
	}
	switch {
	case s.pitcher != nil:
		return s.pitcher.sendHeartbeat(pkt)
	case s.cfg.DiodeURL != "":
		return s.uploadHeartbeatToHTTPDiode(ctx, pkt)
	default:
		return writeBytesAtomic(filepath.Join(s.cfg.ExportDir, diodeHeartbeatFileName), pkt, 0o644)
	}
}

// uploadHeartbeatToHTTPDiode PUTs one heartbeat to the HTTP diode endpoint,
// exactly like a bundle file. An ArtiGate high side records it directly; a
// diode proxy that only moves files deposits it in the landing directory,
// where the import pass consumes it — either way it arrives.
func (s *LowServer) uploadHeartbeatToHTTPDiode(ctx context.Context, pkt []byte) error {
	ctx, cancel := context.WithTimeout(ctx, diodeHeartbeatSendTimeout)
	defer cancel()
	url := strings.TrimRight(s.cfg.DiodeURL, "/") + "/" + diodeHeartbeatFileName
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(pkt))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(pkt))
	if s.cfg.DiodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.DiodeToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", diodeHeartbeatFileName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("PUT %s: HTTP %d: %s", diodeHeartbeatFileName, resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

// heartbeatIntervalStatus renders the startup-log description of the
// heartbeat schedule.
func heartbeatIntervalStatus(interval time.Duration) string {
	if interval <= 0 {
		return "disabled (ARTIGATE_DIODE_HEARTBEAT=off)"
	}
	return fmt.Sprintf("stream indexes sent every %s", interval)
}

// diodeHeartbeatDestination names, for the startup log, where heartbeats go.
func (s *LowServer) diodeHeartbeatDestination() string {
	switch {
	case s.pitcher != nil:
		return "UDP diode"
	case s.cfg.DiodeURL != "":
		return "HTTP diode endpoint"
	default:
		return "export dir, for the folder carrier"
	}
}

// diodeHeartbeatLogLine describes the heartbeat schedule and destination for
// the startup log.
func (s *LowServer) diodeHeartbeatLogLine() string {
	if s.cfg.DiodeHeartbeat <= 0 {
		return heartbeatIntervalStatus(0)
	}
	return fmt.Sprintf("%s → %s", heartbeatIntervalStatus(s.cfg.DiodeHeartbeat), s.diodeHeartbeatDestination())
}

// runDiodeHeartbeats emits the stream-index heartbeat on its configured
// interval until ctx is cancelled — one immediately, so a freshly started high
// side does not wait a full interval to learn the low side's indexes. Send
// failures are logged and retried on the next tick: a heartbeat is periodic by
// nature, so a lost one costs one interval of staleness, nothing more.
func (s *LowServer) runDiodeHeartbeats(ctx context.Context) {
	interval := s.cfg.DiodeHeartbeat
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		recoverWorkerPanic("diode heartbeat", func() {
			if err := s.sendDiodeHeartbeat(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
				log.Printf("diode heartbeat: %v", err)
			}
		})
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// -----------------------------------------------------------------------------
// High side: verification and the last-heartbeat record
// -----------------------------------------------------------------------------

// diodeHeartbeatReceiver verifies heartbeat datagrams against the low side's
// public key and records the accepted ones. It is driven by the catcher's
// single receive goroutine; only the record hook needs its own locking.
type diodeHeartbeatReceiver struct {
	pub      ed25519.PublicKey
	record   func(hb diodeHeartbeat, now time.Time) bool
	accepted int64
	dropped  int64
}

// handle verifies one heartbeat datagram and hands it to the record hook,
// logging rejections (throttled) so a persistent problem is visible without
// flooding the log.
func (r *diodeHeartbeatReceiver) handle(b []byte, now time.Time) {
	hb, err := parseDiodeHeartbeatPacket(r.pub, b)
	if err == nil && !r.record(hb, now) {
		err = errors.New("older than the already-recorded heartbeat (replay?)")
	}
	if err != nil {
		r.dropped++
		if r.dropped <= 3 || r.dropped%1024 == 0 {
			log.Printf("diode catch: dropped heartbeat: %v (%d dropped so far)", err, r.dropped)
		}
		return
	}
	r.accepted++
}

// diodeHeartbeatState is the high side's record of the last verified low-side
// heartbeat, read by the import status (dashboard, /admin/status, /metrics).
// The zero value is a server that has received none.
type diodeHeartbeatState struct {
	mu         sync.Mutex
	received   bool
	receivedAt time.Time
	hb         diodeHeartbeat
}

// recordHeartbeat stores a verified heartbeat and reports whether it was
// accepted, and whether it was the first ever accepted (for one startup-style
// log line however the heartbeat arrived). One created earlier than the
// stored heartbeat is a replay and is refused while the stored one is fresh
// (diodeHeartbeatReplayWindow).
func (h *diodeHeartbeatState) recordHeartbeat(hb diodeHeartbeat, now time.Time) (accepted, first bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.received && hb.Created.Before(h.hb.Created) && now.Sub(h.receivedAt) < diodeHeartbeatReplayWindow {
		return false, false
	}
	first = !h.received
	h.received, h.receivedAt, h.hb = true, now, hb
	return true, first
}

// diodeHeartbeatSnapshot is a copy of the heartbeat state for status builders
// to read without holding the lock.
type diodeHeartbeatSnapshot struct {
	received   bool
	receivedAt time.Time
	hb         diodeHeartbeat
}

func (h *diodeHeartbeatState) snapshot() diodeHeartbeatSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return diodeHeartbeatSnapshot{received: h.received, receivedAt: h.receivedAt, hb: h.hb}
}

// status renders the snapshot for the import status; nil until a heartbeat has
// been received.
func (snap diodeHeartbeatSnapshot) status(now time.Time) *DiodeHeartbeatStatus {
	if !snap.received {
		return nil
	}
	age := int64(now.Sub(snap.receivedAt).Seconds())
	if age < 0 {
		age = 0
	}
	return &DiodeHeartbeatStatus{
		ReceivedAt: snap.receivedAt,
		AgeSeconds: age,
		Created:    snap.hb.Created,
		LowVersion: snap.hb.Generator,
	}
}

// recordDiodeHeartbeat funnels every transport's verified heartbeat — a UDP
// datagram, an HTTP ingest PUT, a file from the landing directory — into the
// one record the import status reads, logging the first arrival however it
// came.
func (s *HighServer) recordDiodeHeartbeat(hb diodeHeartbeat, now time.Time, via string) bool {
	accepted, first := s.heartbeat.recordHeartbeat(hb, now)
	if first {
		log.Printf("diode heartbeat: low side reporting stream indexes via %s (low side %s, %d stream(s) exported)", via, hb.Generator, len(hb.Streams))
	}
	return accepted
}

// consumeLandingHeartbeat picks up a heartbeat file deposited in the landing
// directory by a folder carrier (or a file-moving diode proxy), verifies and
// records it, and removes it — one file is one delivery, like one datagram,
// so a lingering file cannot keep refreshing the heartbeat's age after the
// low side goes quiet. An unverifiable file is left in place briefly (the
// carrier may still be writing it) and removed once past the grace, so junk
// cannot squat in landing. Called from the mutating import pass only:
// read-only status paths must not delete files.
func (s *HighServer) consumeLandingHeartbeat(now time.Time) {
	path := filepath.Join(s.cfg.Landing, diodeHeartbeatFileName)
	b, err := readFileLimit(path, diodeMaxHeartbeatPacketBytes)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		var hb diodeHeartbeat
		if hb, err = parseDiodeHeartbeatPacket(s.publicKey, b); err == nil {
			// A replay-refused heartbeat is still consumed — the file carried
			// its one delivery either way. Racing a carrier that replaced the
			// file between read and remove loses at most one interval's
			// heartbeat; the next arrives on schedule.
			s.recordDiodeHeartbeat(hb, now, "the landing directory")
			_ = os.Remove(path)
			return
		}
	}
	if removeIfOlder(path, now.Add(-diodeHeartbeatFileGrace)) {
		log.Printf("diode heartbeat: removed unverifiable heartbeat file from landing after %s: %v", diodeHeartbeatFileGrace, err)
	}
}

// envHeartbeatInterval reads the heartbeat interval from the named variable:
// a Go duration of at least a second, or "off"/"0" to disable; empty means
// the default.
func envHeartbeatInterval(name string) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(name))
	switch strings.ToLower(v) {
	case "":
		return diodeDefaultHeartbeatInterval, nil
	case "0", "off", "false", "no":
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration (like 30s or 5m; \"off\" disables)", name, v)
	}
	if d < time.Second {
		return 0, fmt.Errorf("%s must be at least 1s, got %s", name, d)
	}
	return d, nil
}

// withHeartbeatStreams returns the sorted union of the known streams and the
// heartbeat's streams, so a stream whose every bundle was lost on the diode —
// nothing imported, nothing landed — still appears in the status as awaiting.
func withHeartbeatStreams(streams []string, hb map[string]int64) []string {
	if len(hb) == 0 {
		return streams
	}
	have := make(map[string]bool, len(streams))
	for _, stream := range streams {
		have[stream] = true
	}
	out := streams
	for stream := range hb {
		if !have[stream] {
			out = append(out, stream)
		}
	}
	sort.Strings(out)
	return out
}
