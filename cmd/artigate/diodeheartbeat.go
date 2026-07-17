package main

// The built-in UDP diode's heartbeat. A one-way fiber gives the high side no
// way to ask "what should I have?": it only learns a bundle exists when
// (part of) it arrives, so a bundle whose every datagram is lost — or a low
// side that stopped exporting — is invisible to /admin/missing, which can
// only report gaps behind bundles that did arrive. The pitcher therefore
// periodically broadcasts a tiny heartbeat datagram carrying each stream's
// newest committed sequence number; the catcher verifies it and the high side
// compares the reported indexes against what it has imported or holds in
// landing/quarantine, surfacing bundles that left the low side but never
// arrived (the dashboard's "awaiting" column, /admin/status, and /metrics).
//
// Heartbeats are trusted only as far as their signature: the payload is
// signed with the low side's Ed25519 key (Ed25519ph with a dedicated context
// string, so a heartbeat signature can never be replayed as a manifest
// signature or vice versa), and the catcher verifies before recording. A
// replayed old heartbeat is refused while a newer one is fresh, so an on-wire
// attacker cannot mask progress; the guard relaxes once the last accepted
// heartbeat goes stale, so a low-side clock reset cannot blind monitoring
// forever. Heartbeats influence monitoring only — never what is imported or
// served.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
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

	// diodeDefaultHeartbeatInterval is how often the pitcher broadcasts when
	// ARTIGATE_PITCHER_HEARTBEAT is unset.
	diodeDefaultHeartbeatInterval = 30 * time.Second
	// diodeHeartbeatReplayWindow is how long the created-time monotonicity
	// guard holds: within it an older heartbeat is a replay and is dropped;
	// past it the stored heartbeat is stale anyway, so a re-send — even one
	// stamped by a reset low-side clock — is better than staying blind.
	diodeHeartbeatReplayWindow = 10 * time.Minute
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

// sendDiodeHeartbeat signs and transmits one heartbeat datagram.
func (s *LowServer) sendDiodeHeartbeat(now time.Time) error {
	pkt, err := marshalDiodeHeartbeatPacket(s.privateKey, s.buildDiodeHeartbeat(now))
	if err != nil {
		return err
	}
	return s.pitcher.sendHeartbeat(pkt)
}

// heartbeatIntervalStatus renders the startup-log description of the
// heartbeat schedule.
func heartbeatIntervalStatus(interval time.Duration) string {
	if interval <= 0 {
		return "disabled (ARTIGATE_PITCHER_HEARTBEAT=off)"
	}
	return fmt.Sprintf("stream indexes broadcast every %s", interval)
}

// runDiodeHeartbeats broadcasts the stream-index heartbeat on its configured
// interval until ctx is cancelled — one immediately, so a freshly started high
// side does not wait a full interval to learn the low side's indexes. Send
// failures are logged and retried on the next tick: a heartbeat is periodic by
// nature, so a lost one costs one interval of staleness, nothing more.
func (s *LowServer) runDiodeHeartbeats(ctx context.Context) {
	interval := s.pitcher.cfg.Heartbeat
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		recoverWorkerPanic("diode heartbeat", func() {
			if err := s.sendDiodeHeartbeat(time.Now().UTC()); err != nil {
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
// logging the first acceptance and (throttled) rejections so a persistent
// problem is visible without flooding the log.
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
	if r.accepted == 1 {
		log.Printf("diode catch: low-side heartbeat received (low side %s, %d stream(s) exported)", hb.Generator, len(hb.Streams))
	}
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
// accepted. One created earlier than the stored heartbeat is a replay and is
// refused while the stored one is fresh (diodeHeartbeatReplayWindow).
func (h *diodeHeartbeatState) recordHeartbeat(hb diodeHeartbeat, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.received && hb.Created.Before(h.hb.Created) && now.Sub(h.receivedAt) < diodeHeartbeatReplayWindow {
		return false
	}
	h.received, h.receivedAt, h.hb = true, now, hb
	return true
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
