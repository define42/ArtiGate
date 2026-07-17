package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testHeartbeat(streams map[string]int64) diodeHeartbeat {
	return diodeHeartbeat{
		Type:      diodeHeartbeatType,
		Created:   time.Now().UTC(),
		Generator: "test-low",
		Streams:   streams,
	}
}

func TestDiodeHeartbeatPacketRoundtrip(t *testing.T) {
	pub, priv := newTestKeys(t)
	hb := testHeartbeat(map[string]int64{streamGo: 42, streamHF: 7})
	pkt, err := marshalDiodeHeartbeatPacket(priv, hb)
	if err != nil {
		t.Fatal(err)
	}
	if !isDiodeHeartbeatDatagram(pkt) {
		t.Fatal("heartbeat packet not recognized by its magic")
	}
	got, err := parseDiodeHeartbeatPacket(pub, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Created.Equal(hb.Created) || got.Generator != hb.Generator ||
		len(got.Streams) != 2 || got.Streams[streamGo] != 42 || got.Streams[streamHF] != 7 {
		t.Fatalf("roundtrip mismatch:\n in: %+v\nout: %+v", hb, got)
	}

	// A bundle data datagram must never be routed as a heartbeat.
	data, err := marshalDiodePacket(nil, &diodePacket{
		Name: "go-bundle-000001.tar.gz", FileSize: 8, BlockCount: 1, BlockLen: 8,
		ShardSize: 8, DataShards: 1, ParityShards: 1, Shard: []byte("12345678"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if isDiodeHeartbeatDatagram(data) {
		t.Fatal("bundle datagram matched the heartbeat magic")
	}

	otherPub, _ := newTestKeys(t)
	cases := map[string]func([]byte) []byte{
		"truncated to header":    func(b []byte) []byte { return b[:diodeHeartbeatHeaderSize] },
		"flipped payload byte":   func(b []byte) []byte { b[len(b)-2] ^= 1; return b },
		"flipped signature byte": func(b []byte) []byte { b[10] ^= 1; return b },
		"future wire version":    func(b []byte) []byte { b[4] = 99; return b },
	}
	for name, breakIt := range cases {
		dup := append([]byte(nil), pkt...)
		if _, err := parseDiodeHeartbeatPacket(pub, breakIt(dup)); err == nil {
			t.Errorf("%s: parse accepted a broken heartbeat", name)
		}
	}
	if _, err := parseDiodeHeartbeatPacket(otherPub, pkt); err == nil {
		t.Error("a heartbeat signed by a different key verified")
	}
}

// TestDiodeHeartbeatPayloadValidation drives the signed-but-wrong payload
// paths: the signature alone must not make a payload acceptable.
func TestDiodeHeartbeatPayloadValidation(t *testing.T) {
	pub, priv := newTestKeys(t)

	t.Run("wrong type refused", func(t *testing.T) {
		hb := testHeartbeat(nil)
		hb.Type = "artigate-something-else"
		pkt, err := marshalDiodeHeartbeatPacket(priv, hb)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseDiodeHeartbeatPacket(pub, pkt); err == nil || !strings.Contains(err.Error(), "wrong heartbeat type") {
			t.Fatalf("parse = %v, want wrong-type error", err)
		}
	})

	t.Run("missing created refused", func(t *testing.T) {
		hb := testHeartbeat(nil)
		hb.Created = time.Time{}
		pkt, err := marshalDiodeHeartbeatPacket(priv, hb)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseDiodeHeartbeatPacket(pub, pkt); err == nil {
			t.Fatal("a heartbeat without a created time was accepted")
		}
	})

	t.Run("unknown streams and bad sequences filtered", func(t *testing.T) {
		pkt, err := marshalDiodeHeartbeatPacket(priv, testHeartbeat(map[string]int64{
			streamGo: 5, "not-a-stream": 9, streamNpm: 0, streamHF: -3,
		}))
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseDiodeHeartbeatPacket(pub, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Streams) != 1 || got.Streams[streamGo] != 5 {
			t.Fatalf("streams = %v, want only go:5", got.Streams)
		}
	})

	t.Run("oversized payload refused on both sides", func(t *testing.T) {
		hb := testHeartbeat(nil)
		hb.Generator = strings.Repeat("x", diodeMaxHeartbeatBytes)
		if _, err := marshalDiodeHeartbeatPacket(priv, hb); err == nil {
			t.Fatal("marshal accepted an oversized payload")
		}
		big := make([]byte, diodeHeartbeatHeaderSize+diodeMaxHeartbeatBytes+1)
		binary.BigEndian.PutUint32(big, diodeHeartbeatMagic)
		big[4] = diodeHeartbeatVersion
		if _, err := parseDiodeHeartbeatPacket(pub, big); err == nil || !strings.Contains(err.Error(), "wire limit") {
			t.Fatalf("parse of oversized payload = %v, want wire-limit error (before any verification)", err)
		}
	})
}

// TestDiodeHeartbeatReplayGuard covers the created-time monotonicity rule and
// its staleness override: while the record is fresh only strictly newer
// heartbeats are taken, so neither an older replay nor an exact duplicate can
// keep the heartbeat's age looking fresh after the low side stops.
func TestDiodeHeartbeatReplayGuard(t *testing.T) {
	var st diodeHeartbeatState
	now := time.Now().UTC()
	initial := testHeartbeat(map[string]int64{streamGo: 3})
	initial.Created = now

	if accepted, first := st.recordHeartbeat(initial, now); !accepted || !first {
		t.Fatalf("initial heartbeat: accepted=%v first=%v, want both", accepted, first)
	}
	// An exact duplicate (same created time — a replayed datagram, an HTTP
	// retry, a re-copied folder file) must not refresh the record's age.
	if accepted, _ := st.recordHeartbeat(initial, now.Add(time.Minute)); accepted {
		t.Fatal("an exact duplicate was accepted while the stored one is fresh")
	}
	if snap := st.snapshot(); !snap.receivedAt.Equal(now) {
		t.Fatal("a rejected duplicate refreshed the record's received time")
	}
	replay := initial
	replay.Created = now.Add(-time.Minute)
	if accepted, _ := st.recordHeartbeat(replay, now.Add(time.Second)); accepted {
		t.Fatal("an older heartbeat was accepted while the stored one is fresh")
	}
	if snap := st.snapshot(); !snap.hb.Created.Equal(now) {
		t.Fatal("the rejected replay overwrote the stored heartbeat")
	}
	// Once the stored heartbeat is stale, even an older-stamped one is better
	// than staying blind (a low-side clock reset must not wedge monitoring).
	if accepted, first := st.recordHeartbeat(replay, now.Add(diodeHeartbeatReplayWindow+time.Second)); !accepted || first {
		t.Fatalf("staleness override: accepted=%v first=%v, want accepted and not first", accepted, first)
	}
	newer := initial
	newer.Created = now.Add(time.Hour)
	if accepted, _ := st.recordHeartbeat(newer, now.Add(2*diodeHeartbeatReplayWindow)); !accepted {
		t.Fatal("a newer heartbeat was refused")
	}
}

func TestDiodeHeartbeatReceiverHandle(t *testing.T) {
	pub, priv := newTestKeys(t)
	var recorded []diodeHeartbeat
	r := &diodeHeartbeatReceiver{pub: pub, record: func(hb diodeHeartbeat, _ time.Time) bool {
		recorded = append(recorded, hb)
		return true
	}}
	pkt, err := marshalDiodeHeartbeatPacket(priv, testHeartbeat(map[string]int64{streamGo: 1}))
	if err != nil {
		t.Fatal(err)
	}
	r.handle(pkt, time.Now())
	if r.accepted != 1 || r.dropped != 0 || len(recorded) != 1 {
		t.Fatalf("accepted=%d dropped=%d recorded=%d, want one acceptance", r.accepted, r.dropped, len(recorded))
	}
	corrupt := append([]byte(nil), pkt...)
	corrupt[len(corrupt)-1] ^= 1
	r.handle(corrupt, time.Now())
	if r.accepted != 1 || r.dropped != 1 || len(recorded) != 1 {
		t.Fatalf("accepted=%d dropped=%d after corruption, want it dropped", r.accepted, r.dropped)
	}

	refused := &diodeHeartbeatReceiver{pub: pub, record: func(diodeHeartbeat, time.Time) bool { return false }}
	refused.handle(pkt, time.Now())
	if refused.accepted != 0 || refused.dropped != 1 {
		t.Fatalf("record refusal not counted as dropped: %+v", refused)
	}
}

// TestCatcherRoutesHeartbeats checks the demux: with a receiver wired the
// heartbeat never touches the file reassembler; without one (transport-only
// tests, an older deployment) it is just another dropped unknown datagram.
func TestCatcherRoutesHeartbeats(t *testing.T) {
	pub, priv := newTestKeys(t)
	pkt, err := marshalDiodeHeartbeatPacket(priv, testHeartbeat(map[string]int64{streamGo: 1}))
	if err != nil {
		t.Fatal(err)
	}

	bare := &diodeCatcher{asm: newDiodeAssembler(t.TempDir(), validBundleFileName, nil)}
	bare.handleDatagram(pkt, time.Now())
	if bare.asm.stats.dropped != 1 {
		t.Fatalf("without a receiver the heartbeat should be an ordinary dropped datagram, stats %+v", bare.asm.stats)
	}

	r := &diodeHeartbeatReceiver{pub: pub, record: func(diodeHeartbeat, time.Time) bool { return true }}
	wired := &diodeCatcher{asm: newDiodeAssembler(t.TempDir(), validBundleFileName, nil), hb: r}
	wired.handleDatagram(pkt, time.Now())
	if r.accepted != 1 || wired.asm.stats.packets != 0 || wired.asm.stats.dropped != 0 {
		t.Fatalf("heartbeat not routed to the receiver (receiver %+v, asm %+v)", r, wired.asm.stats)
	}
}

func TestLowServerHeartbeatIndexes(t *testing.T) {
	ls := newBareLowServer(t)
	if got := ls.lastExportedSequences(); len(got) != 0 {
		t.Fatalf("fresh server reports exported streams: %v", got)
	}
	for _, c := range []struct {
		stream string
		seq    int64
	}{{streamGo, 1}, {streamGo, 2}, {streamHF, 1}} {
		if err := ls.commitSequence(c.stream, c.seq); err != nil {
			t.Fatal(err)
		}
	}
	hb := ls.buildDiodeHeartbeat(time.Unix(1700000000, 0).UTC())
	if hb.Type != diodeHeartbeatType || hb.Generator != versionString() {
		t.Fatalf("heartbeat identity = %+v", hb)
	}
	if len(hb.Streams) != 2 || hb.Streams[streamGo] != 2 || hb.Streams[streamHF] != 1 {
		t.Fatalf("streams = %v, want go:2 hf:1", hb.Streams)
	}
}

// TestHighStatusWithHeartbeat is the identify-missing-bundles core: the
// heartbeat extends the status beyond what disk can show — the tail that
// never arrived, and whole streams nothing has arrived for.
func TestHighStatusWithHeartbeat(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// Import go #1; land future go #4 (quarantined behind the 2-3 gap).
	writeSignedBundle(t, hs.cfg.Landing, priv, 1, 0, []moduleSpec{{"example.com/a", "v1.0.0"}})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	writeSignedStreamBundle(t, hs.cfg.Landing, priv, streamGo, 4, 3)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}

	st, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.DiodeHeartbeat != nil {
		t.Fatalf("heartbeat status before any heartbeat: %+v", st.DiodeHeartbeat)
	}

	// The low side reports go at #6 (5-6 still crossing) and npm at #2 —
	// a stream this high side has seen nothing of.
	hb := testHeartbeat(map[string]int64{streamGo: 6, streamNpm: 2})
	if accepted, _ := hs.heartbeat.recordHeartbeat(hb, time.Now().UTC()); !accepted {
		t.Fatal("heartbeat refused")
	}
	if st, err = hs.ImportStatus(); err != nil {
		t.Fatal(err)
	}
	if st.DiodeHeartbeat == nil || st.DiodeHeartbeat.LowVersion != "test-low" ||
		!st.DiodeHeartbeat.Created.Equal(hb.Created) || st.DiodeHeartbeat.AgeSeconds < 0 {
		t.Fatalf("heartbeat status = %+v", st.DiodeHeartbeat)
	}

	goSt := st.Stream(streamGo)
	if goSt.LowLastSequence != 6 || strings.Join(goSt.MissingRanges, ",") != "2-3" ||
		strings.Join(goSt.AwaitingFromLow, ",") != "5-6" {
		t.Fatalf("go stream = %+v, want low 6, missing 2-3, awaiting 5-6", goSt)
	}
	npmSt := st.Stream(streamNpm)
	if npmSt.LastImportedSequence != 0 || npmSt.LowLastSequence != 2 ||
		strings.Join(npmSt.AwaitingFromLow, ",") != "1-2" || len(npmSt.MissingRanges) != 0 {
		t.Fatalf("npm stream = %+v, want a heartbeat-only stream awaiting 1-2", npmSt)
	}
	hfSt := st.Stream(streamHF)
	if hfSt.Stream == streamHF && (hfSt.LowLastSequence != 0 || hfSt.AwaitingFromLow != nil) {
		t.Fatalf("hf stream gained heartbeat fields it should not have: %+v", hfSt)
	}

	// A heartbeat older than the newest arrival adds nothing: no awaiting.
	if accepted, _ := hs.heartbeat.recordHeartbeat(testHeartbeat(map[string]int64{streamGo: 3}), time.Now().UTC()); !accepted {
		t.Fatal("newer heartbeat refused")
	}
	if st, err = hs.ImportStatus(); err != nil {
		t.Fatal(err)
	}
	if goSt = st.Stream(streamGo); goSt.LowLastSequence != 3 || goSt.AwaitingFromLow != nil {
		t.Fatalf("stale-index heartbeat produced awaiting ranges: %+v", goSt)
	}
}

// TestHighHeartbeatOnMonitoringEndpoints checks the operator-facing surfaces:
// /metrics gains the heartbeat and awaiting gauges, /admin/status the JSON.
func TestHighHeartbeatOnMonitoringEndpoints(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)

	_, before := httpGet(t, srv.URL+"/metrics")
	if strings.Contains(before, "artigate_high_diode_heartbeat_timestamp_seconds") {
		t.Fatal("heartbeat metrics present before any heartbeat")
	}

	if accepted, _ := hs.heartbeat.recordHeartbeat(testHeartbeat(map[string]int64{streamGo: 3}), time.Now().UTC()); !accepted {
		t.Fatal("heartbeat refused")
	}
	_, metrics := httpGet(t, srv.URL+"/metrics")
	for _, want := range []string{
		"artigate_high_diode_heartbeat_timestamp_seconds",
		"artigate_high_diode_heartbeat_age_seconds",
		`artigate_high_low_last_sequence{stream="go"} 3`,
		`artigate_high_bundles_awaiting_from_low{stream="go"} 3`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics is missing %q", want)
		}
	}

	_, status := httpGet(t, srv.URL+"/admin/status")
	for _, want := range []string{`"low_last_sequence": 3`, `"awaiting_from_low"`, `"diode_heartbeat"`} {
		if !strings.Contains(status, want) {
			t.Errorf("/admin/status is missing %q in %s", want, status)
		}
	}
}

// TestEnvHeartbeatInterval covers the ARTIGATE_DIODE_HEARTBEAT parsing rules.
func TestEnvHeartbeatInterval(t *testing.T) {
	const name = "ARTIGATE_DIODE_HEARTBEAT"
	if d, err := envHeartbeatInterval(name); err != nil || d != diodeDefaultHeartbeatInterval {
		t.Fatalf("unset = %s, %v; want the default", d, err)
	}
	t.Setenv(name, "2m")
	if d, err := envHeartbeatInterval(name); err != nil || d != 2*time.Minute {
		t.Fatalf("2m = %s, %v", d, err)
	}
	t.Setenv(name, "off")
	if d, err := envHeartbeatInterval(name); err != nil || d != 0 {
		t.Fatalf("off = %s, %v; want disabled", d, err)
	}
	for _, bad := range []string{"soonish", "100ms", "-30s"} {
		t.Setenv(name, bad)
		if _, err := envHeartbeatInterval(name); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// TestSendDiodeHeartbeatFolderMode checks the default transport: with neither
// pitcher nor HTTP endpoint configured, the heartbeat is written into the
// export dir as one more file for the folder carrier, and each send replaces
// the previous one.
func TestSendDiodeHeartbeatFolderMode(t *testing.T) {
	ls := newBareLowServer(t)
	if err := ls.commitSequence(streamGo, 1); err != nil {
		t.Fatal(err)
	}
	if err := ls.sendDiodeHeartbeat(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("sendDiodeHeartbeat: %v", err)
	}
	path := filepath.Join(ls.cfg.ExportDir, diodeHeartbeatFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("heartbeat file not written: %v", err)
	}
	pub := ls.privateKey.Public().(ed25519.PublicKey)
	hb, err := parseDiodeHeartbeatPacket(pub, b)
	if err != nil {
		t.Fatalf("written heartbeat does not verify: %v", err)
	}
	if len(hb.Streams) != 1 || hb.Streams[streamGo] != 1 {
		t.Fatalf("streams = %v, want go:1", hb.Streams)
	}

	// A later send overwrites in place — the spool never accumulates them.
	if err := ls.commitSequence(streamGo, 2); err != nil {
		t.Fatal(err)
	}
	if err := ls.sendDiodeHeartbeat(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if b, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	if hb, err = parseDiodeHeartbeatPacket(pub, b); err != nil || hb.Streams[streamGo] != 2 {
		t.Fatalf("second send = %v, %v; want go:2", hb.Streams, err)
	}
	// The heartbeat file must never look like a bundle to the spool scans.
	if streams, err := findBundleStreams(ls.cfg.ExportDir); err != nil || len(streams) != 0 {
		t.Fatalf("heartbeat file confused the bundle scan: %v, %v", streams, err)
	}
}

// TestLowToHighHeartbeatOverHTTPDiode is the HTTP path end to end: the low
// side PUTs the heartbeat to the diode endpoint, the high side verifies and
// records it in memory — nothing lands on disk — and the import status
// reports the low side's indexes exactly like the UDP path does.
func TestLowToHighHeartbeatOverHTTPDiode(t *testing.T) {
	ls := newBareLowServer(t)
	if err := ls.commitSequence(streamGo, 2); err != nil {
		t.Fatal(err)
	}
	hs := newTestHighServer(t, ls.privateKey.Public().(ed25519.PublicKey))
	token := strings.Repeat("s", minDiodeTokenBytes)
	hs.cfg.DiodeIngest = true
	hs.cfg.DiodeToken = token
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)
	ls.cfg.DiodeURL = srv.URL + "/diode"
	ls.cfg.DiodeToken = token

	if err := ls.sendDiodeHeartbeat(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("sendDiodeHeartbeat over HTTP: %v", err)
	}
	st, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.DiodeHeartbeat == nil {
		t.Fatal("heartbeat did not reach the import status")
	}
	if goSt := st.Stream(streamGo); goSt.LowLastSequence != 2 || strings.Join(goSt.AwaitingFromLow, ",") != "1-2" {
		t.Fatalf("go stream = %+v, want low 2, awaiting 1-2", goSt)
	}
	entries, err := os.ReadDir(hs.cfg.Landing)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("an HTTP heartbeat touched the landing directory: %v", entries)
	}
}

// TestDiodeIngestHeartbeatValidation drives the ingest endpoint's heartbeat
// branch through its refusals: the token gate still applies, unverifiable
// bytes are 400s, oversized bodies are cut off, and a verified-but-older
// heartbeat is acknowledged without replacing the record.
func TestDiodeIngestHeartbeatValidation(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	token := strings.Repeat("t", minDiodeTokenBytes)
	hs.cfg.DiodeIngest = true
	hs.cfg.DiodeToken = token
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)

	put := func(t *testing.T, body []byte, withToken bool) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, srv.URL+"/diode/"+diodeHeartbeatFileName, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if withToken {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return resp.StatusCode, b.String()
	}

	newer := testHeartbeat(map[string]int64{streamGo: 5})
	newerPkt, err := marshalDiodeHeartbeatPacket(priv, newer)
	if err != nil {
		t.Fatal(err)
	}

	if code, _ := put(t, newerPkt, false); code != http.StatusUnauthorized {
		t.Fatalf("missing token = HTTP %d, want 401", code)
	}
	if code, _ := put(t, []byte("junk"), true); code != http.StatusBadRequest {
		t.Fatalf("garbage body = HTTP %d, want 400", code)
	}
	if code, _ := put(t, make([]byte, diodeMaxHeartbeatPacketBytes+1), true); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = HTTP %d, want 413", code)
	}
	if code, body := put(t, newerPkt, true); code != http.StatusOK || !strings.Contains(body, "recorded") {
		t.Fatalf("valid heartbeat = HTTP %d %q, want recorded", code, body)
	}

	older := testHeartbeat(map[string]int64{streamGo: 1})
	older.Created = newer.Created.Add(-time.Hour)
	olderPkt, err := marshalDiodeHeartbeatPacket(priv, older)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := put(t, olderPkt, true); code != http.StatusOK || !strings.Contains(body, "ignored") {
		t.Fatalf("replayed heartbeat = HTTP %d %q, want acknowledged but ignored", code, body)
	}
	if snap := hs.heartbeat.snapshot(); !snap.hb.Created.Equal(newer.Created) {
		t.Fatal("a replayed older heartbeat replaced the record")
	}
}

// TestConsumeLandingHeartbeat covers the folder transport's high side: a
// heartbeat file in landing is verified, recorded, and consumed by the import
// pass; an unverifiable file survives the grace (a carrier may still be
// writing it) and is removed once past it.
func TestConsumeLandingHeartbeat(t *testing.T) {
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	path := filepath.Join(hs.cfg.Landing, diodeHeartbeatFileName)

	pkt, err := marshalDiodeHeartbeatPacket(priv, testHeartbeat(map[string]int64{streamGo: 4}))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, pkt)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	st, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.DiodeHeartbeat == nil || st.Stream(streamGo).LowLastSequence != 4 {
		t.Fatalf("landing heartbeat not recorded: %+v", st.DiodeHeartbeat)
	}
	if fileExists(path) {
		t.Fatal("consumed heartbeat file still in landing")
	}

	// Unverifiable bytes: kept while fresh (the carrier may still be writing),
	// reaped once older than the grace.
	writeFile(t, path, []byte("junk"))
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	if !fileExists(path) {
		t.Fatal("a fresh unverifiable heartbeat file was removed before the grace")
	}
	old := time.Now().Add(-diodeHeartbeatFileGrace - time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	if fileExists(path) {
		t.Fatal("an unverifiable heartbeat file survived past the grace")
	}
}

// TestDiodeHeartbeatParseEdgeCases covers the parse refusals that need
// hand-built packets: a wrong magic at a valid length, and a correctly signed
// payload that is not JSON (the signature alone must not admit it).
func TestDiodeHeartbeatParseEdgeCases(t *testing.T) {
	pub, priv := newTestKeys(t)

	pkt, err := marshalDiodeHeartbeatPacket(priv, testHeartbeat(nil))
	if err != nil {
		t.Fatal(err)
	}
	wrongMagic := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint32(wrongMagic, diodeMagic) // a data-plane magic, right length
	if _, err := parseDiodeHeartbeatPacket(pub, wrongMagic); err == nil || !strings.Contains(err.Error(), "bad magic") {
		t.Fatalf("wrong magic = %v, want bad-magic error", err)
	}

	payload := []byte("this is not json")
	digest := sha512.Sum512(payload)
	sig, err := priv.Sign(nil, digest[:], diodeHeartbeatSignOpts())
	if err != nil {
		t.Fatal(err)
	}
	notJSON := make([]byte, diodeHeartbeatHeaderSize+len(payload))
	binary.BigEndian.PutUint32(notJSON, diodeHeartbeatMagic)
	notJSON[4] = diodeHeartbeatVersion
	copy(notJSON[5:], sig)
	copy(notJSON[diodeHeartbeatHeaderSize:], payload)
	if _, err := parseDiodeHeartbeatPacket(pub, notJSON); err == nil || !strings.Contains(err.Error(), "decode heartbeat payload") {
		t.Fatalf("signed non-JSON payload = %v, want decode error", err)
	}
}

// TestUploadHeartbeatToHTTPDiodeErrors covers the HTTP send's failure
// reporting: an unreachable endpoint and a non-2xx answer, both surfaced with
// the file name and — for HTTP errors — the status and body detail.
func TestUploadHeartbeatToHTTPDiodeErrors(t *testing.T) {
	ls := newBareLowServer(t)

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	ls.cfg.DiodeURL = dead.URL
	err := ls.sendDiodeHeartbeat(context.Background(), time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "PUT "+diodeHeartbeatFileName) {
		t.Fatalf("unreachable endpoint = %v, want a PUT error", err)
	}

	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "spool full", http.StatusInsufficientStorage)
	}))
	t.Cleanup(refusing.Close)
	ls.cfg.DiodeURL = refusing.URL
	err = ls.sendDiodeHeartbeat(context.Background(), time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "HTTP 507") || !strings.Contains(err.Error(), "spool full") {
		t.Fatalf("refused upload = %v, want the HTTP status and detail", err)
	}
}

// failingReader errors on every read, standing in for a client that dies
// mid-request-body.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection torn down") }

// TestDiodeIngestHeartbeatBodyLimits drives the ingest handler's own body
// bounds, which only apply when the request declares no Content-Length (a
// declared length is rejected earlier, in validateDiodeUpload): an oversized
// chunked body is cut off at the wire limit, and a body that dies mid-read
// reports a server-side error.
func TestDiodeIngestHeartbeatBodyLimits(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	token := strings.Repeat("u", minDiodeTokenBytes)
	hs.cfg.DiodeIngest = true
	hs.cfg.DiodeToken = token

	send := func(t *testing.T, body io.Reader) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/diode/"+diodeHeartbeatFileName, body)
		req.ContentLength = -1 // chunked: the length gate cannot apply
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		hs.ServeHTTP(rec, req)
		return rec
	}

	if rec := send(t, bytes.NewReader(make([]byte, diodeMaxHeartbeatPacketBytes+1))); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked heartbeat = HTTP %d, want 413", rec.Code)
	}
	if rec := send(t, failingReader{}); rec.Code != http.StatusInternalServerError {
		t.Fatalf("failing body = HTTP %d, want 500", rec.Code)
	}
	if snap := hs.heartbeat.snapshot(); snap.received {
		t.Fatal("a refused upload recorded a heartbeat")
	}
}

// TestRunDiodeHeartbeatsFolderLoop runs the sender loop against the folder
// transport: disabled returns immediately; enabled sends once right away,
// again on the ticker, and stops on context cancellation.
func TestRunDiodeHeartbeatsFolderLoop(t *testing.T) {
	ls := newBareLowServer(t)
	ls.cfg.DiodeHeartbeat = 0
	ls.runDiodeHeartbeats(context.Background()) // disabled: must return at once

	if err := ls.commitSequence(streamGo, 1); err != nil {
		t.Fatal(err)
	}
	ls.cfg.DiodeHeartbeat = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ls.runDiodeHeartbeats(ctx)
		close(done)
	}()

	path := filepath.Join(ls.cfg.ExportDir, diodeHeartbeatFileName)
	waitForHeartbeatFile := func(t *testing.T, what string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !fileExists(path) {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("no heartbeat file appeared (%s)", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitForHeartbeatFile(t, "immediate send on start")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitForHeartbeatFile(t, "ticker-driven re-send")

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("loop did not stop on context cancellation")
	}
}

// TestDiodeHeartbeatLogHelpers pins the startup-log wording per transport and
// schedule.
func TestDiodeHeartbeatLogHelpers(t *testing.T) {
	if s := heartbeatIntervalStatus(0); !strings.Contains(s, "disabled") {
		t.Errorf("disabled status = %q", s)
	}
	if s := heartbeatIntervalStatus(30 * time.Second); !strings.Contains(s, "30s") {
		t.Errorf("interval status = %q", s)
	}

	ls := newBareLowServer(t)
	if s := ls.diodeHeartbeatLogLine(); !strings.Contains(s, "disabled") {
		t.Errorf("log line with heartbeats off = %q", s)
	}
	ls.cfg.DiodeHeartbeat = 45 * time.Second
	if s := ls.diodeHeartbeatLogLine(); !strings.Contains(s, "45s") || !strings.Contains(s, "export dir") {
		t.Errorf("folder log line = %q", s)
	}
	if d := ls.diodeHeartbeatDestination(); d != "export dir, for the folder carrier" {
		t.Errorf("folder destination = %q", d)
	}
	ls.cfg.DiodeURL = "http://diode.example"
	if d := ls.diodeHeartbeatDestination(); d != "HTTP diode endpoint" {
		t.Errorf("HTTP destination = %q", d)
	}
	ls.pitcher = &diodePitcher{}
	if d := ls.diodeHeartbeatDestination(); d != "UDP diode" {
		t.Errorf("UDP destination = %q", d)
	}
	// The placeholder pitcher has no socket; drop it before the server's
	// cleanup Close would try to close one.
	ls.pitcher = nil
}

// TestDiodeHeartbeatStatusClamps covers the negative clamps: a snapshot aged
// with a clock that moved backwards, and a heartbeat index behind what has
// already arrived (awaiting must never go negative).
func TestDiodeHeartbeatStatusClamps(t *testing.T) {
	var st diodeHeartbeatState
	now := time.Now().UTC()
	st.recordHeartbeat(testHeartbeat(nil), now)
	if s := st.snapshot().status(now.Add(-time.Minute)); s == nil || s.AgeSeconds != 0 {
		t.Fatalf("status with a backwards clock = %+v, want age clamped to 0", s)
	}

	p := newPromWriter()
	writeStreamHeartbeatMetrics(p, StreamImportStatus{Stream: streamGo, LowLastSequence: 2, HighestSeenSequence: 5})
	out := p.String()
	if !strings.Contains(out, `artigate_high_bundles_awaiting_from_low{stream="go"} 0`) {
		t.Fatalf("awaiting not clamped to 0:\n%s", out)
	}
	writeStreamHeartbeatMetrics(p, StreamImportStatus{Stream: streamHF})
	if strings.Contains(p.String(), `stream="hf"`) {
		t.Fatal("a stream without heartbeat data produced samples")
	}
}
