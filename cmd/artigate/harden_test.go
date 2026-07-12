package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListenAddrIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{":8080", false},
		{"", false},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{"127.0.0.1:8080", true},
		{"127.0.0.1", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"LocalHost:8080", true},
		{"192.168.1.10:8080", false},
		{"example.com:8080", false}, // an unresolved hostname is treated as non-loopback
	}
	for _, c := range cases {
		if got := listenAddrIsLoopback(c.addr); got != c.want {
			t.Errorf("listenAddrIsLoopback(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestRemoteAddrIsLoopback(t *testing.T) {
	cases := []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:5555", true},
		{"[::1]:5555", true},
		{"192.168.0.5:5555", false},
		{"10.0.0.1:80", false},
		{"", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if got := remoteAddrIsLoopback(r); got != c.want {
			t.Errorf("remoteAddrIsLoopback(%q) = %v, want %v", c.remote, got, c.want)
		}
	}
}

// TestGuardLowExposureSafePaths confirms the fail-closed guard returns normally
// (does not log.Fatal, which would abort the test binary) for every deployment
// that is actually safe.
func TestGuardLowExposureSafePaths(t *testing.T) {
	t.Setenv("ARTIGATE_LOW_ALLOW_UNAUTHENTICATED", "")
	t.Setenv("ARTIGATE_LOW_COOKIE_SECURE", "")
	// Loopback bind without auth is fine.
	guardLowExposure("127.0.0.1:8080", false, tlsUnencrypted)
	// Non-loopback WITH auth is fine (a plaintext warning may print, no fatal).
	guardLowExposure(":8080", true, tlsUnencrypted)
	// Non-loopback with auth and TLS is fully fine.
	guardLowExposure(":8080", true, tlsACME)
	// Non-loopback without auth but explicitly acknowledged.
	t.Setenv("ARTIGATE_LOW_ALLOW_UNAUTHENTICATED", "true")
	guardLowExposure(":8080", false, tlsUnencrypted)
}

// TestUnverifiedTransportBytesExcept proves the single quota totals landing +
// quarantine + rejected (so a bundle swept out of landing before verification
// still counts), and that the skip predicate excludes in-progress temp files.
func TestUnverifiedTransportBytesExcept(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	rejected := filepath.Join(hs.cfg.Root, "rejected")
	mustMkdir(t, rejected)

	write := func(dir, name string, size int) {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(hs.cfg.Landing, "go-bundle-000001.tar.gz", 100)
	write(hs.cfg.Landing, "go-bundle-000001.tar.gz.udp-tmp", 999) // in-progress temp, must be skipped
	write(hs.cfg.Quarantine, "go-bundle-000005.tar.gz", 200)
	write(rejected, "go-bundle-000009.tar.gz", 400)

	// Without a skip, everything (including the temp file) counts.
	total, err := hs.unverifiedTransportBytes()
	if err != nil {
		t.Fatal(err)
	}
	if total != 100+999+200+400 {
		t.Errorf("unverifiedTransportBytes = %d, want %d", total, 100+999+200+400)
	}

	// The UDP path skips its own temp files but still counts quarantine+rejected.
	got, err := hs.unverifiedTransportBytesExcept(isUDPTempName)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(100 + 200 + 400); got != want {
		t.Errorf("unverifiedTransportBytesExcept(isUDPTempName) = %d, want %d (landing-minus-temp + quarantine + rejected)", got, want)
	}
}

// TestDiodeQuotaCountsSweptOutBundles is the regression test for the UDP quota
// bypass: even with an EMPTY landing directory, the assembler must refuse a new
// transfer when the shared quota (which includes quarantine/rejected) is already
// exhausted. Before the fix it measured only landing and would keep accepting.
func TestDiodeQuotaCountsSweptOutBundles(t *testing.T) {
	pl := testDiodePlan(t)
	dir := t.TempDir() // landing: deliberately empty
	const name = "go-bundle-000042.tar.gz"

	asm := newDiodeAssembler(dir, validBundleFileName, nil)
	// Simulate quarantine+rejected already holding the full quota.
	asm.measureStored = func() (int64, error) { return diodeMaxUnverifiedBytes, nil }

	for _, pkt := range collectDiodePackets(t, name, testContent(pl.blockDataSize()), pl) {
		asm.handleDatagram(pkt, time.Now())
	}
	if fileExists(filepath.Join(dir, name)) {
		t.Fatal("a transfer was accepted although the shared unverified quota was already exhausted")
	}
	if asm.stats.dropped == 0 {
		t.Fatal("quota-refused packets must be counted as dropped")
	}
}

// TestHighAdminMutationGate confirms the high side's state-changing admin
// endpoints reject non-loopback callers by default and honour the override.
func TestHighAdminMutationGate(t *testing.T) {
	pub, _ := newTestKeys(t)

	post := func(hs *HighServer, path, remote string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		hs.serveHighAdmin(w, r)
		return w.Code
	}

	hs := newTestHighServer(t, pub)
	for _, path := range []string{"/admin/import", "/admin/uploads/delete"} {
		if code := post(hs, path, "203.0.113.7:44444"); code != http.StatusForbidden {
			t.Errorf("remote POST %s = %d, want 403", path, code)
		}
		// A loopback caller passes the gate (it then fails later for its own
		// reasons — a missing file, etc. — but never 403).
		if code := post(hs, path, "127.0.0.1:44444"); code == http.StatusForbidden {
			t.Errorf("loopback POST %s = 403, want it past the gate", path)
		}
	}

	// With the override, a remote caller passes the gate too.
	cfg := HighConfig{Root: t.TempDir(), Landing: t.TempDir(), AllowRemoteAdmin: true}
	hsOpen, err := NewHighServer(cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	if code := post(hsOpen, "/admin/import", "203.0.113.7:44444"); code == http.StatusForbidden {
		t.Error("override set but remote /admin/import still 403")
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}
