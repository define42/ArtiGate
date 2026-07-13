package main

// Tests for the production-readiness hardening: import error classification,
// unverified-storage reaping, low-side CSRF protection, APT token safety, and
// graceful shutdown.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Fix #1: extraction error classification -------------------------------

func TestClassifyExtractError(t *testing.T) {
	var invalid *invalidBundleError

	// An operational staging-I/O fault (e.g. a full disk) must stay retryable.
	op := classifyExtractError(&stagingIOError{err: errors.New("no space left on device")})
	if errors.As(op, &invalid) {
		t.Error("staging I/O error must not be classified as an invalid bundle")
	}

	// A content fault (hash/size/type) must be marked invalid so it is rejected.
	content := classifyExtractError(errors.New("sha256 mismatch"))
	if !errors.As(content, &invalid) {
		t.Error("content error must be classified as an invalid bundle")
	}
}

type alwaysErrWriter struct{}

func (alwaysErrWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestStagingWriterTagsWriteErrors(t *testing.T) {
	_, err := stagingWriter{w: alwaysErrWriter{}}.Write([]byte("x"))
	var ioErr *stagingIOError
	if !errors.As(err, &ioErr) {
		t.Fatalf("stagingWriter must tag write errors as stagingIOError, got %v", err)
	}
}

func TestExtractMissingArchiveIsOperational(t *testing.T) {
	err := extractAndVerifyTarGz(
		filepath.Join(t.TempDir(), "absent.tar.gz"), t.TempDir(),
		[]ManifestFile{{Path: "x", SHA256: strings.Repeat("a", 64), Size: 1}})
	var ioErr *stagingIOError
	if !errors.As(err, &ioErr) {
		t.Fatalf("an unreadable archive is operational, not an invalid bundle, got %v", err)
	}
	var invalid *invalidBundleError
	if errors.As(classifyExtractError(err), &invalid) {
		t.Error("operational open failure must not be rejected")
	}
}

// --- Fix #2: unverified-storage reaping ------------------------------------

func writeAged(t *testing.T, p string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestReapRejectedDir(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "go-bundle-000001.tar.gz")
	recent := filepath.Join(dir, "go-bundle-000002.tar.gz")
	writeAged(t, old, 2*time.Hour)
	writeAged(t, recent, 0)

	n, err := reapRejectedDir(dir, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("reaped %d, want 1", n)
	}
	if fileExists(old) {
		t.Error("aged rejected file should be reaped")
	}
	if !fileExists(recent) {
		t.Error("recent rejected file must be kept")
	}

	// A missing directory is not an error.
	if _, err := reapRejectedDir(filepath.Join(dir, "nope"), time.Now()); err != nil {
		t.Errorf("missing dir should be fine: %v", err)
	}
}

func TestReapIncompleteLanding(t *testing.T) {
	dir := t.TempDir()

	orphan := filepath.Join(dir, "go-bundle-000001.tar.gz")
	writeAged(t, orphan, 72*time.Hour)

	// A complete set, equally aged, must be kept (it is pending import).
	for _, suf := range bundleSuffixes() {
		writeAged(t, filepath.Join(dir, "go-bundle-000002"+suf), 72*time.Hour)
	}

	fresh := filepath.Join(dir, "go-bundle-000003.tar.gz")
	writeAged(t, fresh, 0)

	// UDP reassembly temp files are never reaped here.
	udp := filepath.Join(dir, "go-bundle-000004.tar.gz.udp-abc")
	writeAged(t, udp, 72*time.Hour)

	n, err := reapIncompleteLanding(dir, time.Now().Add(-incompleteLandingRetention))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("reaped %d, want 1", n)
	}
	if fileExists(orphan) {
		t.Error("aged orphan should be reaped")
	}
	if !bundleCompleteInDir(dir, "go-bundle-000002") {
		t.Error("complete pending set must be kept")
	}
	if !fileExists(fresh) {
		t.Error("fresh orphan must be kept")
	}
	if !fileExists(udp) {
		t.Error("UDP temp file must not be reaped")
	}
}

func TestRemoveIfOlderReStats(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	writeAged(t, p, 0) // fresh: newer than the cutoff, must survive
	if removeIfOlder(p, time.Now().Add(-time.Hour)) {
		t.Error("a fresh file must not be removed")
	}
	if !fileExists(p) {
		t.Error("file should still exist")
	}
}

// --- Fix #3: low-side CSRF protection --------------------------------------

func TestIsCrossSiteBrowserRequest(t *testing.T) {
	mk := func(secFetch, origin, host string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/admin/go/collect", nil)
		r.Host = host
		if secFetch != "" {
			r.Header.Set("Sec-Fetch-Site", secFetch)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	cases := []struct {
		name  string
		req   *http.Request
		cross bool
	}{
		{"same-origin fetch-metadata", mk("same-origin", "", "h"), false},
		{"none fetch-metadata", mk("none", "", "h"), false},
		{"cross-site fetch-metadata", mk("cross-site", "", "h"), true},
		{"same-site fetch-metadata", mk("same-site", "", "h"), true},
		{"non-browser (no headers)", mk("", "", "h"), false},
		{"origin matches host", mk("", "http://h", "h"), false},
		{"origin differs from host", mk("", "http://evil", "h"), true},
		{"origin without host", mk("", "http://", "h"), true},
	}
	for _, c := range cases {
		if got := isCrossSiteBrowserRequest(c.req); got != c.cross {
			t.Errorf("%s: got %v, want %v", c.name, got, c.cross)
		}
	}
}

func TestCSRFGuardLow(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	guard := csrfGuardLow(ok)

	do := func(method, secFetch string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/admin/go/collect", nil)
		if secFetch != "" {
			req.Header.Set("Sec-Fetch-Site", secFetch)
		}
		guard.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(http.MethodPost, "cross-site"); code != http.StatusForbidden {
		t.Errorf("cross-site POST: got %d, want 403", code)
	}
	if code := do(http.MethodPost, "same-origin"); code != http.StatusOK {
		t.Errorf("same-origin POST: got %d, want 200", code)
	}
	if code := do(http.MethodGet, "cross-site"); code != http.StatusOK {
		t.Errorf("cross-site GET (safe method): got %d, want 200", code)
	}
	if code := do(http.MethodPost, ""); code != http.StatusOK {
		t.Errorf("non-browser POST: got %d, want 200", code)
	}
}

// --- Fix #6: APT suite/component/architecture token safety -----------------

func TestValidRepoToken(t *testing.T) {
	for _, tok := range []string{"noble", "noble-updates", "main", "universe", "amd64", "a.b"} {
		if !validRepoToken(tok) {
			t.Errorf("token %q should be valid", tok)
		}
	}
	for _, tok := range []string{"", ".", "..", "../x", "a/b", "a b", `a\b`} {
		if validRepoToken(tok) {
			t.Errorf("token %q must be rejected", tok)
		}
	}
}

// --- Fix #5: graceful shutdown ---------------------------------------------

func serveReady(addr string) bool {
	for i := 0; i < 200; i++ {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestListenAndServeGracefulShutdown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for attempt := 0; attempt < 5; attempt++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("cannot bind loopback: %v", err)
		}
		addr := l.Addr().String()
		_ = l.Close() // free the port for the server to claim

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- listenAndServe(ctx, TLSConfig{Mode: tlsUnencrypted}, addr, t.TempDir(), handler)
		}()

		if !serveReady(addr) {
			cancel()
			<-done // likely lost the port race; retry on a fresh one
			continue
		}
		cancel() // a SIGTERM in production: expect a clean, drained return
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("graceful shutdown should return nil, got %v", err)
			}
		case <-time.After(shutdownGracePeriod + 5*time.Second):
			t.Fatal("listenAndServe did not return after context cancellation")
		}
		return
	}
	t.Skip("could not obtain a stable loopback port")
}
