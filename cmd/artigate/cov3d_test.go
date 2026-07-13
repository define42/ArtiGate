package main

// Additional branch coverage for the diode pitcher/catcher, TLS transport,
// watch store/scheduler, exported-content index, argon2 hashpw CLI, session
// login, and the streaming-collect plumbing. Tests are prefixed TestCov3D_ and
// reuse the existing helpers (newLoopbackDiodePair, newBareLowServer,
// newTestKeys, newTestHighServer, newTestAuth, newTestWatchStore, doLowReq, mf)
// without redefining them. File/db write failures are provoked with filesystem
// fault injection, skipped under root; real-socket and multicast paths skip
// cleanly when the environment cannot bind them.

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// catcher.go
// -----------------------------------------------------------------------------

func TestCov3D_CatcherConfigFromEnv(t *testing.T) {
	// Disabled: no interface → zero config, no error.
	t.Setenv("ARTIGATE_CATCHER_INTERFACE", "")
	if cfg, err := catcherConfigFromEnv(); err != nil || cfg.Interface != "" {
		t.Fatalf("disabled catcher config = %+v, %v", cfg, err)
	}

	// Configured with defaults resolves fully.
	t.Run("configured defaults", func(t *testing.T) {
		t.Setenv("ARTIGATE_CATCHER_INTERFACE", "eth1")
		cfg, err := catcherConfigFromEnv()
		if err != nil {
			t.Fatalf("configured catcher config: %v", err)
		}
		if cfg.Interface != "eth1" || cfg.MTU != diodeDefaultMTU || cfg.Port != diodeDefaultPort ||
			cfg.RcvBufMB != diodeDefaultRcvBufMB || cfg.Group != diodeDefaultGroup || !cfg.NetSetup {
			t.Fatalf("configured catcher config = %+v", cfg)
		}
	})

	for name, set := range map[string]func(*testing.T){
		"bad MTU":      func(t *testing.T) { t.Setenv("ARTIGATE_CATCHER_MTU", "900") },
		"bad port":     func(t *testing.T) { t.Setenv("ARTIGATE_CATCHER_PORT", "0") },
		"bad rcvbuf":   func(t *testing.T) { t.Setenv("ARTIGATE_CATCHER_RCVBUF_MB", "0") },
		"bad group":    func(t *testing.T) { t.Setenv("ARTIGATE_CATCHER_GROUP", "224.0.0.1") },
		"bad netsetup": func(t *testing.T) { t.Setenv("ARTIGATE_CATCHER_NETSETUP", "maybe") },
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Setenv("ARTIGATE_CATCHER_INTERFACE", "eth1")
			set(t)
			if cfg, err := catcherConfigFromEnv(); err == nil {
				t.Fatalf("accepted bad catcher config: %+v", cfg)
			}
		})
	}
}

// TestCov3D_StartCatcherIfConfiguredDisabled exercises the no-config early
// return: with no ARTIGATE_CATCHER_INTERFACE the high server starts no catcher.
func TestCov3D_StartCatcherIfConfiguredDisabled(t *testing.T) {
	t.Setenv("ARTIGATE_CATCHER_INTERFACE", "")
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	startCatcherIfConfigured(hs) // must not panic or fatal
}

func TestCov3D_JoinDiodeGroupBadInterface(t *testing.T) {
	if _, err := joinDiodeGroup(CatcherConfig{Interface: "no-such-iface-zzz", Group: diodeDefaultGroup, Port: 0}); err == nil {
		t.Fatal("joinDiodeGroup on a missing interface should error")
	}
}

// TestCov3D_StartCatcherLoopback drives the whole startCatcher path over the
// loopback interface with host networking left as-is; skips where the kernel
// refuses the multicast join.
func TestCov3D_StartCatcherLoopback(t *testing.T) {
	cfg := CatcherConfig{Interface: "lo", Group: diodeDefaultGroup, Port: 0, RcvBufMB: 4, NetSetup: false}
	c, err := startCatcher(cfg, t.TempDir(), func(string) {}, nil)
	if err != nil {
		t.Skipf("startCatcher on loopback unavailable here: %v", err)
	}
	_ = c.Close()
}

// TestCov3D_SetupCatcherIfaceNeedsCapNetAdmin covers the error return: without
// CAP_NET_ADMIN configuring the interface fails. Skipped as root, which would
// actually reconfigure the loopback device.
func TestCov3D_SetupCatcherIfaceNeedsCapNetAdmin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root would reconfigure the loopback interface")
	}
	if err := setupCatcherIface(CatcherConfig{Interface: "lo", MTU: 9000}); err == nil {
		t.Fatal("setupCatcherIface without CAP_NET_ADMIN should error")
	}
}

// -----------------------------------------------------------------------------
// pitcher.go
// -----------------------------------------------------------------------------

func TestCov3D_MustPitcherConfigDisabled(t *testing.T) {
	t.Setenv("ARTIGATE_PITCHER_INTERFACE", "")
	if cfg := mustPitcherConfig(""); cfg.Interface != "" {
		t.Fatalf("mustPitcherConfig with no interface = %+v", cfg)
	}
}

func TestCov3D_AttachPitcherDisabled(t *testing.T) {
	ls := newBareLowServer(t)
	attachPitcher(ls, PitcherConfig{}) // empty interface → no-op
	if ls.pitcher != nil {
		t.Fatal("attachPitcher must not open a socket when disabled")
	}
}

// TestCov3D_SetupPitcherNoNetsetup opens a real diode TX socket over the
// loopback interface with NetSetup off (so it never needs CAP_NET_ADMIN).
func TestCov3D_SetupPitcherNoNetsetup(t *testing.T) {
	cfg := PitcherConfig{
		Interface: "lo", MTU: 1500, TxQueueLen: 1000, RateMbit: 200,
		Group: "::1", Port: 49321, DataShards: 8, ParityShards: 2, NetSetup: false,
	}
	p, err := setupPitcher(cfg)
	if err != nil {
		t.Skipf("diode TX socket over loopback unavailable: %v", err)
	}
	_ = p.Close()
}

// TestCov3D_SendBundleMissingFile covers the sendFile/SendBundle open-error
// path: a bundle whose files are absent fails before any datagram is sent.
func TestCov3D_SendBundleMissingFile(t *testing.T) {
	p, _ := newLoopbackDiodePair(t, t.TempDir(), func(string) {})
	if err := p.SendBundle(context.Background(), t.TempDir(), "go-bundle-000001"); err == nil {
		t.Fatal("SendBundle with no staged files should error")
	}
}

// TestCov3D_PitchBundle covers both the success and failure branches of the
// export-flow hook.
func TestCov3D_PitchBundle(t *testing.T) {
	ls := newBareLowServer(t)
	p, _ := newLoopbackDiodePair(t, t.TempDir(), func(string) {})
	ls.pitcher = p

	// Failure: no staged files → DiodeError reported, nothing cleared.
	failRes := &ExportResult{BundleID: "go-bundle-000009"}
	ls.pitchBundle(context.Background(), failRes)
	if failRes.DiodeError == "" {
		t.Fatal("pitchBundle should report a diode error when files are missing")
	}

	// Success: stage the three files, send them, and confirm the spool clears.
	const bundleID = "go-bundle-000010"
	for _, suffix := range bundleSuffixes() {
		if err := os.WriteFile(filepath.Join(ls.cfg.ExportDir, bundleID+suffix), []byte("payload "+suffix), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	okRes := &ExportResult{BundleID: bundleID}
	ls.pitchBundle(context.Background(), okRes)
	if okRes.DiodeError != "" {
		t.Fatalf("pitchBundle success path reported error: %s", okRes.DiodeError)
	}
	if okRes.Message == "" {
		t.Error("pitchBundle success should set a message")
	}
	for _, suffix := range bundleSuffixes() {
		if fileExists(filepath.Join(ls.cfg.ExportDir, bundleID+suffix)) {
			t.Errorf("%s still staged after a successful pitch", bundleID+suffix)
		}
	}
}

// -----------------------------------------------------------------------------
// tls.go
// -----------------------------------------------------------------------------

func TestCov3D_SelfSignedCertDefaultsAndIPOnly(t *testing.T) {
	// No domains → placeholder DNS name.
	cert, err := selfSignedCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty certificate")
	}
	// IP-only → no DNS SANs, no CommonName path taken.
	if _, err := selfSignedCert([]string{"10.0.0.1"}); err != nil {
		t.Fatalf("IP-only self-signed cert: %v", err)
	}
}

func TestCov3D_ServerTLSConfigInvalidMode(t *testing.T) {
	if _, err := serverTLSConfig(TLSConfig{Mode: tlsMode("bogus")}, t.TempDir()); err == nil {
		t.Fatal("invalid tls mode should error")
	}
}

// TestCov3D_AcmeTLSConfigTrustedRootErrors exercises the certmagic
// configuration up to (but not into) live ACME by failing on the trusted-root
// PEM, which is validated before ManageAsync runs.
func TestCov3D_AcmeTLSConfigTrustedRootErrors(t *testing.T) {
	// Missing root CA file.
	c := TLSConfig{
		Mode: tlsACME, Domains: []string{"mirror.example.com"}, ACMEEmail: "ops@example.com",
		ACMECA: "https://ca.internal/acme/directory", ACMERootCA: "/no/such/root.pem",
	}
	if _, err := acmeTLSConfig(c, t.TempDir()); err == nil {
		t.Fatal("acmeTLSConfig with a missing root CA should error")
	}

	// Present but certificate-free root CA file (explicit storage set).
	badPEM := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(badPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c2 := TLSConfig{Mode: tlsACME, Domains: []string{"mirror.example.com"}, ACMERootCA: badPEM, ACMEStore: t.TempDir()}
	if _, err := acmeTLSConfig(c2, t.TempDir()); err == nil {
		t.Fatal("acmeTLSConfig with a cert-free root CA should error")
	}
}

// TestCov3D_ListenAndServeBindErrors drives listenAndServe through all three
// return branches (config error, plain-HTTP bind, TLS bind) without leaving a
// listener running: the address is pre-occupied so each bind fails fast.
func TestCov3D_ListenAndServeBindErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	ctx := context.Background()

	// serverTLSConfig error propagates out immediately.
	if err := listenAndServe(ctx, TLSConfig{Mode: tlsOwnCert, CertFile: "/no/cert", KeyFile: "/no/key"},
		"127.0.0.1:0", t.TempDir(), handler); err == nil {
		t.Error("listenAndServe with an unloadable certificate should error")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()

	// Plain HTTP: the address is taken, so ListenAndServe fails.
	if err := listenAndServe(ctx, TLSConfig{Mode: tlsUnencrypted}, addr, t.TempDir(), handler); err == nil {
		t.Error("plain listenAndServe on an occupied address should error")
	}
	// TLS: same, exercising the ListenAndServeTLS branch.
	if err := listenAndServe(ctx, TLSConfig{Mode: tlsAutoGen, Domains: []string{"127.0.0.1"}}, addr, t.TempDir(), handler); err == nil {
		t.Error("TLS listenAndServe on an occupied address should error")
	}
}

// -----------------------------------------------------------------------------
// watch.go
// -----------------------------------------------------------------------------

func TestCov3D_WatchStoreMisc(t *testing.T) {
	if boolToInt(false) != 0 || boolToInt(true) != 1 {
		t.Fatal("boolToInt")
	}
	var nilStore *WatchStore
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil WatchStore.Close = %v", err)
	}
	// A path under a nonexistent directory cannot initialise.
	if _, err := OpenWatchStore(filepath.Join(t.TempDir(), "nope", "watches.db")); err == nil {
		t.Fatal("OpenWatchStore under a missing directory should error")
	}
}

func TestCov3D_WatchStoreClosedErrors(t *testing.T) {
	store := newTestWatchStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(Watch{Stream: streamGo, Spec: "{}", IntervalSeconds: 3600}); err == nil {
		t.Error("Create on a closed store should error")
	}
	if _, err := store.List(); err == nil {
		t.Error("List on a closed store should error")
	}
	if _, err := store.Due(time.Now().UTC()); err == nil {
		t.Error("Due on a closed store should error")
	}
}

func TestCov3D_ValidateWatch(t *testing.T) {
	base := Watch{Stream: streamPython, Spec: `{"requirements":["x"]}`, IntervalSeconds: 3600}
	if err := validateWatch(base); err != nil {
		t.Fatalf("valid watch rejected: %v", err)
	}
	cases := map[string]Watch{
		"uploads not schedulable": {Stream: streamUploads, Spec: `{}`, IntervalSeconds: 3600},
		"empty spec":              {Stream: streamPython, Spec: "   ", IntervalSeconds: 3600},
		"invalid json spec":       {Stream: streamPython, Spec: "{not json", IntervalSeconds: 3600},
	}
	for name, w := range cases {
		if err := validateWatch(w); err == nil {
			t.Errorf("%s: validateWatch should error", name)
		}
	}
}

// TestCov3D_EnqueueWatchErrorRecorded covers the error-recording branch (a
// spec that fails to decode) without a real collect: the failed run lands in
// the watch row via the job's completion hook.
func TestCov3D_EnqueueWatchErrorRecorded(t *testing.T) {
	ls := newBareLowServer(t)
	w, err := ls.watches.Create(Watch{Stream: streamGo, Label: "bad", Spec: `{"modules":["x"]}`, IntervalSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := ls.enqueueWatch(Watch{ID: w.ID, Stream: streamGo, Spec: "{not json", IntervalSeconds: 3600}); err != nil || id == 0 {
		t.Fatalf("watch job not enqueued: job %d, %v", id, err)
	}
	waitWatchRecorded(t, ls, w.ID)
	got, err := ls.watches.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != "error" {
		t.Fatalf("failed watch status = %q, want error", got.LastStatus)
	}
}

// TestCov3D_RecoverCollectPanic verifies the scheduler's panic firewall: a
// collector that panics during a scheduled run is turned into an error (which
// runWatch then records, advancing next_run_at) instead of propagating up the
// bare scheduler goroutine and crashing the low server.
func TestCov3D_RecoverCollectPanic(t *testing.T) {
	// A panic becomes an error, not a process crash.
	if _, err := recoverCollectPanic(streamGo, func() (ExportResult, error) {
		panic("boom in collector")
	}); err == nil {
		t.Fatal("recoverCollectPanic swallowed the panic without returning an error")
	} else if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("error = %q, want it to mention the panic", err)
	}

	// The clean path passes the result and nil error straight through.
	want := ExportResult{Stream: streamGo, Sequence: 7}
	got, err := recoverCollectPanic(streamGo, func() (ExportResult, error) { return want, nil })
	if err != nil {
		t.Fatalf("clean collect returned error: %v", err)
	}
	if got.Stream != want.Stream || got.Sequence != want.Sequence {
		t.Errorf("clean collect result = %+v, want %+v", got, want)
	}
}

// TestCov3D_RunWatchSurvivesPanickingCollect drives the record path with a
// collect that panics inside the firewall, and asserts the run is contained and
// recorded as a failed run (not propagated up the goroutine). This is the
// firewall (recoverCollectPanic) and the record path (executeWatch) composed
// exactly as runWatch composes them.
func TestCov3D_RunWatchSurvivesPanickingCollect(t *testing.T) {
	ls := newBareLowServer(t)
	w, err := ls.watches.Create(Watch{Stream: streamGo, Label: "panic", Spec: `{}`, IntervalSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// If the panic firewall regresses, this goroutine crashes the test binary
		// rather than returning — exactly the production failure being guarded.
		ls.executeWatch(w, func() (ExportResult, error) {
			return recoverCollectPanic(w.Stream, func() (ExportResult, error) {
				panic("collector blew up")
			})
		})
	}()
	<-done
	got, err := ls.watches.Get(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != "error" {
		t.Fatalf("panicking watch status = %q, want error", got.LastStatus)
	}
	if got.NextRunAt.IsZero() {
		t.Error("panicking watch did not get an advanced next_run_at; the schedule could tight-loop")
	}
}

// TestCov3D_RunDueWatchesStoreError covers the Due()-error branch of the
// scheduler drain.
func TestCov3D_RunDueWatchesStoreError(t *testing.T) {
	ls := newBareLowServer(t)
	_ = ls.watches.Close() // subsequent Due() fails; runDueWatches must log and return
	ls.runDueWatches()
}

// TestCov3D_RecordWatchOutcomeStoreError covers the RecordRun-error branch of
// the outcome recording: a store that can no longer be written (closed here,
// e.g. mid-shutdown in production) is logged and contained, not propagated
// into the job worker.
func TestCov3D_RecordWatchOutcomeStoreError(t *testing.T) {
	ls := newBareLowServer(t)
	_ = ls.watches.Close()
	ls.executeWatch(Watch{ID: 1, Stream: streamGo, Label: "gone"}, func() (ExportResult, error) {
		return ExportResult{}, nil
	})
}

func TestCov3D_ServeLowWatchesRouting(t *testing.T) {
	ls := newBareLowServer(t)

	call := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		ls.serveLowWatches(rec, req)
		return rec
	}

	// enable route: an id that does not exist still succeeds (0 rows updated).
	if rec := call(http.MethodPost, "/admin/watches/enable", `{"id":1}`); rec.Code != http.StatusOK {
		t.Errorf("enable status = %d, want 200", rec.Code)
	}
	// run route error branches: bad id → 400, missing watch → 404.
	if rec := call(http.MethodPost, "/admin/watches/run", `{"id":0}`); rec.Code != http.StatusBadRequest {
		t.Errorf("run bad-id status = %d, want 400", rec.Code)
	}
	if rec := call(http.MethodPost, "/admin/watches/run", `{"id":9999}`); rec.Code != http.StatusNotFound {
		t.Errorf("run missing-watch status = %d, want 404", rec.Code)
	}
	// Non-POST on an action route and unknown/other paths are not handled.
	if handled := ls.serveLowWatches(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/watches/delete", nil)); handled {
		t.Error("GET on an action route should not be handled")
	}
	if handled := ls.serveLowWatches(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/admin/watches", nil)); handled {
		t.Error("PUT on /admin/watches should not be handled")
	}
	if handled := ls.serveLowWatches(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/watches/bogus", nil)); handled {
		t.Error("unknown watch path should not be handled")
	}
}

func TestCov3D_HandleCreateWatchAndListErrors(t *testing.T) {
	ls := newBareLowServer(t)

	// Invalid JSON body → 400.
	rec := httptest.NewRecorder()
	ls.serveLowWatches(rec, httptest.NewRequest(http.MethodPost, "/admin/watches", strings.NewReader("{not json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid-json create status = %d, want 400", rec.Code)
	}

	// With the store closed, a valid create surfaces a 500 and list a 500.
	_ = ls.watches.Close()
	rec = httptest.NewRecorder()
	ls.serveLowWatches(rec, httptest.NewRequest(http.MethodPost, "/admin/watches",
		strings.NewReader(`{"stream":"python","interval_seconds":3600,"spec":{"requirements":["x"]}}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("create-on-closed-store status = %d, want 500", rec.Code)
	}
	rec = httptest.NewRecorder()
	ls.serveLowWatches(rec, httptest.NewRequest(http.MethodGet, "/admin/watches", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("list-on-closed-store status = %d, want 500", rec.Code)
	}
}

func TestCov3D_WatchIDFromBody(t *testing.T) {
	if _, err := watchIDFromBody(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{not json"))); err == nil {
		t.Error("invalid JSON body should error")
	}
	if _, err := watchIDFromBody(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"id":0}`))); err == nil {
		t.Error("id<=0 should error")
	}
	id, err := watchIDFromBody(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"id":7}`)))
	if err != nil || id != 7 {
		t.Fatalf("watchIDFromBody = %d, %v; want 7, nil", id, err)
	}
}

// -----------------------------------------------------------------------------
// exported.go
// -----------------------------------------------------------------------------

func TestCov3D_OpenExportedStoreError(t *testing.T) {
	if _, err := OpenExportedStore(filepath.Join(t.TempDir(), "nope", "exported.db")); err == nil {
		t.Fatal("OpenExportedStore under a missing directory should error")
	}
}

// TestCov3D_MigrateLegacyExported folds a pre-delta exported_content table into
// the path-qualified schema on open.
func TestCov3D_MigrateLegacyExported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE exported_content (stream TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY (stream, sha256))`,
		`INSERT INTO exported_content (stream, sha256) VALUES ('go', 'deadbeef')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenExportedStore(path) // triggers migrateLegacyExported
	if err != nil {
		t.Fatalf("OpenExportedStore (migrate): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	// A legacy hash-only row matches under any path.
	ok, err := store.IsForwarded("go", "anything", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("migrated legacy row should match hash-only")
	}
}

func TestCov3D_ExportedStoreClosedErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported.db")
	store, err := OpenExportedStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	files := []ManifestFile{mf("npm/packages/a.tgz", "a")}
	if err := store.Record("npm", files); err == nil {
		t.Error("Record on a closed store should error")
	}
	if _, err := store.ForwardedFlags("npm", files); err == nil {
		t.Error("ForwardedFlags on a closed store should error")
	}
	// Empty inputs are cheap no-ops even on a closed store.
	if err := store.Record("npm", nil); err != nil {
		t.Errorf("Record(nil) = %v, want nil", err)
	}
	if flags, err := store.ForwardedFlags("npm", nil); err != nil || len(flags) != 0 {
		t.Errorf("ForwardedFlags(nil) = %v, %v", flags, err)
	}
}

// -----------------------------------------------------------------------------
// auth.go
// -----------------------------------------------------------------------------

// TestCov3D_RunHashpw exercises the happy-path CLI branches (password from the
// flag, with and without a username prefix), avoiding the stdin/log.Fatal
// branches. Output is redirected so it does not clutter the test log.
func TestCov3D_RunHashpw(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() { _, _ = buf.ReadFrom(r); close(done) }()

	runHashpw([]string{"--password", "s3cret"})
	runHashpw([]string{"--user", "alice", "--password", "s3cret"})

	_ = w.Close()
	os.Stdout = old
	<-done
	out := buf.String()
	if !strings.Contains(out, "$argon2id$") {
		t.Errorf("hashpw output missing an argon2id hash: %q", out)
	}
	if !strings.Contains(out, "alice:$argon2id$") {
		t.Errorf("hashpw --user output missing the user prefix: %q", out)
	}
}

// -----------------------------------------------------------------------------
// login.go
// -----------------------------------------------------------------------------

func TestCov3D_LoadOrCreateSessionKeysErrors(t *testing.T) {
	// A directory path yields a read error that is not "not exist".
	if _, _, err := loadOrCreateSessionKeys(t.TempDir()); err == nil {
		t.Error("loadOrCreateSessionKeys on a directory should error")
	}
	// newAuthManager surfaces that same failure.
	if _, err := newAuthManager(map[string]string{}, t.TempDir(), false); err == nil {
		t.Error("newAuthManager should propagate a key-load error")
	}
}

// TestCov3D_LoadSessionKeysWriteFailure provokes the write-error branch with a
// read-only parent directory. Skipped under root, which bypasses the mode bits.
func TestCov3D_LoadSessionKeysWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, _, err := loadOrCreateSessionKeys(filepath.Join(dir, "session.key")); err == nil {
		t.Error("loadOrCreateSessionKeys into a read-only directory should error")
	}
}

func TestCov3D_HandleLoginMethodAndAuthedGet(t *testing.T) {
	am := newTestAuth(t) // single user alice/pw

	// An unsupported method is rejected.
	rec := httptest.NewRecorder()
	am.handleLogin(rec, httptest.NewRequest(http.MethodDelete, "/login", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /login = %d, want 405", rec.Code)
	}

	// A GET carrying a valid session redirects to the dashboard.
	enc, err := am.sc.Encode(sessionCookieName, "alice")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: enc})
	rec = httptest.NewRecorder()
	am.handleLogin(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Errorf("authed GET /login = %d %q, want 303 /", rec.Code, rec.Header().Get("Location"))
	}
}

// -----------------------------------------------------------------------------
// progress.go
// -----------------------------------------------------------------------------

// cov3DNonFlusher is a ResponseWriter that deliberately does not implement
// http.Flusher, forcing followJobNDJSON down its buffered fallback.
type cov3DNonFlusher struct {
	hdr  http.Header
	code int
	buf  bytes.Buffer
}

func (w *cov3DNonFlusher) Header() http.Header {
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}
func (w *cov3DNonFlusher) Write(b []byte) (int, error) { return w.buf.Write(b) }
func (w *cov3DNonFlusher) WriteHeader(code int)        { w.code = code }

func TestCov3D_FollowJobNonFlusherFallback(t *testing.T) {
	w := &cov3DNonFlusher{}
	r := httptest.NewRequest(http.MethodPost, "/admin/go/collect?stream=1", nil)
	m := newJobManager()
	j := testJob(streamGo, func(context.Context) (ExportResult, error) {
		return ExportResult{BundleID: "go-bundle-000001"}, nil
	})
	if _, err := m.enqueue(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	followJobNDJSON(w, r, j, true)
	if !strings.Contains(w.buf.String(), "go-bundle-000001") {
		t.Errorf("buffered fallback body = %q", w.buf.String())
	}
}

func TestCov3D_EnqueueCollectOversizedBody(t *testing.T) {
	ls := &LowServer{jobs: newJobManager()}
	big := bytes.Repeat([]byte("x"), maxStreamCollectBody+1)
	r := httptest.NewRequest(http.MethodPost, "/admin/go/collect?stream=1", bytes.NewReader(big))
	rec := httptest.NewRecorder()
	_, ok := ls.enqueueCollect(rec, r, streamGo, func(context.Context) (ExportResult, error) {
		t.Error("collect must not run when the body is rejected")
		return ExportResult{}, nil
	})
	if ok {
		t.Error("oversized body must refuse the enqueue")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized stream body status = %d, want 400", rec.Code)
	}
}

func TestCov3D_BufferCollectBody(t *testing.T) {
	// A small body buffers and remains readable afterwards.
	r := httptest.NewRequest(http.MethodPost, "/admin/go/collect", strings.NewReader(`{"modules":["a"]}`))
	body, err := bufferCollectBody(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"modules":["a"]}` {
		t.Errorf("buffered body = %q", body)
	}
	rearmed, err := io.ReadAll(r.Body)
	if err != nil || string(rearmed) != string(body) {
		t.Errorf("rearmed body read = %q, %v", rearmed, err)
	}

	// An oversized body errors clearly.
	big := bytes.Repeat([]byte("y"), maxStreamCollectBody+1)
	r2 := httptest.NewRequest(http.MethodPost, "/admin/go/collect", bytes.NewReader(big))
	if _, err := bufferCollectBody(r2); err == nil {
		t.Error("oversized body should error")
	}
}

// A multipart collect (an upload) is never buffered: the run streams the body
// straight from the request, and the job dies with the request context — a
// client that vanishes while its upload is queued frees the queue slot.
func TestCov3D_EnqueueCollectMultipart(t *testing.T) {
	ls := &LowServer{jobs: newJobManager()}
	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()

	// Hold the uploads stream busy so the multipart job stays queued.
	release := make(chan struct{})
	defer close(release)
	blocker := testJob(streamUploads, func(context.Context) (ExportResult, error) {
		<-release
		return ExportResult{}, nil
	})
	if _, err := ls.jobs.enqueue(context.Background(), blocker); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/admin/uploads/collect", strings.NewReader("--b--")).WithContext(reqCtx)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	rec := httptest.NewRecorder()
	j, ok := ls.enqueueCollect(rec, r, streamUploads, func(context.Context) (ExportResult, error) {
		t.Error("queued upload must not run after its client disconnected")
		return ExportResult{}, nil
	})
	if !ok {
		t.Fatalf("multipart enqueue refused: %s", rec.Body.String())
	}
	if j.Label != "uploads: file upload" {
		t.Errorf("upload job label = %q", j.Label)
	}

	cancelReq() // the client goes away while queued
	waitJobDone(t, j)
	if got := j.snapshotInfo(0).State; got != string(jobCanceled) {
		t.Errorf("abandoned queued upload state = %s, want canceled", got)
	}
}

// -----------------------------------------------------------------------------
// ui_low.go
// -----------------------------------------------------------------------------

func TestCov3D_ServeLowUI(t *testing.T) {
	ls := newBareLowServer(t)

	// Dashboard page without auth: no "Log out" button.
	rec := httptest.NewRecorder()
	if !ls.serveLowUI(rec, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("serveLowUI should handle /")
	}
	if strings.Contains(rec.Body.String(), "Log out") {
		t.Error("logout button should be hidden when auth is disabled")
	}

	// With auth enabled the button appears.
	ls.authEnabled = true
	if !strings.Contains(ls.renderLowUI(), "Log out") {
		t.Error("logout button should appear when auth is enabled")
	}

	// Status endpoint returns JSON.
	rec = httptest.NewRecorder()
	if !ls.serveLowUI(rec, httptest.NewRequest(http.MethodGet, "/ui/api/status", nil)) {
		t.Fatal("serveLowUI should handle /ui/api/status")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("status Content-Type = %q", ct)
	}

	// A write method on the dashboard is rejected; unknown paths pass through.
	rec = httptest.NewRecorder()
	if !ls.serveLowUI(rec, httptest.NewRequest(http.MethodPost, "/", nil)) || rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST / = handled?%v code %d, want handled 405", true, rec.Code)
	}
	rec = httptest.NewRecorder()
	if !ls.serveLowUI(rec, httptest.NewRequest(http.MethodPost, "/ui/api/status", nil)) || rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = code %d, want 405", rec.Code)
	}
	if ls.serveLowUI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nope", nil)) {
		t.Error("serveLowUI should not handle unknown paths")
	}
}
