package main

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// covSrvRecorderReq builds a recorder plus request for direct handler calls.
func covSrvRecorderReq(method, path, body string) (*httptest.ResponseRecorder, *http.Request) {
	return httptest.NewRecorder(), httptest.NewRequest(method, path, strings.NewReader(body))
}

// -----------------------------------------------------------------------------
// watch.go
// -----------------------------------------------------------------------------

// TestCovSrv_WatchRunMessage exercises every branch of the run-message renderer.
func TestCovSrv_WatchRunMessage(t *testing.T) {
	if got := watchRunMessage(ExportResult{Skipped: true}); !strings.Contains(got, "skipped") {
		t.Errorf("skipped message = %q", got)
	}
	if got := watchRunMessage(ExportResult{}); got != "no bundle produced" {
		t.Errorf("empty bundle message = %q", got)
	}
	full := watchRunMessage(ExportResult{
		BundleID: "go-bundle-000001", ExportedModules: 3, PriorFiles: 2,
		SkippedModules: []FailedModule{{Module: "a"}, {Module: "b"}}, DiodeError: "502 bad gateway",
	})
	for _, want := range []string{"go-bundle-000001", "3 unit(s)", "2 file(s) already forwarded", "2 skipped", "diode upload failed: 502 bad gateway"} {
		if !strings.Contains(full, want) {
			t.Errorf("full message %q missing %q", full, want)
		}
	}
}

// TestCovSrv_RunWatchCollectDispatch drives the stream dispatch: a malformed
// spec reaches every collector's decode (a parse error), and an unknown stream
// hits the default arm.
func TestCovSrv_RunWatchCollectDispatch(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	for _, stream := range []string{streamGo, streamPython, streamMaven, streamApt, streamRpm, streamContainers, streamNpm, streamHF} {
		if _, err := ls.runWatchCollect(context.Background(), stream, "{not json"); err == nil {
			t.Errorf("stream %q: malformed spec should error", stream)
		}
	}
	if _, err := ls.runWatchCollect(context.Background(), "bogus-stream", "{}"); err == nil ||
		!strings.Contains(err.Error(), "unknown stream") {
		t.Errorf("unknown stream err = %v, want an 'unknown stream' error", err)
	}
}

// TestCovSrv_HandleRunWatch covers the run-now endpoint: wrong method, bad body,
// unknown id, and a valid run that records its outcome in the background.
func TestCovSrv_HandleRunWatch(t *testing.T) {
	ls, _ := newFakeLowServer(t)

	// Wrong method: not handled.
	rec, req := covSrvRecorderReq(http.MethodGet, "/admin/watches/run", "")
	if ls.handleRunWatch(rec, req) {
		t.Error("GET should not be handled by handleRunWatch")
	}
	// Bad JSON body → 400.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/watches/run", "{bad")
	if !ls.handleRunWatch(rec, req) || rec.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d, want 400", rec.Code)
	}
	// Unknown id → 404.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/watches/run", `{"id":9999}`)
	if !ls.handleRunWatch(rec, req) || rec.Code != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", rec.Code)
	}

	// A real watch runs in the background and records its outcome.
	w, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: bar", Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`,
		IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/watches/run", `{"id":`+strconv.FormatInt(w.ID, 10)+`}`)
	if !ls.handleRunWatch(rec, req) || rec.Code != http.StatusOK {
		t.Fatalf("run status = %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "started") {
		t.Errorf("run body = %q, want 'started'", rec.Body.String())
	}
	covSrvWaitWatchRan(t, ls, w.ID)
}

// TestCovSrv_WatchActionErrors covers watchAction's non-happy arms.
func TestCovSrv_WatchActionErrors(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	noop := func(int64) error { return nil }

	// Wrong method: not handled.
	rec, req := covSrvRecorderReq(http.MethodGet, "/admin/watches/delete", "")
	if ls.watchAction(rec, req, noop) {
		t.Error("GET should not be handled by watchAction")
	}
	// Bad body → 400.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/watches/delete", "{bad")
	if !ls.watchAction(rec, req, noop) || rec.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d, want 400", rec.Code)
	}
	// Action error → 500.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/watches/delete", `{"id":1}`)
	boom := func(int64) error { return errors.New("boom") }
	if !ls.watchAction(rec, req, boom) || rec.Code != http.StatusInternalServerError {
		t.Errorf("action-error status = %d, want 500", rec.Code)
	}
}

// TestCovSrv_WatchLoop runs the scheduler loop: a due watch fires on a tick and
// records its run, then the loop exits on context cancellation.
func TestCovSrv_WatchLoop(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	ls.watchTick = 15 * time.Millisecond
	w, err := ls.watches.Create(Watch{
		Stream: streamGo, Label: "go: loop", Spec: `{"modules":["example.com/foo/bar@v1.0.0"]}`,
		IntervalSeconds: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ls.watchLoop(ctx)
	covSrvWaitWatchRan(t, ls, w.ID)
	cancel()
}

// covSrvWaitWatchRan blocks until a watch has recorded a run (or the test times
// out), so a background collect never outlives the test's temp dirs.
func covSrvWaitWatchRan(t *testing.T, ls *LowServer, id int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := ls.watches.Get(id); err == nil && got.LastRunAt != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watch %d never recorded a run", id)
}

// -----------------------------------------------------------------------------
// uploads.go
// -----------------------------------------------------------------------------

// TestCovSrv_ValidateUploadComponent covers the rejection arms not hit elsewhere.
func TestCovSrv_ValidateUploadComponent(t *testing.T) {
	cases := []struct {
		val  string
		want string
	}{
		{"  ", "empty"},
		{"trailing ", "whitespace"},
		{strings.Repeat("x", 129), "longer than 128"},
		{".hidden", "must not start with a dot"},
		{"a/b", "path separators"},
		{`a\b`, "path separators"},
		{"a\x01b", "control characters"},
	}
	for _, c := range cases {
		err := validateUploadComponent("file", c.val)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("validateUploadComponent(%q) = %v, want error containing %q", c.val, err, c.want)
		}
	}
	if err := validateUploadComponent("file", "ok.txt"); err != nil {
		t.Errorf("valid component rejected: %v", err)
	}
}

// TestCovSrv_HandleDeleteUploadValidation drives the delete handler's early
// rejections directly (bypassing the local-admin gate, which is tested via the
// httptest server elsewhere).
func TestCovSrv_HandleDeleteUploadValidation(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// Malformed JSON → 400.
	rec, req := covSrvRecorderReq(http.MethodPost, "/admin/uploads/delete", "{bad")
	if !hs.handleDeleteUpload(rec, req) || rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON status = %d, want 400", rec.Code)
	}
	// Invalid folder → 400.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/uploads/delete", `{"folder":"","name":"a"}`)
	if !hs.handleDeleteUpload(rec, req) || rec.Code != http.StatusBadRequest {
		t.Errorf("empty folder status = %d, want 400", rec.Code)
	}
	// Invalid file name → 400.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/uploads/delete", `{"folder":"tools","name":".x"}`)
	if !hs.handleDeleteUpload(rec, req) || rec.Code != http.StatusBadRequest {
		t.Errorf("bad file status = %d, want 400", rec.Code)
	}
	// Valid but nonexistent → 404.
	rec, req = covSrvRecorderReq(http.MethodPost, "/admin/uploads/delete", `{"folder":"tools","name":"ghost.txt"}`)
	if !hs.handleDeleteUpload(rec, req) || rec.Code != http.StatusNotFound {
		t.Errorf("missing file status = %d, want 404", rec.Code)
	}
}

// TestCovSrv_ServeUploads covers the serve path's guards.
func TestCovSrv_ServeUploads(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)

	// A non-uploads path is not handled.
	rec, req := covSrvRecorderReq(http.MethodGet, "/packages/x", "")
	if hs.serveUploads(rec, req) {
		t.Error("/packages should not be handled by serveUploads")
	}
	// Wrong method → 405.
	rec, req = covSrvRecorderReq(http.MethodPost, "/uploads/tools/a.txt", "")
	if !hs.serveUploads(rec, req) || rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
	// Bare /uploads (empty rel) → 404.
	rec, req = covSrvRecorderReq(http.MethodGet, "/uploads", "")
	if !hs.serveUploads(rec, req) || rec.Code != http.StatusNotFound {
		t.Errorf("bare /uploads status = %d, want 404", rec.Code)
	}
	// Traversal rel → 404.
	rec, req = covSrvRecorderReq(http.MethodGet, "/uploads/../etc/passwd", "")
	if !hs.serveUploads(rec, req) || rec.Code == http.StatusOK {
		t.Errorf("traversal status = %d, want an error", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// ui.go
// -----------------------------------------------------------------------------

// TestCovSrv_ServeUIMethodGuards checks each read-only route rejects writes and
// that an unknown path is not handled.
func TestCovSrv_ServeUIMethodGuards(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	for _, path := range []string{"/", "/ui/app.js", "/ui/api/overview", "/ui/api/tree", "/ui/api/detail", "/ui/api/repos"} {
		rec, req := covSrvRecorderReq(http.MethodPost, path, "")
		if !hs.serveUI(rec, req) || rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s status = %d, want 405", path, rec.Code)
		}
	}
	rec, req := covSrvRecorderReq(http.MethodGet, "/nope", "")
	if hs.serveUI(rec, req) {
		t.Error("/nope should not be handled by serveUI")
	}
}

// TestCovSrv_CachedListsCacheHit calls cachedTrees twice so the second call
// returns the memoized copy.
func TestCovSrv_CachedListsCacheHit(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if _, err := hs.cachedTrees(); err != nil {
		t.Fatalf("first cachedTrees: %v", err)
	}
	if _, err := hs.cachedTrees(); err != nil {
		t.Fatalf("cached cachedTrees: %v", err)
	}
}

// TestCovSrv_HandleUIReposEcosystems covers the hf and containers repo arms and
// the unknown-eco rejection.
func TestCovSrv_HandleUIReposEcosystems(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	for _, eco := range []string{"hf", "containers", "rpm"} {
		if code, _ := httpGet(t, srv.URL+"/ui/api/repos?eco="+eco); code != http.StatusOK {
			t.Errorf("repos eco=%s status = %d, want 200", eco, code)
		}
	}
	if code, _ := httpGet(t, srv.URL+"/ui/api/repos?eco=bogus"); code != http.StatusBadRequest {
		t.Errorf("unknown eco status = %d, want 400", code)
	}
}

// -----------------------------------------------------------------------------
// auth.go
// -----------------------------------------------------------------------------

func TestCovSrv_AuthStatus(t *testing.T) {
	if got := authStatus(nil); got != "disabled" {
		t.Errorf("authStatus(nil) = %q, want disabled", got)
	}
	if got := authStatus(map[string]string{"a": "x", "b": "y"}); got != "2 user(s)" {
		t.Errorf("authStatus(2) = %q", got)
	}
}

func TestCovSrv_CredentialOKUnknownUser(t *testing.T) {
	if credentialOK(map[string]string{}, "nobody", "pw") {
		t.Error("unknown user should not be credentialOK")
	}
}

// TestCovSrv_RunHashpw covers the non-fatal paths: a hash printed bare and one
// prefixed with a username.
func TestCovSrv_RunHashpw(t *testing.T) {
	bare := covSrvCaptureStdout(t, func() { runHashpw([]string{"--password", "secret-pw"}) })
	if !strings.HasPrefix(strings.TrimSpace(bare), "$argon2id$") {
		t.Errorf("bare hashpw output = %q, want an argon2id hash", bare)
	}
	withUser := covSrvCaptureStdout(t, func() { runHashpw([]string{"--password", "secret-pw", "--user", "bob"}) })
	if !strings.HasPrefix(withUser, "bob:$argon2id$") {
		t.Errorf("user hashpw output = %q, want bob:<hash>", withUser)
	}
}

// covSrvCaptureStdout runs fn with os.Stdout redirected and returns what it wrote.
func covSrvCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// -----------------------------------------------------------------------------
// login.go
// -----------------------------------------------------------------------------

// TestCovSrv_HandleLoginExtraPaths covers the GET-already-authenticated redirect
// and the method-not-allowed default.
func TestCovSrv_HandleLoginExtraPaths(t *testing.T) {
	am := newTestAuth(t)

	// GET /login with a valid session redirects home.
	enc, err := am.sc.Encode(sessionCookieName, "alice")
	if err != nil {
		t.Fatal(err)
	}
	rec, req := covSrvRecorderReq(http.MethodGet, "/login", "")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: enc})
	am.handleLogin(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Errorf("authed GET /login = %d %q, want 303 to /", rec.Code, rec.Header().Get("Location"))
	}

	// An unsupported method → 405.
	rec, req = covSrvRecorderReq(http.MethodDelete, "/login", "")
	am.handleLogin(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /login = %d, want 405", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// tls.go
// -----------------------------------------------------------------------------

// TestCovSrv_ServerTLSConfigMore covers the invalid-mode arm and the ACME arm's
// early root-CA failure (no live ACME needed).
func TestCovSrv_ServerTLSConfigMore(t *testing.T) {
	if _, err := serverTLSConfig(TLSConfig{Mode: tlsMode("bogus")}, t.TempDir()); err == nil {
		t.Error("invalid tls mode should error")
	}
	// ACME with a bad trusted-root path fails inside acmeTLSConfig before it
	// ever contacts an ACME server.
	c := TLSConfig{
		Mode: tlsACME, Domains: []string{"h.example"},
		ACMEEmail: "ops@example", ACMECA: "https://ca.internal/dir",
		ACMERootCA: filepath.Join(t.TempDir(), "no-such-root.pem"),
	}
	if _, err := serverTLSConfig(c, t.TempDir()); err == nil {
		t.Error("acme with a missing root CA should error")
	}
}

// TestCovSrv_CertPoolFromPEM covers all three arms: valid, missing, and junk.
func TestCovSrv_CertPoolFromPEM(t *testing.T) {
	cert, err := selfSignedCert([]string{"pool.local"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "root.pem")
	writeFile(t, good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	if pool, err := certPoolFromPEM(good); err != nil || pool == nil {
		t.Fatalf("valid PEM = %v, %v", pool, err)
	}
	if _, err := certPoolFromPEM(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing file should error")
	}
	junk := filepath.Join(dir, "junk.pem")
	writeFile(t, junk, []byte("not a pem"))
	if _, err := certPoolFromPEM(junk); err == nil {
		t.Error("junk file should error")
	}
}

// -----------------------------------------------------------------------------
// exported.go
// -----------------------------------------------------------------------------

// TestCovSrv_ExportedStore drives the store primitives and legacy migration.
func TestCovSrv_ExportedStore(t *testing.T) {
	// nil store's Close is a no-op.
	var nilStore *ExportedStore
	if err := nilStore.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}

	path := filepath.Join(t.TempDir(), "exported.db")
	store, err := OpenExportedStore(path)
	if err != nil {
		t.Fatal(err)
	}
	files := []ManifestFile{
		{Path: "npm/a.tgz", SHA256: strings.Repeat("a", 64), Size: 1},
		{Path: "npm/b.tgz", SHA256: strings.Repeat("b", 64), Size: 1},
	}
	if ok, err := store.IsForwarded(streamNpm, files[0].Path, files[0].SHA256); err != nil || ok {
		t.Fatalf("IsForwarded before record = %v, %v", ok, err)
	}
	if err := store.Record(streamNpm, files); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(streamNpm, nil); err != nil { // empty is a no-op
		t.Fatal(err)
	}
	if ok, err := store.IsForwarded(streamNpm, files[0].Path, files[0].SHA256); err != nil || !ok {
		t.Fatalf("IsForwarded after record = %v, %v", ok, err)
	}
	flags, err := store.ForwardedFlags(streamNpm, append(files, ManifestFile{Path: "npm/c.tgz", SHA256: strings.Repeat("c", 64)}))
	if err != nil {
		t.Fatal(err)
	}
	if !flags[0] || !flags[1] || flags[2] {
		t.Errorf("ForwardedFlags = %v, want [true true false]", flags)
	}
	if empty, err := store.ForwardedFlags(streamNpm, nil); err != nil || len(empty) != 0 {
		t.Errorf("ForwardedFlags(nil) = %v, %v", empty, err)
	}
	if n, err := store.Count(streamNpm); err != nil || n != 2 {
		t.Errorf("Count = %d, %v, want 2", n, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil { // idempotent
		t.Errorf("second Close = %v", err)
	}
}

// TestCovSrv_MigrateLegacyExported folds a legacy hash-only table into the new
// schema on reopen.
func TestCovSrv_MigrateLegacyExported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	store, err := OpenExportedStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TABLE exported_content (stream TEXT NOT NULL, sha256 TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO exported_content (stream, sha256) VALUES (?, ?)`, streamGo, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenExportedStore(path)
	if err != nil {
		t.Fatalf("reopen (migration): %v", err)
	}
	defer reopened.Close()
	// The legacy row migrated with an empty path, so it matches any path by hash.
	if ok, err := reopened.IsForwarded(streamGo, "go/anything.zip", strings.Repeat("d", 64)); err != nil || !ok {
		t.Fatalf("migrated legacy hash not matched: %v, %v", ok, err)
	}
	if n, err := reopened.Count(streamGo); err != nil || n != 1 {
		t.Errorf("migrated Count = %d, %v, want 1", n, err)
	}
}

// TestCovSrv_OpenExportedStoreError covers the init failure path (a directory is
// not a usable database file).
func TestCovSrv_OpenExportedStoreError(t *testing.T) {
	if _, err := OpenExportedStore(t.TempDir()); err == nil {
		t.Error("opening a directory as a database should error")
	}
}

// -----------------------------------------------------------------------------
// pitcher.go / catcher.go
// -----------------------------------------------------------------------------

func TestCovSrv_IsTransientSendErr(t *testing.T) {
	for _, e := range []error{syscall.ENOBUFS, syscall.EADDRNOTAVAIL, syscall.ENETDOWN, syscall.ENETUNREACH} {
		if !isTransientSendErr(e) {
			t.Errorf("isTransientSendErr(%v) = false, want true", e)
		}
	}
	if isTransientSendErr(io.EOF) {
		t.Error("EOF should not be a transient send error")
	}
}

func TestCovSrv_RatePacer(t *testing.T) {
	rp := newRatePacer(1000) // 1000 Mbit/s
	if rp.bytesPerSec <= 0 {
		t.Fatalf("bytesPerSec = %f", rp.bytesPerSec)
	}
	// A small request fits within the initial burst and returns promptly.
	start := time.Now()
	rp.wait(1024)
	if time.Since(start) > time.Second {
		t.Errorf("wait blocked too long: %s", time.Since(start))
	}
}

func TestCovSrv_PitcherTarget(t *testing.T) {
	p := &diodePitcher{cfg: PitcherConfig{Group: "ff02::4147", Interface: "eth1", Port: 4147}}
	if got := p.target(); got != "[ff02::4147%eth1]:4147" {
		t.Errorf("target() = %q", got)
	}
}

func TestCovSrv_HashDiodeFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hash-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("diode-bytes"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	sum, err := hashDiodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if sum != sha256.Sum256([]byte("diode-bytes")) {
		t.Error("hashDiodeFile digest mismatch")
	}
	// hashDiodeFile rewinds for the send pass.
	if pos, _ := f.Seek(0, io.SeekCurrent); pos != 0 {
		t.Errorf("file not rewound, pos = %d", pos)
	}
}

// TestCovSrv_EnvMulticastGroup covers the default, IPv4-rejection, and junk arms.
func TestCovSrv_EnvMulticastGroup(t *testing.T) {
	const name = "ARTIGATE_COVSRV_GROUP"
	t.Setenv(name, "")
	if got, err := envMulticastGroup(name); err != nil || got != diodeDefaultGroup {
		t.Errorf("default group = %q, %v", got, err)
	}
	t.Setenv(name, "224.0.0.1") // IPv4 multicast, rejected
	if _, err := envMulticastGroup(name); err == nil {
		t.Error("IPv4 group should be rejected")
	}
	t.Setenv(name, "not-an-ip")
	if _, err := envMulticastGroup(name); err == nil {
		t.Error("junk group should be rejected")
	}
	t.Setenv(name, "ff02::5")
	if got, err := envMulticastGroup(name); err != nil || got != "ff02::5" {
		t.Errorf("valid group = %q, %v", got, err)
	}
}

// TestCovSrv_PitcherCatcherConfigFromEnv covers the disabled default and an
// invalid numeric setting for both diode config parsers.
func TestCovSrv_PitcherCatcherConfigFromEnv(t *testing.T) {
	t.Setenv("ARTIGATE_PITCHER_INTERFACE", "")
	if cfg, err := pitcherConfigFromEnv(); err != nil || cfg.Interface != "" {
		t.Errorf("disabled pitcher = %+v, %v", cfg, err)
	}
	t.Setenv("ARTIGATE_PITCHER_INTERFACE", "diode0")
	t.Setenv("ARTIGATE_PITCHER_MTU", "9") // below the minimum
	if _, err := pitcherConfigFromEnv(); err == nil {
		t.Error("out-of-range pitcher MTU should error")
	}

	t.Setenv("ARTIGATE_CATCHER_INTERFACE", "")
	if cfg, err := catcherConfigFromEnv(); err != nil || cfg.Interface != "" {
		t.Errorf("disabled catcher = %+v, %v", cfg, err)
	}
	t.Setenv("ARTIGATE_CATCHER_INTERFACE", "diode0")
	t.Setenv("ARTIGATE_CATCHER_PORT", "0") // below the minimum
	if _, err := catcherConfigFromEnv(); err == nil {
		t.Error("out-of-range catcher port should error")
	}
}

func TestCovSrv_BundleBaseName(t *testing.T) {
	if got := bundleBaseName("go-bundle-000042.tar.gz"); got != "go-bundle-000042" {
		t.Errorf("bundleBaseName(tar.gz) = %q", got)
	}
	if got := bundleBaseName("go-bundle-000042.manifest.json.sig"); got != "go-bundle-000042" {
		t.Errorf("bundleBaseName(sig) = %q", got)
	}
	// A name with no recognized bundle suffix is returned unchanged.
	if got := bundleBaseName("random-file.txt"); got != "random-file.txt" {
		t.Errorf("bundleBaseName(unknown) = %q", got)
	}
}

// -----------------------------------------------------------------------------
// progress.go
// -----------------------------------------------------------------------------

// TestCovSrv_DlNameFromURLFallback covers the empty-path fallback arm.
func TestCovSrv_DlNameFromURLFallback(t *testing.T) {
	// A URL with no path component falls back to path.Base of the whole string.
	if got := dlNameFromURL("http://host"); got != "host" {
		t.Errorf("dlNameFromURL(no path) = %q, want host", got)
	}
	// An unparseable URL also falls through to the base-name path.
	if got := dlNameFromURL("::::"); got == "" {
		t.Errorf("dlNameFromURL(junk) = %q, want non-empty", got)
	}
}

// TestCovSrv_NewProgressTracker covers the nil-sink and negative-total arms.
func TestCovSrv_NewProgressTracker(t *testing.T) {
	if tr := newProgressTracker(context.Background(), "x", 10); tr != nil {
		t.Error("no sink should yield a nil tracker")
	}
	ctx := withDownloadProgress(context.Background(), func(string, int64, int64, int64) {})
	tr := newProgressTracker(ctx, "x", -5)
	if tr == nil || tr.total != 0 {
		t.Errorf("negative total should normalize to 0, got %+v", tr)
	}
}
