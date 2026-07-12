package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// covS2RecReq builds a recorder plus request for direct handler calls.
func covS2RecReq(method, path, body string) (*httptest.ResponseRecorder, *http.Request) {
	return httptest.NewRecorder(), httptest.NewRequest(method, path, strings.NewReader(body))
}

// -----------------------------------------------------------------------------
// diode.go — pure validators and store-error classifiers
// -----------------------------------------------------------------------------

// TestCovS2_ValidateDiodeURL covers every arm of the startup URL check.
func TestCovS2_ValidateDiodeURL(t *testing.T) {
	if err := validateDiodeURL(""); err != nil {
		t.Errorf("empty URL should be allowed: %v", err)
	}
	for _, ok := range []string{"http://diode.local/ingest", "https://d.internal:8443/x"} {
		if err := validateDiodeURL(ok); err != nil {
			t.Errorf("valid URL %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://d.local", "://nohost", "http://", "not a url"} {
		if err := validateDiodeURL(bad); err == nil {
			t.Errorf("invalid URL %q accepted", bad)
		}
	}
}

// TestCovS2_DiodeTokenStatus covers both description arms.
func TestCovS2_DiodeTokenStatus(t *testing.T) {
	if got := diodeTokenStatus(""); !strings.Contains(got, "open to the network") {
		t.Errorf("empty token status = %q", got)
	}
	if got := diodeTokenStatus("x"); !strings.Contains(got, "bearer token required") {
		t.Errorf("set token status = %q", got)
	}
}

// TestCovS2_BundleFileSizeLimitUnknown covers the default (unsupported) arm.
func TestCovS2_BundleFileSizeLimitUnknown(t *testing.T) {
	if _, ok := bundleFileSizeLimit("go-bundle-000001.txt"); ok {
		t.Error("an unsupported suffix should not have a size limit")
	}
}

// TestCovS2_DiodeStoreErrorClassifiers covers diodeStoreErrorStatus and
// diodeStoreError across the non-quota, quota, and oversized arms.
func TestCovS2_DiodeStoreErrorClassifiers(t *testing.T) {
	const fileLimit int64 = 1024
	plain := errors.New("disk gone")
	maxErr := &http.MaxBytesError{Limit: 512}

	// Non-MaxBytesError → 500 and a "store <name>" error.
	if s := diodeStoreErrorStatus(plain, fileLimit, fileLimit); s != http.StatusInternalServerError {
		t.Errorf("plain status = %d, want 500", s)
	}
	if err := diodeStoreError("go-bundle-000001.tar.gz", plain, fileLimit, fileLimit); err == nil ||
		!strings.Contains(err.Error(), "store go-bundle-000001.tar.gz") {
		t.Errorf("plain store error = %v", err)
	}
	// MaxBytesError with the limit tightened by the quota (limit < fileLimit) →
	// 507 and a quota message.
	if s := diodeStoreErrorStatus(maxErr, 256, fileLimit); s != http.StatusInsufficientStorage {
		t.Errorf("quota status = %d, want 507", s)
	}
	if err := diodeStoreError("x", maxErr, 256, fileLimit); err == nil ||
		!strings.Contains(err.Error(), "quota would be exceeded") {
		t.Errorf("quota store error = %v", err)
	}
	// MaxBytesError at the file-type ceiling (limit == fileLimit) → 413.
	if s := diodeStoreErrorStatus(maxErr, fileLimit, fileLimit); s != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized status = %d, want 413", s)
	}
	if err := diodeStoreError("x", maxErr, fileLimit, fileLimit); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversized store error = %v", err)
	}
}

// TestCovS2_UploadDiodeFileErrors covers uploadDiodeFile's open-failure and
// non-2xx-response arms via a bare low server and a stub endpoint.
func TestCovS2_UploadDiodeFileErrors(t *testing.T) {
	ls := newBareLowServer(t)

	// Missing source file: os.Open fails before any request.
	if err := ls.uploadDiodeFile(context.Background(), "http://127.0.0.1:1/diode", "go-bundle-000001.tar.gz"); err == nil {
		t.Error("uploadDiodeFile of a missing file should error")
	}

	// A staged file that the endpoint rejects with 500 surfaces the HTTP status.
	name := "go-bundle-000001.manifest.json.sig"
	writeFile(t, filepath.Join(ls.cfg.ExportDir, name), []byte("sig"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	ls.cfg.DiodeToken = strings.Repeat("t", 32)
	if err := ls.uploadDiodeFile(context.Background(), srv.URL, name); err == nil ||
		!strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("uploadDiodeFile non-2xx = %v, want an HTTP 500 error", err)
	}
}

// TestCovS2_DirectoryRegularFileBytesExcept covers the skip predicate and the
// directory/regular-file discrimination.
func TestCovS2_DirectoryRegularFileBytesExcept(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.bin"), []byte("12345"))     // counted
	writeFile(t, filepath.Join(dir, "skip.me"), []byte("ignored")) // skipped by predicate
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	total, err := directoryRegularFileBytesExcept(dir, func(n string) bool { return n == "skip.me" })
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5 (only a.bin)", total)
	}
	// A missing directory totals zero without error.
	if got, err := directoryRegularFileBytesExcept(filepath.Join(dir, "gone"), nil); err != nil || got != 0 {
		t.Errorf("missing dir = %d, %v, want 0, nil", got, err)
	}
}

// -----------------------------------------------------------------------------
// ui_low.go — serveLowUI guards and the logout button
// -----------------------------------------------------------------------------

// TestCovS2_ServeLowUI covers the method guards, the unhandled default, and the
// authenticated-only logout button in the rendered page.
func TestCovS2_ServeLowUI(t *testing.T) {
	ls := newBareLowServer(t)

	// Writes to the read-only routes are rejected.
	for _, path := range []string{"/", "/ui/api/status"} {
		rec, req := covS2RecReq(http.MethodPost, path, "")
		if !ls.serveLowUI(rec, req) || rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s status = %d, want 405", path, rec.Code)
		}
	}
	// An unknown path is not handled.
	rec, req := covS2RecReq(http.MethodGet, "/nope", "")
	if ls.serveLowUI(rec, req) {
		t.Error("/nope should not be handled by serveLowUI")
	}
	// The index renders; with auth enabled it carries a Log out button.
	if strings.Contains(ls.renderLowUI(), "Log out") {
		t.Error("logout button shown without auth")
	}
	ls.authEnabled = true
	if !strings.Contains(ls.renderLowUI(), "Log out") {
		t.Error("logout button missing with auth enabled")
	}
	rec, req = covS2RecReq(http.MethodGet, "/", "")
	if !ls.serveLowUI(rec, req) || rec.Code != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// uploads.go — delete success and folder listing
// -----------------------------------------------------------------------------

// TestCovS2_HandleDeleteUploadSuccess drives the delete handler down its
// happy path: an existing file is removed and its emptied folder with it.
func TestCovS2_HandleDeleteUploadSuccess(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	dir := filepath.Join(hs.uploadsDir(), "tools")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.txt"), []byte("hi"))

	rec, req := covS2RecReq(http.MethodPost, "/admin/uploads/delete", `{"folder":"tools","name":"a.txt"}`)
	if !hs.handleDeleteUpload(rec, req) || rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body %s", rec.Code, rec.Body.String())
	}
	if fileExists(filepath.Join(dir, "a.txt")) {
		t.Error("file was not removed")
	}
}

// TestCovS2_ListUploadedFolders covers the tree walk: a loose top-level file and
// an empty folder are skipped, a populated folder is returned.
func TestCovS2_ListUploadedFolders(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	root := hs.uploadsDir()
	if err := os.MkdirAll(filepath.Join(root, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "loose.txt"), []byte("x")) // not a folder → skipped
	writeFile(t, filepath.Join(root, "tools", "a.txt"), []byte("y"))

	folders, err := hs.listUploadedFolders()
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 1 || folders[0].Folder != "tools" || len(folders[0].Files) != 1 {
		t.Errorf("folders = %+v, want a single 'tools' folder with one file", folders)
	}
}

// -----------------------------------------------------------------------------
// python.go — Simple project page, and CollectPython error arms
// -----------------------------------------------------------------------------

// TestCovS2_ServePythonSimpleProject serves a project's file list (scan +
// per-file sha256 rendering) and covers the not-found arm.
func TestCovS2_ServePythonSimpleProject(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if err := os.MkdirAll(hs.pythonDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hs.pythonDir(), "requests-2.32.4-py3-none-any.whl"), []byte("wheel"))

	rec, req := covS2RecReq(http.MethodGet, "/simple/requests/", "")
	if !hs.servePython(rec, req) || rec.Code != http.StatusOK {
		t.Fatalf("simple project status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "requests-2.32.4-py3-none-any.whl#sha256=") {
		t.Errorf("simple project body missing hashed wheel link: %s", rec.Body.String())
	}
	// An unknown project 404s.
	rec, req = covS2RecReq(http.MethodGet, "/simple/nope/", "")
	if !hs.servePython(rec, req) || rec.Code != http.StatusNotFound {
		t.Errorf("unknown project status = %d, want 404", rec.Code)
	}
}

const covS2PipFailScript = `#!/usr/bin/env bash
echo "boom" >&2
exit 3
`

const covS2PipEmptyScript = `#!/usr/bin/env bash
set -eu
dest=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dest" ]; then dest="$a"; fi
  prev="$a"
done
mkdir -p "$dest"
`

// TestCovS2_CollectPythonErrors covers the pip-failure and no-artifacts arms.
func TestCovS2_CollectPythonErrors(t *testing.T) {
	fail, _ := newPyLowServerWithPip(t, covS2PipFailScript)
	if _, err := fail.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"requests"}}); err == nil ||
		!strings.Contains(err.Error(), "pip") {
		t.Errorf("failing pip = %v, want a pip error", err)
	}

	empty, _ := newPyLowServerWithPip(t, covS2PipEmptyScript)
	if _, err := empty.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"requests"}}); err == nil ||
		!strings.Contains(err.Error(), "no wheels") {
		t.Errorf("empty pip download = %v, want a no-wheels error", err)
	}
}

// -----------------------------------------------------------------------------
// ui.go — pythonDetail arms
// -----------------------------------------------------------------------------

// TestCovS2_PythonDetail covers the invalid-name, not-found, and success arms.
func TestCovS2_PythonDetail(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if err := os.MkdirAll(hs.pythonDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	name := "requests-2.32.4-py3-none-any.whl"
	writeFile(t, filepath.Join(hs.pythonDir(), name), []byte("wheel-bytes"))

	if _, err := hs.pythonDetail(""); err == nil {
		t.Error("empty filename should error")
	}
	if _, err := hs.pythonDetail("a/b.whl"); err == nil {
		t.Error("filename with a separator should error")
	}
	if _, err := hs.pythonDetail("ghost.whl"); err == nil {
		t.Error("missing wheel should error")
	}
	d, err := hs.pythonDetail(name)
	if err != nil {
		t.Fatalf("pythonDetail(%q) = %v", name, err)
	}
	if d.Subtitle != "2.32.4" {
		t.Errorf("detail version = %q, want 2.32.4", d.Subtitle)
	}
	var hasSHA bool
	for _, f := range d.Fields {
		if f.Label == "SHA-256" {
			hasSHA = true
		}
	}
	if !hasSHA {
		t.Error("detail missing SHA-256 field")
	}
}

// -----------------------------------------------------------------------------
// login.go — handleLogin arms, currentUser, session keys
// -----------------------------------------------------------------------------

// TestCovS2_HandleLoginArms covers the malformed-body (400), rate-limited (429),
// and bad-credentials (303 back to /login?e=1) POST arms.
func TestCovS2_HandleLoginArms(t *testing.T) {
	am := newTestAuth(t)

	// A body with invalid percent-encoding fails ParseForm → 400.
	rec, req := covS2RecReq(http.MethodPost, "/login", "x=%zz")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	am.handleLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body = %d, want 400", rec.Code)
	}

	// Saturate the verification semaphore so the next attempt is not admitted → 429.
	for i := 0; i < maxConcurrentLogins; i++ {
		am.verifySem <- struct{}{}
	}
	rec, req = covS2RecReq(http.MethodPost, "/login", "username=alice&password=pw")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	am.handleLogin(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("saturated login = %d, want 429", rec.Code)
	}
	for i := 0; i < maxConcurrentLogins; i++ {
		<-am.verifySem
	}

	// Wrong password redirects back to the login page with the error flag.
	rec, req = covS2RecReq(http.MethodPost, "/login", "username=alice&password=wrong")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	am.handleLogin(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?e=1" {
		t.Errorf("bad creds = %d %q, want 303 to /login?e=1", rec.Code, rec.Header().Get("Location"))
	}
}

// TestCovS2_CurrentUserBadCookie covers the cookie-decode-failure arm.
func TestCovS2_CurrentUserBadCookie(t *testing.T) {
	am := newTestAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "not-a-valid-cookie"})
	if _, ok := am.currentUser(req); ok {
		t.Error("a garbage cookie should not authenticate")
	}
}

// TestCovS2_LoadSessionKeysReadError covers the non-ENOENT read-error arm: a
// directory path is not a readable key file.
func TestCovS2_LoadSessionKeysReadError(t *testing.T) {
	if _, _, err := loadOrCreateSessionKeys(t.TempDir()); err == nil {
		t.Error("reading a directory as a session key file should error")
	}
}

// -----------------------------------------------------------------------------
// exported.go — Record on a closed store
// -----------------------------------------------------------------------------

// TestCovS2_RecordOnClosedStore covers Record's transaction-open error arm.
func TestCovS2_RecordOnClosedStore(t *testing.T) {
	store, err := OpenExportedStore(filepath.Join(t.TempDir(), "exp.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(streamNpm, []ManifestFile{mf("npm/a.tgz", "a")}); err == nil {
		t.Error("Record on a closed store should error")
	}
}

// -----------------------------------------------------------------------------
// tls.go — selfSignedCert IP and default-name arms
// -----------------------------------------------------------------------------

// TestCovS2_SelfSignedCertArms covers the IP-SAN branch and the no-domain
// default-name fallback.
func TestCovS2_SelfSignedCertArms(t *testing.T) {
	if _, err := selfSignedCert([]string{"127.0.0.1", "::1"}); err != nil {
		t.Errorf("IP self-signed cert: %v", err)
	}
	if _, err := selfSignedCert(nil); err != nil {
		t.Errorf("default-name self-signed cert: %v", err)
	}
}

// -----------------------------------------------------------------------------
// pitcher.go / catcher.go — env config validators
// -----------------------------------------------------------------------------

// TestCovS2_PitcherConfigRanges covers the remaining out-of-range validation
// arms for the pitcher (an enabled interface is required to reach them).
func TestCovS2_PitcherConfigRanges(t *testing.T) {
	t.Setenv("ARTIGATE_PITCHER_INTERFACE", "diode0")
	cases := []struct{ name, val string }{
		{"ARTIGATE_PITCHER_TXQUEUELEN", "0"},
		{"ARTIGATE_PITCHER_PORT", "0"},
		{"ARTIGATE_PITCHER_FEC_DATA", "0"},
		{"ARTIGATE_PITCHER_FEC_PARITY", "0"},
	}
	for _, c := range cases {
		t.Setenv(c.name, c.val)
		if _, err := pitcherConfigFromEnv(); err == nil {
			t.Errorf("out-of-range %s should error", c.name)
		}
		t.Setenv(c.name, "") // restore default for the next case
	}
}

// TestCovS2_CatcherConfigRanges covers the remaining out-of-range/invalid arms
// for the catcher.
func TestCovS2_CatcherConfigRanges(t *testing.T) {
	t.Setenv("ARTIGATE_CATCHER_INTERFACE", "diode0")

	t.Setenv("ARTIGATE_CATCHER_MTU", "10") // below the 1280 minimum
	if _, err := catcherConfigFromEnv(); err == nil {
		t.Error("out-of-range catcher MTU should error")
	}
	t.Setenv("ARTIGATE_CATCHER_MTU", "")

	t.Setenv("ARTIGATE_CATCHER_RCVBUF_MB", "0")
	if _, err := catcherConfigFromEnv(); err == nil {
		t.Error("out-of-range catcher receive buffer should error")
	}
	t.Setenv("ARTIGATE_CATCHER_RCVBUF_MB", "")

	t.Setenv("ARTIGATE_CATCHER_GROUP", "224.0.0.1") // IPv4, rejected
	if _, err := catcherConfigFromEnv(); err == nil {
		t.Error("IPv4 catcher group should error")
	}
	t.Setenv("ARTIGATE_CATCHER_GROUP", "")

	t.Setenv("ARTIGATE_CATCHER_NETSETUP", "maybe")
	if _, err := catcherConfigFromEnv(); err == nil {
		t.Error("invalid catcher netsetup should error")
	}
}

// TestCovS2_MustPitcherConfigDisabled covers mustPitcherConfig's disabled path
// (no interface set, no diode URL): it returns a zero config without exiting.
func TestCovS2_MustPitcherConfigDisabled(t *testing.T) {
	t.Setenv("ARTIGATE_PITCHER_INTERFACE", "")
	if cfg := mustPitcherConfig(""); cfg.Interface != "" {
		t.Errorf("disabled mustPitcherConfig = %+v, want zero", cfg)
	}
}

// TestCovS2_NewDiodePitcherLoopback constructs a real pitcher over IPv6
// loopback via the shared helper, covering newDiodePitcher's success path.
func TestCovS2_NewDiodePitcherLoopback(t *testing.T) {
	p, _ := newLoopbackDiodePair(t, t.TempDir(), func(string) {})
	if got := p.target(); !strings.Contains(got, "::1") {
		t.Errorf("pitcher target = %q, want a loopback address", got)
	}
}
