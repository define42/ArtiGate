package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestAuth builds an authManager with a single user alice/pw and a fresh
// key file, for handler tests.
func newTestAuth(t *testing.T) *authManager {
	t.Helper()
	alice, err := hashArgon2("pw")
	if err != nil {
		t.Fatal(err)
	}
	am, err := newAuthManager(map[string]string{"alice": alice}, filepath.Join(t.TempDir(), "session.key"), false)
	if err != nil {
		t.Fatal(err)
	}
	return am
}

// testNext returns the protected handler the middleware guards.
func testNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NEXT"))
	})
}

func serveReq(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loginPost(user, pass string) *http.Request {
	form := url.Values{"username": {user}, "password": {pass}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func assertRedirect(t *testing.T, rec *httptest.ResponseRecorder, loc string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != loc {
		t.Fatalf("Location = %q, want %q", got, loc)
	}
}

func TestMiddlewareUnauthenticated(t *testing.T) {
	h := newTestAuth(t).middleware(testNext())

	// A browser navigation with no session is redirected to the login page.
	nav := httptest.NewRequest(http.MethodGet, "/", nil)
	nav.Header.Set("Accept", "text/html")
	assertRedirect(t, serveReq(h, nav), "/login")

	// An API/fetch call with no session gets 401 (the UI turns this into a redirect).
	if rec := serveReq(h, httptest.NewRequest(http.MethodGet, "/ui/api/status", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauth API: code = %d, want 401", rec.Code)
	}

	// The health check is always allowed.
	if rec := serveReq(h, httptest.NewRequest(http.MethodGet, "/healthz", nil)); rec.Body.String() != "NEXT" {
		t.Errorf("healthz should pass through, got body %q code %d", rec.Body.String(), rec.Code)
	}

	// The login page itself is reachable unauthenticated.
	rec := serveReq(h, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Errorf("login page: code = %d", rec.Code)
	}
}

func TestLoginAndLogout(t *testing.T) {
	h := newTestAuth(t).middleware(testNext())

	// Wrong password: redirect back to the login page with the error flag, no cookie.
	bad := serveReq(h, loginPost("alice", "wrong"))
	assertRedirect(t, bad, "/login?e=1")
	if sessionCookie(bad) != nil {
		t.Error("failed login should not set a session cookie")
	}

	// Correct password: redirect home with a session cookie.
	ok := serveReq(h, loginPost("alice", "pw"))
	assertRedirect(t, ok, "/")
	ck := sessionCookie(ok)
	if ck == nil || ck.Value == "" {
		t.Fatal("successful login should set a session cookie")
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie should be HttpOnly+Lax, got %+v", ck)
	}

	// Reusing the cookie reaches the protected handler.
	authed := httptest.NewRequest(http.MethodGet, "/", nil)
	authed.Header.Set("Accept", "text/html")
	authed.AddCookie(ck)
	if rec := serveReq(h, authed); rec.Body.String() != "NEXT" {
		t.Errorf("authed request: body = %q, want NEXT", rec.Body.String())
	}

	// Logout clears the cookie and returns to the login page.
	out := httptest.NewRequest(http.MethodPost, "/logout", nil)
	out.AddCookie(ck)
	rec := serveReq(h, out)
	assertRedirect(t, rec, "/login")
	if cleared := sessionCookie(rec); cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("logout should expire the cookie, got %+v", cleared)
	}
}

func TestCurrentUserRejectsUnknown(t *testing.T) {
	am := newTestAuth(t)
	// A cookie that decodes correctly but names a user no longer configured
	// (e.g. removed from ARTIGATE_LOW_AUTH) must not authenticate.
	enc, err := am.sc.Encode(sessionCookieName, "ghost")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: enc})
	if _, ok := am.currentUser(req); ok {
		t.Error("cookie for an unconfigured user should not authenticate")
	}
}

func TestSessionKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.key")
	h1, b1, err := loadOrCreateSessionKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != sessionHashKeyLen || len(b1) != sessionBlockKeyLen {
		t.Fatalf("key lengths = %d, %d; want %d, %d", len(h1), len(b1), sessionHashKeyLen, sessionBlockKeyLen)
	}
	// A second call reuses the persisted keys so sessions survive a restart.
	h2, b2, err := loadOrCreateSessionKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) || !bytes.Equal(b1, b2) {
		t.Error("keys should persist across calls")
	}
	// A malformed key file is a clear error, not a silent key rotation.
	bad := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(bad, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateSessionKeys(bad); err == nil {
		t.Error("wrong-size key file should error")
	}
}

func TestLoginPage(t *testing.T) {
	if !strings.Contains(loginPage(true), "Invalid username or password") {
		t.Error("error page should show the error banner")
	}
	if strings.Contains(loginPage(false), "Invalid username or password") {
		t.Error("non-error page should not show the error banner")
	}
	if strings.Contains(loginPage(false), "{{ERROR}}") {
		t.Error("{{ERROR}} placeholder was not substituted")
	}
}

func TestCookieSecure(t *testing.T) {
	cases := []struct {
		override  string
		tlsSecure bool
		want      bool
		wantErr   bool
	}{
		{"", false, false, false},    // default follows TLS mode (plain HTTP)
		{"", true, true, false},      // default follows TLS mode (TLS on)
		{"auto", true, true, false},  // explicit auto == default
		{"true", false, true, false}, // force Secure behind a TLS proxy
		{"on", false, true, false},
		{"false", true, false, false}, // force off even when serving TLS
		{"0", true, false, false},
		{"maybe", false, false, true}, // unrecognised value is an error
	}
	for _, c := range cases {
		got, err := cookieSecure(c.tlsSecure, c.override)
		if (err != nil) != c.wantErr {
			t.Errorf("cookieSecure(%v, %q) err = %v, wantErr = %v", c.tlsSecure, c.override, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Errorf("cookieSecure(%v, %q) = %v, want %v", c.tlsSecure, c.override, got, c.want)
		}
	}
}

func TestCheckCredentialConcurrent(t *testing.T) {
	am := newTestAuth(t) // single user alice/pw
	// Correct results under concurrent load, and the semaphore must not deadlock
	// when more callers than maxConcurrentLogins run at once.
	const n = maxConcurrentLogins * 4
	results := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func() { results <- am.checkCredential("alice", "pw") }()
		go func() { results <- am.checkCredential("alice", "wrong") }()
	}
	good, bad := 0, 0
	for i := 0; i < 2*n; i++ {
		if <-results {
			good++
		} else {
			bad++
		}
	}
	if good != n || bad != n {
		t.Errorf("good = %d, bad = %d; want %d each", good, bad, n)
	}
}

func TestWantsHTML(t *testing.T) {
	nav := httptest.NewRequest(http.MethodGet, "/", nil)
	nav.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !wantsHTML(nav) {
		t.Error("GET with text/html Accept should want HTML")
	}
	api := httptest.NewRequest(http.MethodGet, "/ui/api/x", nil)
	api.Header.Set("Accept", "application/json")
	if wantsHTML(api) {
		t.Error("JSON Accept should not want HTML")
	}
	post := httptest.NewRequest(http.MethodPost, "/", nil)
	post.Header.Set("Accept", "text/html")
	if wantsHTML(post) {
		t.Error("POST should not be treated as a page navigation")
	}
}
