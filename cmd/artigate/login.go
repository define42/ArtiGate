package main

// Low-side session login. When ARTIGATE_LOW_AUTH is configured, the low-side
// dashboard is protected by a cookie session instead of per-request Basic auth:
// the operator signs in through a form, and an encrypted+signed session cookie
// (gorilla/securecookie) carries the identity afterwards. A "Log out" button
// clears it. Credentials are still the argon2id hashes parsed from
// ARTIGATE_LOW_AUTH (see auth.go). The high side is never authenticated.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
)

const (
	sessionCookieName  = "artigate_session"
	sessionMaxAge      = 12 * 60 * 60 // seconds a login stays valid (12h)
	sessionHashKeyLen  = 64           // HMAC key length for securecookie
	sessionBlockKeyLen = 32           // AES-256 key length for securecookie

	// maxConcurrentLogins bounds how many argon2id verifications run at once.
	// Each verification allocates ~64 MiB, and POST /login is unauthenticated, so
	// without a cap a flood of login attempts could exhaust memory and OOM the
	// process. Admission is non-blocking: attempts beyond the cap are rejected
	// with 429 rather than queued, so waiting requests and connections cannot pile
	// up unbounded.
	maxConcurrentLogins = 4

	// maxLoginBodyBytes caps the POST /login request body. The form is a tiny
	// username+password, so anything larger is refused before it is read — a slow
	// or oversized body on this unauthenticated endpoint cannot tie up resources.
	maxLoginBodyBytes = 16 << 10
	// loginReadTimeout bounds how long the whole login body may take to arrive,
	// defeating a slow-trickle body on this endpoint (the server sets no global
	// ReadTimeout because it must stream large artifacts elsewhere).
	loginReadTimeout = 15 * time.Second

	// loginFailureThreshold locks a known account after this many consecutive
	// failed logins; loginLockoutWindow is how long the lock then lasts. Only
	// configured usernames are tracked, so the attacker-supplied username field
	// cannot grow the failure table, and a wrong password no longer permits
	// unlimited online guessing against a real account.
	loginFailureThreshold = 5
	loginLockoutWindow    = time.Minute
)

// loginFailure tracks consecutive failed logins for one configured user.
type loginFailure struct {
	count       int
	lockedUntil time.Time
}

// authManager holds the credential set and the session-cookie codec.
type authManager struct {
	users     map[string]string // username -> argon2id hash
	sc        *securecookie.SecureCookie
	secure    bool          // set the cookie's Secure flag (true when serving over TLS)
	verifySem chan struct{} // bounds concurrent (memory-heavy) argon2 verifications

	failMu   sync.Mutex
	failures map[string]loginFailure // per configured user; bounded by len(users)
}

// newAuthManager builds the session manager, loading (or creating) the cookie
// signing keys from keyPath so that sessions survive a restart.
func newAuthManager(users map[string]string, keyPath string, secure bool) (*authManager, error) {
	hashKey, blockKey, err := loadOrCreateSessionKeys(keyPath)
	if err != nil {
		return nil, err
	}
	sc := securecookie.New(hashKey, blockKey)
	sc.MaxAge(sessionMaxAge)
	return &authManager{
		users:     users,
		sc:        sc,
		secure:    secure,
		verifySem: make(chan struct{}, maxConcurrentLogins),
		failures:  map[string]loginFailure{},
	}, nil
}

// loginLocked reports whether user is currently locked out after repeated
// failed logins.
func (a *authManager) loginLocked(user string, now time.Time) bool {
	a.failMu.Lock()
	defer a.failMu.Unlock()
	return now.Before(a.failures[user].lockedUntil)
}

// noteLoginResult records a login outcome. Success clears the user's failure
// count; a failure increments it and, at the threshold, starts a lockout window.
// Only configured usernames are tracked, so the table stays bounded by the
// credential set no matter what username field an attacker submits.
func (a *authManager) noteLoginResult(user string, ok bool) {
	if _, known := a.users[user]; !known {
		return
	}
	a.failMu.Lock()
	defer a.failMu.Unlock()
	if ok {
		delete(a.failures, user)
		return
	}
	f := a.failures[user]
	f.count++
	if f.count >= loginFailureThreshold {
		f.count = 0
		f.lockedUntil = time.Now().Add(loginLockoutWindow)
	}
	a.failures[user] = f
}

// checkCredential verifies user/pass under a non-blocking concurrency cap. At
// most maxConcurrentLogins argon2 verifications run at once so the unauthenticated
// login endpoint cannot be turned into a memory-exhaustion DoS; when the cap is
// full it returns admitted=false immediately (the caller responds 429) instead of
// queuing, so waiting requests cannot accumulate. ok is the credential result and
// is only meaningful when admitted is true.
func (a *authManager) checkCredential(user, pass string) (ok, admitted bool) {
	select {
	case a.verifySem <- struct{}{}:
		defer func() { <-a.verifySem }()
		return credentialOK(a.users, user, pass), true
	default:
		return false, false
	}
}

// cookieSecure decides the session cookie's Secure attribute. By default it
// follows whether ArtiGate itself terminates TLS, but ARTIGATE_LOW_COOKIE_SECURE
// overrides it — set it to "true" when ArtiGate speaks plain HTTP behind a
// TLS-terminating reverse proxy, so the cookie is still marked Secure.
func cookieSecure(tlsSecure bool, override string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "", "auto":
		return tlsSecure, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid ARTIGATE_LOW_COOKIE_SECURE %q (want auto, true, or false)", override)
	}
}

// loadOrCreateSessionKeys returns the HMAC and AES keys for the session codec,
// reading them from path or generating and persisting them on first use.
func loadOrCreateSessionKeys(path string) (hashKey, blockKey []byte, err error) {
	const wantLen = sessionHashKeyLen + sessionBlockKeyLen
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != wantLen {
			return nil, nil, fmt.Errorf("session key file %s has size %d, want %d; delete it to regenerate", path, len(b), wantLen)
		}
	case errors.Is(err, os.ErrNotExist):
		b = make([]byte, wantLen)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, nil, fmt.Errorf("write session key: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("read session key: %w", err)
	}
	return b[:sessionHashKeyLen], b[sessionHashKeyLen:], nil
}

// middleware enforces authentication on every request except the health check,
// the /metrics scrape endpoint, and the login/logout endpoints, which it
// handles itself.
func (a *authManager) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/metrics":
			// Operational endpoints a monitoring system scrapes without a login,
			// like the health check. They expose only the same non-secret status
			// the dashboard shows; front the listener with a proxy or firewall the
			// scrape port to restrict them.
			next.ServeHTTP(w, r)
			return
		case "/login":
			a.handleLogin(w, r)
			return
		case "/logout":
			a.handleLogout(w, r)
			return
		}
		if user, ok := a.currentUser(r); ok {
			// Downstream handlers see who is acting (the job queue records who
			// requested each collect).
			next.ServeHTTP(w, r.WithContext(withRequestUser(r.Context(), user)))
			return
		}
		if wantsHTML(r) { // a browser navigation: send it to the login page
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized) // an API/fetch call
	})
}

// requestUserKey carries the authenticated username in a request context; the
// unexported empty struct type makes it collision-free without a global.
type requestUserKey struct{}

func withRequestUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, requestUserKey{}, user)
}

// requestUser returns the authenticated username behind a request, or "" when
// authentication is disabled.
func requestUser(ctx context.Context) string {
	user, _ := ctx.Value(requestUserKey{}).(string)
	return user
}

// currentUser returns the authenticated username from the session cookie, if the
// cookie is valid and still names a configured user.
func (a *authManager) currentUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	var user string
	if err := a.sc.Decode(sessionCookieName, c.Value, &user); err != nil {
		return "", false
	}
	if _, ok := a.users[user]; !ok {
		return "", false
	}
	return user, true
}

func (a *authManager) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := a.currentUser(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		writeHTML(w, loginPage(r.URL.Query().Get("e") == "1"))
	case http.MethodPost:
		// Bound the body and the time it may take to arrive: this endpoint is
		// unauthenticated and reads a request body, so it must not be usable to
		// tie up a connection with a slow or oversized upload.
		if rc := http.NewResponseController(w); rc != nil {
			_ = rc.SetReadDeadline(time.Now().Add(loginReadTimeout))
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid login request", http.StatusBadRequest)
			return
		}
		user := r.PostFormValue("username")
		if a.loginLocked(user, time.Now()) {
			http.Error(w, "too many failed attempts; try again shortly", http.StatusTooManyRequests)
			return
		}
		ok, admitted := a.checkCredential(user, r.PostFormValue("password"))
		if !admitted {
			http.Error(w, "too many concurrent login attempts; try again shortly", http.StatusTooManyRequests)
			return
		}
		a.noteLoginResult(user, ok)
		if !ok {
			http.Redirect(w, r, "/login?e=1", http.StatusSeeOther)
			return
		}
		if err := a.setSession(w, user); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *authManager) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *authManager) setSession(w http.ResponseWriter, user string) error {
	enc, err := a.sc.Encode(sessionCookieName, user)
	if err != nil {
		return err
	}
	http.SetCookie(w, a.cookie(enc, sessionMaxAge))
	return nil
}

func (a *authManager) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, a.cookie("", -1))
}

func (a *authManager) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// wantsHTML reports whether the request is a browser page navigation (so an
// unauthenticated response should redirect rather than return 401).
func wantsHTML(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// loginPage renders the sign-in page, optionally with an "invalid credentials"
// banner.
func loginPage(showError bool) string {
	errHTML := ""
	if showError {
		errHTML = `<div class="err">Invalid username or password.</div>`
	}
	return strings.Replace(lowLoginHTML, "{{ERROR}}", errHTML, 1)
}

const lowLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ArtiGate low-side — sign in</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0f1115; color: #e6e6e6; }
  .login { width: 100%; max-width: 340px; background: #161a22; border: 1px solid #2a2f3a; border-radius: 10px; padding: 1.6rem 1.5rem; margin: 1rem; box-sizing: border-box; }
  h1 { font-size: 1.25rem; margin: 0 0 .2rem; }
  .sub { color: #8b93a5; font-size: .85rem; margin: 0 0 1.2rem; }
  label { display: block; font-size: .8rem; color: #c7cedb; margin: .9rem 0 .3rem; }
  input { width: 100%; box-sizing: border-box; background: #0f1115; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .6rem .7rem; font: inherit; }
  input:focus { outline: 2px solid #2b8f59; outline-offset: 0; border-color: #2b8f59; }
  button { width: 100%; margin-top: 1.4rem; background: #1f6f43; color: #eafff2; border: 1px solid #2b8f59; border-radius: 6px; padding: .65rem 1rem; cursor: pointer; font-weight: 600; font: inherit; }
  .err { background: #2e1416; border: 1px solid #7f2a30; color: #ff9ea3; border-radius: 6px; padding: .55rem .75rem; font-size: .85rem; }
</style>
</head>
<body>
  <form class="login" method="post" action="/login">
    <h1>ArtiGate</h1>
    <p class="sub">low-side exporter — sign in</p>
    {{ERROR}}
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
`
