package main

// Low-side session login. When ARTIGATE_LOW_AUTH is configured, the low-side
// dashboard is protected by a cookie session instead of per-request Basic auth:
// the operator signs in through a form, and an encrypted+signed session cookie
// (gorilla/securecookie) carries the identity afterwards. A "Log out" button
// clears it. Credentials are still the argon2id hashes parsed from
// ARTIGATE_LOW_AUTH (see auth.go). The high side is never authenticated.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

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
	// process; excess attempts queue on cheap goroutines instead.
	maxConcurrentLogins = 4
)

// authManager holds the credential set and the session-cookie codec.
type authManager struct {
	users     map[string]string // username -> argon2id hash
	sc        *securecookie.SecureCookie
	secure    bool          // set the cookie's Secure flag (true when serving over TLS)
	verifySem chan struct{} // bounds concurrent (memory-heavy) argon2 verifications
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
	}, nil
}

// checkCredential verifies user/pass, allowing at most maxConcurrentLogins
// argon2 verifications to run concurrently so the unauthenticated login endpoint
// cannot be turned into a memory-exhaustion DoS.
func (a *authManager) checkCredential(user, pass string) bool {
	a.verifySem <- struct{}{}
	defer func() { <-a.verifySem }()
	return credentialOK(a.users, user, pass)
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

// middleware enforces authentication on every request except the health check
// and the login/logout endpoints, which it handles itself.
func (a *authManager) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			next.ServeHTTP(w, r)
			return
		case "/login":
			a.handleLogin(w, r)
			return
		case "/logout":
			a.handleLogout(w, r)
			return
		}
		if _, ok := a.currentUser(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if wantsHTML(r) { // a browser navigation: send it to the login page
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized) // an API/fetch call
	})
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
		_ = r.ParseForm()
		if !a.checkCredential(r.PostFormValue("username"), r.PostFormValue("password")) {
			http.Redirect(w, r, "/login?e=1", http.StatusSeeOther)
			return
		}
		if err := a.setSession(w, r.PostFormValue("username")); err != nil {
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
