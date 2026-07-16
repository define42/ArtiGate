//go:build e2e

package e2e

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

// TestLowSideAuth drives the low-side session-login control plane end-to-end
// (unit-tested until now): with ARTIGATE_LOW_AUTH configured, an argon2id
// credential minted by the real `hashpw` subcommand must gate every admin
// endpoint behind a form login and a session cookie, while the operational
// health/metrics endpoints stay open. No upstream network is involved.
func TestLowSideAuth(t *testing.T) {
	const user, pass = "operator", "correct-horse-battery-staple"
	hash := hashpw(t, user, pass)

	p := startTestPair(t, pairConfig{
		name:    "auth",
		lowOnly: true,
		lowEnv:  []string{"ARTIGATE_LOW_AUTH=" + hash},
	})

	// A browser navigation without a session is redirected to the login page;
	// an API/fetch call (no text/html Accept) gets a bare 401.
	if code := getStatusNoRedirect(t, p.LowURL+"/admin/bundles", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API call = %d, want 401", code)
	}
	if code := getStatusNoRedirect(t, p.LowURL+"/", "text/html", nil); code != http.StatusSeeOther {
		t.Fatalf("unauthenticated browser navigation = %d, want a 303 redirect to /login", code)
	}

	// Operational endpoints must answer without any login.
	if code, _ := httpGet(t, p.LowURL+"/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz behind auth = %d, want 200", code)
	}
	if code, _ := httpGet(t, p.LowURL+"/metrics"); code != http.StatusOK {
		t.Fatalf("/metrics behind auth = %d, want 200", code)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: noRedirect}

	// Wrong password: bounced back to the login page with the error flag, and
	// no session cookie is issued.
	if code, loc := postLogin(t, client, p.LowURL, user, "wrong-password"); code != http.StatusSeeOther || !strings.Contains(loc, "/login?e=1") {
		t.Fatalf("bad-credential login = %d %q, want 303 to /login?e=1", code, loc)
	}
	if sessionCookie(jar, p.LowURL) != "" {
		t.Fatal("a failed login issued a session cookie")
	}

	// Correct password: a session cookie is set and we are redirected to the
	// dashboard.
	if code, loc := postLogin(t, client, p.LowURL, user, pass); code != http.StatusSeeOther || loc != "/" {
		t.Fatalf("good-credential login = %d %q, want 303 to /", code, loc)
	}
	if sessionCookie(jar, p.LowURL) == "" {
		t.Fatal("a successful login issued no session cookie")
	}

	// The session now opens the admin surface.
	if code := getStatusNoRedirect(t, p.LowURL+"/admin/bundles", "", client); code != http.StatusOK {
		t.Fatalf("authenticated /admin/bundles = %d, want 200", code)
	}

	// Logging out clears the session; the admin surface closes again.
	req, _ := http.NewRequest(http.MethodPost, p.LowURL+"/logout", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	_ = resp.Body.Close()
	if code := getStatusNoRedirect(t, p.LowURL+"/admin/bundles", "", client); code != http.StatusUnauthorized {
		t.Fatalf("/admin/bundles after logout = %d, want 401", code)
	}
}

// hashpw runs the real `artigate hashpw` subcommand to mint an argon2id
// credential, exactly as an operator would when configuring ARTIGATE_LOW_AUTH.
func hashpw(t *testing.T, user, password string) string {
	t.Helper()
	out, err := exec.Command(stack.Bin, "hashpw", "--user", user, "--password", password).Output()
	if err != nil {
		t.Fatalf("hashpw: %v", err)
	}
	line := strings.TrimSpace(string(out))
	if !strings.HasPrefix(line, user+":$argon2id$") {
		t.Fatalf("hashpw produced an unexpected credential: %q", line)
	}
	return line
}

// noRedirect makes an http.Client stop at a redirect so the test observes the
// 3xx status and Location itself.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// getStatusNoRedirect issues a GET and returns the status without following
// redirects. accept sets the Accept header (so the auth middleware can tell a
// browser navigation from an API call); client is optional (nil uses a fresh
// cookieless client).
func getStatusNoRedirect(t *testing.T, rawURL, accept string, client *http.Client) int {
	t.Helper()
	if client == nil {
		client = &http.Client{CheckRedirect: noRedirect}
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// postLogin submits the login form and returns the status and Location header
// without following the redirect.
func postLogin(t *testing.T, client *http.Client, lowURL, user, pass string) (int, string) {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}}
	resp, err := client.PostForm(lowURL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// sessionCookie returns the value of the artigate_session cookie the jar holds
// for the server, or "" when none is set.
func sessionCookie(jar *cookiejar.Jar, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == "artigate_session" {
			return c.Value
		}
	}
	return ""
}
