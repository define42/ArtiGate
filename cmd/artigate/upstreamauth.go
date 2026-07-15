package main

// Shared upstream-credential plumbing for streams that authenticate with HTTP
// Basic against plain URL hosts (git, apt, rpm, apk). A per-pull login rides
// the collect request's optional `auth` field and is never stored; standing
// credentials live in ARTIGATE_UPSTREAM_AUTH and are re-read on every collect.
// Containers follow the same model with their own registry-keyed variable
// (ARTIGATE_CONTAINER_AUTH), sharing parseAuthEnv.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// upstreamAuthEnv holds standing per-host credentials for the git, apt, rpm,
// and apk streams as comma-separated host=user:password entries (the host may
// carry a :port and must match the mirror URL's host exactly). It is read at
// collect time so rotated credentials apply without a restart, and it is the
// only credential source scheduled watches can use — watch specs must never
// carry logins (they are stored and echoed in plaintext).
const upstreamAuthEnv = "ARTIGATE_UPSTREAM_AUTH"

// HostCollectAuth is a collect request's optional login for one upstream
// host. It is used for that collect only and never stored; standing
// credentials belong in ARTIGATE_UPSTREAM_AUTH on the low side.
type HostCollectAuth struct {
	// Host names the mirror host the login is for, exactly as it appears in
	// the upstream URL (including any port). It may be left empty when every
	// mirror in the collect lives on one host.
	Host     string `json:"host,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// upstreamHTTPError is a non-2xx reply from an upstream fetch. It renders
// exactly like the plain errors it replaces ("GET <url>: HTTP 404") so error
// text elsewhere is unchanged; keeping the pieces lets the auth-aware streams
// decorate 401/403 with credential guidance.
type upstreamHTTPError struct {
	Method string
	URL    string
	Status int
}

func (e *upstreamHTTPError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d", e.Method, e.URL, e.Status)
}

// parseAuthEnv parses one credential environment variable: comma-separated
// host=user:password entries (the password may contain ':' and '='; a
// password containing ',' cannot be expressed). Errors identify entries by
// position, never by content — the value is a secret and must not surface in
// logs or collect errors.
func parseAuthEnv(envName, spec string, normalizeHost func(string) string) (map[string]registryCredential, error) {
	out := map[string]registryCredential{}
	for i, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, login, ok := strings.Cut(entry, "=")
		if !ok || host == "" || login == "" {
			return nil, fmt.Errorf("invalid %s entry #%d (need host=user:password)", envName, i+1)
		}
		user, pass, ok := strings.Cut(login, ":")
		if !ok || user == "" || pass == "" {
			return nil, fmt.Errorf("invalid %s entry #%d for host %q (need host=user:password)", envName, i+1, strings.TrimSpace(host))
		}
		out[normalizeHost(strings.TrimSpace(host))] = registryCredential{Username: user, Password: pass}
	}
	return out, nil
}

// normalizeUpstreamHost lowercases a mirror host. Unlike container registry
// names there is no aliasing, and a :port stays part of the key.
func normalizeUpstreamHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func parseUpstreamAuthEnv(spec string) (map[string]registryCredential, error) {
	return parseAuthEnv(upstreamAuthEnv, spec, normalizeUpstreamHost)
}

// upstreamCollectCredentials resolves the per-host logins for one collect:
// any standing ARTIGATE_UPSTREAM_AUTH entries, overlaid with the request's
// own auth (the request wins for its host). hosts are the URL hosts of the
// collect's mirrors; the env var is re-read on every collect so rotated
// credentials apply without a restart.
func upstreamCollectCredentials(hosts []string, auth *HostCollectAuth) (map[string]registryCredential, error) {
	creds, err := parseUpstreamAuthEnv(os.Getenv(upstreamAuthEnv))
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return creds, nil
	}
	if auth.Username == "" || auth.Password == "" {
		return nil, errors.New("auth needs both username and password")
	}
	host, err := requestAuthHost(hosts, auth.Host)
	if err != nil {
		return nil, err
	}
	creds[host] = registryCredential{Username: auth.Username, Password: auth.Password}
	return creds, nil
}

// requestAuthHost decides which host a collect's auth applies to: the named
// one, which must match a mirror in the collect (a typo would otherwise
// silently leave the collect anonymous), or the single host every mirror
// lives on when left empty — a login is never presented to a host the user
// didn't mean it for.
func requestAuthHost(hosts []string, host string) (string, error) {
	set := map[string]bool{}
	for _, h := range hosts {
		set[normalizeUpstreamHost(h)] = true
	}
	if host != "" {
		norm := normalizeUpstreamHost(host)
		if !set[norm] {
			return "", fmt.Errorf("auth host %q matches none of the collect's mirrors", host)
		}
		return norm, nil
	}
	if len(set) > 1 {
		return "", errors.New("the collect spans multiple mirror hosts — set auth.host to name the one the login is for")
	}
	for h := range set {
		return h, nil
	}
	return "", errors.New("no mirrors resolved")
}

// upstreamURLHost extracts the normalized host (including any port) from an
// upstream URL, for credential lookups.
func upstreamURLHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return normalizeUpstreamHost(u.Host)
}

// credentialForHost returns the login for a URL host, or nil for anonymous.
func credentialForHost(creds map[string]registryCredential, host string) *registryCredential {
	if cred, ok := creds[normalizeUpstreamHost(host)]; ok {
		return &cred
	}
	return nil
}

// checkNoURLUserinfo rejects upstream URLs that embed a user:password. The
// URL is copied into the signed bundle manifest, progress lines, and error
// text, so a login there would leak — including across the diode to the high
// side. The error names only the URL's host, never the URL itself (it
// contains the secret).
func checkNoURLUserinfo(u *url.URL, what string) error {
	if u.User != nil {
		return fmt.Errorf("%s for host %s must not embed credentials in the URL; use the collect's auth field or %s", what, u.Host, upstreamAuthEnv)
	}
	return nil
}

// setBasicAuth attaches a login to an upstream request. net/http drops
// Authorization on cross-host redirects, so a CDN redirect (packages, packs)
// is followed without leaking the login.
func setBasicAuth(req *http.Request, cred *registryCredential) {
	if cred != nil {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
}

// decorateUpstreamAuthError appends credential guidance to a 401/403 from an
// auth-aware stream: with a login configured for the URL's host the upstream
// rejected it; anonymously the mirror may need one. Every other error passes
// through unchanged.
func decorateUpstreamAuthError(err error, creds map[string]registryCredential) error {
	var httpErr *upstreamHTTPError
	if !errors.As(err, &httpErr) || (httpErr.Status != http.StatusUnauthorized && httpErr.Status != http.StatusForbidden) {
		return err
	}
	host := upstreamURLHost(httpErr.URL)
	if credentialForHost(creds, host) != nil {
		return fmt.Errorf("%w — the credentials for %s were not accepted", err, host)
	}
	return fmt.Errorf("%w — the mirror may be private; supply a login on the collect (auth field) or set %s", err, upstreamAuthEnv)
}
