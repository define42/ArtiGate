package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// basicAuthGate wraps a fake upstream so every request demands the exact
// Authorization value — a private mirror for auth tests.
func basicAuthGate(next http.Handler, authorization string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authorization {
			w.Header().Set("Www-Authenticate", `Basic realm="mirror"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// testBasicAuth renders the Authorization value for a login.
func testBasicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestParseUpstreamAuthEnv(t *testing.T) {
	m, err := parseUpstreamAuthEnv("Apt.Example.com=alice:s3cr3t, mirror.example.com:8443=bob:tok:en= ,")
	if err != nil {
		t.Fatal(err)
	}
	// Hosts are lowercased with the port kept; no docker-style alias folding.
	if m["apt.example.com"] != (registryCredential{Username: "alice", Password: "s3cr3t"}) {
		t.Fatalf("apt.example.com login = %+v", m["apt.example.com"])
	}
	if m["mirror.example.com:8443"] != (registryCredential{Username: "bob", Password: "tok:en="}) {
		t.Fatalf("mirror.example.com:8443 login = %+v", m["mirror.example.com:8443"])
	}
	if len(m) != 2 {
		t.Fatalf("logins = %v", m)
	}
	if m, err := parseUpstreamAuthEnv(""); err != nil || len(m) != 0 {
		t.Fatalf("empty value = %v, %v", m, err)
	}
	for _, tt := range []struct{ entry, secret string }{
		{"apt.example.com", ""},
		{"apt.example.com=aliceonly", "aliceonly"},
		{"apt.example.com=:hunter2", "hunter2"},
		{"apt.example.com=alice:", "alice"},
	} {
		_, err := parseUpstreamAuthEnv(tt.entry)
		if err == nil {
			t.Errorf("entry %q should be rejected", tt.entry)
			continue
		}
		if !strings.Contains(err.Error(), upstreamAuthEnv) {
			t.Errorf("error should name the env var: %v", err)
		}
		if tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
			t.Errorf("error must not echo the login: %v", err)
		}
	}
}

func TestUpstreamCollectCredentials(t *testing.T) {
	t.Setenv(upstreamAuthEnv, "apt.example.com=envuser:envpass")

	// Without request auth the standing env credentials apply (the path
	// scheduled watches take).
	creds, err := upstreamCollectCredentials([]string{"apt.example.com"}, nil)
	if err != nil || creds["apt.example.com"].Username != "envuser" {
		t.Fatalf("env creds = %v, %v", creds, err)
	}

	// A request login wins over the env entry; an unnamed host resolves to
	// the collect's single mirror host.
	creds, err = upstreamCollectCredentials([]string{"apt.example.com"}, &HostCollectAuth{Username: "u", Password: "p"})
	if err != nil || creds["apt.example.com"] != (registryCredential{Username: "u", Password: "p"}) {
		t.Fatalf("request creds = %v, %v", creds, err)
	}

	// Naming the host scopes the login inside a multi-host collect (matched
	// case-insensitively).
	creds, err = upstreamCollectCredentials([]string{"a.example.com", "b.example.com"},
		&HostCollectAuth{Host: "B.example.com", Username: "u", Password: "p"})
	if err != nil || creds["b.example.com"].Username != "u" {
		t.Fatalf("scoped creds = %v, %v", creds, err)
	}

	if _, err := upstreamCollectCredentials([]string{"a.example.com", "b.example.com"},
		&HostCollectAuth{Username: "u", Password: "p"}); err == nil {
		t.Error("multi-host collect with an unscoped login should fail")
	}
	if _, err := upstreamCollectCredentials([]string{"a.example.com"},
		&HostCollectAuth{Host: "c.example.com", Username: "u", Password: "p"}); err == nil {
		t.Error("a login for a host outside the collect should fail")
	}
	if _, err := upstreamCollectCredentials([]string{"a.example.com"},
		&HostCollectAuth{Username: "u"}); err == nil {
		t.Error("a login without a password should fail")
	}

	// A malformed env value fails the collect, naming the variable.
	t.Setenv(upstreamAuthEnv, "garbage")
	if _, err := upstreamCollectCredentials([]string{"a.example.com"}, nil); err == nil || !strings.Contains(err.Error(), upstreamAuthEnv) {
		t.Errorf("malformed env value should fail naming %s, got %v", upstreamAuthEnv, err)
	}
}

func TestDecorateUpstreamAuthError(t *testing.T) {
	creds := map[string]registryCredential{"apt.example.com": {Username: "u", Password: "hunter2"}}
	base := &upstreamHTTPError{Method: http.MethodGet, URL: "https://apt.example.com/dists/x/InRelease", Status: http.StatusUnauthorized}

	// A 401 with a configured login reports it rejected — never echoing it —
	// and keeps the plain prefix intact.
	err := decorateUpstreamAuthError(fmt.Errorf("suite x: %w", base), creds)
	if !strings.Contains(err.Error(), "credentials for apt.example.com were not accepted") ||
		!strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("decorated error = %v", err)
	}

	// A 403 without a login points at both supply paths.
	anon := &upstreamHTTPError{Method: http.MethodGet, URL: "https://other.example.com/x", Status: http.StatusForbidden}
	err = decorateUpstreamAuthError(anon, creds)
	if !strings.Contains(err.Error(), upstreamAuthEnv) || !strings.Contains(err.Error(), "auth field") {
		t.Fatalf("anonymous 403 guidance = %v", err)
	}

	// Other statuses and non-HTTP errors pass through unchanged, and the
	// typed error renders byte-identically to the plain form it replaced.
	notFound := &upstreamHTTPError{Method: http.MethodGet, URL: "https://x/y", Status: http.StatusNotFound}
	if got := decorateUpstreamAuthError(notFound, creds); !errors.Is(got, error(notFound)) || got.Error() != notFound.Error() {
		t.Fatalf("404 should pass through, got %v", got)
	}
	if notFound.Error() != "GET https://x/y: HTTP 404" {
		t.Fatalf("upstreamHTTPError rendering = %q", notFound.Error())
	}
	plain := errors.New("boom")
	if got := decorateUpstreamAuthError(plain, creds); !errors.Is(got, plain) || got.Error() != plain.Error() {
		t.Fatalf("plain error should pass through, got %v", got)
	}
}
