package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type containerTestTransport func(*http.Request) (*http.Response, error)

func (f containerTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// These tests are deliberately sequential: replacing DefaultTransport verifies
// that the registry client retains the process's configured transport.
func useContainerTestTransport(t *testing.T, transport containerTestTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func containerTestResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: make(http.Header), Request: req,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
	}
}

func TestContainerRedirectCredentials(t *testing.T) {
	for _, tc := range []struct {
		name           string
		initial        string
		targets        []string
		wantAuth       []bool
		wantErr        bool
		wantSameOrigin bool
	}{
		{
			name: "same origin and default port", initial: "https://registry.test/start",
			targets: []string{"https://REGISTRY.test:443/blob"}, wantAuth: []bool{true, true}, wantSameOrigin: true,
		},
		{
			name: "different port", initial: "https://registry.test/start",
			targets: []string{"https://registry.test:8443/blob"}, wantAuth: []bool{true, false},
		},
		{
			name: "subdomain", initial: "https://registry.test/start",
			targets: []string{"https://cdn.registry.test/blob"}, wantAuth: []bool{true, false},
		},
		{
			name: "signed CDN", initial: "https://registry.test/start",
			targets: []string{"https://cdn.test/blob?signature=private-signature"}, wantAuth: []bool{true, false},
		},
		{
			name: "upgrade changes origin", initial: "http://registry.test/start",
			targets: []string{"https://registry.test/blob"}, wantAuth: []bool{true, false},
		},
		{
			name: "return to origin stays anonymous", initial: "https://registry.test/start",
			targets:  []string{"https://cdn.registry.test/blob?signature=private-signature", "https://registry.test/finish"},
			wantAuth: []bool{true, false, false},
		},
		{
			name: "redirect URL login stripped", initial: "https://registry.test/start",
			targets: []string{"https://injected:password@cdn.test/blob"}, wantAuth: []bool{true, false},
		},
		{
			name: "HTTPS downgrade rejected", initial: "https://registry.test/start",
			targets: []string{"http://registry.test/blob?signature=private-signature"}, wantAuth: []bool{true}, wantErr: true,
		},
		{
			name: "later HTTPS downgrade rejected", initial: "http://registry.test/start",
			targets:  []string{"https://registry.test/blob", "http://registry.test/finish"},
			wantAuth: []bool{true, false}, wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
				position := requests
				requests++
				if position >= len(tc.wantAuth) {
					t.Fatalf("unexpected redirected request %d", position)
				}
				wantAuth := ""
				if tc.wantAuth[position] {
					wantAuth = "Bearer private-registry-token"
				}
				if got := req.Header.Get("Authorization"); got != wantAuth {
					t.Errorf("request %d authorization = %q, want %q", position, got, wantAuth)
				}
				if position > 0 {
					if req.Header.Get("Referer") != "" || req.URL.User != nil {
						t.Error("redirect retained a Referer or URL credentials")
					}
					if strings.Contains(tc.targets[position-1], "signature=") && req.URL.Query().Get("signature") != "private-signature" {
						t.Error("signed CDN query changed")
					}
				}
				if position < len(tc.targets) {
					resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
					resp.Header.Set("Location", tc.targets[position])
					return resp, nil
				}
				return containerTestResponse(req, http.StatusOK, "blob content"), nil
			})
			resp, sameOrigin, err := (&containerClient{}).doContainerGet(
				t.Context(), tc.initial, "", "Bearer private-registry-token",
			)
			if (err != nil) != tc.wantErr {
				t.Fatalf("redirect result: %v", err)
			}
			if err == nil {
				defer resp.Body.Close()
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil || string(body) != "blob content" || sameOrigin != tc.wantSameOrigin {
					t.Fatalf("response body=%q sameOrigin=%t error=%v", body, sameOrigin, readErr)
				}
			}
			if requests != len(tc.wantAuth) {
				t.Fatalf("made %d requests, want %d", requests, len(tc.wantAuth))
			}
		})
	}
}

func TestContainerRejectsRedirectedLoginChallenge(t *testing.T) {
	for _, target := range []string{"off origin", "return to origin"} {
		for _, cached := range []bool{false, true} {
			name := target + "/anonymous"
			if cached {
				name = target + "/cached"
			}
			t.Run(name, func(t *testing.T) {
				requests := 0
				useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
					requests++
					if req.URL.Host == "token.attacker.test" {
						t.Fatal("redirected challenge received original registry login")
					}
					if req.URL.Path == "/v2/org/app/blobs/example" {
						resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
						resp.Header.Set("Location", "https://cdn.mirror.test/challenge")
						return resp, nil
					}
					if req.Header.Get("Authorization") != "" {
						t.Error("credentials reintroduced after origin boundary")
					}
					if req.URL.Host == "cdn.mirror.test" && target == "return to origin" {
						resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
						resp.Header.Set("Location", "https://mirror.test/challenge")
						return resp, nil
					}
					resp := containerTestResponse(req, http.StatusUnauthorized, "")
					resp.Header.Set("WWW-Authenticate", `Bearer realm="https://token.attacker.test/token"`)
					return resp, nil
				})
				c := (&LowServer{containerRegistryBases: map[string]string{"registry.test": "https://mirror.test"}}).newContainerClient()
				c.creds = map[string]registryCredential{"registry.test": {Username: "private-user", Password: "private-password"}}
				if cached {
					c.auths["registry.test/org/app"] = "Bearer private-token"
				}
				ref := imageRef{Registry: "registry.test", Repository: "org/app"}
				_, err := c.get(t.Context(), ref, "blobs/example", "")
				if err == nil || !strings.Contains(err.Error(), "origin-changing redirect") {
					t.Fatalf("unexpected challenge outcome: %v", err)
				}
				wantRequests := 2
				if target == "return to origin" {
					wantRequests++
				}
				if requests != wantRequests {
					t.Fatalf("made %d requests, want %d", requests, wantRequests)
				}
			})
		}
	}
}

func TestContainerSameOriginRedirectedLoginChallenge(t *testing.T) {
	tokenRequests := 0
	useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "auth.test" {
			tokenRequests++
			user, password, ok := req.BasicAuth()
			if !ok || user != "private-user" || password != "private-password" {
				t.Error("token realm did not receive expected login")
			}
			return containerTestResponse(req, http.StatusOK, `{"token":"pull-token"}`), nil
		}
		if req.URL.Path != "/challenge" {
			resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
			resp.Header.Set("Location", "https://MIRROR.test:443/challenge")
			return resp, nil
		}
		if req.Header.Get("Authorization") == "Bearer pull-token" {
			return containerTestResponse(req, http.StatusOK, "manifest"), nil
		}
		resp := containerTestResponse(req, http.StatusUnauthorized, "")
		resp.Header.Set("WWW-Authenticate", `Bearer realm="https://auth.test/token"`)
		return resp, nil
	})
	c := (&LowServer{containerRegistryBases: map[string]string{"registry.test": "https://mirror.test"}}).newContainerClient()
	c.creds = map[string]registryCredential{"registry.test": {Username: "private-user", Password: "private-password"}}
	resp, err := c.get(t.Context(), imageRef{Registry: "registry.test", Repository: "org/app"}, "manifests/latest", "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || tokenRequests != 1 {
		t.Fatalf("status=%d token requests=%d", resp.StatusCode, tokenRequests)
	}
}

func TestContainerAuthenticatedRedirectRejectsSecondChallenge(t *testing.T) {
	tokenRequests := 0
	useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "auth.test":
			tokenRequests++
			return containerTestResponse(req, http.StatusOK, `{"token":"pull-token"}`), nil
		case "mirror.test":
			if req.Header.Get("Authorization") == "" {
				resp := containerTestResponse(req, http.StatusUnauthorized, "")
				resp.Header.Set("WWW-Authenticate", `Bearer realm="https://auth.test/token"`)
				return resp, nil
			}
			resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
			resp.Header.Set("Location", "https://cdn.mirror.test/blob")
			return resp, nil
		case "cdn.mirror.test":
			if req.Header.Get("Authorization") != "" {
				t.Error("authenticated retry leaked registry token to CDN")
			}
			resp := containerTestResponse(req, http.StatusUnauthorized, "")
			resp.Header.Set("WWW-Authenticate", `Bearer realm="https://attacker.test/token"`)
			return resp, nil
		default:
			t.Fatal("answered an untrusted CDN challenge")
			return nil, errors.New("unexpected token exchange")
		}
	})
	c := (&LowServer{containerRegistryBases: map[string]string{"registry.test": "https://mirror.test"}}).newContainerClient()
	c.creds = map[string]registryCredential{"registry.test": {Username: "user", Password: "password"}}
	_, err := c.get(t.Context(), imageRef{Registry: "registry.test", Repository: "org/app"}, "blobs/example", "")
	if err == nil || !strings.Contains(err.Error(), "origin-changing redirect") || tokenRequests != 1 {
		t.Fatalf("authenticated redirect: error=%v token requests=%d", err, tokenRequests)
	}
}

func TestContainerTokenRedirectCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		targets  []string
		wantAuth []bool
		wantErr  bool
	}{
		{name: "same origin", targets: []string{"https://AUTH.test:443/finish"}, wantAuth: []bool{true, true}},
		{name: "different port", targets: []string{"https://auth.test:8443/finish"}, wantAuth: []bool{true, false}},
		{name: "subdomain", targets: []string{"https://child.auth.test/finish"}, wantAuth: []bool{true, false}},
		{
			name: "return to origin", targets: []string{"https://child.auth.test/redirect", "https://auth.test/finish"},
			wantAuth: []bool{true, false, false},
		},
		{name: "HTTPS downgrade", targets: []string{"http://auth.test/finish"}, wantAuth: []bool{true}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
				position := requests
				requests++
				if position >= len(tc.wantAuth) {
					t.Fatal("token endpoint followed forbidden redirect")
				}
				user, password, ok := req.BasicAuth()
				if ok != tc.wantAuth[position] || (ok && (user != "user" || password != "password")) {
					t.Errorf("request %d has unexpected token endpoint credentials", position)
				}
				if position < len(tc.targets) {
					resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
					resp.Header.Set("Location", tc.targets[position])
					return resp, nil
				}
				return containerTestResponse(req, http.StatusOK, `{"token":"pull-token"}`), nil
			})
			token, err := (&containerClient{}).fetchToken(
				t.Context(), `Bearer realm="https://auth.test/token"`, "org/app",
				&registryCredential{Username: "user", Password: "password"},
			)
			if (err != nil) != tc.wantErr || (!tc.wantErr && token != "pull-token") {
				t.Fatalf("token=%q error=%v", token, err)
			}
			if requests != len(tc.wantAuth) {
				t.Fatalf("made %d requests, want %d", requests, len(tc.wantAuth))
			}
		})
	}
}

func TestContainerSignedCDNDownload(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "signature=opaque%2Bsignature" {
			t.Error("CDN request retained registry credentials or changed signed query")
		}
		_, _ = io.WriteString(w, "exact blob bytes")
	}))
	t.Cleanup(cdn.Close)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("registry did not receive its cached token")
		}
		http.Redirect(w, r, cdn.URL+"/blob?signature=opaque%2Bsignature", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(registry.Close)
	c := (&LowServer{containerRegistryBases: map[string]string{"registry.test": registry.URL}}).newContainerClient()
	c.auths["registry.test/org/app"] = "Bearer private-token"
	resp, err := c.get(t.Context(), imageRef{Registry: "registry.test", Repository: "org/app"}, "blobs/example", "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "exact blob bytes" {
		t.Fatalf("signed CDN download=%q error=%v", body, err)
	}
}

func TestContainerRedirectErrorsHideSensitiveURLs(t *testing.T) {
	const secret = "private-signed-query"
	for _, mode := range []string{"transport", "malformed redirect", "invalid request", "cancellation", "redirect loop"} {
		t.Run(mode, func(t *testing.T) {
			cause := errors.New("transport failed for " + secret)
			useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
				if mode == "transport" {
					return nil, cause
				}
				if mode == "cancellation" {
					return nil, context.Canceled
				}
				resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
				location := "https://registry.test/path?signature=" + secret
				if mode == "malformed redirect" {
					location = "https://cdn.test/%zz?signature=" + secret
				}
				resp.Header.Set("Location", location)
				return resp, nil
			})
			endpoint := "https://registry.test/path?signature=" + secret
			if mode == "invalid request" {
				endpoint = "https://registry.test/%zz?signature=" + secret
			}
			_, _, err := (&containerClient{}).doContainerGet(t.Context(), endpoint, "", "Bearer private-token")
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "registry.test") {
				t.Fatalf("request error missing or exposed sensitive URL: %v", err)
			}
			if mode == "transport" && !errors.Is(err, cause) {
				t.Error("transport error cause lost")
			}
			if mode == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Error("cancellation cause lost")
			}
		})
	}
}
