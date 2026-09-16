package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestContainerBearerQuotedParameters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		challenge string
		want      map[string]string
	}{
		{
			name:      "quoted commas",
			challenge: `Bearer realm="https://auth.test/token?tenant=one,two",scope="repository:org/app:pull,push"`,
			want:      map[string]string{"realm": "https://auth.test/token?tenant=one,two", "scope": "repository:org/app:pull,push"},
		},
		{
			name:      "HTTP quoted pairs and whitespace",
			challenge: "bEaReR\t REALM = \"https://auth.test/token\", Service = \"registry\\\"test\\\\name\\,other\", scope=pull",
			want:      map[string]string{"realm": "https://auth.test/token", "service": "registry\"test\\name,other", "scope": "pull"},
		},
		{
			name:      "other challenges and empty list entries",
			challenge: `,Negotiate abc==,, Basic realm="a,b", Bearer realm="https://auth.test/token",scope="repository:org/app:pull,push", Basic realm="other",`,
			want:      map[string]string{"realm": "https://auth.test/token", "scope": "repository:org/app:pull,push"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realm, params, err := parseBearerChallenge(tc.challenge)
			if err != nil || realm != tc.want["realm"] || !reflect.DeepEqual(params, tc.want) {
				t.Fatalf("realm=%q params=%v err=%v; want %v", realm, params, err, tc.want)
			}
		})
	}
}

func TestContainerBearerRejectsMalformedChallenges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, challenge string }{
		{"duplicate realm", `Bearer realm="https://auth.test/token",REALM="https://other.test/token"`},
		{"duplicate scope", `Bearer realm="https://auth.test/token",scope="one",Scope="two"`},
		{"unterminated quote", `Bearer realm="https://auth.test/token`},
		{"unterminated escape", `Bearer realm="https://auth.test/token\`},
		{"trailing quoted junk", `Bearer realm="https://auth.test/token"oops`},
		{"missing value", `Bearer realm=`},
		{"missing host", `Bearer realm="https:///token"`},
		{"embedded login", `Bearer realm="https://user:secret@auth.test/token"`},
		{"fragment", `Bearer realm="https://auth.test/token#secret"`},
		{"invalid query", `Bearer realm="https://auth.test/token?secret=%zz"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseBearerChallenge(tc.challenge); err == nil {
				t.Fatal("accepted malformed Bearer challenge")
			}
		})
	}
}

func TestContainerAuthenticationMultipleChallenges(t *testing.T) {
	for _, mode := range []string{"combined", "separate", "separate bearer first"} {
		for _, discovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/discovery=%t", mode, discovery), func(t *testing.T) {
				var tokens, requests atomic.Int32
				var endpoint string
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/token" {
						tokens.Add(1)
						q := r.URL.Query()
						if q.Get("tenant") != "one,two" || q.Get("scope") != "repository:org/app:pull,push" {
							t.Errorf("token query corrupted: %v", q)
						}
						_, _ = io.WriteString(w, `{"token":"authenticated"}`)
						return
					}
					requests.Add(1)
					if r.Header.Get("Authorization") == "Bearer authenticated" {
						_, _ = io.WriteString(w, "ok")
						return
					}
					basic := `Basic realm="registry,login"`
					bearer := `Bearer realm="` + endpoint + `/token?tenant=one,two",scope="repository:org/app:pull,push"`
					switch mode {
					case "combined":
						w.Header().Add("WWW-Authenticate", "Negotiate abc==, "+basic+", "+bearer)
					case "separate":
						w.Header().Add("WWW-Authenticate", basic)
						w.Header().Add("WWW-Authenticate", bearer)
					case "separate bearer first":
						w.Header().Add("WWW-Authenticate", bearer)
						w.Header().Add("WWW-Authenticate", basic)
					}
					w.WriteHeader(http.StatusUnauthorized)
				}))
				t.Cleanup(up.Close)
				endpoint = up.URL
				ls := &LowServer{containerRegistryBases: map[string]string{"registry.test": up.URL}}
				c := ls.newContainerClient()
				c.creds = map[string]registryCredential{"registry.test": {Username: "user", Password: "password"}}
				ref := imageRef{Registry: "registry.test", Repository: "org/app"}
				for range 2 {
					var resp *http.Response
					var err error
					if discovery {
						resp, err = c.getDiscoveryResponse(t.Context(), ref, "referrers/"+containerSHA(nil), mtOCIIndex)
					} else {
						resp, err = c.get(t.Context(), ref, "manifests/latest", mtOCIManifest)
					}
					if err != nil {
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status=%d", resp.StatusCode)
					}
				}
				if tokens.Load() != 1 || requests.Load() != 3 {
					t.Fatalf("authentication not reused: token requests=%d registry requests=%d", tokens.Load(), requests.Load())
				}
			})
		}
	}
}

func TestContainerTokenErrorsHideSensitiveURLs(t *testing.T) {
	const secret = "private-token-query"
	for _, mode := range []string{"status", "invalid redirect", "invalid JSON", "transport", "invalid realm"} {
		t.Run(mode, func(t *testing.T) {
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				switch mode {
				case "status":
					w.WriteHeader(http.StatusForbidden)
				case "invalid redirect":
					w.Header().Set("Location", "http://auth.test/%zz?token="+secret)
					w.WriteHeader(http.StatusFound)
				case "invalid JSON":
					_, _ = io.WriteString(w, `{"token":123456789012345678901234567890}`)
				}
			}))
			t.Cleanup(tokenServer.Close)
			realm := tokenServer.URL + "?access_token=" + secret
			if mode == "transport" {
				tokenServer.Close()
			}
			if mode == "invalid realm" {
				realm = "https://auth.test/%zz?access_token=" + secret
			}
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			t.Cleanup(up.Close)
			ls := &LowServer{containerRegistryBases: map[string]string{"registry.test": up.URL}}
			_, err := ls.newContainerClient().get(t.Context(), imageRef{Registry: "registry.test", Repository: "org/app"}, "manifests/latest", mtOCIManifest)
			if err == nil {
				t.Fatal("expected token failure")
			}
			for _, sensitive := range []string{secret, tokenServer.URL, "auth.test", "123456789012345678901234567890"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("token error exposed sensitive value: %v", err)
				}
			}
		})
	}
}

func TestContainerBearerFailureDoesNotDowngrade(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(up.Close)
	c := (&LowServer{}).newContainerClient()
	c.creds = map[string]registryCredential{"registry.test": {Username: "user", Password: "password"}}
	challenge := `Basic realm="registry", Bearer realm="` + up.URL + `"`
	if authorization, err := c.authorizeChallenge(t.Context(), challenge, imageRef{Registry: "registry.test", Repository: "org/app"}); err == nil || authorization != "" {
		t.Fatalf("downgraded failed Bearer authentication: %q, %v", authorization, err)
	}
}

func TestContainerTokenCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (&containerClient{}).fetchToken(ctx, `Bearer realm="https://auth.test/token?secret=private"`, "org/app", nil)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "private") {
		t.Fatalf("cancellation cause lost or URL leaked: %v", err)
	}
}
