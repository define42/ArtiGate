package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUpstreamRedirectCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		initial  string
		targets  []string
		wantAuth []bool
		wantErr  string
	}{
		{
			name: "relative redirect", initial: "https://upstream.test/start",
			targets: []string{"/finish"}, wantAuth: []bool{true, true},
		},
		{
			name: "HTTPS default port and hostname case", initial: "https://upstream.test/start",
			targets: []string{"https://UPSTREAM.test:443/finish"}, wantAuth: []bool{true, true},
		},
		{
			name: "HTTP default port", initial: "http://upstream.test:80/start",
			targets: []string{"http://upstream.test/finish"}, wantAuth: []bool{true, true},
		},
		{
			name: "numeric port equivalence", initial: "https://upstream.test:0443/start",
			targets: []string{"https://upstream.test:443/finish"}, wantAuth: []bool{true, true},
		},
		{
			name: "IPv6 same origin", initial: "https://[::1]/start",
			targets: []string{"https://[::1]:443/finish"}, wantAuth: []bool{true, true},
		},
		{
			name: "different port", initial: "https://upstream.test/start",
			targets: []string{"https://upstream.test:8443/finish"}, wantAuth: []bool{true, false},
		},
		{
			name: "subdomain then return", initial: "https://upstream.test/start",
			targets: []string{"https://cdn.upstream.test/file", "https://upstream.test/finish"}, wantAuth: []bool{true, false, false},
		},
		{
			name: "different port then return", initial: "https://upstream.test/start",
			targets: []string{"https://upstream.test:8443/file", "https://upstream.test/finish"}, wantAuth: []bool{true, false, false},
		},
		{
			name: "unrelated host", initial: "https://upstream.test/start",
			targets: []string{"https://cdn.test/finish"}, wantAuth: []bool{true, false},
		},
		{
			name: "scheme change on same port", initial: "http://upstream.test:443/start",
			targets: []string{"https://upstream.test:443/finish"}, wantAuth: []bool{true, false},
		},
		{
			name: "URL userinfo after leaving origin", initial: "https://upstream.test/start",
			targets:  []string{"https://injected:password@cdn.upstream.test/file", "https://injected:password@upstream.test/finish"},
			wantAuth: []bool{true, false, false},
		},
		{
			name: "downgrade", initial: "https://upstream.test/start",
			targets: []string{"http://upstream.test/finish"}, wantAuth: []bool{true}, wantErr: "downgrade HTTPS",
		},
		{
			name: "downgrade after upgrade", initial: "http://upstream.test/start",
			targets: []string{"https://upstream.test/file", "http://upstream.test/finish"}, wantAuth: []bool{true, false}, wantErr: "downgrade HTTPS",
		},
		{
			name: "unsupported scheme", initial: "http://upstream.test/start",
			targets: []string{"ftp://upstream.test/finish"}, wantAuth: []bool{true}, wantErr: "unsupported scheme",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, auth := range []struct {
				name  string
				value string
			}{
				{name: "basic", value: "Basic dXNlcjpwYXNzd29yZA=="},
				{name: "bearer", value: "Bearer private-token"},
				{name: "anonymous"},
			} {
				t.Run(auth.name, func(t *testing.T) {
					credentials := map[string]string{
						"Authorization":       auth.value,
						"Proxy-Authorization": "Basic cHJveHk6cGFzc3dvcmQ=",
						"Cookie":              "session=private-cookie",
						"Cookie2":             "session=legacy-cookie",
					}
					if auth.value == "" {
						clear(credentials)
					}
					requests := 0
					useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
						position := requests
						requests++
						if position >= len(tc.wantAuth) {
							t.Fatal("followed forbidden redirect")
						}
						for header, value := range credentials {
							want := ""
							if tc.wantAuth[position] {
								want = value
							}
							if got := req.Header.Get(header); got != want {
								t.Errorf("request %d %s = %q, want %q", position, header, got, want)
							}
						}
						if position > 0 && req.Header.Get("Referer") != "" {
							t.Error("redirect leaked Referer")
						}
						if !tc.wantAuth[position] && req.URL.User != nil {
							t.Error("redirect retained URL credentials")
						}
						if req.Header.Get("Accept") != "application/octet-stream" {
							t.Error("redirect dropped non-sensitive header")
						}
						if position < len(tc.targets) {
							resp := containerTestResponse(req, http.StatusFound, "")
							resp.Header.Set("Location", tc.targets[position])
							return resp, nil
						}
						return containerTestResponse(req, http.StatusOK, "payload"), nil
					})
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.initial, nil)
					if err != nil {
						t.Fatal(err)
					}
					for header, value := range credentials {
						req.Header.Set(header, value)
					}
					req.Header.Set("Accept", "application/octet-stream")
					resp, sameOrigin, err := doUpstreamRequest(req)
					if resp != nil {
						defer resp.Body.Close()
					}
					if requests != len(tc.wantAuth) {
						t.Errorf("made %d requests, want %d", requests, len(tc.wantAuth))
					}
					if tc.wantErr != "" {
						if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
							t.Fatalf("error = %v, want %q", err, tc.wantErr)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil || string(body) != "payload" {
						t.Fatalf("body = %q, error = %v", body, readErr)
					}
					if sameOrigin != tc.wantAuth[len(tc.wantAuth)-1] {
						t.Errorf("same origin = %t", sameOrigin)
					}
				})
			}
		})
	}
}

func TestUpstreamRequestRetainsClientSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "follow"},
		{name: "use last response", err: http.ErrUseLastResponse},
		{name: "callback error", err: errors.New("custom redirect rejection")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			origin, err := url.Parse("https://upstream.test/start")
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(origin, []*http.Cookie{{Name: "session", Value: "ambient", Path: "/", Domain: "upstream.test"}})
			checks := 0
			requests := 0
			client := &http.Client{
				Timeout: time.Minute,
				Jar:     jar,
				CheckRedirect: func(req *http.Request, _ []*http.Request) error {
					checks++
					// The shared policy must strip credentials even if an existing
					// callback adds them back to a cross-origin request.
					req.Header.Set("Authorization", "Bearer callback-token")
					return tc.err
				},
				Transport: containerTestTransport(func(req *http.Request) (*http.Response, error) {
					requests++
					if _, ok := req.Context().Deadline(); !ok {
						t.Error("default client timeout lost")
					}
					if req.Header.Get("Cookie") != "" {
						t.Error("ambient client cookie leaked")
					}
					if req.URL.Path == "/start" {
						resp := containerTestResponse(req, http.StatusTemporaryRedirect, "redirect body")
						resp.Header.Set("Location", "https://cdn.upstream.test/finish?signature=opaque%2Bsignature")
						return resp, nil
					}
					if req.Header.Get("Authorization") != "" || req.URL.RawQuery != "signature=opaque%2Bsignature" {
						t.Error("CDN credentials or signed query changed")
					}
					return containerTestResponse(req, http.StatusOK, "payload"), nil
				}),
			}
			previous := http.DefaultClient
			http.DefaultClient = client
			t.Cleanup(func() { http.DefaultClient = previous })
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, _, err := doUpstreamRequest(req)
			wantRequests := 1
			if tc.err == nil {
				wantRequests++
			}
			if checks != 1 || requests != wantRequests {
				t.Errorf("callbacks = %d, requests = %d; want 1, %d", checks, requests, wantRequests)
			}
			if client.Jar != jar || client.CheckRedirect == nil || client.Timeout != time.Minute {
				t.Error("default client mutated")
			}
			if tc.err != nil && !errors.Is(tc.err, http.ErrUseLastResponse) {
				if !errors.Is(err, tc.err) {
					t.Fatalf("error = %v, want callback error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			wantStatus := http.StatusOK
			if errors.Is(tc.err, http.ErrUseLastResponse) {
				wantStatus = http.StatusTemporaryRedirect
			}
			if resp.StatusCode != wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, wantStatus)
			}
			if _, err := io.ReadAll(resp.Body); err != nil {
				t.Fatalf("response body closed too early: %v", err)
			}
		})
	}
}

func TestUpstreamRedirectLimit(t *testing.T) {
	requests := 0
	useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
		requests++
		if requests > 10 {
			t.Fatal("redirect loop exceeded limit")
		}
		resp := containerTestResponse(req, http.StatusFound, "")
		resp.Header.Set("Location", "/loop")
		return resp, nil
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://upstream.test/loop", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = doUpstreamRequest(req)
	if err == nil || !strings.Contains(err.Error(), "redirect limit") || requests != 10 {
		t.Fatalf("requests = %d, error = %v", requests, err)
	}
}
