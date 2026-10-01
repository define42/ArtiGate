package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise each credential-bearing fetch helper through net/http's real
// redirect handling. The transport is replaced, so no external hosts are used.
func TestUpstreamFetchRedirectCredentials(t *testing.T) {
	const payload = "mirrored upstream content"
	const objectID = "0123456789012345678901234567890123456789"
	cred := &registryCredential{Username: "upstream-user", Password: "upstream-password"}
	authRequest := &http.Request{Header: make(http.Header)}
	authRequest.SetBasicAuth(cred.Username, cred.Password)
	basicAuth := authRequest.Header.Get("Authorization")
	digest := sha256.Sum256([]byte(payload))
	wantSHA := hex.EncodeToString(digest[:])
	pack, _ := gitTestPack(t, nil)
	advertisement := gitPktLine("# service=git-upload-pack\n") + gitFlushPkt +
		gitPktLine(objectID+" refs/heads/main\n") + gitFlushPkt

	callers := []struct {
		name     string
		auth     string
		method   string
		response string
		wantBody string
		fetch    func(*testing.T, string) (string, error)
	}{
		{
			name: "metadata", auth: basicAuth, method: http.MethodGet, response: payload, wantBody: payload,
			fetch: func(t *testing.T, rawURL string) (string, error) {
				body, err := httpGetBytesAuth(t.Context(), rawURL, 1024, cred)
				return string(body), err
			},
		},
		{
			name: "verified package", auth: basicAuth, method: http.MethodGet, response: payload, wantBody: payload,
			fetch: func(t *testing.T, rawURL string) (string, error) {
				path := filepath.Join(t.TempDir(), "package")
				sum, size, err := downloadVerifiedFileAuth(t.Context(), rawURL, path, int64(len(payload)), "sha256", wantSHA, cred)
				if err != nil {
					return "", err
				}
				if sum != wantSHA || size != int64(len(payload)) {
					t.Errorf("download digest=%q size=%d", sum, size)
				}
				body, err := os.ReadFile(path)
				return string(body), err
			},
		},
		{
			name: "APK package", auth: basicAuth, method: http.MethodGet, response: payload, wantBody: payload,
			fetch: func(t *testing.T, rawURL string) (string, error) {
				path := filepath.Join(t.TempDir(), "package")
				sum, size, err := downloadFileSHA256Auth(t.Context(), rawURL, path, cred)
				if err != nil {
					return "", err
				}
				if sum != wantSHA || size != int64(len(payload)) {
					t.Errorf("download digest=%q size=%d", sum, size)
				}
				body, err := os.ReadFile(path)
				return string(body), err
			},
		},
		{
			name: "git advertisement", auth: basicAuth, method: http.MethodGet,
			response: advertisement, wantBody: objectID,
			fetch: func(t *testing.T, rawURL string) (string, error) {
				adv, err := gitFetchAdvertisement(t.Context(), rawURL, cred)
				if err != nil {
					return "", err
				}
				if len(adv.refs) != 1 || adv.refs[0].Name != "refs/heads/main" {
					t.Fatalf("unexpected advertisement: %+v", adv)
				}
				return adv.refs[0].SHA1, nil
			},
		},
		{
			name: "git pack", auth: basicAuth, method: http.MethodPost,
			response: gitPktLine("NAK\n") + string(pack), wantBody: string(pack),
			fetch: func(t *testing.T, rawURL string) (string, error) {
				body, err := gitFetchPack(t.Context(), rawURL, []string{objectID}, false, cred)
				return string(body), err
			},
		},
		{
			name: "Hugging Face", auth: "Bearer upstream-token", method: http.MethodGet,
			response: payload, wantBody: payload,
			fetch: func(t *testing.T, rawURL string) (string, error) {
				client := &hfClient{token: "upstream-token"}
				resp, err := client.do(t.Context(), "org/model", rawURL, "application/octet-stream")
				if err != nil {
					return "", err
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				return string(body), err
			},
		},
	}
	for _, caller := range callers {
		t.Run(caller.name, func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				scheme   string
				targets  []string
				wantAuth []bool
				wantErr  bool
			}{
				{
					name: "same origin", scheme: "https",
					targets: []string{"/relative", "https://UPSTREAM.test:443/final"}, wantAuth: []bool{true, true, true},
				},
				{
					name: "subdomain", scheme: "https",
					targets: []string{"https://cdn.upstream.test/final"}, wantAuth: []bool{true, false},
				},
				{
					name: "port", scheme: "https",
					targets: []string{"https://upstream.test:8443/final"}, wantAuth: []bool{true, false},
				},
				{
					name: "return from subdomain", scheme: "https",
					targets:  []string{"https://cdn.upstream.test/next", "https://upstream.test/final"},
					wantAuth: []bool{true, false, false},
				},
				{
					name: "return from port", scheme: "https",
					targets:  []string{"https://upstream.test:8443/next", "https://upstream.test/final"},
					wantAuth: []bool{true, false, false},
				},
				{
					name: "HTTPS upgrade", scheme: "http",
					targets: []string{"https://upstream.test/final"}, wantAuth: []bool{true, false},
				},
				{
					name: "HTTPS downgrade", scheme: "https",
					targets: []string{"http://upstream.test/final"}, wantAuth: []bool{true}, wantErr: true,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					requests := 0
					useContainerTestTransport(t, func(req *http.Request) (*http.Response, error) {
						position := requests
						requests++
						if position >= len(tc.wantAuth) {
							t.Error("followed a forbidden redirect")
							return nil, errors.New("forbidden redirect reached transport")
						}
						wantAuth := ""
						if tc.wantAuth[position] {
							wantAuth = caller.auth
						}
						if got := req.Header.Get("Authorization"); got != wantAuth {
							t.Errorf("request %d authorization=%q, want %q", position, got, wantAuth)
						}
						if req.Method != caller.method {
							t.Errorf("request %d method=%s, want %s", position, req.Method, caller.method)
						}
						if position < len(tc.targets) {
							resp := containerTestResponse(req, http.StatusTemporaryRedirect, "")
							resp.Header.Set("Location", tc.targets[position])
							return resp, nil
						}
						return containerTestResponse(req, http.StatusOK, caller.response), nil
					})
					body, err := caller.fetch(t, tc.scheme+"://upstream.test/start")
					if (err != nil) != tc.wantErr {
						t.Fatalf("fetch error=%v, wantErr=%t", err, tc.wantErr)
					}
					if tc.wantErr && !strings.Contains(err.Error(), "downgrade HTTPS") {
						t.Errorf("expected HTTPS downgrade error, got %v", err)
					}
					if !tc.wantErr && body != caller.wantBody {
						t.Errorf("response body=%q, want %q", body, caller.wantBody)
					}
					if requests != len(tc.wantAuth) {
						t.Errorf("made %d requests, want %d", requests, len(tc.wantAuth))
					}
				})
			}
		})
	}
}
