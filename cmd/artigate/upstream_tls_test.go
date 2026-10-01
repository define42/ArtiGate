package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type upstreamTLSFixture struct {
	dir   string
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	paths upstreamTLSProfile
}

func newUpstreamTLSFixture(t *testing.T) *upstreamTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &upstreamTLSFixture{dir: t.TempDir(), ca: ca, key: key}
	fixture.paths = upstreamTLSProfile{
		CertFile: filepath.Join(fixture.dir, "client.pem"),
		KeyFile:  filepath.Join(fixture.dir, "client-key.pem"),
		CAFile:   filepath.Join(fixture.dir, "ca.pem"),
	}
	writeUpstreamTLSFile(t, fixture.paths.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	fixture.writeClient(t, 2, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	return fixture
}

func writeUpstreamTLSFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *upstreamTLSFixture) certificate(t *testing.T, serial int64, before, after time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "upstream test peer"},
		NotBefore: before, NotAfter: after, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, f.ca, &key.PublicKey, f.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (f *upstreamTLSFixture) writeClient(t *testing.T, serial int64, before, after time.Time) {
	t.Helper()
	cert, key := f.certificate(t, serial, before, after)
	writeUpstreamTLSFile(t, f.paths.CertFile, cert)
	writeUpstreamTLSFile(t, f.paths.KeyFile, key)
}

func (f *upstreamTLSFixture) server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	certPEM, keyPEM := f.certificate(t, 100, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.ca)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func (f *upstreamTLSFixture) configure(t *testing.T, origins ...string) upstreamTLSProfile {
	t.Helper()
	profile := f.paths
	profile.AllowedOrigins = origins
	f.saveProfile(t, profile)
	return profile
}

func (f *upstreamTLSFixture) saveProfile(t *testing.T, profile upstreamTLSProfile) {
	t.Helper()
	data, err := json.Marshal(map[string]upstreamTLSProfile{"redhat": profile})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "profiles.json")
	writeUpstreamTLSFile(t, path, data)
	t.Setenv("ARTIGATE_UPSTREAM_TLS_CONFIG", path)
}

func TestUpstreamTLSClientRequestsAndRedirects(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	var secondaryRequests atomic.Int32
	secondary := fixture.server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondaryRequests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Referer") != "" {
			t.Error("credentials leaked on allowed cross-origin redirect")
		}
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].SerialNumber.Int64() != 2 {
			t.Error("secondary origin did not receive configured client certificate")
		}
		_, _ = io.WriteString(w, "secondary")
	}))
	primary := fixture.server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local" {
			t.Error("same-origin authorization lost")
		}
		switch r.URL.Path {
		case "/relative":
			http.Redirect(w, r, "/finish", http.StatusFound)
		case "/secondary":
			http.Redirect(w, r, secondary.URL+"/finish", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "primary")
		}
	}))
	fixture.configure(t, primary.URL+"/", secondary.URL)
	client, err := loadUpstreamTLSClient("redhat", []string{primary.URL + "/repo"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		name, body string
		sameOrigin bool
	}{
		{name: "relative", body: "primary", sameOrigin: true},
		{name: "secondary", body: "secondary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, primary.URL+"/"+tc.name, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer local")
			response, sameOrigin, err := doUpstreamRequestWithClient(req, client)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != tc.body || sameOrigin != tc.sameOrigin {
				t.Fatalf("body = %q, sameOrigin = %t, error = %v", body, sameOrigin, err)
			}
		})
	}
	if secondaryRequests.Load() != 1 {
		t.Fatal("allowed secondary origin was not requested")
	}
}

func TestUpstreamTLSClientRejectsOriginBeforeConnection(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	var connections atomic.Int32
	forbidden := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("requested forbidden target")
	}))
	forbidden.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	forbidden.StartTLS()
	defer forbidden.Close()
	primary := fixture.server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := forbidden.URL
		switch r.URL.Path {
		case "/host":
			target = strings.Replace(target, "127.0.0.1", "localhost", 1)
		case "/downgrade":
			target = strings.Replace(target, "https:", "http:", 1)
		}
		http.Redirect(w, r, target, http.StatusFound)
	}))
	fixture.configure(t, primary.URL)
	client, err := loadUpstreamTLSClient("redhat", []string{primary.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/port", "/host", "/downgrade"} {
		t.Run(path, func(t *testing.T) {
			// Even direct client use must enforce the certificate boundary.
			response, err := client.Get(primary.URL + path)
			if response != nil {
				response.Body.Close()
			}
			want := "origin is not allowed"
			if path == "/downgrade" {
				want = "requires HTTPS"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("redirect error = %v, want %q", err, want)
			}
		})
	}
	response, err := client.Get(forbidden.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "origin is not allowed") {
		t.Fatalf("direct forbidden request error = %v", err)
	}
	if connections.Load() != 0 {
		t.Fatalf("made %d connections to forbidden origin", connections.Load())
	}
}

func TestUpstreamTLSProfileValidation(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	profile := fixture.configure(t, "https://cdn.redhat.com")
	for _, tc := range []struct {
		name, profile, want string
		urls                []string
	}{
		{name: "unknown", profile: "missing", want: "unknown upstream TLS profile"},
		{name: "invalid", profile: "../redhat", want: "invalid upstream TLS profile name"},
		{name: "too long", profile: strings.Repeat("a", 65), want: "invalid upstream TLS profile name"},
		{name: "unlisted origin", profile: "redhat", urls: []string{"https://example.com/"}, want: "origin is not allowed"},
		{name: "different port", profile: "redhat", urls: []string{"https://cdn.redhat.com:8443/"}, want: "origin is not allowed"},
		{name: "HTTP", profile: "redhat", urls: []string{"http://cdn.redhat.com/"}, want: "requires HTTPS"},
		{name: "invalid URL", profile: "redhat", urls: []string{"https://cdn.redhat.com:%/"}, want: "invalid upstream URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadUpstreamTLSClient(tc.profile, tc.urls)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	for _, origin := range []string{
		"http://cdn.redhat.com", "https://*.redhat.com", "https://user:secret@cdn.redhat.com",
		"https://cdn.redhat.com/path", "https://cdn.redhat.com?query=secret", "https://cdn.redhat.com?",
		"https://cdn.redhat.com#fragment", "https://cdn.redhat.com#", "https://cdn.redhat.com:",
		"https://cdn.redhat.com:0", "https://cdn.redhat.com:65536", "https:///", "https://[::1%25eth0]",
	} {
		t.Run(origin, func(t *testing.T) {
			invalid := profile
			invalid.AllowedOrigins = []string{origin}
			fixture.saveProfile(t, invalid)
			_, err := loadUpstreamTLSClient("redhat", nil)
			if err == nil {
				t.Fatal("accepted invalid origin")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error exposed URL credentials: %v", err)
			}
		})
	}
	fixture.saveProfile(t, profile)
	client, err := loadUpstreamTLSClient("redhat", []string{"https://CDN.REDHAT.com:0443/repo?token=opaque"})
	if err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	if client, err := loadUpstreamTLSClient("", []string{"invalid"}); client != nil || err != nil {
		t.Fatalf("no profile = %v, %v", client, err)
	}
}

func TestUpstreamTLSConfigRejectsInvalidJSON(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	fixture.configure(t, "https://cdn.redhat.com")
	path := os.Getenv("ARTIGATE_UPSTREAM_TLS_CONFIG")
	for _, tc := range []struct{ name, data, want string }{
		{name: "malformed", data: "{", want: "invalid"},
		{name: "null", data: "null", want: "JSON object"},
		{name: "array", data: "[]", want: "JSON object"},
		{name: "trailing", data: "{} {}", want: "unexpected data"},
		{name: "duplicate profile", data: `{"redhat":{},"redhat":{}}`, want: "duplicate"},
		{name: "duplicate field", data: `{"redhat":{"cert_file":"one","cert_file":"two"}}`, want: "duplicate"},
		{name: "unknown field", data: `{"redhat":{"private-key-material":"secret"}}`, want: "unknown profile field"},
		{name: "wrong type", data: `{"redhat":{"allowed_origins":1}}`, want: "invalid allowed_origins"},
		{name: "invalid name", data: `{"../redhat":{}}`, want: "invalid profile name"},
		{name: "null profile", data: `{"redhat":null}`, want: "JSON object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeUpstreamTLSFile(t, path, []byte(tc.data))
			_, err := loadUpstreamTLSClient("redhat", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("configuration material leaked")
			}
		})
	}
	for _, configPath := range []string{"", "relative.json", filepath.Join(fixture.dir, "missing.json")} {
		t.Run("config path "+configPath, func(t *testing.T) {
			t.Setenv("ARTIGATE_UPSTREAM_TLS_CONFIG", configPath)
			if _, err := loadUpstreamTLSClient("redhat", nil); err == nil {
				t.Fatal("accepted invalid config path")
			}
		})
	}
}

func TestUpstreamTLSClientCertificateValidation(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*testing.T, *upstreamTLSFixture, *upstreamTLSProfile)
	}{
		{name: "missing cert", want: "absolute paths", change: func(_ *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) { p.CertFile = "" }},
		{name: "relative key", want: "absolute paths", change: func(_ *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) { p.KeyFile = "key.pem" }},
		{name: "relative CA", want: "ca_file must be an absolute path", change: func(_ *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) { p.CAFile = "ca.pem" }},
		{name: "no origins", want: "at least one HTTPS origin", change: func(_ *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) { p.AllowedOrigins = nil }},
		{name: "missing key file", want: "cannot load client certificate and key", change: func(_ *testing.T, f *upstreamTLSFixture, p *upstreamTLSProfile) {
			p.KeyFile = filepath.Join(f.dir, "missing")
		}},
		{name: "bad cert", want: "matching PEM files", change: func(t *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) {
			writeUpstreamTLSFile(t, p.CertFile, []byte("secret material"))
		}},
		{name: "bad key", want: "matching PEM files", change: func(t *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) {
			writeUpstreamTLSFile(t, p.KeyFile, []byte("secret material"))
		}},
		{name: "mismatched pair", want: "matching PEM files", change: func(t *testing.T, f *upstreamTLSFixture, p *upstreamTLSProfile) {
			_, key := f.certificate(t, 3, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			writeUpstreamTLSFile(t, p.KeyFile, key)
		}},
		{name: "bad CA", want: "ca_file must contain PEM certificates", change: func(t *testing.T, _ *upstreamTLSFixture, p *upstreamTLSProfile) {
			writeUpstreamTLSFile(t, p.CAFile, []byte("secret material"))
		}},
		{name: "missing CA", want: "cannot read upstream TLS ca_file", change: func(_ *testing.T, f *upstreamTLSFixture, p *upstreamTLSProfile) {
			p.CAFile = filepath.Join(f.dir, "missing")
		}},
		{name: "expired", want: "has expired", change: func(t *testing.T, f *upstreamTLSFixture, _ *upstreamTLSProfile) {
			f.writeClient(t, 3, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		}},
		{name: "future", want: "not yet valid", change: func(t *testing.T, f *upstreamTLSFixture, _ *upstreamTLSProfile) {
			f.writeClient(t, 3, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newUpstreamTLSFixture(t)
			profile := fixture.configure(t, "https://cdn.redhat.com")
			tc.change(t, fixture, &profile)
			fixture.saveProfile(t, profile)
			_, err := loadUpstreamTLSClient("redhat", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret material") {
				t.Fatal("certificate material leaked")
			}
		})
	}
}

func TestUpstreamTLSClientReloadsCertificatesAndConfig(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	server := fixture.server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].SerialNumber.String())
	}))
	fixture.configure(t, server.URL)
	oldClient, err := loadUpstreamTLSClient("redhat", []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer oldClient.CloseIdleConnections()
	assertUpstreamTLSBody(t, oldClient, server.URL, "2")
	fixture.writeClient(t, 3, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	renewed, err := loadUpstreamTLSClient("redhat", []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer renewed.CloseIdleConnections()
	assertUpstreamTLSBody(t, renewed, server.URL, "3")
	assertUpstreamTLSBody(t, oldClient, server.URL, "2")
	fixture.configure(t, "https://different.example")
	if _, err := loadUpstreamTLSClient("redhat", []string{server.URL}); err == nil || !strings.Contains(err.Error(), "origin is not allowed") {
		t.Fatalf("changed configuration did not take effect: %v", err)
	}
}

func assertUpstreamTLSBody(t *testing.T, client *http.Client, rawURL, want string) {
	t.Helper()
	response, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != want {
		t.Fatalf("body = %q, error = %v; want %q", body, err, want)
	}
}

func TestUpstreamTLSClientVerifiesServer(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	previous := http.DefaultTransport
	base, ok := previous.(*http.Transport)
	if !ok {
		t.Fatal("default transport is not HTTP")
	}
	unsafeTransport := base.Clone()
	unsafeTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	var customDials atomic.Int32
	unsafeTransport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		customDials.Add(1)
		return nil, errors.New("custom TLS dialer bypassed profile verification")
	}
	unsafeTransport.DialTLS = func(string, string) (net.Conn, error) {
		customDials.Add(1)
		return nil, errors.New("legacy TLS dialer bypassed profile verification")
	}
	http.DefaultTransport = unsafeTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("accepted untrusted server")
	}))
	defer server.Close()
	for _, systemRoots := range []bool{false, true} {
		name := "profile CA"
		if systemRoots {
			name = "system roots"
		}
		t.Run(name, func(t *testing.T) {
			profile := fixture.configure(t, server.URL)
			if systemRoots {
				profile.CAFile = ""
				fixture.saveProfile(t, profile)
			}
			client, err := loadUpstreamTLSClient("redhat", []string{server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			response, err := client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("untrusted server error = %v", err)
			}
		})
	}
	if customDials.Load() != 0 {
		t.Fatal("inherited TLS dialer bypassed profile verification")
	}
}

func TestUpstreamTLSClientRetainsDefaultClientSettings(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	server := fixture.server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/start" {
			t.Error("ignored default client redirect callback")
		}
		http.Redirect(w, r, "/finish", http.StatusFound)
	}))
	fixture.configure(t, server.URL)
	previous := http.DefaultClient
	checks := 0
	http.DefaultClient = &http.Client{
		Timeout: time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			checks++
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(func() { http.DefaultClient = previous })
	client, err := loadUpstreamTLSClient("redhat", []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if client.Timeout != time.Minute {
		t.Fatal("lost default client timeout")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := doUpstreamRequestWithClient(req, client)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || checks != 1 {
		t.Fatalf("status = %d, redirect callbacks = %d", response.StatusCode, checks)
	}
}

func TestUpstreamTLSClientRejectsHTTPSProxyBeforeConnection(t *testing.T) {
	fixture := newUpstreamTLSFixture(t)
	var connections atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unlisted HTTPS proxy contacted")
	}))
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	proxy.StartTLS()
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("private", "proxy-secret")
	previous := http.DefaultTransport
	transport, ok := previous.(*http.Transport)
	if !ok {
		t.Fatal("default transport is not HTTP")
	}
	base := transport.Clone()
	base.Proxy = http.ProxyURL(proxyURL)
	http.DefaultTransport = base
	t.Cleanup(func() { http.DefaultTransport = previous })
	fixture.configure(t, "https://cdn.redhat.com")
	client, err := loadUpstreamTLSClient("redhat", []string{"https://cdn.redhat.com/repo"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://cdn.redhat.com/repo")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "HTTPS proxy origin is not allowed") {
		t.Fatalf("proxy error = %v", err)
	}
	if strings.Contains(err.Error(), "proxy-secret") || connections.Load() != 0 {
		t.Fatalf("proxy credential boundary failed: connections=%d, err=%v", connections.Load(), err)
	}
}
