package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestTLSConfigFromEnv(t *testing.T) {
	t.Run("default is unencrypted", func(t *testing.T) {
		t.Setenv("ARTIGATE_TLS_MODE", "")
		c, err := tlsConfigFromEnv()
		if err != nil || c.Mode != tlsUnencrypted {
			t.Fatalf("mode = %q, err = %v; want unencrypted", c.Mode, err)
		}
	})
	t.Run("acme", func(t *testing.T) {
		t.Setenv("ARTIGATE_TLS_MODE", "acme")
		t.Setenv("ARTIGATE_TLS_DOMAINS", "repo.example.com, mirror.example.com")
		t.Setenv("ARTIGATE_ACME_EMAIL", "ops@example.com")
		t.Setenv("ARTIGATE_ACME_DIRECTORY", "https://ca.internal/acme/directory")
		t.Setenv("ARTIGATE_ACME_CA_ROOT", "/etc/artigate/root.pem")
		c, err := tlsConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if c.Mode != tlsACME || len(c.Domains) != 2 || c.Domains[1] != "mirror.example.com" ||
			c.ACMEEmail != "ops@example.com" || c.ACMECA != "https://ca.internal/acme/directory" ||
			c.ACMERootCA != "/etc/artigate/root.pem" {
			t.Fatalf("acme config = %+v", c)
		}
	})
	t.Run("acme needs domains", func(t *testing.T) {
		t.Setenv("ARTIGATE_TLS_MODE", "acme")
		t.Setenv("ARTIGATE_TLS_DOMAINS", "")
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Error("acme without domains should error")
		}
	})
	t.Run("own-certificate needs cert and key", func(t *testing.T) {
		t.Setenv("ARTIGATE_TLS_MODE", "own-certificate")
		t.Setenv("ARTIGATE_TLS_CERT", "")
		t.Setenv("ARTIGATE_TLS_KEY", "")
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Error("own-certificate without cert/key should error")
		}
	})
	t.Run("invalid mode", func(t *testing.T) {
		t.Setenv("ARTIGATE_TLS_MODE", "bogus")
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Error("invalid mode should error")
		}
	})
}

func TestSelfSignedCert(t *testing.T) {
	cert, err := selfSignedCert([]string{"mirror.example.com", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "mirror.example.com" {
		t.Errorf("DNSNames = %v, want [mirror.example.com]", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
}

// writeSelfSignedPEM writes a self-signed cert + key to dir and returns the paths.
func writeSelfSignedPEM(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	cert, err := selfSignedCert([]string{"own.local"})
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func TestServerTLSConfig(t *testing.T) {
	// Unencrypted → no TLS config.
	if cfg, err := serverTLSConfig(TLSConfig{Mode: tlsUnencrypted}, t.TempDir()); err != nil || cfg != nil {
		t.Fatalf("unencrypted = %v, %v; want nil, nil", cfg, err)
	}
	// Auto-generate → one certificate.
	cfg, err := serverTLSConfig(TLSConfig{Mode: tlsAutoGen, Domains: []string{"h.local"}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("auto-generate config = %+v", cfg)
	}
	// Own-certificate → loaded from PEM files.
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedPEM(t, dir)
	cfg, err = serverTLSConfig(TLSConfig{Mode: tlsOwnCert, CertFile: certPath, KeyFile: keyPath}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("own-certificate config = %+v", cfg)
	}
	// Own-certificate with missing files → error.
	if _, err := serverTLSConfig(TLSConfig{Mode: tlsOwnCert, CertFile: "/no/such/cert", KeyFile: "/no/such/key"}, dir); err == nil {
		t.Error("missing certificate should error")
	}
}

// TestServeAutoGenerateTLS proves the auto-generated TLS config actually serves
// HTTPS end to end.
func TestServeAutoGenerateTLS(t *testing.T) {
	cfg, err := serverTLSConfig(TLSConfig{Mode: tlsAutoGen, Domains: []string{"127.0.0.1"}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test client trusts the self-signed cert
	}}
	resp, err := client.Get(ts.URL) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Errorf("body = %q, want ok", b)
	}
}
