package main

// TLS transport for both servers. The mode and all its settings come entirely
// from environment variables (ARTIGATE_TLS_* / ARTIGATE_ACME_*), so HTTPS can be
// configured without touching flags. ACME certificates are obtained and renewed
// with certmagic (github.com/caddyserver/certmagic).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

// tlsMode selects the transport, via ARTIGATE_TLS_MODE.
type tlsMode string

const (
	tlsUnencrypted tlsMode = "unencrypted"               // plain HTTP
	tlsACME        tlsMode = "acme"                      // automatic certs via ACME (certmagic)
	tlsOwnCert     tlsMode = "own-certificate"           // operator-provided cert + key
	tlsAutoGen     tlsMode = "auto-generate-certificate" // self-signed cert made at startup
)

// TLSConfig is the transport configuration, resolved entirely from environment
// variables so it needs no flags.
type TLSConfig struct {
	Mode       tlsMode
	Domains    []string // ARTIGATE_TLS_DOMAINS (comma-separated): ACME names + self-signed SANs
	CertFile   string   // ARTIGATE_TLS_CERT    (own-certificate)
	KeyFile    string   // ARTIGATE_TLS_KEY     (own-certificate)
	ACMEEmail  string   // ARTIGATE_ACME_EMAIL
	ACMECA     string   // ARTIGATE_ACME_DIRECTORY (ACME server directory URL)
	ACMERootCA string   // ARTIGATE_ACME_CA_ROOT   (PEM of a private ACME server's root CA)
	ACMEStore  string   // ARTIGATE_ACME_STORAGE   (cert cache dir; default <root>/acme)
}

func getenvOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tlsConfigFromEnv reads and validates the transport configuration. The mode
// defaults to unencrypted.
func tlsConfigFromEnv() (TLSConfig, error) {
	c := TLSConfig{
		Mode:       tlsMode(strings.ToLower(getenvOr("ARTIGATE_TLS_MODE", string(tlsUnencrypted)))),
		Domains:    splitCSV(os.Getenv("ARTIGATE_TLS_DOMAINS")),
		CertFile:   strings.TrimSpace(os.Getenv("ARTIGATE_TLS_CERT")),
		KeyFile:    strings.TrimSpace(os.Getenv("ARTIGATE_TLS_KEY")),
		ACMEEmail:  strings.TrimSpace(os.Getenv("ARTIGATE_ACME_EMAIL")),
		ACMECA:     strings.TrimSpace(os.Getenv("ARTIGATE_ACME_DIRECTORY")),
		ACMERootCA: strings.TrimSpace(os.Getenv("ARTIGATE_ACME_CA_ROOT")),
		ACMEStore:  strings.TrimSpace(os.Getenv("ARTIGATE_ACME_STORAGE")),
	}
	switch c.Mode {
	case tlsUnencrypted, tlsAutoGen:
	case tlsOwnCert:
		if c.CertFile == "" || c.KeyFile == "" {
			return TLSConfig{}, errors.New("ARTIGATE_TLS_MODE=own-certificate requires ARTIGATE_TLS_CERT and ARTIGATE_TLS_KEY")
		}
	case tlsACME:
		if len(c.Domains) == 0 {
			return TLSConfig{}, errors.New("ARTIGATE_TLS_MODE=acme requires ARTIGATE_TLS_DOMAINS")
		}
	default:
		return TLSConfig{}, fmt.Errorf("invalid ARTIGATE_TLS_MODE %q (want unencrypted, acme, own-certificate, or auto-generate-certificate)", c.Mode)
	}
	return c, nil
}

// serverTLSConfig returns the *tls.Config for the mode, or nil for unencrypted.
// storageDir is where ACME certificates are cached when ARTIGATE_ACME_STORAGE is
// unset.
func serverTLSConfig(c TLSConfig, storageDir string) (*tls.Config, error) {
	switch c.Mode {
	case tlsUnencrypted:
		return nil, nil
	case tlsOwnCert:
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case tlsAutoGen:
		cert, err := selfSignedCert(c.Domains)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case tlsACME:
		return acmeTLSConfig(c, storageDir)
	default:
		return nil, fmt.Errorf("invalid tls mode %q", c.Mode)
	}
}

// acmeTLSConfig configures certmagic and returns a tls.Config that obtains and
// renews certificates in the background and answers the TLS-ALPN-01 challenge on
// the server's own listener.
func acmeTLSConfig(c TLSConfig, storageDir string) (*tls.Config, error) {
	store := c.ACMEStore
	if store == "" {
		store = filepath.Join(storageDir, "acme")
	}
	certmagic.Default.Storage = &certmagic.FileStorage{Path: store}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = c.ACMEEmail
	if c.ACMECA != "" {
		certmagic.DefaultACME.CA = c.ACMECA
	}
	if c.ACMERootCA != "" { // a private ACME server's root, so its certs are trusted
		pool, err := certPoolFromPEM(c.ACMERootCA)
		if err != nil {
			return nil, err
		}
		certmagic.DefaultACME.TrustedRoots = pool
	}
	magic := certmagic.NewDefault()
	if err := magic.ManageAsync(context.Background(), c.Domains); err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}
	tlsCfg := magic.TLSConfig()
	// Pin the same TLS 1.2 floor as the other modes; certmagic's default already
	// matches, but set it explicitly so the guarantee is enforced here too.
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	return tlsCfg, nil
}

func certPoolFromPEM(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// selfSignedCert makes an in-memory self-signed certificate for the given
// domains/IPs (defaulting to a placeholder name), used by the auto-generate
// mode.
func selfSignedCert(domains []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"ArtiGate"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, d := range domains {
		if ip := net.ParseIP(d); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, d)
		}
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		tmpl.DNSNames = []string{"artigate.local"}
	}
	if len(tmpl.DNSNames) > 0 {
		tmpl.Subject.CommonName = tmpl.DNSNames[0]
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// listenAddrIsLoopback reports whether a listen address binds only the local
// loopback interface (so it is unreachable from other hosts). A host-less
// address such as ":8080" — or an unresolved hostname, which could point
// anywhere — is treated as NOT loopback, so the fail-closed guards err on the
// side of caution.
func listenAddrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port present; consider the whole value the host
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// remoteAddrIsLoopback reports whether a request originates from the local host
// (directly, or via a reverse proxy running on it). Used to keep high-side
// mutation endpoints local by default.
func remoteAddrIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

// shutdownGracePeriod bounds how long a graceful shutdown waits for in-flight
// requests to finish before the process exits anyway. Large artifact transfers
// can exceed it; those connections are cut at exit exactly as an ungraceful stop
// would have done, while short requests and durable-state writes drain cleanly.
const shutdownGracePeriod = 30 * time.Second

// listenAndServe serves handler on addr using the configured transport, blocking
// until the server stops or ctx is cancelled. On cancellation (a SIGINT/SIGTERM
// the caller wired into ctx) it drains in-flight requests for up to
// shutdownGracePeriod before returning nil, so a `docker stop` or systemd stop
// no longer aborts requests and truncates the caller's deferred store closes.
// storageDir is the ACME cert cache root.
func listenAndServe(ctx context.Context, c TLSConfig, addr, storageDir string, handler http.Handler) error {
	tlsCfg, err := serverTLSConfig(c, storageDir)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		// IdleTimeout bounds how long an idle keep-alive connection is held so a
		// flood of opened-but-silent connections cannot pin resources. No
		// ReadTimeout/WriteTimeout is set deliberately: both servers stream
		// multi-gigabyte artifacts (model/repo downloads, diode bundle ingest)
		// whose transfers legitimately outrun any fixed whole-request deadline.
		// Slow-header attacks are covered by ReadHeaderTimeout; the small
		// unauthenticated endpoints that do read a body (e.g. /login) set their
		// own per-request body limit and read deadline.
		IdleTimeout: 120 * time.Second,
	}
	srvErr := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			srv.TLSConfig = tlsCfg
			srvErr <- srv.ListenAndServeTLS("", "") // certificates come from TLSConfig
			return
		}
		srvErr <- srv.ListenAndServe()
	}()
	select {
	case err := <-srvErr:
		return err // failed to start, or stopped on its own
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown incomplete after %s: %v", shutdownGracePeriod, err)
		}
		<-srvErr // ListenAndServe returns ErrServerClosed once Shutdown closes it
		return nil
	}
}
