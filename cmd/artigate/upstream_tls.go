package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// upstreamTLSProfile contains only local operator configuration. Requests and
// watches refer to its name; none of these paths belongs in a bundle.
type upstreamTLSProfile struct {
	CertFile       string   `json:"cert_file"`
	KeyFile        string   `json:"key_file"`
	CAFile         string   `json:"ca_file,omitempty"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// loadUpstreamTLSClient reads both the configuration and certificate files for
// every collect, so renewal takes effect without restarting the low side.
func loadUpstreamTLSClient(profileName string, rawURLs []string) (*http.Client, error) {
	if profileName == "" {
		return nil, nil
	}
	if !validUpstreamTLSProfileName(profileName) {
		return nil, errors.New("invalid upstream TLS profile name: use 1-64 letters, digits, underscores or hyphens")
	}
	profile, err := readUpstreamTLSProfile(profileName)
	if err != nil {
		return nil, err
	}
	origins, err := upstreamTLSAllowedOrigins(profile)
	if err != nil {
		return nil, fmt.Errorf("upstream TLS profile %q: %w", profileName, err)
	}
	for _, rawURL := range rawURLs {
		u, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			return nil, errors.New("invalid upstream URL for TLS profile")
		}
		if err := checkUpstreamTLSOrigin(u, origins); err != nil {
			return nil, err
		}
	}
	tlsConfig, err := upstreamTLSConfig(profile)
	if err != nil {
		return nil, fmt.Errorf("upstream TLS profile %q: %w", profileName, err)
	}
	transport, err := newUpstreamTLSTransport(tlsConfig, origins)
	if err != nil {
		return nil, err
	}
	client := *http.DefaultClient
	client.Transport = transport
	client.Jar = nil
	return &client, nil
}

func validUpstreamTLSProfileName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, char := range name {
		letter := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
		digit := char >= '0' && char <= '9'
		if !letter && !digit && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func readUpstreamTLSProfile(name string) (upstreamTLSProfile, error) {
	configPath := os.Getenv("ARTIGATE_UPSTREAM_TLS_CONFIG")
	if !filepath.IsAbs(configPath) {
		return upstreamTLSProfile{}, errors.New("ARTIGATE_UPSTREAM_TLS_CONFIG must name an absolute JSON file path")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return upstreamTLSProfile{}, fmt.Errorf("read upstream TLS configuration: %w", err)
	}
	profiles, err := upstreamTLSJSONObject(data)
	if err != nil {
		return upstreamTLSProfile{}, fmt.Errorf("invalid upstream TLS configuration: %w", err)
	}
	var selected upstreamTLSProfile
	for profileName, raw := range profiles {
		if !validUpstreamTLSProfileName(profileName) {
			return upstreamTLSProfile{}, errors.New("upstream TLS configuration contains an invalid profile name")
		}
		profile, err := decodeUpstreamTLSProfile(raw)
		if err != nil {
			return upstreamTLSProfile{}, fmt.Errorf("invalid upstream TLS profile %q: %w", profileName, err)
		}
		if profileName == name {
			selected = profile
		}
	}
	if _, found := profiles[name]; !found {
		return upstreamTLSProfile{}, fmt.Errorf("unknown upstream TLS profile %q", name)
	}
	return selected, nil
}

// Reject duplicate keys and trailing JSON instead of letting the decoder pick
// one of two conflicting credential or origin settings.
func upstreamTLSJSONObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid JSON object key")
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON object key")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate JSON object key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid JSON field value")
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after JSON object")
	}
	return fields, nil
}

func decodeUpstreamTLSProfile(data []byte) (upstreamTLSProfile, error) {
	fields, err := upstreamTLSJSONObject(data)
	if err != nil {
		return upstreamTLSProfile{}, err
	}
	var profile upstreamTLSProfile
	destinations := map[string]any{
		"cert_file": &profile.CertFile, "key_file": &profile.KeyFile,
		"ca_file": &profile.CAFile, "allowed_origins": &profile.AllowedOrigins,
	}
	for key, raw := range fields {
		destination, known := destinations[key]
		if !known {
			return upstreamTLSProfile{}, errors.New("unknown profile field (want cert_file, key_file, ca_file or allowed_origins)")
		}
		if err := json.Unmarshal(raw, destination); err != nil {
			return upstreamTLSProfile{}, fmt.Errorf("invalid %s value", key)
		}
	}
	return profile, nil
}

func upstreamTLSAllowedOrigins(profile upstreamTLSProfile) (map[string]bool, error) {
	if len(profile.AllowedOrigins) == 0 {
		return nil, errors.New("allowed_origins must contain at least one HTTPS origin")
	}
	origins := make(map[string]bool, len(profile.AllowedOrigins))
	for _, raw := range profile.AllowedOrigins {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, errors.New("allowed_origins contains an invalid URL")
		}
		if u.Path != "" && u.Path != "/" {
			return nil, errors.New("allowed_origins entries must not include a path")
		}
		if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
			return nil, errors.New("allowed_origins entries must not include a query or fragment")
		}
		origin, err := upstreamTLSOrigin(u)
		if err != nil {
			return nil, err
		}
		origins[origin] = true
	}
	return origins, nil
}

func upstreamTLSOrigin(u *url.URL) (string, error) {
	if u == nil || u.Scheme != "https" {
		return "", errors.New("upstream TLS profile requires HTTPS")
	}
	if u.User != nil || u.Opaque != "" {
		return "", errors.New("upstream TLS URLs must not include userinfo or opaque URLs")
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || strings.ContainsAny(hostname, "*%") {
		return "", errors.New("upstream TLS origin must have a concrete hostname")
	}
	port := upstreamOriginPort(u)
	if port < 1 || port > 65535 || strings.HasSuffix(u.Host, ":") {
		return "", errors.New("upstream TLS origin has an invalid port")
	}
	return "https://" + net.JoinHostPort(hostname, strconv.Itoa(port)), nil
}

func checkUpstreamTLSOrigin(u *url.URL, origins map[string]bool) error {
	origin, err := upstreamTLSOrigin(u)
	if err != nil {
		return err
	}
	if !origins[origin] {
		return errors.New("origin is not allowed by upstream TLS profile")
	}
	return nil
}

func upstreamTLSConfig(profile upstreamTLSProfile) (*tls.Config, error) {
	if !filepath.IsAbs(profile.CertFile) || !filepath.IsAbs(profile.KeyFile) {
		return nil, errors.New("cert_file and key_file must be absolute paths")
	}
	cert, err := tls.LoadX509KeyPair(profile.CertFile, profile.KeyFile)
	if err != nil {
		return nil, errors.New("cannot load client certificate and key: files must be readable, matching PEM files")
	}
	if err := validateUpstreamTLSCertificate(cert); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if profile.CAFile != "" {
		if !filepath.IsAbs(profile.CAFile) {
			return nil, errors.New("ca_file must be an absolute path")
		}
		data, err := os.ReadFile(profile.CAFile)
		if err != nil {
			return nil, errors.New("cannot read upstream TLS ca_file")
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(data) {
			return nil, errors.New("upstream TLS ca_file must contain PEM certificates")
		}
	}
	return tlsConfig, nil
}

func validateUpstreamTLSCertificate(cert tls.Certificate) error {
	now := time.Now()
	for _, der := range cert.Certificate {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("invalid upstream TLS client certificate")
		}
		if now.Before(certificate.NotBefore) {
			return errors.New("upstream TLS client certificate is not yet valid")
		}
		if !now.Before(certificate.NotAfter) {
			return errors.New("upstream TLS client certificate has expired; renew it before collecting")
		}
	}
	return nil
}

// The gate is inside RoundTrip, so it also protects direct client.Do calls and
// redirects before a connection can present the configured certificate.
type upstreamTLSTransport struct {
	transport *http.Transport
	origins   map[string]bool
}

func newUpstreamTLSTransport(config *tls.Config, origins map[string]bool) (*upstreamTLSTransport, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("upstream TLS requires a standard HTTP default transport")
	}
	transport := base.Clone()
	transport.TLSClientConfig = config
	// A custom TLS dialer or protocol handler can bypass TLSClientConfig and
	// its server verification. Profiles always use the standard TLS handshake.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSNextProto = nil
	if proxy := transport.Proxy; proxy != nil {
		transport.Proxy = upstreamTLSProxy(proxy, origins)
	}
	return &upstreamTLSTransport{transport: transport, origins: origins}, nil
}

func upstreamTLSProxy(proxy func(*http.Request) (*url.URL, error), origins map[string]bool) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err
		}
		// Go uses TLSClientConfig for HTTPS proxy handshakes too. Such a
		// proxy must be explicitly permitted to see the client certificate.
		if proxyURL.Scheme == "https" {
			origin := *proxyURL
			origin.User = nil
			if err := checkUpstreamTLSOrigin(&origin, origins); err != nil {
				return nil, errors.New("HTTPS proxy origin is not allowed by upstream TLS profile")
			}
		}
		return proxyURL, nil
	}
}

func (t *upstreamTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := checkUpstreamTLSOrigin(req.URL, t.origins); err != nil {
		return nil, err
	}
	return t.transport.RoundTrip(req)
}

func (t *upstreamTLSTransport) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}
