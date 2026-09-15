package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSFTPURLValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		url  string
		ok   bool
	}{
		{name: "default port", url: "sftp://sender@example.test/inbox", ok: true},
		{name: "IPv6", url: "sftp://sender@[::1]:2222/inbox", ok: true},
		{name: "escaped path", url: "sftp://sender@example.test/incoming%20files", ok: true},
		{name: "wrong scheme", url: "https://sender@example.test/inbox"},
		{name: "missing user", url: "sftp://example.test/inbox"},
		{name: "missing host", url: "sftp://sender@/inbox"},
		{name: "missing path", url: "sftp://sender@example.test"},
		{name: "embedded secret", url: "sftp://sender:secret-value@example.test/inbox"},
		{name: "query", url: "sftp://sender@example.test/inbox?token=secret-value"},
		{name: "empty query", url: "sftp://sender@example.test/inbox?"},
		{name: "fragment", url: "sftp://sender@example.test/inbox#secret-value"},
		{name: "empty fragment", url: "sftp://sender@example.test/inbox#"},
		{name: "bad port", url: "sftp://sender@example.test:65536/inbox"},
		{name: "zero port", url: "sftp://sender@example.test:0/inbox"},
		{name: "empty port", url: "sftp://sender@example.test:/inbox"},
		{name: "NUL path", url: "sftp://sender@example.test/in%00box"},
		{name: "backslash path", url: "sftp://sender@example.test/in%5cbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseSFTPURL(tc.url)
			if (err == nil) != tc.ok {
				t.Fatalf("parseSFTPURL error = %v, want valid %v", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "secret-value") {
				t.Fatal("configuration error leaked a URL credential")
			}
		})
	}
}

func TestSFTPEnvironmentConfig(t *testing.T) {
	for _, name := range []string{
		"ARTIGATE_SFTP_URL", "ARTIGATE_SFTP_PRIVATE_KEY", "ARTIGATE_SFTP_PASSWORD",
		"ARTIGATE_SFTP_KNOWN_HOSTS", "ARTIGATE_SFTP_POLL_INTERVAL", "ARTIGATE_SFTP_TIMEOUT",
	} {
		t.Setenv(name, "")
	}
	if cfg, err := sftpConfigFromEnv(); cfg != nil || err != nil {
		t.Fatalf("disabled config = %v, %v", cfg, err)
	}
	t.Setenv("ARTIGATE_SFTP_URL", "sftp://sender@example.test/inbox")
	t.Setenv("ARTIGATE_SFTP_PASSWORD", "secret-value")
	if _, err := sftpConfigFromEnv(); err == nil {
		t.Fatal("SFTP accepted missing trusted host keys")
	}
	hosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(hosts, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTIGATE_SFTP_KNOWN_HOSTS", hosts)
	cfg, err := sftpConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval != 10*time.Second || cfg.Timeout != 4*time.Hour || cfg.remoteDir() != "/inbox" {
		t.Fatalf("unexpected SFTP defaults: poll=%s timeout=%s path=%s", cfg.PollInterval, cfg.Timeout, cfg.remoteDir())
	}
	for _, name := range []string{"ARTIGATE_SFTP_POLL_INTERVAL", "ARTIGATE_SFTP_TIMEOUT"} {
		for _, value := range []string{"0", "-1s", "invalid"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				t.Setenv(name, value)
				if _, err := sftpConfigFromEnv(); err == nil {
					t.Fatal("SFTP accepted an invalid duration")
				}
			})
		}
	}
	t.Setenv("ARTIGATE_SFTP_PASSWORD", "")
	if _, err := sftpConfigFromEnv(); err == nil {
		t.Fatal("SFTP accepted missing authentication")
	}
}

func TestSFTPTransportConflicts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		cfg     *SFTPConfig
		httpURL string
		udp     bool
		fail    bool
	}{
		{name: "folder"},
		{name: "SFTP only", cfg: &SFTPConfig{}},
		{name: "existing HTTP", httpURL: "https://example.test/diode"},
		{name: "existing UDP", udp: true},
		{name: "HTTP conflict", cfg: &SFTPConfig{}, httpURL: "https://example.test/diode", fail: true},
		{name: "UDP conflict", cfg: &SFTPConfig{}, udp: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateLowSFTPTransport(tc.cfg, tc.httpURL, tc.udp); (err != nil) != tc.fail {
				t.Fatalf("transport validation error = %v, want failure %v", err, tc.fail)
			}
		})
	}
}
