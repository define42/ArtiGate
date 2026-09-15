package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SFTPConfig configures the low-side uploader or high-side remote inbox.
type SFTPConfig struct {
	URL            string
	PrivateKeyPath string
	Password       string
	KnownHostsPath string
	PollInterval   time.Duration
	Timeout        time.Duration
}

func mustSFTPConfig() *SFTPConfig {
	cfg, err := sftpConfigFromEnv()
	must(err)
	return cfg
}

func sftpConfigFromEnv() (*SFTPConfig, error) {
	cfg := &SFTPConfig{
		URL:            os.Getenv("ARTIGATE_SFTP_URL"),
		PrivateKeyPath: os.Getenv("ARTIGATE_SFTP_PRIVATE_KEY"),
		Password:       os.Getenv("ARTIGATE_SFTP_PASSWORD"),
		KnownHostsPath: os.Getenv("ARTIGATE_SFTP_KNOWN_HOSTS"),
	}
	if cfg.URL == "" {
		return nil, nil
	}
	u, err := parseSFTPURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	cfg.PollInterval, err = sftpEnvDuration("ARTIGATE_SFTP_POLL_INTERVAL", 10*time.Second)
	if err != nil {
		return nil, err
	}
	cfg.Timeout, err = sftpEnvDuration("ARTIGATE_SFTP_TIMEOUT", 4*time.Hour)
	if err != nil {
		return nil, err
	}
	if _, err := cfg.sshConfig(u.User.Username()); err != nil {
		return nil, err
	}
	return cfg, nil
}

func sftpEnvDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return duration, nil
}

func parseSFTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("ARTIGATE_SFTP_URL must be a valid sftp://user@host/absolute/directory URL")
	}
	if u.Scheme != "sftp" || u.Hostname() == "" || u.User == nil || u.User.Username() == "" {
		return nil, errors.New("ARTIGATE_SFTP_URL requires the sftp scheme, username, and host")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return nil, errors.New("ARTIGATE_SFTP_URL must not contain a password; use ARTIGATE_SFTP_PASSWORD")
	}
	if u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, errors.New("ARTIGATE_SFTP_URL must not contain a query or fragment")
	}
	if !path.IsAbs(u.Path) || strings.ContainsAny(u.Path, "\\\x00") {
		return nil, errors.New("ARTIGATE_SFTP_URL requires an absolute remote directory")
	}
	if err := validateSFTPPort(u); err != nil {
		return nil, err
	}
	return u, nil
}

func validateSFTPPort(u *url.URL) error {
	if u.Port() == "" && !strings.HasSuffix(u.Host, ":") {
		return nil
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("ARTIGATE_SFTP_URL port must be between 1 and 65535")
	}
	return nil
}

func (cfg *SFTPConfig) remoteDir() string {
	u, err := parseSFTPURL(cfg.URL)
	if err != nil {
		return ""
	}
	return path.Clean(u.Path)
}

func (cfg *SFTPConfig) sshConfig(username string) (*ssh.ClientConfig, error) {
	if cfg.KnownHostsPath == "" {
		return nil, errors.New("ARTIGATE_SFTP_KNOWN_HOSTS is required for SFTP host verification")
	}
	verifyHost, err := knownhosts.New(cfg.KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load SFTP known hosts: %w", err)
	}
	auth, err := cfg.sshAuth()
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{User: username, Auth: auth, HostKeyCallback: verifyHost}, nil
}

func (cfg *SFTPConfig) sshAuth() ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if cfg.PrivateKeyPath != "" {
		key, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read SFTP private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SFTP private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		auth = append(auth, ssh.Password(cfg.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("SFTP requires ARTIGATE_SFTP_PRIVATE_KEY or ARTIGATE_SFTP_PASSWORD")
	}
	return auth, nil
}

func validateLowSFTPTransport(cfg *SFTPConfig, diodeURL string, pitcherEnabled bool) error {
	if cfg != nil && (diodeURL != "" || pitcherEnabled) {
		return errors.New("ARTIGATE_SFTP_URL cannot be combined with an HTTP diode endpoint or UDP pitcher")
	}
	return nil
}

// dialSFTP bounds the TCP connection, SSH handshake, and every subsequent SFTP
// operation with the same context. Closing the raw connection also interrupts
// blocked protocol operations that do not accept a context themselves.
func dialSFTP(ctx context.Context, cfg *SFTPConfig) (*sftp.Client, func(), error) {
	u, err := parseSFTPURL(cfg.URL)
	if err != nil {
		return nil, nil, err
	}
	sshCfg, err := cfg.sshConfig(u.User.Username())
	if err != nil {
		return nil, nil, err
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 4 * time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	port := u.Port()
	if port == "" {
		port = "22"
	}
	address := net.JoinHostPort(u.Hostname(), port)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect SFTP: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	closeConn := func() {
		stop()
		cancel()
		_ = conn.Close()
	}
	client, err := sftpClientOnConn(conn, address, sshCfg)
	if err != nil {
		closeConn()
		return nil, nil, err
	}
	return client, func() {
		closeConn()
		_ = client.Close()
	}, nil
}

func sftpClientOnConn(conn net.Conn, address string, cfg *ssh.ClientConfig) (*sftp.Client, error) {
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, cfg)
	if err != nil {
		return nil, fmt.Errorf("SFTP SSH handshake: %w", err)
	}
	sshClient := ssh.NewClient(sshConn, channels, requests)
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		return nil, fmt.Errorf("open SFTP session: %w", err)
	}
	return client, nil
}
