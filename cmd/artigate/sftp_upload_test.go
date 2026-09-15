//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type sftpTestOperation struct{ method, name, target string }

type sftpTestFS struct {
	handlers sftp.Handlers
	mu       sync.Mutex
	ops      []sftpTestOperation
	deny     string
}

func (fs *sftpTestFS) record(r *sftp.Request) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.ops = append(fs.ops, sftpTestOperation{r.Method, r.Filepath, r.Target})
	return fs.deny != "" && (strings.HasSuffix(r.Target, fs.deny) || (r.Method == "Get" && strings.HasSuffix(r.Filepath, fs.deny)))
}

func (fs *sftpTestFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if fs.record(r) {
		return nil, os.ErrPermission
	}
	return fs.handlers.FileGet.Fileread(r)
}

func (fs *sftpTestFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	fs.record(r)
	return fs.handlers.FilePut.Filewrite(r)
}

func (fs *sftpTestFS) Filecmd(r *sftp.Request) error {
	if fs.record(r) {
		return os.ErrPermission
	}
	return fs.handlers.FileCmd.Filecmd(r)
}

func (fs *sftpTestFS) PosixRename(r *sftp.Request) error {
	if fs.record(r) {
		return os.ErrPermission
	}
	return fs.handlers.FileCmd.(sftp.PosixRenameFileCmder).PosixRename(r)
}

func (fs *sftpTestFS) operations() []sftpTestOperation {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]sftpTestOperation(nil), fs.ops...)
}

func (fs *sftpTestFS) resetOperations(deny string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.ops = nil
	fs.deny = deny
}

type sftpTestFixture struct {
	cfg      SFTPConfig
	fs       *sftpTestFS
	listener net.Listener
	ssh      *ssh.ServerConfig
	wg       sync.WaitGroup
}

func newSFTPFixture(t *testing.T) *sftpTestFixture {
	t.Helper()
	_, hostKey := newTestKeys(t)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey := newTestKeys(t)
	clientSigner, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(clientKey, "SFTP integration fixture")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	knownPath := filepath.Join(dir, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownPath, []byte(line), 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	fx := &sftpTestFixture{
		cfg: SFTPConfig{
			URL:            "sftp://transfer@" + listener.Addr().String() + "/inbox",
			PrivateKeyPath: keyPath, KnownHostsPath: knownPath,
			PollInterval: 10 * time.Millisecond, Timeout: 5 * time.Second,
		},
		listener: listener,
		fs:       &sftpTestFS{handlers: sftp.InMemHandler()},
		ssh: &ssh.ServerConfig{
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if conn.User() == "transfer" && bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
					return nil, nil
				}
				return nil, errors.New("unknown SSH identity")
			},
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if conn.User() == "transfer" && string(password) == "fixture-password" {
					return nil, nil
				}
				return nil, errors.New("incorrect SSH password")
			},
		},
	}
	fx.ssh.AddHostKey(hostSigner)
	ctx, cancel := context.WithCancel(t.Context())
	fx.wg.Add(1)
	go fx.serve(ctx)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		fx.wg.Wait()
	})
	client := fx.client(t)
	if err := client.Mkdir("/inbox"); err != nil {
		t.Fatal(err)
	}
	fx.fs.resetOperations("")
	return fx
}

func (fx *sftpTestFixture) serve(ctx context.Context) {
	defer fx.wg.Done()
	for {
		conn, err := fx.listener.Accept()
		if err != nil {
			return
		}
		fx.wg.Add(1)
		go fx.serveConnection(ctx, conn)
	}
}

func (fx *sftpTestFixture) serveConnection(ctx context.Context, conn net.Conn) {
	defer fx.wg.Done()
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	server, channels, requests, err := ssh.NewServerConn(conn, fx.ssh)
	if err != nil {
		return
	}
	defer server.Close()
	fx.wg.Add(1)
	go func() {
		defer fx.wg.Done()
		ssh.DiscardRequests(requests)
	}()
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "only SFTP sessions supported")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		fx.wg.Add(1)
		go fx.serveSession(channel, requests)
	}
}

func (fx *sftpTestFixture) serveSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer fx.wg.Done()
	defer channel.Close()
	for request := range requests {
		var subsystem struct{ Name string }
		ok := request.Type == "subsystem" && ssh.Unmarshal(request.Payload, &subsystem) == nil && subsystem.Name == "sftp"
		_ = request.Reply(ok, nil)
		if ok {
			server := sftp.NewRequestServer(channel, sftp.Handlers{
				FileGet: fx.fs, FilePut: fx.fs, FileCmd: fx.fs, FileList: fx.fs.handlers.FileList,
			})
			_ = server.Serve()
			_ = server.Close()
			return
		}
	}
}

func (fx *sftpTestFixture) client(t *testing.T) *sftp.Client {
	t.Helper()
	client, closeClient, err := dialSFTP(t.Context(), &fx.cfg)
	if err != nil {
		t.Fatalf("connect fixture: %v", err)
	}
	t.Cleanup(closeClient)
	return client
}

func (fx *sftpTestFixture) read(t *testing.T, name string) []byte {
	t.Helper()
	f, err := fx.client(t).Open(path.Join("/inbox", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (fx *sftpTestFixture) write(t *testing.T, name string, body []byte) {
	t.Helper()
	f, err := fx.client(t).Create(path.Join("/inbox", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSFTPDialAuthentication(t *testing.T) {
	fx := newSFTPFixture(t)
	for _, tc := range []struct {
		name     string
		password string
		key      bool
		fail     bool
	}{
		{name: "private key", key: true},
		{name: "password", password: "fixture-password"},
		{name: "wrong password", password: "wrong", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fx.cfg
			if !tc.key {
				cfg.PrivateKeyPath = ""
				cfg.Password = tc.password
			}
			_, closeClient, err := dialSFTP(t.Context(), &cfg)
			if closeClient != nil {
				defer closeClient()
			}
			if (err != nil) != tc.fail {
				t.Fatalf("SSH authentication = %v, want failure %v", err, tc.fail)
			}
		})
	}
	other := newSFTPFixture(t)
	cfg := fx.cfg
	cfg.KnownHostsPath = other.cfg.KnownHostsPath
	if _, closeClient, err := dialSFTP(t.Context(), &cfg); err == nil {
		closeClient()
		t.Fatal("connected to a host absent from known_hosts")
	}
}

func TestSFTPDialTimeoutAndCancellation(t *testing.T) {
	fx := newSFTPFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
		close(accepted)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		for conn := range accepted {
			_ = conn.Close()
		}
	})
	cfg := fx.cfg
	cfg.URL = "sftp://transfer@" + listener.Addr().String() + "/inbox"
	cfg.Timeout = 100 * time.Millisecond
	started := time.Now()
	if _, closeClient, err := dialSFTP(t.Context(), &cfg); err == nil {
		closeClient()
		t.Fatal("SSH handshake without a server response succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("SSH timeout took %s, want within two seconds", elapsed)
	}
	ctx, cancel := context.WithCancel(t.Context())
	client, closeClient, err := dialSFTP(ctx, &fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	cancel()
	failed := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := client.Stat("/inbox"); err != nil {
				failed <- err
				return
			}
		}
		failed <- nil
	}()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("cancelled connection still accepted requests")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not close the SFTP connection")
	}
}

func TestSFTPUploadPublishesWritingFilesAndReexports(t *testing.T) {
	fx := newSFTPFixture(t)
	ls := newBareLowServer(t)
	ls.cfg.SFTP = &fx.cfg
	res := collectUpload(t, ls, "tools", []uploadPair{{"tool.txt", "SFTP content"}})
	if res.DiodeError != "" {
		t.Fatalf("SFTP upload: %s", res.DiodeError)
	}
	var renamed []string
	for _, op := range fx.fs.operations() {
		switch op.method {
		case "Put", "Open":
			if !strings.HasSuffix(op.name, ".writing") {
				t.Errorf("upload wrote directly to ready filename %s", op.name)
			}
		case "Rename", "PosixRename":
			if op.name != op.target+".writing" {
				t.Errorf("publication rename = %s -> %s", op.name, op.target)
			}
			renamed = append(renamed, path.Base(op.target))
		}
	}
	want := make([]string, 0, 3)
	for _, suffix := range bundleSuffixes() {
		name := res.BundleID + suffix
		want = append(want, name)
		archive, err := os.ReadFile(filepath.Join(ls.bundleArchiveDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fx.read(t, name); !bytes.Equal(got, archive) {
			t.Errorf("remote %s differs from archived bundle", name)
		}
		if fileExists(filepath.Join(ls.cfg.ExportDir, name)) {
			t.Errorf("successful upload retained %s in the export spool", name)
		}
	}
	if !reflect.DeepEqual(renamed, want) {
		t.Fatalf("ready publication order = %v, want %v", renamed, want)
	}
	replayed, err := ls.ExportSequence(streamUploads, res.Sequence)
	if err != nil || replayed.DiodeError != "" {
		t.Fatalf("SFTP retransmit = %+v, %v", replayed, err)
	}
	entries, err := fx.client(t).ReadDir("/inbox")
	if err != nil || len(entries) != 3 {
		t.Fatalf("remote files after replay = %v, %v; want exactly three ready files", entries, err)
	}
}

func TestSFTPUploadFailureRetainsBundle(t *testing.T) {
	fx := newSFTPFixture(t)
	fx.fs.resetOperations(".manifest.json.sig")
	ls := newBareLowServer(t)
	ls.cfg.SFTP = &fx.cfg
	res := collectUpload(t, ls, "tools", []uploadPair{{"tool.txt", "retry me"}})
	if res.DiodeError == "" {
		t.Fatal("signature publication failure was not reported")
	}
	for _, suffix := range bundleSuffixes() {
		if !fileExists(filepath.Join(ls.cfg.ExportDir, res.BundleID+suffix)) {
			t.Errorf("failed upload lost staged %s", suffix)
		}
	}
	if _, err := fx.client(t).Stat(path.Join("/inbox", res.BundleID+".manifest.json.sig")); !os.IsNotExist(err) {
		t.Fatalf("failed signature was published: %v", err)
	}
	fx.fs.resetOperations("")
	replayed, err := ls.ExportSequence(streamUploads, res.Sequence)
	if err != nil || replayed.DiodeError != "" {
		t.Fatalf("retry after permission recovery = %+v, %v", replayed, err)
	}
}
