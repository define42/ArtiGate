package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const rpmTLSProfileName = "rhel-entitlement-test"

type rpmTLSFixture struct {
	server     *httptest.Server
	ca         *x509.Certificate
	caKey      ed25519.PrivateKey
	configPath string
	certPath   string
	keyPath    string
	caPath     string
	rpmBody    string
	mu         sync.Mutex
	requests   map[int64]map[string]int
	status     int
}

func newRpmTLSFixture(t *testing.T) *rpmTLSFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RPM entitlement test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := &rpmTLSFixture{
		ca: ca, caKey: key, configPath: filepath.Join(dir, "upstream-tls.json"),
		certPath: filepath.Join(dir, "entitlement.pem"), keyPath: filepath.Join(dir, "entitlement-key.pem"),
		caPath: filepath.Join(dir, "redhat-uep.pem"), requests: make(map[int64]map[string]int),
	}
	mux := http.NewServeMux()
	f.rpmBody = registerRpmRepo(t, mux, "/rhel/baseos", "rhel-fixture", "1.0", "1", false)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		serial := r.TLS.PeerCertificates[0].SerialNumber.Int64()
		f.mu.Lock()
		if f.requests[serial] == nil {
			f.requests[serial] = make(map[string]int)
		}
		f.requests[serial][r.URL.Path]++
		status := f.status
		f.mu.Unlock()
		if status != 0 {
			http.Error(w, "repository access denied", status)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	f.server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	writeFile(t, f.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}))
	f.rotateCertificate(t, 101)
	f.writeConfig(t, []string{f.server.URL})
	t.Setenv("ARTIGATE_UPSTREAM_TLS_CONFIG", f.configPath)
	return f
}

func (f *rpmTLSFixture) rotateCertificate(t *testing.T, serial int64) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "lowside entitlement"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, f.ca, pub, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		f.certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		f.keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *rpmTLSFixture) writeConfig(t *testing.T, origins []string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		rpmTLSProfileName: map[string]any{
			"cert_file": f.certPath, "key_file": f.keyPath, "ca_file": f.caPath,
			"allowed_origins": origins,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *rpmTLSFixture) collectRequest() RpmCollectRequest {
	return RpmCollectRequest{
		Name: "baseos", BaseURL: f.server.URL + "/rhel/baseos", TLSProfile: rpmTLSProfileName, Force: true,
	}
}

func (f *rpmTLSFixture) assertRequests(t *testing.T, serial int64) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, path := range []string{
		"/rhel/baseos/repodata/repomd.xml",
		"/rhel/baseos/repodata/primary.xml.gz",
		"/rhel/baseos/repodata/filelists.xml.gz",
		"/rhel/baseos/repodata/updateinfo.xml.gz",
		"/rhel/baseos/Packages/rhel-fixture-1.0-1.x86_64.rpm",
	} {
		if got := f.requests[serial][path]; got != 1 {
			t.Errorf("certificate %d requested %s %d times, want 1", serial, path, got)
		}
	}
}

func (f *rpmTLSFixture) assertNoCredentials(t *testing.T, label string, body []byte, includeProfile bool) {
	t.Helper()
	for _, forbidden := range []string{
		f.configPath, f.certPath, f.keyPath, f.caPath, "BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "lowside entitlement",
	} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Errorf("%s contains TLS credential material or a local credential path", label)
		}
	}
	if includeProfile && bytes.Contains(body, []byte(rpmTLSProfileName)) {
		t.Errorf("%s contains the lowside TLS profile name", label)
	}
}

func (f *rpmTLSFixture) assertBundleNoCredentials(t *testing.T, low *LowServer, id string) {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join(low.cfg.ExportDir, id+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.assertNoCredentials(t, "manifest", manifest, true)
	archive, err := os.Open(filepath.Join(low.cfg.ExportDir, id+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		f.assertNoCredentials(t, "archive entry name", []byte(hdr.Name), true)
		f.assertNoCredentials(t, hdr.Name, body, true)
	}
}

func TestCollectRpmTLSProfileMirrorsProtectedRepository(t *testing.T) {
	f := newRpmTLSFixture(t)
	// This client trusts the test server but has no entitlement certificate.
	if resp, err := f.server.Client().Get(f.server.URL + "/rhel/baseos/repodata/repomd.xml"); err == nil {
		resp.Body.Close()
		t.Fatal("upstream accepted a client without an entitlement certificate")
	}
	low, priv := newRpmLowServer(t)
	res, err := low.CollectRpm(t.Context(), f.collectRequest())
	if err != nil {
		t.Fatalf("collect protected repository: %v", err)
	}
	if res.BundleID != "rpm-bundle-000001" || res.ExportedModules != 1 {
		t.Fatalf("unexpected export: %+v", res)
	}
	f.assertRequests(t, 101)
	f.assertBundleNoCredentials(t, low, res.BundleID)
	pub := priv.Public().(ed25519.PublicKey)
	assertBundleSigned(t, low.cfg.ExportDir, res.BundleID, pub)
	high := newTestHighServer(t, pub)
	transferAptBundle(t, low, high, res.BundleID)
	if imported, err := high.ImportNext(); err != nil || !imported.Imported {
		t.Fatalf("import entitled RPM repository: %+v, %v", imported, err)
	}
	server := httptest.NewServer(high)
	t.Cleanup(server.Close)
	assertServed(t, server.URL+"/rpm/baseos/Packages/rhel-fixture-1.0-1.x86_64.rpm", f.rpmBody)
	for _, path := range []string{"primary.xml.gz", "filelists.xml.gz", "updateinfo.xml.gz"} {
		assertServed(t, server.URL+"/rpm/baseos/repodata/"+path, "")
	}
}

func TestCollectRpmTLSProfileReloadsCredentials(t *testing.T) {
	f := newRpmTLSFixture(t)
	low, _ := newRpmLowServer(t)
	for _, serial := range []int64{101, 102, 103} {
		if serial == 103 {
			// subscription-manager may replace the certificate filename as well
			// as the pair's contents; the profile map must be reread too.
			f.certPath = filepath.Join(filepath.Dir(f.certPath), "renewed-entitlement.pem")
			f.keyPath = filepath.Join(filepath.Dir(f.keyPath), "renewed-entitlement-key.pem")
		}
		if serial != 101 {
			f.rotateCertificate(t, serial)
			f.writeConfig(t, []string{f.server.URL})
		}
		res, err := low.CollectRpm(t.Context(), f.collectRequest())
		if err != nil {
			t.Fatalf("collect using certificate %d: %v", serial, err)
		}
		if res.Sequence != serial-100 {
			t.Errorf("collect using certificate %d has sequence %d", serial, res.Sequence)
		}
		f.assertRequests(t, serial)
		f.assertBundleNoCredentials(t, low, res.BundleID)
	}
}

func TestWatchRpmTLSProfileReloadsCredentials(t *testing.T) {
	f := newRpmTLSFixture(t)
	low, _ := newRpmLowServer(t)
	spec, err := json.Marshal(f.collectRequest())
	if err != nil {
		t.Fatal(err)
	}
	watch := Watch{Stream: streamRpm, Label: "RHEL BaseOS", Spec: string(spec), IntervalSeconds: 3600, Enabled: true}
	if err := validateWatch(watch); err != nil {
		t.Fatalf("TLS profile reference rejected in watch: %v", err)
	}
	watch, err = low.watches.Create(watch)
	if err != nil {
		t.Fatal(err)
	}
	for _, serial := range []int64{101, 102} {
		if serial == 102 {
			f.rotateCertificate(t, serial)
		}
		id, err := low.enqueueWatch(watch)
		if err != nil {
			t.Fatal(err)
		}
		job := low.jobs.get(id)
		waitJobDone(t, job)
		// Completion hooks persist the outcome after the job becomes done.
		low.jobs.wg.Wait()
		info := job.snapshotInfo(0)
		if info.State != string(jobOK) {
			t.Fatalf("scheduled TLS collect failed: %+v", info)
		}
		stored, err := low.watches.Get(watch.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.LastStatus != "ok" || stored.Spec != string(spec) {
			t.Fatalf("watch changed its spec or failed: %+v", stored)
		}
		persisted, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		f.assertNoCredentials(t, "persisted watch", persisted, false)
		if !strings.Contains(stored.Spec, `"tls_profile":"`+rpmTLSProfileName+`"`) {
			t.Error("persisted watch lost its profile reference")
		}
		f.assertRequests(t, serial)
		f.assertBundleNoCredentials(t, low, info.BundleID)
	}
}

func TestCollectRpmTLSProfileAccessDeniedGuidance(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newRpmTLSFixture(t)
			f.mu.Lock()
			f.status = status
			f.mu.Unlock()
			low, _ := newRpmLowServer(t)
			_, err := low.CollectRpm(t.Context(), f.collectRequest())
			if err == nil {
				t.Fatal("collect succeeded despite entitlement access rejection")
			}
			for _, want := range []string{rpmTLSProfileName, "certificate renewal", "repository access"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("access error %q lacks %q guidance", err, want)
				}
			}
			if strings.Contains(err.Error(), upstreamAuthEnv) {
				t.Errorf("entitlement rejection incorrectly suggests a Basic login: %v", err)
			}
			f.assertNoCredentials(t, "access error", []byte(err.Error()), false)
			if next := low.peekSequence(streamRpm); next != 1 {
				t.Errorf("denied collect consumed sequence: next = %d", next)
			}
		})
	}
}

func TestCollectRpmTLSProfileRejectsBeforeExport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *rpmTLSFixture, *RpmCollectRequest)
	}{
		{name: "unknown profile", change: func(_ *testing.T, _ *rpmTLSFixture, req *RpmCollectRequest) {
			req.TLSProfile = "missing-profile"
		}},
		{name: "different origin", change: func(t *testing.T, f *rpmTLSFixture, _ *RpmCollectRequest) {
			f.writeConfig(t, []string{"https://different-origin.example"})
		}},
		{name: "unencrypted base URL", change: func(_ *testing.T, _ *rpmTLSFixture, req *RpmCollectRequest) {
			req.BaseURL = strings.Replace(req.BaseURL, "https://", "http://", 1)
		}},
		{name: "missing certificate", change: func(t *testing.T, f *rpmTLSFixture, _ *RpmCollectRequest) {
			if err := os.Remove(f.certPath); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRpmTLSFixture(t)
			low, _ := newRpmLowServer(t)
			req := f.collectRequest()
			tc.change(t, f, &req)
			if _, err := low.CollectRpm(t.Context(), req); err == nil {
				t.Fatal("collect accepted an invalid TLS profile or target")
			}
			if next := low.peekSequence(streamRpm); next != 1 {
				t.Errorf("failed TLS collect consumed sequence: next = %d", next)
			}
			files, err := os.ReadDir(low.cfg.ExportDir)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if len(files) != 0 {
				t.Errorf("failed TLS collect exported artifacts: %v", files)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 0 {
				t.Errorf("invalid TLS profile contacted upstream: %v", f.requests)
			}
		})
	}
}
