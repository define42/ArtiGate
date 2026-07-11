package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidBundleFileName(t *testing.T) {
	valid := []string{
		"hf-bundle-000001.tar.gz",
		"go-bundle-000042.manifest.json",
		"containers-bundle-123456.manifest.json.sig",
		"apt-bundle-1234567.tar.gz", // numbering grows past six digits
	}
	for _, name := range valid {
		if !validBundleFileName(name) {
			t.Errorf("validBundleFileName(%q) = false, want true", name)
		}
	}
	invalid := []string{
		"",
		"hf-bundle-000001",           // no suffix
		"hf-bundle-000001.tar",       // wrong suffix
		"../hf-bundle-000001.tar.gz", // traversal
		"HF-bundle-000001.tar.gz",    // uppercase stream
		"hf-bundle-1.tar.gz",         // too few digits
		"exported.db",                // arbitrary file
		"hf-bundle-000001.manifest.json.sig.tar.gz",
	}
	for _, name := range invalid {
		if validBundleFileName(name) {
			t.Errorf("validBundleFileName(%q) = true, want false", name)
		}
	}
}

func TestParseOnOff(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "off": false, "No": false, "1": true, "true": true, "ON": true, "yes": true} {
		got, err := parseOnOff(v)
		if err != nil || got != want {
			t.Errorf("parseOnOff(%q) = %v, %v; want %v", v, got, err, want)
		}
	}
	if _, err := parseOnOff("maybe"); err == nil {
		t.Error("parseOnOff(\"maybe\") should be rejected")
	}
}

// TestHighDiodeIngest checks the upload endpoint: gating, token, name
// validation, and that stored files land byte-exact in the landing directory.
func TestHighDiodeIngest(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	hs.cfg.DiodeIngest = true
	hs.cfg.DiodeToken = "diode-secret"
	srv := httptest.NewServer(hs)
	defer srv.Close()

	put := func(name, token, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/diode/"+name, strings.NewReader(body)) //nolint:noctx // test request
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	if resp := put("hf-bundle-000001.tar.gz", "wrong", "x"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", resp.StatusCode)
	}
	if resp := put("exported.db", "diode-secret", "x"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad name = %d, want 400", resp.StatusCode)
	}
	if resp := put("../evil.tar.gz", "diode-secret", "x"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal name = %d, want 400", resp.StatusCode)
	}
	getResp, err := http.Get(srv.URL + "/diode/hf-bundle-000001.tar.gz") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusUnauthorized && getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 401 or 405", getResp.StatusCode)
	}

	content := strings.Repeat("bundle-bytes", 1000)
	if resp := put("hf-bundle-000001.tar.gz", "diode-secret", content); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d, want 200", resp.StatusCode)
	}
	got, err := os.ReadFile(filepath.Join(hs.cfg.Landing, "hf-bundle-000001.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(content)) {
		t.Fatal("stored file does not match the uploaded bytes")
	}

	// A declared oversized body is rejected before anything reaches disk.
	req, err := http.NewRequest(http.MethodPut, "/diode/hf-bundle-000002.tar.gz", strings.NewReader("x")) //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+hs.cfg.DiodeToken)
	req.ContentLength = diodeMaxUploadBytes + 1
	rec := httptest.NewRecorder()
	hs.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload = %d, want 413", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(hs.cfg.Landing, "hf-bundle-000002.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("oversized upload reached landing directory: %v", err)
	}

	// Disabled ingest refuses uploads outright.
	hs2 := newTestHighServer(t, pub)
	srv2 := httptest.NewServer(hs2)
	defer srv2.Close()
	req, _ = http.NewRequest(http.MethodPut, srv2.URL+"/diode/hf-bundle-000001.tar.gz", strings.NewReader("x")) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled ingest = %d, want 403", resp.StatusCode)
	}
}

func TestWriteStreamAtomicLimitRejectsOversizedBody(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "hf-bundle-000001.tar.gz")
	const original = "existing bundle"
	if err := os.WriteFile(dst, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := writeStreamAtomicLimit(dst, strings.NewReader("123456789"), 8)
	var maxBytesErr *http.MaxBytesError
	if !errors.As(err, &maxBytesErr) {
		t.Fatalf("writeStreamAtomicLimit error = %v, want MaxBytesError", err)
	}
	if n != 9 {
		t.Fatalf("writeStreamAtomicLimit wrote %d bytes, want 9", n)
	}
	if maxBytesErr.Limit != 8 {
		t.Fatalf("MaxBytesError limit = %d, want 8", maxBytesErr.Limit)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("oversized upload replaced destination with %q", got)
	}
	temps, err := filepath.Glob(dst + ".upload-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("oversized upload left temporary files: %v", temps)
	}

	exactDst := filepath.Join(dir, "hf-bundle-000002.tar.gz")
	n, err = writeStreamAtomicLimit(exactDst, strings.NewReader("12345678"), 8)
	if err != nil {
		t.Fatalf("exact-limit upload: %v", err)
	}
	if n != 8 {
		t.Fatalf("exact-limit upload wrote %d bytes, want 8", n)
	}
	got, err = os.ReadFile(exactDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "12345678" {
		t.Fatalf("exact-limit upload stored %q", got)
	}
}

// diodeReceiver captures uploads like a diode proxy would.
type diodeReceiver struct {
	mu     sync.Mutex
	files  map[string][]byte
	auth   map[string]string
	status int // 0 = accept
}

func (d *diodeReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status != 0 {
		http.Error(w, "receiver unavailable", d.status)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(r.Body)
	if d.files == nil {
		d.files = map[string][]byte{}
		d.auth = map[string]string{}
	}
	d.files[name] = body.Bytes()
	d.auth[name] = r.Header.Get("Authorization")
	w.WriteHeader(http.StatusOK)
}

func (d *diodeReceiver) file(name string) ([]byte, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.files[name], d.auth[name]
}

// TestLowPushesBundleToDiode checks the happy path: after a collect, all
// three bundle files are uploaded (with the token), the outbound spool is
// cleared, and the archive copy is retained for re-transmits — which also go
// out over HTTP.
func TestLowPushesBundleToDiode(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-diode")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")
	receiver := &diodeReceiver{}
	diode := httptest.NewServer(receiver)
	t.Cleanup(diode.Close)

	ls, _ := newHFLowServer(t, hub.URL)
	ls.cfg.DiodeURL = diode.URL
	ls.cfg.DiodeToken = "diode-secret"

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"unsloth/gpt-oss-20b-GGUF:Q4_0"}})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.DiodeError != "" {
		t.Fatalf("diode error: %s", res.DiodeError)
	}
	if res.Message != "uploaded to diode endpoint" {
		t.Errorf("message = %q", res.Message)
	}

	for _, suffix := range bundleSuffixes() {
		name := res.BundleID + suffix
		body, auth := receiver.file(name)
		if len(body) == 0 {
			t.Fatalf("receiver did not get %s", name)
		}
		if auth != "Bearer diode-secret" {
			t.Errorf("%s auth = %q", name, auth)
		}
		archived, err := os.ReadFile(filepath.Join(ls.bundleArchiveDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, archived) {
			t.Errorf("%s uploaded bytes differ from the archive", name)
		}
		if fileExists(filepath.Join(ls.cfg.ExportDir, name)) {
			t.Errorf("%s still staged after a successful upload", name)
		}
	}

	// A re-transmit replays the archive over the same transport and clears
	// the spool again.
	reres, err := ls.ExportSequence(streamHF, res.Sequence)
	if err != nil {
		t.Fatalf("ExportSequence: %v", err)
	}
	if reres.DiodeError != "" {
		t.Fatalf("re-export diode error: %s", reres.DiodeError)
	}
	if fileExists(filepath.Join(ls.cfg.ExportDir, res.BundleID+".tar.gz")) {
		t.Error("re-exported bundle still staged after upload")
	}
}

// TestLowPushFailureKeepsBundleStaged checks the failure path: the collect
// still succeeds, the failure is reported on the result, and the bundle stays
// in the export dir for a re-transmit.
func TestLowPushFailureKeepsBundleStaged(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-diode-down")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")
	receiver := &diodeReceiver{status: http.StatusBadGateway}
	diode := httptest.NewServer(receiver)
	t.Cleanup(diode.Close)

	ls, _ := newHFLowServer(t, hub.URL)
	ls.cfg.DiodeURL = diode.URL

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"unsloth/gpt-oss-20b-GGUF:Q4_0"}})
	if err != nil {
		t.Fatalf("CollectHF must not fail on a diode outage: %v", err)
	}
	if res.DiodeError == "" || !strings.Contains(res.DiodeError, "502") {
		t.Fatalf("DiodeError = %q, want an HTTP 502 report", res.DiodeError)
	}
	for _, suffix := range bundleSuffixes() {
		if !fileExists(filepath.Join(ls.cfg.ExportDir, res.BundleID+suffix)) {
			t.Errorf("%s missing from the export dir after a failed upload", res.BundleID+suffix)
		}
	}
	if watchRunMessage(res) == "" || !strings.Contains(watchRunMessage(res), "diode upload failed") {
		t.Errorf("watch message should surface the failure: %q", watchRunMessage(res))
	}
}

// TestLowToHighOverHTTPDiode runs the whole loop over HTTP: the low side
// collects and uploads straight to the high side's ingest endpoint, the high
// side imports (signature, sequence, hashes — trust is unchanged by the
// transport), and the model serves.
func TestLowToHighOverHTTPDiode(t *testing.T) {
	model := makeFakeHFModel("Q4_0", "gguf-over-http")
	hub := fakeHFHub(t, map[string]fakeHFModel{"unsloth/gpt-oss-20b-GGUF:Q4_0": model}, nil, "")

	ls, priv := newHFLowServer(t, hub.URL)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	hs.cfg.DiodeIngest = true
	hs.cfg.DiodeToken = "shared-secret"
	high := httptest.NewServer(hs)
	t.Cleanup(high.Close)

	ls.cfg.DiodeURL = high.URL + "/diode"
	ls.cfg.DiodeToken = "shared-secret"

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"unsloth/gpt-oss-20b-GGUF:Q4_0"}})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	if res.DiodeError != "" {
		t.Fatalf("upload to high side failed: %s", res.DiodeError)
	}

	// The ingest endpoint kicks an import on bundle completion; wait for it,
	// then fall back to an explicit run (the kick and this call serialize).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := hs.ImportNext(); err != nil {
			t.Fatalf("ImportNext: %v", err)
		}
		st, err := hs.ImportStatus()
		if err != nil {
			t.Fatal(err)
		}
		if st.Stream(streamHF).LastImportedSequence >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	st, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.Stream(streamHF).LastImportedSequence != 1 {
		t.Fatalf("hf stream not imported over HTTP: %+v", st.Stream(streamHF))
	}
	assertHTTPBody(t, high.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0", string(model.manifest))
}
