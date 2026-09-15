//go:build integration

package main

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSFTPLowToHighSignedBundleAndHeartbeat(t *testing.T) {
	fx := newSFTPFixture(t)
	ls := newBareLowServer(t)
	ls.cfg.SFTP = &fx.cfg
	hs := newTestHighServer(t, ls.privateKey.Public().(ed25519.PublicKey))
	hs.cfg.SFTP = &fx.cfg
	res := collectUpload(t, ls, "tools", []uploadPair{{"readme.txt", "verified SFTP data"}})
	if res.DiodeError != "" {
		t.Fatalf("collect upload: %s", res.DiodeError)
	}
	for _, when := range []time.Time{time.Now().UTC().Add(-time.Second), time.Now().UTC()} {
		if err := ls.sendDiodeHeartbeat(t.Context(), when); err != nil {
			t.Fatalf("send SFTP heartbeat: %v", err)
		}
	}
	fx.fs.resetOperations("")
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatalf("poll SFTP: %v", err)
	}
	status, err := hs.ImportStatus()
	if err != nil {
		t.Fatal(err)
	}
	if got := status.Stream(streamUploads); got.LastImportedSequence != res.Sequence || got.LowLastSequence != res.Sequence {
		t.Fatalf("imported stream and signed heartbeat = %+v", got)
	}
	if status.DiodeHeartbeat == nil {
		t.Fatal("signed heartbeat was not imported")
	}
	recorder := httptest.NewRecorder()
	hs.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/uploads/tools/readme.txt", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "verified SFTP data" {
		t.Fatalf("verified artifact response = %d %q", recorder.Code, recorder.Body.String())
	}
	assertSFTPReadOnly(t, fx.fs.operations())
	entries, err := fx.client(t).ReadDir("/inbox")
	if err != nil || len(entries) != 4 {
		t.Fatalf("remote retained files = %v, %v; want bundle trio and heartbeat", entries, err)
	}
	fx.fs.resetOperations("")
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, op := range fx.fs.operations() {
		if op.method == "Get" && path.Base(op.name) != diodeHeartbeatFileName {
			t.Errorf("already imported bundle downloaded again: %s", op.name)
		}
	}
}

func assertSFTPReadOnly(t *testing.T, operations []sftpTestOperation) {
	t.Helper()
	for _, op := range operations {
		if op.method != "Get" {
			t.Errorf("high-side polling mutated remote files: %+v", op)
		}
	}
}

func TestSFTPPollIgnoresHiddenAndWritingFiles(t *testing.T) {
	fx := newSFTPFixture(t)
	ls := newBareLowServer(t)
	ls.cfg.SFTP = &fx.cfg
	hs := newTestHighServer(t, ls.privateKey.Public().(ed25519.PublicKey))
	hs.cfg.SFTP = &fx.cfg
	res := collectUpload(t, ls, "tools", []uploadPair{{"ready.txt", "complete"}})
	if res.DiodeError != "" {
		t.Fatal(res.DiodeError)
	}
	client := fx.client(t)
	signature := path.Join("/inbox", res.BundleID+".manifest.json.sig")
	if err := client.Rename(signature, signature+".writing"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range bundleSuffixes() {
		fx.write(t, ".uploads-bundle-000002"+suffix, []byte("still being written"))
	}
	fx.write(t, ".artigate.heartbeat", []byte("incomplete heartbeat"))
	fx.write(t, "artigate.heartbeat.writing", []byte("incomplete heartbeat"))
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatalf("poll with pending files: %v", err)
	}
	entries, err := os.ReadDir(hs.cfg.Landing)
	if err != nil || len(entries) != 0 {
		t.Fatalf("pending remote bundle touched landing: %v, %v", entries, err)
	}
	if err := client.Rename(signature+".writing", signature); err != nil {
		t.Fatal(err)
	}
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := hs.ImportStatus()
	if err != nil || status.Stream(streamUploads).LastImportedSequence != 1 {
		t.Fatalf("completed rename did not import: %+v, %v", status, err)
	}
}

func TestSFTPDownloadFailurePublishesNoPartialBundle(t *testing.T) {
	fx := newSFTPFixture(t)
	ls := newBareLowServer(t)
	ls.cfg.SFTP = &fx.cfg
	hs := newTestHighServer(t, ls.privateKey.Public().(ed25519.PublicKey))
	hs.cfg.SFTP = &fx.cfg
	res := collectUpload(t, ls, "tools", []uploadPair{{"retry.txt", "retry download"}})
	if res.DiodeError != "" {
		t.Fatal(res.DiodeError)
	}
	fx.fs.resetOperations(".manifest.json")
	if err := hs.pollSFTP(t.Context()); err == nil {
		t.Fatal("remote read refusal was not reported")
	}
	entries, err := os.ReadDir(hs.cfg.Landing)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed bundle download exposed partial files: %v, %v", entries, err)
	}
	fx.fs.resetOperations("")
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatalf("retry download: %v", err)
	}
	status, err := hs.ImportStatus()
	if err != nil || status.Stream(streamUploads).LastImportedSequence != 1 {
		t.Fatalf("recovered download did not import: %+v, %v", status, err)
	}
}

func TestSFTPPollRejectsInvalidSignatureThenAcceptsRepair(t *testing.T) {
	fx := newSFTPFixture(t)
	ls := newBareLowServer(t)
	ls.cfg.SFTP = &fx.cfg
	hs := newTestHighServer(t, ls.privateKey.Public().(ed25519.PublicKey))
	hs.cfg.SFTP = &fx.cfg
	res := collectUpload(t, ls, "tools", []uploadPair{{"trusted.txt", "signed bytes"}})
	if res.DiodeError != "" {
		t.Fatal(res.DiodeError)
	}
	name := res.BundleID + ".manifest.json.sig"
	fx.write(t, name, []byte(strings.Repeat("A", 88)))
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatalf("poll corrupted bundle: %v", err)
	}
	if !fileExists(filepath.Join(hs.cfg.Root, "rejected", name)) {
		t.Fatal("invalid signature bypassed rejection")
	}
	status, err := hs.ImportStatus()
	if err != nil || status.Stream(streamUploads).LastImportedSequence != 0 {
		t.Fatalf("invalid signature advanced import: %+v, %v", status, err)
	}
	replayed, err := ls.ExportSequence(streamUploads, res.Sequence)
	if err != nil || replayed.DiodeError != "" {
		t.Fatalf("repair retransmit = %+v, %v", replayed, err)
	}
	if err := hs.pollSFTP(t.Context()); err != nil {
		t.Fatalf("poll repaired bundle: %v", err)
	}
	status, err = hs.ImportStatus()
	if err != nil || status.Stream(streamUploads).LastImportedSequence != 1 {
		t.Fatalf("repaired bundle did not import: %+v, %v", status, err)
	}
}
