package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSFTPReadyFilesAndBundles(t *testing.T) {
	dir := t.TempDir()
	complete := []string{"go-bundle-000002", "go-bundle-000010", "uploads-bundle-000001"}
	for _, id := range complete {
		for _, suffix := range bundleSuffixes() {
			if err := os.WriteFile(filepath.Join(dir, id+suffix), []byte("ready"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{
		"go-bundle-000001.manifest.json", ".go-bundle-000003.tar.gz",
		"go-bundle-000003.tar.gz.writing", ".artigate.heartbeat", "artigate.heartbeat.writing",
		diodeHeartbeatFileName, "unrelated.txt", "unknown-bundle-000001.manifest.json",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pending"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "go-bundle-000004.manifest.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "unrelated.txt"), filepath.Join(dir, "go-bundle-000005.tar.gz")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	infos := make([]os.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, info)
	}
	files := sftpReadyFiles(infos)
	if got := sftpReadyBundles(files); !reflect.DeepEqual(got, complete) {
		t.Fatalf("ready bundles = %v, want %v", got, complete)
	}
	if len(files) != 11 {
		t.Fatalf("ready files = %v, want nine complete files, one incomplete manifest, and heartbeat", files)
	}
	for name := range files {
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".writing") || name == "unrelated.txt" {
			t.Errorf("accepted pending or unrelated file %q", name)
		}
	}
}

func TestSFTPWriteTempBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		size int64
		fail bool
	}{
		{name: "exact", body: "content", size: 7},
		{name: "empty", size: 0},
		{name: "short", body: "short", size: 7, fail: true},
		{name: "grown", body: "too much", size: 7, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), ".go-bundle-000001.tar.gz")
			err := writeSFTPTemp(tmp, strings.NewReader(tc.body), tc.size)
			if (err != nil) != tc.fail {
				t.Fatalf("writeSFTPTemp = %v, want failure %v", err, tc.fail)
			}
			if tc.fail {
				if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed download left temp file: %v", err)
				}
				return
			}
			body, err := os.ReadFile(tmp)
			if err != nil || string(body) != tc.body {
				t.Fatalf("temporary contents = %q, %v", body, err)
			}
		})
	}
}

func TestSFTPWriteTempRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keep")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".go-bundle-000001.tar.gz")
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := writeSFTPTemp(tmp, strings.NewReader("replacement"), 11); err == nil {
		t.Fatal("download followed an existing symlink")
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "original" {
		t.Fatalf("symlink target was changed: %q, %v", body, err)
	}
}

type sftpBrokenReader struct{}

func (sftpBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestSFTPWriteTempRemovesInterruptedDownload(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".go-bundle-000001.tar.gz")
	if err := writeSFTPTemp(tmp, sftpBrokenReader{}, 10); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("writeSFTPTemp = %v, want interrupted read", err)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted download left temp file: %v", err)
	}
}
