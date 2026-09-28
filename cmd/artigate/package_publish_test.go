package main

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

func TestPackageArchiveErrorClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		err     error
		invalid bool
	}{
		{name: "zip format", err: zip.ErrFormat, invalid: true},
		{name: "zip checksum", err: zip.ErrChecksum, invalid: true},
		{name: "zip compression", err: zip.ErrAlgorithm, invalid: true},
		{name: "gzip header", err: gzip.ErrHeader, invalid: true},
		{name: "gzip checksum", err: gzip.ErrChecksum, invalid: true},
		{name: "tar header", err: tar.ErrHeader, invalid: true},
		{name: "truncated archive", err: io.ErrUnexpectedEOF, invalid: true},
		{name: "empty archive", err: io.EOF, invalid: true},
		{name: "deflate data", err: flate.CorruptInputError(12), invalid: true},
		{name: "missing archive", err: &os.PathError{Op: "open", Path: "archive", Err: os.ErrNotExist}},
		{name: "permission denied", err: &os.PathError{Op: "open", Path: "archive", Err: os.ErrPermission}},
		{name: "disk read failure", err: &os.PathError{Op: "read", Path: "archive", Err: syscall.EIO}},
		{name: "unknown failure", err: errors.New("unknown archive reader failure")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyPackageArchiveError(fmt.Errorf("read package: %w", tc.err))
			var invalid *invalidPackageError
			if got := errors.As(err, &invalid); got != tc.invalid {
				t.Fatalf("invalid content = %v, want %v: %v", got, tc.invalid, err)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("classification lost original error: %v", err)
			}
		})
	}
}
