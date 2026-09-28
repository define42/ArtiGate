package main

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
)

// invalidPackageError marks confirmed invalid package content. Publishers may
// skip that package, but must return operational errors so the importer leaves
// the bundle's sequence uncommitted and retries after storage is repaired.
// Errors reading existing repository metadata are never invalid package content.
type invalidPackageError struct{ err error }

func (e *invalidPackageError) Error() string { return e.err.Error() }
func (e *invalidPackageError) Unwrap() error { return e.err }

func invalidPackage(err error) error {
	return &invalidPackageError{err: err}
}

// classifyPackageArchiveError marks known archive-format failures. Archive
// readers also return underlying filesystem errors; unfamiliar errors stay
// retryable rather than silently acknowledging a package we could not read.
func classifyPackageArchiveError(err error) error {
	for _, invalid := range []error{
		zip.ErrFormat, zip.ErrAlgorithm, zip.ErrChecksum,
		gzip.ErrHeader, gzip.ErrChecksum, tar.ErrHeader,
		io.EOF, io.ErrUnexpectedEOF,
	} {
		if errors.Is(err, invalid) {
			return invalidPackage(err)
		}
	}
	var corrupt flate.CorruptInputError
	if errors.As(err, &corrupt) {
		return invalidPackage(err)
	}
	return err
}
