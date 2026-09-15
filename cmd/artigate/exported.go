package main

// Exported-content index (export dedup), SQLite-backed.
//
// A permanent, per-stream record of the files already written into a bundle —
// i.e. forwarded across the diode — keyed by bundle path and content hash.
// Collectors use it three ways:
//
//   - Skip: a collect whose entire resolved file set and metadata are already
//     recorded produces no bundle and burns no sequence number.
//   - Delta: when only part of the set is new, the bundle's archive carries
//     just the new files; the recorded ones ride along in the manifest
//     as prior references (ManifestFile.Prior) the high side verifies against
//     its accumulated repository instead of re-receiving.
//   - Download skip: collectors whose upstream declares a file's SHA-256
//     before the bytes are fetched (APT and RPM indexes, container digests,
//     Hugging Face LFS) consult the index first and emit a prior reference
//     without downloading at all.
//
// Immutable files use path-qualified historical rows. Mutable paths instead
// match only their latest delivered contents: an older snapshot no longer
// describes the receiver after a replacement. Legacy hash-only rows may match
// immutable paths, but cannot establish the current state of a mutable path.
//
// It uses the same pure-Go SQLite driver as the watch store (rather than a JSON
// set rewritten whole on every collect) so lookups and inserts stay O(new) as
// the mirror grows into hundreds of thousands of artifacts. It is deliberately
// independent of the rolling bundle archive: rebuilding it from archived
// manifests would let archive pruning forget shipped content and re-ship it.
// Re-export never consults or updates it. The index is an optimization, not
// correctness state. Lookup failures cause callers to export or download
// anyway. Before writing mutable replacements, callers must durably invalidate
// their old entries so a failed export or record cannot leave stale dedup hits.

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// ExportedStore records, per stream, the files and metadata already forwarded.
type ExportedStore struct {
	db *sql.DB
}

// ExportMetadata identifies one metadata record and its content hash. Keys
// name mutable receiver state, such as a repository's container tag mapping.
type ExportMetadata struct {
	Key    string
	SHA256 string
}

// forwardedSchema is a pure key table. The primary key is ordered
// (stream, sha256, path) so both lookups the collectors make — "this exact
// path+hash" and the legacy "this hash under any path" — resolve on one index
// prefix scan, and WITHOUT ROWID avoids a redundant rowid for a table only
// ever queried by that key.
const forwardedSchema = `CREATE TABLE IF NOT EXISTS forwarded_files (
  stream TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  path   TEXT NOT NULL,
  PRIMARY KEY (stream, sha256, path)
) WITHOUT ROWID`

// Mutable history has no export ordering, so existing historical rows cannot
// seed this table. An upgrade safely re-exports each mutable path once.
const mutableForwardedSchema = `CREATE TABLE IF NOT EXISTS mutable_forwarded_files (
  stream TEXT NOT NULL,
  path   TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  PRIMARY KEY (stream, path)
) WITHOUT ROWID`

// Metadata describes current receiver state, so only its latest hash can
// suppress an export. Historical hashes would incorrectly skip reversions.
const forwardedMetadataSchema = `CREATE TABLE IF NOT EXISTS forwarded_metadata (
  stream TEXT NOT NULL,
  key    TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  PRIMARY KEY (stream, key)
) WITHOUT ROWID`

// OpenExportedStore opens (creating if needed) the exported-content database at
// path, mirroring the watch store's single-writer setup, and folds in any
// legacy hash-only index.
func OpenExportedStore(path string) (*ExportedStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open exported db: %w", err)
	}
	// SQLite has a single writer; serialize all access so the collectors never
	// collide on "database is locked", waiting briefly if contended.
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{"PRAGMA busy_timeout=5000", forwardedSchema, mutableForwardedSchema, forwardedMetadataSchema} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init exported db: %w", err)
		}
	}
	if err := migrateLegacyExported(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate exported db: %w", err)
	}
	return &ExportedStore{db: db}, nil
}

// migrateLegacyExported folds the pre-delta exported_content table into
// forwarded_files. The legacy schema recorded hashes without paths, so its
// rows migrate with an empty path and keep satisfying hash-only membership.
func migrateLegacyExported(db *sql.DB) error {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exported_content'`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO forwarded_files (stream, sha256, path)
		SELECT stream, sha256, '' FROM exported_content`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE exported_content`); err != nil {
		return err
	}
	return tx.Commit()
}

// Close releases the database. It is safe to call more than once (a closed
// *sql.DB's Close is a no-op) and on a nil store. After Close, queries return a
// "database is closed" error rather than panicking, which the collectors treat
// as a fail-safe signal to export without dedup.
func (s *ExportedStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// forwardedQuery matches one file by exact path or by a legacy hash-only row.
const forwardedQuery = `SELECT 1 FROM forwarded_files
	WHERE stream = ? AND sha256 = ? AND (path = ? OR path = '') LIMIT 1`

const mutableForwardedQuery = `SELECT 1 FROM mutable_forwarded_files
	WHERE stream = ? AND sha256 = ? AND path = ?`

// IsForwarded reports whether one file (bundle path plus content hash) is
// already recorded for the stream. Mutable files must match the latest export.
func (s *ExportedStore) IsForwarded(stream, path, sha256 string) (bool, error) {
	query := forwardedQuery
	if mutableRepoPath(path) {
		query = mutableForwardedQuery
	}
	var one int
	switch err := s.db.QueryRow(query, stream, sha256, path).Scan(&one); {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, err
	}
}

// ForwardedFlags reports, per file, whether that file is already recorded for
// the stream. The result always has one entry per input file.
func (s *ExportedStore) ForwardedFlags(stream string, files []ManifestFile) ([]bool, error) {
	flags := make([]bool, len(files))
	if len(files) == 0 {
		return flags, nil
	}
	stmt, err := s.db.Prepare(forwardedQuery)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stmt.Close() }()
	mutableStmt, err := s.db.Prepare(mutableForwardedQuery)
	if err != nil {
		return nil, err
	}
	defer func() { _ = mutableStmt.Close() }()
	for i, f := range files {
		query := stmt
		if mutableRepoPath(f.Path) {
			query = mutableStmt
		}
		var one int
		switch err := query.QueryRow(stream, f.SHA256, f.Path).Scan(&one); {
		case err == nil:
			flags[i] = true
		case errors.Is(err, sql.ErrNoRows):
		default:
			return nil, err
		}
	}
	return flags, nil
}

// InvalidateMutable forgets delivered mutable paths before a bundle is written.
// If writing, committing its sequence, or recording the new contents fails,
// future collects safely resend those paths, including after a restart. Prior
// references do not replace anything and must retain their current entries.
func (s *ExportedStore) InvalidateMutable(stream string, files []ManifestFile) error {
	var paths []string
	for _, f := range files {
		if !f.Prior && mutableRepoPath(f.Path) {
			paths = append(paths, f.Path)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare("DELETE FROM mutable_forwarded_files WHERE stream = ? AND path = ?")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, path := range paths {
		if _, err := stmt.Exec(stream, path); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Record adds every file (path plus hash) to the stream's index in one
// transaction, updating the latest contents of delivered mutable files. Prior
// references do not establish mutable state because they deliver no bytes.
func (s *ExportedStore) Record(stream string, files []ManifestFile) error {
	if len(files) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO forwarded_files (stream, sha256, path) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	mutableStmt, err := tx.Prepare(`INSERT INTO mutable_forwarded_files (stream, sha256, path) VALUES (?, ?, ?)
		ON CONFLICT (stream, path) DO UPDATE SET sha256 = excluded.sha256`)
	if err != nil {
		return err
	}
	defer func() { _ = mutableStmt.Close() }()
	for _, f := range files {
		if _, err := stmt.Exec(stream, f.SHA256, f.Path); err != nil {
			return err
		}
		if !f.Prior && mutableRepoPath(f.Path) {
			if _, err := mutableStmt.Exec(stream, f.SHA256, f.Path); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// MetadataChanged reports whether any metadata record differs from the latest
// one forwarded for the stream. Missing records always require an export.
func (s *ExportedStore) MetadataChanged(stream string, metadata []ExportMetadata) (bool, error) {
	if len(metadata) == 0 {
		return false, nil
	}
	stmt, err := s.db.Prepare("SELECT sha256 FROM forwarded_metadata WHERE stream = ? AND key = ?")
	if err != nil {
		return false, err
	}
	defer func() { _ = stmt.Close() }()
	for _, m := range metadata {
		var sha256 string
		switch err := stmt.QueryRow(stream, m.Key).Scan(&sha256); {
		case err == nil:
			if sha256 != m.SHA256 {
				return true, nil
			}
		case errors.Is(err, sql.ErrNoRows):
			return true, nil
		default:
			return false, err
		}
	}
	return false, nil
}

// InvalidateMetadata forgets each supplied key before writing a metadata
// bundle. A failed write, sequence commit, or record then safely causes a
// future collect to resend the metadata, including after a restart.
func (s *ExportedStore) InvalidateMetadata(stream string, metadata []ExportMetadata) error {
	if len(metadata) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare("DELETE FROM forwarded_metadata WHERE stream = ? AND key = ?")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, m := range metadata {
		if _, err := stmt.Exec(stream, m.Key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RecordMetadata records the latest metadata after a successful sequence
// commit. Records are applied in order in one transaction, so the last value
// for a repeated key describes the receiver's current state.
func (s *ExportedStore) RecordMetadata(stream string, metadata []ExportMetadata) error {
	if len(metadata) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO forwarded_metadata (stream, key, sha256) VALUES (?, ?, ?)
		ON CONFLICT (stream, key) DO UPDATE SET sha256 = excluded.sha256`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, m := range metadata {
		if _, err := stmt.Exec(stream, m.Key, m.SHA256); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Count returns how many distinct content hashes are recorded for a stream.
func (s *ExportedStore) Count(stream string) (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(DISTINCT sha256) FROM forwarded_files WHERE stream = ?", stream).Scan(&n)
	return n, err
}
