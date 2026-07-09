package main

// Exported-content index (export dedup), SQLite-backed.
//
// A permanent, per-stream record of the files already written into a bundle —
// i.e. forwarded across the diode — keyed by bundle path and content hash.
// Collectors use it three ways:
//
//   - Skip: a collect whose entire resolved file set is already recorded
//     produces no bundle and burns no sequence number.
//   - Delta: when only part of the set is new, the bundle's archive carries
//     just the new files; the recorded ones ride along in the manifest
//     as prior references (ManifestFile.Prior) the high side verifies against
//     its accumulated repository instead of re-receiving.
//   - Download skip: collectors whose upstream declares a file's SHA-256
//     before the bytes are fetched (APT and RPM indexes, container digests,
//     Hugging Face LFS) consult the index first and emit a prior reference
//     without downloading at all.
//
// Rows are path-qualified: a hit means "this exact bundle path with this exact
// content was forwarded", which is precisely the claim a prior reference makes
// and the high side verifies. Rows migrated from the legacy hash-only schema
// carry an empty path and match any path with that hash; the first export that
// touches such content re-records it path-qualified.
//
// It uses the same pure-Go SQLite driver as the watch store (rather than a JSON
// set rewritten whole on every collect) so lookups and inserts stay O(new) as
// the mirror grows into hundreds of thousands of artifacts. It is deliberately
// independent of the rolling bundle archive: rebuilding it from archived
// manifests would let archive pruning forget shipped content and re-ship it.
// Re-export never consults or updates it. The index is an optimization, not
// correctness state — callers fail safe (export or download anyway) on any
// store error — so keeping it here, separate from the stdlib-JSON sequence
// state, keeps a SQLite problem from ever wedging the core export pipeline.

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// ExportedStore records, per stream, the files already forwarded.
type ExportedStore struct {
	db *sql.DB
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
	for _, stmt := range []string{"PRAGMA busy_timeout=5000", forwardedSchema} {
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

// IsForwarded reports whether one file (bundle path plus content hash) is
// already recorded for the stream.
func (s *ExportedStore) IsForwarded(stream, path, sha256 string) (bool, error) {
	var one int
	switch err := s.db.QueryRow(forwardedQuery, stream, sha256, path).Scan(&one); {
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
	for i, f := range files {
		var one int
		switch err := stmt.QueryRow(stream, f.SHA256, f.Path).Scan(&one); {
		case err == nil:
			flags[i] = true
		case errors.Is(err, sql.ErrNoRows):
		default:
			return nil, err
		}
	}
	return flags, nil
}

// Record adds every file (path plus hash) to the stream's index in one
// transaction. It is idempotent via the primary key; recording a prior file
// again also gives content migrated from the legacy schema its path-qualified
// row.
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
	for _, f := range files {
		if _, err := stmt.Exec(stream, f.SHA256, f.Path); err != nil {
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
