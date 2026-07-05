package main

// Exported-content index (Tier-1 export dedup), SQLite-backed.
//
// A permanent, per-stream set of the content hashes already written into a
// bundle — i.e. forwarded across the diode. A collect whose entire resolved file
// set is already recorded produces no bundle, so a scheduled re-pull of an
// unchanged upstream stops re-sending bytes the high side already has.
//
// It uses the same pure-Go SQLite driver as the watch store (rather than a JSON
// set rewritten whole on every collect) so lookups and inserts stay O(new) as
// the mirror grows into hundreds of thousands of artifacts. It is deliberately
// independent of the rolling bundle archive: rebuilding it from archived
// manifests would let archive pruning forget shipped content and re-ship it.
// Re-export never consults or updates it. The index is an optimization, not
// correctness state — callers fail safe (export anyway) on any store error — so
// keeping it here, separate from the stdlib-JSON sequence state, keeps a SQLite
// problem from ever wedging the core export pipeline.

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// ExportedStore records, per stream, the content hashes already forwarded.
type ExportedStore struct {
	db *sql.DB
}

// exportedSchema is a pure key table: the (stream, sha256) primary key gives
// O(log n) membership tests and dedups inserts, and WITHOUT ROWID avoids a
// redundant rowid for a table that is only ever queried by that key.
const exportedSchema = `CREATE TABLE IF NOT EXISTS exported_content (
  stream TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  PRIMARY KEY (stream, sha256)
) WITHOUT ROWID`

// OpenExportedStore opens (creating if needed) the exported-content database at
// path, mirroring the watch store's single-writer setup.
func OpenExportedStore(path string) (*ExportedStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open exported db: %w", err)
	}
	// SQLite has a single writer; serialize all access so the collectors never
	// collide on "database is locked", waiting briefly if contended.
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{"PRAGMA busy_timeout=5000", exportedSchema} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init exported db: %w", err)
		}
	}
	return &ExportedStore{db: db}, nil
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

// AllForwarded reports whether every hash is already recorded for the stream. It
// short-circuits on the first miss, so a collect that carries any new content
// returns quickly; an empty hash list returns false (nothing to skip).
func (s *ExportedStore) AllForwarded(stream string, hashes []string) (bool, error) {
	if len(hashes) == 0 {
		return false, nil
	}
	stmt, err := s.db.Prepare("SELECT 1 FROM exported_content WHERE stream = ? AND sha256 = ?")
	if err != nil {
		return false, err
	}
	defer func() { _ = stmt.Close() }()
	for _, h := range hashes {
		var one int
		switch err := stmt.QueryRow(stream, h).Scan(&one); {
		case err == nil: // present; keep checking the rest
		case err == sql.ErrNoRows:
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

// Record adds every hash to the stream's index in one transaction. It is
// idempotent: re-recording an already-present hash is a no-op via the primary
// key.
func (s *ExportedStore) Record(stream string, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO exported_content (stream, sha256) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, h := range hashes {
		if _, err := stmt.Exec(stream, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Count returns how many hashes are recorded for a stream.
func (s *ExportedStore) Count(stream string) (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM exported_content WHERE stream = ?", stream).Scan(&n)
	return n, err
}
