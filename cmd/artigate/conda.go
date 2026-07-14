package main

// Conda channel ecosystem adapter (manifest types; implementation follows).

import "encoding/json"

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type CondaManifest struct {
	Channels []CondaChannel `json:"channels"`
}

// CondaChannel is one mirrored conda channel (named like an APT mirror, so
// several upstreams can coexist under /conda/<name>).
type CondaChannel struct {
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Packages []CondaPackage `json:"packages"`
}

// CondaPackage records one mirrored package file. RepodataEntry is the
// verbatim upstream repodata.json entry for the file; it travels inside the
// signed manifest and its sha256 must equal the package file's SHA-256.
type CondaPackage struct {
	Subdir        string          `json:"subdir"`
	Filename      string          `json:"filename"`
	Path          string          `json:"path"`
	SHA256        string          `json:"sha256"`
	RepodataEntry json.RawMessage `json:"repodata_entry"`
}
