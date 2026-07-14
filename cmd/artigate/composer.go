package main

// PHP Composer ecosystem adapter (manifest types; implementation follows).

import "encoding/json"

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type ComposerManifest struct {
	Packages []ComposerPackage `json:"packages"`
}

// ComposerPackage records one mirrored package release. Metadata is the
// upstream Composer v2 (p2) version object with its dist section removed; the
// high side re-adds a dist section pointing at the verified zip it serves.
type ComposerPackage struct {
	Name              string          `json:"name"`
	Version           string          `json:"version"`
	VersionNormalized string          `json:"version_normalized"`
	Path              string          `json:"path"`
	SHA256            string          `json:"sha256"`
	Metadata          json.RawMessage `json:"metadata"`
}
