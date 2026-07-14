package main

// RubyGems ecosystem adapter (manifest types; implementation follows).

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type RubyGemsManifest struct {
	Gems []GemVersion `json:"gems"`
}

// GemVersion records one mirrored gem release. InfoLine is the verbatim
// upstream compact-index /info/<name> line for the release; it travels inside
// the signed manifest and its checksum must equal the .gem file's SHA-256.
type GemVersion struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform,omitempty"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	InfoLine string `json:"info_line"`
}
