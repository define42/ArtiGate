package main

// Ansible Galaxy collection ecosystem adapter (manifest types; implementation
// follows).

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type GalaxyManifest struct {
	Collections []GalaxyCollection `json:"collections"`
}

// GalaxyCollection records one mirrored collection version (.tar.gz artifact).
type GalaxyCollection struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}
