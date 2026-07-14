package main

// VS Code extension (Open VSX) ecosystem adapter (manifest types;
// implementation follows).

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type VSXManifest struct {
	Extensions []VSXExtension `json:"extensions"`
}

// VSXExtension records one mirrored extension version (.vsix archive).
type VSXExtension struct {
	Publisher string `json:"publisher"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}
