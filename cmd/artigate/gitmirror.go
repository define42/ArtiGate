package main

// Raw git repository mirroring ecosystem adapter (manifest types;
// implementation follows).

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type GitManifest struct {
	Repos []GitRepoMirror `json:"repos"`
}

// GitRepoMirror records one mirrored repository snapshot: the refs it
// advertises and the single self-contained packfile carrying every object.
// The high side regenerates the pack index (.idx) from the verified pack
// itself and serves the repository over git's dumb HTTP protocol.
type GitRepoMirror struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Head       string   `json:"head,omitempty"`
	Refs       []GitRef `json:"refs"`
	PackPath   string   `json:"pack_path"`
	PackSHA256 string   `json:"pack_sha256"`
}

// GitRef is one advertised ref: a full ref name and the object it points at.
type GitRef struct {
	Name string `json:"name"`
	SHA1 string `json:"sha1"`
}
