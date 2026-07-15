package main

// Go checksum-database (sumdb) mirroring: the path plumbing shared by both
// sides and the high-side import/serve pieces.
//
// The GOPROXY protocol lets a module proxy also proxy the checksum database
// under $GOPROXY/sumdb/<name>/... . The low side captures, for every mirrored
// module@version, the exact lookup record and Merkle-tree tiles the Go
// toolchain verified against the database's public key (gosumdbcapture.go);
// they travel inside ordinary signed go-stream bundles as sumdb/<name>/...
// files and install under the high side's go/ subtree. The high side then
// answers the passthrough endpoints (supported, latest, lookup, tile), so
// offline clients keep GOSUMDB enabled: every served byte is re-verified by
// the client itself against the database's public key, restoring end-to-end
// checksum-db verification across the diode.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/tlog"
)

// sumdbPathPrefix namespaces checksum-database files in go-stream manifests
// and under the high side's go/ subtree — the same shape the GOPROXY protocol
// uses on the wire, so a stored path is exactly its URL under /go/.
const sumdbPathPrefix = "sumdb/"

type sumdbPathKind int

const (
	// sumdbPathLatest is the database's latest signed tree head.
	sumdbPathLatest sumdbPathKind = iota
	// sumdbPathSupported is the proxy-protocol probe endpoint. It is only ever
	// a URL — never a stored file.
	sumdbPathSupported
	// sumdbPathLookup is a per-module record: go.sum lines plus a signed tree
	// head the record verifies against.
	sumdbPathLookup
	// sumdbPathTile is one tile of the database's Merkle hash tree.
	sumdbPathTile
)

// sumdbRef identifies one checksum database path: which database and which
// kind of endpoint/file.
type sumdbRef struct {
	Name string
	Kind sumdbPathKind
}

// parseSumDBPath parses a checksum-database path relative to the sumdb/
// namespace ("<name>/latest", "<name>/lookup/<mod>@<ver>",
// "<name>/tile/8/0/x001/234[.p/5]", "<name>/supported"), enforcing the exact
// shapes the protocol defines. The database name may itself be path-qualified
// (the go command accepts sumdb names in host[/path] form), so the name spans
// every segment up to the endpoint word. Both sides use it: the low side to
// decide what may be listed in a bundle, the high side to validate manifests at
// import and URLs at serve time — the untrusted import side applies the same
// rules the low side does at collect time.
func parseSumDBPath(rel string) (sumdbRef, error) {
	name, endpoint, ok := splitSumDBEndpoint(rel)
	if !ok {
		return sumdbRef{}, fmt.Errorf("incomplete sumdb path %q", rel)
	}
	if err := validateSumDBName(name); err != nil {
		return sumdbRef{}, err
	}
	ref := sumdbRef{Name: name}
	switch {
	case endpoint == "latest":
		ref.Kind = sumdbPathLatest
	case endpoint == "supported":
		ref.Kind = sumdbPathSupported
	case strings.HasPrefix(endpoint, "lookup/"):
		ref.Kind = sumdbPathLookup
		if err := validateSumDBLookup(strings.TrimPrefix(endpoint, "lookup/")); err != nil {
			return sumdbRef{}, err
		}
	case strings.HasPrefix(endpoint, "tile/"):
		ref.Kind = sumdbPathTile
		if _, err := tlog.ParseTilePath(endpoint); err != nil {
			return sumdbRef{}, err
		}
	default:
		return sumdbRef{}, fmt.Errorf("unknown sumdb path %q", rel)
	}
	return ref, nil
}

// splitSumDBEndpoint separates a sumdb path into its database name and the
// endpoint tail. The name may be path-qualified (host[/path]), so the split is
// the first path segment that opens an endpoint — "latest", "supported",
// "lookup", or "tile". Those four words are reserved: because the wire path is
// sumdb/<name>/<endpoint>, a name that used one as a segment could not be told
// apart from an endpoint, so validateSumDBName rejects them in a name. Returns
// ok=false when no endpoint word is present or one leads with no name before it.
func splitSumDBEndpoint(rel string) (name, endpoint string, ok bool) {
	pos := 0
	for _, seg := range strings.Split(rel, "/") {
		if isSumDBEndpointWord(seg) {
			if pos == 0 {
				return "", "", false
			}
			return rel[:pos-1], rel[pos:], true
		}
		pos += len(seg) + 1
	}
	return "", "", false
}

// isSumDBEndpointWord reports whether seg is a reserved endpoint-opening word.
func isSumDBEndpointWord(seg string) bool {
	switch seg {
	case "latest", "supported", "lookup", "tile":
		return true
	default:
		return false
	}
}

// validateSumDBName checks a checksum database name that becomes both a URL
// prefix and a directory path under the go/ subtree. A name is one or more
// slash-separated segments (a hostname, optionally path-qualified, e.g.
// "sum.golang.org" or "sums.example.com/dev"); every segment must be a
// lowercase hostname-shaped token, so nothing can be a dot-file, a "."/".."
// traversal, an empty (leading-, trailing-, or double-slash) segment, or a
// reserved endpoint word.
func validateSumDBName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("invalid sumdb name %q", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if err := validateSumDBNameSegment(seg); err != nil {
			return fmt.Errorf("invalid sumdb name %q: %w", name, err)
		}
	}
	return nil
}

// validateSumDBNameSegment enforces the per-segment rules of a database name.
func validateSumDBNameSegment(seg string) error {
	if seg == "" || seg[0] == '.' || seg[0] == '-' || isSumDBEndpointWord(seg) {
		return fmt.Errorf("bad name segment %q", seg)
	}
	if strings.Contains(seg, "..") {
		return fmt.Errorf("bad name segment %q", seg)
	}
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return fmt.Errorf("bad name segment %q", seg)
		}
	}
	return nil
}

// validateSumDBLookup checks the "<escaped-module>@<escaped-version>" tail of
// a lookup path with the module escaping rules the proxy protocol defines.
func validateSumDBLookup(rest string) error {
	escPath, escVers, ok := strings.Cut(rest, "@")
	if !ok || strings.ContainsAny(escVers, "@/") {
		return fmt.Errorf("invalid sumdb lookup path %q", rest)
	}
	if _, err := module.UnescapePath(escPath); err != nil {
		return fmt.Errorf("invalid sumdb lookup path %q: %w", rest, err)
	}
	if _, err := module.UnescapeVersion(escVers); err != nil {
		return fmt.Errorf("invalid sumdb lookup path %q: %w", rest, err)
	}
	return nil
}

// validateManifestSumDBPath rejects a manifest file path in the sumdb/
// namespace that is not a well-formed checksum-database file. Applied to
// every manifest file on import (the namespace belongs to the go stream; no
// other collector produces it), so a signed bundle can only ever install
// protocol-shaped sumdb files.
func validateManifestSumDBPath(p string) error {
	rel, ok := strings.CutPrefix(p, sumdbPathPrefix)
	if !ok {
		return nil
	}
	ref, err := parseSumDBPath(rel)
	if err != nil {
		return err
	}
	if ref.Kind == sumdbPathSupported {
		return fmt.Errorf("sumdb path %q is an endpoint, not a file", p)
	}
	return nil
}

// mutableSumDBPath reports whether a sumdb file may legitimately be replaced
// with different content: the latest tree head advances with every capture,
// and a lookup's embedded tree note is refreshed when the low side re-fetches
// it (a rebuilt cache). Tiles stay immutable — their bytes are fixed prefixes
// of the append-only transparency log.
func mutableSumDBPath(p string) bool {
	rel, ok := strings.CutPrefix(p, sumdbPathPrefix)
	if !ok {
		return false
	}
	ref, err := parseSumDBPath(rel)
	return err == nil && (ref.Kind == sumdbPathLatest || ref.Kind == sumdbPathLookup)
}

// withGoSumDBFilePaths adds a go-stream manifest's sumdb/ files to the set the
// importer installs under the go/ subtree. Only module records place files
// there otherwise, and sumdb files belong to no module.
func withGoSumDBFilePaths(goFiles map[string]bool, m BundleManifest) map[string]bool {
	if manifestStream(m) != streamGo {
		return goFiles
	}
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, sumdbPathPrefix) {
			if goFiles == nil {
				goFiles = map[string]bool{}
			}
			goFiles[f.Path] = true
		}
	}
	return goFiles
}

// serveGoSumDB answers the GOPROXY protocol's checksum-database passthrough
// endpoints under /go/sumdb/<name>/..., serving the verified files bundles
// installed. urlPath is the request path with the /go prefix already
// stripped. It reports whether it handled the request.
func (s *HighServer) serveGoSumDB(w http.ResponseWriter, r *http.Request, urlPath string) bool {
	rel, err := cleanProxyPath(urlPath)
	if err != nil || !strings.HasPrefix(rel, sumdbPathPrefix) {
		return false
	}
	ref, err := parseSumDBPath(strings.TrimPrefix(rel, sumdbPathPrefix))
	if err != nil {
		http.Error(w, "invalid sumdb path", http.StatusNotFound)
		return true
	}
	if ref.Kind == sumdbPathSupported {
		s.answerSumDBSupported(w, ref.Name)
		return true
	}
	s.serveSumDBFile(w, r, ref, rel)
	return true
}

// answerSumDBSupported implements the proxy protocol's support probe: any
// 200 tells the go command to send all checksum-database requests here. It
// claims support only for a database this mirror actually holds data for —
// on a 404 the client falls back to asking the database directly, exactly as
// it would against a proxy without sumdb passthrough.
func (s *HighServer) answerSumDBSupported(w http.ResponseWriter, name string) {
	if !dirExists(filepath.Join(s.goModuleDir(), "sumdb", filepath.FromSlash(name))) {
		http.Error(w, "no checksum-database data mirrored for "+name, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// serveSumDBFile serves one stored sumdb file (latest, lookup, or tile). A
// missing lookup gets an actionable message: it is the one miss an operator
// can fix per module.
func (s *HighServer) serveSumDBFile(w http.ResponseWriter, r *http.Request, ref sumdbRef, rel string) {
	abs := filepath.Join(s.goModuleDir(), filepath.FromSlash(rel))
	if !safeJoin(s.goModuleDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	if !fileExists(abs) {
		msg := "not found"
		if ref.Kind == sumdbPathLookup {
			msg = "no checksum-database record mirrored for this module; re-collect it on the low side (or list it in the client's GONOSUMDB)"
		}
		http.Error(w, msg, http.StatusNotFound)
		return
	}
	if ref.Kind == sumdbPathTile {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	http.ServeFile(w, r, abs)
}

// migrateLegacyGoSumDBDir moves sumdb files a pre-sumdb-serving high side
// installed at the download root (it had no placement rule for them) into
// the go/ subtree where they are served from. One-time and best-effort: a
// failure only means those early files stay unserved until a forced
// re-collect delivers them again.
func migrateLegacyGoSumDBDir(downloadDir string) {
	legacy := filepath.Join(downloadDir, "sumdb")
	if !dirExists(legacy) {
		return
	}
	dst := filepath.Join(downloadDir, "go", "sumdb")
	if dirExists(dst) || fileExists(dst) {
		log.Printf("go sumdb: legacy files remain at %s (already have %s); run a forced go re-collect to re-deliver them", legacy, dst)
		return
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		log.Printf("go sumdb: migrating legacy dir: %v", err)
		return
	}
	if err := os.Rename(legacy, dst); err != nil {
		log.Printf("go sumdb: migrating legacy dir: %v", err)
		return
	}
	log.Printf("go sumdb: moved legacy checksum-database files from %s to %s", legacy, dst)
}

// dirExists reports whether p exists and is a directory.
func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
