package main

// VS Code extension (Open VSX) ecosystem adapter. The low side resolves
// extensions against an Open VSX registry's REST API — GET
// /api/<namespace>/<name> describes the newest version and
// /api/<namespace>/<name>/<version> a pinned one; the response's
// "namespace"/"name"/"version" fields carry the canonical identity, "files"
// maps asset kinds to URLs ("download" is the .vsix archive; "sha256", where
// the server publishes one, its hex digest), and "dependencies" /
// "bundledExtensions" reference the extensions a version pulls in — then
// downloads the .vsix archives (with their dependency and extension-pack
// closure) and packs them into the same numbered, signed ArtiGate bundle
// format used by the other ecosystems. The high side regenerates per-version
// metadata from each archive's own embedded extension/package.json (never
// trusting transferred metadata) and answers the VS Code Marketplace gallery
// query subset that VSCodium and Code - OSS speak, so pointing a
// product.json's extensionsGallery.serviceUrl (or VSCODE_GALLERY_SERVICE_URL)
// at <base>/vsx/gallery makes `codium --install-extension publisher.name`
// work against the mirror.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// vsxEcosystem is the VS Code extension stream's registry entry (see
// ecosystems in ecosystem.go).
func vsxEcosystem() ecosystem {
	return ecosystem{
		stream:       streamVSX,
		label:        "VS Code",
		title:        "VS Code extensions",
		collect:      (*LowServer).HandleVSXCollect,
		watchCollect: watchAdapter((*LowServer).CollectVSX),
		flags: func(fs *flag.FlagSet, cfg *LowConfig) {
			fs.StringVar(&cfg.VSXRegistryURL, "vsx-registry", "", "Open VSX registry VS Code extensions are fetched from (default "+defaultVSXRegistryURL+")")
		},
		manifestContent: func(m BundleManifest) bool { return m.VSX != nil && len(m.VSX.Extensions) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateVSXExtensions(m.VSX.Extensions, seen)
		},
		contentDesc: "vs code extensions",
		publish:     func(s *HighServer, m BundleManifest) error { return s.publishVSX(m.VSX) },
		serve:       (*HighServer).serveVSX,
		scanTree:    flatTreeScan((*HighServer).listVSXExtensions),
		detail:      (*HighServer).vsxDetail,
	}
}

// defaultVSXRegistryURL is the public Open VSX registry.
const defaultVSXRegistryURL = "https://open-vsx.org"

const (
	// vsxMaxResolved bounds a dependency/pack resolution so a pathological
	// reference graph cannot run away.
	vsxMaxResolved = 300
	// vsxMaxMetadataBytes caps one /api extension-metadata response held in
	// memory for parsing.
	vsxMaxMetadataBytes = 16 << 20
	// vsxMaxPackageJSONBytes caps one extension/package.json read from a
	// .vsix, so a hostile zip entry cannot balloon in memory.
	vsxMaxPackageJSONBytes = 8 << 20
	// vsxMaxDigestBytes caps a fetched .sha256 digest file (a hex digest plus
	// at most a filename).
	vsxMaxDigestBytes = 4 << 10
	// vsxMaxQueryBytes caps one gallery extensionquery request body.
	vsxMaxQueryBytes = 1 << 20
	// vsxDefaultPageSize and vsxMaxPageSize bound gallery query pagination.
	vsxDefaultPageSize = 50
	vsxMaxPageSize     = 200
)

// Marketplace gallery asset and property names the served protocol uses.
const (
	vsxAssetVSIXPackage = "Microsoft.VisualStudio.Services.VSIXPackage"
	vsxAssetManifest    = "Microsoft.VisualStudio.Code.Manifest"
	vsxPropEngine       = "Microsoft.VisualStudio.Code.Engine"
	vsxPropDependencies = "Microsoft.VisualStudio.Code.ExtensionDependencies"
	vsxPropPack         = "Microsoft.VisualStudio.Code.ExtensionPack"
)

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

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// vsxNameRE matches an Open VSX namespace (publisher) or extension name. The
// charset contains no dots — that keeps "publisher.name" splitting
// unambiguous at the first dot — and the first character excludes "_" and
// "-", so a name can never be ".."/"-flag" or escape a path segment.
var vsxNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// vsxVersionRE matches an extension version, which always starts with a
// digit, so it is path-safe.
var vsxVersionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,63}$`)

// vsxSHA256RE matches a bare lowercase hex SHA-256 digest.
var vsxSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validateVSXName checks one publisher or extension name.
func validateVSXName(name string) error {
	if !vsxNameRE.MatchString(name) {
		return fmt.Errorf("invalid extension publisher/name %q", name)
	}
	return nil
}

// validateVSXVersion checks one extension version.
func validateVSXVersion(v string) error {
	if !vsxVersionRE.MatchString(v) {
		return fmt.Errorf("invalid extension version %q", v)
	}
	return nil
}

// vsxFilename is the canonical archive name a mirrored extension version is
// stored under, whatever the upstream download URL looked like.
func vsxFilename(publisher, name, version string) string {
	return publisher + "." + name + "-" + version + ".vsix"
}

// vsxFileRel is the repository-relative path of one extension archive.
func vsxFileRel(publisher, name, filename string) string {
	return path.Join("vsx", "files", publisher, name, filename)
}

// validateVSXExtension checks one manifest extension record: path-safe
// identity, the canonical storage path, and that the referenced file is
// listed.
func validateVSXExtension(e VSXExtension, seen map[string]bool) error {
	if err := validateVSXName(e.Publisher); err != nil {
		return err
	}
	if err := validateVSXName(e.Name); err != nil {
		return err
	}
	if err := validateVSXVersion(e.Version); err != nil {
		return fmt.Errorf("extension %s.%s: %w", e.Publisher, e.Name, err)
	}
	if e.Filename != vsxFilename(e.Publisher, e.Name, e.Version) {
		return fmt.Errorf("extension %s.%s@%s has non-canonical filename %s", e.Publisher, e.Name, e.Version, e.Filename)
	}
	if e.Path != vsxFileRel(e.Publisher, e.Name, e.Filename) || !seen[e.Path] {
		return fmt.Errorf("extension %s.%s@%s references file not listed in manifest.files: %s", e.Publisher, e.Name, e.Version, e.Path)
	}
	return nil
}

// validateVSXExtensions checks every extension record of a bundle manifest.
func validateVSXExtensions(exts []VSXExtension, seen map[string]bool) error {
	for _, e := range exts {
		if err := validateVSXExtension(e, seen); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: gallery serving
// -----------------------------------------------------------------------------

func (s *HighServer) vsxFilesDir() string {
	return filepath.Join(s.downloadDir, "vsx", "files")
}

func (s *HighServer) vsxMetadataDir() string {
	return filepath.Join(s.downloadDir, "vsx", "metadata")
}

// vsxArtifactAbs is the on-disk location of one stored .vsix archive.
func (s *HighServer) vsxArtifactAbs(publisher, name, filename string) string {
	return filepath.Join(s.vsxFilesDir(), publisher, name, filename)
}

// serveVSX handles the VS Code extension routes under /vsx/: the Marketplace
// gallery query endpoint (POST /vsx/gallery/extensionquery), gallery asset
// downloads, and direct archive downloads. It reports whether it wrote a
// response for the request.
func (s *HighServer) serveVSX(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/vsx" && !strings.HasPrefix(p, "/vsx/") {
		return false
	}
	rest := strings.Trim(strings.TrimPrefix(p, "/vsx"), "/")
	// The gallery query POSTs, so its route must dodge the read-method gate
	// below.
	if rest == "gallery/extensionquery" {
		s.handleVSXGalleryQuery(w, r)
		return true
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	s.serveVSXRead(w, r, rest)
	return true
}

// serveVSXRead dispatches the read-only routes:
// assets/<publisher>/<name>/<version>/<assetType> for gallery clients and
// files/<publisher>/<name>/<file>.vsix for direct downloads.
func (s *HighServer) serveVSXRead(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(rest, "/")
	switch {
	case len(segs) == 5 && segs[0] == "assets":
		s.handleVSXAsset(w, r, segs[1], segs[2], segs[3], segs[4])
	case len(segs) == 4 && segs[0] == "files":
		s.handleVSXFile(w, r, segs[1], segs[2], segs[3])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// handleVSXAsset serves one gallery asset: the .vsix package itself, or the
// stored extension manifest (the embedded package.json). Anything else 404s.
func (s *HighServer) handleVSXAsset(w http.ResponseWriter, r *http.Request, publisher, name, version, assetType string) {
	if validateVSXName(publisher) != nil || validateVSXName(name) != nil || validateVSXVersion(version) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	st, err := s.readVSXStored(publisher, name, version)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch assetType {
	case vsxAssetVSIXPackage:
		serveFile(w, r, s.vsxArtifactAbs(publisher, name, st.Filename))
	case vsxAssetManifest:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(st.Manifest)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// handleVSXFile serves one archive by filename (the browser/script-facing
// download the dashboard links).
func (s *HighServer) handleVSXFile(w http.ResponseWriter, r *http.Request, publisher, name, file string) {
	if validateVSXName(publisher) != nil || validateVSXName(name) != nil || !strings.HasSuffix(file, ".vsix") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := s.vsxArtifactAbs(publisher, name, file)
	if !safeJoin(s.vsxFilesDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// vsxGalleryFilter is the subset of a gallery extensionquery the mirror
// honors: exact-id criteria (filterType 7), free-text criteria (filterType
// 10), and the first filter's pagination. Other criteria kinds (target
// platform, flag exclusions, categories) are ignored.
type vsxGalleryFilter struct {
	ids    []string // lowercased "publisher.name" values
	search []string // lowercased free-text terms
	page   int      // 1-based
	size   int
}

// parseVSXGalleryFilter decodes a gallery query body. An empty body — or one
// with no id/text criteria — lists everything.
func parseVSXGalleryFilter(body []byte) (vsxGalleryFilter, error) {
	f := vsxGalleryFilter{page: 1, size: vsxDefaultPageSize}
	if len(bytes.TrimSpace(body)) == 0 {
		return f, nil
	}
	var q struct {
		Filters []struct {
			Criteria []struct {
				FilterType int    `json:"filterType"`
				Value      string `json:"value"`
			} `json:"criteria"`
			PageNumber int `json:"pageNumber"`
			PageSize   int `json:"pageSize"`
		} `json:"filters"`
	}
	if err := json.Unmarshal(body, &q); err != nil {
		return f, fmt.Errorf("parse gallery query: %w", err)
	}
	if len(q.Filters) == 0 {
		return f, nil
	}
	first := q.Filters[0]
	if first.PageNumber > 1 {
		f.page = first.PageNumber
	}
	if first.PageSize > 0 {
		f.size = min(first.PageSize, vsxMaxPageSize)
	}
	for _, c := range first.Criteria {
		value := strings.ToLower(strings.TrimSpace(c.Value))
		if value == "" {
			continue
		}
		switch c.FilterType {
		case 7:
			f.ids = append(f.ids, value)
		case 10:
			f.search = append(f.search, value)
		}
	}
	return f, nil
}

// matches reports whether one gallery entry satisfies the filter: any exact
// id when ids were given, otherwise every free-text term as a
// case-insensitive substring of the id, display name, or description.
func (f vsxGalleryFilter) matches(e vsxGalleryExtension) bool {
	id := strings.ToLower(e.Publisher.PublisherName + "." + e.ExtensionName)
	if len(f.ids) > 0 {
		return slices.Contains(f.ids, id)
	}
	hay := id + " " + strings.ToLower(e.DisplayName) + " " + strings.ToLower(e.ShortDescription)
	for _, term := range f.search {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

// vsxGalleryExtension is one extension entry of an extensionquery response.
type vsxGalleryExtension struct {
	Publisher        vsxGalleryPublisher `json:"publisher"`
	ExtensionID      string              `json:"extensionId"`
	ExtensionName    string              `json:"extensionName"`
	DisplayName      string              `json:"displayName"`
	ShortDescription string              `json:"shortDescription"`
	Flags            string              `json:"flags"`
	LastUpdated      string              `json:"lastUpdated"`
	Versions         []vsxGalleryVersion `json:"versions"`
	Statistics       []vsxGalleryStat    `json:"statistics"`
}

// vsxGalleryPublisher identifies an extension's publisher to gallery clients.
type vsxGalleryPublisher struct {
	PublisherID   string `json:"publisherId"`
	PublisherName string `json:"publisherName"`
	DisplayName   string `json:"displayName"`
}

// vsxGalleryVersion is one version entry of a gallery extension.
type vsxGalleryVersion struct {
	Version          string               `json:"version"`
	LastUpdated      string               `json:"lastUpdated"`
	AssetURI         string               `json:"assetUri"`
	FallbackAssetURI string               `json:"fallbackAssetUri"`
	Files            []vsxGalleryFile     `json:"files"`
	Properties       []vsxGalleryProperty `json:"properties"`
}

// vsxGalleryFile is one downloadable asset of a gallery version entry.
type vsxGalleryFile struct {
	AssetType string `json:"assetType"`
	Source    string `json:"source"`
}

// vsxGalleryProperty is one key/value property of a gallery version entry.
type vsxGalleryProperty struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// vsxGalleryStat is one gallery statistics entry; the mirror publishes none,
// but clients expect the array to be present.
type vsxGalleryStat struct {
	StatisticName string  `json:"statisticName"`
	Value         float64 `json:"value"`
}

// handleVSXGalleryQuery answers POST /vsx/gallery/extensionquery, the
// Marketplace query endpoint extension managers point their gallery service
// URL at.
func (s *HighServer) handleVSXGalleryQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, vsxMaxQueryBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	filter, err := parseVSXGalleryFilter(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries, total, err := s.vsxGalleryResults(npmBaseURL(r), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, vsxGalleryResponse(entries, total))
}

// vsxGalleryResults assembles the filtered, paginated gallery entries and the
// pre-pagination match count.
func (s *HighServer) vsxGalleryResults(base string, f vsxGalleryFilter) ([]vsxGalleryExtension, int, error) {
	served, err := s.vsxListServed()
	if err != nil {
		return nil, 0, err
	}
	matched := []vsxGalleryExtension{}
	for _, ext := range served {
		entry, ok := s.vsxGalleryEntry(base, ext)
		if ok && f.matches(entry) {
			matched = append(matched, entry)
		}
	}
	return vsxGalleryPage(matched, f.page, f.size), len(matched), nil
}

// vsxGalleryPage slices one page out of the matched entries. A huge
// unauthenticated pageNumber can overflow (page-1)*size to a negative start,
// so anything outside [0, len) is just an empty page, never a slice panic.
func vsxGalleryPage(matched []vsxGalleryExtension, page, size int) []vsxGalleryExtension {
	start := (page - 1) * size
	if start < 0 || start >= len(matched) {
		return []vsxGalleryExtension{}
	}
	return matched[start:min(start+size, len(matched))]
}

// vsxGalleryResponse renders the extensionquery response envelope: one result
// with the entries and a ResultCount/TotalCount metadata block.
func vsxGalleryResponse(entries []vsxGalleryExtension, total int) map[string]any {
	return map[string]any{
		"results": []map[string]any{{
			"extensions": entries,
			"resultMetadata": []map[string]any{{
				"metadataType": "ResultCount",
				"metadataItems": []map[string]any{{
					"name":  "TotalCount",
					"count": total,
				}},
			}},
		}},
	}
}

// vsxGalleryEntry renders one served extension as a gallery entry, versions
// newest first. Display name and description come from the newest version's
// stored manifest, falling back to the extension name.
func (s *HighServer) vsxGalleryEntry(base string, ext vsxServedExtension) (vsxGalleryExtension, bool) {
	versions := make([]vsxGalleryVersion, 0, len(ext.Versions))
	var newest vsxManifestMeta
	for _, v := range ext.Versions {
		gv, meta, err := s.vsxGalleryVersion(base, ext, v)
		if err != nil {
			continue
		}
		if len(versions) == 0 {
			newest = meta
		}
		versions = append(versions, gv)
	}
	if len(versions) == 0 {
		return vsxGalleryExtension{}, false
	}
	id := ext.Publisher + "." + ext.Name
	return vsxGalleryExtension{
		Publisher:        vsxGalleryPublisher{PublisherID: vsxUUID(ext.Publisher), PublisherName: ext.Publisher, DisplayName: ext.Publisher},
		ExtensionID:      vsxUUID(id),
		ExtensionName:    ext.Name,
		DisplayName:      orDefault(newest.DisplayName, ext.Name),
		ShortDescription: newest.Description,
		Flags:            "validated",
		LastUpdated:      versions[0].LastUpdated,
		Versions:         versions,
		Statistics:       []vsxGalleryStat{},
	}, true
}

// vsxGalleryVersion renders one stored version as a gallery version entry,
// returning the parsed manifest subset alongside for the entry-level fields.
func (s *HighServer) vsxGalleryVersion(base string, ext vsxServedExtension, version string) (vsxGalleryVersion, vsxManifestMeta, error) {
	st, err := s.readVSXStored(ext.Publisher, ext.Name, version)
	if err != nil {
		return vsxGalleryVersion{}, vsxManifestMeta{}, err
	}
	fi, err := os.Stat(s.vsxArtifactAbs(ext.Publisher, ext.Name, st.Filename))
	if err != nil {
		return vsxGalleryVersion{}, vsxManifestMeta{}, err
	}
	meta := parseVSXManifestMeta(st.Manifest)
	assetBase := base + "/vsx/assets/" + ext.Publisher + "/" + ext.Name + "/" + version
	return vsxGalleryVersion{
		Version:          version,
		LastUpdated:      fi.ModTime().UTC().Format(time.RFC3339),
		AssetURI:         assetBase,
		FallbackAssetURI: assetBase,
		Files: []vsxGalleryFile{
			{AssetType: vsxAssetVSIXPackage, Source: assetBase + "/" + vsxAssetVSIXPackage},
			{AssetType: vsxAssetManifest, Source: assetBase + "/" + vsxAssetManifest},
		},
		Properties: vsxVersionProperties(meta),
	}, meta, nil
}

// vsxVersionProperties renders the manifest-derived version properties
// clients read (engine compatibility, extension dependencies, pack members),
// omitting empty-valued ones.
func vsxVersionProperties(meta vsxManifestMeta) []vsxGalleryProperty {
	props := []vsxGalleryProperty{}
	if v := meta.engineVSCode(); v != "" {
		props = append(props, vsxGalleryProperty{Key: vsxPropEngine, Value: v})
	}
	if len(meta.ExtensionDependencies) > 0 {
		props = append(props, vsxGalleryProperty{Key: vsxPropDependencies, Value: strings.Join(meta.ExtensionDependencies, ",")})
	}
	if len(meta.ExtensionPack) > 0 {
		props = append(props, vsxGalleryProperty{Key: vsxPropPack, Value: strings.Join(meta.ExtensionPack, ",")})
	}
	return props
}

// vsxUUID derives a stable UUID-shaped identifier from a name. Gallery
// clients key publishers and extensions by the ids the marketplace assigned;
// hashing the mirrored identity keeps them deterministic across requests,
// imports, and restarts.
func vsxUUID(name string) string {
	sum := sha256.Sum256([]byte(name))
	h := hex.EncodeToString(sum[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// vsxManifestMeta is the subset of an extension's package.json the gallery
// and the dashboard surface. Parsing is best-effort: absent or oddly-typed
// fields just stay empty.
type vsxManifestMeta struct {
	DisplayName           string         `json:"displayName"`
	Description           string         `json:"description"`
	Engines               map[string]any `json:"engines"`
	ExtensionDependencies []string       `json:"extensionDependencies"`
	ExtensionPack         []string       `json:"extensionPack"`
}

// parseVSXManifestMeta decodes the served subset of a stored package.json.
func parseVSXManifestMeta(manifest json.RawMessage) vsxManifestMeta {
	var meta vsxManifestMeta
	_ = json.Unmarshal(manifest, &meta)
	return meta
}

// engineVSCode returns the manifest's engines.vscode compatibility range.
func (m vsxManifestMeta) engineVSCode() string {
	v, _ := m.Engines["vscode"].(string)
	return v
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// vsxStoredManifest is the per-version metadata the high side regenerates at
// import time from the archive's own embedded extension/package.json. Gallery
// responses are assembled from these.
type vsxStoredManifest struct {
	Filename string          `json:"filename"`
	Manifest json.RawMessage `json:"manifest"`
}

// publishVSX regenerates the served metadata for every extension in an
// imported bundle from the archive's own embedded package.json. An archive
// that cannot be parsed — or whose embedded identity disagrees with its
// bundle record — is logged and skipped (its version stays out of the
// gallery) rather than wedging the stream's import forever.
func (s *HighServer) publishVSX(m *VSXManifest) error {
	if m == nil {
		return nil
	}
	for _, e := range m.Extensions {
		if err := s.publishVSXExtension(e); err != nil {
			log.Printf("vsx publish %s.%s@%s: %v", e.Publisher, e.Name, e.Version, err)
		}
	}
	return nil
}

// publishVSXExtension regenerates one version's stored metadata, cross-
// checking the archive's embedded package.json identity against the bundle
// record first.
func (s *HighServer) publishVSXExtension(e VSXExtension) error {
	if err := validateVSXName(e.Publisher); err != nil {
		return err
	}
	if err := validateVSXName(e.Name); err != nil {
		return err
	}
	if err := validateVSXVersion(e.Version); err != nil {
		return err
	}
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(e.Path))
	if !strings.HasPrefix(e.Path, "vsx/files/") || !safeJoin(s.vsxFilesDir(), abs) {
		return fmt.Errorf("unsafe archive path %s", e.Path)
	}
	manifest, err := extractVSXPackageJSON(abs)
	if err != nil {
		return err
	}
	if err := vsxCheckManifestIdentity(manifest, e); err != nil {
		return err
	}
	st := vsxStoredManifest{Filename: path.Base(e.Path), Manifest: manifest}
	out := filepath.Join(s.vsxMetadataDir(), e.Publisher, e.Name, e.Version+".json")
	if !safeJoin(s.vsxMetadataDir(), out) {
		return fmt.Errorf("unsafe metadata path for %s.%s@%s", e.Publisher, e.Name, e.Version)
	}
	return writeJSONAtomic(out, st, 0o644)
}

// extractVSXPackageJSON reads the extension manifest embedded in a .vsix
// archive (a zip whose manifest sits at exactly extension/package.json).
func extractVSXPackageJSON(vsixPath string) (json.RawMessage, error) {
	zr, err := zip.OpenReader(vsixPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "extension/package.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, readErr := io.ReadAll(io.LimitReader(rc, vsxMaxPackageJSONBytes))
		if err := errors.Join(readErr, rc.Close()); err != nil {
			return nil, err
		}
		if !json.Valid(b) {
			return nil, errors.New("embedded package.json is not valid JSON")
		}
		return b, nil
	}
	return nil, errors.New("archive has no extension/package.json")
}

// vsxCheckManifestIdentity compares an embedded package.json's identity with
// the bundle record it arrived under: publisher and name case-insensitively
// (registries treat them so), the version exactly.
func vsxCheckManifestIdentity(manifest json.RawMessage, e VSXExtension) error {
	var meta struct {
		Publisher string `json:"publisher"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &meta); err != nil {
		return fmt.Errorf("parse embedded package.json: %w", err)
	}
	if !strings.EqualFold(meta.Publisher, e.Publisher) || !strings.EqualFold(meta.Name, e.Name) {
		return fmt.Errorf("embedded package.json names %s.%s", meta.Publisher, meta.Name)
	}
	if meta.Version != e.Version {
		return fmt.Errorf("embedded package.json version is %q", meta.Version)
	}
	return nil
}

// readVSXStored loads one version's regenerated metadata and checks its
// archive is still present (only complete versions are served).
func (s *HighServer) readVSXStored(publisher, name, version string) (vsxStoredManifest, error) {
	p := filepath.Join(s.vsxMetadataDir(), publisher, name, version+".json")
	if !safeJoin(s.vsxMetadataDir(), p) {
		return vsxStoredManifest{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return vsxStoredManifest{}, err
	}
	var st vsxStoredManifest
	if err := json.Unmarshal(b, &st); err != nil {
		return vsxStoredManifest{}, err
	}
	if st.Filename == "" || strings.ContainsRune(st.Filename, '/') {
		return vsxStoredManifest{}, fmt.Errorf("invalid stored filename for %s.%s@%s", publisher, name, version)
	}
	abs := s.vsxArtifactAbs(publisher, name, st.Filename)
	if !safeJoin(s.vsxFilesDir(), abs) || !fileExists(abs) {
		return vsxStoredManifest{}, fmt.Errorf("archive missing for %s.%s@%s", publisher, name, version)
	}
	return st, nil
}

// vsxServedExtension is one mirrored extension with its servable versions,
// newest first.
type vsxServedExtension struct {
	Publisher string
	Name      string
	Versions  []string
}

// vsxListServed lists every extension with at least one complete version,
// sorted by "publisher.name", from the regenerated metadata store.
func (s *HighServer) vsxListServed() ([]vsxServedExtension, error) {
	pubs, err := os.ReadDir(s.vsxMetadataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []vsxServedExtension
	for _, p := range pubs {
		if p.IsDir() && validateVSXName(p.Name()) == nil {
			out = s.vsxServedUnder(p.Name(), out)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Publisher != out[j].Publisher {
			return out[i].Publisher < out[j].Publisher
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// vsxServedUnder appends one publisher's servable extensions.
func (s *HighServer) vsxServedUnder(publisher string, out []vsxServedExtension) []vsxServedExtension {
	names, err := os.ReadDir(filepath.Join(s.vsxMetadataDir(), publisher))
	if err != nil {
		return out
	}
	for _, n := range names {
		if !n.IsDir() || validateVSXName(n.Name()) != nil {
			continue
		}
		if versions := s.vsxServedVersions(publisher, n.Name()); len(versions) > 0 {
			out = append(out, vsxServedExtension{Publisher: publisher, Name: n.Name(), Versions: versions})
		}
	}
	return out
}

// vsxServedVersions lists one extension's complete versions, newest first.
func (s *HighServer) vsxServedVersions(publisher, name string) []string {
	entries, err := os.ReadDir(filepath.Join(s.vsxMetadataDir(), publisher, name))
	if err != nil {
		return nil
	}
	var versions []string
	for _, e := range entries {
		v := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || v == e.Name() || validateVSXVersion(v) != nil {
			continue
		}
		if _, err := s.readVSXStored(publisher, name, v); err != nil {
			continue
		}
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions("v"+versions[i], "v"+versions[j]) > 0
	})
	return versions
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listVSXExtensions lists the mirrored extensions as "publisher.name" with
// their versions for the dashboard tree.
func (s *HighServer) listVSXExtensions() ([]UIModule, error) {
	served, err := s.vsxListServed()
	if err != nil {
		return nil, err
	}
	out := make([]UIModule, 0, len(served))
	for _, e := range served {
		out = append(out, UIModule{Module: e.Publisher + "." + e.Name, Versions: e.Versions})
	}
	return out, nil
}

// splitVSXDetailSpec parses a dashboard detail spec "publisher.name@version":
// the version after the last "@", the publisher before the first ".".
func splitVSXDetailSpec(spec string) (publisher, name, version string, err error) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 || i == len(spec)-1 {
		return "", "", "", errors.New("invalid extension@version")
	}
	id, version := spec[:i], spec[i+1:]
	publisher, name, ok := strings.Cut(id, ".")
	if !ok || validateVSXName(publisher) != nil || validateVSXName(name) != nil || validateVSXVersion(version) != nil {
		return "", "", "", errors.New("invalid extension or version")
	}
	return publisher, name, version, nil
}

// vsxDetail describes one mirrored extension version for the dashboard
// detail panel.
func (s *HighServer) vsxDetail(spec string) (UIDetail, error) {
	publisher, name, version, err := splitVSXDetailSpec(spec)
	if err != nil {
		return UIDetail{}, err
	}
	st, err := s.readVSXStored(publisher, name, version)
	if err != nil {
		return UIDetail{}, errors.New("version not found")
	}
	meta := parseVSXManifestMeta(st.Manifest)
	id := publisher + "." + name
	fields := []UIDetailField{
		{Label: "Extension", Value: id, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	if meta.DisplayName != "" {
		fields = append(fields, UIDetailField{Label: "Display name", Value: meta.DisplayName})
	}
	if meta.Description != "" {
		fields = append(fields, UIDetailField{Label: "Description", Value: meta.Description})
	}
	if v := meta.engineVSCode(); v != "" {
		fields = append(fields, UIDetailField{Label: "VS Code engine", Value: v, Mono: true})
	}
	abs := s.vsxArtifactAbs(publisher, name, st.Filename)
	if fi, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Archive size", Value: formatBytes(fi.Size())})
	}
	if sum, err := s.detailDigests.get(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	fields = append(fields, UIDetailField{Label: "Asset path", Value: "/vsx/assets/" + publisher + "/" + name + "/" + version, Mono: true})
	downloads := []UIDownload{{Label: st.Filename, URL: "/vsx/files/" + publisher + "/" + name + "/" + st.Filename}}
	return UIDetail{Title: id, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// Low side: extension collector
// -----------------------------------------------------------------------------

// VSXCollectRequest is the body of POST /admin/vsx/collect.
type VSXCollectRequest struct {
	// Extensions lists the extensions to mirror as "publisher.name" (newest
	// version) or "publisher.name@1.2.3" (pinned). Extension dependencies
	// and extension packs are mirrored with them.
	Extensions []string `json:"extensions"`
	// NoDeps limits the collect to exactly the listed extensions, leaving
	// their dependency and pack references unresolved.
	NoDeps bool `json:"no_deps,omitempty"`
	// Force disables export dedup for this collect: every archive is packed
	// even when already forwarded, producing a full self-contained bundle
	// (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// parseVSXSpec splits "publisher.name" or "publisher.name@version". Names
// contain no dots, so the first dot separates publisher from name
// unambiguously; "latest" is accepted as an alias for the newest version.
func parseVSXSpec(spec string) (publisher, name, version string, err error) {
	id, version, _ := strings.Cut(spec, "@")
	publisher, name, ok := strings.Cut(id, ".")
	if !ok {
		return "", "", "", fmt.Errorf("extension %q must be \"publisher.name\"", spec)
	}
	if err := validateVSXName(publisher); err != nil {
		return "", "", "", err
	}
	if err := validateVSXName(name); err != nil {
		return "", "", "", err
	}
	if version == "" || version == "latest" {
		return publisher, name, "", nil
	}
	if err := validateVSXVersion(version); err != nil {
		return "", "", "", fmt.Errorf("extension %s.%s: %w", publisher, name, err)
	}
	return publisher, name, version, nil
}

// validateVSXRequest checks the collect request before any network work.
func validateVSXRequest(req VSXCollectRequest) error {
	if len(req.Extensions) == 0 {
		return errors.New("no extensions provided")
	}
	for _, spec := range req.Extensions {
		if _, _, _, err := parseVSXSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// vsxRegistryBase returns the configured Open VSX registry base URL,
// defaulting to the public open-vsx.org.
func (s *LowServer) vsxRegistryBase() string {
	base := strings.TrimSpace(s.cfg.VSXRegistryURL)
	if base == "" {
		base = defaultVSXRegistryURL
	}
	return strings.TrimSuffix(base, "/")
}

// HandleVSXCollect parses a JSON collect request from the admin endpoint and
// runs the collection.
func (s *LowServer) HandleVSXCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req VSXCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse vsx collect request: %w", err)
		}
	}
	return s.CollectVSX(ctx, req)
}

// CollectVSX resolves the requested extensions against the Open VSX API,
// downloads their .vsix archives — and, unless the request opts out, their
// extension dependencies and pack members at their latest versions — and
// writes them into a signed bundle on the vsx stream. Extensions that cannot
// be resolved or fetched are skipped and reported so one of them never
// blocks the rest of the batch.
func (s *LowServer) CollectVSX(ctx context.Context, req VSXCollectRequest) (ExportResult, error) {
	if err := validateVSXRequest(req); err != nil {
		return ExportResult{}, err
	}
	// Hold only the vsx stream's lock for the whole fetch->write->commit so a
	// concurrent vsx exporter cannot claim the same sequence number between
	// peek and commit. Other streams export in parallel.
	mu := s.streamLock(streamVSX)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "vsx", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	d := &vsxDownloader{base: s.vsxRegistryBase(), stageRoot: stageRoot, noDeps: req.NoDeps, done: map[string]bool{}}
	d.run(ctx, req.Extensions)
	if len(d.exts) == 0 {
		return ExportResult{}, fmt.Errorf("no extensions could be fetched: %s", summarizeFailures(d.failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(d.files))
	res, err := s.exportIfNew(ctx, streamVSX, stageRoot, d.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeVSXBundle(ctx, seq, stageRoot, d.files, d.exts)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = d.failed
	return res, nil
}

// vsxExtensionRef is one dependency or extension-pack member reference from
// upstream metadata. The Open VSX API renders these as objects carrying
// "namespace" plus "extension" (older servers: "name"); some deployments
// flatten them to "publisher.name" strings. All three shapes decode, and an
// unrecognized shape decodes to an empty reference rather than failing the
// extension it appeared under.
type vsxExtensionRef struct {
	Namespace string
	Extension string
}

// UnmarshalJSON decodes the reference shapes described on vsxExtensionRef.
func (r *vsxExtensionRef) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		r.Namespace, r.Extension, _ = strings.Cut(s, ".")
		return nil
	}
	var obj struct {
		Namespace string `json:"namespace"`
		Extension string `json:"extension"`
		Name      string `json:"name"`
	}
	if json.Unmarshal(b, &obj) != nil {
		return nil
	}
	r.Namespace = obj.Namespace
	r.Extension = orDefault(obj.Extension, obj.Name)
	return nil
}

// vsxUpstreamExtension is the subset of an Open VSX
// /api/<namespace>/<name>[/<version>] response ArtiGate reads: the canonical
// identity, the files map (asset kind -> URL; "download" is the .vsix,
// "sha256" its published digest), and the references to resolve next. The
// response's allVersions map is not needed — the versionless endpoint
// already answers with the newest version.
type vsxUpstreamExtension struct {
	Namespace         string            `json:"namespace"`
	Name              string            `json:"name"`
	Version           string            `json:"version"`
	Files             map[string]string `json:"files"`
	Dependencies      []vsxExtensionRef `json:"dependencies"`
	BundledExtensions []vsxExtensionRef `json:"bundledExtensions"`
}

// vsxFetchMetadata fetches and validates one extension's metadata. The
// caller's publisher/name/version are already path-safe, so they embed into
// the URL directly; the response's canonical identity must agree with what
// was asked for (case-insensitively — registries fold case on lookup) and be
// path-safe itself, because it names the storage paths.
func vsxFetchMetadata(ctx context.Context, base, publisher, name, version string) (*vsxUpstreamExtension, error) {
	u := base + "/api/" + publisher + "/" + name
	if version != "" {
		u += "/" + version
	}
	b, err := httpGetBytes(ctx, u, vsxMaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	var ext vsxUpstreamExtension
	if err := json.Unmarshal(b, &ext); err != nil {
		return nil, fmt.Errorf("parse extension metadata: %w", err)
	}
	if validateVSXName(ext.Namespace) != nil || validateVSXName(ext.Name) != nil || validateVSXVersion(ext.Version) != nil {
		return nil, fmt.Errorf("metadata names unusable extension %q.%q@%q", ext.Namespace, ext.Name, ext.Version)
	}
	if !strings.EqualFold(ext.Namespace, publisher) || !strings.EqualFold(ext.Name, name) {
		return nil, fmt.Errorf("metadata is for %s.%s, not %s.%s", ext.Namespace, ext.Name, publisher, name)
	}
	if version != "" && ext.Version != version {
		return nil, fmt.Errorf("metadata is for version %s, not %s", ext.Version, version)
	}
	return &ext, nil
}

// vsxWant is one queued extension to mirror; an empty version means the
// newest.
type vsxWant struct {
	publisher, name, version string
}

// vsxDownloader walks the dependency/pack closure, downloading each
// extension once.
type vsxDownloader struct {
	base      string
	stageRoot string
	noDeps    bool
	exts      []VSXExtension
	files     []ManifestFile
	failed    []FailedModule
	done      map[string]bool // lowercased "publisher.name"; first version selected wins
}

// run resolves and downloads the requested specs and, unless noDeps, their
// dependency and pack closure. Dependencies always resolve to the newest
// version, like a fresh client install does.
func (d *vsxDownloader) run(ctx context.Context, specs []string) {
	queue := make([]vsxWant, 0, len(specs))
	for _, spec := range specs {
		publisher, name, version, _ := parseVSXSpec(spec) // validated with the request
		queue = append(queue, vsxWant{publisher: publisher, name: name, version: version})
	}
	for len(queue) > 0 && len(d.done) < vsxMaxResolved {
		w := queue[0]
		queue = queue[1:]
		key := strings.ToLower(w.publisher + "." + w.name)
		if d.done[key] {
			continue
		}
		d.done[key] = true
		emitProgress(ctx, "→ %s.%s@%s", w.publisher, w.name, orDefault(w.version, "latest"))
		wants, err := d.fetchOne(ctx, w)
		if err != nil {
			emitProgress(ctx, "  ✗ %s.%s: %s", w.publisher, w.name, err)
			d.failed = append(d.failed, FailedModule{Module: w.publisher + "." + w.name, Version: orDefault(w.version, "latest"), Error: err.Error()})
			continue
		}
		if !d.noDeps {
			queue = append(queue, wants...)
		}
	}
}

// fetchOne mirrors one extension: metadata, then the .vsix archive. It
// returns the dependency/pack references to resolve next.
func (d *vsxDownloader) fetchOne(ctx context.Context, w vsxWant) ([]vsxWant, error) {
	ext, err := vsxFetchMetadata(ctx, d.base, w.publisher, w.name, w.version)
	if err != nil {
		return nil, err
	}
	rec, mf, err := d.downloadVSIX(ctx, ext)
	if err != nil {
		return nil, err
	}
	d.exts = append(d.exts, rec)
	d.files = append(d.files, mf)
	return d.refWants(ext), nil
}

// refWants turns an extension's dependency and pack references into queue
// entries, reporting unusable references instead of silently dropping them.
func (d *vsxDownloader) refWants(ext *vsxUpstreamExtension) []vsxWant {
	refs := make([]vsxExtensionRef, 0, len(ext.Dependencies)+len(ext.BundledExtensions))
	refs = append(refs, ext.Dependencies...)
	refs = append(refs, ext.BundledExtensions...)
	var wants []vsxWant
	for _, ref := range refs {
		if ref.Namespace == "" && ref.Extension == "" {
			continue // an unrecognized shape carried nothing to resolve
		}
		if validateVSXName(ref.Namespace) != nil || validateVSXName(ref.Extension) != nil {
			d.failed = append(d.failed, FailedModule{
				Module:  ref.Namespace + "." + ref.Extension,
				Version: "latest",
				Error:   "invalid extension reference in upstream metadata",
			})
			continue
		}
		wants = append(wants, vsxWant{publisher: ref.Namespace, name: ref.Extension})
	}
	return wants
}

// vsxDownloadURL returns the archive URL an extension's metadata advertises
// (files.download), requiring http(s).
func vsxDownloadURL(ext *vsxUpstreamExtension) (string, error) {
	raw := strings.TrimSpace(ext.Files["download"])
	if raw == "" {
		return "", errors.New("metadata lists no download URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("download URL %q is not http(s)", raw)
	}
	return raw, nil
}

// vsxFetchSHA256 resolves an extension's files.sha256 entry to a hex digest.
// Open VSX publishes it as a URL to a small text file carrying the archive's
// digest (bare, or sha256sum-style "digest  filename"); an inlined digest
// value is accepted too. It returns "" when the entry is absent or unusable:
// the digest comes from the same server as the archive over the same TLS
// channel, so it guards transfer corruption rather than a hostile upstream,
// and the download then falls back to TLS trust. A digest that resolves but
// mismatches the archive still fails the download hard.
func vsxFetchSHA256(ctx context.Context, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if d := strings.ToLower(raw); vsxSHA256RE.MatchString(d) {
		return d
	}
	if u, err := url.Parse(raw); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	b, err := httpGetBytes(ctx, raw, vsxMaxDigestBytes)
	if err != nil {
		return ""
	}
	if fields := strings.Fields(string(b)); len(fields) > 0 {
		if d := strings.ToLower(fields[0]); vsxSHA256RE.MatchString(d) {
			return d
		}
	}
	return ""
}

// downloadVSIX fetches one extension archive into the staging tree under its
// canonical path, verifying the registry-published SHA-256 when one exists.
func (d *vsxDownloader) downloadVSIX(ctx context.Context, ext *vsxUpstreamExtension) (VSXExtension, ManifestFile, error) {
	dlURL, err := vsxDownloadURL(ext)
	if err != nil {
		return VSXExtension{}, ManifestFile{}, err
	}
	filename := vsxFilename(ext.Namespace, ext.Name, ext.Version)
	rel := vsxFileRel(ext.Namespace, ext.Name, filename)
	abs := filepath.Join(d.stageRoot, filepath.FromSlash(rel))
	var sum string
	var size int64
	if digest := vsxFetchSHA256(ctx, ext.Files["sha256"]); digest != "" {
		sum, size, err = downloadVerifiedFile(ctx, dlURL, abs, 0, "sha256", digest)
	} else {
		// Without a published digest, integrity rests on TLS to the
		// operator-configured registry, like the other index-less fetches.
		sum, size, err = downloadFileSHA256(ctx, dlURL, abs)
	}
	if err != nil {
		return VSXExtension{}, ManifestFile{}, err
	}
	rec := VSXExtension{Publisher: ext.Namespace, Name: ext.Name, Version: ext.Version, Filename: filename, Path: rel, SHA256: sum}
	return rec, ManifestFile{Path: rel, SHA256: sum, Size: size}, nil
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

// writeVSXBundle writes one signed bundle carrying the collected extensions.
func (s *LowServer) writeVSXBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, exts []VSXExtension) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(exts, func(i, j int) bool {
		if exts[i].Publisher != exts[j].Publisher {
			return exts[i].Publisher < exts[j].Publisher
		}
		if exts[i].Name != exts[j].Name {
			return exts[i].Name < exts[j].Name
		}
		return exts[i].Version < exts[j].Version
	})
	id := bundleIDFor(streamVSX, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamVSX,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"vsx"},
		VSX:              &VSXManifest{Extensions: exts},
		Files:            files,
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: streamVSX, Sequence: seq, ExportedModules: len(exts), BundleID: id}, nil
}
