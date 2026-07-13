package main

// Terraform/OpenTofu ecosystem adapter. The low side speaks the registry
// protocols (registry.terraform.io by default; point --terraform-registry at
// registry.opentofu.org to mirror OpenTofu): it resolves provider versions,
// downloads the per-platform zips together with the upstream SHA256SUMS, its
// GPG signature, and the registry-served signing keys — verifying every zip
// against the registry-declared shasum — and fetches modules from their
// upstream source (https archives, or git via the git tool), packing
// everything into the same numbered, signed ArtiGate bundle format used by
// the other ecosystems. The high side serves the provider and module registry
// protocols regenerated from the artifacts present; terraform's own
// signature chain (shasum -> SHA256SUMS -> GPG key) verifies end-to-end
// against the mirrored upstream signatures.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const defaultTerraformRegistry = "https://registry.terraform.io"

// terraformMaxMetaBytes caps the registry metadata documents (version lists,
// download descriptors, SHA256SUMS, signatures) parsed in memory.
const terraformMaxMetaBytes = 4 << 20

// -----------------------------------------------------------------------------
// Manifest types
// -----------------------------------------------------------------------------

type TerraformManifest struct {
	Providers []TerraformProvider `json:"providers,omitempty"`
	Modules   []TerraformModule   `json:"modules,omitempty"`
}

// TerraformProvider records one mirrored provider version: the per-platform
// zips plus the upstream verification chain (SHA256SUMS, its signature, and
// the registry-served signing keys) terraform validates on install.
type TerraformProvider struct {
	Namespace      string              `json:"namespace"`
	Type           string              `json:"type"`
	Version        string              `json:"version"`
	Protocols      []string            `json:"protocols,omitempty"`
	Platforms      []TerraformPlatform `json:"platforms"`
	SHASumsPath    string              `json:"shasums_path"`
	SHASumsSigPath string              `json:"shasums_sig_path"`
	KeysPath       string              `json:"keys_path"`
}

type TerraformPlatform struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

// TerraformModule records one mirrored module version, repacked as a
// deterministic tar.gz whatever the upstream source form was.
type TerraformModule struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	System    string `json:"system"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}

// -----------------------------------------------------------------------------
// Naming and validation
// -----------------------------------------------------------------------------

// tfTokenRE matches one path-safe registry address token (namespace, type,
// module name, system, os, arch). The first character excludes ".", "_", and
// "-" so a token can never be ".."/"-flag".
var tfTokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validateTfToken(kind, tok string) error {
	if !tfTokenRE.MatchString(tok) {
		return fmt.Errorf("invalid terraform %s %q", kind, tok)
	}
	return nil
}

// tfVersionRE matches a provider/module version, which always starts with a
// digit, so it can never be ".."/"-flag" or contain a path separator.
var tfVersionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

func validateTfVersion(v string) error {
	if !tfVersionRE.MatchString(v) {
		return fmt.Errorf("invalid terraform version %q", v)
	}
	return nil
}

// tfProviderZipName is the release-convention zip filename for one platform.
func tfProviderZipName(typ, version, osName, arch string) string {
	return "terraform-provider-" + typ + "_" + version + "_" + osName + "_" + arch + ".zip"
}

// tfProviderDir is the repository-relative directory of one provider version.
func tfProviderDir(ns, typ, version string) string {
	return path.Join("terraform", "providers", ns, typ, version)
}

// tfModuleRel is the repository-relative path of one module archive.
func tfModuleRel(ns, name, system, version string) string {
	return path.Join("terraform", "modules", ns, name, system, version, "module.tar.gz")
}

// validateTerraformManifest checks every provider and module record of a
// bundle manifest.
func validateTerraformManifest(m *TerraformManifest, seen map[string]bool) error {
	for _, p := range m.Providers {
		if err := validateTerraformProvider(p, seen); err != nil {
			return err
		}
	}
	for _, mod := range m.Modules {
		if err := validateTerraformModule(mod, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateTerraformProvider(p TerraformProvider, seen map[string]bool) error {
	for kind, tok := range map[string]string{"namespace": p.Namespace, "type": p.Type} {
		if err := validateTfToken(kind, tok); err != nil {
			return err
		}
	}
	if err := validateTfVersion(p.Version); err != nil {
		return err
	}
	dir := tfProviderDir(p.Namespace, p.Type, p.Version)
	sums := path.Join(dir, "terraform-provider-"+p.Type+"_"+p.Version+"_SHA256SUMS")
	if p.SHASumsPath != sums || !seen[p.SHASumsPath] {
		return fmt.Errorf("provider %s/%s@%s: SHA256SUMS not listed in manifest.files", p.Namespace, p.Type, p.Version)
	}
	if p.SHASumsSigPath != sums+".sig" || !seen[p.SHASumsSigPath] {
		return fmt.Errorf("provider %s/%s@%s: SHA256SUMS.sig not listed in manifest.files", p.Namespace, p.Type, p.Version)
	}
	if p.KeysPath != path.Join(dir, "signing_keys.json") || !seen[p.KeysPath] {
		return fmt.Errorf("provider %s/%s@%s: signing_keys.json not listed in manifest.files", p.Namespace, p.Type, p.Version)
	}
	if len(p.Platforms) == 0 {
		return fmt.Errorf("provider %s/%s@%s lists no platforms", p.Namespace, p.Type, p.Version)
	}
	for _, pl := range p.Platforms {
		if err := validateTerraformPlatform(p, pl, dir, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateTerraformPlatform(p TerraformProvider, pl TerraformPlatform, dir string, seen map[string]bool) error {
	for kind, tok := range map[string]string{"os": pl.OS, "arch": pl.Arch} {
		if err := validateTfToken(kind, tok); err != nil {
			return err
		}
	}
	if pl.Filename != tfProviderZipName(p.Type, p.Version, pl.OS, pl.Arch) {
		return fmt.Errorf("provider %s/%s@%s has non-canonical zip name %s", p.Namespace, p.Type, p.Version, pl.Filename)
	}
	if pl.Path != path.Join(dir, pl.Filename) || !seen[pl.Path] {
		return fmt.Errorf("provider %s/%s@%s references file not listed in manifest.files: %s", p.Namespace, p.Type, p.Version, pl.Path)
	}
	return nil
}

func validateTerraformModule(m TerraformModule, seen map[string]bool) error {
	for kind, tok := range map[string]string{"namespace": m.Namespace, "name": m.Name, "system": m.System} {
		if err := validateTfToken(kind, tok); err != nil {
			return err
		}
	}
	if err := validateTfVersion(m.Version); err != nil {
		return err
	}
	if m.Path != tfModuleRel(m.Namespace, m.Name, m.System, m.Version) || !seen[m.Path] {
		return fmt.Errorf("module %s/%s/%s@%s references file not listed in manifest.files: %s", m.Namespace, m.Name, m.System, m.Version, m.Path)
	}
	return nil
}

// -----------------------------------------------------------------------------
// High side: registry protocols
// -----------------------------------------------------------------------------

func (s *HighServer) terraformDir() string {
	return filepath.Join(s.downloadDir, "terraform")
}

// serveTerraform handles terraform's service discovery document and the
// provider/module registry protocols under /terraform/. Clients use this host
// directly in source addresses (e.g. "<host>/hashicorp/aws"). It reports
// whether it wrote a response for the request.
func (s *HighServer) serveTerraform(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p == "/.well-known/terraform.json" {
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		// Relative URLs resolve against this document's own URL.
		writeJSON(w, map[string]string{"providers.v1": "/terraform/v1/providers/", "modules.v1": "/terraform/v1/modules/"})
		return true
	}
	if p != "/terraform" && !strings.HasPrefix(p, "/terraform/") {
		return false
	}
	if !isReadMethod(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	rest := strings.TrimPrefix(p, "/terraform")
	switch {
	case strings.HasPrefix(rest, "/v1/providers/"):
		s.handleTfProviderAPI(w, r, strings.TrimPrefix(rest, "/v1/providers/"))
	case strings.HasPrefix(rest, "/v1/modules/"):
		s.handleTfModuleAPI(w, r, strings.TrimPrefix(rest, "/v1/modules/"))
	case strings.HasPrefix(rest, "/providers/") || strings.HasPrefix(rest, "/modules/"):
		s.handleTfFile(w, r, strings.Trim(rest, "/"))
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

// handleTfFile serves the artifact files: provider zips, SHA256SUMS(.sig),
// and module archives. The stored metadata/keys files stay private (their
// content is embedded in the API responses).
func (s *HighServer) handleTfFile(w http.ResponseWriter, r *http.Request, rel string) {
	if validateRelPath(rel) != nil || !tfServablePath(rel) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.terraformDir(), filepath.FromSlash(strings.TrimPrefix(rel, "terraform/")))
	if !safeJoin(s.terraformDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

// tfServablePath restricts the served files to the client-facing artifacts.
func tfServablePath(rel string) bool {
	segs := strings.Split(rel, "/")
	switch {
	case len(segs) == 6 && segs[0] == "providers":
		f := segs[5]
		return strings.HasSuffix(f, ".zip") || strings.HasSuffix(f, "_SHA256SUMS") || strings.HasSuffix(f, "_SHA256SUMS.sig")
	case len(segs) == 7 && segs[0] == "modules":
		return segs[6] == "module.tar.gz"
	}
	return false
}

// tfStoredProvider is the per-version metadata regenerated at import.
type tfStoredProvider struct {
	Protocols []string            `json:"protocols,omitempty"`
	Platforms []TerraformPlatform `json:"platforms"`
}

// handleTfProviderAPI dispatches {ns}/{type}/versions and
// {ns}/{type}/{version}/download/{os}/{arch}.
func (s *HighServer) handleTfProviderAPI(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case len(segs) == 3 && segs[2] == "versions":
		s.handleTfProviderVersions(w, segs[0], segs[1])
	case len(segs) == 6 && segs[3] == "download":
		s.handleTfProviderDownload(w, r, segs)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// readTfProviderMeta loads one provider version's stored metadata, with every
// platform gated on its zip being present.
func (s *HighServer) readTfProviderMeta(ns, typ, version string) (tfStoredProvider, error) {
	if validateTfToken("namespace", ns) != nil || validateTfToken("type", typ) != nil || validateTfVersion(version) != nil {
		return tfStoredProvider{}, errors.New("invalid provider address")
	}
	p := filepath.Join(s.terraformDir(), "providers", ns, typ, version, "metadata.json")
	if !safeJoin(s.terraformDir(), p) {
		return tfStoredProvider{}, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return tfStoredProvider{}, err
	}
	var st tfStoredProvider
	if err := json.Unmarshal(b, &st); err != nil {
		return tfStoredProvider{}, err
	}
	present := st.Platforms[:0]
	for _, pl := range st.Platforms {
		abs := filepath.Join(s.downloadDir, filepath.FromSlash(pl.Path))
		if safeJoin(s.terraformDir(), abs) && fileExists(abs) {
			present = append(present, pl)
		}
	}
	st.Platforms = present
	return st, nil
}

func (s *HighServer) handleTfProviderVersions(w http.ResponseWriter, ns, typ string) {
	if validateTfToken("namespace", ns) != nil || validateTfToken("type", typ) != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dir := filepath.Join(s.terraformDir(), "providers", ns, typ)
	if !safeJoin(s.terraformDir(), dir) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) || err == nil && len(entries) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var versions []map[string]any
	for _, e := range entries {
		st, err := s.readTfProviderMeta(ns, typ, e.Name())
		if err != nil || len(st.Platforms) == 0 {
			continue
		}
		platforms := make([]map[string]string, 0, len(st.Platforms))
		for _, pl := range st.Platforms {
			platforms = append(platforms, map[string]string{"os": pl.OS, "arch": pl.Arch})
		}
		versions = append(versions, map[string]any{"version": e.Name(), "protocols": st.Protocols, "platforms": platforms})
	}
	if len(versions) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions("v"+versions[i]["version"].(string), "v"+versions[j]["version"].(string)) < 0
	})
	writeJSON(w, map[string]any{"versions": versions})
}

func (s *HighServer) handleTfProviderDownload(w http.ResponseWriter, r *http.Request, segs []string) {
	ns, typ, version, osName, arch := segs[0], segs[1], segs[2], segs[4], segs[5]
	st, err := s.readTfProviderMeta(ns, typ, version)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var platform *TerraformPlatform
	for i := range st.Platforms {
		if st.Platforms[i].OS == osName && st.Platforms[i].Arch == arch {
			platform = &st.Platforms[i]
			break
		}
	}
	if platform == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	keys, err := s.readTfSigningKeys(ns, typ, version)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	base := npmBaseURL(r) + "/terraform/" + tfProviderDir(ns, typ, version)[len("terraform/"):]
	sums := "terraform-provider-" + typ + "_" + version + "_SHA256SUMS"
	writeJSON(w, map[string]any{
		"protocols":             st.Protocols,
		"os":                    osName,
		"arch":                  arch,
		"filename":              platform.Filename,
		"download_url":          base + "/" + platform.Filename,
		"shasums_url":           base + "/" + sums,
		"shasums_signature_url": base + "/" + sums + ".sig",
		"shasum":                platform.SHA256,
		"signing_keys":          keys,
	})
}

// readTfSigningKeys loads the registry-served signing keys mirrored alongside
// a provider version.
func (s *HighServer) readTfSigningKeys(ns, typ, version string) (json.RawMessage, error) {
	p := filepath.Join(s.terraformDir(), "providers", ns, typ, version, "signing_keys.json")
	if !safeJoin(s.terraformDir(), p) {
		return nil, errors.New("unsafe path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("stored signing keys are not valid JSON")
	}
	return json.RawMessage(b), nil
}

// handleTfModuleAPI dispatches {ns}/{name}/{system}/versions and
// {ns}/{name}/{system}/{version}/download.
func (s *HighServer) handleTfModuleAPI(w http.ResponseWriter, r *http.Request, rest string) {
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	for _, tok := range segs {
		if validateRelPath(tok) != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	switch {
	case len(segs) == 4 && segs[3] == "versions":
		s.handleTfModuleVersions(w, segs[0], segs[1], segs[2])
	case len(segs) == 5 && segs[4] == "download":
		s.handleTfModuleDownload(w, r, segs[0], segs[1], segs[2], segs[3])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// tfModuleVersions lists one module's mirrored versions (ascending), gated on
// the archive being present.
func (s *HighServer) tfModuleVersions(ns, name, system string) []string {
	if validateTfToken("namespace", ns) != nil || validateTfToken("name", name) != nil || validateTfToken("system", system) != nil {
		return nil
	}
	dir := filepath.Join(s.terraformDir(), "modules", ns, name, system)
	if !safeJoin(s.terraformDir(), dir) {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if validateTfVersion(e.Name()) != nil {
			continue
		}
		if fileExists(filepath.Join(dir, e.Name(), "module.tar.gz")) {
			out = append(out, e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool { return compareVersions("v"+out[i], "v"+out[j]) < 0 })
	return out
}

func (s *HighServer) handleTfModuleVersions(w http.ResponseWriter, ns, name, system string) {
	versions := s.tfModuleVersions(ns, name, system)
	if len(versions) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	list := make([]map[string]string, 0, len(versions))
	for _, v := range versions {
		list = append(list, map[string]string{"version": v})
	}
	writeJSON(w, map[string]any{"modules": []any{map[string]any{"versions": list}}})
}

func (s *HighServer) handleTfModuleDownload(w http.ResponseWriter, r *http.Request, ns, name, system, version string) {
	if validateTfVersion(version) != nil || !containsString(s.tfModuleVersions(ns, name, system), version) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// go-getter unpacks the archive by its .tar.gz suffix.
	w.Header().Set("X-Terraform-Get", npmBaseURL(r)+"/"+tfModuleRel(ns, name, system, version))
	w.WriteHeader(http.StatusNoContent)
}

// -----------------------------------------------------------------------------
// High side: dashboard tree/detail
// -----------------------------------------------------------------------------

// listTerraformItems lists the mirrored providers and modules as
// slash-separated addresses ("providers/hashicorp/aws",
// "modules/org/vpc/aws") with their versions.
func (s *HighServer) listTerraformItems() ([]UIModule, error) {
	var out []UIModule
	for _, kind := range []struct {
		prefix string
		depth  int
	}{{"providers", 2}, {"modules", 3}} {
		items, err := s.listTfAddresses(kind.prefix, kind.depth)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out, nil
}

// listTfAddresses walks terraform/<prefix> to the given address depth and
// lists each address's version directories.
func (s *HighServer) listTfAddresses(prefix string, depth int) ([]UIModule, error) {
	root := filepath.Join(s.terraformDir(), prefix)
	var out []UIModule
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil || rel == "." {
			return nil
		}
		segs := strings.Split(filepath.ToSlash(rel), "/")
		if len(segs) != depth {
			return nil
		}
		versions := tfVersionDirs(p)
		if len(versions) > 0 {
			out = append(out, UIModule{Module: prefix + "/" + filepath.ToSlash(rel), Versions: versions})
		}
		return filepath.SkipDir
	})
	return out, err
}

// tfVersionDirs lists the version subdirectories of one address, ascending.
func tfVersionDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && validateTfVersion(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool { return compareVersions("v"+out[i], "v"+out[j]) < 0 })
	return out
}

// terraformDetail describes one mirrored provider or module version for the
// dashboard detail panel. spec is "providers/<ns>/<type>@<version>" or
// "modules/<ns>/<name>/<system>@<version>".
func (s *HighServer) terraformDetail(spec string) (UIDetail, error) {
	addr, version, ok := strings.Cut(spec, "@")
	if !ok || validateTfVersion(version) != nil {
		return UIDetail{}, errors.New("invalid address@version")
	}
	segs := strings.Split(addr, "/")
	switch {
	case len(segs) == 3 && segs[0] == "providers":
		return s.tfProviderDetail(segs[1], segs[2], version)
	case len(segs) == 4 && segs[0] == "modules":
		return s.tfModuleDetail(segs[1], segs[2], segs[3], version)
	}
	return UIDetail{}, errors.New("invalid terraform address")
}

func (s *HighServer) tfProviderDetail(ns, typ, version string) (UIDetail, error) {
	st, err := s.readTfProviderMeta(ns, typ, version)
	if err != nil || len(st.Platforms) == 0 {
		return UIDetail{}, errors.New("version not found")
	}
	fields := []UIDetailField{
		{Label: "Provider", Value: ns + "/" + typ, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	if len(st.Protocols) > 0 {
		fields = append(fields, UIDetailField{Label: "Protocols", Value: strings.Join(st.Protocols, ", ")})
	}
	var downloads []UIDownload
	for _, pl := range st.Platforms {
		fields = append(fields, UIDetailField{Label: pl.OS + "/" + pl.Arch, Value: pl.SHA256, Mono: true})
		downloads = append(downloads, UIDownload{Label: pl.Filename, URL: "/" + pl.Path})
	}
	return UIDetail{Title: ns + "/" + typ, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

func (s *HighServer) tfModuleDetail(ns, name, system, version string) (UIDetail, error) {
	if !containsString(s.tfModuleVersions(ns, name, system), version) {
		return UIDetail{}, errors.New("version not found")
	}
	rel := tfModuleRel(ns, name, system, version)
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(rel))
	fields := []UIDetailField{
		{Label: "Module", Value: ns + "/" + name + "/" + system, Mono: true},
		{Label: "Version", Value: version, Mono: true},
	}
	if st, err := os.Stat(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "Archive size", Value: formatBytes(st.Size())})
	}
	if sum, err := sha256File(abs); err == nil {
		fields = append(fields, UIDetailField{Label: "SHA-256", Value: sum, Mono: true})
	}
	downloads := []UIDownload{{Label: "module.tar.gz", URL: "/" + rel}}
	return UIDetail{Title: ns + "/" + name + "/" + system, Subtitle: version, Fields: fields, Downloads: downloads}, nil
}

// -----------------------------------------------------------------------------
// High side: metadata regeneration at import
// -----------------------------------------------------------------------------

// publishTerraform regenerates the served provider metadata for an imported
// bundle. A provider version whose verification chain does not line up is
// logged and skipped (it 404s) rather than wedging the stream's import
// forever. Modules need no regeneration — their protocol is served straight
// from the directory layout.
func (s *HighServer) publishTerraform(m *TerraformManifest) error {
	if m == nil {
		return nil
	}
	for _, p := range m.Providers {
		if err := s.publishTerraformProvider(p); err != nil {
			log.Printf("terraform publish %s/%s@%s: %v", p.Namespace, p.Type, p.Version, err)
		}
	}
	return nil
}

// publishTerraformProvider cross-checks each installed zip against the
// mirrored SHA256SUMS (the document terraform verifies the GPG signature of)
// and merges the version's platforms into its stored metadata.
func (s *HighServer) publishTerraformProvider(p TerraformProvider) error {
	sums, err := s.readTfSHA256SUMS(p)
	if err != nil {
		return err
	}
	for _, pl := range p.Platforms {
		abs := filepath.Join(s.downloadDir, filepath.FromSlash(pl.Path))
		if !safeJoin(s.terraformDir(), abs) || !fileExists(abs) {
			return fmt.Errorf("provider zip missing: %s", pl.Path)
		}
		if !strings.EqualFold(sums[pl.Filename], pl.SHA256) {
			return fmt.Errorf("SHA256SUMS does not cover %s with the delivered digest", pl.Filename)
		}
	}
	out := filepath.Join(s.terraformDir(), "providers", p.Namespace, p.Type, p.Version, "metadata.json")
	if !safeJoin(s.terraformDir(), out) {
		return errors.New("unsafe metadata path")
	}
	st := tfStoredProvider{Protocols: p.Protocols, Platforms: p.Platforms}
	if b, err := os.ReadFile(out); err == nil {
		var prev tfStoredProvider
		if json.Unmarshal(b, &prev) == nil {
			st.Platforms = mergeTfPlatforms(prev.Platforms, p.Platforms)
		}
	}
	return writeJSONAtomic(out, st, 0o644)
}

// readTfSHA256SUMS parses the mirrored SHA256SUMS document into
// filename -> digest.
func (s *HighServer) readTfSHA256SUMS(p TerraformProvider) (map[string]string, error) {
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(p.SHASumsPath))
	if !strings.HasPrefix(p.SHASumsPath, "terraform/providers/") || !safeJoin(s.terraformDir(), abs) {
		return nil, fmt.Errorf("unsafe SHA256SUMS path %s", p.SHASumsPath)
	}
	b, err := readFileLimit(abs, terraformMaxMetaBytes)
	if err != nil {
		return nil, err
	}
	return parseSHA256SUMS(string(b)), nil
}

// parseSHA256SUMS parses "digest  filename" lines.
func parseSHA256SUMS(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && len(fields[0]) == 64 {
			out[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
		}
	}
	return out
}

// mergeTfPlatforms unions the platform lists of successive bundles (a mirror
// may add darwin builds after linux ones), the newer record winning per
// os/arch.
func mergeTfPlatforms(prev, next []TerraformPlatform) []TerraformPlatform {
	byKey := map[string]TerraformPlatform{}
	var order []string
	for _, list := range [][]TerraformPlatform{prev, next} {
		for _, pl := range list {
			key := pl.OS + "_" + pl.Arch
			if _, ok := byKey[key]; !ok {
				order = append(order, key)
			}
			byKey[key] = pl
		}
	}
	sort.Strings(order)
	out := make([]TerraformPlatform, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

// -----------------------------------------------------------------------------
// Low side: collector
// -----------------------------------------------------------------------------

// TerraformCollectRequest is the body of POST /admin/terraform/collect.
//
// Providers lists provider addresses ("hashicorp/aws" for the newest release,
// "hashicorp/aws@5.50.0" to pin), mirrored for each requested platform
// ("linux_amd64" by default). Modules lists registry module addresses
// ("terraform-aws-modules/vpc/aws", optionally @version). Registry overrides
// the configured upstream registry for this collect (e.g. to mirror OpenTofu
// from registry.opentofu.org).
type TerraformCollectRequest struct {
	Providers []string `json:"providers,omitempty"`
	Modules   []string `json:"modules,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
	Registry  string   `json:"registry,omitempty"`
	// Force disables export dedup for this collect: everything is packed even
	// when already forwarded, producing a full self-contained bundle (for
	// disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// tfProviderSpec is a parsed provider address with an optional version pin.
type tfProviderSpec struct {
	ns, typ, version string
}

// tfModuleSpec is a parsed module address with an optional version pin.
type tfModuleSpec struct {
	ns, name, system, version string
}

func parseTfProviderSpec(spec string) (tfProviderSpec, error) {
	addr, version, _ := strings.Cut(spec, "@")
	parts := strings.Split(addr, "/")
	if len(parts) != 2 {
		return tfProviderSpec{}, fmt.Errorf("provider %q must be namespace/type", spec)
	}
	out := tfProviderSpec{ns: parts[0], typ: parts[1], version: version}
	if err := validateTfToken("namespace", out.ns); err != nil {
		return tfProviderSpec{}, err
	}
	if err := validateTfToken("type", out.typ); err != nil {
		return tfProviderSpec{}, err
	}
	if version != "" && version != "latest" {
		if err := validateTfVersion(version); err != nil {
			return tfProviderSpec{}, err
		}
	} else {
		out.version = ""
	}
	return out, nil
}

func parseTfModuleSpec(spec string) (tfModuleSpec, error) {
	addr, version, _ := strings.Cut(spec, "@")
	parts := strings.Split(addr, "/")
	if len(parts) != 3 {
		return tfModuleSpec{}, fmt.Errorf("module %q must be namespace/name/system", spec)
	}
	out := tfModuleSpec{ns: parts[0], name: parts[1], system: parts[2], version: version}
	for kind, tok := range map[string]string{"namespace": out.ns, "name": out.name, "system": out.system} {
		if err := validateTfToken(kind, tok); err != nil {
			return tfModuleSpec{}, err
		}
	}
	if version != "" && version != "latest" {
		if err := validateTfVersion(version); err != nil {
			return tfModuleSpec{}, err
		}
	} else {
		out.version = ""
	}
	return out, nil
}

// tfPlatforms parses the requested "os_arch" platform list.
func tfPlatforms(req TerraformCollectRequest) ([][2]string, error) {
	names := req.Platforms
	if len(names) == 0 {
		names = []string{"linux_amd64"}
	}
	out := make([][2]string, 0, len(names))
	for _, name := range dedupeStrings(names) {
		osName, arch, ok := strings.Cut(name, "_")
		if !ok || validateTfToken("os", osName) != nil || validateTfToken("arch", arch) != nil {
			return nil, fmt.Errorf("invalid platform %q (want os_arch, e.g. linux_amd64)", name)
		}
		out = append(out, [2]string{osName, arch})
	}
	return out, nil
}

func validateTerraformRequest(req TerraformCollectRequest) error {
	if len(req.Providers) == 0 && len(req.Modules) == 0 {
		return errors.New("no providers or modules provided")
	}
	if req.Registry != "" {
		if u, err := url.Parse(req.Registry); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("registry %q must be an http(s) URL", req.Registry)
		}
	}
	for _, spec := range req.Providers {
		if _, err := parseTfProviderSpec(spec); err != nil {
			return err
		}
	}
	for _, spec := range req.Modules {
		if _, err := parseTfModuleSpec(spec); err != nil {
			return err
		}
	}
	_, err := tfPlatforms(req)
	return err
}

// HandleTerraformCollect parses a JSON collect request from the admin
// endpoint and runs the collection.
func (s *LowServer) HandleTerraformCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req TerraformCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse terraform collect request: %w", err)
		}
	}
	return s.CollectTerraform(ctx, req)
}

// terraformRegistry is the upstream registry for one collect.
func (s *LowServer) terraformRegistry(req TerraformCollectRequest) string {
	if req.Registry != "" {
		return strings.TrimSuffix(req.Registry, "/")
	}
	if s.cfg.TerraformRegistry != "" {
		return strings.TrimSuffix(s.cfg.TerraformRegistry, "/")
	}
	return defaultTerraformRegistry
}

// CollectTerraform mirrors the requested providers (for each requested
// platform, with the upstream verification chain) and modules from the
// registry, and writes them into a signed bundle on the terraform stream.
// Items that cannot be fetched are skipped and reported so one of them never
// blocks the rest of the batch.
func (s *LowServer) CollectTerraform(ctx context.Context, req TerraformCollectRequest) (ExportResult, error) {
	if err := validateTerraformRequest(req); err != nil {
		return ExportResult{}, err
	}
	mu := s.streamLock(streamTerraform)
	mu.Lock()
	defer mu.Unlock()

	stagingBase := filepath.Join(s.cfg.Root, "terraform", "staging")
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		return ExportResult{}, err
	}
	stageRoot, err := os.MkdirTemp(stagingBase, "collect-")
	if err != nil {
		return ExportResult{}, err
	}
	defer os.RemoveAll(stageRoot)

	registry := s.terraformRegistry(req)
	emitProgress(ctx, "Discovering registry services at %s…", registry)
	disc, err := tfDiscover(ctx, registry)
	if err != nil {
		return ExportResult{}, err
	}
	col := &tfCollector{s: s, stageRoot: stageRoot, disc: disc}
	manifest, failed := col.collectAll(ctx, req)
	if len(manifest.Providers) == 0 && len(manifest.Modules) == 0 {
		return ExportResult{}, fmt.Errorf("nothing could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(col.files))

	res, err := s.exportIfNew(ctx, streamTerraform, stageRoot, col.files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeTerraformBundle(ctx, seq, stageRoot, col.files, manifest)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// tfDiscovery holds the service URLs from a registry's discovery document.
type tfDiscovery struct {
	providers string
	modules   string
}

// tfDiscover reads /.well-known/terraform.json and resolves the (possibly
// relative) service URLs.
func tfDiscover(ctx context.Context, registry string) (tfDiscovery, error) {
	b, err := httpGetBytes(ctx, registry+"/.well-known/terraform.json", 1<<20)
	if err != nil {
		return tfDiscovery{}, err
	}
	var doc struct {
		Providers string `json:"providers.v1"`
		Modules   string `json:"modules.v1"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return tfDiscovery{}, fmt.Errorf("parse discovery document: %w", err)
	}
	base, err := url.Parse(registry + "/.well-known/terraform.json")
	if err != nil {
		return tfDiscovery{}, err
	}
	out := tfDiscovery{}
	if out.providers, err = tfResolveService(base, doc.Providers); err != nil {
		return tfDiscovery{}, err
	}
	if out.modules, err = tfResolveService(base, doc.Modules); err != nil {
		return tfDiscovery{}, err
	}
	return out, nil
}

func tfResolveService(base *url.URL, svc string) (string, error) {
	if svc == "" {
		return "", nil
	}
	ref, err := url.Parse(svc)
	if err != nil {
		return "", fmt.Errorf("invalid service URL %q", svc)
	}
	u := base.ResolveReference(ref)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("service URL %q is not http(s)", u.String())
	}
	return strings.TrimSuffix(u.String(), "/") + "/", nil
}

// tfCollector accumulates the staged files of one collect.
type tfCollector struct {
	s         *LowServer
	stageRoot string
	disc      tfDiscovery
	files     []ManifestFile
}

// stageBytes writes one small in-memory document into the staging tree and
// records it in the manifest file list.
func (c *tfCollector) stageBytes(rel string, data []byte) (ManifestFile, error) {
	abs := filepath.Join(c.stageRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ManifestFile{}, err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return ManifestFile{}, err
	}
	mf, err := hashManifestFile(abs, rel)
	if err != nil {
		return ManifestFile{}, err
	}
	c.files = append(c.files, mf)
	return mf, nil
}

// collectProvider mirrors one provider version for the requested platforms.
func (c *tfCollector) collectProvider(ctx context.Context, spec tfProviderSpec, platforms [][2]string) (TerraformProvider, error) {
	if c.disc.providers == "" {
		return TerraformProvider{}, errors.New("registry does not offer the providers.v1 service")
	}
	version, err := c.pickProviderVersion(ctx, spec)
	if err != nil {
		return TerraformProvider{}, err
	}
	emitProgress(ctx, "→ provider %s/%s@%s", spec.ns, spec.typ, version)
	p := TerraformProvider{Namespace: spec.ns, Type: spec.typ, Version: version}
	var chain *tfChain
	for _, platform := range platforms {
		dl, err := c.fetchProviderDownload(ctx, spec, version, platform[0], platform[1])
		if err != nil {
			return TerraformProvider{}, err
		}
		pl, got, err := c.stageProviderPlatform(ctx, spec, version, dl)
		if err != nil {
			return TerraformProvider{}, err
		}
		p.Protocols = dl.Protocols
		p.Platforms = append(p.Platforms, pl)
		if chain == nil {
			chain = got
		}
	}
	return c.stageProviderChain(p, chain)
}

// collectAll mirrors every requested provider and module, reporting the ones
// that could not be fetched so one never blocks the rest of the batch.
func (c *tfCollector) collectAll(ctx context.Context, req TerraformCollectRequest) (*TerraformManifest, []FailedModule) {
	platforms, _ := tfPlatforms(req)
	manifest := &TerraformManifest{}
	var failed []FailedModule
	for _, spec := range req.Providers {
		parsed, _ := parseTfProviderSpec(spec)
		// A provider that fails part-way (say, one platform's checksum) must
		// not leave its already-staged files in the bundle without a manifest
		// record referencing them.
		mark := len(c.files)
		if p, err := c.collectProvider(ctx, parsed, platforms); err != nil {
			c.files = c.files[:mark]
			emitProgress(ctx, "  ✗ %s: %s", spec, err)
			failed = append(failed, FailedModule{Module: parsed.ns + "/" + parsed.typ, Version: orDefault(parsed.version, "latest"), Error: err.Error()})
		} else {
			manifest.Providers = append(manifest.Providers, p)
		}
	}
	for _, spec := range req.Modules {
		parsed, _ := parseTfModuleSpec(spec)
		if m, err := c.collectModule(ctx, parsed); err != nil {
			emitProgress(ctx, "  ✗ %s: %s", spec, err)
			failed = append(failed, FailedModule{Module: parsed.ns + "/" + parsed.name + "/" + parsed.system, Version: orDefault(parsed.version, "latest"), Error: err.Error()})
		} else {
			manifest.Modules = append(manifest.Modules, m)
		}
	}
	return manifest, failed
}

// tfChain carries a provider version's verification-chain documents.
type tfChain struct {
	sums, sig, keys []byte
}

// pickProviderVersion resolves the version a provider spec pins or the newest
// release.
func (c *tfCollector) pickProviderVersion(ctx context.Context, spec tfProviderSpec) (string, error) {
	if spec.version != "" {
		return spec.version, nil
	}
	b, err := httpGetBytes(ctx, c.disc.providers+spec.ns+"/"+spec.typ+"/versions", terraformMaxMetaBytes)
	if err != nil {
		return "", err
	}
	var doc struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("parse provider versions: %w", err)
	}
	best := ""
	for _, v := range doc.Versions {
		if validateTfVersion(v.Version) != nil {
			continue
		}
		if parseSemver("v"+v.Version).pre != "" {
			continue
		}
		if best == "" || compareVersions("v"+best, "v"+v.Version) < 0 {
			best = v.Version
		}
	}
	if best == "" {
		return "", errors.New("no release versions found upstream")
	}
	return best, nil
}

// tfDownloadDoc is the registry's per-platform download descriptor.
type tfDownloadDoc struct {
	Protocols           []string        `json:"protocols"`
	OS                  string          `json:"os"`
	Arch                string          `json:"arch"`
	Filename            string          `json:"filename"`
	DownloadURL         string          `json:"download_url"`
	SHASumsURL          string          `json:"shasums_url"`
	SHASumsSignatureURL string          `json:"shasums_signature_url"`
	SHASum              string          `json:"shasum"`
	SigningKeys         json.RawMessage `json:"signing_keys"`
}

func (c *tfCollector) fetchProviderDownload(ctx context.Context, spec tfProviderSpec, version, osName, arch string) (tfDownloadDoc, error) {
	b, err := httpGetBytes(ctx, c.disc.providers+spec.ns+"/"+spec.typ+"/"+version+"/download/"+osName+"/"+arch, terraformMaxMetaBytes)
	if err != nil {
		return tfDownloadDoc{}, err
	}
	var doc tfDownloadDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return tfDownloadDoc{}, fmt.Errorf("parse download descriptor: %w", err)
	}
	doc.OS, doc.Arch = osName, arch
	if len(doc.SHASum) != 64 || doc.DownloadURL == "" || doc.SHASumsURL == "" || doc.SHASumsSignatureURL == "" {
		return tfDownloadDoc{}, errors.New("download descriptor is missing the shasum, download, or signature URLs")
	}
	return doc, nil
}

// stageProviderPlatform downloads one platform zip (verified against the
// registry-declared shasum) and collects the version's verification-chain
// documents.
func (c *tfCollector) stageProviderPlatform(ctx context.Context, spec tfProviderSpec, version string, dl tfDownloadDoc) (TerraformPlatform, *tfChain, error) {
	filename := tfProviderZipName(spec.typ, version, dl.OS, dl.Arch)
	rel := path.Join(tfProviderDir(spec.ns, spec.typ, version), filename)
	abs := filepath.Join(c.stageRoot, filepath.FromSlash(rel))
	sum, size, err := downloadVerifiedFile(ctx, dl.DownloadURL, abs, 0, "sha256", dl.SHASum)
	if err != nil {
		return TerraformPlatform{}, nil, err
	}
	c.files = append(c.files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	sums, err := httpGetBytes(ctx, dl.SHASumsURL, terraformMaxMetaBytes)
	if err != nil {
		return TerraformPlatform{}, nil, err
	}
	if got := parseSHA256SUMS(string(sums))[filename]; !strings.EqualFold(got, dl.SHASum) {
		return TerraformPlatform{}, nil, fmt.Errorf("SHA256SUMS does not list %s with the registry-declared digest", filename)
	}
	sig, err := httpGetBytes(ctx, dl.SHASumsSignatureURL, terraformMaxMetaBytes)
	if err != nil {
		return TerraformPlatform{}, nil, err
	}
	if len(dl.SigningKeys) == 0 || !json.Valid(dl.SigningKeys) {
		return TerraformPlatform{}, nil, errors.New("download descriptor carries no signing keys")
	}
	pl := TerraformPlatform{OS: dl.OS, Arch: dl.Arch, Filename: filename, Path: rel, SHA256: strings.ToLower(dl.SHASum)}
	return pl, &tfChain{sums: sums, sig: sig, keys: dl.SigningKeys}, nil
}

// stageProviderChain writes the verification-chain files (SHA256SUMS, its
// signature, the signing keys) into the staging tree once per provider
// version and records their manifest paths.
func (c *tfCollector) stageProviderChain(p TerraformProvider, chain *tfChain) (TerraformProvider, error) {
	if chain == nil {
		return TerraformProvider{}, errors.New("no platform delivered the verification chain")
	}
	dir := tfProviderDir(p.Namespace, p.Type, p.Version)
	sumsRel := path.Join(dir, "terraform-provider-"+p.Type+"_"+p.Version+"_SHA256SUMS")
	if _, err := c.stageBytes(sumsRel, chain.sums); err != nil {
		return TerraformProvider{}, err
	}
	if _, err := c.stageBytes(sumsRel+".sig", chain.sig); err != nil {
		return TerraformProvider{}, err
	}
	if _, err := c.stageBytes(path.Join(dir, "signing_keys.json"), chain.keys); err != nil {
		return TerraformProvider{}, err
	}
	p.SHASumsPath = sumsRel
	p.SHASumsSigPath = sumsRel + ".sig"
	p.KeysPath = path.Join(dir, "signing_keys.json")
	return p, nil
}

// collectModule mirrors one module version, repacking its source tree into a
// deterministic tar.gz.
func (c *tfCollector) collectModule(ctx context.Context, spec tfModuleSpec) (TerraformModule, error) {
	if c.disc.modules == "" {
		return TerraformModule{}, errors.New("registry does not offer the modules.v1 service")
	}
	version, err := c.pickModuleVersion(ctx, spec)
	if err != nil {
		return TerraformModule{}, err
	}
	emitProgress(ctx, "→ module %s/%s/%s@%s", spec.ns, spec.name, spec.system, version)
	source, err := c.fetchModuleSource(ctx, spec, version)
	if err != nil {
		return TerraformModule{}, err
	}
	rel := tfModuleRel(spec.ns, spec.name, spec.system, version)
	abs := filepath.Join(c.stageRoot, filepath.FromSlash(rel))
	sum, size, err := c.s.fetchTerraformModuleArchive(ctx, source, abs)
	if err != nil {
		return TerraformModule{}, err
	}
	c.files = append(c.files, ManifestFile{Path: rel, SHA256: sum, Size: size})
	return TerraformModule{Namespace: spec.ns, Name: spec.name, System: spec.system, Version: version, Path: rel, SHA256: sum}, nil
}

func (c *tfCollector) pickModuleVersion(ctx context.Context, spec tfModuleSpec) (string, error) {
	if spec.version != "" {
		return spec.version, nil
	}
	b, err := httpGetBytes(ctx, c.disc.modules+spec.ns+"/"+spec.name+"/"+spec.system+"/versions", terraformMaxMetaBytes)
	if err != nil {
		return "", err
	}
	var doc struct {
		Modules []struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("parse module versions: %w", err)
	}
	best := ""
	for _, m := range doc.Modules {
		for _, v := range m.Versions {
			if validateTfVersion(v.Version) != nil || parseSemver("v"+v.Version).pre != "" {
				continue
			}
			if best == "" || compareVersions("v"+best, "v"+v.Version) < 0 {
				best = v.Version
			}
		}
	}
	if best == "" {
		return "", errors.New("no release versions found upstream")
	}
	return best, nil
}

// fetchModuleSource asks the registry where a module version's source lives:
// a 204 with X-Terraform-Get, or a 200 body naming a location.
func (c *tfCollector) fetchModuleSource(ctx context.Context, spec tfModuleSpec, version string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	dlURL := c.disc.modules + spec.ns + "/" + spec.name + "/" + spec.system + "/" + version + "/download"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Terraform-Get"); got != "" {
		return resolveTfGet(dlURL, got)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var doc struct {
		Location string `json:"location"`
	}
	if resp.StatusCode == http.StatusOK && json.Unmarshal(body, &doc) == nil && doc.Location != "" {
		return resolveTfGet(dlURL, doc.Location)
	}
	return "", fmt.Errorf("GET %s: HTTP %d with no X-Terraform-Get", dlURL, resp.StatusCode)
}

// resolveTfGet resolves a relative X-Terraform-Get value against the download
// endpoint URL.
func resolveTfGet(dlURL, got string) (string, error) {
	if strings.HasPrefix(got, "/") || strings.HasPrefix(got, "./") || strings.HasPrefix(got, "../") {
		base, err := url.Parse(dlURL)
		if err != nil {
			return "", err
		}
		ref, err := url.Parse(got)
		if err != nil {
			return "", err
		}
		return base.ResolveReference(ref).String(), nil
	}
	return got, nil
}

// fetchTerraformModuleArchive materializes a module source as a deterministic
// tar.gz at abs: https archive sources download directly; git:: sources are
// cloned with the git tool and repacked.
func (s *LowServer) fetchTerraformModuleArchive(ctx context.Context, source, abs string) (string, int64, error) {
	if gitURL, ok := strings.CutPrefix(source, "git::"); ok {
		return s.packGitModule(ctx, gitURL, abs)
	}
	u, err := url.Parse(source)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", 0, fmt.Errorf("unsupported module source %q (only git:: and http(s) archives are mirrored)", source)
	}
	if !strings.HasSuffix(u.Path, ".tar.gz") && !strings.HasSuffix(u.Path, ".tgz") && u.Query().Get("archive") != "tar.gz" {
		return "", 0, fmt.Errorf("unsupported module source %q (not a tar.gz archive)", source)
	}
	u.RawQuery = ""
	return downloadFileSHA256(ctx, u.String(), abs)
}

// packGitModule clones a git module source ("<repo-url>[//subdir]?ref=<ref>")
// and repacks the requested tree deterministically.
func (s *LowServer) packGitModule(ctx context.Context, gitURL, abs string) (string, int64, error) {
	repoURL, subdir, ref, err := splitGitSource(gitURL)
	if err != nil {
		return "", 0, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(abs), "git-")
	if err != nil {
		return "", 0, err
	}
	defer os.RemoveAll(tmp)
	if err := s.gitCloneModule(ctx, repoURL, ref, tmp); err != nil {
		return "", 0, err
	}
	root := tmp
	if subdir != "" {
		if validateRelPath(subdir) != nil {
			return "", 0, fmt.Errorf("unsafe module subdirectory %q", subdir)
		}
		root = filepath.Join(tmp, filepath.FromSlash(subdir))
		if !safeJoin(tmp, root) {
			return "", 0, fmt.Errorf("unsafe module subdirectory %q", subdir)
		}
	}
	if err := packDirTarGz(root, abs); err != nil {
		return "", 0, err
	}
	mf, err := hashManifestFile(abs, "module.tar.gz")
	if err != nil {
		return "", 0, err
	}
	return mf.SHA256, mf.Size, nil
}

// splitGitSource splits a go-getter git URL into the repository URL, the
// optional //subdir, and the ?ref= revision.
func splitGitSource(gitURL string) (repoURL, subdir, ref string, err error) {
	u, err := url.Parse(gitURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", "", fmt.Errorf("unsupported git source %q (only http(s) remotes are mirrored)", gitURL)
	}
	ref = u.Query().Get("ref")
	u.RawQuery = ""
	if i := strings.Index(u.Path, "//"); i >= 0 {
		subdir = strings.Trim(u.Path[i+2:], "/")
		u.Path = u.Path[:i]
	}
	return u.String(), subdir, ref, nil
}

// gitCloneModule clones one revision of a module repository with the git
// tool. A tag or branch ref clones shallowly; any other revision falls back
// to a full clone plus checkout.
func (s *LowServer) gitCloneModule(ctx context.Context, repoURL, ref, dir string) error {
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	if _, err := s.runGit(ctx, append(args, "--", repoURL, dir)...); err == nil {
		return nil
	} else if ref == "" {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if _, err := s.runGit(ctx, "clone", "--", repoURL, dir); err != nil {
		return err
	}
	_, err := s.runGit(ctx, "-C", dir, "checkout", "--detach", ref)
	return err
}

func (s *LowServer) runGit(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	bin := s.cfg.GitBinary
	if bin == "" {
		bin = "git"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("git %s failed: %w\n%s", strings.Join(args, " "), err, tailBytes(out, 4096))
	}
	return out, nil
}

// packDirTarGz packs a directory into a deterministic tar.gz: sorted paths,
// epoch timestamps, fixed ownership, and normalized modes, so re-collecting
// an unchanged module produces identical bytes and dedups cleanly. The .git
// tree and symlinks are skipped.
func packDirTarGz(root, dst string) error {
	rels, err := listModuleTreeFiles(root)
	if err != nil {
		return err
	}
	if len(rels) == 0 {
		return errors.New("module source tree is empty")
	}
	sort.Strings(rels)
	files := make([]ManifestFile, 0, len(rels))
	for _, rel := range rels {
		st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		files = append(files, ManifestFile{Path: rel, Size: st.Size()})
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return createTarGzAtomic(context.Background(), dst, root, files)
}

// listModuleTreeFiles walks a module checkout, returning the regular files'
// slash-relative paths, skipping the .git tree and non-regular entries.
func listModuleTreeFiles(root string) ([]string, error) {
	var rels []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == ".git":
			return filepath.SkipDir
		case d.IsDir() || !d.Type().IsRegular():
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	return rels, err
}

// -----------------------------------------------------------------------------
// Bundle writing
// -----------------------------------------------------------------------------

func (s *LowServer) writeTerraformBundle(ctx context.Context, seq int64, stageRoot string, files []ManifestFile, m *TerraformManifest) (ExportResult, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	id := bundleIDFor(streamTerraform, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           streamTerraform,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"terraform"},
		Terraform:        m,
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, stageRoot, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	count := len(m.Providers) + len(m.Modules)
	return ExportResult{Stream: streamTerraform, Sequence: seq, ExportedModules: count, BundleID: id}, nil
}
