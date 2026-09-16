//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errorLensVersion pins an immutable ErrorLens release on open-vsx.org, so
// the collect and the gallery assertions ask for the same thing.
const errorLensVersion = "3.16.0"

// TestVSX mirrors a real extension from open-vsx.org across the diode and
// consumes it through the served Marketplace gallery protocol: an exact-id
// extensionquery must advertise a VSIXPackage asset, and that asset must
// download as a zip. A real VS Code-compatible client then installs the pinned
// extension while restricted to the high-side mirror.
func TestVSX(t *testing.T) {
	stack.Prepare(t)
	client := requireTool(t, "codium", "codium-insiders", "code-oss")

	res := stack.Collect(t, "vsx", map[string]any{
		"extensions": []string{"usernamehw.errorlens@" + errorLensVersion},
	})
	// ErrorLens declares no extension dependencies or pack members, so the
	// pinned extension is the bundle's only unit.
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned extension, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "vsx", res.Sequence)

	// The gallery query a VS Code-compatible client sends when asked to
	// install "usernamehw.errorlens" (filterType 7 = exact extension id).
	query := map[string]any{
		"filters": []map[string]any{{
			"criteria":   []map[string]any{{"filterType": 7, "value": "usernamehw.errorlens"}},
			"pageNumber": 1,
			"pageSize":   50,
		}},
		"flags": 950,
	}
	code, body := vsxPostJSON(t, stack.HighURL+"/vsx/gallery/extensionquery", query)
	if code != 200 {
		t.Fatalf("extensionquery status %d: %s", code, body)
	}
	source := vsxPackageSource(t, body)
	if !strings.HasPrefix(source, stack.HighURL+"/vsx/") {
		t.Fatalf("gallery advertised an asset outside the high side: %s", source)
	}

	// The advertised package asset downloads as a non-trivial zip archive.
	code, prefix, length := httpGetPrefix(t, source, 2)
	if code != 200 {
		t.Fatalf("GET %s: status %d", source, code)
	}
	if string(prefix) != "PK" {
		t.Fatalf("vsix from %s does not start with the zip magic: %q", source, prefix)
	}
	if length < 10*1024 {
		t.Fatalf("vsix from %s is implausibly small: %d bytes", source, length)
	}

	vsxInstallWithClient(t, client)
}

// vsxPostJSON posts a JSON body and returns status and response body (the
// shared e2e helpers only cover GET).
func vsxPostJSON(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal gallery query: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST %s: reading body: %v", url, err)
	}
	return resp.StatusCode, b
}

// vsxPackageSource digs the pinned version's VSIXPackage source URL out of an
// extensionquery response, failing loudly on any shape surprise.
func vsxPackageSource(t *testing.T, body []byte) string {
	t.Helper()
	var doc struct {
		Results []struct {
			Extensions []struct {
				ExtensionName string `json:"extensionName"`
				Publisher     struct {
					PublisherName string `json:"publisherName"`
				} `json:"publisher"`
				Versions []struct {
					Version string `json:"version"`
					Files   []struct {
						AssetType string `json:"assetType"`
						Source    string `json:"source"`
					} `json:"files"`
				} `json:"versions"`
			} `json:"extensions"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("extensionquery response is not JSON: %v\n%s", err, body)
	}
	if len(doc.Results) != 1 || len(doc.Results[0].Extensions) != 1 {
		t.Fatalf("extensionquery did not list exactly the mirrored extension: %s", body)
	}
	ext := doc.Results[0].Extensions[0]
	if ext.Publisher.PublisherName != "usernamehw" || ext.ExtensionName != "errorlens" {
		t.Fatalf("extensionquery listed %s.%s, want usernamehw.errorlens", ext.Publisher.PublisherName, ext.ExtensionName)
	}
	for _, v := range ext.Versions {
		if v.Version != errorLensVersion {
			continue
		}
		for _, f := range v.Files {
			if f.AssetType == "Microsoft.VisualStudio.Services.VSIXPackage" && f.Source != "" {
				return f.Source
			}
		}
	}
	t.Fatalf("no VSIXPackage source for version %s in: %s", errorLensVersion, body)
	return ""
}

func vsxInstallWithClient(t *testing.T, client string) {
	t.Helper()
	tmp := t.TempDir()
	extDir := filepath.Join(tmp, "ext")
	userDir := filepath.Join(tmp, "user")
	writeFile(t, filepath.Join(userDir, "User", "settings.json"), `{"telemetry.telemetryLevel":"off","extensions.autoCheckUpdates":false,"extensions.autoUpdate":false,"update.mode":"none"}`)
	env := vsxGalleryEnvironment(stack.HighURL)
	receiver := newReceiver(t, stack.HighURL)
	args := []string{"--no-sandbox", "--user-data-dir", userDir, "--extensions-dir", extDir}
	pinned := "usernamehw.errorlens@" + errorLensVersion
	receiver.Run(t, tmp, env, client, append(args, "--install-extension", pinned, "--force")...)
	installed := receiver.RunStdout(t, tmp, env, client, append(args, "--list-extensions", "--show-versions")...)
	if !strings.Contains(installed, pinned) {
		t.Fatalf("client does not list the installed pinned extension: %s", installed)
	}
	matches, err := filepath.Glob(filepath.Join(extDir, "usernamehw.errorlens-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("no usernamehw.errorlens-* directory under %s (matches %v, err %v)", extDir, matches, err)
	}
	vsxCheckInstalledManifest(t, matches[0])
}

func vsxGalleryEnvironment(base string) []string {
	return []string{
		"VSCODE_GALLERY_SERVICE_URL=" + base + "/vsx/gallery",
		"VSCODE_GALLERY_ITEM_URL=" + base + "/vsx/item",
		"VSCODE_GALLERY_CONTROL_URL=" + base + "/vsx/gallery/control",
		"VSCODE_GALLERY_LATEST_URL_TEMPLATE=" + base + "/vsx/gallery/{publisher}/{name}/latest",
		"VSCODE_GALLERY_EXTENSION_URL_TEMPLATE=" + base + "/vsx/assets/{publisher}/{name}/{version}/Microsoft.VisualStudio.Code.Manifest",
		"VSCODE_GALLERY_RESOURCE_URL_TEMPLATE=" + base + "/vsx/assets/{publisher}/{name}/{version}/{path}",
	}
}

func vsxCheckInstalledManifest(t *testing.T, dir string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Publisher string `json:"publisher"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Main      string `json:"main"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Publisher != "usernamehw" || manifest.Name != "errorlens" || manifest.Version != errorLensVersion || manifest.Main == "" {
		t.Fatalf("unexpected installed extension manifest: %s", body)
	}
	if _, err := os.Stat(filepath.Join(dir, manifest.Main)); err != nil {
		t.Fatalf("installed extension entry point is missing: %v", err)
	}
}
