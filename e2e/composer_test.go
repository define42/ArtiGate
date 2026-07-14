//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestComposer mirrors psr/container 2.0.2 from packagist across the diode
// (its only require is php itself, so the closure adds nothing) and installs
// it from the regenerated Composer v2 repository with the real composer
// client, which re-verifies the injected dist shasum against the zip.
func TestComposer(t *testing.T) {
	stack.Prepare(t)

	res := stack.Collect(t, "composer", map[string]any{"packages": []string{"psr/container:2.0.2"}})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned package, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "composer", res.Sequence)

	// The repository entry point lists the mirrored package...
	code, body := httpGet(t, stack.HighURL+"/composer/packages.json")
	if code != 200 || !strings.Contains(string(body), `"psr/container"`) {
		t.Fatalf("packages.json = %d %s", code, body)
	}
	// ...and its regenerated p2 metadata names the release with a dist URL
	// pointing back at the mirror.
	code, body = httpGet(t, stack.HighURL+"/composer/p2/psr/container.json")
	if code != 200 || !strings.Contains(string(body), `"2.0.2"`) ||
		!strings.Contains(string(body), "/composer/dist/psr/container/") {
		t.Fatalf("p2 metadata = %d %s", code, body)
	}

	composer := requireTool(t, "composer")
	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	// secure-http is off because the harness mirror is plain HTTP on
	// loopback; packagist.org is disabled so every byte must come from the
	// mirror.
	writeFile(t, filepath.Join(proj, "composer.json"), fmt.Sprintf(`{
  "repositories": {
    "packagist.org": false,
    "mirror": {"type": "composer", "url": "%s/composer"}
  },
  "require": {"psr/container": "2.0.2"},
  "config": {"secure-http": false}
}`, stack.HighURL))

	env := []string{
		"COMPOSER_HOME=" + filepath.Join(tmp, "home"),
		"COMPOSER_CACHE_DIR=" + filepath.Join(tmp, "cache"),
		"HOME=" + tmp,
	}
	run(t, proj, env, composer, "install", "--no-interaction", "--prefer-dist")
	installed := filepath.Join(proj, "vendor", "psr", "container", "composer.json")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("installed package missing at %s: %v", installed, err)
	}
}
