//go:build e2e

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// certManagerVersion pins an immutable chart release in the jetstack
// repository, so the collect and the helm pull ask for the same thing.
const certManagerVersion = "v1.16.2"

// TestHelm mirrors a chart from a real classic Helm repository across the
// diode and consumes the regenerated repo with the real helm: repo add +
// update parse the rebuilt index.yaml, and template downloads the archive and
// renders it.
func TestHelm(t *testing.T) {
	stack.Prepare(t)
	helm := requireTool(t, "helm")

	res := stack.Collect(t, "helm", map[string]any{
		"name":   "jetstack",
		"url":    "https://charts.jetstack.io",
		"charts": []string{"cert-manager@" + certManagerVersion},
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned chart, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "helm", res.Sequence)

	// The regenerated index is rebuilt from the chart's own Chart.yaml and
	// links the archive relatively.
	code, body := httpGet(t, stack.HighURL+"/helm/jetstack/index.yaml")
	if code != 200 || !strings.Contains(string(body), "cert-manager") ||
		!strings.Contains(string(body), "charts/cert-manager-"+certManagerVersion+".tgz") {
		t.Fatalf("regenerated index.yaml = %d %s", code, body)
	}

	tmp := t.TempDir()
	helmEnv := []string{
		"HELM_CONFIG_HOME=" + filepath.Join(tmp, "config"),
		"HELM_CACHE_HOME=" + filepath.Join(tmp, "cache"),
		"HELM_DATA_HOME=" + filepath.Join(tmp, "data"),
	}
	run(t, tmp, helmEnv, helm, "repo", "add", "mirror", stack.HighURL+"/helm/jetstack")
	run(t, tmp, helmEnv, helm, "repo", "update")

	// helm pull fetches the archive through the repo index; template renders
	// it — proof the mirrored chart is intact and usable.
	run(t, tmp, helmEnv, helm, "pull", "mirror/cert-manager", "--version", certManagerVersion, "-d", tmp)
	if matches, err := filepath.Glob(filepath.Join(tmp, "cert-manager-*.tgz")); err != nil || len(matches) != 1 {
		t.Fatalf("helm pull left %v (err %v), want one chart archive", matches, err)
	}
	out := run(t, tmp, helmEnv, helm, "template", "test-release", "mirror/cert-manager",
		"--version", certManagerVersion)
	if !strings.Contains(out, "kind: Deployment") {
		t.Fatalf("helm template rendered no Deployment:\n%s", out[:min(len(out), 2048)])
	}
}
