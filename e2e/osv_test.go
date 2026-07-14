//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// lodashAdvisoryID is a GitHub-reviewed 2021 lodash advisory (CVE-2021-23337,
// fixed in 4.17.21). Published GHSA records are permanent, so both the
// advisory route and the audit assertions below stay stable.
const lodashAdvisoryID = "GHSA-35jh-r3h4-6jhm"

// TestOsv mirrors the real OSV "npm" advisory database across the diode,
// checks the high side serves it in the upstream bucket's layout
// (ecosystems.txt, all.zip, single advisories), and then proves the point of
// the stream: a real `npm audit` against the mirror — with a known-vulnerable
// lodash mirrored on the npm stream — flags the vulnerability without ever
// reaching the public registry.
func TestOsv(t *testing.T) {
	stack.Prepare(t)

	res := stack.Collect(t, "osv", map[string]any{"ecosystems": []string{"npm"}})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly one database, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "osv", res.Sequence)

	code, body := httpGet(t, stack.HighURL+"/osv/ecosystems.txt")
	if code != 200 || !strings.Contains(string(body), "npm") {
		t.Fatalf("ecosystems.txt = %d %q", code, body)
	}
	code, prefix, size := httpGetPrefix(t, stack.HighURL+"/osv/npm/all.zip", 4)
	if code != 200 || !bytes.HasPrefix(prefix, []byte("PK")) || size <= 0 {
		t.Fatalf("all.zip = %d, prefix %q, %d byte(s); want a zip archive", code, prefix, size)
	}
	code, body = httpGet(t, stack.HighURL+"/osv/npm/"+lodashAdvisoryID+".json")
	if code != 200 || !strings.Contains(string(body), `"`+lodashAdvisoryID+`"`) {
		t.Fatalf("advisory %s = %d %.200s", lodashAdvisoryID, code, body)
	}

	// The regenerated bulk-audit endpoint answers a plain-JSON query (the npm
	// CLI exercises the gzip path below).
	resp, err := http.Post(stack.HighURL+"/npm/-/npm/v1/security/advisories/bulk",
		"application/json", strings.NewReader(`{"lodash":["4.17.20"]}`))
	if err != nil {
		t.Fatalf("bulk audit POST: %v", err)
	}
	var bulk map[string][]struct {
		URL                string `json:"url"`
		VulnerableVersions string `json:"vulnerable_versions"`
	}
	err = json.NewDecoder(resp.Body).Decode(&bulk)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || err != nil || len(bulk["lodash"]) == 0 {
		t.Fatalf("bulk audit = %d (decode: %v), lodash advisories: %+v", resp.StatusCode, err, bulk["lodash"])
	}

	npm := requireTool(t, "npm")

	// npm audit resolves advisory metadata against its configured registry,
	// so the vulnerable package must be mirrored too — which is exactly the
	// deployment story: packages on the npm stream, advisories on osv.
	npmRes := stack.Collect(t, "npm", map[string]any{"packages": []string{"lodash@4.17.20"}})
	stack.WaitImported(t, "npm", npmRes.Sequence)

	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	writeFile(t, filepath.Join(proj, "package.json"), `{"name":"e2e-audit","version":"1.0.0","private":true}`)
	writeFile(t, filepath.Join(proj, ".npmrc"), fmt.Sprintf(`registry=%s/npm/
cache=%s
fund=false
update-notifier=false
`, stack.HighURL, filepath.Join(tmp, "npm-cache")))
	env := []string{"HOME=" + filepath.Join(tmp, "home")}
	run(t, proj, env, npm, "install", "lodash@4.17.20", "--package-lock-only", "--no-audit", "--no-fund")

	// A vulnerable dependency makes `npm audit` exit non-zero and name the
	// package — the CLI gzip-POSTs the bulk endpoint and renders our OSV-fed
	// response.
	out, err := runAllowFail(t, proj, env, npm, "audit")
	if err == nil {
		t.Fatalf("npm audit reported no vulnerabilities for lodash@4.17.20:\n%s", out)
	}
	for _, want := range []string{"lodash", "severity"} {
		if !strings.Contains(out, want) {
			t.Errorf("npm audit output lacks %q:\n%s", want, out)
		}
	}
}
