//go:build e2e

package e2e

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Pinned, immutable registry.terraform.io releases: a tiny provider and a
// pure-HCL module whose registry source is a git:: GitHub URL (the usual
// form), so the collect exercises the git fetch+repack path too.
const (
	tfE2EProviderVersion = "3.2.2" // hashicorp/null
	tfE2EModuleVersion   = "1.0.0" // hashicorp/subnets/cidr
)

// TestTerraform mirrors a provider (zips + SHA256SUMS + signature + signing
// keys) and a registry module from the real registry.terraform.io, then runs
// a real `terraform init` (or `tofu init`) against the mirror. terraform
// requires HTTPS for registry hosts, so the bundle is also imported into a
// second high side that serves a self-signed certificate, trusted via
// SSL_CERT_FILE — terraform's own verification chain (shasum → SHA256SUMS →
// GPG signature) runs unchanged against the mirrored documents.
func TestTerraform(t *testing.T) {
	stack.Prepare(t)
	terraform := requireTool(t, "terraform", "tofu")

	res := stack.Collect(t, "terraform", map[string]any{
		"providers": []string{"hashicorp/null@" + tfE2EProviderVersion},
		"modules":   []string{"hashicorp/subnets/cidr@" + tfE2EModuleVersion},
	})
	if res.ExportedModules != 2 {
		t.Fatalf("expected the provider and the module, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "terraform", res.Sequence)

	// The plain-HTTP high side already serves the protocol; spot-check the
	// discovery document and the download descriptor before the TLS leg.
	code, body := httpGet(t, stack.HighURL+"/.well-known/terraform.json")
	if code != 200 || !strings.Contains(string(body), "providers.v1") {
		t.Fatalf("discovery document = %d %s", code, body)
	}
	code, body = httpGet(t, stack.HighURL+
		"/terraform/v1/providers/hashicorp/null/"+tfE2EProviderVersion+"/download/linux/amd64")
	if code != 200 || !strings.Contains(string(body), "shasums_signature_url") ||
		!strings.Contains(string(body), "gpg_public_keys") {
		t.Fatalf("download descriptor = %d %s", code, body)
	}

	high := tfE2EStartTLSHigh(t, res.BundleID)
	caFile := tfE2EServerCertPEM(t, high.host)

	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "main.tf"), fmt.Sprintf(`terraform {
  required_providers {
    null = {
      source  = "%[1]s/hashicorp/null"
      version = "= %[2]s"
    }
  }
}

module "subnets" {
  source  = "%[1]s/hashicorp/subnets/cidr"
  version = "= %[3]s"

  base_cidr_block = "10.0.0.0/8"
  networks        = []
}

resource "null_resource" "probe" {}
`, high.host, tfE2EProviderVersion, tfE2EModuleVersion))

	env := []string{
		"HOME=" + tmp, // no ~/.terraformrc surprises
		"SSL_CERT_FILE=" + caFile,
		"CHECKPOINT_DISABLE=1",
		"TF_IN_AUTOMATION=1",
	}
	out := run(t, tmp, env, terraform, "init", "-backend=false", "-input=false", "-no-color")
	if !strings.Contains(out, "hashicorp/null v"+tfE2EProviderVersion) ||
		!strings.Contains(out, "has been successfully initialized") {
		t.Fatalf("terraform init did not install the mirrored provider:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".terraform", "modules", "subnets", "main.tf")); err != nil {
		t.Fatalf("mirrored module not unpacked: %v", err)
	}
	// validate loads the provider plugin from the mirrored zip — proof the
	// artifact is a working binary, not just a well-hashed blob.
	out = run(t, tmp, env, terraform, "validate", "-no-color")
	if !strings.Contains(out, "Success!") {
		t.Fatalf("terraform validate: %s", out)
	}
}

// tfE2EHigh is the TLS-serving high side of the terraform test.
type tfE2EHigh struct {
	srv  *server
	host string // "127.0.0.1:<port>" — the registry host in source addresses
}

// tfE2EStartTLSHigh starts a second high server with a self-signed
// certificate, feeds it the already-exported bundle from the low side's
// archive, and waits for the import.
func tfE2EStartTLSHigh(t *testing.T, bundleID string) tfE2EHigh {
	t.Helper()
	root := filepath.Join(stack.WorkDir, "tf-high-root")
	landing := filepath.Join(stack.WorkDir, "tf-high-landing")
	for _, d := range []string{root, landing} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		src := filepath.Join(stack.WorkDir, "low-root", "bundles", bundleID+suffix)
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("reading archived bundle: %v", err)
		}
		if err := os.WriteFile(filepath.Join(landing, bundleID+suffix), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pub := filepath.Join(stack.WorkDir, "keys", "high.ed25519.pub")
	logPath := filepath.Join(stack.WorkDir, "tf-high.log")
	env := []string{
		"ARTIGATE_TLS_MODE=auto-generate-certificate",
		"ARTIGATE_TLS_DOMAINS=localhost,127.0.0.1",
	}
	var srv *server
	var port int
	for attempt := 1; ; attempt++ {
		var err error
		port, err = pickFreePort()
		if err != nil {
			t.Fatal(err)
		}
		srv, err = launch(stack.Bin, []string{
			"high",
			"--listen", fmt.Sprintf("127.0.0.1:%d", port),
			"--root", root,
			"--landing", landing,
			"--public-key", pub,
			"--import-interval", "1s",
		}, env, logPath)
		if err != nil {
			t.Fatal(err)
		}
		srv.url = fmt.Sprintf("https://127.0.0.1:%d", port)
		if err := tfE2EWaitTLSHealthz(srv); err == nil {
			break
		}
		srv.stop()
		if attempt == 3 {
			logTail(t, logPath)
			t.Fatal("TLS high side did not become healthy after 3 attempts")
		}
	}
	t.Cleanup(srv.stop)
	t.Cleanup(func() {
		if t.Failed() {
			logTail(t, logPath)
		}
	})

	// terraform requires a module registry hostname to contain a dot, so the
	// source addresses use the dotted loopback IP (covered by the generated
	// certificate's IP SAN), never "localhost".
	high := tfE2EHigh{srv: srv, host: fmt.Sprintf("127.0.0.1:%d", port)}
	tfE2EWaitTLSImported(t, high)
	return high
}

// tfE2EInsecureClient trusts nothing on purpose: it exists only to reach the
// self-signed server before its certificate has been extracted.
func tfE2EInsecureClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fetching the self-signed cert to pin it
		},
	}
}

func tfE2EWaitTLSHealthz(srv *server) error {
	client := tfE2EInsecureClient()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-srv.done:
			return fmt.Errorf("process exited before becoming healthy: %v", srv.waitErr)
		default:
		}
		resp, err := client.Get(srv.url + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("no healthy /healthz within 30s")
}

// tfE2EWaitTLSImported polls the TLS high side until the terraform provider
// versions endpoint answers — the import of the copied bundle is done.
func tfE2EWaitTLSImported(t *testing.T, high tfE2EHigh) {
	t.Helper()
	client := tfE2EInsecureClient()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		resp, err := client.Get(high.srv.url + "/terraform/v1/providers/hashicorp/null/versions")
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(b), tfE2EProviderVersion) {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("TLS high side never served the imported provider versions")
}

// tfE2EServerCertPEM connects once (insecurely) to capture the self-signed
// certificate and writes it as a PEM file terraform can trust via
// SSL_CERT_FILE.
func tfE2EServerCertPEM(t *testing.T, host string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", "127.0.0.1:"+host[strings.LastIndex(host, ":")+1:],
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // capturing the cert to pin it
	if err != nil {
		t.Fatalf("dialing the TLS high side: %v", err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("TLS high side presented no certificate")
	}
	out := filepath.Join(t.TempDir(), "artigate-e2e-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
	if err := os.WriteFile(out, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}
