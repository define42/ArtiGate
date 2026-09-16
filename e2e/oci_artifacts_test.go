//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Distribution 3.1.1, pinned by its multi-platform image digest.
const (
	ociFixtureRegistryImage = "registry:3.1.1@sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33"
	ociFixtureRegistryName  = "oci.artigate.test"
)

// TestOCIArtifacts uses real registry clients and a local upstream registry.
// Artifacts cross the same signed HTTP diode as production traffic. Local
// keys and disabled transparency-log integration keep signing self-contained.
func TestOCIArtifacts(t *testing.T) {
	oras := requireTool(t, "oras")
	cosign := requireTool(t, "cosign")
	upstream := startOCIRegistry(t)
	pair := startTestPair(t, pairConfig{
		name: "oci-artifacts", httpDiode: true,
		containerRegistry: ociFixtureRegistryName + "=" + upstream,
	})
	t.Run("native_referrer_graph", func(t *testing.T) {
		testOCINativeArtifacts(t, pair, oras, strings.TrimPrefix(upstream, "http://"))
	})
	t.Run("legacy_cosign_signature", func(t *testing.T) {
		testOCILegacySignature(t, pair, oras, cosign, strings.TrimPrefix(upstream, "http://"))
	})
}

func startOCIRegistry(t *testing.T) string {
	t.Helper()
	return startOCIRegistryImage(t, ociFixtureRegistryImage, []string{"--env", "REGISTRY_LOG_LEVEL=error"})
}

func startOCIRegistryImage(t *testing.T, image string, options []string) string {
	t.Helper()
	requireDocker(t)
	args := append([]string{"run", "--detach", "--rm", "--publish", "127.0.0.1::5000"}, options...)
	args = append(args, image)
	id := strings.TrimSpace(runStdout(t, "", nil, "docker", args...))
	t.Cleanup(func() {
		if t.Failed() {
			_, _ = runAllowFail(t, "", nil, "docker", "logs", id)
		}
		_, _ = runAllowFail(t, "", nil, "docker", "rm", "--force", "--volumes", id)
	})
	port := strings.TrimSpace(runStdout(t, "", nil, "docker", "inspect", "--format",
		`{{(index (index .NetworkSettings.Ports "5000/tcp") 0).HostPort}}`, id))
	base := "http://127.0.0.1:" + port
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/v2/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("local OCI registry did not become ready: %s", base)
	return ""
}

func ociClientEnv(t *testing.T, dir string) []string {
	t.Helper()
	dockerConfig := filepath.Join(dir, "docker-config")
	if err := os.MkdirAll(dockerConfig, 0o755); err != nil {
		t.Fatal(err)
	}
	ociWriteFile(t, filepath.Join(dockerConfig, "config.json"), []byte(`{"auths":{}}`))
	return []string{
		"DOCKER_CONFIG=" + dockerConfig,
		"COSIGN_PASSWORD=artigate-e2e-temporary-key",
		"COSIGN_REPOSITORY=",
		// Client operations must succeed without Rekor, Fulcio, or TUF.
		// Any attempted external HTTP request fails through this closed proxy.
		"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=127.0.0.1,localhost",
	}
}

func testOCINativeArtifacts(t *testing.T, pair *testPair, oras, upstreamHost string) {
	t.Helper()
	dir := t.TempDir()
	env := ociClientEnv(t, dir)
	upstreamRepo := upstreamHost + "/artifacts/native"
	ociWriteFile(t, filepath.Join(dir, "payload.txt"), []byte("mirrored OCI artifact\n"))
	ociWriteFile(t, filepath.Join(dir, "empty.txt"), nil)
	run(t, dir, env, oras, "push", "--plain-http", "--artifact-type", "application/vnd.artigate.test.payload",
		"--export-manifest", "root.json", upstreamRepo+":v1", "payload.txt:text/plain", "empty.txt:text/plain")
	rootDigest := ociManifestDigest(t, filepath.Join(dir, "root.json"))
	ociWriteFile(t, filepath.Join(dir, "attestation.json"), []byte(`{"fixture":"native OCI referrer"}`))
	run(t, dir, env, oras, "attach", "--plain-http", "--artifact-type", "application/vnd.artigate.test.attestation",
		"--export-manifest", "attestation-manifest.json", upstreamRepo+"@"+rootDigest, "attestation.json:application/json")
	attestationDigest := ociManifestDigest(t, filepath.Join(dir, "attestation-manifest.json"))
	ociWriteFile(t, filepath.Join(dir, "attachment.txt"), []byte("attachment of an attachment\n"))
	run(t, dir, env, oras, "attach", "--plain-http", "--artifact-type", "application/vnd.artigate.test.signature",
		"--export-manifest", "nested-manifest.json", upstreamRepo+"@"+attestationDigest, "attachment.txt:text/plain")
	nestedDigest := ociManifestDigest(t, filepath.Join(dir, "nested-manifest.json"))

	collectOCIArtifact(t, pair, "artifacts/native:v1")
	highRef := pair.HighHost + "/" + ociFixtureRegistryName + "/artifacts/native:v1"
	discovered := runStdout(t, dir, env, oras, "discover", "--plain-http", "--format", "json", highRef)
	assertOCIDiscoveryGraph(t, discovered, rootDigest, attestationDigest, nestedDigest)
	run(t, dir, env, oras, "cp", "--recursive", "--from-plain-http", "--to-oci-layout", highRef, "copied:v1")
	copied := runStdout(t, dir, env, oras, "discover", "--oci-layout", "--format", "json", "copied:v1")
	assertOCIDiscoveryGraph(t, copied, rootDigest, attestationDigest, nestedDigest)
	run(t, dir, env, oras, "pull", "--oci-layout", "--output", "pulled", "copied:v1")
	for _, file := range []string{"payload.txt", "empty.txt"} {
		want, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "pulled", file))
		if err != nil || string(got) != string(want) {
			t.Fatalf("copied artifact file %s = %q, error %v; want %q", file, got, err, want)
		}
	}
}

func testOCILegacySignature(t *testing.T, pair *testPair, oras, cosign, upstreamHost string) {
	t.Helper()
	dir := t.TempDir()
	env := ociClientEnv(t, dir)
	upstreamRepo := upstreamHost + "/artifacts/signed"
	ociWriteFile(t, filepath.Join(dir, "payload.txt"), []byte("signed OCI artifact\n"))
	run(t, dir, env, oras, "push", "--plain-http", "--artifact-type", "application/vnd.artigate.test.payload",
		"--export-manifest", "root.json", upstreamRepo+":v1", "payload.txt:text/plain")
	digest := ociManifestDigest(t, filepath.Join(dir, "root.json"))
	run(t, dir, env, cosign, "generate-key-pair")
	run(t, dir, env, cosign, "sign", "--yes", "--key", "cosign.key", "--allow-http-registry",
		"--new-bundle-format=false", "--registry-referrers-mode=legacy", "--tlog-upload=false", "--use-signing-config=false",
		upstreamRepo+"@"+digest)
	sigTag := strings.Replace(digest, ":", "-", 1) + ".sig"
	sigDigest := strings.TrimSpace(runStdout(t, dir, env, oras, "resolve", "--plain-http", upstreamRepo+":"+sigTag))
	collectOCIArtifact(t, pair, "artifacts/signed:v1")
	highRepo := pair.HighHost + "/" + ociFixtureRegistryName + "/artifacts/signed"
	if got := strings.TrimSpace(runStdout(t, dir, env, oras, "resolve", "--plain-http", highRepo+":"+sigTag)); got != sigDigest {
		t.Fatalf("mirrored legacy signature digest = %s, want %s", got, sigDigest)
	}
	verification := runStdout(t, dir, env, cosign, "verify", "--key", "cosign.pub", "--allow-http-registry",
		"--insecure-ignore-tlog", "--offline", "--new-bundle-format=false", highRepo+"@"+digest)
	var claims []struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal([]byte(verification), &claims); err != nil || len(claims) != 1 || claims[0].Critical.Image.Digest != digest {
		t.Fatalf("cosign did not verify the mirrored digest: %s (error %v)", verification, err)
	}
	discovered := runStdout(t, dir, env, oras, "discover", "--plain-http", "--format", "json", highRepo+"@"+digest)
	assertOCIDiscoveryGraph(t, discovered, digest)
	// Legacy signatures remain tag-addressable, but must not masquerade as
	// native subject edges and break ORAS's recursive graph traversal.
	run(t, dir, env, oras, "cp", "--recursive", "--from-plain-http", "--to-oci-layout", highRepo+"@"+digest, "copied:v1")
	assertOCIDiscoveryGraph(t, runStdout(t, dir, env, oras, "discover", "--oci-layout", "--format", "json", "copied:v1"), digest)
}

// A local fixture failure must fail CI rather than use the external-upstream
// retry/skip behavior of Stack.Collect.
func collectOCIArtifact(t *testing.T, pair *testPair, ref string) {
	t.Helper()
	res, err := pair.collectOnce(t, "containers", map[string]any{"images": []string{ociFixtureRegistryName + "/" + ref}})
	if err != nil {
		t.Fatal(err)
	}
	pair.checkResult(t, "containers", res)
	pair.WaitImported(t, "containers", res.Sequence)
}

type ociDiscoveryNode struct {
	Digest    string             `json:"digest"`
	Referrers []ociDiscoveryNode `json:"referrers"`
}

func assertOCIDiscoveryGraph(t *testing.T, body string, digests ...string) {
	t.Helper()
	var node ociDiscoveryNode
	if err := json.Unmarshal([]byte(body), &node); err != nil {
		t.Fatalf("decode ORAS discovery: %v\n%s", err, body)
	}
	for i, digest := range digests {
		if node.Digest != digest {
			t.Fatalf("discovery depth %d digest = %q, want %q\n%s", i, node.Digest, digest, body)
		}
		wantChildren := 0
		if i+1 < len(digests) {
			wantChildren = 1
		}
		if len(node.Referrers) != wantChildren {
			t.Fatalf("discovery depth %d has %d referrers, want %d\n%s", i, len(node.Referrers), wantChildren, body)
		}
		if wantChildren == 1 {
			node = node.Referrers[0]
		}
	}
}

func ociManifestDigest(t *testing.T, filename string) string {
	t.Helper()
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ociWriteFile(t *testing.T, filename string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(fmt.Errorf("write OCI fixture: %w", err))
	}
}
