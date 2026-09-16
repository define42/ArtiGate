//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	cosignBundleMediaType     = "application/vnd.dev.sigstore.bundle.v0.3+json"
	cosignSignaturePredicate  = "https://sigstore.dev/cosign/sign/v1"
	cosignFixturePredicate    = "https://artigate.test/attestation/v1"
	cosignPredicateAnnotation = "dev.sigstore.bundle.predicateType"
)

// Both signatures and attestations in Cosign's new format are Sigstore bundles
// containing DSSE in-toto statements about the original manifest digest. Exercise
// native registry discovery first, then verify only high-side bytes in a separate
// network namespace. No Fulcio identity, Rekor entry, or online trust root is used.
func testOCIModernCosign(t *testing.T, pair *testPair, oras, cosign, upstreamHost string) {
	t.Helper()
	dir := t.TempDir()
	env := ociClientEnv(t, dir)
	upstreamRepo := upstreamHost + "/artifacts/modern-cosign"
	ociWriteFile(t, filepath.Join(dir, "payload.txt"), []byte("modern signed OCI artifact\n"))
	ociWriteFile(t, filepath.Join(dir, "predicate.json"), []byte(`{"builder":"ArtiGate offline fixture","result":"passed"}`))
	run(t, dir, env, oras, "push", "--plain-http", "--artifact-type", "application/vnd.artigate.test.payload",
		"--export-manifest", "root.json", upstreamRepo+":v1", "payload.txt:text/plain")
	digest := ociManifestDigest(t, filepath.Join(dir, "root.json"))
	run(t, dir, env, cosign, "generate-key-pair", "--output-key-prefix", "trusted")
	run(t, dir, env, cosign, "generate-key-pair", "--output-key-prefix", "wrong")
	run(t, dir, env, cosign, "sign", "--yes", "--key", "trusted.key", "--allow-http-registry",
		"--new-bundle-format=true", "--tlog-upload=false", "--use-signing-config=false",
		"--bundle", "signature.sigstore.json", upstreamRepo+"@"+digest)
	run(t, dir, env, cosign, "attest", "--yes", "--key", "trusted.key", "--allow-http-registry",
		"--new-bundle-format=true", "--tlog-upload=false", "--use-signing-config=false",
		"--predicate", "predicate.json", "--type", cosignFixturePredicate,
		"--bundle", "attestation.sigstore.json", upstreamRepo+"@"+digest)

	collectOCIArtifact(t, pair, "artifacts/modern-cosign:v1")
	highRepo := pair.HighHost + "/" + ociFixtureRegistryName + "/artifacts/modern-cosign"
	// These real Cosign registry commands must discover native bundles through
	// high. The fully isolated verification below is the network-boundary proof.
	run(t, dir, env, cosign, "verify", "--key", "trusted.pub", "--allow-http-registry",
		"--new-bundle-format=true", "--insecure-ignore-tlog", "--offline", highRepo+"@"+digest)
	run(t, dir, env, cosign, "verify-attestation", "--key", "trusted.pub", "--allow-http-registry",
		"--new-bundle-format=true", "--insecure-ignore-tlog", "--offline", "--type", cosignFixturePredicate, highRepo+"@"+digest)

	// Only public keys and bytes obtained from high enter this directory. Private
	// keys, source bundles, and the upstream registry are unavailable to Docker.
	verifyDir := t.TempDir()
	for _, key := range []string{"trusted.pub", "wrong.pub"} {
		ociWriteFile(t, filepath.Join(verifyDir, key), readOCIFile(t, filepath.Join(dir, key)))
	}
	run(t, verifyDir, env, oras, "manifest", "fetch", "--plain-http", "--output", "root.json", highRepo+"@"+digest)
	if got := ociManifestDigest(t, filepath.Join(verifyDir, "root.json")); got != digest {
		t.Fatalf("high manifest digest = %s, want %s", got, digest)
	}
	ociWriteFile(t, filepath.Join(verifyDir, "tampered-root.json"), append(readOCIFile(t, filepath.Join(verifyDir, "root.json")), '\n'))
	bundles := fetchHighCosignBundles(t, verifyDir, env, oras, highRepo, digest)
	for _, tc := range []struct {
		name, predicate, source string
	}{
		{"signature", cosignSignaturePredicate, "signature.sigstore.json"},
		{"attestation", cosignFixturePredicate, "attestation.sigstore.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, ok := bundles[tc.predicate]
			if !ok {
				t.Fatalf("missing native bundle with predicate %q", tc.predicate)
			}
			body := readOCIFile(t, filepath.Join(verifyDir, bundle))
			if !bytes.Equal(body, readOCIFile(t, filepath.Join(dir, tc.source))) {
				t.Fatal("high bundle bytes differ from Cosign's signed source bundle")
			}
			tampered := "tampered-" + bundle
			ociWriteFile(t, filepath.Join(verifyDir, tampered), tamperCosignBundle(t, body))
			for _, check := range []struct {
				name, key, bundle, artifact, wantError string
			}{
				{"valid", "trusted.pub", bundle, "root.json", ""},
				{"wrong_signer", "wrong.pub", bundle, "root.json", "signature"},
				{"tampered_subject", "trusted.pub", bundle, "tampered-root.json", "digest"},
				{"tampered_bundle", "trusted.pub", tampered, "root.json", "signature"},
			} {
				t.Run(check.name, func(t *testing.T) {
					out, err := verifyCosignOffline(t, cosign, verifyDir, tc.predicate, check.key, check.bundle, check.artifact)
					if check.wantError == "" {
						if err != nil || !strings.Contains(out, "Verified OK") {
							t.Fatalf("isolated bundle verification: %v\n%s", err, out)
						}
						return
					}
					// Check Cosign's final error, excluding informational warnings
					// that mention signatures even when a file or Docker is broken.
					_, reason, hasError := strings.Cut(out, "error during command execution: ")
					if err == nil || !hasError || !strings.Contains(strings.ToLower(reason), check.wantError) {
						t.Fatalf("expected %s verification rejection, got %v\n%s", check.wantError, err, out)
					}
				})
			}
		})
	}
}

// fetchHighCosignBundles checks native OCI subjects, predicate annotations,
// descriptors, and exact content hashes before returning high-side bundle files.
func fetchHighCosignBundles(t *testing.T, dir string, env []string, oras, repo, rootDigest string) map[string]string {
	t.Helper()
	discovered := runStdout(t, dir, env, oras, "discover", "--plain-http", "--format", "json", repo+"@"+rootDigest)
	var root ociDiscoveryNode
	if err := json.Unmarshal([]byte(discovered), &root); err != nil {
		t.Fatal(err)
	}
	if root.Digest != rootDigest || len(root.Referrers) != 2 {
		t.Fatalf("expected two native Cosign referrers of %s, got %s", rootDigest, discovered)
	}
	bundles := make(map[string]string, 2)
	for _, referrer := range root.Referrers {
		manifest := runStdout(t, dir, env, oras, "manifest", "fetch", "--plain-http", repo+"@"+referrer.Digest)
		var m struct {
			ArtifactType string            `json:"artifactType"`
			Annotations  map[string]string `json:"annotations"`
			Subject      struct {
				Digest string `json:"digest"`
			} `json:"subject"`
			Layers []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int64  `json:"size"`
			} `json:"layers"`
		}
		if err := json.Unmarshal([]byte(manifest), &m); err != nil {
			t.Fatal(err)
		}
		predicate := m.Annotations[cosignPredicateAnnotation]
		if m.ArtifactType != cosignBundleMediaType || m.Subject.Digest != rootDigest || len(m.Layers) != 1 ||
			m.Layers[0].MediaType != cosignBundleMediaType || predicate == "" || bundles[predicate] != "" {
			t.Fatalf("unexpected native Cosign manifest: %s", manifest)
		}
		layer := m.Layers[0]
		filename := strings.TrimPrefix(layer.Digest, "sha256:") + ".sigstore.json"
		run(t, dir, env, oras, "blob", "fetch", "--plain-http", "--output", filename, repo+"@"+layer.Digest)
		if got := ociManifestDigest(t, filepath.Join(dir, filename)); got != layer.Digest ||
			int64(len(readOCIFile(t, filepath.Join(dir, filename)))) != layer.Size {
			t.Fatalf("high bundle does not match descriptor %s", layer.Digest)
		}
		bundles[predicate] = filename
	}
	return bundles
}

func verifyCosignOffline(t *testing.T, cosign, dir, predicate, key, bundle, artifact string) (string, error) {
	t.Helper()
	// Docker gives this verifier only a loopback interface. It cannot reach
	// upstream, high, host services, DNS, Fulcio, Rekor, or TUF even if --offline
	// were ignored. Reuse the already-pinned fixture image as a static-binary
	// runtime; fresh HOME and read-only mounts prevent host trust-cache reuse.
	return runAllowFail(t, "", nil, "docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
		"--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()),
		"--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp", "--env", "HOME=/tmp", "--workdir", "/verify",
		"--mount", "type=bind,src="+cosign+",dst=/cosign,readonly",
		"--mount", "type=bind,src="+dir+",dst=/verify,readonly",
		"--entrypoint", "/cosign", ociFixtureRegistryImage, "verify-blob-attestation", "--timeout=15s",
		"--new-bundle-format=true", "--offline", "--insecure-ignore-tlog", "--key", key, "--bundle", bundle, "--type", predicate, artifact)
}

func tamperCosignBundle(t *testing.T, body []byte) []byte {
	t.Helper()
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(bundle["dsseEnvelope"], &envelope); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err := json.Unmarshal(envelope["payload"], &encoded); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var statement map[string]json.RawMessage
	if err := json.Unmarshal(payload, &statement); err != nil {
		t.Fatal(err)
	}
	// Retain the subject and a valid JSON/DSSE/bundle structure, but change the
	// signed predicate without resigning. The failure must be cryptographic.
	statement["predicate"] = json.RawMessage(`{"tampered":true}`)
	payload = marshalOCIJSON(t, statement)
	envelope["payload"] = marshalOCIJSON(t, base64.StdEncoding.EncodeToString(payload))
	bundle["dsseEnvelope"] = marshalOCIJSON(t, envelope)
	return marshalOCIJSON(t, bundle)
}

func readOCIFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func marshalOCIJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
