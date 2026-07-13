//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHFRepo mirrors a full (safetensors-style) Hugging Face repository and
// downloads it back through the high side's Hub API with the real
// huggingface_hub CLI via HF_ENDPOINT — the same way vLLM and transformers
// consume the mirror. The repo is a tiny model published for exactly this
// kind of testing.
func TestHFRepo(t *testing.T) {
	stack.Prepare(t)
	cli := requireTool(t, "hf", "huggingface-cli")

	const repo = "hf-internal-testing/tiny-random-gpt2"
	res := stack.Collect(t, "hf", map[string]any{"repos": []string{repo}})
	stack.WaitImported(t, "hf", res.Sequence)

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "model")
	env := []string{
		"HF_ENDPOINT=" + stack.HighURL,
		"HF_HOME=" + filepath.Join(tmp, "hf-home"),
		"HF_HUB_DISABLE_TELEMETRY=1",
	}
	run(t, tmp, env, cli, "download", repo, "--local-dir", dest)

	cfgBytes, err := os.ReadFile(filepath.Join(dest, "config.json"))
	if err != nil {
		t.Fatalf("config.json missing after hf download: %v", err)
	}
	var cfg struct {
		ModelType string `json:"model_type"`
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("config.json does not parse: %v", err)
	}
	if cfg.ModelType != "gpt2" {
		t.Fatalf("config.json model_type = %q, want gpt2", cfg.ModelType)
	}
	weights, _ := filepath.Glob(filepath.Join(dest, "*.bin"))
	safetensors, _ := filepath.Glob(filepath.Join(dest, "*.safetensors"))
	if len(weights)+len(safetensors) == 0 {
		t.Fatal("no weight file (*.bin / *.safetensors) downloaded")
	}
}

// defaultGGUF is the GGUF reference TestHFGGUF mirrors: a small,
// standard-named quantization from a high-volume publisher. If it ever
// disappears upstream, override with ARTIGATE_E2E_HF_GGUF=org/name:quant
// (and update this default). The CI workflow preflights this exact
// reference against huggingface.co so rot fails fast.
const defaultGGUF = "bartowski/SmolLM2-135M-Instruct-GGUF:Q4_K_M"

// TestHFGGUF mirrors one GGUF quantization (resolved through Hugging Face's
// Ollama-compatible endpoint) and validates the two ways the high side
// serves it: the raw /hf/.../<tag>.gguf download used by llama.cpp/vLLM,
// and the /v2 manifest+blob pair an ollama client pulls. Running an actual
// ollama daemon is deliberately out of scope (it would need a ~GB install
// plus TLS/--insecure plumbing); the bytes and protocol are asserted
// directly instead.
func TestHFGGUF(t *testing.T) {
	stack.Prepare(t)

	ref := os.Getenv("ARTIGATE_E2E_HF_GGUF")
	if ref == "" {
		ref = defaultGGUF
	}
	org, name, quant, err := splitGGUFRef(ref)
	if err != nil {
		t.Fatalf("bad GGUF ref %q: %v", ref, err)
	}

	res := stack.Collect(t, "hf", map[string]any{"models": []string{ref}})
	stack.WaitImported(t, "hf", res.Sequence)

	// The raw GGUF endpoint: magic bytes plus a sane size, without pulling
	// the whole model through the test again.
	ggufURL := fmt.Sprintf("%s/hf/%s/%s/%s.gguf", stack.HighURL, org, name, quant)
	code, prefix, size := httpGetPrefix(t, ggufURL, 4)
	if code != 200 || string(prefix) != "GGUF" {
		t.Fatalf("GET %s: HTTP %d, first bytes %q; want 200 and GGUF magic", ggufURL, code, prefix)
	}
	if size < 1<<20 {
		t.Fatalf("GET %s: Content-Length %d, want > 1 MiB", ggufURL, size)
	}

	// The Ollama-protocol pair: the manifest names a model layer whose blob
	// starts with the GGUF magic.
	manifestURL := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", stack.HighURL, org, name, quant)
	code, body := httpGet(t, manifestURL)
	if code != 200 {
		t.Fatalf("GET %s: HTTP %d: %s", manifestURL, code, body)
	}
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("manifest does not parse: %v\n%s", err, body)
	}
	var modelDigest string
	for _, layer := range manifest.Layers {
		if strings.Contains(layer.MediaType, "vnd.ollama.image.model") {
			modelDigest = layer.Digest
			break
		}
	}
	if modelDigest == "" {
		t.Fatalf("manifest has no ollama model layer:\n%s", body)
	}
	blobURL := fmt.Sprintf("%s/v2/%s/%s/blobs/%s", stack.HighURL, org, name, modelDigest)
	code, prefix, _ = httpGetPrefix(t, blobURL, 4)
	if code != 200 || string(prefix) != "GGUF" {
		t.Fatalf("GET %s: HTTP %d, first bytes %q; want 200 and GGUF magic", blobURL, code, prefix)
	}
}

func splitGGUFRef(ref string) (org, name, quant string, err error) {
	repo, quant, ok := strings.Cut(ref, ":")
	if !ok {
		return "", "", "", fmt.Errorf("missing :quant tag")
	}
	org, name, ok = strings.Cut(repo, "/")
	if !ok || org == "" || name == "" || quant == "" {
		return "", "", "", fmt.Errorf("want org/name:quant")
	}
	return org, name, quant, nil
}
