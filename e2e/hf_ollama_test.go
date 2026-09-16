//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The daemon performs registry downloads, so it must share the CLI's isolated
// receiver namespace. A private model directory prevents a cached model from
// making the pull pass without reading the high-side registry.
func consumeGGUFWithOllama(t *testing.T, ollama, curl, model string) {
	t.Helper()
	tmp := t.TempDir()
	request, err := json.Marshal(map[string]any{
		"model": model, "prompt": "The capital city of France is", "stream": false, "keep_alive": 0,
		"options": map[string]any{"num_gpu": 0, "num_predict": 8, "num_ctx": 256, "num_thread": 2, "temperature": 0, "seed": 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tmp, "generate.json"), string(request))
	writeFile(t, filepath.Join(tmp, "ollama-receiver.sh"), ollamaReceiverScript)
	env := []string{
		"OLLAMA_HOST=127.0.0.1:11434", "OLLAMA_MODELS=" + filepath.Join(tmp, "models"),
		"OLLAMA_NO_CLOUD=1", "OLLAMA_CONTEXT_LENGTH=256", "OLLAMA_NUM_PARALLEL=1",
		"CUDA_VISIBLE_DEVICES=-1", "HIP_VISIBLE_DEVICES=-1", "ROCR_VISIBLE_DEVICES=-1",
	}
	receiver := newReceiver(t, stack.HighURL)
	receiver.Run(t, tmp, env, "sh", filepath.Join(tmp, "ollama-receiver.sh"), ollama, curl, model)
	body, err := os.ReadFile(filepath.Join(tmp, "generated.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Done      bool   `json:"done"`
		Response  string `json:"response"`
		EvalCount int    `json:"eval_count"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode Ollama inference: %v: %s", err, body)
	}
	if result.Error != "" || !result.Done || result.EvalCount < 1 || strings.TrimSpace(result.Response) == "" {
		t.Fatalf("mirrored model did not complete CPU inference: %s", body)
	}
	t.Logf("Ollama generated %d tokens from the mirrored GGUF: %q", result.EvalCount, result.Response)
}

const ollamaReceiverScript = `#!/bin/sh
set -eu
ollama=$1
curl=$2
model=$3
"$ollama" serve >ollama.log 2>&1 &
server_pid=$!
cleanup() {
    result=$?
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    if [ "$result" -ne 0 ]; then cat ollama.log; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 143' TERM INT
attempt=0
until "$curl" -fsS --max-time 1 http://127.0.0.1:11434/api/version >/dev/null 2>&1; do
    kill -0 "$server_pid"
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ]
    sleep 0.1
done
"$ollama" pull --insecure "$model"
"$ollama" show "$model"
"$curl" -fsS --max-time 120 -H 'Content-Type: application/json' \
    --data-binary @generate.json http://127.0.0.1:11434/api/generate -o generated.json
`
