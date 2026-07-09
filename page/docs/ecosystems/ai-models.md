# AI models (Hugging Face)

ArtiGate mirrors AI models from Hugging Face in two complementary forms. **GGUF model variants** are addressed container-style — `hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0`, where the tag selects a quantization — fetched over the Hub's Ollama-compatible model API and served back so an air-gapped **Ollama pulls straight from the mirror**. **Full repository snapshots** cover releases that publish safetensors rather than GGUF (`openai/gpt-oss-20b`): every file is mirrored at a pinned commit and served back over the download subset of the **Hub HTTP API**, so vLLM, transformers, and `hf download` work unchanged by pointing `HF_ENDPOINT` at the mirror.

Model work travels on the `hf` stream. Like every ecosystem, that stream has its own sequence counter, export lock, and export-dedup index; both forms share one content-addressed blob store, so a file common to two variants — or to a variant and a snapshot — is bundled and stored once.

!!! warning "GGUF variants need a GGUF repository"
    The variant form uses the Hub's Ollama-compatible endpoint, which serves **GGUF repositories only** — the same ones `ollama run hf.co/…` accepts. A safetensors-only release (the Hub answers HTTP 400) cannot be mirrored as a variant; mirror one of its GGUF conversions (usually named `<model>-GGUF`), or mirror the release itself as a **full repository**.

## Low-side inputs

Drive a collect with `POST /admin/hf/collect`. The request body (max 1 MiB) carries either or both reference lists, plus optional excludes for repositories:

```json
{
  "models": ["hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0"],
  "repos": ["openai/gpt-oss-20b"],
  "repo_exclude": ["original", "metal"],
  "force": false
}
```

`force: true` bypasses the export-dedup index — every blob is downloaded and packed even when already forwarded, producing a full self-contained bundle.

### GGUF variant references (`models`)

| Form | Example | Meaning |
|---|---|---|
| Org + name | `unsloth/gpt-oss-20b-GGUF` | default quantization (tag `latest`) |
| With quantization | `unsloth/gpt-oss-20b-GGUF:Q4_0` | exact variant, resolved by the Hub |
| Explicit host | `hf.co/…`, `huggingface.co/…`, pasted `https://…` | same; the prefix is optional |

The quantization is resolved **by Hugging Face itself** — never guessed from filenames. Digest pins (`@sha256:…`) are rejected; use a tag. Organizations never contain dots (that is what distinguishes an org from a host, and on the high side an AI model from a container repository); repository names may (`Llama-3.2-…`).

### Full repository references (`repos`)

| Form | Example | Meaning |
|---|---|---|
| Org + name | `openai/gpt-oss-20b` | branch `main`, pinned to its commit at collect time |
| Branch or tag | `openai/gpt-oss-20b@main` | same, explicit |
| Commit pin | `org/model@<40-hex-commit>` | exact revision |
| Pasted browser URL | `https://huggingface.co/openai/gpt-oss-20b/tree/dev` | branch `dev` |

One Hub API call (`/api/models/…/revision/…?blobs=true`) resolves the revision to its **commit hash** and lists every file with the LFS files' upstream SHA-256s. Large LFS files stream to disk verified against those; small non-LFS files (configs, tokenizers) carry no upstream sha256 and are hashed while downloading.

**`repo_exclude`** skips repository paths: a bare directory name (`original` or `original/`) excludes that whole subtree; anything else is a `path.Match` pattern against the full file path. For gpt-oss, `original, metal` skips the two extra full-weight copies and roughly third-sizes the bundle.

### Gated models and endpoint override

| Setting | Meaning |
|---|---|
| `ARTIGATE_HF_TOKEN` (env, low side) | Hugging Face access token for gated/private models; sent as a Bearer header, read at collect time so it can rotate without a restart |
| `--hf-endpoint` (flag, low side) | fetch from a private Hub mirror instead of `https://huggingface.co` |

Without a token, a gated model fails with a hint to set `ARTIGATE_HF_TOKEN`. `net/http` drops the `Authorization` header on the cross-host CDN redirects blob downloads follow, so the token never leaks downstream.

## Internals

**Variant fetch.** A variant's manifest comes from `GET /v2/<org>/<name>/manifests/<tag>` — a Docker-schema-2 manifest whose layers are the GGUF model file, chat template, params, and license, each fetched from `/v2/<org>/<name>/blobs/<digest>` and streamed to disk under a size + SHA-256 check. The manifest bytes themselves are stored verbatim as a blob, so the high side replays exactly what the Hub served.

**Content-addressed, sharded blob store.** Every file — manifests, GGUF blobs, snapshot files — lands at:

```text
hf/blobs/sha256/<first-3-hex>/<full-64-hex>
```

the same first-3-hex sharding as the [container](containers.md) store. Blobs already staged in a run are skipped, and `manifest.files` lists each blob once even when several variants reference it.

**Resilient batches.** Per-reference failures (an unknown quantization, a gated model without a token) are skipped into `skipped_modules` rather than aborting the batch; only if *nothing* succeeds does the run fail. [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies with the pre-download skip: manifest blob digests and LFS SHA-256s are known *before* the bytes are fetched, so already-forwarded model files are **not downloaded again** — they ride as `prior` manifest references while only new content is downloaded and packed into a delta bundle. An unchanged re-collect writes no bundle and burns no sequence number. (Small non-LFS files carry no upstream hash, so they are re-downloaded and deduped after hashing.)

**Bundle manifest.** The bundle carries an `HFManifest` with both forms:

```json
{
  "models": [
    {
      "org": "unsloth",
      "name": "gpt-oss-20b-GGUF",
      "variants": [
        {
          "tag": "Q4_0",
          "digest": "sha256:...",
          "media_type": "application/vnd.docker.distribution.manifest.v2+json",
          "size": 485,
          "blobs": [
            { "digest": "sha256:...", "size": 199 },
            { "digest": "sha256:...", "size": 11785434752, "media_type": "application/vnd.ollama.image.model" }
          ]
        }
      ]
    }
  ],
  "repos": [
    {
      "org": "openai",
      "name": "gpt-oss-20b",
      "revision": "<40-hex commit>",
      "ref": "main",
      "files": [
        { "path": "config.json", "sha256": "...", "size": 1523 },
        { "path": "model-00000-of-00002.safetensors", "sha256": "...", "size": 4504304 }
      ]
    }
  ]
}
```

On import the high side re-validates every referenced blob against the bundle's `manifest.files` — the digest a client pulls by is exactly the hash the import verifies. Snapshot revisions must be full commit hashes and every file path is validated safe before install.

## High-side serving

Imported content is merged into persistent indexes (`<root>/hf/models/<org>/<name>/_index.json` for variants, `<root>/hf/repos/<org>/<name>/_index.json` for snapshots). Re-collecting a tag or branch moves it to the new digest/commit; older snapshots stay pullable by commit hash. Everything is read-only.

### Ollama-compatible registry (variants)

| Route | Response |
|---|---|
| `GET\|HEAD /v2/<org>/<name>/manifests/<tag-or-digest>` | stored manifest bytes, `Docker-Content-Digest`, stored `Content-Type` |
| `GET\|HEAD /v2/<org>/<name>/blobs/<digest>` | blob (Range supported, so pulls resume) |
| `GET /v2/<org>/<name>/tags/list` | `{"name": "<org>/<name>", "tags": [...]}` |
| `GET /hf/<org>/<name>/<tag>.gguf` | the variant's raw model file, with a descriptive download filename |

An Ollama model name is `host/namespace/model:tag` — exactly two path segments after the host — so the pull name is simply `<high-host>/<org>/<name>:<tag>`; the explicit `/v2/hf.co/<org>/<name>/…` form is also served for scripts. The registry shares `/v2/` with [containers](containers.md) without ambiguity: a container name's first segment is a dotted registry host, which can never parse as a Hugging Face organization. Model names and quantization tags match case-insensitively (as on the Hub), and per-model isolation applies over the shared blob store.

### Hub API subset (snapshots)

| Route | Response |
|---|---|
| `GET /api/models/<org>/<name>[/revision/<rev>]` | model info: pinned commit (`sha`) + file list (`siblings`) |
| `GET\|HEAD /<org>/<name>/resolve/<rev>/<path>` | file download with `ETag` (the sha256 — the client's cache key) and `X-Repo-Commit` (its snapshot directory); Range supported |

`<rev>` may be a collected branch name (`main`), the commit hash, or absent for the default. Misses carry the `X-Error-Code` values `huggingface_hub` maps to typed errors (`RepoNotFound`, `RevisionNotFound`, `EntryNotFound`). This is the **download subset only** — search, listing, and write APIs are not served, which is exactly what `HF_ENDPOINT`-pointed model loading needs.

## Client setup

```bash
# Ollama — pull straight from the mirror (add --insecure for a plain-HTTP mirror)
ollama pull <high-host>/unsloth/gpt-oss-20b-GGUF:Q4_0
ollama run  <high-host>/unsloth/gpt-oss-20b-GGUF:Q4_0

# Raw GGUF for llama.cpp, or vLLM's per-architecture GGUF loader
curl -fL -o gpt-oss-20b-GGUF-Q4_0.gguf \
  https://<high-host>/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf
llama-server -m gpt-oss-20b-GGUF-Q4_0.gguf

# Full repositories — every huggingface_hub client, via HF_ENDPOINT
export HF_ENDPOINT=https://<high-host>
vllm serve openai/gpt-oss-20b
hf download openai/gpt-oss-20b
```

!!! tip "The dashboard renders this for you"
    The high-side "Set me up" guide builds all three blocks from what is actually mirrored — real pull names, your host, and an `--insecure` flag when the mirror is plain HTTP. Sections whose content is not mirrored yet are labeled as examples.

## Limitations

- **Variants: GGUF repositories only** — the ones the Hub's Ollama-compatible endpoint serves; sharded/split GGUFs are not supported upstream, and digest pins are rejected.
- **Ollama requires HTTPS** — enable [TLS](../tls.md) on the high side or pass `--insecure` to `ollama pull`.
- **Snapshots serve the Hub API's download subset only** — no search, listing, or write endpoints.
- **`sha256` digests only**, as everywhere in ArtiGate.
- **vLLM + GGUF** is per-architecture and needs `HF_HUB_OFFLINE=1`; full repositories via `HF_ENDPOINT` are the reliable vLLM path.
- **Revision references cannot contain `/`** — a branch like `feature/x` is not addressable; pin the commit instead.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the mirror
- [Scheduling (watches)](../scheduling.md) — recurring pulls track a tag or branch over time
- [Security & trust](../security.md) — the trust model, including `ARTIGATE_HF_TOKEN` handling
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
