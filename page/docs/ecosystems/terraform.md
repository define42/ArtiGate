# Terraform / OpenTofu

ArtiGate mirrors Terraform **providers** and **registry modules** across a data diode by speaking the registry protocols on the low side (`https://registry.terraform.io` by default — point it at `https://registry.opentofu.org` to mirror OpenTofu), and serving the provider and module registry protocols on the high side, regenerated from the artifacts actually present.

The distinguishing property: provider zips are mirrored **together with the upstream `SHA256SUMS`, its GPG signature, and the registry-served signing keys**, so terraform's own verification chain (zip shasum → `SHA256SUMS` → GPG key) verifies end-to-end against the mirror, unchanged.

## How it works

```text
  provider addresses + module addresses
        │
        ▼
  /.well-known/terraform.json ──▶ discover providers.v1 / modules.v1
        │
        ├─▶ providers: per-platform zip, verified against the
        │   registry shasum + mirrored SHA256SUMS/.sig/signing keys
        │
        └─▶ modules: https archive downloaded, or git:: source
            cloned with git and repacked as a deterministic tar.gz
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        cross-check every zip against the mirrored
                        SHA256SUMS, serve the registry protocols
                        under /.well-known + /terraform/v1/…
```

- Fetching uses plain HTTPS plus the **`git` tool** for `git::` module sources (`--git` selects the binary; default `git`). No `terraform` binary is invoked on either side.
- The high side **never trusts transferred metadata**: served version lists and download descriptors are regenerated from the artifacts present, and each installed zip is cross-checked against the mirrored `SHA256SUMS` — the very document terraform verifies the GPG signature of.

## Low side: input

`POST /admin/terraform/collect` (add `?stream=1` for streamed progress). Body limit **1 MiB**.

```json
{
  "providers": ["hashicorp/aws@5.50.0", "hashicorp/random"],
  "modules": ["terraform-aws-modules/vpc/aws@5.8.1"],
  "platforms": ["linux_amd64", "darwin_arm64"],
  "registry": ""
}
```

| Field | Type | Meaning |
|---|---|---|
| `providers` | `[]string` | Provider addresses `namespace/type`, optionally `@version` (bare = newest release; pre-releases are skipped) |
| `modules` | `[]string` | Registry module addresses `namespace/name/system`, optionally `@version` (bare = newest release) |
| `platforms` | `[]string` | `os_arch` platform names the provider zips are mirrored for. **Defaults to `["linux_amd64"]`** |
| `registry` | string | Upstream registry override for this collect (an http(s) URL) — e.g. `https://registry.opentofu.org` for OpenTofu |
| `force` | bool | Bypass the export-dedup index — pack everything even if already forwarded (full, self-contained bundle) |

At least one provider or module is required (`no providers or modules provided`). The upstream registry for a collect is, in order of precedence: the request's `registry`, the `--terraform-registry` flag, then `https://registry.terraform.io`.

Address tokens (namespace, type, name, system, os, arch) must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; versions always start with a digit. Items that cannot be fetched are skipped and reported in `skipped_modules`; a provider that fails part-way (say, one platform's checksum) is rolled back completely rather than shipping half its files.

## Low side: providers — the verification chain travels too

For each provider, ArtiGate resolves the version (`…/versions`, newest non-prerelease unless pinned), then for **each requested platform** fetches the registry's download descriptor and:

1. Downloads the zip, **verified against the registry-declared `shasum`** while streaming to disk.
2. Fetches the upstream `SHA256SUMS` and checks it lists this zip **with the same digest** (a disagreement between the descriptor and the document is a hard failure).
3. Fetches the detached GPG signature `SHA256SUMS.sig`.
4. Takes the `signing_keys` JSON from the descriptor (must be present and valid).

Everything is staged under the canonical layout, one chain per provider version:

```text
terraform/providers/<ns>/<type>/<version>/terraform-provider-<type>_<version>_<os>_<arch>.zip
terraform/providers/<ns>/<type>/<version>/terraform-provider-<type>_<version>_SHA256SUMS
terraform/providers/<ns>/<type>/<version>/terraform-provider-<type>_<version>_SHA256SUMS.sig
terraform/providers/<ns>/<type>/<version>/signing_keys.json
```

!!! note "Extending a version's platforms"
    A collect mirrors exactly the `platforms` listed. Re-collect the same provider version with more platforms to extend it — on import the high side **merges** the platform lists of successive bundles (the newer record wins per os/arch).

## Low side: modules — deterministic repacking

Module versions resolve through `…/versions` (newest non-prerelease unless pinned), and the registry names the source location (`X-Terraform-Get` on a 204, or a 200 body's `location`). Two source forms are mirrored:

- **https archives** — a `.tar.gz`/`.tgz` URL (or `?archive=tar.gz`), downloaded directly and stored as-is;
- **`git::` sources** — `git::https://…[//subdir]?ref=<ref>`, cloned with the `git` tool (shallow for a tag/branch ref, full clone + detached checkout otherwise; `GIT_TERMINAL_PROMPT=0`, 10-minute timeout) and the requested tree **repacked as a deterministic tar.gz** — sorted paths, epoch timestamps, fixed ownership and modes, `.git` and symlinks skipped.

Either way the archive lands at the canonical path `terraform/modules/<ns>/<name>/<system>/<version>/module.tar.gz`. Determinism (a stable upstream archive, or the normalized git repack) means re-collecting an unchanged module produces identical bytes and [dedups](../architecture.md#export-deduplication-and-delta-bundles) cleanly. Other go-getter schemes (`s3::`, `gcs::`, ssh remotes, …) are skipped and reported.

## High side: import and serving

On import, each provider version's zips are **cross-checked against the mirrored `SHA256SUMS`** and its platform list is merged into the stored metadata; a version whose chain does not line up is logged and 404s. Modules need no regeneration — their protocol is served straight from the directory layout, gated on `module.tar.gz` being present.

The high side serves terraform's service discovery plus both registry protocols (GET/HEAD only):

| Route | Response |
|---|---|
| `GET /.well-known/terraform.json` | `{"providers.v1": "/terraform/v1/providers/", "modules.v1": "/terraform/v1/modules/"}` |
| `GET /terraform/v1/providers/<ns>/<type>/versions` | Mirrored versions with per-platform availability (only platforms whose zip is present) |
| `GET /terraform/v1/providers/<ns>/<type>/<version>/download/<os>/<arch>` | Download descriptor: `download_url`, `shasum`, `shasums_url`, `shasums_signature_url`, and the mirrored `signing_keys` |
| `GET /terraform/v1/modules/<ns>/<name>/<system>/versions` | Mirrored module versions |
| `GET /terraform/v1/modules/<ns>/<name>/<system>/<version>/download` | `204` with `X-Terraform-Get` pointing at the archive |
| `GET /terraform/providers/…`, `/terraform/modules/…` | The artifact files themselves: provider zips, `…_SHA256SUMS`, `…_SHA256SUMS.sig`, `module.tar.gz` |

The stored `metadata.json` and `signing_keys.json` files stay private — their content is embedded in the API responses. Because the discovery document uses relative URLs and descriptors are built from the request host, the mirror works under any name that reaches it.

## Client setup

Two ways to consume the mirror:

```hcl
# ~/.terraformrc — providers via a network mirror (terraform requires HTTPS here)
provider_installation {
  network_mirror {
    url = "https://artigate-high.local/terraform/v1/providers/"
  }
}
```

```hcl
# …or address the mirror host directly in source addresses
# (terraform performs service discovery against the host itself)
terraform {
  required_providers {
    aws = { source = "artigate-high.local/hashicorp/aws" }
  }
}

module "vpc" {
  source  = "artigate-high.local/terraform-aws-modules/vpc/aws"
  version = "5.8.1"
}
```

Terraform verifies each install exactly as it would against the upstream registry: the zip against `shasums_url`'s document, and that document against `shasums_signature_url` with the served `signing_keys` — all three mirrored from upstream, so the trust anchor stays the **original publisher's key** (e.g. HashiCorp's), not an ArtiGate key.

!!! note "`network_mirror` needs HTTPS"
    Terraform refuses plain-HTTP network mirrors — enable [TLS](../tls.md) on the high side, or use host-prefixed source addresses. Host-prefixed sources also need HTTPS for the discovery request by default.

## Mirroring OpenTofu

Set the registry once (`--terraform-registry https://registry.opentofu.org`) or per collect (`"registry": "https://registry.opentofu.org"`). The protocols are identical; OpenTofu clients configure the same `network_mirror` / source addresses against the high side.

## Limitations

- **Platforms are collect-time.** Provider mirroring covers exactly the `platforms` listed (`linux_amd64` by default); re-collect with more platforms to extend a version.
- **Module sources**: only https `.tar.gz` archives and `git::https` URLs (the usual registry forms) are mirrored; other go-getter schemes are skipped and reported.
- **Not served**: `terraform login`, publishing APIs, and the registry's search/UI endpoints — the mirror covers the install protocols only.
- Registry metadata documents (version lists, descriptors, `SHA256SUMS`, signatures) are capped at **4 MiB** each; the request body at 1 MiB.
- **External binary**: `git` on the low side, only when a module resolves to a `git::` source.

### Low-side flags

| Flag | Default | Meaning |
|---|---|---|
| `--terraform-registry` | `""` (→ `https://registry.terraform.io`) | Registry providers/modules are fetched from; use `https://registry.opentofu.org` for OpenTofu |
| `--git` | `git` | git command used to fetch Terraform modules from `git::` sources |

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Security & trust](../security.md) — the signing/verification chain
- [Scheduling (watches)](../scheduling.md) — recurring provider/module collects
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
