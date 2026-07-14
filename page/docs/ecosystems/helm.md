# Helm charts

ArtiGate mirrors **classic Helm chart repositories** — the `index.yaml` kind that `helm repo add` consumes — across a data diode. The low side fetches a repository's index, downloads the requested chart archives (verifying each against the index-declared digest when the upstream index carries one), and the high side serves each upstream repo as its own mirror under `/helm/<mirror>`, with an `index.yaml` **regenerated from every chart's own embedded `Chart.yaml`**.

!!! note "OCI charts are out of scope"
    Charts hosted in OCI registries (`oci://…`) are not mirrored by this adapter — mirror them as [container images](containers.md) instead. This page covers classic `index.yaml` repositories only.

## How it works

```text
  repo URL + chart specs ("nginx@21.1.0", "redis")
        │
        ▼
  fetch <repo>/index.yaml ──▶ pick each chart's entry
        │
        ▼
  download every .tgz ──▶ verify the index digest (when declared)
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        parse each archive's embedded Chart.yaml,
                        recompute digests, regenerate index.yaml
                        under /helm/<mirror>/
```

- Fetching is plain HTTPS — **no `helm` binary is invoked** on either side.
- The high side **never trusts a transferred index**: `index.yaml` is rebuilt from the metadata embedded in each verified chart archive, with the `digest` recomputed from the artifact bytes.
- Mirrors are namespaced like [APT](apt.md) mirrors, so several upstream repositories coexist under `/helm/<mirror>` without mixing.

## Low side: input

`POST /admin/helm/collect` (add `?stream=1` for streamed progress). Body limit **1 MiB**.

```json
{
  "name": "bitnami",
  "url": "https://charts.bitnami.com/bitnami",
  "charts": ["nginx@21.1.0", "redis"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Optional mirror name — the URL segment under `/helm/<name>` on the high side. Defaults to a slug of the URL (host + path, non-alphanumerics collapsed to `-`) |
| `url` | string | **Required.** The upstream chart repository — the same URL `helm repo add` would use (http/https) |
| `charts` | `[]string` | **Required.** Chart specs: `nginx` for the newest version, `nginx@21.1.0` to pin (`@latest` equals the bare form) |
| `force` | bool | Bypass the export-dedup index — pack every chart even if already forwarded (full, self-contained bundle) |

In the low-side dashboard (**Helm** tab), enter one chart per line. Chart names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; versions are semver, optionally `v`-prefixed like many repos publish.

### Resolution and download

The upstream `index.yaml` is fetched from `<url>/index.yaml` and each spec picks its entry: the exact pinned version, or the **newest version (stable preferred over pre-release)** for a bare name. Duplicate specs resolving to the same `name@version` are downloaded once. The download URL is the entry's first `urls` value — absolute, or relative to the repository base, as the index format allows.

Each archive is verified against the index-declared `digest` (plain or `sha256:`-prefixed hex) **when the index carries one**:

!!! warning "Digest-less repositories download TLS-trusted"
    Some repositories publish index entries with no `digest`. Those chart archives are downloaded **without an upstream hash check** — integrity then rests on TLS to the operator-configured upstream, like the other index-less fetches. Everything after the download is hash-locked into the signed bundle either way, and the high side recomputes the served digest from the artifact.

Whatever the upstream URL looked like, the archive is stored under the canonical name and path `helm/<mirror>/charts/<name>-<version>.tgz`. Per-file downloads are capped at 8 GiB with a 30-minute timeout; the index fetch at 1 GiB. Charts that cannot be resolved or fetched are skipped and reported in `skipped_modules`; zero fetched charts fail the collect (`no charts could be fetched: …`).

## Low side: the signed bundle

Fetched charts are packed into the standard numbered, Ed25519-signed bundle on the `helm` stream. The manifest records the mirror (name + upstream URL) and one record per chart:

```json
{
  "name": "nginx",
  "version": "21.1.0",
  "filename": "nginx-21.1.0.tgz",
  "path": "helm/bitnami/charts/nginx-21.1.0.tgz",
  "sha256": "…"
}
```

[Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies as usual: an unchanged re-collect is skipped without consuming a sequence, a partly-new one ships a delta bundle, and `"force": true` bypasses the index.

## High side: index regeneration

On import (after the Ed25519 signature and per-file SHA-256 checks), the high side publishes each mirror:

1. For every chart, the archive's **embedded `Chart.yaml`** is extracted (helm requires `<chart>/Chart.yaml` at depth one; read with an 8 MiB cap) and must name exactly this chart and version — a mismatch is logged and that chart stays out of the index rather than wedging the import.
2. The chart's `digest` is **recomputed from the artifact bytes**.
3. The mirror's `index.yaml` is rebuilt from the accumulated stored metadata, listing **only charts whose archive is present**, newest version first, each entry carrying the full embedded `Chart.yaml` metadata plus:

```yaml
urls: ["charts/nginx-21.1.0.tgz"]   # relative — resolves against the repo base
digest: "<recomputed sha256>"
created: "<archive mtime, RFC 3339>"
```

Relative `urls` mean the index needs no absolute self-URL and survives being served under any host name. Charts accumulate across bundles — re-collecting adds versions, it never removes ones that already crossed.

## High side: serving

Exactly two client-facing shapes are served under `/helm/` (GET/HEAD only); the regenerated metadata store stays private:

| Route | Response |
|---|---|
| `GET /helm/<mirror>/index.yaml` | The regenerated repository index (`Content-Type: application/yaml`) |
| `GET /helm/<mirror>/charts/<name>-<version>.tgz` | The chart archive |

## Client setup

Each mirrored upstream repo is added under its mirror name:

```bash
helm repo add artigate https://artigate-high.local/helm/bitnami
helm repo update
helm install my-release artigate/nginx --version 21.1.0
```

`helm search repo artigate/` lists what the mirror actually holds. Charts referencing sibling charts as dependencies (`Chart.yaml` `dependencies`) resolve against whatever repositories the client has configured — mirror the dependency charts too and keep ArtiGate the only configured repository.

!!! warning "No upstream fallback"
    Configure ArtiGate as the **sole** chart repository on high-side clients. Any additional public repository reintroduces the substitution risk the diode exists to eliminate. See [Security & trust](../security.md).

## Limitations

- **Classic `index.yaml` repositories only.** OCI-hosted charts are out of scope — mirror those as [container images](containers.md).
- **Provenance files (`.prov`) are not mirrored.** Integrity comes from the regenerated index digests (recomputed from the verified artifacts) plus ArtiGate's own bundle signature and hash chain.
- **Digest verification is upstream-dependent**: it happens exactly when the upstream index declares a digest; otherwise the low-side download is TLS-trusted.
- **Exactly the charts you name** are mirrored — chart dependencies are not auto-resolved; list them explicitly.
- Size and time caps: request body 1 MiB, upstream index 1 GiB, embedded `Chart.yaml` 8 MiB, per-chart download 8 GiB / 30 minutes.
- Mirror names must be a single path segment; two upstreams wanting the same derived name need explicit distinct `name`s.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Container images (OCI)](containers.md) — the route for OCI-hosted charts
- [Security & trust](../security.md) — the signing/verification chain
- [Scheduling (watches)](../scheduling.md) — recurring chart collects
- [HTTP API reference](../api.md) — the exact request/response contracts
