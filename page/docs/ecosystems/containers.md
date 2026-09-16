# Container images (OCI)

ArtiGate mirrors OCI/Docker container images end to end: the [low side](../low-side.md) resolves each image reference against its upstream registry over the OCI Distribution HTTP API, pulls the `linux/amd64` manifest with its config and layer blobs, and packs everything into a signed bundle; the [high side](../high-side.md) serves it all back as a **read-only OCI Distribution registry** under `/v2/` that `docker`, `podman`, and `containerd` can pull from.

Container work travels on the `containers` stream. Like every ecosystem, that stream has its own sequence counter, export lock, and export-dedup index, so a container collect never blocks or interleaves with Go, Python, Maven, npm, APT, RPM, or AI model work.

!!! warning "linux/amd64 only"
    ArtiGate mirrors the `linux/amd64` platform exclusively. The original multi-platform index is preserved to keep its digest and signatures intact, but other platform images are not downloaded. Pulls are anonymous by default; private registries authenticate with a per-pull login or standing `ARTIGATE_CONTAINER_AUTH` credentials (see [Private registries](#private-registries)).

## Low-side inputs

Drive a collect with `POST /admin/containers/collect`. The request body (max 1 MiB) is a list of image references:

```json
{ "images": ["alpine:3.20", "ghcr.io/org/app:v1", "golang:1.26.x"], "force": false }
```

References are parsed docker-style and de-duplicated before fetching. Each reference may carry a tag, a digest, or a version constraint in the tag slot. `force: true` bypasses the export-dedup index — every blob is downloaded and packed even when already forwarded, producing a full self-contained bundle. An optional `auth` object supplies a one-time login for a private registry (see [Private registries](#private-registries)).

The `images` list also accepts opaque OCI artifacts, such as documents published with `oras push`. A nonstandard config media type, or an explicit `artifactType` without a standard image-config media type, identifies an opaque artifact. Its config is preserved as bytes, including non-JSON or empty content. Indexes with an `artifactType`, a native `subject`, or no platform descriptors are treated as artifact indexes and retain all required children. Manifests with Docker/OCI image-config media types continue to undergo the `linux/amd64` platform check, even when they also carry an artifact type or subject.

### Image reference forms

| Form | Example | Meaning |
|---|---|---|
| Bare name | `alpine` | Docker Hub `library/alpine`, tag `latest` |
| Name + tag | `alpine:3.20` | exact tag |
| Registry + repo + tag | `ghcr.io/org/app:v1` | exact tag on a named registry |
| Digest pin | `registry.access.redhat.com/ubi9/ubi@sha256:<64hex>` | exact content pin |
| Version constraint | `golang:1.26.x`, `golang:<2.0.0` | resolved to a concrete numeric tag at collect time |

If no tag, digest, or constraint is given, the tag defaults to `latest`.

### Docker Hub short-name normalization

The first path component is treated as a **registry only if** it contains a `.` or `:`, or is exactly `localhost`. Otherwise the whole string is a Docker Hub repository, and single-component names get a `library/` prefix:

| Input | Normalized `registry` | Normalized `repository` |
|---|---|---|
| `alpine` | `docker.io` | `library/alpine` |
| `library/alpine` | `docker.io` | `library/alpine` |
| `bitnami/redis` | `docker.io` | `bitnami/redis` |
| `ghcr.io/org/app` | `ghcr.io` | `org/app` |

The registry aliases `docker.io`, `index.docker.io`, and `registry-1.docker.io` all fold to the logical name `docker.io` (case-insensitively); every other host is simply lowercased. Internally the logical `docker.io` name maps to the API host `https://registry-1.docker.io`.

!!! note "Digests must be sha256"
    A digest must match `sha256:<64 hex>` exactly. Only `sha256` is supported anywhere in the container pipeline — parsing, verification, and serving all reject any other algorithm. A reference cannot pin a digest **and** carry a version constraint at the same time.

### Version constraints

A value in the tag slot is treated as a **version constraint** — rather than a literal tag — when it:

- equals `x` or `*`, or
- contains any of `< > = ~ ! ,` or a space, or
- matches the wildcard pattern `v?N(.N)*(.x|.*)+` (e.g. `1.26.x`, `1.x`, `2.x.x`, `1.26.*`).

Plain versions like `3.20` remain **exact tags**, never constraints.

| Constraint | Meaning (normalized) |
|---|---|
| `1.26.x` | `>= 1.26.0, < 1.27.0` |
| `1.x` | `>= 1.0.0, < 2.0.0` |
| `<2.0.0` | strictly below 2.0.0 |
| `>= 1.24, < 2.0` | half-open range |
| `~> 1.26` | pessimistic (go-version syntax) |
| `x` or `*` | matches everything (`>= 0`) |

**Numeric tags only.** When resolving a constraint, ArtiGate lists all upstream tags but considers **only plain numeric tags** matching `v?N(.N){0,3}` (e.g. `1.26.3`, `v2.0`, `17`). Variant tags like `1.26.3-alpine`, `1.26-slim`, date tags, and `latest` are ignored entirely, so a variant image can never outrank the plain one. The best match is the highest version satisfying the constraint; when two tags are the same version (`1.26` vs `1.26.0`), the longer, more specific tag string wins.

**The resolved concrete tag is recorded — not the constraint.** Once resolved, the constraint is replaced by the winning tag before mirroring (logged as `containers: golang:1.26.x resolved to tag golang:1.26.3`), and the bundle records the concrete tag. The high side therefore serves `golang:1.26.3`, not `golang:1.26.x`.

**Scheduled re-resolution.** Constraints are re-resolved on every collect run — including when a collect is driven by a [watch](../scheduling.md). A recurring watch on `golang:1.26.x` picks up newer patch tags over time. The stored watch spec is the JSON `{"images":[...]}` request, re-decoded and re-run each interval.

!!! warning "A literal tag that looks like a constraint is unreachable"
    If a repository publishes a tag literally named `1.26.x` (or anything containing `< > = ~ ! ,` / space), that tag can never be pulled by name through ArtiGate — the parser treats it as a constraint. Pin it by digest instead.

### `--container-registry` override

By default the API base for a registry is `https://<registry>` (with `docker.io` mapped to `https://registry-1.docker.io`). The `low` flag `--container-registry` supplies comma-separated `host=baseURL` overrides — for example to point Docker Hub at an internal mirror:

```bash
artigate low \
  --private-key /etc/artigate/low.ed25519 \
  --container-registry docker.io=https://mirror.example.com
```

| Flag | Default | Meaning |
|---|---|---|
| `--container-registry` | *(empty)* | comma-separated `host=baseURL` overrides for container registries |

Each base must parse as an `http`/`https` URL; a trailing `/` is trimmed and the host is normalized. A malformed entry fails startup with `invalid --container-registry entry` or `invalid --container-registry base URL`.

!!! warning "Non-standard registry ports are unsupported"
    Because the high side serves an image under the name `<registry>/<repository>`, and a port `:` cannot appear in that name, any upstream reference whose registry carries a port is rejected at parse time: `registries on non-standard ports cannot be mirrored (the port cannot appear in the high-side pull name)`. (This concerns the *upstream* registry host — the ArtiGate high-side `host:port` you pull from is entirely separate.)

### Private registries

Registries that demand authentication (GHCR, Harbor, private Docker Hub repositories, htpasswd-protected `registry:2`, …) are pulled with a login from one of two sources, resolved per registry as *request auth → `ARTIGATE_CONTAINER_AUTH` → anonymous*:

**Per-pull login** — an optional `auth` object on the collect request, also exposed as the *Private registry login* fields on the low-side Containers page. It is used for that one collect and never stored:

```json
{
  "images": ["ghcr.io/org/private-app:v1"],
  "auth": { "registry": "ghcr.io", "username": "mirror-bot", "password": "<token>" }
}
```

`username` and `password` are both required (a registry token — a GHCR PAT, a Harbor robot secret — goes in `password`, exactly as with `docker login`). `registry` may be omitted when every image in the pull comes from the same registry; a pull spanning several registries must name the one the login is for, and a `registry` matching none of the pull's images is rejected — a login is never presented to a registry you didn't mean it for.

**Standing credentials** — the low-side environment variable `ARTIGATE_CONTAINER_AUTH` holds comma-separated `host=user:password` entries:

```bash
export ARTIGATE_CONTAINER_AUTH='ghcr.io=mirror-bot:ghp_xxx,harbor.example.com=robot$mirror:secret'
```

It is re-read on **every collect** (rotate it without a restart), applies to manual pulls without an `auth` field, and is the **only** credential source for [scheduled watches](../scheduling.md) — the server rejects any watch spec carrying an `auth` key, because specs are stored and echoed in plaintext. Hosts fold through the usual normalization (`index.docker.io` → `docker.io`); the password may contain `:` and `=`, but an entry cannot express a password containing `,`.

!!! note "Where the login is sent"
    On a `Bearer` challenge the login is sent as HTTP Basic **to the token endpoint the registry's challenge names** (the `docker login` flow), never to the registry URL itself; on a `Basic` challenge it is sent to the registry directly. Each login is keyed to one registry, so it can only ever reach that registry's chosen realm. Credentials never appear in bundles, logs, progress lines, or error messages.

## Internals

**Bearer token dance.** The stdlib registry client requests `<apiBase>/v2/<repository>/<path>`. On a `401` it reads `Www-Authenticate`: a `Bearer` challenge fetches a token from the realm with scope `repository:<repository>:pull` (adding HTTP Basic credentials when the registry has a login configured) and retries once; a `Basic` challenge answers with the configured login directly, or fails with guidance when there is none. A persistent `401` is a hard error — `credentials for <registry> were not accepted` with a login, or `the image may be private; supply a login on the pull (auth field) or set ARTIGATE_CONTAINER_AUTH` without one. One Authorization value is cached per `<registry>/<repository>` for the whole collect run. The `Authorization` header is set per-request only, so `net/http` drops it on cross-host CDN (S3 blob) redirects, avoiding token or login leakage.

**Manifest resolution.** Manifests are requested with an `Accept` header covering Docker and OCI, single-image and index media types. A multi-platform index is unmarshalled and the **first entry with `os == "linux"` and `architecture == "amd64"`** is chosen and re-fetched by digest; attestation entries (`unknown/unknown`) never match. No amd64 manifest is a hard error: `image has no linux/amd64 manifest`. When a manifest is fetched by digest, its recomputed SHA-256 must match or the collect errors with `manifest digest mismatch`.

**Platform re-check.** After download, the config blob is parsed and the image is rejected unless its `os` is empty or `linux` and its `architecture` is empty or `amd64` — a second guard beyond index selection.

**Content-addressed, sharded blob store.** Every blob — the image manifest, the config, and each layer — is stored content-addressed at:

```text
containers/blobs/sha256/<first-3-hex>/<full-64-hex>
```

The first **3 hex characters** of the digest form the shard directory, spreading blobs across 16³ = **4096 directories** (the same first-N-hex scheme Docker's own registry and git use). The store is **shared across all repositories**, so a layer common to many images is stored exactly once (dedup). Blobs already staged in a run are skipped — and because the manifest declares every blob's digest *before* the bytes are fetched, blobs already forwarded on the `containers` stream in an earlier bundle are **not downloaded at all**: they ride in the manifest as [`prior` references](../architecture.md#export-deduplication-and-delta-bundles) while only new blobs are downloaded and packed. A base image shared by many tags therefore crosses the diode exactly once.

**Streaming download & verification.** Blobs are streamed to disk through `io.MultiWriter(file, sha256)` under a 30-minute context — never buffered in memory — and verified against both the expected size and digest; a mismatch removes the file and fails. Foreign / non-distributable layers (media type containing `foreign`) are rejected outright. Image manifests, preserved indexes, and attached-artifact manifests share a **4 MiB collection and serving limit**; larger documents are rejected during collection so an accepted image remains servable on the high side. Token responses are capped at 1 MiB; the upstream `tags/list` pager follows RFC 5988 `Link` headers up to a hard cap of 100 pages (≈1M tags).

**Resilient batches.** Per-image failures are non-fatal: a broken reference is skipped and reported in `SkippedModules`. Only if *zero* images succeed does the whole run fail with `no images could be fetched`. If nothing new was produced at all, `exportIfNew` writes no bundle and burns no sequence; if only some blobs are new, the bundle is a delta carrying just those.

**Bundle manifest.** Each bundle carries a `ContainerManifest` of repos, keeping `registry` and `repository` separate:

```json
{
  "repos": [
    {
      "registry": "docker.io",
      "repository": "library/alpine",
      "images": [
        {
          "tag": "3.20",
          "digest": "sha256:...",
          "media_type": "application/vnd.oci.image.manifest.v1+json",
          "size": 1234,
          "blobs": [
            { "digest": "sha256:...", "size": 2811 },
            { "digest": "sha256:...", "size": 3400000 }
          ]
        }
      ]
    }
  ]
}
```

`Blobs[0]` is the config; `Blobs[1:]` are the layers. On import the high side re-validates every referenced digest against the bundle's `manifest.files`: each digest must match `sha256:<64 hex>`, appear in the file set at its content-addressed path, and hash to that digest. **The digest a client pulls by is exactly the hash the import verifies.**

## High-side read-only OCI registry

Imported images are merged into a persistent **per-repository index** at:

```text
<root>/containers/repos/<registry>/<repository>/_index.json
```

(The `_index.json` name can never collide with real content because a repository component may not start with `_`.) Re-importing a tag moves it to its new digest; digest-pinned images accumulate. The high side then serves a read-only OCI Distribution registry under `/v2/`. Only `GET` and `HEAD` are accepted — any write returns `405 UNSUPPORTED` (`read-only registry`), so it can never be a push target.

### Signatures, attestations, and referrers

Collection discovers attachments through the OCI referrers API and its tag fallback, legacy cosign `.sig`/`.att`/`.sbom` tags, and BuildKit attestation entries. Native referrer manifests must declare the queried digest in their OCI `subject` field; missing or mismatched subjects are skipped with a warning. Legacy cosign and BuildKit attachments may omit `subject`.

Referrer discovery follows `Link: rel="next"` pages within the same registry, repository, and subject endpoint. It stops at 100 pages, 4,096 listed descriptors, or 4 MiB per response. Only an initial API `404` selects the legacy fallback index tag. Authentication failures, invalid responses, unsafe pagination links, and exhausted retries produce a **discovery incomplete** warning in the collect's progress/job log and the server log. Successfully discovered pages are retained. Transient `429` and selected `5xx` responses receive up to three attempts; a `Retry-After` longer than two seconds is reported for a later collection instead of retried prematurely.

Both manifest and index referrers are supported. Every required child of an artifact index must be collected and verified before that index is included in the bundle. A missing child, descriptor mismatch, or traversal limit skips the entire new required graph, while other attachments may still succeed. Optional attachments are then discovered on each collected manifest or index, so signatures attached to SBOMs also cross the diode. Index membership alone does not create an OCI `subject` relationship.

Traversal is bounded to 64 artifact documents, 256 artifact-manifest fetch attempts, and 16 levels of required index children per requested reference. Repeated digests are reused and index cycles are rejected. Exceeding a limit emits a warning. The limits also apply to directly collected artifacts; if their required graph cannot be completed, that reference fails collection. Zero-length blobs are accepted only when their actual size and digest verify.

The repository stores each artifact by immutable digest and resolves its mutable tags in one repository-wide map. When a signature tag changes, the tag serves the new artifact and the old artifact remains pullable by digest, including its blobs. A refresh that discovers fewer attachments, including a failed discovery request, preserves previously imported artifacts. Absence from a collection does not delete an attachment.

`GET /v2/<name>/referrers/<digest>` advertises only matching `subject` relationships found in the stored manifest bytes. Artifact type and annotations also come from those bytes. A legacy cosign tag or a BuildKit index annotation alone does not create an OCI referrer; these artifacts remain available through their imported tags or digests. `?artifactType=...` filters the native referrers. Artifact tags stay out of `tags/list`, which lists collected image tags.

Existing repository indexes are rebuilt automatically on first access or import, using stored manifests, and the upgraded index is saved atomically. No re-collection is needed for native relationship repair. Old indexes did not record when conflicting signature tags were observed: migration preserves their first effective mapping and logs the conflict; collecting the image again resolves that tag from upstream. A missing or corrupt stored artifact prevents migration and leaves the existing index intact.

Update the high side before collecting index artifacts or subjectless artifact nodes with the updated low side: older importers reject these new graph records.

### Routes

| Route | Response |
|---|---|
| `GET /v2/` | version probe: `{}`, header `Docker-Distribution-API-Version: registry/2.0` |
| `GET /v2/_catalog` | `{"repositories": ["docker.io/library/alpine", ...]}` (empty is `[]`) |
| `GET /v2/<name>/tags/list` | `{"name": "<name>", "tags": [...]}` — tagged images only, sorted |
| `GET\|HEAD /v2/<name>/manifests/<ref>` | manifest by tag or `sha256:` digest |
| `GET\|HEAD /v2/<name>/blobs/<digest>` | blob by `sha256:` digest |
| `GET\|HEAD /v2/<name>/referrers/<digest>` | OCI index of genuine native referrers, optionally filtered by `artifactType` |

`<name>` is the registry-namespaced repository, e.g. `docker.io/library/alpine`. Because the name itself contains slashes, the route keyword is matched immediately before the final reference; repository components may themselves be named `manifests`, `blobs`, or `referrers`. A manifest response sets `Content-Type` to the stored `media_type`, plus `Docker-Content-Digest` and `Content-Length`; `HEAD` returns headers only. Blobs are served via `http.ServeFile` with `Content-Type: application/octet-stream` and `Docker-Content-Digest`.

### Error codes

Errors use the standard OCI JSON shape `{"errors":[{"code":"...","message":"..."}]}`:

| Situation | Status | Code |
|---|---|---|
| Non-GET/HEAD method | 405 | `UNSUPPORTED` |
| Malformed repository name | 404 | `NAME_INVALID` |
| Unknown repository | 404 | `NAME_UNKNOWN` |
| Manifest / tag not found | 404 | `MANIFEST_UNKNOWN` |
| Bad blob digest | 404 | `DIGEST_INVALID` |
| Blob not found for this repo | 404 | `BLOB_UNKNOWN` |

!!! note "Per-repo isolation over the shared store"
    Although blobs are physically shared across all repositories, a served repo can only expose content **its own index references**. A manifest is served only if found in that repo's index (by tag or digest), and a blob only if the requesting repo's index references it (as a manifest, config, or layer digest) — so `docker.io/...` can never expose `ghcr.io/...` content, even by digest.

## Client pull

Point the client at the high side and prefix the upstream registry namespace onto the repository:

```bash
docker pull <high-host>/docker.io/library/alpine:3.20
docker pull <high-host>/ghcr.io/org/app:v1
```

The same form works with `podman` and `containerd` — a read-only registry is all a pull needs. Because the served name is `<registry>/<repository>`, `docker.io` and `ghcr.io` content stay in separate namespaces and never collide.

For a collected opaque artifact, ORAS can pull its files or copy its native attachment graph:

```bash
oras pull <high-host>/ghcr.io/org/artifact:v1
oras cp --recursive --to-oci-layout <high-host>/ghcr.io/org/artifact:v1 ./artifact-layout:v1
```

Legacy cosign signature tags remain separate from that native graph and can be verified against the mirror with the original public key. CI exercises real ORAS discovery/copy/pull and local-key cosign verification through a signed low-to-high transfer, using a local upstream registry.

### HTTPS vs. insecure-registries

By default `docker` requires HTTPS to any registry that is not `localhost`. The recommended setup is to terminate TLS on the ArtiGate high side — see [TLS / HTTPS](../tls.md) for the four modes (`unencrypted`, `own-certificate`, `auto-generate-certificate`, `acme`). Over HTTPS no client-side registry configuration is needed.

If the high side runs plain HTTP, mark it insecure in the Docker daemon config at `/etc/docker/daemon.json`:

```json
{ "insecure-registries": ["<high-host>"] }
```

Then restart the daemon:

```bash
sudo systemctl restart docker
```

!!! tip "The dashboard renders this for you"
    The high-side "Set me up" guide generates the exact `daemon.json` block, the restart command, and ready-to-copy `docker pull` lines for your host. Over HTTPS it omits the `insecure-registries` entry entirely.

## Limitations

- **`linux/amd64` only** — the upstream index is preserved, but other platform images are not downloaded.
- **One login per pull** — the `auth` field names a single registry; pulls needing different logins for different registries run as separate collects (standing `ARTIGATE_CONTAINER_AUTH` entries cover any number of registries).
- **Scheduled pulls authenticate only via `ARTIGATE_CONTAINER_AUTH`** — watch specs carrying an `auth` key are rejected, because specs are stored and echoed in plaintext.
- **`sha256` digests only** — every other algorithm is rejected at parse, verify, and serve time.
- **Foreign / non-distributable layers are rejected** outright.
- **Registry ports are unsupported** — a port cannot appear in the high-side pull name, so such references are rejected at parse time.
- **A literal tag that looks like a constraint** (e.g. `1.26.x`, or anything with `< > = ~ ! ,` / space) is unreachable by name — pin it by digest.
- **Constraint resolution ignores variant and non-numeric tags** (`-alpine`, `-slim`, date tags, `latest`).
- **`tags/list` is capped at 100 pages**; manifests and preserved indexes at 4 MiB; token responses at 1 MiB.
- **The registry is read-only** — all writes return `405`, so it cannot be a push target.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only registry
- [Scheduling (watches)](../scheduling.md) — recurring re-resolution of constraints
- [TLS / HTTPS](../tls.md) — enabling HTTPS so clients pull without insecure-registries
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
