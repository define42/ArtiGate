# Security & trust

ArtiGate is a two-process data-diode gateway. The **low side** fetches, verifies, signs and exports content bundles; the **high side** imports them, re-verifies every byte, regenerates its own repository metadata and serves the result read-only. This page explains the trust chain that makes that safe and the hardening you are responsible for at deployment time.

!!! note "The one-sentence trust model"
    The high side serves only content that (a) was covered by a valid Ed25519 signature, (b) hash-matches the signed manifest byte-for-byte, and (c) chains by sequence to the previously imported bundle — and it rebuilds all index/metadata itself rather than trusting anything transferred. New bundles use standard Ed25519ph so manifest hashing is streamed before verification; legacy raw-Ed25519 bundles remain readable under the manifest size cap. The high side never fetches upstream.

## Signing keys

Every bundle manifest is signed on the low side with an **Ed25519** key pair. The private key lives *only* on the low side; the high side only ever holds the public key.

### Generating a key pair

```bash
artigate keygen --private low.ed25519 --public high.ed25519.pub
```

| Flag | Default | Purpose |
|---|---|---|
| `--private` | `low.ed25519` | Private key output path (signs bundles on the low side) |
| `--public` | `high.ed25519.pub` | Public key output path (verifies bundles on the high side) |

On-disk format and permissions:

| File | Mode | Format |
|---|---|---|
| Private key | `0600` | base64 (standard encoding) of the raw key bytes + trailing newline |
| Public key | `0644` | base64 of the raw key bytes + trailing newline |

The keys are loaded and length-checked at startup: the private key must decode to exactly 64 bytes (`ed25519.PrivateKeySize`), the public key to exactly 32 bytes (`ed25519.PublicKeySize`), otherwise the process refuses to start.

The low server **requires** `--private-key`; the high server **requires** `--public-key`. A missing key is a fatal startup error.

```bash
# low side — holds the private key, is the only signer
artigate low  --private-key /etc/artigate/low.ed25519 ...

# high side — holds only the public key, verifies
artigate high --public-key  /etc/artigate/high.ed25519.pub ...
```

!!! warning "Keep the private key on the low side only"
    Distribute `high.ed25519.pub` to the high side (and only the public key). The private key must never cross the diode. Anyone holding it can forge bundles that the high side will accept as authentic. Store it with `0600` ownership on the low host and back it up out of band.

### Rotation caveats

There is no in-place key-rotation protocol. The high side trusts exactly one public key — the one passed as `--public-key`. To rotate:

1. Generate a new pair on the low side.
2. Stop signing new bundles with the old key.
3. Deliver the new public key to the high side and restart the high process with the new `--public-key`.

!!! warning "Rotation is a hard cutover"
    Bundles are verified against a single public key, so at the moment you swap the key on the high side, **every bundle still signed with the old key will fail verification** and will not import. Drain the diode — let the high side import all outstanding old-key bundles — before cutting over, or re-export the affected sequences after signing them with the new key. There is no dual-key/grace-period mode. Because the sequence chain is strict (each bundle's `previous_sequence` must equal the high side's last imported sequence), you cannot simply skip the un-importable bundles; the stream would block.

## The verification chain

### Low side signs the manifest

Each bundle is three files sharing a bundle ID (e.g. `go-bundle-000042`):

```text
go-bundle-000042.tar.gz            # the artifact archive
go-bundle-000042.manifest.json     # the signed bytes
go-bundle-000042.manifest.json.sig # detached Ed25519 signature (base64 + newline)
```

The manifest records, for every file in the archive, its slash-relative `path`, its `sha256`, and its `size`. It is serialized once with `json.MarshalIndent`, and the signature is computed over those **exact** manifest bytes as written to disk:

```go
sig := ed25519.Sign(s.privateKey, manifestBytes)
```

!!! note "The signed bytes are the on-disk bytes"
    Verification later re-reads the exact same bytes rather than re-marshalling, so byte-for-byte stability of the manifest JSON is load-bearing. Any tooling that rewrites or reformats a `.manifest.json` file will break its signature.

### High side verifies before installing

Import is strictly gated. `importBundleFromDirLocked` runs the following before any artifact is served:

1. **All three files present.** A missing archive, manifest, or signature errors with `bundle X incomplete: need archive, manifest and signature`.
2. **Signature check.** The `.sig` is base64-decoded and checked against the raw on-disk manifest bytes with `ed25519.Verify(s.publicKey, manifestBytes, sig)`, *before* the JSON is unmarshalled. Failure → `signature verification failed for X`.
3. **Field / chain checks** (`checkManifestFields`):
    - `type` is the expected manifest type;
    - `stream` matches (an empty stream is treated as legacy `go`);
    - `sequence` equals the expected next sequence;
    - `previous_sequence` equals the high side's last imported sequence for that stream — **strict monotonic chaining, no gaps and no replays**;
    - `bundle_id` matches;
    - the manifest is structurally complete (every declared artifact references a path present in the flat `files` list, each `sha256` is exactly 64 hex chars, and at least one ecosystem section is populated).
4. **Extract-and-hash.** `extractAndVerifyTarGz` walks every tar entry: it rejects non-regular files, rejects any file not listed in the manifest (`archive contains unexpected file`), checks the size, and recomputes SHA-256 **while extracting** (`io.MultiWriter(out, h)`). Paths are validated for traversal safety (`safeJoin`, `O_EXCL`). Finally it requires that every non-prior manifest file was seen (`archive missing file X`). Only content whose hash matches the signed manifest reaches staging.
5. **Prior-file check.** A manifest entry marked `prior` (a [delta bundle](architecture.md#export-deduplication-and-delta-bundles)) is deliberately absent from the archive: it must already exist in the accumulated repository at the manifest path and size, or the import fails naming the missing file. This does not weaken the model — that content passed the full signature + hash gate when it first crossed, and installs are immutable, so path + size identifies exactly the bytes the earlier verification pinned.
6. **Immutable install.** `installVerifiedFile` treats mirrored content as write-once: an existing file whose SHA-256 differs is a hard error (`immutable file conflict for X`); identical content is an idempotent no-op. Exactly two subtrees are exempt because their content is *updates by design* — operator `uploads/` (re-uploading a name replaces it) and `osv/` advisory-database snapshots (each import replaces the previous snapshot at its canonical path). Both still arrive only through the full signature + hash gate of a correctly sequenced bundle.

### High side regenerates metadata — never trusts transferred indexes

After the verified files are installed, the high side rebuilds all served repository metadata from the artifacts themselves, deliberately ignoring any index that crossed the diode:

- **APT** — regenerates `Release`/`Packages` from the stanzas of the `.deb` files now present (never trusting a transferred `Release`/`Packages`). The regenerated `InRelease` is optionally signed with `--apt-gpg-key`.
- **RPM** — regenerates `repodata`; optionally signs `repomd.xml.asc` with `--rpm-gpg-key`.
- **npm** — regenerates the served packument from each tarball's own embedded `package.json`. The manifest's `integrity` value is kept only for audit and recomputed from the artifact.
- **Containers** — regenerates the served registry metadata.
- **Go** — listings are computed from the `.info`/`.mod`/`.zip` files on disk; a version is only visible once its `.complete` marker and all three files are present. There is no transferred "latest" index that the high side trusts.
- **Crates** — regenerates every served sparse-index file from the manifest-carried index lines, and never serves a line whose `cksum` does not equal the byte-verified artifact's SHA-256 (re-checked at import).
- **OSV** — regenerates `ecosystems.txt`, the per-database metadata (advisory counts, hashes), and the npm bulk-audit index from the verified database zips themselves; advisory bodies are served straight out of those zips.
- **Terraform** — regenerates provider version lists and download descriptors after cross-checking every zip against the mirrored `SHA256SUMS`; terraform's own chain (shasum → `SHA256SUMS` → GPG key) then verifies against the mirrored upstream signatures.
- **Helm** — regenerates each mirror's `index.yaml` from the charts' own embedded `Chart.yaml`, with digests recomputed from the artifacts (never trusting a transferred index).
- **NuGet** — regenerates the served v3 feed metadata from each package's own embedded `.nuspec`.
- **Alpine** — regenerates `APKINDEX.tar.gz` from the manifest-carried stanzas of the `.apk` files now present; optionally signed with `--apk-rsa-key`.

### No upstream fetch on the high side

The high side has **no HTTP client and no upstream fetcher**. Its only loops are the import loop and the read-only serving mux. Missing content returns `404` — it is never fetched from anywhere. (All upstream/fetch configuration lives on the low side — e.g. `--upstream-goproxy`, `--npm-registry`, `--container-registry`, `--gosumdb`, `--crates-index`, `--terraform-registry`, `--nuget-source`; the high side has none.) This is the property the diode exists to guarantee: nothing the high side serves came from the network, only from a signed, hash-verified, sequence-chained bundle.

## Low-side authentication

Authentication is **optional**, **off by default**, and **low side only**. It is configured entirely through environment variables and gated on the presence of `ARTIGATE_LOW_AUTH`.

!!! danger "Unauthenticated by default — including all of `/admin/*`"
    With no `ARTIGATE_LOW_AUTH` set, the low side is **fully open**. Anyone who can reach the listener can drive collects and re-exports and read every admin endpoint:

    - `POST /admin/{go,python,maven,apt,rpm,containers,npm,hf,crates,terraform,helm,nuget,apk}/collect` — trigger fetching and export
    - `POST /admin/reexport?stream=go&sequences=42,45-47` — replay archived bundles
    - `GET /admin/bundles` — bundle status
    - the dashboard UI and the watches routes

    In production, **either set `ARTIGATE_LOW_AUTH` or place the low side behind strict network controls** (see [Network placement](#network-placement)). `GET /healthz`, `GET /readyz`, and `GET /metrics` are always reachable, even when auth is enabled, so health probes and monitoring keep working.

### `ARTIGATE_LOW_AUTH` — the credential set

The variable holds one or more `username:<hash>` entries. Each hash is an argon2id PHC string produced by `artigate hashpw`.

| Rule | Detail |
|---|---|
| Separator | `;`, newline, or carriage return — **not commas** (commas appear inside an argon2 PHC hash: `m=…,t=…,p=…`) |
| Entry format | `username` and hash split on the **first** `:`; empty username or hash is rejected |
| Hash prefix | Each hash must start with `$argon2id$`, else `credential for "X" is not an argon2id hash` |
| Multiple users | Supported — list several entries |
| Empty value | Auth disabled (no credentials, no error) |

!!! warning "Fail-closed on a broken value"
    A non-empty `ARTIGATE_LOW_AUTH` that yields **zero** valid credentials — for example `";"` or stray whitespace from a Compose quoting slip — is a startup **error** (`ARTIGATE_LOW_AUTH is set but contains no valid credentials`), not silently-disabled auth. An operator who tried to enable auth is never left with an open dashboard by accident.

Example (two users, semicolon-separated):

```bash
export ARTIGATE_LOW_AUTH='alice:$argon2id$v=19$m=65536,t=3,p=1$...$...;bob:$argon2id$v=19$m=65536,t=3,p=1$...$...'
```

### `hashpw` — generating argon2id hashes

```bash
# reads the password from stdin so it never appears in process args
artigate hashpw --user alice
```

| Flag | Default | Behavior |
|---|---|---|
| `--user` | (empty) | If set, output is `user:hash`; otherwise just `hash` |
| `--password` | (empty) | Password to hash; **if empty, one line is read from stdin** |

When `--password` is omitted, the password is read as a single line from stdin (trailing `\r\n` stripped), so the secret never lands in your shell history or the process command line. An empty password is rejected. The output is paste-ready into `ARTIGATE_LOW_AUTH`:

```bash
printf '%s' 'correct horse battery staple' | artigate hashpw --user alice
# alice:$argon2id$v=19$m=65536,t=3,p=1$...$...
```

New hashes use argon2id with memory `64 MiB`, `3` iterations, parallelism `1`, a 16-byte salt and a 32-byte key. Verification reads the parameters *out of the stored hash*, so you can strengthen these presets in future without invalidating existing credentials. Embedded parameters are sanity-bounded before use (iterations `1..2^20`, parallelism `1..255`, memory `8 KiB..1 GiB`, non-empty digest) so a malformed stored hash rejects the login rather than crashing it, and comparison is constant-time.

### Sessions and the login cookie

When at least one credential is configured, the low side enables form login and wraps its mux with the auth middleware:

- Session cookie `artigate_session`, valid **12 hours**, `HttpOnly`, `SameSite=Lax`, `Path=/`.
- The cookie is both **signed (HMAC)** and **encrypted (AES-256)** via `gorilla/securecookie`.
- Signing keys are persisted at `<root>/session.key` (96 bytes, mode `0600`). They are generated on first use, so **sessions survive a restart**. A wrong-size existing file errors with `...has size N, want 96; delete it to regenerate`.
- `POST /login` is memory-bounded: at most 4 argon2id verifications (each ~64 MiB) run concurrently, so the unauthenticated login endpoint cannot be turned into an OOM DoS; excess attempts queue on goroutines.
- Removing a user from `ARTIGATE_LOW_AUTH` and restarting invalidates that user's live sessions — the named user must still exist for a session to be accepted.

Middleware routing:

| Path | Behavior with auth enabled |
|---|---|
| `/healthz`, `/readyz`, `/metrics` | Always open (bypass auth — probes and scrapers cannot log in) |
| `/login`, `/logout` | Handled by the auth manager |
| Any other path | Requires a valid session |

Unauthenticated requests are handled by intent: a browser navigation (a `GET` sending `Accept: text/html`) is redirected `303` to `/login`, while an API/fetch call gets `401 unauthorized`.

### `ARTIGATE_LOW_COOKIE_SECURE`

Controls the `Secure` attribute of the session cookie. Only meaningful when auth is enabled.

| Value | Effect |
|---|---|
| `""` / `auto` (default) | Follow ArtiGate's own TLS — `Secure=true` iff ArtiGate is terminating TLS |
| `1` / `true` / `yes` / `on` | Force `Secure=true` |
| `0` / `false` / `no` / `off` | Force `Secure=false` |
| anything else | Startup error: `invalid ARTIGATE_LOW_COOKIE_SECURE "X" (want auto, true, or false)` |

!!! tip "Set `true` behind a TLS-terminating proxy"
    If ArtiGate speaks plain HTTP (`ARTIGATE_TLS_MODE=unencrypted`) behind a reverse proxy that terminates TLS, `auto` would produce `Secure=false` and browsers on the HTTPS front would drop the cookie. Set `ARTIGATE_LOW_COOKIE_SECURE=true` in that topology so the session cookie is still flagged `Secure`. See [TLS / HTTPS](tls.md).

## The high side is never authenticated

There is no `ARTIGATE_HIGH_AUTH` and no auth middleware on the high side. Its admin endpoints are open by design:

- `GET /healthz`, `GET /readyz`, and `GET /metrics`
- `POST /admin/import`
- `GET /admin/status` and `GET /admin/missing`

The high side's integrity comes from **signature + hash verification at import**, not from request authentication. It is a read-only repository intended to sit on the trusted/high network; anyone who can reach it can *read* what has already been verified, but nothing they send can inject content — writes only ever happen through the verified import path. Place it on a trusted segment accordingly.

### The one optional write surface: diode ingest

With `ARTIGATE_DIODE_INGEST=on` (off by default), the high side accepts bundle uploads at `PUT/POST /diode/<file>` — the receiving end of the [HTTP diode transport](deployment.md). This does **not** weaken the trust model: only supported stream names and positive bundle sequences are accepted, and nothing is served until signature, sequencing, and hash checks pass. Enabling ingest requires a whitespace-free bearer token of at least 32 bytes, compared in constant time. Before verification, archives are capped at 64 GiB, manifests at 16 MiB, signatures at 4 KiB, and direct unverified files across landing, quarantine, and rejected storage at 128 GiB. Completed uploads feed one bounded, coalescing import worker. Leave ingest off entirely when you use the folder flow.

### Upstream credentials on the low side

ArtiGate itself sends four kinds of upstream credentials, all read from the environment at collect time and never persisted:

- `ARTIGATE_HF_TOKEN` (a Hugging Face access token for gated models) is attached as a Bearer header to Hugging Face requests only.
- `ARTIGATE_CONTAINER_AUTH` (per-registry `host=user:password` container logins) — plus the equivalent one-shot `auth` field on a container collect request — is sent as HTTP Basic to the token endpoint a registry's `Bearer` challenge names (the `docker login` trust model: the registry chooses its realm, and each login is keyed to a single registry so it can only reach that registry's realm), or directly to a registry that challenges with `Basic`.
- `ARTIGATE_UPSTREAM_AUTH` (per-host `host=user:password` logins for git, APT, RPM, Alpine, and Conda upstreams) — plus the equivalent one-shot `auth` field on those collect requests — is sent as HTTP Basic to the mirror host it is keyed to.
- `ARTIGATE_GO_AUTH` (per-host `host=user:password` logins for private Go module hosts) — plus the equivalent one-shot `auth` field on a Go collect request. Go fetching is delegated to the `go`/`git` subprocesses, so the login is injected as a per-collect `0600` netrc + a host-scoped git credential helper, both removed when the collect ends (stale ones are scrubbed at startup should the daemon die mid-collect) and never written to the host's own git/netrc config. A standing Go credential also marks its host private (`GOPRIVATE`/`GONOSUMDB`/`GONOPROXY`) for the collect — the reason Go does not share `ARTIGATE_UPSTREAM_AUTH`: a git/APT login on a shared host such as `github.com` must never push that host's public module fetches off the proxy and checksum database.

Watch specs carrying credentials are rejected outright on every stream, so logins never land in the plaintext watch store or the dashboard. Upstream URLs that embed a `user:password@` are rejected too — the URL is copied into the signed manifest, progress lines, and error text, so a login there would leak, including across the diode.

No credential is ever forwarded: `net/http` drops the `Authorization` header on the cross-host CDN redirects that package, pack, blob, and model downloads follow, and no credential appears in bundles, manifests, logs, error messages, or the high side.

## Dependency-confusion guidance

The high side serves **only** what crossed the diode as signed, verified bundles, and it never reaches upstream. To keep that guarantee, high-side clients must point **exclusively** at ArtiGate with no fallback upstream. A missing package must **fail**, never silently resolve from a public registry — otherwise an attacker can get a same-named package pulled from elsewhere (a dependency-confusion / substitution attack), which is exactly what the diode exists to eliminate.

```bash
# Go: ,off forbids any upstream fallback (NOT ,direct)
export GOPROXY=http://high-proxy:8080/go,off
# GOSUMDB stays on: ArtiGate serves the mirrored checksum database at
# <base>/go/sumdb/, so verification needs no upstream either.
```

The same principle applies to every ecosystem — configure ArtiGate as the sole registry/mirror with **no secondary or public upstream**:

| Ecosystem | Rule |
|---|---|
| Go | `GOPROXY=<base>/go,off` — `,off` not `,direct`; `GOSUMDB` stays on (served from the mirror) |
| npm | ArtiGate as the only registry; no upstream fallback |
| Python (PyPI) | ArtiGate as the sole index; no extra `--extra-index-url` |
| Maven | ArtiGate as the only repository / mirror-of `*` |
| APT | Only the ArtiGate `sources.list` entry |
| RPM | Only the ArtiGate `.repo`; no other baseurls |
| Rust crates | Replace crates.io (`replace-with` in `~/.cargo/config.toml`); no second registry |
| Terraform / OpenTofu | ArtiGate as the `network_mirror` / source host; no direct registry fallback |
| Helm | ArtiGate mirrors as the only configured chart repositories |
| NuGet | `<clear />` in `nuget.config`, then ArtiGate as the sole source |
| Alpine | Only ArtiGate lines in `/etc/apk/repositories` — replace, don't append |

!!! warning "Do not add extra upstreams on the high side"
    The high side has no mechanism to add upstreams, so this guidance is entirely about **client** configuration. Any additional registry, mirror, or index configured on a high-side client reintroduces the confusion risk the diode was built to remove. Per-ecosystem client configuration is documented under [Ecosystems](ecosystems/index.md).

## Network placement

The trust boundary is physical: the low side lives on (or bridges to) the untrusted/low network where it fetches from the internet, and the high side lives on the trusted/high network and only ever receives files through the one-way diode.

Recommendations:

- **Low side** — treat it as internet-exposed for outbound fetches. Its admin surface is a control plane: put it behind network controls and/or enable `ARTIGATE_LOW_AUTH`. Never allow inbound traffic from the high network to the low side (that would defeat the diode).
- **Diode transfer** — ArtiGate never moves files across the gap itself; a one-way transfer copies the three bundle files from the low export directory (`/var/spool/diode-out`) to the high landing directory (`/var/spool/diode-in`). Keep that transfer strictly one-directional.
- **High side** — place it on the trusted segment. It is unauthenticated by design and read-only; restrict who can reach its listener to the clients that consume artifacts. Do not give it any outbound path to the internet — it must not need one, and its correctness depends on not having one.
- **TLS** — both sides read the same `ARTIGATE_TLS_*` variables; enable HTTPS per [TLS / HTTPS](tls.md), and when terminating TLS at a proxy, set `ARTIGATE_LOW_COOKIE_SECURE=true`.

## See also

- [TLS / HTTPS](tls.md) — enabling HTTPS with the same env vars on both sides.
- [Configuration reference](configuration.md) — every flag and environment variable.
- [Low side](low-side.md) and [High side](high-side.md) — operating each process.
- [Architecture](architecture.md) — the full bundle and import model.
