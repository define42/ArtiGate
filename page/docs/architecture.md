# Architecture

ArtiGate is a single Go binary that mirrors artifact ecosystems across a one-way data diode. This page is the deep model: how a low-side *exporter* turns upstream artifacts into signed, sequenced **bundles**, how those bundles cross the diode, and how a high-side *importer* verifies them and rebuilds every repository index from the artifacts themselves — trusting nothing that was transferred except bytes that pass an Ed25519 signature and a SHA-256 hash.

!!! note "Two design constraints drive everything below"
    - **Lean on the stdlib.** The core mirroring pipeline uses only two third-party dependencies: pure-Go SQLite (`modernc.org/sqlite`) for the [watch scheduler](scheduling.md) and the export-dedup index, and `hashicorp/go-version` for [container](ecosystems/containers.md) tag constraints. The optional TLS, login, and UDP-diode features add four more: `caddyserver/certmagic` for automatic HTTPS, `gorilla/securecookie` for login sessions, `golang.org/x/crypto` for argon2id auth hashes, and `klauspost/reedsolomon` for the [built-in UDP diode](data-diode.md)'s forward error correction — six direct dependencies in all, linked into the single binary.
    - **The low side delegates fetching** to the installed `go` / `git` / `pip` / `mvn` / `npm` toolchains. **The high side never invokes them and never reaches upstream.** It only serves what crossed the diode.

## The big picture

One binary, four subcommands (`keygen`, `low`, `high`, plus `hashpw` for low-side auth hashes). Data flows in exactly one direction:

```text
  ┌──────────────── LOW SIDE (internet-facing) ────────────────┐
  │                                                            │
  │  operator ──POST /admin/{eco}/collect──▶ runLow            │
  │                                            │               │
  │            native toolchains (go/pip/…) ◀──┘ fetch          │
  │                                            │               │
  │            build + Ed25519-sign bundle ────┤               │
  │                                            ▼               │
  │      <root>/bundles  (archive)      --export-dir           │
  │      retained for re-export         /var/spool/diode-out   │
  └────────────────────────────────────────────┬──────────────┘
                                                │
                       ═══ ONE-WAY DATA DIODE ═══  (folder move, HTTP upload,
                                                │   or the built-in UDP pitcher/catcher)
  ┌────────────────────────────────────────────▼──────────────┐
  │  --landing /var/spool/diode-in                             │
  │                                            │               │
  │  importLoop (ticks) ──▶ verify sig+hashes ─┤ HIGH SIDE     │
  │                          install immutably │ (isolated)    │
  │                          regenerate indexes│               │
  │                                            ▼               │
  │  serve  /go /simple /maven /apt /rpm /v2 /npm /hf /api    │
  └────────────────────────────────────────────────────────────┘
```

1. **Low side** (`runLow`) is an *exporter*, not a proxy. Its HTTP handler rejects anything that is not an `/admin/*` route or the dashboard — "the low side is an exporter, not a module proxy." Operators drive it with `POST /admin/{ecosystem}/collect`; it fetches with the native tools and writes a signed **bundle** (three files) into the export directory (default `/var/spool/diode-out`).
2. **The diode transfer** moves those three files from the low export dir to the high **landing** dir (default `/var/spool/diode-in`). By default ArtiGate never performs this move — it is your diode/guard — but the optional [HTTP transport](#optional-http-transport) lets the two sides do it themselves for diodes that speak HTTP, and the [built-in UDP diode](data-diode.md) drives a one-way fiber directly.
3. **High side** (`runHigh`) watches the landing dir on a ticker, imports bundles **strictly in sequence order per stream**, verifies signature + hashes, installs artifacts immutably, and **regenerates** all repository metadata from the artifacts actually present. Then it serves read-only clients.

See [Low side](low-side.md) and [High side](high-side.md) for operating each half, and [Security &amp; trust](security.md) for the threat model.

## Streams: independent per-ecosystem numbering

Each ecosystem is its own **stream** with its **own independent sequence counter**, so a lost or out-of-order bundle in one stream never blocks the others.

```go
const (
    streamGo         = "go"
    streamPython     = "python"
    streamMaven      = "maven"
    streamApt        = "apt"
    streamRpm        = "rpm"
    streamContainers = "containers"
    streamNpm        = "npm"
    streamHF         = "hf"
)
```

`knownStreams()` returns all eight; they appear in status even before anything has been exported. The `go` stream deliberately keeps the pre-multi-stream numbering for backward compatibility.

| Concern | Low side | High side |
|---|---|---|
| State file | `<root>/low-state.json` (mode `0600`) | `<root>/import-state.json` |
| State struct | `LowState.Sequences map[string]int64` — **next** sequence per stream | `HighState.Imported map[string]int64` — **last-imported** sequence per stream, plus `ImportedAt` |
| Legacy migration | `next_sequence` → `Sequences["go"]` on load | `last_imported_sequence` → `Imported["go"]` on load |

!!! tip "Why streams are independent"
    A long APT mirror and a quick Python collect run **concurrently**. Per-stream export locks (`streamLock`) serialize each stream's *allocate → write → commit* so two exporters on one stream can't claim the same sequence, while different streams proceed in parallel. These locks are deliberately separate from the fast `mu` that guards status readers — status must never block for the minutes a bundle write takes.

## The bundle format

One transferable bundle is **three files** sharing a bundle ID:

| File | Contents |
|---|---|
| `<bundleID>.tar.gz` | The artifact archive — only the manifest's **non-prior** files (see [delta bundles](#export-deduplication-and-delta-bundles)) |
| `<bundleID>.manifest.json` | The manifest — **these exact bytes are what gets signed** |
| `<bundleID>.manifest.json.sig` | Detached Ed25519 signature, base64 + trailing newline |

**Bundle ID**: `fmt.Sprintf("%s-bundle-%06d", stream, seq)` — e.g. `go-bundle-000042`, `python-bundle-000007`. The parser (`^([a-z0-9]+)-bundle-([0-9]{6,})\.manifest\.json$`) accepts **6 or more** digits, so sequences past `999999` still parse; ordering compares the parsed integer, not the string.

### BundleManifest

```go
type BundleManifest struct {
    Type             string             `json:"type"`               // always "go-module-bundle"
    Stream           string             `json:"stream,omitempty"`   // empty ⇒ legacy "go"
    Sequence         int64              `json:"sequence"`
    PreviousSequence int64              `json:"previous_sequence"`  // == Sequence-1
    Created          time.Time          `json:"created"`
    Generator        string             `json:"generator"`          // hostname
    BundleID         string             `json:"bundle_id"`
    Ecosystems       []string           `json:"ecosystems,omitempty"`
    Modules          []ManifestMod      `json:"modules,omitempty"`     // Go
    Python           *PythonManifest    `json:"python,omitempty"`
    Maven            *MavenManifest     `json:"maven,omitempty"`
    Apt              *AptManifest       `json:"apt,omitempty"`
    Rpm              *RpmManifest       `json:"rpm,omitempty"`
    Containers       *ContainerManifest `json:"containers,omitempty"`
    Npm              *NpmManifest       `json:"npm,omitempty"`
    HuggingFace      *HFManifest        `json:"huggingface,omitempty"`
    Files            []ManifestFile     `json:"files"`               // flat authoritative file set
}
```

!!! warning "`Type` is always `\"go-module-bundle\"`"
    The `Type` value is the legacy constant `"go-module-bundle"` for **every** ecosystem — it is *not* per-ecosystem. Do not use it to detect the ecosystem. The real ecosystem is carried by `Stream` plus whichever sub-manifest pointer is populated.

### ManifestFile — the atomic verified unit

Everything the high side installs is a `ManifestFile`. Each is independently hash-verified.

```go
type ManifestFile struct {
    Path   string `json:"path"`             // slash-relative repo path
    SHA256 string `json:"sha256"`           // exactly 64 hex chars
    Size   int64  `json:"size"`
    Prior  bool   `json:"prior,omitempty"`  // already forwarded on this stream — listed, not archived
}
```

The flat `Files` slice is the **authoritative** set: it is what the archive is checked against on import, and every ecosystem sub-manifest must reference paths that appear here. A file marked `prior` was already shipped in an earlier bundle on the same stream — it stays in the manifest so the repository reference set is complete, but it is **not packed into the archive**; the importer verifies it against the accumulated repository instead.

### Ecosystem sub-manifests

Each sub-manifest wraps a slice and carries **raw upstream metadata for high-side regeneration** — never for trust:

| Stream | Sub-manifest | Carries (examples) |
|---|---|---|
| Go | `Modules []ManifestMod` | `Files` keyed by `"info"` / `"mod"` / `"zip"` |
| Python | `Python.Projects` | `normalized_name` (PEP 503), `requires_python`, `yanked` |
| npm | `Npm.Packages` | `integrity` (SRI) — high side **recomputes** it from the tarball |
| APT | `Apt.Mirrors` | the raw `Packages` **stanza** string per `.deb`, per suite |
| RPM | `Rpm.Mirrors` | per-package repodata inputs |
| Maven | `Maven.Artifacts` | coordinates + files |
| Containers | `Containers.Repos` | registry/repository, manifest+config+layer digests |

### Deterministic archive

Bundles are byte-reproducible: every tar entry is written with mode `0644`, `ModTime = time.Unix(0, 0).UTC()`, and `Name = mf.Path`.

## Ed25519 signing

```text
keygen ──▶ low.ed25519       (private, base64, mode 0600)  ─── stays on low side
       └─▶ high.ed25519.pub  (public,  base64, mode 0644)  ─── copied to high side
```

- **Keygen** (`runKeygen`) uses `ed25519.GenerateKey`. Keys are stored base64, whole-file, and length-checked against `ed25519.PrivateKeySize` / `PublicKeySize` on load.
- **Signing** is over the *canonical manifest bytes*. In the writer, the manifest is serialized with `json.MarshalIndent(manifest, "", "  ")`, and `sig := ed25519.Sign(s.privateKey, manifestBytes)`. The **exact `manifestBytes` written to disk are what is signed** — the signature file is `base64.StdEncoding.EncodeToString(sig) + "\n"`.
- On import the high side re-reads those same on-disk bytes and calls `ed25519.Verify`. Field order and indentation are therefore load-bearing.

!!! warning "Never rewrite a manifest in place"
    Because the signature is over the exact serialized bytes — not a re-marshal — any tool that reformats or re-orders the manifest JSON invalidates the signature. Move the three files together, untouched.

`--private-key` is **required** on the low side; `--public-key` is **required** on the high side. See [Security &amp; trust](security.md).

## Low side: write, archive, export

`writeBundleArtifacts` is the shared writer for every ecosystem (its `baseDir` is the Go module cache for Go, a staging dir for the others):

1. `createTarGzAtomic` — write to `.tmp` with `O_CREATE|O_EXCL`, fsync, then atomic `os.Rename`.
2. Atomically write the manifest (`0644`) and the base64 signature (`0644`).
3. `archiveBundle` — copy all three files into the persistent archive `<root>/bundles`.

So a bundle lives in **two** places:

| Location | Purpose | After the diode transfer |
|---|---|---|
| `--export-dir` (`/var/spool/diode-out`) | staged for the diode; the transfer — or a successful HTTP/UDP diode upload — moves these out | gone (forwarded) |
| `<root>/bundles` | retained for [re-export](low-side.md) | kept |

`GET /admin/bundles` surfaces `InArchive` / `InOutbound` booleans and `SizeBytes` per sequence: a forwarded bundle is archive-only; a not-yet-sent one is in both.

### The mark-prior → allocate → write → commit → record path

`exportIfNew` is the shared core, applied by every collector while holding that stream's lock, with dedup resolved **first**:

```text
if not force:
        markPriorFiles(stream, files)     # flag every already-forwarded file as prior
if countDelivered(files) == 0:            # nothing new at all
        return {Skipped: true, "no new content since the last export"}   # NO sequence consumed
seq := peekSequence(stream)     # reads Sequences[stream], clamped ≥1; does NOT advance
res := write(seq)               # build + sign + write bundle (archive carries non-prior files only)
commitSequence(stream, seq)     # sets Sequences[stream] = seq+1, persists state
res.PriorFiles = <prior count>  # reported back to the dashboard / schedule
recordForwarded(stream, files)  # record hashes AFTER the commit succeeds
uploadBundleIfConfigured()      # HTTP diode, if ARTIGATE_DIODE_URL is set — failure is reported, never fatal
```

!!! note "Ordering is a correctness invariant"
    Hashes are recorded in the dedup index **only after** the sequence commit succeeds. If the commit fails, the content is not durably part of the stream, so a retry must re-export it rather than see it as "already forwarded" and wrongly skip.

Collectors also refuse to burn a sequence on an empty bundle — "the high side would then wait on it forever." The Go collector, for example, fetches *before* allocating a sequence, skips individually-unfetchable modules into `SkippedModules` rather than aborting the batch, and never writes an empty bundle.

## Export deduplication and delta bundles

A per-stream index of everything already forwarded lets a scheduled re-pull of an unchanged upstream stop re-sending — and often re-downloading — bytes the high side already has. It is a SQLite DB at `<root>/exported.db`:

```sql
CREATE TABLE IF NOT EXISTS forwarded_files (
  stream TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  path   TEXT NOT NULL,
  PRIMARY KEY (stream, sha256, path)
) WITHOUT ROWID
```

- **What it records**: for every file ever written into a bundle (i.e. forwarded across the diode), its `(stream, sha256, path)`. Writes use `INSERT OR IGNORE` in one transaction (idempotent via the primary key). Rows from the pre-delta schema carry an empty path and still match by hash alone; they are path-qualified the first time they are touched.
- **Nothing new**: when *every* file is already forwarded, `exportIfNew` returns `Skipped: true`, **consumes no sequence number**, and writes no bundle.
- **Delta bundles**: when only *some* files are new, the bundle is still written — but already-forwarded files are marked `prior` in the manifest and left out of the archive. The `ExportResult.prior_files` count reports how many rode along as references.
- **Pre-download skip**: collectors whose upstream declares a file's SHA-256 *before* the bytes are fetched — APT `Packages` indexes, RPM `primary.xml`, container image digests, Hugging Face LFS metadata — consult the index first and skip the download entirely. The pip/mvn/npm/go-driven collectors have no usable pre-download hash, so they still download (Go's module cache already avoids re-downloads) and dedup after hashing.
- **Force**: every collect request accepts `"force": true`, which bypasses the index for that collect and produces a full, self-contained bundle — the disaster-recovery path when a high side is rebuilt from scratch.
- **Fail-safe**: an empty file set is never "all forwarded"; any store error is logged ("exporting without dedup") and treated as *not forwarded*. The index is an *optimization, not correctness state* — it never suppresses content when unsure.

!!! warning "Deliberately independent of the bundle archive"
    The dedup index is kept separate from `<root>/bundles` on purpose. Rebuilding it from archived manifests would let archive pruning "forget" already-shipped content and re-ship it. The DB uses `SetMaxOpenConns(1)` + `PRAGMA busy_timeout=5000` (single-writer, serialized), so a SQLite failure can never wedge the JSON-based sequence pipeline.

Two more properties: dedup is **per-stream** — it does not dedup across streams. And **re-export bypasses it entirely** — `POST /admin/reexport?stream=go&sequences=42,45-47` replays the *exact archived bytes* via `replayArchivedBundle` (no re-signing), never consulting or updating the dedup index. This is how the same content can be re-shipped after a lost transfer without being wrongly skipped.

!!! note "A delta bundle assumes its history"
    A bundle whose manifest lists `prior` files imports only on a high side that has already imported this stream's earlier bundles. On a fresh or pruned high side the import fails with *"bundle references prior file … that is not in the repository: import this stream's earlier bundles first, or run a forced (full) re-collect on the low side"* — which is also the fix.

## The diode transfer

By default ArtiGate does not move files across the diode — your data-diode or cross-domain guard does. The contract is minimal:

- Move the three files of each bundle (`.tar.gz`, `.manifest.json`, `.manifest.json.sig`) from the low `--export-dir` to the high `--landing` dir.
- The transfer is **one-way**: nothing ever flows high → low. There is no acknowledgement channel, which is exactly why the low side retains `<root>/bundles` for operator-driven re-export.
- A partially-arrived bundle is simply not yet "complete" on the high side (see below) and is skipped until all three files are present.

### Optional HTTP transport

For diodes (or diode proxies) that speak HTTP instead of moving files, both sides also implement the transfer themselves, configured by environment variables (see [Deployment](deployment.md)): with `ARTIGATE_DIODE_URL` set, the low side uploads each bundle's three files (`PUT <url>/<file>`, the archive first) right after export and re-export, then clears them from the export dir — which keeps its exact spool semantics, staged-until-transferred; with `ARTIGATE_DIODE_INGEST=on`, the high side accepts uploads at `PUT/POST /diode/<file>`, streams them atomically into the landing directory, and imports a completed bundle immediately instead of waiting for the next scan tick. An optional shared bearer token (`ARTIGATE_DIODE_TOKEN`) gates the endpoint.

The transport carries **zero trust**: an uploaded bundle enters the same verify-and-import pipeline as a diode-carried file — signature, sequencing, and every hash are still checked. A failed upload never loses a bundle; the collect still succeeds, the failure is reported (`diode_error` in the result, and on a schedule's status), and the staged bundle is re-transmitted from the Status page.

### Optional built-in UDP diode

For a real one-way fiber with no proxy software at all, the low side's **pitcher** transmits every bundle as rate-limited, Reed-Solomon-coded IPv6 link-local multicast out a dedicated NIC, and the high side's **catcher** reassembles the datagrams into the landing directory and triggers an immediate import. The wire, like the HTTP transport, carries zero trust. See [Built-in UDP diode](data-diode.md) for the full design and tuning guide.

## High side: strict in-order import per stream

`importLoop` ticks every `--import-interval` (default **10s**; `0` disables the background importer, leaving only `POST /admin/import`). Each tick calls `ImportNext`, which holds `s.mu` for the whole operation.

**Sort first** — `quarantineFutureBundlesLocked` scans the landing dir and routes each complete bundle:

| Condition | Destination |
|---|---|
| `seq > next` | move to `--quarantine` (default `<root>/quarantine`) — a future/out-of-order bundle |
| `seq <= Imported[stream]` | move to `<landing>/duplicates` — an already-imported replay |
| `seq == next` | left in place, ready to import |

**Then drain** — for each known stream, repeatedly compute `next = Imported[stream] + 1`, find `bundleIDFor(stream, next)` via `findBundleDirLocked` (which checks **landing then quarantine**), import it, advance, and repeat. If the next bundle isn't found, that stream `break`s and the others continue.

!!! tip "Auto-import when a gap fills"
    Because `findBundleDirLocked` also looks in quarantine, a future bundle that was set aside is imported automatically the moment its missing predecessor arrives and is imported — no operator action needed. A permanently missing bundle blocks only its own stream, forever, never the others.

The chain link is enforced: a manifest's `PreviousSequence` must equal the high side's current `Imported[stream]`. Bundles import strictly consecutively; gaps quarantine, they never skip forward.

## Verification on import

`importBundleFromDirLocked` is the gate every artifact passes through:

1. **All three files present**, or the bundle is "incomplete" and skipped.
2. **`loadVerifiedManifest`** — read the manifest bytes + signature, base64-decode the sig, and `ed25519.Verify(s.publicKey, manifestBytes, sig)` on the **raw on-disk bytes**. Failure ⇒ "signature verification failed".
3. **`checkManifestFields`** — `Type == "go-module-bundle"`; `Stream` matches (empty ⇒ `go`); `Sequence == expectedSeq`; `PreviousSequence == Imported[stream]`; `BundleID` matches; then `validateManifestCompleteness` requires valid `Files` (64-hex SHA-256, safe relative paths) and at least one populated ecosystem section, each cross-checked so every declared artifact references a path present in `Files`.
4. **Extract + hash-verify the archive** into `<root>/tmp/<bundleID>`: each tar entry must be a regular file, must be listed in the manifest (an `unexpected file` is rejected), its **size must match**, its path must `safeJoin` under staging (blocking traversal), and its **streaming SHA-256 must equal the manifest hash**. Any non-prior manifest file missing from the archive is an error.
5. **Check prior files** — a file marked `prior` is not in the archive at all: it must already sit in the accumulated repository. Repository installs are immutable and were hash-verified when they first arrived, so the importer checks **existence and size** (re-hashing every prior file would make a large delta import as expensive as a full one). A missing prior file fails the import with *"bundle references prior file `<path>` (sha256 `<hash>`) that is not in the repository: import this stream's earlier bundles first, or run a forced (full) re-collect on the low side"*.
6. **Install** the verified files, then **regenerate metadata** (below).
7. On success: set `Imported[stream] = manifest.Sequence` and `ImportedAt`, save state, and move the three landing files into `<landing>/imported`.

### Immutable installs

`installVerifiedFile` makes every repo path **write-once**:

- If the destination already exists, it is re-hashed. A different hash ⇒ **`"immutable file conflict"`** error. A matching hash ⇒ **no-op** (re-imports are idempotent).
- Otherwise the file is copied atomically at `0644`.

Content can never be silently mutated across bundles. For Go, a `.complete` marker is written per module **only after all its files are installed**, and the proxy's `isComplete` requires that marker plus the `.info` / `.mod` / `.zip` before serving a version — so half-installed versions are never visible.

## The trust model: regenerate, never trust transferred indexes

This is the heart of ArtiGate. The high side treats **the artifacts themselves as the only source of truth** and rebuilds all repository metadata locally, after signature + hash verification. It never serves a transferred index, `latest`, `Release`, packument, or repodata file.

| Ecosystem | What the high side regenerates |
|---|---|
| APT | `InRelease` / `Packages` per suite from the accumulated stanzas of the `.deb` files now present — never the transferred Release/Packages. Optionally signed with `--apt-gpg-key` (unset ⇒ served unsigned). |
| RPM | `repodata` from the `.rpm` files present; `repomd.xml.asc` optionally signed with `--rpm-gpg-key`. |
| npm | The served packument from each tarball's own embedded `package.json` — never a transferred packument. `integrity` is **recomputed** from the artifact; the manifest's value is kept only for audit. |
| Containers | Per-repo `_index.json` merged from the manifests/blobs present; blobs served only if the requesting repo's own index references them. |
| Go | Listings are computed by scanning the `@v` directory for complete versions; `chooseLatest` is derived from the present `.info` files. There is no transferred "latest" the high side trusts. |

!!! note "Why this matters"
    Even a maliciously crafted bundle can only ever cause the high side to serve exactly the bytes whose SHA-256 the signed manifest committed to — and those bytes had to pass the archive hash check on the way in. The index a client browses is a *local derivation* of verified content, so a forged index in a bundle is simply ignored. See [Security &amp; trust](security.md) for the full argument.

## On-disk layout: content-addressed container blob store

The [container store](ecosystems/containers.md) is a good illustration of the on-disk model. Blobs are **content-addressed and shared across all repositories** — a layer used by ten images is stored once — using **3-character sharding** so no single directory holds millions of entries (`16³ = 4096` shard dirs — the same prefix-sharding idea git and Docker's registry use, though they shard on the first two hex chars while ArtiGate uses three):

```text
<root>/cache/download/containers/
├── blobs/sha256/
│   ├── ab1/ab1c9e…f0   ← blob whose digest starts sha256:ab1c9e…
│   ├── 3f2/3f2a77…9b
│   └── …               ← first 3 hex chars of the digest = shard dir
└── repos/
    └── docker.io/library/alpine/
        └── _index.json  ← per-repo index; served repo name is "<registry>/<repository>"
```

The shard key is `containerBlobShardHex(hex)` — the first 3 hex characters of the digest — and the bundle-relative path is `containers/blobs/sha256/<first3hex>/<full64hex>`. The `_index.json` name cannot collide with real content because a repository path component may not start with `_`. Per-repo isolation still holds over the shared store: a served repo can expose only blobs its own index references. Other ecosystems follow the same "verified artifacts on disk, metadata derived on demand" shape — and content addressing is what makes [delta bundles](#export-deduplication-and-delta-bundles) cheap, since a shared layer or model blob is forwarded exactly once.

## Where to go next

- [Low side](low-side.md) — collecting, re-exporting, watches, and the export dir.
- [High side](high-side.md) — importing, quarantine, status/missing, and serving.
- [Scheduling (watches)](scheduling.md) — recurring collects on a stored spec.
- [Built-in UDP diode](data-diode.md) — the pitcher/catcher transport.
- [Security &amp; trust](security.md) — the full trust argument and hardening.
- [Ecosystems](ecosystems/index.md) — the eight streams and their per-ecosystem details.
