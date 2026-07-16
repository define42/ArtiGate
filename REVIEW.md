# ArtiGate — full code review

**Scope:** the whole `cmd/artigate` binary (~45k LOC of non-test Go across ~60 files).
Rounds 1–2 reviewed correctness, security (the diode trust boundary above all),
concurrency, and resource safety; round 3 (this branch) reviewed **performance,
operations, and completeness** — throughput and latency of the diode data path, import
and serve costs at mirror scale, disk-lifecycle gaps, and docs/test coverage drift.
Every finding below was verified against the source, not taken on faith.

**Verdict:** the security-critical core — the high-side verify-and-import pipeline, path
containment, archive extraction, manifest signature/sequence verification, the UDP wire
parser, auth/sessions, TLS — is **exceptionally well engineered** and I found no way
through it. The real defects are concentrated in the per-ecosystem *collect* and
*publish* code and in a few unauthenticated high-side endpoints. Every High/Medium from
the first round (H1–H2, M1–M10) is now **fixed**; a second review round found the M11–M13
class (unauthenticated per-request work on the public port) — request-cost/DoS, not
trust-boundary — and that class is now **fixed** too (M4b, L2 detail reads, M11, M12,
M13). The third round found **no new correctness or trust-boundary defects**: everything
works, and the whole validation suite is green. Its findings are performance and
operational: redundant full-file I/O on the bundle path (P1–P3, fixed), unbounded
processed-bundle disk growth and quota-pinning orphans on the high side (O1–O3, fixed),
and a documented backlog of larger wins (serial collects, import-lock coupling,
per-import index regeneration, HTTP caching) recorded as P/O recommendations below.

**Status at a glance (this branch):**
- **Fixed (rounds 1–2):** H1, H2, M1–M10; M11 (`/ui/api/detail` digests memoized),
  M12 (nuget search paged, composer packages.json derived from directory structure),
  M13 (container/HF manifest reads capped); L2 (the two unauthenticated dashboard
  config-blob reads).
- **Fixed (round 3):** P1 (install now renames instead of re-copying every byte),
  P2 (bundle packing at `gzip.BestSpeed`, ~7× measured), P3 (bundle archive/replay
  hardlinks instead of full copies), P4 (dashboard tree cache invalidated on import,
  TTL 3s→60s), O1 (`landing/imported`+`duplicates` 7-day retention), O2 (orphaned
  HTTP-ingest `.upload-*` temps reaped — they pinned the unverified quota forever),
  O3 (startup sweep of crash-stranded import staging), O4 (`lz4` added to the runtime
  image; retention + `/admin/status` docs corrected).
- **Open, recommended:** the L-series defense-in-depth and the round-3 P/O/T/D backlog
  (see "Round 3" below; P5–P7 are the highest-value items).

## Validation baseline

All green on the current branch (Go 1.26.5), re-run after the round-3 fixes:

| check | result |
|-------|--------|
| `go build ./...` | ✅ |
| `go vet ./...` (incl. `-tags e2e ./e2e`) | ✅ |
| `go test -race ./...` | ✅ (~50s) |
| `golangci-lint run` (v2.12.2, `GOTOOLCHAIN=go1.26.5`) | ✅ `0 issues` |
| `TestEcosystemRegistryWiring` (registry invariant) | ✅ |
| `govulncheck ./...` | runs in CI (`.github/workflows/govulncheck.yml`); the vuln DB is unreachable from the sandbox |
| statement coverage | 88.7% (`go test -cover`); zero benchmarks/fuzz targets — see T1 |

## Method

Core trust-boundary files were read in full and traced by hand
(`highside.go`, `archive.go`, `bundle.go`, `diode.go`, `diodewire.go`, `auth.go`,
`login.go`, `goauth.go`, `goproxy.go`, `gosumdb.go`, `tls.go`, `readyz.go`). The
per-ecosystem breadth was covered by parallel review agents (UDP transport, low-side
control plane, container/HF, apt/rpm/apk/conda, npm/python/java/crates/nuget, the
remaining ecosystems, and the UI). A follow-up round re-verified the landed fixes
(rpm/helm metadata rework, nuget hash-pinning, conda auth) against source and swept the
unauthenticated high-side serve paths for the M11–M13 request-cost class. **Every agent
finding was re-verified against the source before inclusion here**, and speculative or
non-reproducible items were dropped.

---

## High

### H1 — APT `Packages` indexes are regenerated malformed (multi-package mirrors break)

**`apt.go:1325`** (in `publishAptSuite`), with `apt.go:1389` (`presentAptStanzas`).

```go
plain := []byte(strings.Join(pkgs, "\n") + "\n")   // pkgs[i] = strings.TrimSpace(p.Stanza)
```

Each stanza is stored `strings.TrimSpace`d (no trailing newline), then stanzas are joined
with a **single** `\n`. deb822 requires paragraphs to be separated by a **blank line**
(`\n\n`). With one newline, `apt-get update` parses the entire component/arch index as a
**single** stanza with repeated `Package:`/`Version:`/`Filename:` fields, keeping one value
per field — so every package but one silently disappears and is uninstallable.

- **Impact:** any real (multi-package) APT mirror serves a broken `Packages` index. High
  availability impact on a shipped feature.
- **Why it survived:** `apt_test.go` and `e2e/apt_test.go` mirror a **single** package
  (`gh`) and assert only `Package: gh`, so the 2+-package path is never exercised. The APK
  sibling does it correctly (`apk.go:916` uses `"\n\n"`).
- **Fix:** join with `"\n\n"`: `strings.Join(pkgs, "\n\n") + "\n"`. Add a 2-package index
  test.
- **Status: fixed in this branch** (`apt.go:1328`), with a 2-package regression test
  (`TestCov3B_PublishAptSuiteStanzaSeparator`) that fails on the single-`\n` join.

### H2 — Unescaped upstream data injected into the high-side-signed `repomd.xml` (XML injection)

**`rpm.go:1196–1213`** (`writeRepomdData`), validation gap at **`rpm.go:1101–1124`**
(`validateRpmMirror`).

```go
fmt.Fprintf(b, "  <data type=%q>\n", d.Type)                                   // %q is Go-quoting, NOT XML-escaping
fmt.Fprintf(b, "    <checksum type=%q>%s</checksum>\n", ..., d.Checksum)        // %s is raw
fmt.Fprintf(b, "    <location href=%q/>\n", d.Href)
fmt.Fprintf(b, "    <timestamp>%s</timestamp>\n", d.Timestamp)                  // raw
```

`d.Type`/`d.Checksum`/`d.Timestamp`/`d.OpenChecksum` come verbatim from the upstream
`repomd.xml` parsed at collect time and are **never charset-validated** — `validateRpmMirror`
checks only that `d.Href` is a manifest file, nothing about the other fields. `%q` escapes
`"`→`\"` (which XML does not understand) and does not escape `<`/`>`/`&`; `%s` escapes
nothing. So `<`/`>`/`&`/`"` in any of these fields breaks out of the element/attribute.

The upstream `repomd.xml` is commonly fetched **unverified**: `localKeyringPath`
(`rpm.go:1051`) returns `ok=false` for a remote `gpgkey=https://…` (the usual RPM repo
config) or an absent key, so low-side signature verification is skipped entirely.

- **Impact:** a malicious or MITM'd upstream repo injects arbitrary XML into a `repomd.xml`
  that ArtiGate then **GPG-signs and serves**. Minimum: a corrupt-but-signed entry point
  (`dnf` can't parse the repo → DoS). Worse: attacker-shaped `<data>` elements inside a
  document bearing ArtiGate's valid signature.
- **Fix:** XML-escape every emitted value (build the document with `encoding/xml`, or escape
  with `xml.EscapeText`), and validate `Type`/`Checksum`/`ChecksumType`/`Timestamp` charset
  on the import side the way the low side is expected to.
- **Status: fixed in this branch** — all `writeRepomdData` fields now go through
  `xmlEscape` (`xml.EscapeText`), with a regression test
  (`TestWriteRepomdDataEscapesHostileFields`) that asserts a hostile upstream `<data>` field
  cannot break out of the element or forge a second one. (The additional import-side
  charset validation is left as a follow-up hardening item — escaping already closes the
  injection.)

---

## Medium

### M1 — Background goroutines that process untrusted input don't recover panics

CLAUDE.md states: *"Background goroutines (the watch scheduler, diode workers) must not let
a panic escape — recover it into an error, or a single bad upstream response crashes the
whole server."* This is enforced for the collect path (`recoverCollectPanic`, `watch.go:401`;
`jobs.go:246`; `notify.go:122`) but **not** for three long-lived loops:

- **`catcher.go:188`** (`diodeCatcher.run`) — the one goroutine dedicated to hostile UDP
  input (`handleDatagram` → reedsolomon, `requestImport`, OS I/O). **This is the most direct
  violation** — "diode workers" are named explicitly.
- **`highside.go:236`** (`requestImport` worker) and **`highside.go:525`** (`importLoop`) —
  `ImportNext` runs every ecosystem `publish` hook, which parse verified-but-upstream-authored
  content to regenerate indexes; a panic there escapes and crash-loops the high side on the
  same landed bundle.
- **`watch.go:301`** (`watchLoop` → `runDueWatches`) — DB/bookkeeping only, lowest concern.

No datagram/bundle that triggers a live panic was found (the wire parser and manifest
validation are thorough), so this is an **invariant-compliance / defense-in-depth** gap — but
the blast radius is whole-process, and every sibling worker already has the guard.
**Fix:** a one-line `defer func(){ recover() }()` (logging into an error) at the top of each loop.
**Status: fixed** — a shared `recoverWorkerPanic` (`watch.go:417`) now wraps every iteration of
all four long-lived loops: the diode catcher (`catcher.go:196`), both high-side import workers
(`requestImport` `highside.go:240`, `importLoop` `highside.go:541`), and the watch scheduler
tick (`watch.go:312`).

### M2 — Unbounded non-LFS Hugging Face file download (low-side staging exhaustion)

**`hf.go:669`** (`downloadHFToTemp`, via `downloadHFRepoPlainFile`).

```go
n, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)   // no io.LimitReader
```

Every other download path bounds the copy (LFS via `writeVerifiedBlob`'s `LimitReader`,
manifests via `io.LimitReader(…, 8<<20)`). The plain path is taken whenever a repo file is
**not** LFS-tracked (`hf.go:572`), which the upstream repo's `.gitattributes` controls, and
`meta.Size` isn't used as a bound. An attacker-published HF repo can ship a large
non-LFS file → the privileged low side streams it unbounded into staging → **disk exhaustion**
(fails all streams' collects, since staging shares the low-side root).
**Fix:** `io.LimitReader(resp.Body, meta.Size+1)` (or a sane plain-file cap) and verify the count.
**Status: fixed in this branch** — the plain path is bounded by a fixed `hfMaxPlainFileBytes`
cap (512 MiB) via `io.LimitReader`, rejecting an oversized body; regression assertion added to
`TestCovR2_DownloadHFRepoFiles`.

### M3 — gzip-bomb decompression while scanning archives for a metadata file

**`helm.go:293–323`** (`extractChartYAML`), same shape in **`galaxy.go`** (`extractGalaxyCollectionInfo`)
and **`cran.go`** (`extractCRANDescription`).

`tar.Reader.Next()` decompresses each *skipped* entry in full; only the final target read is
wrapped in a `LimitReader`, the traversal is not. A crafted `.tgz` (highly-compressible
padding entry, metadata file last or absent) forces the high side to inflate the whole
archive at import — and the import loop is single-threaded under `s.mu`, so this **wedges the
entire import pipeline** (all streams) while it grinds. cran also hits it on the low side.
The repo already has the correct pattern: `terraform.go:1420` (`extractTarGzTree`) caps with a
`remaining int64` budget.
**Fix:** wrap the gzip/tar stream in a total-bytes budget as terraform does.
**Status: fixed in this branch** — every "scan a `.tar.gz` for one named member" reader now reads
through `io.LimitReader(gz, tarScanMaxDecompressedBytes)` (2 GiB), so a bomb is bounded instead
of inflated wholesale. The first pass bounded only three of the six such scanners
(`helm.go`/`galaxy.go`/`cran.go`); the identical idiom in `python.go` (`sdistRequiresPython`,
PKG-INFO), `apk.go` (`apkIndexFromArchive`, APKINDEX), and `npm.go` (`extractNpmPackageJSON`,
package.json) was left raw and is now wrapped too. The `python.go` site was the most exposed:
it runs on the **unauthenticated** high side via `GET /simple/<project>/`
(`pyProjectFiles` → `requiresPythonFor`) and is re-scanned per request, not just once at import.

### M4 — Unauthenticated high-side endpoints do expensive / mutating work

- **`ui.go:129`** (`/ui/api/overview`) and **`highside.go:373`** (`/admin/status`, `/admin/missing`)
  call `ImportStatus()`, which runs `quarantineFutureBundlesLocked()` — **moving files** and
  firing `bundle_rejected` webhooks/metrics — under `s.mu`. A read-only variant
  (`importStatusReadOnly`) already exists and is used for `/metrics`, but not here. Any
  unauthenticated client (or the dashboard's own poll) repeatedly hitting `/ui/api/overview`
  churns the filesystem and serializes against the import loop.
  **Fix:** use `importStatusReadOnly` for these read endpoints.
  **Status: fixed in this branch** — `handleUIOverview` (`ui.go:129`) and the `/admin/status`,
  `/admin/missing` cases (`highside.go`) now call `importStatusReadOnly`, so no unauthenticated
  read runs the quarantine sweep; the background import loop and diode kick still own it.
  `TestHighServerUIOverview` was updated to drive the quarantine through an explicit import pass
  and then assert the read endpoint faithfully reports it.
- **`python.go:477`** (`pyProjectFiles`, the PEP 503/691 `/simple/<project>/` page pip fetches
  for every requirement) re-reads and SHA-256-hashes **all** of a project's wheels and re-opens
  each archive on **every request**, with no caching — O(total wheel bytes) per hit on an
  unauthenticated port (trivial to amplify against a project with multi-hundred-MB wheels).
  npm/nuget/crates persist digests at import instead. **Fix:** memoize digests at publish time.
  **Status: fixed in this branch** — a `pyDigestCache` (`python.go`) memoizes each wheel's
  SHA-256 and Requires-Python keyed by `(size, modtime)`; a repeated request re-`stat`s (cheap)
  but re-hashes only changed wheels. Regression test `TestPyDigestCacheMemoizesAndInvalidates`
  proves both the cache hit and modtime-driven invalidation.

### M5 — Upload staging has no part-count or aggregate cap (DoS on the signing plane)

**`uploads.go:185–211`** (`stageUploadParts`) / **`uploads.go:255`** (`stageOneUpload`).

The multipart loop has no part-count limit, each part streams to its **own** temp file with
no size cap, and all temp files persist until the whole stream ends. A POST with ~1M tiny
parts → inode exhaustion; a single huge part → disk full. Because `<root>` also holds
`low-state.json` and bundle archives, exhaustion breaks state/bundle writes on the plane that
holds the signing key. (Per-file size is intentionally unbounded for large models; the gap is
the missing part-count / aggregate-bytes / free-space guard.)
- **Status: fixed in this branch** — `stageUploadParts` now rejects an upload exceeding
  `maxUploadParts` (10000) parts, closing the inode/handle-exhaustion vector; regression test
  `TestStageUploadPartsCountCap`. (The single-huge-part disk-fill is inherent to the deliberately
  unbounded per-file size for large-model uploads and is left as-is.)

### M6 — git pack header object count drives an eager multi-GB allocation (low-side OOM)

**`gitmirror.go:784`** with the bound at **`gitmirror.go:677`**.

```go
if int64(count)*3 > int64(len(pack)) { ... }        // count bounded only by len(pack)/3
objs := make([]*gitPackObject, 0, count)            // eager count*8 bytes
```

`count` is attacker-controlled (`Uint32(pack[8:12])`). With a 2 GiB pack (`gitMaxPackBytes`),
`count` can be ~716M → `make(…, 0, count)` reserves ~5.7 GiB **before** any object body is
read, on top of the 2 GiB pack already in memory → OOM of the low-side control plane when
mirroring a hostile repo. **Fix:** cap `count` to a sane maximum (or grow the slice lazily).
**Status: fixed in this branch** — the object slice is pre-sized to
`min(count, gitInitialObjectHint)` (64Ki) and grows to the real count as objects are scanned,
so a forged count can no longer drive the up-front allocation; smoke test
`TestGitScanPackForgedObjectCount`.

### M7 — vsx gallery `pageNumber` overflow → slice-bounds panic (unauthenticated)

**`vsx.go:456`** (`vsxGalleryPage`), reached via **`vsx.go:324`** (`pageNumber` from the request,
no upper bound).

```go
start := (page - 1) * size          // page from request, size ≤ vsxMaxPageSize
if start >= len(matched) { return ... }
return matched[start:min(start+size, len(matched))]
```

`(page-1)*size` overflows `int` for a large `pageNumber`, yielding a **negative** `start`;
`start >= len(matched)` is then false, so `matched[start:…]` panics ("slice bounds out of
range") — reachable even with zero mirrored extensions, unauthenticated, via
`POST /vsx/gallery/extensionquery`. Recovered per-request by `net/http` (not a process crash),
so it's a request-level DoS/defect. **Fix:** validate/clamp `pageNumber`, or guard `start < 0`.
**Status: fixed** — `vsxGalleryPage` (`vsx.go:457`) now guards `start < 0 || start >= len`, so
any out-of-range page (including an overflowed negative `start`) returns an empty page.

### M8 — terraform `git checkout` omits `--` before an attacker-controlled ref (option injection)

**`terraform.go:1596`** (`gitCloneModule`), ref from **`terraform.go:1565`** (`splitGitSource`).

```go
if _, err := s.runGit(ctx, "clone", "--", repoURL, dir); ... // clone IS guarded by --
_, err := s.runGit(ctx, "-C", dir, "checkout", "--detach", ref)  // ref is NOT guarded by --
```

`ref` comes unvalidated from a mirrored module's `?ref=` (controlled by an untrusted module
author via the registry's `X-Terraform-Get`/`location`). A `ref` starting with `-` is parsed
as a `git checkout` option (argument injection; no shell, so bounded to what `checkout` flags
can do). The clone line directly above deliberately uses `--`.
**Fix:** add `--` before `ref`, and validate `ref` against a safe refname charset.
**Status: fixed** — `splitGitSource` (`terraform.go:1581`) now validates `?ref=` against
`tfGitRefRE` (`validateTfGitRef`, `terraform.go:1570`): a ref must start with an alphanumeric,
so an option-shaped ref can never reach `git`, whichever argument position it lands in.

### M9 — conda channel URL accepts embedded credentials (login leaks across the diode + into logs)

**`conda.go:971`** (`condaChannelURL`).

Unlike `apt`/`rpm`/`apk` (which all call `checkNoURLUserinfo` — e.g. `rpm.go:1076` — precisely
because *"the URI is recorded in the signed manifest and echoed in progress and error text, so
it must never carry a login"*), conda accepts `https://user:token@channel` unchecked. The
userinfo is stored in the signed bundle manifest that crosses to the unauthenticated high side
and is printed by `emitProgress`. **Fix:** call `checkNoURLUserinfo` in `condaChannelURL`.
**Status: fixed** — `condaChannelURL` (`conda.go:987`) now rejects a channel URL that embeds a
login. Conda private-channel access was subsequently wired into the shared upstream-credential
plumbing (a one-shot per-collect `auth` field / `ARTIGATE_UPSTREAM_AUTH`, never stored; watch
specs still refuse any `auth` key), so rejecting the userinfo form no longer blocks private mirrors.

### M10 — NuGet mirrors content with no cryptographic pinning + weak flat-base check

**`nuget.go:1234`** (`downloadPackage`) hashes the `.nupkg` but never compares it against any
upstream digest — integrity rests on TLS + an embedded-nuspec identity check (documented at
`nuget.go:1226`). The other four adapters pin an upstream hash (npm SRI, crates `cksum`,
python declared sha256). Compounding it, **`nuget.go:1078`** takes the flat-container base from
the service index with only `strings.HasPrefix(res.ID, "http")` (matches `httpfoo://…`, any
host). A malicious/MITM source or service index can substitute arbitrary package content that
the signed bundle then makes "verified" downstream.
**Fix:** pin against the registration/catalog `packageHash` (SHA-512); parse the flat base as a
real URL with a scheme allowlist.
**Status: fixed** — each `.nupkg` is now verified against the upstream registration/catalog
`packageHash` when the feed publishes one (nuget.org always does), via `nugetEntryDigest`
(`nuget.go`) → `downloadVerifiedFile`, falling back to TLS-only integrity otherwise; and every
service-index resource URL is parsed by `nugetResourceURLOK` (absolute http(s), real host, no
userinfo) instead of `HasPrefix(id, "http")`. Regression tests `TestNugetUpstreamDigestPinning`
and the URL-gate cases cover it. *Residual (by design):* the pin comes from the same upstream as
the bytes, so it defends a compromised/buggy CDN edge, not a fully malicious source or a broken
TLS session — TLS to the configured source stays the MITM defense, as the code comments state.

---

## Medium — newly found this review round (unauthenticated per-request work)

A second sweep (beyond the original agents) turned up a *class* the first pass under-weighted:
high-side serve endpoints that do work proportional to artifact or mirror size on **every**
unauthenticated request, with no cache. None is a correctness or trust-boundary bug — the high
side still serves only verified content — but each is an amplifiable request-cost/DoS vector on
the public port. M4(b) (python `/simple`) was the first instance; these are its siblings.

### M11 — `/ui/api/detail` re-hashes the selected artifact on every request (all ecosystems)

**`ui.go:655`** (`handleUIDetail`, unauthenticated), which dispatches to each ecosystem's `detail`
hook — `goDetail`, `pythonDetail`, `cratesDetail`, `uploadsDetail`, `nugetDetail`, `cranDetail`,
`tfModuleDetail`, `gitDetail`, `composerDetailFor`, `mavenDetail`, `rubygemsDetail`, `vsxDetail`,
`npmDetail` — nearly all of which call `sha256File` on the **whole** selected artifact per request.
`GET /ui/api/detail?eco=<eco>&path=<spec>` against the largest mirrored artifact (an unbounded
upload, a multi-GB HF/Go zip) is O(that artifact's bytes) per hit, uncached. `npmDetail`
(`npm.go:758`) re-hashes even though npm already persists the digest at import.
**Fix:** serve the digest persisted at publish time (npm/nuget/crates already store one), or a
`(size, modtime)`-keyed cache like M4(b)'s `pyDigestCache`.
**Status: fixed** — a shared `(size, modtime)`-keyed `detailDigestCache` (`ui.go`, field
`HighServer.detailDigests`) now backs every detail hook's digest field; `pythonDetail` reuses
the existing `pyDigests` cache so a wheel is hashed at most once across `/simple` and the
detail panel. Regression test: `TestDetailDigestCacheMemoizesAndInvalidates` (`ui_test.go`).

### M12 — Two unauthenticated endpoints walk the entire mirror per request

- **`nuget.go:592`** (`handleNugetSearch`, `GET /nuget/v3/search`): `q` is optional and an
  empty/absent `q` skips the filter, so it iterates every package id and reads each id's stored
  metadata + all versions, emitting a body ∝ mirror size, with no pagination (`skip`/`take` are
  ignored). **Fix:** require a non-empty `q` (or enforce a `take` cap) and filter ids before load.
  **Status: fixed** — the protocol's `skip`/`take` window is enforced (default 20, capped at
  `nugetSearchMaxTake` 100); ids are matched and counted before any stored JSON is read
  (`nugetHasServableVersion` gates on directory scans + archive stats only, preserving the
  "removed archive drops out of search" invariant), and full metadata is loaded for the
  returned window alone. Tests: `TestNugetSearchPaging`, `TestNugetSearchPageCap`.
- **`composer.go:686`** (`handleComposerRoot` → `listComposerPackages` `composer.go:930`,
  `GET /composer/packages.json` — the first document every Composer client fetches): to emit just
  the name list it reads **every release's** stored JSON across the whole mirror. **Fix:** cache
  the name list (invalidate on import), or derive names from directory structure without reading
  each release.
  **Status: fixed** — `packages.json` is now served from `listComposerPackageNames`, which
  derives names from the metadata directory structure plus a dist-zip existence check
  (`composerHasServableRelease`, first hit wins) and reads no stored JSON; p2/detail responses
  still go through `readComposerStored`'s full per-release re-check. The zip-gating case is
  covered at the end of the composer pipeline test.

### M13 — Unbounded manifest/config reads on the container/HF serve path (OOM)

The dashboard-detail half of this (config blobs) is fixed under **L2** above. The other half: the
registry manifest reads `handleContainerManifest` (`container.go:1624`) and `handleHFManifest`
(`hf.go:1552`) `os.ReadFile` the manifest blob whole (size checked only `> 0` at import) on the
unauthenticated `GET /v2/.../manifests/<ref>` pull path. Manifests are tiny in practice, so a cap
is pure hardening, but it closes the last unauthenticated whole-blob-into-memory read.
**Fix:** `readFileLimit` these two with a manifest-sized cap.
**Status: fixed** — both handlers read through `readFileLimit(..., maxServedManifestBytes)`
(4 MiB, the conventional registry manifest-upload cap; `container.go`), and an oversize blob
404s as unservable. Tests: `TestContainerManifestServeCapsBlobRead`,
`TestHFManifestServeCapsBlobRead`.

---

## Low / defense-in-depth

- **L1 — No `X-Frame-Options`/CSP `frame-ancestors` anywhere** (only `jobs_http.go:101` sets
  `nosniff`). Enables clickjacking of the low-side dashboard in the supported
  loopback-without-auth mode, and removes a CSP backstop against any future escaping regression.
- **L2 — Config blobs read unbounded into memory.** `container.go:1267`/`:1836`, `hf.go:2242`
  do `os.ReadFile` of a blob whose size is only checked `> 0` (`container.go:878`), up to the
  64 GiB archive cap → transient OOM from a giant declared "config" blob (low side every
  collect; high side per dashboard detail view).
  **Status: partially fixed in this branch** — the two *unauthenticated high-side* detail reads
  (`containerImageLayers` `container.go:1836`, `hfConfigFields` `hf.go`) now use
  `readFileLimit(..., maxRenderedBlobBytes)` (32 MiB); an oversize blob is treated as unreadable,
  so the panel omits those fields instead of OOMing (regression case added to
  `TestCovR2_ContainerImageLayersFallbacks`). The collect-time read (`container.go:1267`, low side)
  is left as-is. See also **M13** for the manifest-serving reads on the same path.
- **L3 — Reflected `Host` baked into generated absolute URLs** (`npmBaseURL`, `npm.go:301`;
  reused for nuget/crates download bases). Behind a shared cache a poisoned `Host` can redirect
  downloads — DoS for npm (client re-verifies via `dist.integrity`), content substitution for
  NuGet (no leaf hash, see M10). Prefer deriving the base from config.
- **L4 — `mavenTokenRE` (`java.go:87`) accepts `..`/`.`/`-`** — unlike every sibling name regex.
  Not currently exploitable (high-side paths derive from `validateRelPath`-checked on-disk
  paths), but it's the one adapter that doesn't re-validate its grammar on the untrusted side.
- **L5 — Stateless sessions have no server-side revocation** (`login.go:290`). Logout only
  clears the caller's cookie; a copied cookie stays valid until the 12h `MaxAge`.
- **L6 — Per-account login lockout enables targeted lockout-DoS** (`login.go:266`): an attacker
  who knows an operator username can keep that account 429'd with failed attempts.
- **L7 — Unauthenticated `/metrics` (disk walks) and `/readyz?verbose` (leaks the diode URL +
  stuck bundle IDs via `checkDiodeTransfers`, `readyz.go:168` ← `diode.go:492`).** Mitigated
  only by the documented "firewall the scrape port" expectation.
- **L8 — `csrfGuard` fails open when a browser sends neither `Sec-Fetch-Site` nor `Origin`**
  (`lowside.go:356`). Only reachable by pre-Fetch-Metadata browsers (effectively extinct), but
  it's the sole CSRF defense in loopback-without-auth mode.
- **L9 — Collect body-limit mismatch:** `bufferCollectBody` accepts 16 MiB
  (`maxStreamCollectBody`) but handlers re-read with 1–8 MiB caps (e.g. `lowside.go:854`), so a
  body in that gap is silently truncated → a misleading `400 parse … unexpected end of JSON`,
  contradicting the "never truncated" comment.
- **L10 — Queued-body memory bound is per-stream, not global** (`jobs_http.go:240`): ~25 streams
  × 20 queued × 16 MiB ≈ 8 GiB of pinnable heap; the `jobQueueCap` comment reasons per-stream.
- **L11 — UDP transfers reserve the full *declared* `FileSize` against the shared quota on the
  first packet** (`diodewire.go:550`): two forged first-packets at 64 GiB each exhaust the
  128 GiB quota with ~zero data. Self-heals in 90s, capped at 16 transfers, and physically
  mitigated by a receive-only diode NIC (needs fiber-side injection).
- **L12 — UDP receive goroutine hashes the whole reassembled file inline** (`diodewire.go:1033`),
  blocking socket draining for tens of seconds on a multi-GB bundle → datagram loss on
  back-to-back large bundles (recoverable via FEC/resume; throughput, not correctness).
- **L13 — `npm listNpmPackages` (`npm.go:664`) reports `_tags.json` as a phantom `_tags`
  version** in the high-side dashboard tree (cosmetic; `npmVersionObjects` filters it, this walk
  doesn't).
- **L14 — `diskusage_linux.go:24` multiplies a clamped `uint64` by block size without a second
  overflow guard** → theoretical negative `/metrics` gauge (not attacker-reachable).
- **L15 — RPM filelists/other are string-filtered without a prior XML well-formedness check**
  (`restagePkgidIndexes` `rpm.go:525` → `filterIndexXML`). Primary is `xml.Unmarshal`'d first, but
  the pkgid-keyed indexes are only checksum-verified then block-matched as raw strings. A
  malformed-but-checksum-matching upstream filelists could desync block boundaries. Bounded: low
  side only, supplementary metadata (primary stays authoritative), no crash/traversal, output
  stays count-consistent. Optional: `xml.Unmarshal`-validate before filtering.
- **L16 — RPM sqlite `_db` indexes are not rewritten when packages are filtered**
  (`isRpmPkgidIndex` `rpm.go:513` covers only the XML `filelists`/`filelists_ext`/`other`). If an
  upstream still ships `primary_db`/`filelists_db`/`other_db`, those are served verbatim and still
  list dropped packages, so an old sqlite-only yum client could 404 on a filtered `.rpm`.
  Pre-existing and strictly improved by the filtered-metadata fix; modern `createrepo_c` omits
  `_db`. Optional: rewrite or drop the `_db` entries too.
- **L17 — Minor mirror-size-scaled reads on `/ui/api/detail` and metadata endpoints**
  (`aptDetail` `apt.go:1631` / `rpmDetail` `rpm.go:1444` read the whole `index.json`;
  `buildMavenMetadata` `java.go:214` does O(versions) `ReadDir` per `maven-metadata.xml`). Operator-
  size, not attacker-size, and uncached — cache or bound if a mirror grows large. (Same family as
  M11/M12, lower severity.)
- **L18 — The NuGet V3 low side follows upstream-provided URLs with no host allowlist (blind-GET
  SSRF surface).** `nugetResourceURLOK` (`nuget.go:1071`) validates *form* (absolute http(s), a
  host, no userinfo) but not *host*, and it gates the service-index resources, the registration
  base, and the `catalogEntry` catalog-document URL (`fetchNugetCatalogEntry` `nuget.go:1292`) —
  all attacker-influenced if the configured feed is malicious/MITM'd. So a hostile feed can steer
  the privileged low side to `GET` an arbitrary http(s) host (including link-local/internal). Bounded:
  the response is parsed only for a `packageHash` the `.nupkg` must then match (blind GET, ≤4 MiB,
  no body exfiltration to the attacker), and multi-host resolution is inherent to NuGet V3 — but a
  host allowlist derived from the configured source would shrink the surface. Not specific to the
  M10 catalog fetch; it is the whole V3 chain.
- **L19 — An immutable-file conflict wedges a stream instead of rejecting the bundle.**
  `installVerifiedFile` (`highside.go:1527`) returns a *plain* `"immutable file conflict"` error,
  which `handleStreamImportError` (`highside.go:748`) classifies as **operational** (retried in
  place) rather than `invalidBundleError` (rejected). A permanent conflict — two validly-signed
  bundles writing different bytes to the same immutable path — therefore retries forever and blocks
  every later bundle in that stream. General and pre-existing (the design deliberately leaves
  operational faults like a full disk unmarked so a good bundle stays retryable; a *permanent*
  conflict is the edge that slips through). Not attacker-reachable with a correct low side (paths
  are content/version-pinned); the one concrete trigger is a pre-fix Helm bundle carrying the
  adversarial legacy pair chart `a-1`@`1.0.0` + chart `a`@`1-1.0.0` (both legacy-map to
  `a-1-1.0.0.tgz`), which is not producible by the current low side. Visible in `/readyz` and
  `/admin/status`. Fix would be a semantic call (reject-and-skip vs wedge) best made deliberately.

---

## What's solid (verified, not merely unexamined)

- **Trust boundary / import pipeline** (`highside.go`, `archive.go`): Ed25519ph signature over a
  streamed SHA-512 with a post-read digest recheck (closes the verify-then-use TOCTOU) →
  per-stream sequence/previous/bundle-id binding (blocks replay and cross-stream substitution) →
  verify-while-extract with per-file SHA-256, `TypeReg`-only (no symlink planting), duplicate-entry
  rejection, and file/parent-dir collision checks → immutable-path enforcement on install →
  index regeneration from installed artifacts, never from transferred indexes.
- **Path containment:** `validateRelPath` (clean-path enforced) + `safeJoin` (`filepath.Rel`
  containment) applied at extract *and* install, plus `validateMirrorName`/`validateSumDBName`
  for the segment-shaped names; landing/quarantine/rejected live outside the served subtree.
- **UDP wire parser** (`diodewire.go:194–258`): fixed-header length gate, `nameLen` bounded before
  slicing, all geometry validated (shards ≤256, `ShardSize` tied to actual payload length,
  `BlockOffset ∈ [0, FileSize-BlockLen]`), `FileSize` bounded against the per-file transport
  limit before any transfer state is created, disk-backed reassembly with per-transfer/global RAM
  budgets. No overflow, slice panic, unbounded alloc, FEC corruption, or leak found.
- **Auth/sessions** (`auth.go`, `login.go`): argon2id with embedded-parameter bounds + decoy-hash
  timing defense, per-user lockout, non-blocking concurrency cap, body-size + read-deadline limits;
  securecookie sessions, `HttpOnly` + `SameSite=Lax` + TLS-driven `Secure`.
- **Go credential injection / sumdb** (`goauth.go`, `gosumdb.go`): 0600 netrc, scratch scrubbed on
  restart, whitespace-rejecting logins, GIT_CONFIG secrets via env; strict sumdb path validation
  re-applied on the untrusted import side; watch specs carrying `auth` are refused at store & run.
- **Concurrency:** consistent `m.mu → j.mu` lock order (no inversion/deadlock), idempotent
  `finishJob`, per-stream `streamLock` serialization with `s.mu`-guarded sequence maps, all
  in-memory caches mutex-guarded (`go test -race` clean).
- **TLS** (`tls.go`): TLS 1.2 floor across every mode, P256 self-signed, certmagic ACME; graceful
  shutdown drains without deadlock. **HTTP admin mutations** are loopback-gated on the real TCP
  peer (no `X-Forwarded-For` trust) plus `csrfGuard`; diode ingest requires a ≥32-byte token.
- **Ecosystem serve/publish path traversal:** every high-side filesystem path traced (go, python,
  npm, nuget, crates, maven, apt, rpm, apk, conda, container, hf, helm, galaxy, cran, vsx,
  terraform, git, osv, uploads) pairs name/digest validation with a `safeJoin`; integrity chains
  (crates `cksum`, npm SRI, container/hf digest regex) are end-to-end.

---

# Round 3 — performance, operations, and completeness

**Method:** core data-path files re-read in full with a performance lens (`diodewire.go`,
`pitcher.go`, `catcher.go`, `diode.go`, `highside.go`, `archive.go`, `metrics.go`,
`readyz.go`, `tls.go`, `ui.go`); four parallel review agents covered the diode/import
pipeline, the high-side serve handlers of all 22 ecosystems, the low-side collect paths and
background machinery, and the docs/ops/test gap surface. Every agent finding referenced
below was re-verified against source before inclusion; the gzip claim was measured on this
machine. Numbering: **P** performance, **O** operations/lifecycle, **T** tests, **D** docs.

## Fixed in this branch

### P1 — Install re-copied (and re-fsynced) every verified byte from staging into the repo
`installVerifiedFile` published each file with `copyFileAtomic` — a full second read+write of
the entire bundle content plus one fsync per file, even though staging (`<root>/tmp/<id>`)
and the repository (`<root>/cache/download`) share a filesystem. A 64 GiB bundle paid
~128 GiB of disk I/O per import; a thousand-file bundle paid a thousand serial fsyncs — all
inside the import pass. **Fixed:** extraction fsyncs each verified file once
(`archive.go`, `extractTarEntry`), and install renames it into place (`moveVerifiedFile`,
`highside.go`), falling back to the copying path on EXDEV or any rename failure. Idempotent
re-import, the immutable-conflict check, and operational-vs-invalid error classification are
unchanged; regression test `TestCov3A_InstallVerifiedFileMovesFromStaging`.

### P2 — Bundle packing gzipped mostly-incompressible payloads at the default level
`createTarGzAtomic` used `gzip.NewWriter` (level 6) while the split-budget model itself
documents the content as "already compressed or incompressible" (`lowside.go:1327`).
Measured here: level 6 = **57 MB/s**, level 1 = **387 MB/s** on incompressible data (one
core), identical output size; on repetitive JSON level 1 is ~3× faster and still compresses
~150:1. A 64 GiB HF bundle's pack step drops from ~19 min of CPU to ~3 min. **Fixed:**
`gzip.NewWriterLevel(f, gzip.BestSpeed)` with the rationale in a comment (`archive.go`).

### P3 — Bundle archive and re-export copied the just-written archive byte-for-byte
`archiveBundle` and `replayArchivedBundle` did `copyFileAtomic` of all three bundle files —
another full read+write (and double disk footprint churn) of a potentially multi-GiB archive
on every export and every re-export. **Fixed:** `linkOrCopyFile` (`lowside.go`) hardlinks
the immutable signed files (tmp-link + rename, so replay stays idempotent), falling back to
the copy on EXDEV/no-hardlink filesystems.

### P4 — Dashboard tree cache re-walked the whole mirror every 3 seconds
`cachedTrees` memoized the full 22-ecosystem inventory scan (per-version stats + reads in
several ecosystems) for only 3 s, so any unauthenticated dashboard/tree/search poll kept a
large mirror permanently re-scanning. The mirror only changes on import or upload deletion.
**Fixed:** both mutation paths call `treeCache.invalidate()` (`highside.go`, `uploads.go`),
and the TTL is now a 60 s backstop for direct on-disk mutation (`ui.go`); test
`TestCov4_TreeCacheInvalidation`.

### O1 — `landing/imported/` and `landing/duplicates/` grew forever
Every imported bundle's three files were moved to `landing/imported` (`highside.go:847`) and
every replayed duplicate to `landing/duplicates`, and **no reaper ever touched either** —
the high side retained a compressed second copy of everything ever imported until the
landing volume filled (the docs said "automatic retention is not yet built"). **Fixed:**
`reapUnverifiedLocked` now reaps both after `processedLandingRetention` (7 days — the
authoritative replay copy is the low side's bundle archive); test
`TestReapProcessedLandingDirs`; docs updated (`deployment.md`, `high-side.md`).

### O2 — Orphaned HTTP-ingest temp files pinned the unverified quota forever
A kill/OOM mid-`PUT /diode/<file>` stranded `<name>.upload-<rand>` in the landing directory
(`diode.go:272`). The orphan **counted against the 128 GiB unverified quota** (it is a
regular file in landing) but matched no reaper: `reapIncompleteLanding` skips names without
a bundle suffix and the UDP reaper matches only `.udp-`. One 64 GiB orphan permanently ate
half the quota until an operator hand-deleted it. **Fixed:** the temp reaper is now
`reapStaleTransportTemps` and also matches `.upload-*` names past the 48 h retention
(`highside.go`, `isIngestUploadTempName` in `diode.go`); test extended.

### O3 — Crash-stranded import staging survived forever
`<root>/tmp/<bundleID>` is removed by the importing pass itself; a hard kill mid-import
stranded the extracted copy (up to a whole bundle's content) with nothing ever looking at it
again. **Fixed:** `NewHighServer` sweeps `<root>/tmp` at construction — no import can be
running then, and the directory holds nothing else. (The low-side sibling —
`<root>/<eco>/staging/collect-*` — is O15 below, recommended.)

### O4 — `lz4` missing from the runtime image; two stale docs claims
`Packages.lz4` decompression shells out to the `lz4` binary (`apt.go:418`, `lz4Decompress`)
but the Dockerfile installed only `xz zstd` — an APT repo whose Release lists only `.lz4`
indexes failed to collect in the shipped image with a confusing exec error. **Fixed:** `lz4`
added to the image and its toolchain comment. Also corrected: the two "retention is not yet
built" doc notes (now describing O1's behavior), and `high-side.md`'s claim that
`GET /admin/status` sorts landing bundles as a side effect — that side effect was removed by
the M4 fix (`importStatusReadOnly`).

## Recommended — performance (verified, not fixed here)

### P5 — The whole import pass holds `s.mu`; observability blocks behind a running import
`importPass` (`highside.go:662`) takes `s.mu` for the full multi-stream drain — signature
verify, full-archive gunzip + per-file SHA-256, install, and every publish hook — and
`importStatusReadOnly` (`/metrics`, `/readyz`, `/ui/api/overview`, `/admin/status`) takes
the same lock. During a multi-GiB import, every scrape and readiness probe hangs for
minutes: Prometheus times out and Kubernetes readiness flaps exactly when the pipeline is
busiest. It also serializes imports **across** streams — a 64 GiB `hf` bundle stalls a 2 MB
`go` bundle — the one place the per-stream-independence design doesn't hold. Artifact
serving is unaffected (no lock). *Fix direction:* split the pass into a narrow-lock state
phase and an unlocked extract phase (staging is per-bundle already), or serve a cached
status snapshot; note `checkImportBacklog`'s no-flap reasoning (`readyz.go:231`) leans on
"the draining pass holds the status lock" — any decoupling must keep an equivalent
guarantee (e.g. an `importRunning`/pass-start flag consulted by the backlog check). P1
(fixed) already removes the largest chunk of time under the lock.

### P6 — Several publish hooks regenerate the whole ecosystem per bundle, and once per bundle in a backlog drain
`drainStreamLocked` runs `installVerifiedBundle` → publish per bundle, so N queued bundles
cost N full regenerations (O(N × mirror) instead of O(mirror)). The heavy hooks, per import:
**CRAN** re-reads and re-MD5s *every* newest tarball (`writeCRANIndexRecord` → `md5File`,
`cran.go:505–532`) — O(mirror bytes); **RubyGems** re-reads every gem's JSON, stats every
version, and rewrites+fsyncs every `/info/<gem>` file even when unchanged
(`rubygems.go:713–806`) — the unconditional rewrite also bumps mtimes, breaking
`http.ServeFile` 304s and Bundler's incremental compact-index Range updates; **APT** re-reads
and rewrites the full mirror `index.json` and regenerates + GPG-signs every suite
(`apt.go:1226–1455`); **APK** same shape (`apk.go:807–915`). *Fix direction:* store the CRAN
MD5 in the stored-package record at publish; regenerate only gems/suites named in the
bundle and skip byte-identical writes; defer publish to the end of a drain (dedup by
ecosystem) — taking care that a mid-drain failure still publishes for the bundles already
installed, and that a crash between state-commit and a deferred publish can't leave a stale
index (publish-before-commit per batch, or a persisted dirty-ecosystems note).

### P7 — Every collect downloads strictly serially, and re-downloads what it already has
Two compounding findings across all 20+ collectors:
- **No parallelism anywhere** — not one goroutine on the collect side; npm tarballs
  (`npm.go:1223`), HF files (`hf.go:963`), container layers (`container.go:1226`), conda
  (`conda.go:1398`), crates, apt, rpm, … all download one-at-a-time. A 200-package conda
  closure pays 200 serial RTT+transfer cycles. A bounded 4–8-worker pool per collect is a
  near-linear wall-clock win; raise `MaxIdleConnsPerHost` (default 2) at the same time and
  add a `ResponseHeaderTimeout` — all collects share bare `http.DefaultClient` today.
- **Dedup runs after download** for conda/crates/rubygems/helm/python-sdists even though the
  upstream index declares the sha256 (and usually size) *before* the fetch: a recurring
  watch re-downloads 100% of an unchanged channel every interval, then `markPriorFiles`
  discards the bytes. apt/rpm/HF/containers already skip via `priorFileCheck`
  (`lowside.go:1524`; e.g. `rpm.go:824`) — wire the same check into the other five.

### P8 — git mirror: full clone per watch tick, no ref short-circuit, packs buffered in RAM
`CollectGit` never compares the advertised ref tips against the last exported mirror, so an
hourly watch full-clones an unchanged repo every hour (`gitmirror.go:1490–1525`), buffers
up to 2 GiB of pack in memory (`gitReadCapped`), and — because the dedup key embeds the pack
trailer (`gitPackRel`) — an upstream repack re-ships the whole pack across the diode with
zero ref movement. *Cheapest fix:* after `gitFetchAdvertisement`, return Skipped when the
selected ref set (name+sha) equals the last exported set.

### P9 — Watch-driven index refetch has no conditional GET, no retry, size-capped-by-time downloads
No collect-side request sends `If-None-Match`/`If-Modified-Since` (conda repodata — up to
1 GiB compressed/8 GiB decompressed in RAM per tick, `conda.go:72`; OSV `all.zip`; apt/rpm
metadata "always fetched", `rpm.go:816`; helm index; container tag pages). No request
retries or honors `Retry-After` — one transient 429/5xx drops that item from the signed
bundle (npm/crates/conda) or aborts the whole mirror collect (apt/rpm/git). And most
downloads run under fixed wall-clock deadlines (30 min in `downloadVerifiedFileAuth`,
10 min npm/pip, 15 min mvn) — a deadline caps effective file size by link speed regardless
of progress; an idle/stall timeout (the `progressReader` already sees every chunk) would
not. Persist per-URL validators beside `exported.db`, add a small retry helper, and switch
the fixed deadlines to stall-based ones.

### P10 — HTTP diode ingest serializes all uploads under one mutex for the full body transfer
`handleDiodeUpload` holds `ingestMu` across `storeDiodeUpload`'s entire body copy
(`diode.go:179–181`) — a 64 GiB PUT at 1 Gbit/s blocks every other stream's 4 KB signature
upload for ~9 minutes (and a trickling client indefinitely; there is deliberately no server
ReadTimeout). The lock only needs to make quota-check + admission atomic: reserve
`ContentLength` against an in-memory pending counter under the lock, stream outside it,
release on completion — the UDP assembler already does exactly this (`activeSize`,
`diodewire.go:583`). Unknown-length uploads can keep the serialized path.

### P11 — Pitcher/catcher data-path costs (matter above ~1 Gbit)
Send side: each bundle file is read **twice** (SHA-256 pre-pass `pitcher.go:314`, then the
paced send) — tee the hash at pack time and store it beside the bundle; `SendBundle` runs
inside the collect job under `p.mu`, so one 64 GiB send (~15 min at the default 800 Mbit,
77% goodput after FEC+headers) blocks other streams' *collect completions* — a durable
outbound queue would decouple them; `splitDiodeBlock` allocates a fresh ~350 KB backing per
block. Receive side: one ~8.7 KB heap copy per datagram (`addShard`,
`diodewire.go:742`), a `SetReadDeadline` syscall per packet (`catcher.go:204`), up to 32
`WriteAt`s per block, and the known L12 inline whole-file hash. At the 800 Mbit default all
of this is comfortably fine; for multi-Gbit targets: one contiguous backing per block (one
alloc, one `WriteAt` on the no-loss path), deadline reset only at sweep boundaries, and the
L12 hash moved off the receive goroutine. **The single-goroutine catcher is the end-to-end
ceiling (~1 Gbit easy, ~8 Gbit optimistic).**

### P12 — Remaining per-request serve-path costs (M11/M12/L17 family, new instances)
Verified but unfixed, in rough impact order: **VSX** `POST /vsx/gallery/extensionquery`
(fired per keystroke by VS Code, never HTTP-cacheable) reads and parses every stored version
JSON in the mirror **twice** per request (`vsx.go:439–451,517–521,778–793`); **OSV**
`GET /osv/<eco>/<ID>.json` re-parses the whole database zip's central directory per advisory
(`osv.go:299–318`) — memoize a name→entry map keyed by (size, modtime); **python**
`/simple/<project>/` still ReadDirs + filename-parses the entire flat wheel store per
request (`python.go:393–417`) — M4b removed the hashing, not the O(mirror) scan; **nuget**
search still ReadDirs every package dir per request and the registration index reads every
version's JSON twice (`nuget.go:521–558,607–655`); **npm** packuments rebuild with a double
unmarshal per version per request (`npm.go:396–467`); **goproxy** `@v/list`/`@latest` do
ReadDir + 4 stats + read + parse per version per request (`highside.go:464–507`) — extend
L17; **composer** `packages.json` residual dir walk; **HF** case-insensitive fallback walks
the whole tree on every miss of a bogus name (`hf.go:1262–1319`) and hub resolve re-parses
the full repo index per file (`hf.go:1945`); **apk** re-reads and re-parses the RSA key per
`GET /apk/keys/<name>` (`apk.go:628–641`). Publish-time upserts (npm/nuget/crates/…) are the
right pattern to extend: store what serving needs at import.

### P13 — No HTTP caching or compression on the serve surface
The only `Cache-Control` on the high side is the dashboard's `no-store`; the only `ETag` is
HF resolve. Digest-addressed immutable blobs (container/HF blobs, goproxy zips, `.crate`/
`.nupkg`/`.tgz`) should get `Cache-Control: public, max-age=31536000, immutable`; generated
metadata should get validators (digests are already known). No endpoint negotiates
`Accept-Encoding`; all `writeJSON` output is `SetIndent`-pretty-printed (~20–40% larger);
conda serves only plain `repodata.json` — conda/mamba probe `repodata.json.zst` first, so
publishing the `.zst` beside it at regen time is both a 404-round-trip and a bandwidth win.
Also perf-low: `ecosystems()` rebuilds all 22 descriptors on every request
(`highside.go:298`) — a `sync.OnceValue` accessor removes the per-request garbage.

### P14 — Maven collect re-downloads its entire closure every run
`dependency:go-offline` resolves into a `maven.repo.local` inside the throwaway staging temp
(`java.go:521–528`) — a daily watch pulls hundreds of MB from Central daily and then
discards it all as prior. Go, by contrast, uses a persistent module cache. Give maven a
persistent local repo under `<root>` (and python/pip already keeps its `$HOME` cache
incidentally — worth pinning deliberately).

## Recommended — operations & missing pieces

- **O5 — The mirror is append-only forever.** No endpoint or tool prunes a mirrored
  artifact or version except the `uploads` stream's delete; the only recourse is wiping the
  high side and force-recollecting. An offline prune tool could reuse the existing
  regenerate-from-disk publish machinery.
- **O6 — The low-side `<root>/bundles` archive has no retention knob** (every bundle ever
  exported, forever — by design for replay, but unbounded; `artigate_low_bundle_bytes`
  already exposes the gauge to alert on). An age/byte budget with "never evict bundles the
  high side hasn't imported" semantics needs a maintainer decision.
- **O7 — No global concurrent-collect cap, jitter, or failure backoff.** All 22 streams can
  collect simultaneously (`jobs.go:126` is per-stream only) — a restart after downtime
  fires every overdue watch on one tick; `RecordRun` advances `next_run_at` identically on
  success and failure (`watch.go:232–240`). A weighted semaphore (default ~4) plus ±10%
  jitter and capped backoff would smooth all three.
- **O8 — No `--version`, build stamp, or manifest format version.** Two air-gapped binaries
  can't report what they run; unknown manifest *fields* are silently dropped by an older
  high side. `-ldflags -X` stamp + `--version` + a manifest `format` field checked with a
  clear error.
- **O9 — Job queue/history are memory-only** (`jobs.go:9`) — queued manual collects vanish
  silently on restart (watches persist and recover). Document at minimum.
- **O10 — No disk-space readiness check** on either side; disk-full surfaces only as the
  `artigate_disk_free_bytes` gauge and retry loops.
- **O11 — No sequence rebase/recovery tooling** for a rebuilt low side (its bundles land in
  `duplicates/` silently; recovery is hand-editing state files, undocumented), and no
  operator control to abandon a dead quarantine gap.
- **O12 — `exported.db` is insert-only** (`exported.go:102,179`) — millions of rows on a
  large mirror; note the growth in docs, optionally compact.
- **O13 — No diode throughput/loss metrics.** The catcher's packet/drop/repair counters are
  log-only (`diodewire.go:1132`); the pitcher has none; import-pass duration isn't recorded.
  The two numbers that size a diode deployment — achieved goodput and datagram loss vs the
  parity budget — cannot be scraped or alerted on.
- **O14 — HTTP diode transfers: no automatic retry, no resume** (one attempt, then a human
  on the Status page; a 60 GiB PUT failing at 99% restarts from byte 0). The UDP path has
  per-block resume; the HTTP path deserves at least bounded retries with backoff.
- **O15 — Low-side startup sweep** for `<root>/<eco>/staging/collect-*` (the high-side half
  is fixed as O3): crash-stranded collect staging accumulates silently.
- **O16 — apt index decompression should fall through** to the next hash-verified candidate
  when the decompressor binary is missing (the loop currently returns on the error,
  `apt.go:421–438`; conda's zstd path already degrades gracefully). The image now ships lz4
  (O4), so this is defense-in-depth.

## Test gaps

- **T1 — Zero benchmarks and zero fuzz targets** in the repo. Natural fuzz candidates parse
  hostile bytes: `extractAndVerifyTarGz`, manifest load, `parseDiodePacket`,
  `parseAptPackages`, the git pack verifier. Natural benchmarks: FEC encode/reassembly,
  `createTarGzAtomic`, publish hooks at mirror scale.
- **T2 — The UDP socket layer is the least-tested subsystem** (`catcher.go` 36% / `pitcher.go`
  63% / `netsetup_linux.go` 17% file coverage; `run`/`receiveOne`/`SendBundle`/`sendFile`/
  `writeRetry` at 0%), and the e2e suite exercises the HTTP transport only. A
  loopback/veth pitcher→catcher integration test (skipped without privileges) would cover
  the real receive loop.
- **T3 — Minor untested paths:** `HandleCratesCollect`/`HandleOsvCollect` request parsing,
  the split-go-bundle import path (`allManifestFilePaths`, `moduleEscFromInfoPath`),
  `recordImportError`, `lz4Decompress`, `probeSumDBSupported`.

## Docs drift (beyond the two fixed in O4)

- **D1** — `configuration.md` claims exhaustiveness but omits 7 flags (`--composer-repo`,
  `--conda-channel-base`, `--cran-mirror`, `--galaxy-server`, `--pypi-json` — the last
  documented nowhere at all, `python.go:52` — `--rubygems-url`, `--vsx-registry`) and 4 env
  vars (`ARTIGATE_LOW_ALLOW_UNAUTHENTICATED`, `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN`,
  `ARTIGATE_WEBHOOK_URL`, `ARTIGATE_WEBHOOK_TOKEN`); the docs site never mentions webhooks.
- **D2** — Python sdist support is implemented (`python.go:662`, README feature bullet) but
  flatly denied in README:941 ("wheels only… always enforced") and in `python.md` and
  `troubleshooting.md`.
- **D3** — 8 of 22 streams have no docs page (conda, rubygems, composer, vsx, galaxy, cran,
  git, uploads); `api.md` omits their collect endpoints, the whole jobs API
  (`/admin/jobs*`), and `dry_run`.
- **D4** — README says `hashpw` "reads the password from stdin so it never appears in your
  shell history", but a `--password` flag exists and is documented in `configuration.md`.
- **D5** — `ARTIGATE_HF_TOKEN` (needed for gated models) is absent from
  `docker-compose.yml` and `.env.example`, unlike the other credential env vars.

## What's healthy (round-3 positives, verified)

- **Artifact serving is the right shape everywhere:** every file-backed response goes
  through `http.ServeFile` (sendfile, Range, If-Modified-Since); no handler reads a large
  artifact into memory to serve it (the two manifest reads are capped — M13).
- **HTTP server hygiene:** `ReadHeaderTimeout` 30 s + `IdleTimeout` 120 s, deliberately no
  whole-request timeouts for multi-GiB streams, 30 s graceful drain on SIGTERM.
- **The UDP transport design is sound at its provisioned rate:** stateless per-packet
  metadata, strict wire validation, per-block FEC with loss-only decode cost, per-transfer
  and global RAM budgets, disk-backed reassembly, per-block resume across re-sends with
  quota-correct adoption, eviction that keeps lossy transfers moving.
- **Crash-consistency is exemplary:** tmp+fsync+rename everywhere (now including the
  extract→rename install path), bundle-before-state ordering with skip-forward sequence
  allocation, in-memory counters rolled back on failed state saves, idempotent re-imports.
- **Background loops are contained:** coalesced import kicks (one worker, one pending slot),
  panic recovery on every long-lived loop, the watch scheduler never blocks on collects,
  per-stream queues isolate slow streams (on the low side).
- **No TODO/FIXME debt:** zero in non-test code; the debt lives in docs and this file.
