# ArtiGate — full code review

**Scope:** the whole `cmd/artigate` binary (~45k LOC of non-test Go across ~60 files),
reviewed for correctness, security (the diode trust boundary above all), concurrency,
and resource safety. Every finding below was verified against the source, not taken on
faith.

**Verdict:** the security-critical core — the high-side verify-and-import pipeline, path
containment, archive extraction, manifest signature/sequence verification, the UDP wire
parser, auth/sessions, TLS — is **exceptionally well engineered** and I found no way
through it. The real defects are concentrated in the per-ecosystem *collect* and
*publish* code and in a few unauthenticated high-side endpoints. Every High/Medium from
the first round (H1–H2, M1–M10) is now **fixed**; a second review round found the M11–M13
class (unauthenticated per-request work on the public port) — request-cost/DoS, not
trust-boundary — of which the two most concrete instances (M4b, L2 detail reads) are fixed
and the rest are recommended follow-ups. The remainder are defense-in-depth (L-series).

**Status at a glance (this branch):**
- **Fixed:** H1, H2, M1, M2, M3, M4 (both parts), M5, M6, M7, M8, M9, M10; L2 (the two
  unauthenticated dashboard config-blob reads).
- **Open, recommended:** M11 (`/ui/api/detail` re-hash), M12 (nuget-search / composer
  whole-mirror walks), M13 (container/HF manifest reads), and the L-series defense-in-depth.

## Validation baseline

All green on the current branch (Go 1.26.5):

| check | result |
|-------|--------|
| `go build ./...` | ✅ |
| `go vet ./...` (incl. `-tags e2e ./e2e`) | ✅ |
| `go test -race ./...` | ✅ (~60s) |
| `golangci-lint run` (v2.12.2, `GOTOOLCHAIN=go1.26.5`) | ✅ `0 issues` |
| `TestEcosystemRegistryWiring` (registry invariant) | ✅ |
| `govulncheck ./...` | runs in CI (`.github/workflows/govulncheck.yml`); the vuln DB is unreachable from the sandbox |

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
`(size, modtime)`-keyed cache like M4(b)'s `pyDigestCache`. **Status: open (recommended).**

### M12 — Two unauthenticated endpoints walk the entire mirror per request

- **`nuget.go:592`** (`handleNugetSearch`, `GET /nuget/v3/search`): `q` is optional and an
  empty/absent `q` skips the filter, so it iterates every package id and reads each id's stored
  metadata + all versions, emitting a body ∝ mirror size, with no pagination (`skip`/`take` are
  ignored). **Fix:** require a non-empty `q` (or enforce a `take` cap) and filter ids before load.
- **`composer.go:686`** (`handleComposerRoot` → `listComposerPackages` `composer.go:930`,
  `GET /composer/packages.json` — the first document every Composer client fetches): to emit just
  the name list it reads **every release's** stored JSON across the whole mirror. **Fix:** cache
  the name list (invalidate on import), or derive names from directory structure without reading
  each release. **Status: open (recommended).**

### M13 — Unbounded manifest/config reads on the container/HF serve path (OOM)

The dashboard-detail half of this (config blobs) is fixed under **L2** above. Still open: the
registry manifest reads `handleContainerManifest` (`container.go:1624`) and `handleHFManifest`
(`hf.go:1552`) `os.ReadFile` the manifest blob whole (size checked only `> 0` at import) on the
unauthenticated `GET /v2/.../manifests/<ref>` pull path. Manifests are tiny in practice, so a cap
is pure hardening, but it closes the last unauthenticated whole-blob-into-memory read.
**Fix:** `readFileLimit` these two with a manifest-sized cap. **Status: open (recommended).**

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
