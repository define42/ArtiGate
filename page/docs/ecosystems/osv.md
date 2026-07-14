# OSV advisories

ArtiGate mirrors **vulnerability-advisory databases** from the [OSV](https://osv.dev) aggregator across a data diode — the piece that turns the air-gapped side from "can build against mirrored dependencies" into "can also *audit* them". The low side fetches one `all.zip` archive of OSV JSON records per ecosystem name (the same artifacts osv-scanner and friends consume offline); the high side serves the verified snapshots in the upstream bucket's own URL layout under `/osv/`, and — when the `npm` database is mirrored — answers **`npm audit`** on its npm registry, so clients can drop the `audit=false` workaround.

!!! note "Snapshots, not artifacts"
    Advisory databases are the one deliberately **mutable** mirrored subtree: upstream replaces them continuously, so each import replaces the previous snapshot at the same canonical path. Everything still crosses only inside signed, hash-verified, strictly sequenced bundles — and an unchanged database dedups to a no-op export, which makes a daily schedule near-free on the diode.

## How it works

```text
  OSV ecosystem names ("npm", "PyPI", "Alpine:v3.22", …)
        │
        ▼
  fetch <bucket>/<name>/all.zip ──▶ verify it is a readable
        │                           advisory archive (≥1 record)
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        recount advisories from the zip itself,
                        regenerate ecosystems.txt + metadata,
                        rebuild the npm bulk-audit index,
                        serve under /osv/…
```

- Fetching is plain HTTPS from `https://osv-vulnerabilities.storage.googleapis.com` (override with `--osv-upstream`); **no scanner tool is invoked** on either side.
- The high side **never trusts transferred numbers**: advisory counts, hashes, and the audit index are all re-derived from the verified zip at import.
- Ecosystem names become storage **slugs** (lowercased, characters outside `[a-z0-9._-]` collapsed to `-`): `Alpine:v3.20` is stored — and also addressable — as `alpine-v3.20`.

## Low side: input

`POST /admin/osv/collect` (add `?stream=1` for streamed progress). Body limit **1 MiB**.

```json
{
  "ecosystems": ["npm", "PyPI", "Go", "crates.io", "Alpine:v3.22", "Debian:12"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `ecosystems` | `[]string` | **Required.** OSV ecosystem names, exactly as osv.dev spells them (case-sensitive, spaces and colons allowed: `Rocky Linux`, `Ubuntu:22.04:LTS`) |
| `force` | bool | Bypass the export-dedup index — pack every database even if its content already crossed |

In the low-side dashboard (**OSV** tab), enter one name per line. The upstream's `ecosystems.txt` (`https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`) lists every valid name. Two distinct names that collide on one storage slug (`PyPI` and `pypi`) are rejected — they could not both be delivered in one bundle.

!!! warning "TLS-trusted downloads"
    The OSV bucket publishes no digests for its zips, so the download itself is TLS-trusted — like the other index-less fetches (NuGet, digest-less Helm repos). Each archive must parse as a zip holding at least one advisory before it is signed into a bundle; everything after that is hash-locked end to end.

Databases that cannot be fetched are skipped and reported in `skipped_modules`; zero fetched databases fail the collect. [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies per snapshot: a scheduled re-collect exports only databases whose content actually changed.

## Low side: the signed bundle

Fetched databases are packed into the standard numbered, Ed25519-signed bundle on the `osv` stream, one record per database:

```json
{
  "ecosystem": "Alpine:v3.22",
  "path": "osv/dbs/alpine-v3.22/all.zip",
  "sha256": "…",
  "advisories": 4711
}
```

At import the high side rejects any record whose path is not the ecosystem's canonical one or whose hash claim differs from the byte-verified artifact. The `advisories` count is informational — the high side recounts from the zip itself.

## High side: regeneration and serving

On import (after the Ed25519 signature and per-file SHA-256 checks), each database's metadata is re-derived from the installed zip — advisory count, hash, size — and `ecosystems.txt` is assembled from the databases actually present. Everything is served read-only (GET/HEAD) under `/osv/`:

| Route | Response |
|---|---|
| `GET /osv/ecosystems.txt` | Mirrored ecosystem names, one per line (404 while nothing is mirrored) |
| `GET /osv/<ecosystem>/all.zip` | The database snapshot (`application/zip`) — name verbatim (URL-encoded where needed) or its slug |
| `GET /osv/<ecosystem>/<ID>.json` | One advisory (`GHSA-…`, `CVE-…`, `MAL-…`), streamed straight out of the verified zip — no 100k-file database is ever unpacked onto disk |

### npm audit

Importing the **`npm`** database additionally rebuilds a name-keyed advisory index (rendered from each record's own OSV data — GitHub-Advisory severities mapped onto npm's words, OSV version events rendered as npm ranges), and the npm registry answers the bulk-audit protocol npm 7+ uses:

```text
POST /npm/-/npm/v1/security/advisories/bulk    (gzip request bodies supported)
```

`npm audit` then works against the mirror with no client configuration beyond the registry itself. Three deliberate choices:

- **404 until the database is mirrored** — npm reports "audit endpoint unavailable" rather than a false all-clear.
- **Fail loud, never narrow** — a record whose version events cannot be rendered exactly is reported as affecting all versions (`*`), and *withdrawn* advisories are dropped from audit results (their raw records stay downloadable from the zip).
- **No fabricated scores** — OSV publishes CVSS vectors, not scores, so audit responses carry no `cvss` block; npm renders the qualitative severity as usual.

Version filtering is left to the client: npm re-checks every installed version against `vulnerable_versions` anyway, so the mirror returns each requested package's full advisory list.

## Client setup

```bash
# Browse what is mirrored
curl -fsSL https://artigate-high.local/osv/ecosystems.txt

# Feed an offline scanner — osv-scanner reads <cache>/osv-scanner/<ecosystem>/all.zip
curl -fL -o "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scanner/npm/all.zip" \
  https://artigate-high.local/osv/npm/all.zip
osv-scanner --offline -r .

# Fetch one advisory
curl -fsSL https://artigate-high.local/osv/npm/GHSA-xxxx-xxxx-xxxx.json
```

```ini
# npm audit needs nothing extra — with the "npm" database mirrored, drop audit=false:
registry=https://artigate-high.local/npm/
```

Schedule the collect daily ([Scheduling](../scheduling.md)) so the air-gapped side's advisory picture keeps tracking upstream: the low side re-fetches, unchanged databases dedup away, and only real advisory churn crosses the diode.

## Limitations

- **npm's bulk protocol only** (npm 7+). yarn classic's older `/-/npm/v1/security/audits` protocol is not served; pnpm uses the bulk endpoint.
- **Advisory contents are upstream's** — served verbatim from the zip. Only the npm audit *index* interprets records, with the widen-don't-narrow rules above.
- **Whole-database granularity**: each ecosystem's `all.zip` is fetched in full when it changed (the OSV bucket offers no deltas). Large ecosystems (npm with its malicious-package records, distro CVE feeds) run to a few hundred MB per refresh.
- Size and time caps: request body 1 MiB, per-database download 8 GiB / 30 minutes, one advisory parsed from a zip 32 MiB.

## Related pages

- [NPM](npm.md) — the registry whose `npm audit` this stream powers
- [Low side](../low-side.md) / [High side](../high-side.md) — operating the two halves
- [Security & trust](../security.md) — the signing/verification chain, and why `osv/` is a mutable subtree
- [Scheduling (watches)](../scheduling.md) — the daily advisory refresh
- [HTTP API reference](../api.md) — the exact request/response contracts
