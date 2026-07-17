# PHP Composer

ArtiGate mirrors **PHP Composer packages** across a data diode. The low side resolves the require closure from the upstream's **Composer v2 (p2) metadata** over stable releases and downloads each release's dist zip; each release's expanded version object travels in the signed manifest **with its `dist` and `source` sections stripped**. The high side re-renders the p2 API from those verified objects — re-injecting a `dist` that points back at its own verified zips — so `composer install` works against `/composer` with packagist.org disabled.

!!! note "Dist URLs always point at the mirror"
    The upstream `dist`/`source` sections are stripped before the metadata crosses the diode (they would leak internal URLs and bypass the mirror), and a manifest that still carries either is rejected at import. The served p2 objects get a fresh `dist` whose URL is the mirror's own `/composer/dist/...` path with a recomputed shasum.

## How it works

```text
  package specs ("monolog/monolog", "psr/container:2.0.2")
        │
        ▼
  fetch <upstream>/p2/<vendor>/<project>.json ──▶ select release, follow require
        │
        ▼
  download each dist zip ──▶ strip dist/source from the metadata
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        re-render packages.json + p2 metadata from the
                        verified objects, dist re-pointed at /composer/dist/
```

## Low side: input

`POST /admin/composer/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "packages": ["monolog/monolog", "psr/container:2.0.2"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `packages` | `[]string` | **Required.** Package specs: `vendor/project` for the newest stable release, `vendor/project:2.0.2` to pin (pretty or normalized version both match) |
| `no_deps` | bool | Mirror only the listed packages, skipping the require closure |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

`--composer-repo` points the collector at another Composer repository (default `https://repo.packagist.org`). There is no auth field — private repositories are not supported on this stream. Scheduled [watches](../scheduling.md) are supported.

### Resolution and download

The p2 metadata (`<upstream>/p2/<vendor>/<project>.json`, Composer's minified format expanded first) drives everything; no `composer` binary is invoked. A pinned spec picks its exact release; a bare spec picks the **newest stable** release (falling back to the newest of anything only when no stable exists). The `require` closure is followed breadth-first, capped at 2000 packages, with three deliberate skips:

- **Platform packages** — `php`, `hhvm`, `composer-plugin-api`, `composer-runtime-api`, `ext-*`, `lib-*` — are requirements on the runtime, not mirrorable packages.
- **Dependencies resolve stable-only** (Composer's default `minimum-stability: stable`); a require satisfiable only by a beta is reported, not guessed.
- **`dev` constraints** (`dev-master`, `2.x-dev`, …) are skipped — the mirror serves tagged releases only.

The constraint language is a pragmatic subset — `*`, `^`, `~` (two-field or more), comparisons, `.*` wildcards, `||` alternation, comma/space AND — and anything outside it (hyphen ranges, stability flags, `dev-*`) is **reported per package, never guessed**.

Composer's metadata declares no usable digest for dists (the upstream `shasum` field is empty in practice), so the zip download is TLS-trusted to the metadata-declared URL — http(s) `zip` dists only — then hash-locked into the signed bundle. Everything after the download is covered by the bundle's SHA-256 chain.

## High side: p2 re-rendering

On import, each zip is stored (never opened — metadata comes from the verified manifest objects) and its **SHA-1 recomputed** for the client-facing `dist.shasum`. Serving regenerates everything on the fly, gated on the zip being present:

| Route | Response |
|---|---|
| `GET /composer/packages.json` | `{"metadata-url": "/composer/p2/%package%.json", "available-packages": [...]}` |
| `GET /composer/p2/<vendor>/<project>.json` | Full version objects, newest first, each with a re-injected mirror `dist` |
| `GET /composer/p2/<vendor>/<project>~dev.json` | Always an empty list for known packages (the mirror carries no dev versions) |
| `GET /composer/dist/<vendor>/<project>/<version_normalized>.zip` | The dist zip |

## Client setup

```json
// composer.json
{
  "repositories": {
    "packagist.org": false,
    "mirror": { "type": "composer", "url": "https://artigate-high.local/composer" }
  },
  "require": { "psr/container": "2.0.2" }
}
```

```bash
composer install
```

`"packagist.org": false` disables the built-in Packagist fallback — required, or Composer will quietly fetch anything the mirror lacks from the internet. Composer re-verifies the served `dist.shasum` against each downloaded zip.

## Limitations

- **Tagged releases only, stable-first.** Dev versions are never mirrored (`~dev` metadata is served as an empty list), and dependency edges resolve stable-only.
- **http(s) `zip` dists only** — other dist types or schemes fail that package.
- **No upstream digest**: the low-side zip download is TLS-trusted (Composer metadata carries no usable checksum); integrity from there on rests on the signed bundle, and the served shasum is recomputed by the mirror.
- **Constraint subset**: unsupported constraint forms are reported and skipped, never guessed.
- **No private-repository auth** on this stream.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged re-collect is skipped without consuming a sequence number; `"force": true` bypasses it. Re-collecting accumulates additional releases of a package.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
