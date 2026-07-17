# RubyGems

ArtiGate mirrors **Ruby gems** across a data diode. The low side resolves the runtime dependency closure from the upstream **compact index** (`/info/<gem>` documents), downloads every `.gem` verified against its index-declared SHA-256, and carries each release's **verbatim `/info` line** inside the signed manifest. The high side regenerates a compact index (`/versions`, `/info/<gem>`, `/names`) gated on the gems actually present, so Bundler works with the mirror as its only `source`.

!!! note "Compact index only"
    ArtiGate serves the modern compact index that Bundler and current RubyGems use. The legacy Marshal endpoints (`specs.4.8.gz`, `quick/`, `api/v1/dependencies`) are deliberately not served.

## How it works

```text
  gem specs ("rake@13.2.1", "rails")
        │
        ▼
  fetch <upstream>/info/<gem> ──▶ select version, follow runtime deps
        │
        ▼
  download every .gem ──▶ verify the info line's SHA-256
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        regenerate /versions, /info/<gem>, /names
                        from the verbatim lines whose .gem is present
```

## Low side: input

`POST /admin/rubygems/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "gems": ["rake@13.2.1", "rails"],
  "platforms": ["x86_64-linux"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `gems` | `[]string` | **Required.** Gem specs: `rake` for the newest release, `rake@13.2.1` to pin (`@latest` equals the bare form) |
| `platforms` | `[]string` | Optional platform variants (e.g. `x86_64-linux`) fetched **in addition to** the pure-Ruby gem, for the selected version, when upstream publishes them |
| `no_deps` | bool | Mirror only the listed gems, skipping the dependency closure |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

`--rubygems-url` points the collector at another gem server (default `https://rubygems.org`). There is no auth field — private gem servers are not supported on this stream. Scheduled [watches](../scheduling.md) are supported.

### Resolution and download

Resolution reads each gem's compact-index `/info/<gem>` document directly (no `gem`/`bundle` binary is invoked, and upstream `/versions` is never needed). The **runtime dependency closure** is followed breadth-first — first version selected for a gem wins — capped at 2000 gems. Version selection: an exact pin picks the pure-Ruby line for that version; a bare name picks the newest release satisfying all collected constraints, considering **prereleases only when no normal release qualifies**. Constraint operators are Ruby's own: `=`, `!=`, `>`, `<`, `>=`, `<=`, `~>`.

Every `.gem` is downloaded from `<upstream>/gems/<filename>` and stream-verified against the info line's declared **SHA-256** — a tampered upstream fails the collect. The exact upstream `/info` line for each mirrored release travels in the signed manifest, and import re-checks that the line's checksum, the manifest record, and the verified file all agree.

## High side: compact-index regeneration

On import, each `.gem` is re-hashed and its verbatim info line stored; the compact index is then regenerated **gated on the gems present**:

| Route | Response |
|---|---|
| `GET /rubygems/versions` | `created_at` header + one `<name> <versions> <md5>` line per gem |
| `GET /rubygems/info/<gem>` | `---` + the verbatim upstream info lines whose `.gem` is present, versions ascending |
| `GET /rubygems/names` | `---` + one gem name per line |
| `GET /rubygems/gems/<name>-<version>[-<platform>].gem` | The gem file |

The `<md5>` in `/versions` is the MD5 of the served info file — the compact-index content fingerprint Bundler uses for caching, not a security control. Removing a `.gem` delists its version; removing a gem's last artifact removes its `/info` file and `/names` entry.

## Client setup

```ruby
# Gemfile
source "https://artigate-high.local/rubygems"

gem "rake", "13.2.1"
```

```bash
bundle install
```

Bundler re-verifies each info line's checksum against the downloaded `.gem`, so the client-side integrity check keeps working against the mirror.

!!! warning "No upstream fallback"
    Use the mirror as the **only** `source`. A second source reintroduces the substitution risk the diode exists to eliminate. See [Security & trust](../security.md).

## Limitations

- **Compact index only** — the legacy Marshal API (`specs.4.8.gz`, `quick/`, `api/v1/dependencies`) is not served; old RubyGems clients that need it cannot use the mirror.
- **Greedy resolution.** The collect's resolver is first-version-wins, not Bundler's full resolver; Bundler still resolves properly against the served index at install time. Pin versions when the greedy pick matters.
- **Platform gems are opt-in** via `platforms`, and only fetched when upstream publishes that variant for the selected version; the pure-Ruby gem is always mirrored.
- **Prereleases** are selected only when no normal release satisfies the constraints; an exact pin can still mirror one deliberately.
- **No private-server auth** on this stream.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged re-collect is skipped without consuming a sequence number; `"force": true` bypasses it.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring gem collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
