# Conda channels

ArtiGate mirrors **conda channels** across a data diode. The low side fetches a channel's `repodata.json` per platform subdir, resolves the requested package specs and their dependency closure against it, and downloads each package file verified against its **repodata-declared SHA-256**. The high side regenerates per-subdir `repodata.json` from the verified entries whose packages are actually present and serves the channel under `/conda/<mirror>`, so `conda`, `mamba`, and `micromamba` install from the mirror unchanged.

!!! note "Verbatim repodata entries travel in the signed manifest"
    Each mirrored package's upstream repodata entry crosses the diode inside the signed manifest, and the high side rebuilds `repodata.json` **only** from those verified entries — it never serves a transferred index. A repodata entry that declares no SHA-256 is refused at collect time: an unverifiable file is never mirrored.

## How it works

```text
  channel + package specs ("numpy", "scipy==1.13.1")
        │
        ▼
  fetch <channel>/<subdir>/repodata.json(.zst|.bz2)   (noarch always included)
        │
        ▼
  resolve specs + depends greedily ──▶ download each file, verify repodata SHA-256
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        regenerate repodata.json per subdir from the
                        verified entries present, under /conda/<mirror>/
```

## Low side: input

`POST /admin/conda/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "channel": "conda-forge",
  "subdirs": ["linux-64"],
  "packages": ["numpy", "scipy==1.13.1", "pandas>=2.0,<3"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `channel` | string | **Required.** A bare channel name (`conda-forge`), resolved under the channel base (`https://conda.anaconda.org` by default; `--conda-channel-base` overrides), or a full `http(s)` channel URL |
| `name` | string | Optional mirror name — the URL segment under `/conda/<name>`. Defaults to the bare channel name, or a slug of the channel URL |
| `subdirs` | `[]string` | Platform subdirs to search (`linux-64`, `osx-arm64`, …). **`noarch` is always searched too**; an empty list means just `noarch` |
| `packages` | `[]string` | **Required.** Package specs (see below) |
| `no_deps` | bool | Mirror only the listed packages, skipping the `depends` closure |
| `auth` | object | One-shot HTTP Basic login for a private channel (`{"username": "…", "password": "…"}`, optional `host`) — used for this collect only, never stored |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

**Spec syntax** is a pragmatic MatchSpec subset: `numpy` (newest), `numpy==1.26.4` (exact — `==1.2` also matches `1.2.0`), `numpy=1.26` / `1.26.*` / `2.7*` (prefix), `pandas>=2.0,<3` (comma = AND) with operators `==`, `!=`, `>=`, `<=`, `>`, `<`, `=`, and `*` for any. `|` alternation and mid-string wildcards are rejected.

Scheduled [watches](../scheduling.md) re-run a stored collect; a watch spec may not embed `auth` — standing credentials for private channels go in `ARTIGATE_UPSTREAM_AUTH` (`host=user:password`, the same variable the git/APT/RPM/Alpine streams use). URLs embedding `user:pass@` are rejected.

### Resolution and download

Per subdir, the repodata is fetched preferring `repodata.json.zst` (decompressed with the host's `zstd` tool), then `repodata.json.bz2`, then plain `repodata.json`. Resolution is **greedy and breadth-first**: for each name the best candidate wins — highest version, then highest `build_number`, preferring a platform subdir over `noarch` and the `.conda` format over `.tar.bz2` — and the first selection of a name is final (no SAT solving or backtracking). Virtual `__`-prefixed packages (`__glibc`, …) are skipped. The closure is capped at 4000 packages.

Each selected file is downloaded from `<channel>/<subdir>/<filename>` and stream-verified against the repodata entry's SHA-256. When the same `(name, version, build)` exists in both formats, only the `.conda` form is kept.

## High side: repodata regeneration

On import (after the Ed25519 signature and per-file SHA-256 checks), each package's verbatim repodata entry is re-verified against the artifact and stored; then `repodata.json` is regenerated per touched subdir — split into the standard `packages` (`.tar.bz2`) and `packages.conda` maps — listing **only entries whose package file is present**. The `noarch` subdir is always served, even as an empty skeleton, because conda clients unconditionally request it.

| Route | Response |
|---|---|
| `GET /conda/<mirror>/<subdir>/repodata.json` | The regenerated subdir index (`application/json`) |
| `GET /conda/<mirror>/<subdir>/<file>.conda` / `….tar.bz2` | The package file |

The served repodata lists **every mirrored version-build**, not just the newest — the client's own solver picks, exactly as against the real channel.

## Client setup

```bash
conda install --override-channels -c https://artigate-high.local/conda/conda-forge numpy
micromamba install -c https://artigate-high.local/conda/conda-forge --override-channels numpy
```

```yaml
# ~/.condarc
channels:
  - https://artigate-high.local/conda/conda-forge
override_channels_enabled: true
```

!!! warning "No upstream fallback"
    `--override-channels` (or a `.condarc` with only the mirror) keeps the solver off `defaults`/`conda-forge` upstream. Any extra channel reintroduces the substitution risk the diode exists to eliminate. See [Security & trust](../security.md).

## Limitations

- **Greedy resolution, no SAT backtracking.** The collect may pick a combination a full solver would refine; pin exact versions for anything sensitive. The client-side solver still runs against the served repodata as usual.
- **Memory budget.** Repodata is decompressed and parsed fully in memory, and big channels are genuinely large — conda-forge's `linux-64` repodata alone exceeds 1 GiB plain. Give the low side a generous RAM budget (decompression is capped at 8 GiB).
- **A subdir that fails to fetch fails the whole collect** — partial channel views are never mirrored silently.
- **Unverifiable entries are refused**: a repodata entry without a 64-hex `sha256` never mirrors.
- Private channels authenticate with the `auth` field or `ARTIGATE_UPSTREAM_AUTH`; there is no anonymous retry once credentials are configured for the host.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged re-collect is skipped without consuming a sequence number; `"force": true` bypasses it.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring channel collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
