# Git repositories

ArtiGate mirrors **raw git repositories** across a data diode. The low side speaks the smart HTTP protocol as a **pure-Go client** — no `git` binary runs beside the signing key — fetches every selected branch and tag as **one self-contained packfile**, and fully verifies it (trailer hash, every object, every delta) before signing. The high side re-verifies the pack the same way, **rebuilds the `.idx` itself**, and serves the repository over git's **dumb HTTP protocol**, so `git clone <mirror>/git/<name>.git` works with stock git.

!!! note "The pack is verified end to end, twice"
    Both sides run the same verification: the pack's SHA-1 trailer, every object header and zlib stream, every delta resolved to completion (thin packs are rejected), and every object id recomputed. The high side then regenerates `info/refs`, `HEAD`, and the pack index from what it verified — nothing transferred is trusted as metadata.

## How it works

```text
  clone URL (+ optional name, refs)
        │
        ▼
  GET  <url>/info/refs?service=git-upload-pack     (ref advertisement)
  POST <url>/git-upload-pack                        (wants, no haves)
        │
        ▼
  one self-contained pack ──▶ verify trailer + every object + every delta
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        re-verify pack, rebuild .idx, write info/refs + HEAD,
                        serve dumb HTTP under /git/<name>.git
```

## Low side: input

`POST /admin/git/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "url": "https://github.com/octocat/Hello-World.git",
  "name": "hello",
  "refs": ["refs/heads/master", "refs/tags/v1.0"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `url` | string | **Required.** The upstream http(s) clone URL (smart protocol). URLs embedding `user:pass@` are rejected — use `auth` or `ARTIGATE_UPSTREAM_AUTH` |
| `name` | string | Optional mirror name — the segment in `/git/<name>.git`. Defaults to a slug of the URL (`github-com-octocat-Hello-World`) |
| `refs` | `[]string` | Optional full ref names (`refs/heads/…`, `refs/tags/…`) to restrict the mirror. Empty mirrors **every advertised branch and tag**. A listed ref the upstream does not advertise fails the collect |
| `auth` | object | One-shot HTTP Basic login for a private upstream (`{"username": "…", "password": "…"}`) — used for this collect only, never stored |
| `force` | bool | Bypass the export-dedup index (re-send the pack even if unchanged) |

Private upstreams can also use a standing `host=user:password` entry in `ARTIGATE_UPSTREAM_AUTH` — the only credential source scheduled [watches](../scheduling.md) use. Each re-collect (or watch run) refreshes the mirror to the current upstream refs.

### The fetch, mechanically

The client sends one `want` per selected tip and **no `have`s**, so the server always returns one complete, self-contained pack — there is no incremental negotiation. The whole exchange runs under a 30-minute deadline; the pack is capped at **2 GiB** and parsed **entirely in memory** on both sides (delta resolution needs random access), with individual objects capped at 512 MiB decompressed. The pack is stored content-addressed by its own trailer hash, so an unchanged upstream re-collect dedups to "no new content" without consuming a sequence number.

The signed manifest carries the mirror's URL, the selected refs with their commit ids, the head, and the pack's path + SHA-256.

## High side: serving (dumb HTTP)

On import the pack is re-verified from scratch and a fresh **idx v2** is written beside it. Refs whose objects are missing from the pack are dropped (and logged) rather than served dangling. The served layout is exactly what stock git's dumb-protocol walker needs:

| Route | Response |
|---|---|
| `GET /git/<name>[.git]/HEAD` | `ref: refs/heads/<default>` |
| `GET /git/<name>[.git]/info/refs` | The ref list (also answers the smart probe `?service=git-upload-pack` with the same plain text, which makes git fall back to dumb HTTP) |
| `GET /git/<name>[.git]/objects/info/packs` | `P pack-<sha1>.pack` — the newest pack |
| `GET /git/<name>[.git]/objects/pack/pack-<sha1>.{pack,idx}` | The pack and its regenerated index |

Only the newest pack is advertised, so clients walk exactly one complete pack.

## Client usage

```bash
git clone https://artigate-high.local/git/hello.git
git ls-remote https://artigate-high.local/git/hello.git
```

Stock git, no credentials (the high side is unauthenticated), no special configuration. `git fsck --strict` on a clone re-hashes every object if you want to double-check end to end.

## Limitations

- **Read-only, dumb protocol.** No pushes, no smart-protocol negotiation, no server-side shallow or partial clones — a client always fetches the full advertised pack.
- **Full pack per collect.** The low side never sends `have`s, so each re-collect re-downloads the whole pack for the selected tips (export dedup still keeps unchanged packs off the diode).
- **2 GiB pack cap, in-memory verification.** A repository whose pack exceeds the cap needs a narrower ref selection; both sides hold the pack in memory while verifying.
- **Git LFS media is not fetched** — LFS pointer files travel as ordinary blobs, but the media on the separate LFS endpoint does not. **Submodules are not followed**; mirror each submodule repository separately.
- **Unusual ref names** (spaces, `@{`, …) are skipped in default selection and rejected in an explicit `refs` list.
- An **empty repository** (no advertised branches or tags) fails the collect.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — keeping mirrors fresh
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
