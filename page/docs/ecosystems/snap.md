# Snap packages

ArtiGate mirrors **Snap packages** from the [Snap Store](https://snapcraft.io) across a data diode. The low side resolves each snap's current revision in a channel through the Snap Store API, downloads the `.snap` squashfs (verified against the store-declared SHA3-384), and fetches the store's **signed assertion chain** — the same `.assert` document `snap download` writes. The high side re-verifies every archive against those assertions and serves the `<name>_<rev>.snap` + `<name>_<rev>.assert` pairs, so the air-gapped machine installs with snapd's own supported offline flow: `snap ack` + `snap install`, signatures verified by snapd itself, no `--dangerous`.

!!! note "A download mirror, not a store proxy"
    snapd cannot be pointed at a third-party store URL without a Canonical-registered store proxy, so ArtiGate does not impersonate the store API. It serves the artifact pairs snapd's documented offline flow consumes — which keeps the full signature chain intact end to end.

## How it works

```text
  snap specs ("hello", "firefox@latest/candidate", "blender@4.1/stable")
        │
        ▼
  GET <store>/v2/snaps/info/<name>   (Snap-Device-Series: 16)
  pick the channel-map entry for the requested channel + architecture
        │
        ▼
  download the .snap (verify store SHA3-384 + size)
  fetch assertions: account-key → account → snap-declaration → snap-revision
  follow the snap's base (core22, …) unless opted out
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        recompute each archive's SHA3-384; require the
                        snap-revision assertion to vouch for exactly those
                        bytes; serve /snap/files/ + /snap/info/
```

## Low side: input

`POST /admin/snap/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "snaps": ["hello", "firefox@latest/candidate"],
  "architecture": "amd64"
}
```

| Field | Type | Meaning |
|---|---|---|
| `snaps` | `[]string` | **Required.** Snap specs: `name` for the stable channel, `name@channel` to pick another (`hello@edge`, `blender@4.1/stable`; `@latest` equals the bare form) |
| `architecture` | string | Store architecture for this collect (default `amd64`; one per collect — run again for another) |
| `no_bases` | bool | Mirror only the listed snaps, skipping the base snaps they declare |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

There is no auth field. `--snap-store` overrides the upstream (default `https://api.snapcraft.io`). Scheduled [watches](../scheduling.md) are supported — a channel watch picks up new revisions as the store promotes them.

### Resolution and download

Each spec resolves through `GET /v2/snaps/info/<name>`; the requested channel matches the store's channel map by bare risk (`stable`), `track/risk` (`4.1/stable`), or either spelling of the default track. The `.snap` is downloaded from the store-declared URL and **verified during download against the store-declared SHA3-384 and size**. Unless `no_bases` is set, the revision's declared **base snap** (`core22`, `core24`, …) is queued too, from its stable channel — capped at 100 snaps per collect, first-channel-wins per name. Individually unfetchable snaps are skipped into `skipped_modules` rather than aborting the batch.

The assertion chain is fetched from the store's assertion endpoints and composed in the order `snap download` writes: the **account-key** of the store signing key(s), the publisher's **account**, the **snap-declaration** (binding snap-id ↔ name), and the **snap-revision** (binding the archive digest ↔ revision). The snap-revision is cross-checked against the channel entry *before* anything is staged, so a store inconsistency fails the snap at collect time.

## High side: verification and serving

On import, the high side **recomputes each archive's SHA3-384** and parses the stored `.assert`: the snap-revision assertion must vouch for exactly the recomputed digest, size, revision, and snap-id, and the snap-declaration must bind that snap-id to the snap's name — a mismatch is logged and the revision stays out of the served metadata. The assertions themselves pass through **verbatim**: their signatures are snapd's to verify, against its built-in root of trust, at `snap ack` time.

| Route | Response |
|---|---|
| `GET /snap/files/<name>/<name>_<rev>.snap` | The squashfs archive |
| `GET /snap/files/<name>/<name>_<rev>.assert` | The assertion chain (`application/x.ubuntu.assertion`) |
| `GET /snap/info/<name>` | JSON: the mirrored revisions (newest first) with version, channel, architecture, digest, and both file URLs |

## Client setup

```bash
# on the air-gapped machine — find the revision, download the pair
curl -fsS https://artigate-high.local/snap/info/hello
curl -fLO https://artigate-high.local/snap/files/hello/hello_42.snap
curl -fLO https://artigate-high.local/snap/files/hello/hello_42.assert

# acknowledge the store assertions, then install — snapd verifies the
# signatures itself, so no --dangerous is needed
snap ack hello_42.assert
snap install hello_42.snap
```

!!! tip "First snap on a fresh machine"
    A machine that has never installed a snap also needs the `snapd` snap (and the app's base, which ArtiGate mirrors alongside by default). Mirror `snapd` like any other snap and install it first.

## Limitations

- **One architecture per collect** (default `amd64`) — run a second collect (or schedule) for another architecture; revisions are store-global, so the files never collide.
- **Offline install flow, not a store proxy.** `snap install <name>` straight from snapd against the mirror is not supported (that requires a Canonical store proxy registration); `snap ack` + `snap install` of the served pair is.
- **No automatic updates on the client.** snapd refreshes only against a store; re-collect (or schedule) the channel and install newer revisions the same way.
- **Bases ride along, content snaps do not.** The declared base is auto-mirrored; content-interface providers (themes, codecs) must be listed explicitly.
- **No private-store auth** on this stream.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged channel re-collect is skipped without consuming a sequence number; `"force": true` bypasses it.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
