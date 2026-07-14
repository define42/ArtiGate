# Alpine (apk)

ArtiGate mirrors Alpine Linux package repositories across a data diode: the low side fetches an Alpine mirror's `APKINDEX` per **branch / repository / architecture**, downloads every listed `.apk` — verified against the index-declared size and control checksum — and the high side **regenerates** `APKINDEX.tar.gz` from the verbatim index stanzas carried inside the signed manifest, gated on the packages actually present, optionally signing it with an operator-held RSA key so stock `apk` clients accept it without `--allow-untrusted`.

Like the [APT adapter](apt.md), a mirror is one **archive base** carrying one or more branch selections, and the high side accumulates everything ever imported under `/apk/<mirror>`.

## How it works

```text
  mirror base + branches/repos/arches
  (or a pasted /etc/apk/repositories file)
        │
        ▼
  fetch APKINDEX.tar.gz per branch/repo/arch
        │
        ▼
  keep newest version per package (default) ──▶ download every .apk
        │                                        verify size + Q1 checksum
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
   (carries the verbatim index stanzas)   │
                                          ▼
                        regenerate APKINDEX.tar.gz per branch/repo/arch
                        from the stanzas of the .apks present —
                        optionally RSA-signed (--apk-rsa-key)
```

- Fetching is plain HTTPS — **no `apk` binary is invoked** on either side.
- The high side **never trusts a transferred index**: served indexes are rebuilt from the manifest-carried stanzas of packages that are actually on disk, and each stanza is validated so it can only describe the artifact the bundle delivered.

## Low side: input

`POST /admin/apk/collect` (add `?stream=1` for streamed progress). Body limit **1 MiB**. Two input modes:

```json
{
  "name": "alpine",
  "uri": "https://dl-cdn.alpinelinux.org/alpine",
  "branches": ["v3.22"],
  "repositories": ["main", "community"],
  "architectures": ["x86_64"],
  "newest_only": true
}
```

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Optional mirror name — the URL segment under `/apk/<name>` on the high side. Defaults to a slug of the URI |
| `uri` | string | The mirror base (http/https) — the part **before** `<branch>/<repo>`, e.g. `https://dl-cdn.alpinelinux.org/alpine` |
| `branches` | `[]string` | Branches to mirror, e.g. `["v3.22"]` or `["edge"]` — required with `uri` |
| `repositories` | `[]string` | Repositories per branch. **Defaults to `["main"]`** |
| `architectures` | `[]string` | Architectures per branch. **Defaults to `["x86_64"]`** |
| `repositories_file` | string | A pasted `/etc/apk/repositories` file — an alternative to `uri`+`branches`+`repositories` |
| `newest_only` | `*bool` | **Defaults true when absent**: keep only each package's highest version (the usual state of an Alpine index). `false` mirrors every listed version |
| `force` | bool | Bypass the export-dedup index — pack every package even if already forwarded (full, self-contained bundle) |

### Mode 2 — a pasted `/etc/apk/repositories` file

`repositories_file` takes the client file verbatim: each line names `<uri>/<branch>/<repo>` (comments and `@tag`-prefixed lines are handled), and ArtiGate derives the shared mirror base plus the branch → repositories selection from it. `architectures` still applies (default `x86_64`).

```text
https://dl-cdn.alpinelinux.org/alpine/v3.22/main
https://dl-cdn.alpinelinux.org/alpine/v3.22/community
```

!!! warning "One mirror base per collect"
    Every line must share the same mirror base — lines naming different mirrors are rejected with `repositories name different mirrors (… and …); collect them separately`. Branch, repository, and architecture tokens must be single path-safe segments.

## What gets mirrored and how it is verified

For each **branch × repository × architecture**, ArtiGate fetches `<uri>/<branch>/<repo>/<arch>/APKINDEX.tar.gz`, extracts the `APKINDEX` member (walking straight through a leading signature segment), and parses its stanzas. With `newest_only` (the default) only each package's highest version is kept, compared with apk's own version rules (dotted numerics, trailing letter, `_alpha < _beta < _pre < _rc <` release `< _cvs < _svn < _git < _hg < _p` suffixes, then `-rN`).

Every `.apk` is then downloaded from `<repo-url>/<name>-<version>.apk` and verified against its stanza:

- the byte size must equal the index's `S:` field **exactly**;
- the `C:` **pull checksum** must match — `Q1` + base64 of the SHA-1 of the package's compressed control segment, the same check `apk` itself performs (SHA-1 here is apk's index format, not an ArtiGate security control).

!!! note "No whole-file hash upstream ⇒ re-collects re-download"
    The APKINDEX declares no whole-file hash, so a [scheduled](../scheduling.md) re-collect must re-download packages on the low side to hash them. [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) still applies afterward: unchanged packages are never re-**sent** — a re-collect that finds nothing new writes no bundle and consumes no sequence, and a partly-new one ships a delta bundle carrying only the churn.

Per-package failures are skipped and reported in `skipped_modules`; an unreachable index fails the collect (a selection error the operator should see). Zero fetched packages fail with `no apk packages could be fetched: …`.

## Low side: the signed bundle

Packages are packed into the standard numbered, Ed25519-signed bundle on the `apk` stream. Each record carries the **verbatim APKINDEX stanza** inside the signed manifest, alongside the identity and the computed SHA-256:

```json
{
  "package": "curl",
  "version": "8.9.1-r0",
  "architecture": "x86_64",
  "branch": "v3.22",
  "repository": "main",
  "filename": "curl-8.9.1-r0.apk",
  "sha256": "…",
  "size": 265390,
  "stanza": "C:Q1…\nP:curl\nV:8.9.1-r0\nA:x86_64\n…"
}
```

On import the stanza is validated strictly: every line must be a single-letter `X:` field (so a hostile stanza cannot embed a blank line and forge extra index entries when stanzas are concatenated back into an APKINDEX), its `P:`/`V:` fields must name exactly this package, the filename must be the canonical `<name>-<version>.apk`, and the branch/repo/arch must be within the mirror's declared selection.

## High side: index regeneration and optional signing

On import, each mirror is **merged** into a persistent per-mirror index (branch selections union; the newer record wins per branch/repo/arch/filename — the high side accumulates every version ever imported), and every touched `APKINDEX.tar.gz` is regenerated from the accumulated stanzas **whose `.apk` is actually present**.

With `--apk-rsa-key` set, the regenerated index is signed the way `apk` expects: a leading `.SIGN.RSA.<key-name>` segment carrying an RSA PKCS#1 v1.5 signature (over the index segment's SHA-1 digest, apk's format), verified by clients against `/etc/apk/keys/<key-name>`.

| Flag (high side) | Default | Effect |
|---|---|---|
| `--apk-rsa-key` | `""` (unset) | PEM RSA private key (PKCS#1 or PKCS#8) used to sign regenerated `APKINDEX.tar.gz` files. Unset serves them **unsigned** — clients then need `apk --allow-untrusted` |
| `--apk-key-name` | `artigate.rsa.pub` | Filename clients install the matching **public** key under (`/etc/apk/keys/<name>`); also the served key route |

The signing key is ArtiGate's own, held on the high side — not Alpine's. Generate one with e.g. `openssl genrsa -out /etc/artigate/apk.pem 4096`.

## High side: serving

The high side serves the Alpine repository shape under `/apk/` (GET/HEAD only):

| Route | Response |
|---|---|
| `GET /apk/<mirror>/<branch>/<repo>/<arch>/APKINDEX.tar.gz` | The regenerated (optionally signed) index |
| `GET /apk/<mirror>/<branch>/<repo>/<arch>/<pkg>-<ver>.apk` | The package |
| `GET /apk/keys/<key-name>` | The PEM **public** key matching `--apk-rsa-key` (only when signing is configured) |

The dashboard's **"Set me up"** guide lists each apk mirror with its branch/repo/arch selections and whether its indexes are signed.

## Client setup

```bash
# with --apk-rsa-key on the high side: install the mirror's key once
wget -O /etc/apk/keys/artigate.rsa.pub https://artigate-high.local/apk/keys/artigate.rsa.pub

echo https://artigate-high.local/apk/alpine/v3.22/main >> /etc/apk/repositories
apk update
apk add curl
```

Without high-side signing, pass `--allow-untrusted` to `apk update`/`apk add` instead — content was still hash-verified end-to-end when its signed bundle was imported, but prefer configuring the key.

!!! warning "No upstream fallback"
    Replace the stock repository lines rather than appending to them — a public mirror left in `/etc/apk/repositories` reintroduces the substitution risk the diode exists to eliminate. See [Security & trust](../security.md).

## Limitations

- **Re-collects re-download.** The upstream index has no whole-file hash, so scheduled re-collects re-download packages on the low side; export dedup still keeps re-sends off the diode.
- **`newest_only` is a low-side filter** — the high side accumulates every version, branch, repository, and architecture ever imported and never removes what already crossed.
- **`Q1` checksums only**: a stanza with a non-`Q1` `C:` checksum fails that package. Stanzas without a checksum skip the control check; the exact-size check applies whenever the stanza declares `S:`.
- **Signing is optional and ArtiGate's own** — `--apk-rsa-key` signs with the operator's key, not Alpine's; unsigned mirrors need `--allow-untrusted` on clients.
- Size caps: request body 1 MiB, compressed index fetch 1 GiB, decompressed `APKINDEX` 2 GiB, per-`.apk` download 8 GiB / 30 minutes, control-segment decompression guard 16 MiB.

## Related pages

- [APT (Debian/Ubuntu)](apt.md) — the closest sibling adapter (stanzas in the manifest, regenerated indexes, optional signing)
- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Security & trust](../security.md) — the signing/verification chain
- [Scheduling (watches)](../scheduling.md) — recurring Alpine collects
- [HTTP API reference](../api.md) — the exact request/response contracts
