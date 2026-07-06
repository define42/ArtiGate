# RPM (RHEL/Fedora)

ArtiGate mirrors yum/dnf repositories at full metadata fidelity: the [low side](../low-side.md) fetches `repomd.xml`, every metadata file it references, and every `.rpm`, verifies them, and packs them into a signed bundle; the [high side](../high-side.md) regenerates `repomd.xml` from the recorded entries, optionally re-signs it, and serves the whole repository read-only under `/rpm/<mirror>`.

RPM work travels on the `rpm` stream. Like every ecosystem, that stream has its own sequence counter and export lock, so an RPM collect never blocks or interleaves with Go, Python, Maven, npm, APT, container, or AI model work — only the `rpm` stream lock is held across the whole mirror → write → commit.

Unlike a pull-through cache, ArtiGate is a **full repository mirror** (Fedora/RHEL/EPEL-scale): each collect is a complete re-sync of the current upstream repository into one new sequenced, Ed25519-signed bundle. There is no incremental/delta logic.

## What it mirrors

For each mirror, ArtiGate downloads and integrity-checks:

| Content | Source | Verification |
|---|---|---|
| `repodata/repomd.xml` | `GET {base}/repodata/repomd.xml` | optional detached signature (see below) |
| Every metadata file | each `<data>` `href` in `repomd.xml` (primary, filelists, other, updateinfo, comps/group, modules, zchunk variants, …) | upstream-declared checksum |
| Every `.rpm` | each `<location>` in the primary index | SHA-256 (the package `pkgid`) |

The primary index is parsed to enumerate packages; the `.rpm` files and all metadata files are packed into the bundle, along with the `repomd.xml` `<data>` entries the high side needs to regenerate the repository entry point.

!!! note "Every file is checksum-gated before it is staged"
    Each download is verified against the checksum upstream declares for it, and discarded on mismatch. Metadata honours the upstream algorithm (`sha256`, `sha512`, or legacy `sha1`); every `.rpm` is always verified as **SHA-256** against its `<checksum pkgid="YES">` value. The bundle manifest additionally records each file's own SHA-256, which the high side re-verifies on import.

## Low-side input: the `.repo` stanza

Drive a collect with `POST /admin/rpm/collect`. Provide **either** a full yum/dnf `.repo` file, **or** the explicit `name`/`base_url` fields:

```json
{
  "name": "",
  "base_url": "https://packages.microsoft.com/rhel/9.0/prod/",
  "gpg_key": "",
  "repo_file": "",
  "newest_only": true
}
```

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Mirror name; derived from the URL host/path when empty. Must not contain `/`. |
| `base_url` | string | Concrete `baseurl` (see the variable rule below). Required if no `repo_file`. |
| `gpg_key` | string | **Local** keyring path for `gpgv`, used to verify `repomd.xml.asc`. Optional. |
| `repo_file` | string | A full `.repo` (INI) file, one or more `[section]`s. Wins when non-blank. |
| `newest_only` | *bool | Keep only the newest version of each package. **Defaults to `true`** when omitted. |

When `repo_file` is present and non-blank it wins: each `[section]` becomes one mirror. A top-level `gpg_key` in the request **overrides** the `gpgkey=` parsed from every section. Duplicate mirror names across sections are rejected (`give each repo a distinct name`).

### `.repo` (INI) parsing

Only two keys are read from each `[section]`; everything else (`enabled`, `gpgcheck`, `name`, `metalink`, `mirrorlist`, …) is **silently ignored**:

```ini
[my-repo]
name=My Repo
baseurl=https://packages.microsoft.com/rhel/9.0/prod/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/MICROSOFT-GPG-KEY
```

- **`baseurl`** → only the first whitespace-separated token is kept (a multi-URL baseurl keeps just the first URL).
- **`gpgkey`** → passed through only when it names a **local** file:
    - `file:///path` → `file://` stripped, used as a local `gpgv` keyring.
    - `/absolute/path` → used directly.
    - anything else (e.g. an `https://` key URL) → **dropped**, so low-side signature verification is simply skipped.

!!! warning "A remote `gpgkey=https://…` yields no verification"
    ArtiGate only verifies `repomd.xml.asc` when `gpgkey` resolves to a local keyring file. A normal upstream `gpgkey=https://…` URL is silently dropped and the repomd signature is **not** checked at collect time. To verify on the low side, point `gpg_key` (or a `file://` `gpgkey=`) at a keyring you have already imported locally.

### The `baseurl` must be concrete

There is **no** variable substitution. Any `$` in `base_url` is a hard error — you must expand `$releasever`/`$basearch` yourself and pin a concrete URL:

```text
base_url "https://.../$releasever/$basearch/" has unresolved variables
($releasever/$basearch); pin a concrete URL
```

The scheme must be `http` or `https`.

## "Newest version only" default

`newest_only` **defaults to `true`**. When enabled, ArtiGate keeps only the highest **EVR** (epoch → version → release) of each `(name, arch)` pair, using a faithful reimplementation of rpm's `rpmvercmp` — including the `~` (pre-release, sorts before everything) and `^` (post-release) separators, numeric-outranks-alpha segment rules, and leading-zero-stripped numeric comparison.

Set `"newest_only": false` to mirror **every** version present in the index.

When newest-only actually drops packages, ArtiGate rewrites the staged primary index so the served repository advertises **only** the kept packages: it keeps each retained `<package>` block **verbatim** (no metadata-field loss), rewrites the root `packages="N"` count, recompresses to match the original href extension, and updates both the manifest file entry and the primary `<data>` entry (checksums/open-checksums/sizes) so the bundle and the high side's regenerated `repomd.xml` stay consistent.

!!! warning "Newest-only cannot rewrite a zchunk-only primary index"
    Rewriting the primary requires recompressing it. If the primary index is offered **only** as `.zck` (zchunk), the rewrite fails with `cannot rewrite zchunk (.zck) index … for newest-only; disable newest-only for this repo`. The fix is `"newest_only": false`.

## High-side regeneration and signing

On import, for each mirror the high side:

1. **Persists a snapshot** of the mirror (`repodata` entries + package list) to `<root>/rpm/<mirror>/index.json`. The newest snapshot wins — metadata files are content-named and immutable; `repomd.xml` is high-side-owned.
2. **Regenerates `repomd.xml`** from the recorded `<data>` entries, emitting a `<data>` block **only for entries whose file actually exists on disk** (so a metadata file absent from the bundle is dropped from the index). It preserves the upstream checksums and open-checksums **verbatim** — it never decompresses or re-hashes the (potentially huge or zchunk-only) metadata — defaulting the checksum type to `sha256` when blank. `<revision>` is set to the current Unix time.
3. **Optionally re-signs** the regenerated `repomd.xml`.

!!! note "The high side re-signs with its own key"
    ArtiGate never trusts the transferred upstream `repomd.xml.asc` as final; the low side used it only to verify at collect time. The high side owns the repository entry point and signs it with its **own** GPG key.

Signing is controlled by one high-side flag:

| Flag | Effect |
|---|---|
| `--rpm-gpg-key <key-id>` | GPG key id used to sign regenerated RPM repositories. Produces `repodata/repomd.xml.asc`. |
| *(unset)* | Repositories are served **unsigned**; any stale `repomd.xml.asc` is removed. |

When set, the high side runs:

```bash
gpg --batch --yes --armor --local-user <key-id> \
    --detach-sign --output repodata/repomd.xml.asc repodata/repomd.xml
```

The key must exist in the high side's GPG keyring. See [Security & trust](../security.md) for the full sign-on-low, verify-and-regenerate-on-high model.

## High-side serving

The repository is served read-only under the `/rpm` prefix. Only `GET` and `HEAD` are accepted; anything else is `405`. Paths are validated against traversal and joined under `<root>/rpm/`.

A mirror named `epel9` therefore exposes:

| URL | Content |
|---|---|
| `/rpm/epel9/repodata/repomd.xml` | regenerated index entry point |
| `/rpm/epel9/repodata/repomd.xml.asc` | detached signature (only when `--rpm-gpg-key` is set) |
| `/rpm/epel9/repodata/<metadata>` | mirrored primary/filelists/other/… files |
| `/rpm/epel9/Packages/f/foo.rpm` | a package at its upstream `<location>` |

## Client `.repo` config

Point dnf/yum at the high side and configure it as the **sole** repository with no public fallback — that is what closes the dependency-confusion gap the diode exists to eliminate (see [Security & trust](../security.md)).

**Signed repo** (high side started with `--rpm-gpg-key`), written to `/etc/yum.repos.d/artigate-<name>.repo`:

```ini
[artigate-epel9]
name=ArtiGate epel9
baseurl=https://high:8080/rpm/epel9
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-artigate
```

**Unsigned repo** (no signing key configured on the high side):

```ini
[artigate-epel9]
name=ArtiGate epel9
baseurl=https://high:8080/rpm/epel9
enabled=1
gpgcheck=0
repo_gpgcheck=0
```

| Key | Meaning |
|---|---|
| `gpgcheck` | Per-**package** signature check. |
| `repo_gpgcheck` | Verifies `repomd.xml` against ArtiGate's high-side key. |
| `gpgkey` | Path to ArtiGate's high-side public key. |

!!! note "You must distribute the high-side public key"
    The signed config references `/etc/pki/rpm-gpg/RPM-GPG-KEY-artigate`, but ArtiGate does **not** install that key on clients. Export the public half of the key you passed to `--rpm-gpg-key` and place it at that path (or wherever your `gpgkey=` points). If you serve the repo unsigned instead, both `gpgcheck` and `repo_gpgcheck` are off — sign it with `--rpm-gpg-key` to turn signature checks back on.

## Example

Mirror the newest packages of a concrete vendor repo, then serve it signed.

Low side — trigger a collect from a `.repo` file:

```bash
curl -fsS -X POST http://low:8080/admin/rpm/collect \
  -H 'Content-Type: application/json' \
  -d '{
        "repo_file": "[packages-microsoft]\nname=Microsoft RHEL9\nbaseurl=https://packages.microsoft.com/rhel/9.0/prod/\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/MICROSOFT-GPG-KEY\n",
        "newest_only": true
      }'
```

Or with the explicit fields and no local verification key:

```bash
curl -fsS -X POST http://low:8080/admin/rpm/collect \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "packages-microsoft",
        "base_url": "https://packages.microsoft.com/rhel/9.0/prod/",
        "newest_only": true
      }'
```

High side — start it with a signing key so `repomd.xml` is re-signed on import:

```bash
artigate high \
  --public-key /etc/artigate/high.ed25519.pub \
  --rpm-gpg-key artigate-repo-signing
```

Client — after the bundle crosses the diode and is imported, on an air-gapped host:

```bash
cat >/etc/yum.repos.d/artigate-packages-microsoft.repo <<'EOF'
[artigate-packages-microsoft]
name=ArtiGate packages-microsoft
baseurl=https://high:8080/rpm/packages-microsoft
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-artigate
EOF

dnf --disablerepo='*' --enablerepo='artigate-packages-microsoft' makecache
```

## Limitations

- **The primary index must be `.gz`, `.xz`, or uncompressed.** ArtiGate must parse it to enumerate packages; a primary offered **only as `.zck` (zchunk)** cannot be parsed and the collect fails with `zchunk (.zck) index cannot be parsed`. Metadata files ArtiGate never parses (it only stores and re-serves them) may still be `.zck`.
- **Newest-only cannot rewrite a `.zck` primary.** If newest-only would drop packages but the primary is zchunk-only, disable newest-only for that repo.
- **Each collect is a full re-sync.** There is no incremental fetch — every collect re-fetches the current `repomd.xml` and re-mirrors everything it points at into a new sequenced bundle. Content-level dedup means an unchanged repository writes no new bundle and burns no sequence.
- **`baseurl` variables are not expanded.** Any `$releasever`/`$basearch` (any `$`) is rejected; pin concrete URLs.
- **Remote `gpgkey=https://…` is not used for verification.** Only `file://`/absolute local keyrings are honoured on the low side.
- **External binaries.** `xz` must be installed on the **low** side for `.xz` metadata (parsing the primary index and recompressing it for newest-only) — the high side never decompresses or re-hashes RPM metadata, so it needs no `xz`; `gpgv` on the low side for repomd verification; `gpg` on the high side for signing. Each download has a 10-minute timeout and a 4 GiB response cap.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring re-syncs
- [Security & trust](../security.md) — the sign / verify / regenerate model
- [HTTP API reference](../api.md) — the exact request/response contracts
- [Configuration reference](../configuration.md) — every flag and environment variable
