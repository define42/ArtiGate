# Java (Maven)

ArtiGate mirrors Java artifacts by delegating to a real Maven install on the low side — `mvn dependency:go-offline` resolves a project's full dependency **and plugin** closure into an isolated local repository, which is packed verbatim into a signed bundle. The high side then serves those files as a static Maven 2 repository under `/maven/`, generating `maven-metadata.xml` on the fly.

Because the resolved local repository is already in Maven 2 layout, ArtiGate maps it directly onto the paths the high side serves — no repacking, no rewriting.

!!! note "Release versions only"
    ArtiGate mirrors **reproducible** artifacts. `SNAPSHOT` builds change over time, and dynamic/range versions (`LATEST`, `RELEASE`, `1.+`, `[1.0,2.0)`) resolve to different concrete versions over time — none of them can back a reproducible air-gapped mirror, so they are rejected. See [Version policy](#version-policy).

## Data flow

| Side | Role | Mechanism |
|---|---|---|
| **Low** | collect-only | Runs `mvn -B dependency:go-offline -Dmaven.repo.local=…`, walks the resolved repo, packs it into a numbered, Ed25519-signed bundle on the `maven` stream |
| **High** | serve-only | Serves stored `.pom`/`.jar`/`.module` files (and their checksums) directly; computes `maven-metadata.xml` from the versions physically present |

The low side never serves artifacts and the high side never invokes `mvn` or reaches upstream — the two halves only ever exchange signed bundles across the diode. See [Architecture](../architecture.md).

## Low side: collecting

### Inputs

The Java tab of the [low-side dashboard](../low-side.md) accepts either:

- **Coordinates** — a textarea (`#mvncoords`), one `groupId:artifactId:version` per line. `#`-prefixed lines and trailing ` # comment` text are stripped client-side.
- **A `pom.xml` upload** — if a pom file is selected it is sent instead, and the coordinate list is ignored.

Both map to the same HTTP endpoint.

### HTTP endpoint

```text
POST /admin/maven/collect            (buffered JSON result)
POST /admin/maven/collect?stream=1   (live NDJSON progress)
```

The request body is JSON (`MavenCollectRequest`), capped at **8 MiB**:

```json
{
  "coordinates": ["org.slf4j:slf4j-api:2.0.16", "com.google.guava:guava:33.2.1-jre"],
  "pom_xml": "<project>…</project>"
}
```

| Field | Type | Meaning |
|---|---|---|
| `coordinates` | `[]string` | One `groupId:artifactId:version` per entry |
| `pom_xml` | `string` | A complete `pom.xml` to resolve as-is |
| `force` | bool | Bypass the export-dedup index — pack every artifact even if already forwarded (full, self-contained bundle) |

!!! warning "`pom_xml` wins; `coordinates` is ignored when it is set"
    If `pom_xml` is non-empty (after trimming whitespace), `coordinates` is ignored **entirely**. Provide one or the other. If neither is supplied the collect fails with `no maven coordinates or pom_xml provided`.

Drive it directly with `curl`:

```bash
curl -X POST http://localhost:8080/admin/maven/collect \
  -H 'Content-Type: application/json' \
  -d '{"coordinates":["org.slf4j:slf4j-api:2.0.16"]}'
```

### Coordinate format

Each coordinate is exactly three colon-separated tokens — `groupId:artifactId:version`. Every token is trimmed and must match `^[A-Za-z0-9._-]+$`; anything else is rejected before Maven runs.

For a coordinate list, ArtiGate builds a small synthetic project and lets Maven resolve its dependency closure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>local.artigate</groupId>
  <artifactId>artigate-collect</artifactId>
  <version>0.0.0</version>
  <packaging>pom</packaging>
  <dependencies>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.16</version></dependency>
  </dependencies>
</project>
```

### Version policy

The release-only policy is enforced on every coordinate before resolution:

| Version input | Result |
|---|---|
| empty | rejected — `empty version` |
| contains `SNAPSHOT` | rejected — not reproducible |
| exactly `LATEST` or `RELEASE` | rejected — `pin an exact version` |
| contains any of `[ ] ( ) , + *` (ranges like `[1.0,2.0)`, `1.+`) | rejected — `pin an exact version` |
| not matching `^[A-Za-z0-9._-]+$` | rejected — `invalid version` |
| e.g. `2.0.16`, `33.2.1-jre` | accepted |

!!! warning "An uploaded `pom.xml` bypasses input validation"
    Coordinate-level validation only runs on the `coordinates` path. An uploaded `pom_xml` is passed to Maven **verbatim** — it is not scanned for `SNAPSHOT` or range versions at input time. The only backstop on that path is a post-resolution check that rejects any resolved artifact whose version contains `SNAPSHOT`. A range in an uploaded pom that resolves to a concrete release will pass. Pin exact release versions in poms you upload.

### Resolution internals

`CollectMaven` performs a lock-protected resolve → pack → commit:

1. **Lock the `maven` stream.** The per-stream mutex is held for the whole operation so a concurrent Maven exporter cannot claim the same sequence number; other streams (Go, Python, …) export in parallel. See [Low side](../low-side.md).
2. **Stage.** A temp dir is created under `<root>/maven/staging/collect-*` and the `pom.xml` is written into it. The local repository lives at `<stageRoot>/maven` so its Maven 2 layout maps directly onto the `maven/…` paths the high side serves.
3. **Resolve.** ArtiGate runs, in batch mode with an isolated local repo:
   ```bash
   mvn -B -f <stageRoot>/pom.xml dependency:go-offline -Dmaven.repo.local=<stageRoot>/maven
   ```
   `dependency:go-offline` pulls the full transitive dependency and plugin closure. The invocation has a **15-minute** timeout; on failure the last 4096 bytes of `mvn` output are returned as diagnostics.
4. **Walk & filter.** The resolved repo is walked; each artifact file becomes a manifest entry. If nothing resolved, the collect errors with `maven resolution produced no artifacts` rather than emit an empty bundle.
5. **Reject SNAPSHOTs.** Any resolved artifact whose version contains `SNAPSHOT` aborts the collect.
6. **Dedup & export.** If every resolved file was already exported on the `maven` stream, the collect is skipped (no sequence consumed). If only some are new, the signed bundle is a [delta](../architecture.md#export-deduplication-and-delta-bundles): its archive carries the new files and the rest ride as `prior` manifest references. `"force": true` bypasses the index for a full bundle.

### The `mvn` binary

The low side delegates fetching to the `mvn` already installed on the host, run with the host's Maven settings, credentials, and network access — so its upstream repositories are whatever that host's Maven is configured to use.

| Setting | Default | Meaning |
|---|---|---|
| `--maven` flag / `MavenBinary` | `mvn` | Maven command used to resolve artifacts |

See the [configuration reference](../configuration.md) for all low-side flags.

### What gets bundled

The walk derives each artifact's coordinate from its Maven 2 layout position (`…/group/parts/artifactId/version/file`), skipping Maven's internal bookkeeping. These files are **never** bundled:

| Skipped | Why |
|---|---|
| names starting with `_` (e.g. `_remote.repositories`) | resolver bookkeeping |
| `maven-metadata*` | per-remote metadata — regenerated on the high side |
| `resolver-status.properties` | resolver bookkeeping |
| `*.lastUpdated` | resolver bookkeeping |
| `*.part`, `*.tmp` | partial downloads |

Everything else — `.pom`, `.jar`, `.module`, `-sources.jar`, and their legacy `.sha1`/`.md5` checksums — is packed. The bundle's `maven` sub-manifest records one entry per coordinate:

```json
{
  "artifacts": [
    {
      "group_id": "org.slf4j",
      "artifact_id": "slf4j-api",
      "version": "2.0.16",
      "files": ["maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar",
                "maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.pom"]
    }
  ]
}
```

On import, the high side rejects any bundle whose artifacts lack a coordinate, list no files, or reference a file that is not in the manifest's overall file set. The real integrity control is the Ed25519 signature over the manifest (which hashes every file); the `.sha1`/`.md5` files are legacy Maven checksums, not a security control — see [Security &amp; trust](../security.md).

## High side: serving a Maven 2 repository

The high side exposes the mirrored files as a static Maven 2 repository rooted at `<root>/cache/download/maven`, served under `/maven/`.

### Routing

- Only `GET` and `HEAD` are allowed; other methods return `405 method not allowed`.
- Bare `/maven` (no file) returns `404`. Paths that fail relative-path or safe-join validation return `404` / `400 unsafe path`.
- **`maven-metadata.xml`** (and its `.sha1`/`.md5`) is **computed on the fly** — never served from disk. Every other path (`.pom`, `.jar`, `.module`, checksums, …) is served directly from `<root>/cache/download/maven/<path>`.

```http
GET /maven/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar   → stored file
GET /maven/org/slf4j/slf4j-api/maven-metadata.xml            → generated
```

### Generated `maven-metadata.xml`

For a metadata request, ArtiGate scans the requested artifact directory and lists every version subdirectory that **contains a `.pom`** (jar-only directories are invisible). A directory with no such versions returns `404`. The rendered document:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.slf4j</groupId>
  <artifactId>slf4j-api</artifactId>
  <versioning>
    <latest>2.0.16</latest>
    <release>2.0.16</release>
    <versions>
      <version>2.0.9</version>
      <version>2.0.16</version>
    </versions>
    <lastUpdated>20260705120000</lastUpdated>
  </versioning>
</metadata>
```

- `<latest>` and `<release>` are the same value — the highest version present.
- `<lastUpdated>` uses the newest `.pom` mod-time in UTC (`YYYYMMDDHHMMSS`); it is omitted when unknown.
- The `.sha1`/`.md5` variants are the checksums of the **generated** XML bytes, not of any stored file.

!!! note "Version ordering is best-effort"
    Versions are ordered by a best-effort comparison (dot/dash-separated tokens compared numerically when both are numbers, otherwise lexically). This only drives the `latest`/`release` hints — it is not a full Maven version-spec implementation. Because clients pin exact versions, ordering imprecision is cosmetic.

### High-side dashboard

The [high-side dashboard](../high-side.md) lists mirrored artifacts as `group/artifact` paths (e.g. `org/slf4j/slf4j-api`) with the versions present. The detail panel for a version shows the `groupId:artifactId:version` coordinate, its repo path (`/maven/<artifactPath>/<version>/`), each primary file with its size (checksums omitted), and the `.jar`'s SHA-256 when present.

## Client configuration

Point Maven at the high side as a **mirror of everything** via `~/.m2/settings.xml`:

```xml
<!-- ~/.m2/settings.xml -->
<settings>
  <mirrors>
    <mirror>
      <id>artigate</id>
      <mirrorOf>*</mirrorOf>
      <url>https://artigate-high.local/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

- `mirrorOf=*` routes **all** repositories through ArtiGate.
- The trailing slash on `.../maven/` matters.

!!! warning "Don't reopen egress"
    On the high side, use ArtiGate as the **only** source. Leaving `mavenCentral()` (Gradle) or extra `<repository>` upstreams configured reopens dependency-confusion / egress risk. The high side is unauthenticated by design — it serves only already-verified public mirror content, so bind it to localhost or a trusted network. See [Security &amp; trust](../security.md); for HTTPS see [TLS / HTTPS](../tls.md).

## Scheduling

Any Maven collect can be turned into a recurring **watch** so an unchanged upstream produces no new bundles (thanks to export dedup) while new releases flow across automatically. See [Scheduling (watches)](../scheduling.md).

## Limitations

- **Release, exact versions only.** `SNAPSHOT`, `LATEST`, `RELEASE`, `1.+`, and `[1.0,2.0)` are rejected on the coordinate path.
- **Uploaded `pom.xml` is trusted verbatim** — not scanned for `SNAPSHOT`/range at input; only what actually resolves is re-checked (for `SNAPSHOT` only).
- **`coordinates` is silently ignored** whenever `pom_xml` is set.
- **`maven-metadata.xml` is always regenerated** from present `.pom` files; transferred metadata is never bundled or served. A version directory counts only if it holds a `.pom`.
- **Best-effort version ordering** — cosmetic only.
- **15-minute** Maven timeout; **8 MiB** request-body cap.
- **The high-side `/maven/` endpoint is unauthenticated by design.**
- Needs a working `mvn` on the low-side host (configurable via `--maven`); resolution reaches whatever upstream repositories that host's Maven is configured for.

See [Troubleshooting &amp; limitations](../troubleshooting.md) for the consolidated list, and the [Ecosystems overview](index.md) for the other seven.
