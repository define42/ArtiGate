# Backup, checkpoints, and archive retention

ArtiGate provides offline recovery commands for both roles and signed checkpoints
for initializing a receiver without replaying its entire history. These commands
currently require Linux for atomic directory publication.

| Operation | Purpose |
| --- | --- |
| `backup create` / `verify` / `restore` | Preserve and restore a consistent local high-side or low-side data directory. |
| `checkpoint create` / `verify` / `restore` | Reconstruct exported receiver state from signed history and initialize a new high-side root. |
| `retention plan` / `apply` | Verify recovery paths, preview removable archived bundles, and apply that exact plan. |

Stop the relevant server before creating a backup or checkpoint, or planning and
applying retention. Updated low/high processes hold `.artigate.lock` in their
storage root; recovery commands refuse to operate while that lock is held. Stop
older binaries too: they do not participate in this lock. Restoration always
requires a **nonexistent destination directory** and never replaces a running
mirror. Run recovery as the service account that will own the restored files.
Use real directories without symlinked ancestors; the destination's parent must
already exist. All commands accept `--help`.

## Consistent local backups

Create a backup outside the storage root:

```bash
artigate backup create --role high \
  --root /var/lib/artigate-high \
  --output /backups/high-2026-10-01
```

The JSON result includes `manifest_sha256`, the SHA-256 of the backup manifest.
Record that digest separately in trusted backup storage. Local backups are
unsigned; their authenticity depends on that independently trusted digest.

```bash
artigate backup verify \
  --input /backups/high-2026-10-01 --digest <manifest-sha256>

artigate backup restore \
  --input /backups/high-2026-10-01 --digest <manifest-sha256> \
  --root /var/lib/artigate-high-restored
```

After successful restoration, configure the service to use the new root and its
usual trusted public key, landing directory, and repository-signing settings.
Replay every subsequent sequence from retained low-side archives. Keep the old
root until the restored instance has passed your acceptance checks.

### Included data

- **High side:** `cache/download`, `import-state.json`, and `python-index.json`
  when present. This preserves installed artifacts, ecosystem metadata, and
  receiver-local upload deletions at the same recovery point.
- **Low side:** `bundles`, `low-state.json`, `exported.db`, `watches.db` when
  present, container discovery state, and recovery ledgers/journals. SQLite WAL
  and rollback-journal files are included when present; shared-memory files are
  excluded. The server must remain stopped throughout the copy.

Runtime configuration, signing keys, upstream credentials, TLS files, and external
landing/export/SFTP directories are managed separately. Back up secrets in
appropriate protected storage. A checkpoint sent across the diode never contains
the low-side private key. Low-side collector caches and temporary directories are
not backup inputs; retained signed history supplies exported artifact bytes.

### Restoring a low-side backup

Use `--role low` when creating the backup. A low-side restore additionally requires
`--confirm-low-state-current`:

```bash
artigate backup restore \
  --input /backups/low-2026-10-01 --digest <manifest-sha256> \
  --root /var/lib/artigate-low-restored --confirm-low-state-current
```

This flag asserts that no later exports exist outside the backup. Restoring an
older exporter state can reuse a sequence already observed by receivers. If later
exports exist, recover their original archives and reconcile sequence, deduplication,
and recovery records before resuming the exporter. Never run the original and
restored low sides concurrently with the same signing key and stream history.
Unsent archives can be staged again through the existing re-export operation.
Finish any interrupted retention operation before creating a low-side backup.

## Signed bootstrap checkpoints

With the low side stopped:

```bash
artigate checkpoint create \
  --root /var/lib/artigate-low \
  --private-key /etc/artigate/low.ed25519 \
  --output /backups/checkpoint-2026-10-01
```

Creation reconstructs an isolated high-side repository through the normal bundle
signature, content, sequence, and publication checks. It copies installed bytes
and persistent ecosystem metadata, including mutable snapshots, tag mappings,
and verified content awaiting a later metadata bundle. It does not fetch upstream
content. The completed artifact must pass a restore drill before creation reports
success. Allow disk space for the reconstructed repository, packaged checkpoint,
and temporary verification copies.

The checkpoint records an independent position for every included stream. A
checkpoint through Go sequence 12000 resumes normal Go import at 12001; npm and
the other streams retain their own positions. Checkpoints use a distinct format
and signature context and are not ordinary sequence-numbered bundles.

Transfer the **complete checkpoint directory** through your file carrier. The
directory includes the manifest, signature, and all payload parts. The ordinary
HTTP/SFTP/UDP bundle senders do not automatically transfer checkpoint directories.

On the high side:

```bash
artigate checkpoint verify \
  --input /landing/checkpoint-2026-10-01 \
  --public-key /etc/artigate/high.ed25519.pub

artigate checkpoint restore \
  --input /landing/checkpoint-2026-10-01 \
  --public-key /etc/artigate/high.ed25519.pub \
  --digest <manifest-sha256> \
  --root /var/lib/artigate-high-restored
```

Restore requires the trusted manifest digest printed at creation as well as the
public key. The signature establishes who signed the checkpoint; the separately
selected digest identifies the intended recovery point. A valid signature alone
cannot establish freshness on a machine with no previous state.

### Local repository signatures

Checkpoints reconstructed on the low side contain unsigned APT, RPM, and Alpine
repository indexes. If your clients require local repository signatures, pass
the receiver's signing settings to `checkpoint restore`:

```bash
artigate checkpoint restore \
  --input /landing/checkpoint-2026-10-01 \
  --public-key /etc/artigate/high.ed25519.pub --digest <manifest-sha256> \
  --root /var/lib/artigate-high-restored \
  --apt-gpg-key <apt-key-id> --rpm-gpg-key <rpm-key-id> \
  --apk-rsa-key /etc/artigate/apk.rsa --apk-key-name artigate.rsa.pub
```

Supply only the settings used by your deployment, and keep the same settings
when starting the high side. The restore signs APT/RPM metadata and rebuilds
signed Alpine indexes locally before publishing the new root. A signing failure
leaves the destination absent. These private keys remain on the receiver.
Local high-side backups already preserve existing repository signatures.

### Checkpoint trust and subsequent checkpoints

Checkpoints are administrative snapshots. Their repository metadata is derived
by the normal importer during creation and preserved exactly during restoration.
Only accept checkpoints produced and reviewed through your trusted recovery
process. Restore is separate from the ordinary bundle importer and does not
provide an automatic way for incoming bundles to skip sequence checks.

After pruning old archives, create the next checkpoint from a retained base:

```bash
artigate checkpoint create \
  --root /var/lib/artigate-low \
  --private-key /etc/artigate/low.ed25519 \
  --base /backups/checkpoint-2026-10-01 --base-digest <base-manifest-sha256> \
  --output /backups/checkpoint-next
```

Every subsequent bundle must be available and verifiable under the configured
key. The current format does not introduce a key-rotation protocol. A checkpoint
reconstructed on the low side represents exported history; use a local high-side
backup to preserve receiver-local changes such as upload deletions.

Use a separate signing key for each independent low-side history. The bundle and
checkpoint formats do not bind sequences to a source UUID or a chain of previous
manifest hashes. Reusing one key for unrelated exporters can make their recovery
points indistinguishable at the same sequence positions.

## Preview archive retention

List every checkpoint that must remain recoverable, the actual export spool,
and the oldest confirmed receiver position for each stream:

```bash
artigate retention plan \
  --root /var/lib/artigate-low --export-dir /var/spool/diode-out \
  --public-key /etc/artigate/high.ed25519.pub \
  --checkpoint /backups/checkpoint-2026-10-01 \
  --receiver-floor go=12000 --receiver-floor npm=3400 \
  --output /backups/retention-plan.json
```

The JSON plan lists per-stream cutoffs, blocked streams, candidate files, input
fingerprints, and estimated reclaimable bytes (the sum of candidate file sizes).
Filesystem compression and hard links can reduce actual space recovered.
Save the plan outside the low root, export spool, and checkpoint directories.
Planning restores each supplied checkpoint
and replays its tail through the current tip. Missing, changed, unverifiable, or
incomplete recovery inputs stop the operation.

For each stream, the cutoff is limited by the oldest retained checkpoint and the
oldest supported receiver. For example, checkpoints at 100 and 200 require bundles
101 onward to remain available when both are promised as replayable recovery
points. Outstanding spool bundles and unfinished metadata also protect history.

Unknown receiver progress retains history. `--allow-bootstrap` explicitly accepts
checkpoint recovery for receivers whose progress is unknown; it does not confirm
delivery. Receivers behind the retained history must then restore a checkpoint.
If receiver floors are provided alongside this flag, those floors still constrain
deletion. ArtiGate never infers receiver import from transport success, an empty
spool, a heartbeat, or the export deduplication database.

Keep independently protected copies of your retained checkpoints and keys.
The planner verifies the supplied files; it cannot establish that a second disk
or backup system will survive loss of the low-side host.

## Apply and resume

Review the plan, then apply it with the low side still stopped:

```bash
artigate retention apply \
  --plan /backups/retention-plan.json \
  --public-key /etc/artigate/high.ed25519.pub
```

Apply revalidates the inputs and recovery paths. A changed archive, spool,
checkpoint, or state requires a new plan. Deletion is limited to the archived
bundle files named by the plan. Installed artifacts and the export deduplication
database are retained.

Before deletion, ArtiGate persists the plan journal and an independent sequence
ledger. Those records prevent pruned sequence numbers from becoming reusable.
If application stops midway, rerun the same `retention apply` command. An
unfinished journal prevents the low side from starting until application is
resumed. Preserve `recovery-ledger.json` and `recovery-retention` with the matching
low-side state; do not remove them to bypass a recovery error.

Retention is explicitly invoked; it is not a background timer or an automatic
response to low disk space.
