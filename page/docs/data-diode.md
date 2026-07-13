# Built-in UDP data diode

ArtiGate can drive a **hardware data diode directly**: a one-way fiber between
a spare NIC on the low side and a spare NIC on the high side, with no diode
proxy software in between. The low side's sender is the **pitcher**, the high
side's receiver is the **catcher**. Both are enabled by naming the dedicated
interface in one environment variable — ArtiGate configures the NIC itself.

```
[ low ] ──▶ eth1 ═══ one-way fiber ═══▶ eth1 ──▶ [ high ]
 pitcher      MTU 9000, EUI-64             MTU 9000, EUI-64      catcher
              rate-limited multicast       FEC reassembly → landing dir
```

The transport carries **zero trust**, exactly like the folder and HTTP
transports: only strictly valid bundle file names can land, and the importer
still verifies the Ed25519 manifest signature, per-stream sequencing, and
every file hash. The wire's own CRC-32 (per datagram) and SHA-256 (per file)
only keep transport damage out of the landing directory.

## Why the wire looks the way it does

A one-way link removes everything networking normally leans on, and each
removal forces a design choice:

- **No replies → no neighbor discovery.** The pitcher can never learn the
  catcher's MAC address (NDP needs an answer), so datagrams go to an **IPv6
  link-local multicast group** (default `ff02::4147`), which maps directly to
  an Ethernet group MAC. The catcher joins the same group on its NIC. Both
  interfaces get their IPv6 link-local address derived from the MAC
  (`addr-gen-mode eui64`, as in NetworkManager's `ipv6.addr-gen-mode=eui64`) —
  deterministic, no DHCP, no router.
- **No retransmissions → forward error correction.** Every file is cut into
  blocks of `FEC_DATA × shard` bytes; each block is Reed-Solomon-encoded into
  `FEC_DATA + FEC_PARITY` equal shards, one shard per UDP datagram. **Any**
  `FEC_DATA` of them rebuild the block, so with the default 32+8 any 8 of
  every 40 datagrams may be lost harmlessly. Every datagram also carries the
  file's full metadata (name, size, SHA-256) plus a CRC-32, so the catcher can
  start from any packet and discard corruption before it poisons a block.
- **No congestion control → a hard send-rate ceiling.**
  `ARTIGATE_PITCHER_RATE_MBIT` (default 800) paces the pitcher to a wire rate
  — IP/UDP/Ethernet framing included — that the catcher host must be
  provisioned to absorb. Loss on a clean fiber comes from overrunning the
  receiver, not from the glass; the rate limit is the knob that prevents it.
- **Jumbo frames.** Both NICs run MTU 9000 by default, so each datagram
  carries ~8.7 KB of payload. Shards are sized to the MTU and never fragment.

When a file's last block completes, the catcher verifies the SHA-256,
atomically renames the file into the landing directory, and — once the
bundle's three files are all present — triggers an import immediately, the
same hand-off the HTTP ingest endpoint does.

## Configuration reference

Setting the `*_INTERFACE` variable is what enables each side; everything else
has defaults. `ARTIGATE_DIODE_URL` (the HTTP transport) and the pitcher are
mutually exclusive.

### Low side (pitcher)

| Variable | Default | Meaning |
|---|---|---|
| `ARTIGATE_PITCHER_INTERFACE` | unset (disabled) | Dedicated diode TX NIC, e.g. `eth1` |
| `ARTIGATE_PITCHER_RATE_MBIT` | `800` | Max wire rate in Mbit/s (framing included) — keep at or below what the catcher absorbs |
| `ARTIGATE_PITCHER_MTU` | `9000` | Interface MTU; shards are sized to it |
| `ARTIGATE_PITCHER_TXQUEUELEN` | `10000` | Interface TX queue length |
| `ARTIGATE_PITCHER_GROUP` | `ff02::4147` | IPv6 multicast group (must match the catcher) |
| `ARTIGATE_PITCHER_PORT` | `4147` | UDP port (must match the catcher) |
| `ARTIGATE_PITCHER_FEC_DATA` | `32` | Data shards per block |
| `ARTIGATE_PITCHER_FEC_PARITY` | `8` | Parity shards per block — the per-block loss budget |
| `ARTIGATE_PITCHER_NETSETUP` | `on` | `on`: ArtiGate configures the NIC (link bounce, eui64, MTU, txqueuelen, TX rings, link up, waits for DAD). `off`: the host pre-configured it |

### High side (catcher)

| Variable | Default | Meaning |
|---|---|---|
| `ARTIGATE_CATCHER_INTERFACE` | unset (disabled) | Dedicated diode RX NIC, e.g. `eth1` |
| `ARTIGATE_CATCHER_RCVBUF_MB` | `64` | UDP receive buffer in MiB (set with `SO_RCVBUFFORCE`, so no `rmem_max` tuning needed) — rides out import/disk stalls |
| `ARTIGATE_CATCHER_MTU` | `9000` | Interface MTU; must be ≥ the pitcher's |
| `ARTIGATE_CATCHER_GROUP` | `ff02::4147` | IPv6 multicast group |
| `ARTIGATE_CATCHER_PORT` | `4147` | UDP port |
| `ARTIGATE_CATCHER_NETSETUP` | `on` | `on`: ArtiGate configures the NIC (eui64, MTU, RX rings at hardware max, link up) and best-effort raises `net.core.netdev_max_backlog`. `off`: the host pre-configured it |

## Docker: host networking and permissions

Both containers need to own a real host NIC and to configure it, so — unlike
the demo stack — the diode deployments run with:

```yaml
network_mode: host      # the diode NIC is a real host interface
user: "0:0"             # Docker grants added capabilities to root only
cap_add: [NET_ADMIN]    # NIC setup (ioctl/rtnetlink) + SO_SNDBUFFORCE/SO_RCVBUFFORCE
```

Ready-made per-host files: [`examples/docker-compose-diode-low.yml`](https://github.com/define42/ArtiGate/blob/main/examples/docker-compose-diode-low.yml)
and [`examples/docker-compose-diode-high.yml`](https://github.com/define42/ArtiGate/blob/main/examples/docker-compose-diode-high.yml).
With host networking `ports:` mappings do not apply — each dashboard binds
host port 8080 directly.

!!! note "Running without root"
    Set `ARTIGATE_{PITCHER,CATCHER}_NETSETUP=off` and configure the NIC on the
    host (MTU, txqueuelen, `ip link set dev eth1 addrgenmode eui64`, link up).
    ArtiGate then only opens sockets; without `NET_ADMIN` the forced socket
    buffers fall back to the `wmem_max`/`rmem_max` ceilings — raise those on
    the host for line-rate transfers. `net.core.netdev_max_backlog` is only
    writable from inside a container with `privileged: true`; setting it on
    the host is equally good.

## Loss, recovery, and monitoring

FEC absorbs random loss up to `FEC_PARITY` datagrams per block. When a
transfer still can't complete (a pulled fiber, loss beyond the budget), the
catcher abandons it after 90 seconds of silence and logs it — nothing partial
ever reaches the landing directory. Recovery is the standard ArtiGate story,
because a one-way link cannot ask for retransmission:

1. the high side's **Status page / `GET /admin/missing`** shows the gap,
2. the low side's **Status page / `POST /admin/reexport`** re-transmits those
   sequences from the bundle archive — over the diode again.

The re-send does not start from zero: the catcher keeps an abandoned
transfer's completed FEC blocks beside the landing directory for 24 hours
(they count against the unverified-storage quota), and a re-sent file with
the same name and content hash resumes from them, so each attempt only has
to deliver the blocks every earlier attempt lost. Under loss beyond the
parity budget the catcher also evicts stuck half-received blocks instead of
stalling, so one pass completes every block the link let through. Together
these make a multi-gigabyte model bundle converge in a couple of re-sends on
a lossy link, instead of demanding one perfect pass.

The catcher logs one summary line whenever something happened: datagrams and
bytes received, drops, **blocks repaired** (parity actually used), files
landed / expired / failed / resumed, and **blocks evicted** (loss beyond the
parity budget). A steadily climbing repair count means the link or
the rate limit needs attention *before* transfers start failing.

The receiver also applies hard resource ceilings before content authentication:
the same 64 GiB / 16 MiB / 4 KiB suffix limits as HTTP ingest, at most 16 active
transfers and 32 open blocks per transfer, 64 MiB reserved reconstruction memory
per transfer and 256 MiB globally, four million blocks per file, 4,096 remembered
completed transfer IDs, and 64 cached Reed-Solomon encoder geometries. A block
reserves its full data-plus-parity footprint before the first shard is retained.
The block-count ceiling also bounds one transfer's size for a given geometry
(`FEC_DATA` × shard size × 2²²); the low side folds that bound into its bundle
split budget, so a small geometry never produces a bundle the pitcher would
then refuse to send.

The pitcher clears each bundle from the export dir after the send finishes
(it shows as *sent* on the Status page) and keeps the archive copy for
re-transmits — identical bookkeeping to the HTTP transport, including the
collect result carrying a `diode_error` when a send fails.

!!! warning "Simplex fiber and link state"
    On a simplex rig the pitcher's RX strand sees no light, so many NICs
    report *no carrier* and IPv6 DAD cannot finish — ArtiGate waits briefly,
    explains, and retries sends rather than dying. The usual hardware fixes:
    loop the TX split back into the pitcher's RX, or force link-up in the NIC
    firmware. The catcher side receives light and needs nothing special.

## Sizing the FEC and the rate

- **Throughput cost of parity** is `FEC_PARITY / FEC_DATA` (25% at 32+8). A
  clean, correctly rate-limited fiber sees essentially zero loss — 32+8 is
  deliberately conservative; 32+4 (12.5%) is reasonable once the repair
  counter stays at zero across real transfers.
- **Burst tolerance**: loss tends to arrive in bursts (a receive queue
  overflowing). A block is 40 consecutive datagrams (~350 KB on the wire at
  MTU 9000); a burst longer than 8 datagrams (~70 KB) inside one block kills
  that transfer. Bigger receive buffers and a lower rate both stretch the
  burst the catcher can ride out.
- **Rate**: start at the default 800 Mbit/s on 10G hardware (or ~80% of a
  1G link's capacity), watch the catcher's repair/expiry counters, and raise
  it while they stay clean.
