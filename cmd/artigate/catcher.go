package main

// The catcher: the high side of the built-in UDP data diode. It joins the
// pitcher's multicast group on a dedicated receive-only NIC, reassembles the
// FEC-coded datagrams (diodewire.go) into bundle files, and drops them into
// the landing directory — from there the normal verify-and-import pipeline
// takes over, exactly as if a folder diode had delivered them. Configured
// entirely through environment variables:
//
//	ARTIGATE_CATCHER_INTERFACE  dedicated diode NIC (e.g. eth1); setting it
//	                            enables the catcher
//	ARTIGATE_CATCHER_MTU        interface MTU, default 9000 — must be at
//	                            least the pitcher's
//	ARTIGATE_CATCHER_GROUP      IPv6 multicast group, default ff02::4147
//	ARTIGATE_CATCHER_PORT       UDP port, default 4147
//	ARTIGATE_CATCHER_RCVBUF_MB  UDP receive buffer in MiB, default 64 — the
//	                            queue that rides out import/disk stalls; set
//	                            via SO_RCVBUFFORCE so no rmem_max tuning is
//	                            needed (CAP_NET_ADMIN)
//	ARTIGATE_CATCHER_NETSETUP   on (default) lets ArtiGate configure the
//	                            interface itself (MTU, RX rings, EUI-64
//	                            link-local, link up; needs CAP_NET_ADMIN);
//	                            off expects a pre-configured interface
//
// The wire carries zero trust, like every other diode transport: only
// strictly valid bundle file names can land, and the importer still verifies
// the Ed25519 signature, per-stream sequencing, and every file hash.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	diodeDefaultRcvBufMB = 64

	// diodeSweepEvery is how often the catcher expires stale transfers and
	// logs its counters, with or without traffic.
	diodeSweepEvery = 15 * time.Second

	// diodeNetdevBacklog is the net.core.netdev_max_backlog the catcher asks
	// for (default 1000 is sized for interactive hosts, not line-rate UDP).
	diodeNetdevBacklog = 30000

	// diodeReadBufSize comfortably holds any datagram the wire format allows.
	diodeReadBufSize = 64 << 10
)

// CatcherConfig is the built-in UDP diode receiver's configuration, parsed
// from ARTIGATE_CATCHER_* environment variables. A zero Interface means
// disabled.
type CatcherConfig struct {
	Interface string
	MTU       int
	Group     string
	Port      int
	RcvBufMB  int
	NetSetup  bool
}

// catcherConfigFromEnv reads and validates the catcher's environment
// configuration, failing fast at startup.
func catcherConfigFromEnv() (CatcherConfig, error) {
	cfg := CatcherConfig{Interface: strings.TrimSpace(os.Getenv("ARTIGATE_CATCHER_INTERFACE"))}
	if cfg.Interface == "" {
		return CatcherConfig{}, nil
	}
	var err error
	if cfg.MTU, err = envIntInRange("ARTIGATE_CATCHER_MTU", diodeDefaultMTU, 1280, 65536); err != nil {
		return CatcherConfig{}, err
	}
	if cfg.Port, err = envIntInRange("ARTIGATE_CATCHER_PORT", diodeDefaultPort, 1, 65535); err != nil {
		return CatcherConfig{}, err
	}
	if cfg.RcvBufMB, err = envIntInRange("ARTIGATE_CATCHER_RCVBUF_MB", diodeDefaultRcvBufMB, 1, 4096); err != nil {
		return CatcherConfig{}, err
	}
	if cfg.Group, err = envMulticastGroup("ARTIGATE_CATCHER_GROUP"); err != nil {
		return CatcherConfig{}, err
	}
	if cfg.NetSetup, err = envOnOffDefault("ARTIGATE_CATCHER_NETSETUP", true); err != nil {
		return CatcherConfig{}, err
	}
	return cfg, nil
}

// startCatcherIfConfigured parses the catcher environment at startup and, when
// enabled, starts receiving into the high server's landing directory;
// failures are fatal at startup, like every other misconfiguration.
func startCatcherIfConfigured(hs *HighServer) {
	cfg, err := catcherConfigFromEnv()
	must(err)
	if cfg.Interface == "" {
		return
	}
	_, err = startCatcher(cfg, hs.cfg.Landing, hs.onDiodeFileLanded)
	must(err)
	log.Printf("high-side diode catcher: %s ← [%s%%%s]:%d (MTU %d, receive buffer %d MiB) into %s",
		cfg.Interface, cfg.Group, cfg.Interface, cfg.Port, cfg.MTU, cfg.RcvBufMB, hs.cfg.Landing)
}

// diodeCatcher owns the diode RX socket and the reassembler behind it.
type diodeCatcher struct {
	cfg  CatcherConfig
	conn *net.UDPConn
	asm  *diodeAssembler
}

// startCatcher configures the diode interface (unless the host already did),
// joins the multicast group, and starts the receive loop. Reassembled files
// land in dir; onComplete runs for each (the high server uses it to kick an
// import as soon as a bundle is whole).
func startCatcher(cfg CatcherConfig, dir string, onComplete func(name string)) (*diodeCatcher, error) {
	if cfg.NetSetup {
		if err := setupCatcherIface(cfg); err != nil {
			return nil, err
		}
	}
	conn, err := joinDiodeGroup(cfg)
	if err != nil {
		return nil, err
	}
	if granted, err := forceUDPBuffer(conn, true, cfg.RcvBufMB<<20); err != nil {
		log.Printf("diode catch: receive buffer left at kernel default (%v)", err)
	} else if granted < cfg.RcvBufMB<<20 {
		log.Printf("diode catch: receive buffer %s (asked %s; the full size needs CAP_NET_ADMIN for SO_RCVBUFFORCE, or a higher net.core.rmem_max)",
			formatBytes(int64(granted)), formatBytes(int64(cfg.RcvBufMB)<<20))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c := &diodeCatcher{cfg: cfg, conn: conn, asm: newDiodeAssembler(dir, validBundleFileName, onComplete)}
	go c.run()
	return c, nil
}

// setupCatcherIface prepares the receive NIC: jumbo MTU, EUI-64 link-local,
// maxed RX descriptor ring, and (best-effort, needs a writable /proc/sys) a
// deeper kernel backlog queue.
func setupCatcherIface(cfg CatcherConfig) error {
	err := applyDiodeIfaceSetup(diodeIfaceSetup{
		Name:      cfg.Interface,
		MTU:       cfg.MTU,
		MaxRXRing: true,
	})
	if err != nil {
		return fmt.Errorf("configure diode interface %s: %w (needs CAP_NET_ADMIN over the host network namespace — network_mode: host, cap_add: NET_ADMIN, root — or preconfigure the NIC and set ARTIGATE_CATCHER_NETSETUP=off)", cfg.Interface, err)
	}
	if err := raiseNetdevBacklog(diodeNetdevBacklog); err != nil {
		log.Printf("diode catch: net.core.netdev_max_backlog left as-is (%v) — raise it on the host if datagrams drop at high rates", err)
	}
	return nil
}

// joinDiodeGroup binds the group's port on the diode interface and joins the
// multicast group there. Joining sends an MLD report out the catcher's TX —
// which on a one-way fiber is dark, and that is fine: delivery on a direct
// fiber needs no switch state, the join only opens the local NIC filter.
func joinDiodeGroup(cfg CatcherConfig) (*net.UDPConn, error) {
	ifi, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("no such interface %s: %w", cfg.Interface, err)
	}
	conn, err := net.ListenMulticastUDP("udp6", ifi, &net.UDPAddr{IP: net.ParseIP(cfg.Group), Port: cfg.Port})
	if err != nil {
		return nil, fmt.Errorf("join diode group [%s%%%s]:%d: %w", cfg.Group, cfg.Interface, cfg.Port, err)
	}
	return conn, nil
}

// Close stops the receive loop.
func (c *diodeCatcher) Close() error {
	return c.conn.Close()
}

// run is the catcher's single-threaded receive loop. One goroutine owns the
// socket and the assembler, so there is no locking anywhere on the hot path;
// the read deadline doubles as the idle tick for expiry and stats.
func (c *diodeCatcher) run() {
	buf := make([]byte, diodeReadBufSize)
	nextSweep := time.Now().Add(diodeSweepEvery)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(diodeSweepEvery))
		n, _, err := c.conn.ReadFromUDP(buf)
		now := time.Now()
		switch {
		case err == nil:
			c.asm.handleDatagram(buf[:n], now)
		case errors.Is(err, os.ErrDeadlineExceeded):
			// idle: sweep below
		case errors.Is(err, net.ErrClosed):
			return
		default:
			log.Printf("diode catch: read: %v", err)
		}
		if now.After(nextSweep) {
			c.asm.expireStale(now)
			c.asm.logStats()
			nextSweep = now.Add(diodeSweepEvery)
		}
	}
}

// onDiodeFileLanded is the catcher→importer bridge: when a landed file
// completes its bundle, import right away instead of waiting for the next
// timer tick — the same bounded/coalesced hand-off the HTTP ingest endpoint
// uses.
func (s *HighServer) onDiodeFileLanded(name string) {
	if !bundleCompleteInDir(s.cfg.Landing, bundleBaseName(name)) {
		return
	}
	s.requestImport()
}

// bundleBaseName strips a bundle file's suffix ("go-bundle-000042.tar.gz" →
// "go-bundle-000042").
func bundleBaseName(name string) string {
	for _, suffix := range bundleSuffixes() {
		if base, ok := strings.CutSuffix(name, suffix); ok {
			return base
		}
	}
	return name
}
