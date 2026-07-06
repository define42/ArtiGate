//go:build linux

package main

// Diode interface setup. ArtiGate configures the dedicated diode NIC itself —
// jumbo MTU, deep queues, EUI-64 IPv6 link-local addressing — so deploying the
// built-in diode is one env var, not a page of `ip`/`ethtool`/`sysctl` host
// bootstrap. Everything speaks ioctl/rtnetlink directly (the runtime image
// carries no iproute2) and needs CAP_NET_ADMIN over the interface's network
// namespace: in Docker that is network_mode: host + cap_add: NET_ADMIN, run
// as root (Docker grants added capabilities to the root user only).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Stable kernel ABI numbers the frozen syscall package predates.
const (
	sysSIOCETHTOOL = 0x8946

	// rtnetlink attributes for per-family link config
	// (IFLA_AF_SPEC → AF_INET6 → IFLA_INET6_ADDR_GEN_MODE).
	iflaAFSpec           = 26
	iflaInet6AddrGenMode = 8
	addrGenModeEUI64     = 0 // IN6_ADDR_GEN_MODE_EUI64

	ethtoolGRingParam = 0x10
	ethtoolSRingParam = 0x11

	// /proc/net/if_inet6 address flags (include/uapi/linux/if_addr.h).
	ifaFlagDadFailed = 0x08
	ifaFlagTentative = 0x40

	ipv6ScopeLink = 0x20
)

// diodeIfaceSetup describes how a dedicated diode NIC must be configured
// before the pitcher or catcher touches it.
type diodeIfaceSetup struct {
	Name       string
	MTU        int
	TxQueueLen int // 0 leaves the qdisc queue length alone (catcher)
	MaxTXRing  bool
	MaxRXRing  bool
	// WaitLinkLocal blocks until the EUI-64 link-local address has passed
	// duplicate address detection — the pitcher cannot source packets from a
	// tentative address. The catcher joins its multicast group by interface
	// index and never waits.
	WaitLinkLocal bool
}

// applyDiodeIfaceSetup configures the diode interface deterministically: link
// down → addr-gen-mode eui64 → MTU → txqueuelen → ring buffers → link up. The
// bounce guarantees the kernel regenerates the link-local address from the
// MAC (RFC 4291 modified EUI-64) no matter what mode or address the interface
// had before.
func applyDiodeIfaceSetup(s diodeIfaceSetup) error {
	ifi, err := net.InterfaceByName(s.Name)
	if err != nil {
		return fmt.Errorf("no such interface: %w", err)
	}
	fd, err := ifaceControlSocket()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := setLinkUpDown(fd, s.Name, false); err != nil {
		return fmt.Errorf("link down: %w", err)
	}
	if err := setAddrGenModeEUI64(ifi.Index, s.Name); err != nil {
		return fmt.Errorf("set ipv6 addr-gen-mode eui64: %w", err)
	}
	if err := setIfreqInt(fd, s.Name, syscall.SIOCSIFMTU, int32(s.MTU)); err != nil {
		return fmt.Errorf("set MTU %d: %w", s.MTU, err)
	}
	if s.TxQueueLen > 0 {
		if err := setIfreqInt(fd, s.Name, syscall.SIOCSIFTXQLEN, int32(s.TxQueueLen)); err != nil {
			return fmt.Errorf("set txqueuelen %d: %w", s.TxQueueLen, err)
		}
	}
	// Ring buffers are best-effort: virtual NICs (veth, tap) don't have them,
	// and the socket buffers are what really absorb bursts.
	if s.MaxTXRing || s.MaxRXRing {
		if change, err := maxRingBuffers(fd, s.Name, s.MaxRXRing, s.MaxTXRing); err != nil {
			log.Printf("diode iface %s: NIC ring buffers left as-is (%v)", s.Name, err)
		} else {
			log.Printf("diode iface %s: NIC ring buffers %s", s.Name, change)
		}
	}
	if err := setLinkUpDown(fd, s.Name, true); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	return waitLinkLocalIfWanted(s)
}

func waitLinkLocalIfWanted(s diodeIfaceSetup) error {
	if !s.WaitLinkLocal {
		log.Printf("diode iface %s: up (MTU %d, ipv6 addr-gen-mode eui64)", s.Name, s.MTU)
		return nil
	}
	addr, err := waitForLinkLocal(s.Name, 15*time.Second)
	if err != nil {
		// Not fatal: a pitcher whose RX strand is dark (common on simplex
		// fiber rigs) has no carrier and DAD cannot finish until link comes
		// up. Sends retry; explain instead of dying.
		log.Printf("diode iface %s: no usable link-local address yet (%v) — check the link light; on a simplex fiber the pitcher's RX strand must see light (loop it back or force link on the NIC)", s.Name, err)
		return nil
	}
	log.Printf("diode iface %s: up (MTU %d, link-local %s%%%s)", s.Name, s.MTU, addr, s.Name)
	return nil
}

// ifaceControlSocket opens the throwaway datagram socket interface ioctls
// operate on.
func ifaceControlSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	}
	if err != nil {
		return -1, fmt.Errorf("open interface control socket: %w", err)
	}
	return fd, nil
}

// ifreq mirrors struct ifreq for value ioctls: 16 bytes of name plus a
// 24-byte union accessed through the typed setters below.
type ifreq struct {
	name [16]byte
	data [24]byte
}

// ifreqPtr mirrors struct ifreq for pointer ioctls (ethtool). The payload is
// a real unsafe.Pointer field so the runtime keeps it correct if the stack
// holding the pointed-to value moves.
type ifreqPtr struct {
	name [16]byte
	data unsafe.Pointer
	pad  [16]byte
}

func ifreqName(name string) ([16]byte, error) {
	var b [16]byte
	if len(name) >= len(b) {
		return b, fmt.Errorf("interface name %q too long", name)
	}
	copy(b[:], name)
	return b, nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

// setIfreqInt performs an ioctl whose ifreq payload is a single int32 (MTU,
// txqueuelen).
func setIfreqInt(fd int, name string, req uint, v int32) error {
	r := ifreq{}
	var err error
	if r.name, err = ifreqName(name); err != nil {
		return err
	}
	binary.NativeEndian.PutUint32(r.data[:], uint32(v))
	return ioctlPtr(fd, req, unsafe.Pointer(&r))
}

// setLinkUpDown sets or clears IFF_UP, read-modify-write over the interface
// flags.
func setLinkUpDown(fd int, name string, up bool) error {
	r := ifreq{}
	var err error
	if r.name, err = ifreqName(name); err != nil {
		return err
	}
	if err := ioctlPtr(fd, syscall.SIOCGIFFLAGS, unsafe.Pointer(&r)); err != nil {
		return err
	}
	flags := binary.NativeEndian.Uint16(r.data[:])
	if up {
		flags |= syscall.IFF_UP
	} else {
		flags &^= syscall.IFF_UP
	}
	binary.NativeEndian.PutUint16(r.data[:], flags)
	return ioctlPtr(fd, syscall.SIOCSIFFLAGS, unsafe.Pointer(&r))
}

// -----------------------------------------------------------------------------
// rtnetlink: ipv6 addr-gen-mode
// -----------------------------------------------------------------------------

// setAddrGenModeEUI64 asks the kernel to derive the interface's IPv6
// link-local address from its MAC — the equivalent of NetworkManager's
// ipv6.addr-gen-mode=eui64. It speaks rtnetlink because /proc/sys/net is
// mounted read-only in unprivileged containers while netlink works with
// CAP_NET_ADMIN alone; the /proc write remains as a fallback for exotic
// setups that filter netlink.
func setAddrGenModeEUI64(ifindex int, name string) error {
	nlErr := netlinkSetAddrGenMode(ifindex)
	if nlErr == nil {
		return nil
	}
	procPath := "/proc/sys/net/ipv6/conf/" + name + "/addr_gen_mode"
	if procErr := os.WriteFile(procPath, []byte("0\n"), 0o644); procErr != nil {
		return fmt.Errorf("netlink: %w; %s: %w", nlErr, procPath, procErr)
	}
	return nil
}

func netlinkSetAddrGenMode(ifindex int) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	msg := addrGenModeMessage(ifindex)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	return awaitNetlinkAck(fd)
}

// addrGenModeMessage builds the RTM_NEWLINK request:
//
//	nlmsghdr | ifinfomsg | IFLA_AF_SPEC { AF_INET6 { IFLA_INET6_ADDR_GEN_MODE = eui64 } }
//
// Netlink speaks host byte order and pads every attribute to 4 bytes.
func addrGenModeMessage(ifindex int) []byte {
	b := make([]byte, 48)
	binary.NativeEndian.PutUint32(b[0:], 48) // nlmsg_len
	binary.NativeEndian.PutUint16(b[4:], syscall.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(b[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(b[8:], 1) // nlmsg_seq
	b[16] = syscall.AF_UNSPEC               // ifinfomsg.ifi_family
	binary.NativeEndian.PutUint32(b[20:], uint32(ifindex))
	// ifi_flags/ifi_change stay 0: only the AF_SPEC attribute changes.
	binary.NativeEndian.PutUint16(b[32:], 16) // IFLA_AF_SPEC: rta_len
	binary.NativeEndian.PutUint16(b[34:], iflaAFSpec)
	binary.NativeEndian.PutUint16(b[36:], 12) // AF_INET6 nest: rta_len
	binary.NativeEndian.PutUint16(b[38:], syscall.AF_INET6)
	binary.NativeEndian.PutUint16(b[40:], 5) // ADDR_GEN_MODE: rta_len = hdr + u8
	binary.NativeEndian.PutUint16(b[42:], iflaInet6AddrGenMode)
	b[44] = addrGenModeEUI64
	return b
}

// awaitNetlinkAck reads the kernel's NLMSG_ERROR reply: code 0 is the ACK,
// anything else is the errno the request failed with.
func awaitNetlinkAck(fd int) error {
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.NLMSG_ERROR || len(m.Data) < 4 {
			continue
		}
		if code := int32(binary.NativeEndian.Uint32(m.Data[:4])); code != 0 {
			return syscall.Errno(-code)
		}
		return nil
	}
	return errors.New("no netlink acknowledgement")
}

// -----------------------------------------------------------------------------
// ethtool: NIC ring buffers
// -----------------------------------------------------------------------------

// ethtoolRingparam mirrors struct ethtool_ringparam.
type ethtoolRingparam struct {
	cmd               uint32
	rxMaxPending      uint32
	rxMiniMaxPending  uint32
	rxJumboMaxPending uint32
	txMaxPending      uint32
	rxPending         uint32
	rxMiniPending     uint32
	rxJumboPending    uint32
	txPending         uint32
}

// maxRingBuffers grows the NIC's RX and/or TX descriptor rings to their
// hardware maximum — the very first queue a datagram can be dropped from on a
// catcher that briefly falls behind, and the last one before the wire on a
// pitcher.
func maxRingBuffers(fd int, name string, growRX, growTX bool) (string, error) {
	ring := ethtoolRingparam{cmd: ethtoolGRingParam}
	r := ifreqPtr{data: unsafe.Pointer(&ring)}
	var err error
	if r.name, err = ifreqName(name); err != nil {
		return "", err
	}
	if err := ioctlPtr(fd, sysSIOCETHTOOL, unsafe.Pointer(&r)); err != nil {
		return "", err
	}
	before := ring
	if growRX && ring.rxMaxPending > ring.rxPending {
		ring.rxPending = ring.rxMaxPending
	}
	if growTX && ring.txMaxPending > ring.txPending {
		ring.txPending = ring.txMaxPending
	}
	if ring.rxPending == before.rxPending && ring.txPending == before.txPending {
		return fmt.Sprintf("already at rx %d, tx %d", ring.rxPending, ring.txPending), nil
	}
	ring.cmd = ethtoolSRingParam
	if err := ioctlPtr(fd, sysSIOCETHTOOL, unsafe.Pointer(&r)); err != nil {
		return "", err
	}
	return fmt.Sprintf("rx %d → %d, tx %d → %d", before.rxPending, ring.rxPending, before.txPending, ring.txPending), nil
}

// -----------------------------------------------------------------------------
// Link-local readiness
// -----------------------------------------------------------------------------

// waitForLinkLocal polls /proc/net/if_inet6 until the interface owns a
// link-local address that has passed duplicate address detection. DAD on a
// one-way fiber gets no answer, so this normally completes in about a second
// after link up.
func waitForLinkLocal(name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	state := "no link-local address appeared"
	for {
		b, err := os.ReadFile("/proc/net/if_inet6")
		if err != nil {
			return "", err
		}
		addr, st := linkLocalState(string(b), name)
		if addr != "" {
			return addr, nil
		}
		if st != "" {
			state = st
		}
		if time.Now().After(deadline) {
			return "", errors.New(state)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// linkLocalState scans if_inet6 content for the interface's link-local
// address. It returns the usable address, or a description of why there is
// none yet.
func linkLocalState(ifInet6, name string) (addr, state string) {
	for _, line := range strings.Split(ifInet6, "\n") {
		f := strings.Fields(line)
		if len(f) != 6 || f[5] != name {
			continue
		}
		scope, err1 := strconv.ParseUint(f[3], 16, 32)
		flags, err2 := strconv.ParseUint(f[4], 16, 32)
		if err1 != nil || err2 != nil || scope != ipv6ScopeLink {
			continue
		}
		switch {
		case flags&ifaFlagDadFailed != 0:
			state = "duplicate address detection failed"
		case flags&ifaFlagTentative != 0:
			state = "address still tentative (duplicate address detection running)"
		default:
			return formatIfInet6Addr(f[0]), ""
		}
	}
	return "", state
}

// formatIfInet6Addr renders if_inet6's 32-hex-digit address column as a
// normal IPv6 literal.
func formatIfInet6Addr(hex32 string) string {
	if len(hex32) != 32 {
		return hex32
	}
	ip := make(net.IP, net.IPv6len)
	for i := range ip {
		v, err := strconv.ParseUint(hex32[i*2:i*2+2], 16, 8)
		if err != nil {
			return hex32
		}
		ip[i] = byte(v)
	}
	return ip.String()
}

// -----------------------------------------------------------------------------
// Socket buffers and host queues
// -----------------------------------------------------------------------------

// forceUDPBuffer raises a UDP socket buffer as far as the kernel permits:
// SO_RCVBUFFORCE/SO_SNDBUFFORCE first (CAP_NET_ADMIN, ignores the
// rmem_max/wmem_max ceilings), the plain option as fallback. It returns the
// size the kernel actually granted.
func forceUDPBuffer(c *net.UDPConn, recv bool, size int) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	force, plain, read := syscall.SO_SNDBUFFORCE, syscall.SO_SNDBUF, syscall.SO_SNDBUF
	if recv {
		force, plain, read = syscall.SO_RCVBUFFORCE, syscall.SO_RCVBUF, syscall.SO_RCVBUF
	}
	granted, setErr := 0, error(nil)
	err = raw.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, force, size); err != nil {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, plain, size)
		}
		granted, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, read)
	})
	if err != nil {
		return 0, err
	}
	return granted, setErr
}

// raiseNetdevBacklog best-effort raises net.core.netdev_max_backlog — the
// kernel's per-CPU queue between the driver and the UDP stack, the "RX queue
// length" of the host itself. /proc/sys is read-only in unprivileged
// containers; failure here is survivable (the forced socket buffer does the
// heavy lifting) and merely logged by the caller.
func raiseNetdevBacklog(target int) error {
	const p = "/proc/sys/net/core/netdev_max_backlog"
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	current, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err == nil && current >= target {
		return nil
	}
	return os.WriteFile(p, []byte(strconv.Itoa(target)+"\n"), 0o644)
}
