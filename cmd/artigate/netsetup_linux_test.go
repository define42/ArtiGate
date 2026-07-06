package main

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// sampleIfInet6 mirrors /proc/net/if_inet6: address, ifindex, prefixlen,
// scope, flags, name.
const sampleIfInet6 = `00000000000000000000000000000001 01 80 10 80       lo
20010db8000000000000000000000001 02 40 00 80    eth0
fe80000000000000021122fffe334455 02 40 20 40    eth0
fe80000000000000021122fffe334455 03 40 20 80    eth1
fe80000000000000aabbccfffeddeeff 04 40 20 08    eth2
`

func TestLinkLocalState(t *testing.T) {
	if addr, _ := linkLocalState(sampleIfInet6, "eth1"); addr != "fe80::211:22ff:fe33:4455" {
		t.Errorf("eth1 addr = %q, want the formatted link-local", addr)
	}
	if addr, state := linkLocalState(sampleIfInet6, "eth0"); addr != "" || state == "" {
		t.Errorf("tentative eth0 = %q/%q, want no address and a tentative explanation", addr, state)
	}
	if addr, state := linkLocalState(sampleIfInet6, "eth2"); addr != "" || state != "duplicate address detection failed" {
		t.Errorf("dad-failed eth2 = %q/%q", addr, state)
	}
	if addr, state := linkLocalState(sampleIfInet6, "lo"); addr != "" || state != "" {
		t.Errorf("lo (host scope only) = %q/%q, want nothing", addr, state)
	}
	if addr, state := linkLocalState(sampleIfInet6, "missing0"); addr != "" || state != "" {
		t.Errorf("unknown interface = %q/%q, want nothing", addr, state)
	}
}

// TestAddrGenModeMessage decodes the hand-built rtnetlink request with the
// stdlib netlink parser to prove the framing is exactly what the kernel will
// parse.
func TestAddrGenModeMessage(t *testing.T) {
	msg := addrGenModeMessage(7)
	if len(msg) != 48 {
		t.Fatalf("message length %d, want 48", len(msg))
	}
	parsed, err := syscall.ParseNetlinkMessage(msg)
	if err != nil {
		t.Fatalf("ParseNetlinkMessage: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed %d messages, want 1", len(parsed))
	}
	h := parsed[0].Header
	if h.Type != syscall.RTM_NEWLINK || h.Flags != syscall.NLM_F_REQUEST|syscall.NLM_F_ACK {
		t.Fatalf("header = %+v", h)
	}
	data := parsed[0].Data
	if got := binary.NativeEndian.Uint32(data[4:]); got != 7 {
		t.Fatalf("ifindex = %d, want 7", got)
	}
	// The single attribute chain: AF_SPEC{ AF_INET6{ ADDR_GEN_MODE = eui64 } }.
	attrs, err := syscall.ParseNetlinkRouteAttr(&parsed[0])
	if err != nil {
		t.Fatalf("ParseNetlinkRouteAttr: %v", err)
	}
	if len(attrs) != 1 || attrs[0].Attr.Type != iflaAFSpec {
		t.Fatalf("attrs = %+v, want one IFLA_AF_SPEC", attrs)
	}
	nest := attrs[0].Value
	if binary.NativeEndian.Uint16(nest[2:]) != syscall.AF_INET6 {
		t.Fatalf("nested family attr = %v", nest)
	}
	inner := nest[4:]
	if binary.NativeEndian.Uint16(inner[2:]) != iflaInet6AddrGenMode || inner[4] != addrGenModeEUI64 {
		t.Fatalf("addr-gen-mode attr = %v", inner)
	}
}

func TestFormatIfInet6Addr(t *testing.T) {
	if got := formatIfInet6Addr("fe80000000000000021122fffe334455"); got != "fe80::211:22ff:fe33:4455" {
		t.Errorf("formatted = %q", got)
	}
	if got := formatIfInet6Addr("garbage"); got != "garbage" {
		t.Errorf("malformed input should pass through, got %q", got)
	}
}
