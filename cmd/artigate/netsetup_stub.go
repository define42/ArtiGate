//go:build !linux

package main

// Non-Linux stubs for the diode interface setup. The built-in UDP diode's
// send/receive path is portable, but configuring a NIC (MTU, queue lengths,
// ipv6 addr-gen-mode) is Linux-only — elsewhere the interface must be
// prepared by the host and ARTIGATE_{PITCHER,CATCHER}_NETSETUP set to off.

import (
	"errors"
	"net"
)

type diodeIfaceSetup struct {
	Name          string
	MTU           int
	TxQueueLen    int
	MaxTXRing     bool
	MaxRXRing     bool
	WaitLinkLocal bool
}

func applyDiodeIfaceSetup(diodeIfaceSetup) error {
	return errors.New("diode interface setup requires Linux; configure the interface on the host and set the NETSETUP variable to off")
}

// forceUDPBuffer sets the socket buffer with the portable options (no
// SO_*BUFFORCE outside Linux) and reports the requested size back.
func forceUDPBuffer(c *net.UDPConn, recv bool, size int) (int, error) {
	if recv {
		return size, c.SetReadBuffer(size)
	}
	return size, c.SetWriteBuffer(size)
}

func raiseNetdevBacklog(int) error {
	return errors.New("netdev_max_backlog is Linux-only")
}
