package tun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

type tcpNATEntry struct {
	src netip.AddrPort
	dst netip.AddrPort
}

type natKey struct {
	src, dst netip.AddrPort
}

const natPortMin uint16 = 32768

var ErrNATPortExhausted = errors.New("NAT port exhausted")

type TCPNAT struct {
	mu        sync.Mutex
	byConn    map[uint16]tcpNATEntry
	bySrcDst  map[natKey]uint16
	nextPort  uint16
	freePorts []uint16
}

func NewTCPNAT() *TCPNAT {
	n := &TCPNAT{
		byConn:    make(map[uint16]tcpNATEntry),
		bySrcDst:  make(map[natKey]uint16),
		nextPort:  natPortMin,
		freePorts: make([]uint16, 0),
	}
	n.randomizePort()
	return n
}

func (n *TCPNAT) randomizePort() {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err == nil {
		n.nextPort = natPortMin + binary.BigEndian.Uint16(buf[:])%32768
	}
}

func (n *TCPNAT) LookupOrAllocate(src, dst netip.AddrPort) (uint16, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	key := natKey{src, dst}
	if port, ok := n.bySrcDst[key]; ok {
		return port, nil
	}

	port, err := n.allocatePort()
	if err != nil {
		return 0, err
	}

	n.byConn[port] = tcpNATEntry{src: src, dst: dst}
	n.bySrcDst[key] = port
	return port, nil
}

func (n *TCPNAT) LookupBack(localPort uint16) (netip.AddrPort, netip.AddrPort, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry, ok := n.byConn[localPort]
	if !ok {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	return entry.src, entry.dst, true
}

func (n *TCPNAT) Delete(localPort uint16) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry, ok := n.byConn[localPort]
	if !ok {
		return
	}
	key := natKey{entry.src, entry.dst}
	delete(n.byConn, localPort)
	delete(n.bySrcDst, key)
	n.freePorts = append(n.freePorts, localPort)
}

type udpNATEntry struct {
	src netip.AddrPort
	dst netip.AddrPort
}

type UDPNAT struct {
	mu        sync.Mutex
	entries   map[natKey]uint16
	byPort    map[uint16]udpNATEntry
	nextPort  uint16
	freePorts []uint16
}

func NewUDPNAT() *UDPNAT {
	n := &UDPNAT{
		entries:   make(map[natKey]uint16),
		byPort:    make(map[uint16]udpNATEntry),
		nextPort:  natPortMin,
		freePorts: make([]uint16, 0),
	}
	n.randomizePort()
	return n
}

func (n *UDPNAT) randomizePort() {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err == nil {
		n.nextPort = natPortMin + binary.BigEndian.Uint16(buf[:])%32768
	}
}

func (n *UDPNAT) LookupOrAllocate(src, dst netip.AddrPort) (uint16, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	key := natKey{src, dst}
	if port, ok := n.entries[key]; ok {
		return port, nil
	}

	port, err := n.allocatePort()
	if err != nil {
		return 0, err
	}

	n.entries[key] = port
	n.byPort[port] = udpNATEntry{src, dst}
	return port, nil
}

func (n *UDPNAT) LookupBack(localPort uint16) (netip.AddrPort, netip.AddrPort, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry, ok := n.byPort[localPort]
	if !ok {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	return entry.src, entry.dst, true
}

func (n *UDPNAT) Delete(localPort uint16) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry, ok := n.byPort[localPort]
	if !ok {
		return
	}
	key := natKey{entry.src, entry.dst}
	delete(n.entries, key)
	delete(n.byPort, localPort)
	n.freePorts = append(n.freePorts, localPort)
}

func (n *TCPNAT) allocatePort() (uint16, error) {
	if len(n.freePorts) > 0 {
		port := n.freePorts[len(n.freePorts)-1]
		n.freePorts = n.freePorts[:len(n.freePorts)-1]
		return port, nil
	}

	start := n.nextPort
	for {
		port := n.nextPort
		n.nextPort++
		if n.nextPort < natPortMin {
			n.nextPort = natPortMin
		}

		if _, exists := n.byConn[port]; !exists {
			return port, nil
		}

		if n.nextPort == start {
			return 0, ErrNATPortExhausted
		}
	}
}

func (n *UDPNAT) allocatePort() (uint16, error) {
	if len(n.freePorts) > 0 {
		port := n.freePorts[len(n.freePorts)-1]
		n.freePorts = n.freePorts[:len(n.freePorts)-1]
		return port, nil
	}

	start := n.nextPort
	for {
		port := n.nextPort
		n.nextPort++
		if n.nextPort < natPortMin {
			n.nextPort = natPortMin
		}

		if _, exists := n.byPort[port]; !exists {
			return port, nil
		}

		if n.nextPort == start {
			return 0, ErrNATPortExhausted
		}
	}
}
