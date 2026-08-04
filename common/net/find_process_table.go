package net

import (
	"encoding/binary"
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
)

type searcher struct {
	itemSize   int
	port       int
	ip         int
	ipSize     int
	remotePort int
	remoteIP   int
	remoteSize int
	pid        int
	allowAnyIP bool
}

func (s *searcher) Search(b []byte, ip netip.Addr, port uint16, remoteIP netip.Addr, remotePort uint16) (uint32, error) {
	n := int(readNativeUint32(b[:4]))
	itemSize := s.itemSize
	matchRemote := s.remoteIP >= 0 && remoteIP.IsValid() && remotePort != 0

	for i := range n {
		row := b[4+itemSize*i : 4+itemSize*(i+1)]

		srcPort := readNetworkPort(row[s.port : s.port+4])
		if srcPort != port {
			continue
		}

		srcIP, _ := netip.AddrFromSlice(row[s.ip : s.ip+s.ipSize])
		srcIP = srcIP.Unmap()
		// Windows binds an unbound UDP socket to 0.0.0.0/[::] while first sendto.
		if ip != srcIP && (!srcIP.IsUnspecified() || !s.allowAnyIP) {
			continue
		}

		if matchRemote {
			rowRemoteIP, _ := netip.AddrFromSlice(row[s.remoteIP : s.remoteIP+s.remoteSize])
			rowRemoteIP = rowRemoteIP.Unmap()
			rowRemotePort := readNetworkPort(row[s.remotePort : s.remotePort+4])
			if remoteIP != rowRemoteIP || remotePort != rowRemotePort {
				continue
			}
		}

		pid := readNativeUint32(row[s.pid : s.pid+4])
		return pid, nil
	}
	return 0, errors.New("not found")
}

func newSearcher(network Network, family AddressFamily) *searcher {
	var itemSize, port, ip, ipSize, remotePort, remoteIP, remoteSize, pid int
	allowAnyIP := false
	remotePort, remoteIP, remoteSize = -1, -1, 0

	switch network {
	case Network_TCP:
		if family == AddressFamilyIPv4 {
			// struct MIB_TCPROW_OWNER_PID
			itemSize, port, ip, ipSize, remotePort, remoteIP, remoteSize, pid = 24, 8, 4, 4, 16, 12, 4, 20
		}
		if family == AddressFamilyIPv6 {
			// struct MIB_TCP6ROW_OWNER_PID
			itemSize, port, ip, ipSize, remotePort, remoteIP, remoteSize, pid = 56, 20, 0, 16, 44, 24, 16, 52
		}
	case Network_UDP:
		allowAnyIP = true
		if family == AddressFamilyIPv4 {
			// struct MIB_UDPROW_OWNER_PID
			itemSize, port, ip, ipSize, pid = 12, 4, 0, 4, 8
		}
		if family == AddressFamilyIPv6 {
			// struct MIB_UDP6ROW_OWNER_PID
			itemSize, port, ip, ipSize, pid = 28, 20, 0, 16, 24
		}
	}

	return &searcher{
		itemSize:   itemSize,
		port:       port,
		ip:         ip,
		ipSize:     ipSize,
		remotePort: remotePort,
		remoteIP:   remoteIP,
		remoteSize: remoteSize,
		pid:        pid,
		allowAnyIP: allowAnyIP,
	}
}

func readNetworkPort(b []byte) uint16 {
	return binary.BigEndian.Uint16(b[:2])
}

func readNativeUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}
