package realm

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	defaultPunchTimeout  = 10 * time.Second
	defaultPunchInterval = 100 * time.Millisecond

	symmetricNATPortGap         = 4
	symmetricNATExtraPorts      = 4
	symmetricNATMaxPortsPerHost = 32
)

func sendPunchPackets(conn net.PacketConn, addrs []netip.AddrPort, meta PunchMetadata, packetType PunchPacketType) {
	for _, addr := range addrs {
		sendPunchPacket(conn, addr, meta, packetType)
	}
}

func sendPunchPacket(conn net.PacketConn, addr netip.AddrPort, meta PunchMetadata, packetType PunchPacketType) {
	packet, err := EncodePunchPacket(packetType, meta)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(packet, net.UDPAddrFromAddrPort(addr))
}

func candidatePunchAddrs(locals, peers []netip.AddrPort) ([]netip.AddrPort, map[netip.AddrPort]struct{}) {
	var allow4, allow6 bool
	for _, local := range locals {
		if local.Addr().Is4() {
			allow4 = true
		} else {
			allow6 = true
		}
		if allow4 && allow6 {
			break
		}
	}
	var seen = make(map[netip.AddrPort]struct{}, len(peers))
	var candidates = make([]netip.AddrPort, 0, len(peers))
	for _, peer := range peers {
		if _, ok := seen[peer]; ok {
			continue
		}
		if peer.IsValid() {
			if peer.Addr().Is4() {
				if allow4 {
					seen[peer] = struct{}{}
					candidates = append(candidates, peer)
				}
			} else {
				if allow6 {
					seen[peer] = struct{}{}
					candidates = append(candidates, peer)
				}
			}
		}
	}
	return candidates, seen
}

func expandSymmetricNATCandidates(candidates []netip.AddrPort, seen map[netip.AddrPort]struct{}) []netip.AddrPort {
	portsByIP := make(map[netip.Addr][]uint16)
	for _, addr := range candidates {
		if addr.Addr().Is4() {
			portsByIP[addr.Addr()] = append(portsByIP[addr.Addr()], addr.Port())
		}
	}
	for ip, ports := range portsByIP {
		ports = uniqueSortedPorts(ports)
		if !predictablePortGroup(ports) {
			continue
		}
		start := int(ports[0])
		end := int(ports[len(ports)-1]) + symmetricNATExtraPorts
		if end > 65535 {
			end = 65535
		}
		added := 0
		for port := start; port <= end && added < symmetricNATMaxPortsPerHost; port++ {
			addr := netip.AddrPortFrom(ip, uint16(port))
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			candidates = append(candidates, addr)
			added++
		}
	}
	sortAddrPorts(candidates)
	return candidates
}

func uniqueSortedPorts(ports []uint16) []uint16 {
	slices.Sort(ports)
	out := ports[:0]
	var last uint16
	for i, port := range ports {
		if i > 0 && port == last {
			continue
		}
		out = append(out, port)
		last = port
	}
	return out
}

func predictablePortGroup(ports []uint16) bool {
	if len(ports) < 2 {
		return false
	}
	for i := 1; i < len(ports); i++ {
		if ports[i]-ports[i-1] > symmetricNATPortGap {
			return false
		}
	}
	return true
}

func sortAddrPorts(addrs []netip.AddrPort) {
	slices.SortFunc(addrs, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})
}

func addrPortStrings(addrs []netip.AddrPort) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func parseAddrPorts(addrs []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, s := range addrs {
		addr, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}
