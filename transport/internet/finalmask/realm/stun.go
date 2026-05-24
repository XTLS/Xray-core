package realm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun/v3"
)

const (
	defaultSTUNTimeout   = 4 * time.Second
	defaultPunchTimeout  = 10 * time.Second
	defaultPunchInterval = 100 * time.Millisecond

	symmetricNATPortGap         = 4
	symmetricNATExtraPorts      = 4
	symmetricNATMaxPortsPerHost = 32
)

func resolveSTUNServers(local net.IP, servers []string) []*net.UDPAddr {
	var network string
	if local.IsUnspecified() {
		network = "ip"
	} else {
		if local.To4() != nil {
			network = "ip4"
		} else {
			network = "ip6"
		}
	}

	var seen = make(map[string]struct{})
	var addrs = make([]*net.UDPAddr, 0, len(servers))
	for _, server := range servers {
		h, p, err := net.SplitHostPort(server)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		ips, err := net.DefaultResolver.LookupIP(context.Background(), network, h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if _, ok := seen[net.JoinHostPort(ip.String(), p)]; !ok {
				seen[net.JoinHostPort(ip.String(), p)] = struct{}{}
				addrs = append(addrs, &net.UDPAddr{IP: ip, Port: port})
				break
			}
		}
	}

	return addrs
}

func parseSTUNBindingResponse(packet []byte) (*stun.Message, netip.AddrPort, error) {
	msg := stun.New()
	if err := stun.Decode(packet, msg); err != nil {
		return nil, netip.AddrPort{}, err
	}
	if msg.Type != stun.BindingSuccess {
		return nil, netip.AddrPort{}, errors.New("not a STUN binding success response")
	}

	var xorMapped stun.XORMappedAddress
	if err := xorMapped.GetFrom(msg); err == nil {
		addr, err := netIPPortToAddrPort(xorMapped.IP, xorMapped.Port)
		return msg, addr, err
	}

	var mapped stun.MappedAddress
	if err := mapped.GetFrom(msg); err == nil {
		addr, err := netIPPortToAddrPort(mapped.IP, mapped.Port)
		return msg, addr, err
	}

	return nil, netip.AddrPort{}, errors.New("STUN mapped address not found")
}

func netIPPortToAddrPort(ip net.IP, port int) (netip.AddrPort, error) {
	if port <= 0 || port > 65535 {
		return netip.AddrPort{}, errors.New("invalid STUN mapped port")
	}
	if ip4 := ip.To4(); ip4 != nil {
		var addr [4]byte
		copy(addr[:], ip4)
		return netip.AddrPortFrom(netip.AddrFrom4(addr), uint16(port)), nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return netip.AddrPort{}, errors.New("invalid STUN mapped IP")
	}
	var addr [16]byte
	copy(addr[:], ip16)
	return netip.AddrPortFrom(netip.AddrFrom16(addr), uint16(port)), nil
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
