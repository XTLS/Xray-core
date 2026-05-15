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
	"github.com/xtls/xray-core/common"
)

const (
	defaultSTUNTimeout = 4 * time.Second
)

func Discover(conn net.PacketConn, servers []*net.UDPAddr) []netip.AddrPort {
	var transactionIDs = make(map[[stun.TransactionIDSize]byte]struct{}, len(servers))
	for _, s := range servers {
		msg := common.Must2(stun.Build(stun.TransactionID, stun.BindingRequest))
		transactionIDs[msg.TransactionID] = struct{}{}
		_, _ = conn.WriteTo(msg.Raw, s)
	}

	var buf = make([]byte, 1500)
	var results = make([]netip.AddrPort, 0, len(servers))
	conn.SetReadDeadline(time.Now().Add(defaultSTUNTimeout))
	for len(transactionIDs) > 0 {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		msg, addrPort, err := parseSTUNBindingResponse(buf[:n])
		if err != nil {
			continue
		}
		if _, ok := transactionIDs[msg.TransactionID]; ok {
			delete(transactionIDs, msg.TransactionID)
			results = append(results, addrPort)
		}
	}
	conn.SetReadDeadline(time.Time{})
	slices.SortFunc(results, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})

	return results
}

func DiscoverWithDemux(writeto func(p []byte, addr net.Addr) (n int, err error), ch <-chan STUNPacketEvent, servers []*net.UDPAddr) []netip.AddrPort {
	var transactionIDs = make(map[[stun.TransactionIDSize]byte]struct{}, len(servers))
	for _, addr := range servers {
		msg := common.Must2(stun.Build(stun.TransactionID, stun.BindingRequest))
		transactionIDs[msg.TransactionID] = struct{}{}
		_, _ = writeto(msg.Raw, addr)
	}

	var deadline = time.NewTimer(defaultSTUNTimeout)
	var results = make([]netip.AddrPort, 0, len(servers))
	for len(transactionIDs) > 0 {
		select {
		case <-deadline.C:
			goto end
		case ev := <-ch:
			if _, ok := transactionIDs[ev.Message.TransactionID]; ok {
				delete(transactionIDs, ev.Message.TransactionID)
				results = append(results, ev.Addr)
			}
		}
	}
end:
	deadline.Stop()
	slices.SortFunc(results, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})

	return results
}

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
