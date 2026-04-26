//go:build windows

package icmp

import (
	stderrors "errors"
	stdnet "net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestSocketCandidatesWindows(t *testing.T) {
	tests := []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		dstIP    tcpip.Address
		network  string
		ip       stdnet.IP
	}{
		{
			name:     "ipv4",
			netProto: header.IPv4ProtocolNumber,
			dstIP:    tcpip.AddrFromSlice([]byte{1, 1, 1, 1}),
			network:  "ip4:icmp",
			ip:       stdnet.IPv4(1, 1, 1, 1),
		},
		{
			name:     "ipv6",
			netProto: header.IPv6ProtocolNumber,
			dstIP:    tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			network:  "ip6:ipv6-icmp",
			ip:       stdnet.ParseIP("2001:db8::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := socketCandidates(tt.netProto, tt.dstIP)
			if len(candidates) != 1 {
				t.Fatalf("unexpected candidate count: %d", len(candidates))
			}
			candidate := candidates[0]
			if candidate.network != tt.network {
				t.Fatalf("unexpected network: %q", candidate.network)
			}
			if IsDatagramNetwork(candidate.network) {
				t.Fatalf("windows candidate must not be datagram based: %q", candidate.network)
			}

			addr, ok := candidate.remoteAddr.(*stdnet.IPAddr)
			if !ok {
				t.Fatalf("unexpected remote addr type: %T", candidate.remoteAddr)
			}
			if !addr.IP.Equal(tt.ip) {
				t.Fatalf("unexpected remote addr: %v", addr.IP)
			}
		})
	}
}

func TestIsPermissionErrorWindows(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{err: stderrors.New("socket: permission denied"), want: true},
		{err: stderrors.New("listen ip4:icmp 0.0.0.0: access is denied"), want: true},
		{err: stderrors.New("listen ip4:icmp 0.0.0.0: An attempt was made to access a socket in a way forbidden by its access permissions."), want: true},
		{err: stderrors.New("i/o timeout"), want: false},
	}

	for _, tt := range tests {
		if got := isPermissionError(tt.err); got != tt.want {
			t.Fatalf("isPermissionError(%q) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
