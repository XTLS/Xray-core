package outbound

import (
	"github.com/xtls/xray-core/common/net"
	"testing"
)

type addressPacket struct{ dest net.Destination }

func (p *addressPacket) ReadPacket(b []byte) (int, net.Destination, error) {
	return copy(b, "x"), p.dest, nil
}
func (p *addressPacket) WritePacket(b []byte, d net.Destination) (int, error) {
	p.dest = d
	return len(b), nil
}
func TestPacketSenderAddressMappingKeepsOtherDestinations(t *testing.T) {
	original := net.DomainAddress("first.test")
	resolved := net.LocalHostIP
	p := &addressPacket{dest: net.UDPDestination(resolved, 100)}
	r := packetAddressReader{PacketReader: p, from: resolved, to: original}
	_, dest, err := r.ReadPacket(make([]byte, 8))
	if err != nil || dest.Address != original || dest.Port != 100 {
		t.Fatal(dest, err)
	}
	w := packetAddressWriter{PacketWriter: p, from: original, to: resolved}
	w.WritePacket([]byte("x"), dest)
	if p.dest.Address != resolved {
		t.Fatal(p.dest)
	}
	other := net.UDPDestination(net.DomainAddress("second.test"), 200)
	p.dest = other
	_, dest, err = r.ReadPacket(make([]byte, 8))
	if err != nil || dest != other {
		t.Fatal(dest, err)
	}
	w.WritePacket([]byte("x"), dest)
	if p.dest != other {
		t.Fatal(p.dest)
	}
}
