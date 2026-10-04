package xudp

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestXudpReadWrite(t *testing.T) {
	addr, _ := net.ParseDestination("tcp:127.0.0.1:1345")
	mb := make(buf.MultiBuffer, 0, 16)
	m := buf.MultiBufferContainer{
		MultiBuffer: mb,
	}
	var arr [8]byte
	writer := NewPacketWriter(&m, addr, arr)

	source := make(buf.MultiBuffer, 0, 16)
	b := buf.New()
	b.WriteByte('a')
	b.UDP = &addr
	source = append(source, b)
	writer.WriteMultiBuffer(source)

	reader := NewPacketReader(&m)
	dest, err := reader.ReadMultiBuffer()
	common.Must(err)
	if dest[0].Byte(0) != 'a' {
		t.Error("failed to parse xudp buffer")
	}
	if dest[0].UDP.Port != 1345 {
		t.Error("failed to parse xudp buffer")
	}
}

func TestPacketWriter(t *testing.T) {
	dest := net.UDPDestination(net.IPAddress([]byte{1, 2, 3, 4}), 443)

	// A Keep frame to an IPv4 address has 16 bytes ahead of its payload.
	// A following one shares the Buffer if it fits with 268 bytes ahead of its payload.
	for _, c := range []struct {
		sizes   []int32
		buffers int
	}{
		{[]int32{1200}, 1},
		{[]int32{1200, 1200, 1200, 1200, 1200, 1200}, 1}, // was 6
		{[]int32{1200, 1200, 1200, 1200, 1200, 1200, 1200}, 2},
		{[]int32{7526, 382}, 1},
		{[]int32{7526, 383}, 2},
		{[]int32{7527}, 0}, // too large, as before
	} {
		var m buf.MultiBufferContainer
		var mb buf.MultiBuffer
		for i, size := range c.sizes {
			b := buf.New()
			b.Write(bytes.Repeat([]byte{byte(i + 1)}, int(size)))
			b.UDP = &net.Destination{Network: net.Network_UDP, Address: dest.Address, Port: net.Port(i + 1)}
			mb = append(mb, b)
		}
		// no target, so that all the frames are Keep ones, which PacketReader takes
		common.Must(NewPacketWriter(&m, net.Destination{}, [8]byte{}).WriteMultiBuffer(mb))
		if len(m.MultiBuffer) != c.buffers {
			t.Errorf("%v: %d Buffers, want %d", c.sizes, len(m.MultiBuffer), c.buffers)
		}

		reader := NewPacketReader(&m)
		for i, size := range c.sizes {
			if size+666 > buf.Size {
				continue
			}
			mb, err := reader.ReadMultiBuffer()
			common.Must(err)
			if b := mb[0]; !bytes.Equal(b.Bytes(), bytes.Repeat([]byte{byte(i + 1)}, int(size))) || b.UDP.Port != net.Port(i+1) {
				t.Errorf("%v: packet %d came out wrong, to %v", c.sizes, i, b.UDP)
			}
			buf.ReleaseMulti(mb)
		}
	}
}
