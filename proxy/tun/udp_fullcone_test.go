package tun

import (
	"io"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/xudp"
)

// newTestUDPConn returns the udpConn of a flow that got the given number of packets,
// each one to its own port and starting with its number.
func newTestUDPConn(packets int, size int) *udpConn {
	conns := make(chan *udpConn, 1)
	handler := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) { conns <- conn.(*udpConn) }, nil)
	src := net.UDPDestination(net.LocalHostIP, 12345)
	for i := 0; i < packets; i++ {
		data := make([]byte, size)
		data[0] = byte(i)
		handler.HandlePacket(src, net.UDPDestination(net.LocalHostIP, net.Port(1000+i)), data)
	}
	return <-conns
}

func TestUDPConnReadsWhatIsQueued(t *testing.T) {
	conn := newTestUDPConn(12, 100)
	// one that gets dropped; what is queued is still read after Close
	conn.handler.HandlePacket(conn.src, conn.dst, make([]byte, buf.Size+1))
	conn.Close()

	next := 0
	for _, want := range []int{1, 8, 3} { // the first read is the one that sniffing looks at
		mb, err := conn.ReadMultiBuffer()
		common.Must(err)
		if len(mb) != want {
			t.Fatalf("read %d packets, want %d", len(mb), want)
		}
		for _, b := range mb {
			if b.Byte(0) != byte(next) || b.UDP.Port != net.Port(1000+next) {
				t.Errorf("packet %d came out as %d to %v", next, b.Byte(0), b.UDP)
			}
			next++
		}
		buf.ReleaseMulti(mb)
	}
	if _, err := conn.ReadMultiBuffer(); err != io.EOF {
		t.Error("read from a closed conn: ", err)
	}
}

func TestUDPConnBurstToXUDP(t *testing.T) {
	conn := newTestUDPConn(7, 1200)
	conn.Close()

	var m buf.MultiBufferContainer
	reader := &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)} // as in HandleConnection
	common.Must(buf.Copy(reader, xudp.NewPacketWriter(&m, conn.dst, [8]byte{})))
	// the first packet, then the other 6 in one Buffer: 24 + 1200 and 6 * (16 + 1200) bytes
	if len(m.MultiBuffer) != 2 || m.MultiBuffer.Len() != 1224+7296 {
		t.Errorf("%d Buffers of %d bytes, want 2 of %d", len(m.MultiBuffer), m.MultiBuffer.Len(), 1224+7296)
	}
}
