package mux_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestWriterPacket(t *testing.T) {
	target := net.UDPDestination(net.LocalHostIP, 53)
	ipv4 := net.UDPDestination(net.IPAddress([]byte{1, 2, 3, 4}), 443)
	domain := net.UDPDestination(net.DomainAddress("example.com"), 443)
	dests := []*net.Destination{&ipv4, &domain, nil}

	// The first frame has 16 bytes ahead of its payload from a response writer and 24 from a client's one.
	// A following frame shares the Buffer if it fits with 268 bytes ahead of its payload.
	for _, c := range []struct {
		sizes   []int32
		buffers int
	}{
		{[]int32{1200}, 1}, // was 2
		{[]int32{1200, 1200, 1200, 1200, 1200, 1200}, 1},
		{[]int32{1200, 1200, 1200, 1200, 1200, 1200, 1200}, 2},
		{[]int32{7800, 100}, 1},
		{[]int32{7809, 100}, 2},
		{[]int32{8168}, 1},
		{[]int32{8177}, 2}, // the header, then the payload as it is
		{[]int32{100, 8192, 100}, 4},
	} {
		for _, client := range []bool{false, true} {
			var carrier buf.MultiBufferContainer
			writer := mux.NewResponseWriter(1, &carrier, protocol.TransferTypePacket)
			if client {
				writer = mux.NewWriter(1, target, &carrier, protocol.TransferTypePacket, [8]byte{1}, nil)
			}
			var mb buf.MultiBuffer
			for i, size := range c.sizes {
				b := buf.New()
				b.Write(bytes.Repeat([]byte{byte(i + 1)}, int(size)))
				b.UDP = dests[i%len(dests)]
				mb = append(mb, b)
			}
			common.Must(writer.WriteMultiBuffer(mb))
			if len(carrier.MultiBuffer) != c.buffers {
				t.Errorf("%v, client %v: %d Buffers, want %d", c.sizes, client, len(carrier.MultiBuffer), c.buffers)
			}

			reader := &buf.BufferedReader{Reader: &carrier}
			for i, size := range c.sizes {
				var meta mux.FrameMetadata
				common.Must(meta.Unmarshal(reader, false))
				mb, err := mux.NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
				common.Must(err)
				dest := dests[i%len(dests)]
				if client && i == 0 {
					dest = &target // a New frame carries the target of the session
				}
				b := mb[0]
				if !bytes.Equal(b.Bytes(), bytes.Repeat([]byte{byte(i + 1)}, int(size))) || (b.UDP == nil) != (dest == nil) || (dest != nil && *b.UDP != *dest) {
					t.Errorf("%v, client %v: packet %d to %v came out wrong, to %v", c.sizes, client, i, dest, b.UDP)
				}
				b.Release()
			}
		}
	}
}

// A session with a backlog must not get around the size limit of the carrier.
func TestWriterPacketLimit(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(64 * 1024))
	var mb buf.MultiBuffer
	for i := 0; i < 400; i++ {
		b := buf.New()
		b.Extend(1250)
		mb = append(mb, b)
	}
	go mux.NewResponseWriter(1, writer, protocol.TransferTypePacket).WriteMultiBuffer(mb)

	for left := int32(400 * (8 + 1250)); left > 0; {
		mb, err := reader.ReadMultiBuffer()
		common.Must(err)
		if mb.Len() > 64*1024+buf.Size {
			t.Fatal("the pipe held ", mb.Len(), " bytes")
		}
		left -= mb.Len()
		buf.ReleaseMulti(mb)
	}
}
