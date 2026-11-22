package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type recordConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *recordConn) Write(b []byte) (int, error) { return c.written.Write(b) }

type recordWriter struct{ mb buf.MultiBuffer }

func (w *recordWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mb = append(w.mb, mb...)
	return nil
}

func tlsRecord(typ byte, n int) []byte {
	r := make([]byte, 5+n)
	r[0], r[1], r[2], r[3], r[4] = typ, 3, 3, byte(n>>8), byte(n)
	rand.Read(r[5:])
	return r
}

func toMultiBuffer(b []byte) buf.MultiBuffer {
	var mb buf.MultiBuffer
	for len(b) > 0 {
		x := buf.New()
		n, _ := x.Write(b[:min(len(b), buf.Size)])
		b = b[n:]
		mb = append(mb, x)
	}
	return mb
}

// https://github.com/XTLS/Xray-core/issues/7164
func TestVisionWriterSwitchesOnBackToBackRecords(t *testing.T) {
	uuid := make([]byte, 16)
	rand.Read(uuid)

	// what the sender writes after its own handshake messages, then full-size
	// application data records with no pause in between
	up := append(tlsRecord(0x14, 1), tlsRecord(0x17, 53)...) // client: ChangeCipherSpec + Finished
	down := tlsRecord(0x16, 1679)                            // server: ServerHello and the rest of its flight
	for range 8 {
		up = append(up, tlsRecord(0x17, 16401)...)
		down = append(down, tlsRecord(0x17, 16401)...)
	}

	cases := []struct {
		name    string
		stream  []byte
		batches []int // then 64 KiB each
		want    int   // where the padding should end
	}{
		{"upload, first batch ends on the boundary", up, []int{64}, 64},
		{"upload, 8 KiB first batch", up, []int{8192}, 64},
		{"upload, boundary inside a short batch", up, []int{100}, 64},
		{"download, records cut by every batch", down, []int{1684, 8192, 16384}, 1684 + 16406},
		{"download, 64 KiB batches", down, []int{1684}, 1684 + 3*16406},
	}
	for _, c := range cases {
		state := NewTrafficState(uuid)
		state.NumberOfPacketToFilter = 0
		state.IsTLS, state.IsTLS12orAbove, state.EnableXtls = true, true, true

		padded, raw := &recordWriter{}, &recordConn{}
		w := NewVisionWriter(padded, state, true, context.Background(), raw, nil, nil)
		for i, j := 0, 0; i < len(c.stream); j++ {
			n := 65536
			if j < len(c.batches) {
				n = c.batches[j]
			}
			n = min(n, len(c.stream)-i)
			if err := w.WriteMultiBuffer(toMultiBuffer(c.stream[i : i+n])); err != nil {
				t.Fatal(err)
			}
			i += n
		}

		reader := NewTrafficState(uuid)
		var content []byte
		for _, b := range padded.mb {
			content = append(content, XtlsUnpadding(b, reader, true, context.Background()).Bytes()...)
		}
		if reader.Inbound.CurrentCommand != int(CommandPaddingDirect) {
			t.Errorf("%s: padding did not end with CommandPaddingDirect", c.name)
		}
		if len(content) != c.want {
			t.Errorf("%s: padding ended at %d, want %d", c.name, len(content), c.want)
		}
		if !bytes.Equal(append(content, raw.written.Bytes()...), c.stream) {
			t.Errorf("%s: padded %d + raw %d bytes do not match the stream", c.name, len(content), raw.written.Len())
		}
	}
}

func TestTlsRecordEnd(t *testing.T) {
	hs := tlsRecord(0x16, 100)
	ad := tlsRecord(0x17, 100)
	join := func(b ...[]byte) []byte { return bytes.Join(b, nil) }
	cases := []struct {
		name           string
		data           []byte
		skip           int32
		typ            byte
		end, remaining int32
		lastType       byte
	}{
		{"aligned", join(ad, ad), 0, 0, 210, 0, 0x17},
		{"cut", join(ad, ad[:50]), 0, 0, 105, 55, 0x17},
		{"carried data", join(ad[60:], ad), 45, 0x17, 150, 0, 0x17},
		{"carried data, cut", join(ad[60:], ad[:50]), 45, 0x17, 45, 55, 0x17},
		{"carried handshake", join(hs[60:], ad), 45, 0x16, 0, 0, 0x17},
		{"inside a record", ad[:50], 80, 0x17, 0, 30, 0x17},
		{"handshake", join(hs, ad), 0, 0, 0, 0, 0x17},
		{"cut header", join(ad, ad[:3]), 0, 0, 105, -1, 0},
		{"not tls", []byte("GET / HTTP/1.1\r\n\r\n"), 0, 0, 0, -1, 0},
	}
	for _, c := range cases {
		end, remaining, lastType := tlsRecordEnd(toMultiBuffer(c.data), c.skip, c.typ)
		if end != c.end || remaining != c.remaining || lastType != c.lastType {
			t.Errorf("%s: got (%d, %d, %#x), want (%d, %d, %#x)", c.name, end, remaining, lastType, c.end, c.remaining, c.lastType)
		}
	}
}
