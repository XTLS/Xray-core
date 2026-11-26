package hysteria

import (
	"bytes"
	"io"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// datagramReader returns one datagram per Read, like a QUIC datagram stream.
type datagramReader struct {
	msgs [][]byte
}

func (r *datagramReader) Read(p []byte) (int, error) {
	if len(r.msgs) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.msgs[0])
	r.msgs = r.msgs[1:]
	return n, nil
}

func newTestReader(msgs []UDPMessage) *UDPReader {
	datagrams := make([][]byte, len(msgs))
	for i := range msgs {
		datagrams[i] = make([]byte, msgs[i].Size())
		msgs[i].Serialize(datagrams[i])
	}
	return &UDPReader{reader: &datagramReader{msgs: datagrams}, df: &Defragger{}}
}

func TestUDPReaderFragments(t *testing.T) {
	want := &UDPMessage{PacketID: 1, Addr: "example.com:443", Data: bytes.Repeat([]byte("0123456789"), 20)}
	frags := FragUDPMessage(want, 100)
	if len(frags) < 2 {
		t.Fatalf("got %d fragments, want at least 2", len(frags))
	}

	p := make([]byte, buf.Size)
	n, dest, err := newTestReader(frags).ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if dest.NetAddr() != want.Addr || !bytes.Equal(p[:n], want.Data) {
		t.Errorf("got %q to %v, want %q to %s", p[:n], dest, want.Data, want.Addr)
	}
}

func TestUDPReaderDestinations(t *testing.T) {
	msgs := []UDPMessage{
		{Addr: "203.0.113.1:53", Data: []byte("first")},
		{Addr: "203.0.113.1:53", Data: []byte("second")},
		{Addr: "203.0.113.2:53", Data: []byte("third")},
	}
	r := newTestReader(msgs)
	p := make([]byte, buf.Size)
	for i, want := range msgs {
		n, dest, err := r.ReadFrom(p)
		if err != nil {
			t.Fatal(err)
		}
		if dest.NetAddr() != want.Addr || !bytes.Equal(p[:n], want.Data) {
			t.Errorf("packet %d: got %q to %v, want %q to %s", i, p[:n], dest, want.Data, want.Addr)
		}
		// Callers rewrite the destination in place, the next packet must not see it.
		dest.Port = 5353
	}
}

type captureWriter struct {
	writes [][]byte
}

func (w *captureWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, bytes.Clone(p))
	return len(p), nil
}

func TestUDPWriterAddress(t *testing.T) {
	ip := xnet.UDPDestination(xnet.ParseAddress("203.0.113.1"), 53)
	domain := xnet.UDPDestination(xnet.DomainAddress("example.com"), 53)

	cw := &captureWriter{}
	w := &UDPWriter{writer: cw, addr: "198.51.100.1:1"}
	for _, tc := range []struct {
		udp  *xnet.Destination
		want string
	}{
		{&ip, "203.0.113.1:53"},
		{&domain, "example.com:53"},
		{nil, "198.51.100.1:1"},
		{&ip, "203.0.113.1:53"},
	} {
		b := buf.FromBytes([]byte("data"))
		b.UDP = tc.udp
		if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
		msg, err := ParseUDPMessage(cw.writes[len(cw.writes)-1])
		if err != nil {
			t.Fatal(err)
		}
		if msg.Addr != tc.want {
			t.Errorf("address = %q, want %q", msg.Addr, tc.want)
		}
	}
}

// fragmentingWriter rejects datagrams larger than max, like a QUIC connection.
type fragmentingWriter struct {
	max    int
	writes [][]byte
}

func (w *fragmentingWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(w.max)}
	}
	w.writes = append(w.writes, bytes.Clone(p))
	return len(p), nil
}

func TestUDPWriterFragmentation(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 20)
	fw := &fragmentingWriter{max: 100}
	w := &UDPWriter{writer: fw, addr: "example.com:443"}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(data)}); err != nil {
		t.Fatal(err)
	}
	if len(fw.writes) < 2 {
		t.Fatalf("got %d datagrams, want at least 2", len(fw.writes))
	}

	r := &UDPReader{reader: &datagramReader{msgs: fw.writes}, df: &Defragger{}}
	p := make([]byte, buf.Size)
	n, dest, err := r.ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if dest.NetAddr() != w.addr || !bytes.Equal(p[:n], data) {
		t.Errorf("got %q to %v, want %q to %s", p[:n], dest, data, w.addr)
	}
}
