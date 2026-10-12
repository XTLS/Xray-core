package xdns

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

func TestTCPResolverWritesLengthFrame(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	header := make(chan uint16, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err == nil {
			header <- binary.BigEndian.Uint16(prefix[:])
		}
	}()
	dialer := &finalmask.Dialer{DialTCP: func(dest xnet.Destination) (net.Conn, error) {
		return net.DialTimeout("tcp", dest.NetAddr(), time.Second)
	}}
	r, err := NewTCPResolver(&ResolverProto{Addr: listener.Addr().String()}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	query, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("resolver.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	r.Send(query)
	select {
	case got := <-header:
		if got != uint16(len(query)) {
			t.Fatalf("DNS frame length = %d, want %d", got, len(query))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP query did not contain a complete length prefix")
	}
}
