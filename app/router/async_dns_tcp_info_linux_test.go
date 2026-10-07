//go:build linux

package router

import (
	"net"
	"testing"
)

func TestAsyncDNSTCPInfoExistingSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	info := asyncDNSReadTCPInfo(c)
	if info.Status != "available" || info.TotalRetrans < 0 || info.RTTMicros < 0 {
		t.Fatalf("TCP_INFO %+v", info)
	}
	// The observational read must leave the original connection usable.
	go p.Write([]byte{1})
	b := make([]byte, 1)
	if _, err := c.Read(b); err != nil || b[0] != 1 {
		t.Fatal("connection changed")
	}
}
