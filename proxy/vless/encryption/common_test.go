package encryption_test

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/xtls/xray-core/proxy/vless/encryption"
)

func newConn(conn net.Conn) *encryption.CommonConn {
	c := encryption.NewCommonConn(conn, true)
	c.UnitedKey = make([]byte, 32)
	c.AEAD = encryption.NewAEAD(nil, c.UnitedKey, true)
	c.PeerAEAD = encryption.NewAEAD(nil, c.UnitedKey, true)
	return c
}

func TestCommonConnRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	// Longer than one 8192-byte record.
	payload := bytes.Repeat([]byte("0123456789"), 2000)
	written := make(chan error, 1)
	go func() {
		_, err := newConn(left).Write(payload)
		written <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(newConn(right), got); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("payload changed in transit")
	}
}

// discardConn takes every write.
type discardConn struct{ net.Conn }

func (discardConn) Write(b []byte) (int, error) { return len(b), nil }

func TestCommonConnWriteAllocs(t *testing.T) {
	c := newConn(discardConn{})
	payload := make([]byte, 20000)
	if n := testing.AllocsPerRun(100, func() { c.Write(payload) }); n != 0 {
		t.Errorf("Write: %v allocs", n)
	}
}
