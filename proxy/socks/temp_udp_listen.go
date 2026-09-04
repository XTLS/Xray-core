package socks

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/signal"
)

func NewTempUDPConn(udpConn net.PacketConn, tcpConn net.Conn, expectedRemote *net.UDPAddr) *TempUDPConn {
	t := &TempUDPConn{
		PacketConn:        udpConn,
		AssociatedTCPConn: tcpConn,
	}
	t.ExpectedRemote.Store(expectedRemote)
	return t
}

// TempUDPConn wait for the first packet to determine the remote address
// SetTimeout MUST be called before any read/write operation
type TempUDPConn struct {
	net.PacketConn
	AssociatedTCPConn net.Conn
	ExpectedRemote    atomic.Pointer[net.UDPAddr]
	Timer             *signal.ActivityTimer
}

func (c *TempUDPConn) Read(b []byte) (n int, err error) {
	var remote net.Addr
	for {
		n, remote, err = c.PacketConn.ReadFrom(b)
		if err != nil {
			return
		}
		remote := remote.(*net.UDPAddr)
		expected := c.ExpectedRemote.Load()
		if remote.IP.Equal(expected.IP) {
			if remote.Port == expected.Port {
				c.Timer.Update()
				return
			}
			if expected.Port == 0 {
				c.ExpectedRemote.Store(remote)
				c.Timer.Update()
				return
			}
		}
	}
}

func (c *TempUDPConn) Write(b []byte) (n int, err error) {
	c.Timer.Update()
	return c.PacketConn.WriteTo(b, c.ExpectedRemote.Load())
}

func (c *TempUDPConn) RemoteAddr() net.Addr {
	return c.ExpectedRemote.Load()
}

func (c *TempUDPConn) SetTimeout(d time.Duration) {
	c.Timer = signal.CancelAfterInactivity(context.Background(), func() {
		c.Close()
	}, d)
}

func (c *TempUDPConn) Close() error {
	c.Timer.SetTimeout(0)
	c.AssociatedTCPConn.Close()
	return c.PacketConn.Close()
}
