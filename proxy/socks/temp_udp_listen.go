package socks

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
)

func NewTempUDPConn(udpConn *net.UDPConn, tcpConn net.Conn) *TempUDPConn {
	return &TempUDPConn{
		UDPConn:          udpConn,
		AssociateTCPConn: tcpConn,
	}
}

// TempUDPConn wait for the first packet to determine the remote address
// SetTimeout MUST be called before any read/write operation
type TempUDPConn struct {
	*net.UDPConn
	AssociateTCPConn net.Conn

	timer           *signal.ActivityTimer
	firstPacketDone atomic.Bool
	remote          *net.UDPAddr
}

func (c *TempUDPConn) Read(b []byte) (n int, err error) {
	c.timer.Update()
	if c.firstPacketDone.CompareAndSwap(false, true) {
		n, remote, err := c.UDPConn.ReadFromUDP(b)
		c.remote = remote
		return n, err
	}
	for {
		n, remote, err := c.UDPConn.ReadFromUDP(b)
		if err != nil {
			return n, err
		}
		if remote.AddrPort() != c.remote.AddrPort() {
			continue
		}
		return n, err
	}
}

func (c *TempUDPConn) Write(b []byte) (n int, err error) {
	c.timer.Update()
	if c.remote == nil {
		return 0, errors.New("remote address not determined yet")
	}
	return c.UDPConn.WriteTo(b, c.remote)
}

func (c *TempUDPConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *TempUDPConn) SetTimeout(d time.Duration) {
	c.timer = signal.CancelAfterInactivity(context.Background(), func() {
		c.Close()
	}, d)
}

func (c *TempUDPConn) Close() error {
	c.timer.SetTimeout(0)
	c.AssociateTCPConn.Close()
	return c.UDPConn.Close()
}
