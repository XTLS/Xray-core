package socks

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
)

func NewTempUDPConn(udpConn net.PacketConn, tcpConn net.Conn, remoteIP string) *TempUDPConn {
	return &TempUDPConn{
		PacketConn:       udpConn,
		AssociateTCPConn: tcpConn,
		ExpectedRemoteIP: remoteIP,
	}
}

// TempUDPConn wait for the first packet to determine the remote address
// SetTimeout MUST be called before any read/write operation
type TempUDPConn struct {
	net.PacketConn
	AssociateTCPConn net.Conn
	ExpectedRemoteIP string

	timer  *signal.ActivityTimer
	remote atomic.Pointer[net.Addr]
}

func (c *TempUDPConn) Read(b []byte) (n int, err error) {
	c.timer.Update()
	var remote net.Addr
	for {
		n, remote, err = c.PacketConn.ReadFrom(b)
		if err != nil {
			break
		}
		if c.remote.Load() == nil {
			if remoteIP, _, _ := net.SplitHostPort(remote.String()); remoteIP == c.ExpectedRemoteIP {
				c.remote.CompareAndSwap(nil, &remote)
				break
			}
		} else if remote.String() == (*c.remote.Load()).String() {
			break
		}
	}
}

func (c *TempUDPConn) Write(b []byte) (n int, err error) {
	c.timer.Update()
	if c.remote.Load() == nil {
		return 0, errors.New("remote address not determined yet")
	}
	return c.PacketConn.WriteTo(b, *c.remote.Load())
}

func (c *TempUDPConn) RemoteAddr() net.Addr {
	if c.remote.Load() == nil {
		return nil
	}
	return *c.remote.Load()
}

func (c *TempUDPConn) SetTimeout(d time.Duration) {
	c.timer = signal.CancelAfterInactivity(context.Background(), func() {
		c.Close()
	}, d)
}

func (c *TempUDPConn) Close() error {
	c.timer.SetTimeout(0)
	c.AssociateTCPConn.Close()
	return c.PacketConn.Close()
}
