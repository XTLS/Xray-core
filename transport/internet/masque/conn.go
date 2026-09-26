package masque

import (
	"context"
	go_errors "errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
)

type PacketTooBigError struct {
	ICMP []byte
}

func (e *PacketTooBigError) Error() string {
	return "packet too big for the tunnel"
}

type httpConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type quicConn struct {
	*quic.Conn
}

func (c quicConn) Close() error {
	return c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
}

type Conn struct {
	ipConn    *connectip.Conn
	httpConn  httpConn
	local     []netip.Addr
	closeOnce sync.Once
}

func (c *Conn) LocalAddrs() []netip.Addr {
	return c.local
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.ipConn.ReadPacket(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	icmp, err := c.ipConn.WritePacket(b)
	if err != nil {
		if go_errors.Is(err, connectip.ErrMTUTooSmall) {
			errors.LogWarning(context.Background(), "MASQUE: closing the tunnel as it cannot carry ", MinPacketSize, "-byte packets")
		} else {
			errors.LogInfoInner(context.Background(), err, "MASQUE: closing the tunnel as sending failed")
		}
		c.Close()
		return 0, err
	}
	if len(icmp) > 0 {
		return 0, &PacketTooBigError{ICMP: icmp}
	}
	return len(b), nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.ipConn.Close()
		c.httpConn.Close()
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.httpConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.httpConn.RemoteAddr()
}

func (c *Conn) SetDeadline(time.Time) error {
	return nil
}

func (c *Conn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *Conn) serveAddressAssignments() {
	for {
		assigned, err := c.ipConn.ReceiveAddressAssignment(context.Background())
		if err != nil {
			return
		}
		for _, addr := range c.local {
			if !slices.ContainsFunc(assigned, func(a connectip.AssignedAddress) bool { return !a.Rejected() && a.IPPrefix.Contains(addr) }) {
				errors.LogInfo(context.Background(), "MASQUE: closing the tunnel as the proxy withdrew ", addr)
				c.Close()
				return
			}
		}
		if len(localAddrs(assigned)) > len(c.local) {
			errors.LogInfo(context.Background(), "MASQUE: the proxy assigned another IP family, which is used once the tunnel is set up again")
		}
	}
}

func (c *Conn) serveAddressRequests() {
	for {
		req, err := c.ipConn.ReceiveAddressRequest(context.Background())
		if err != nil {
			return
		}
		if err := req.Respond(make([]netip.Prefix, len(req.Prefixes)), nil); err != nil {
			return
		}
	}
}
