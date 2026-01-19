package obfs

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type obfsPacketConn struct {
	first     bool
	leaveSize int32

	conn net.PacketConn
	obfs *SalamanderObfuscator
}

func NewConnClient(password string, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(password))
	if err != nil {
		return nil, errors.New("salamander err").Base(err)
	}
	return &obfsPacketConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		obfs: ob,
	}, nil
}

func NewConnServer(password string, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(password, raw, first, leaveSize)
}

func (c *obfsPacketConn) Size() int32 {
	return smSaltLen
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) && (len(p) != 8192) {
		b := buf.StackNew()
		defer b.Release()
		bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
	}

	n, addr, err = c.conn.ReadFrom(bufp)
	if err != nil {
		return n, addr, err
	}

	nn := c.obfs.Deobfuscate(bufp[:n], p)
	if nn == 0 {
		return 0, addr, errors.New("nn == 0")
	}

	return nn, addr, err
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	data := p
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) {
		if len(p) != 8192 {
			b := buf.StackNew()
			defer b.Release()
			bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
		}
		copy(bufp[c.leaveSize+c.Size():], p)
	} else {
		data = p[c.leaveSize+c.Size():]
	}

	nn := c.obfs.Obfuscate(data, bufp[c.leaveSize:])
	if nn == 0 {
		return 0, errors.New("nn == 0")
	}
	nn += int(c.leaveSize)

	if _, err := c.conn.WriteTo(bufp[:nn], addr); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *obfsPacketConn) Close() error {
	return c.conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
