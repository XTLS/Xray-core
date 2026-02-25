package salamander

import (
	"context"
	"io"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type salamanderConn struct {
	net.PacketConn
	obfs *SalamanderObfuscator
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, errors.New("salamander err").Base(err)
	}

	conn := &salamanderConn{
		PacketConn: raw,
		obfs:       ob,
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *salamanderConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	if len(p) < finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	}

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if n < smSaltLen {
		errors.LogDebug(context.Background(), addr, " mask read err short lenth ", n)
		return 0, addr, nil
	}

	if len(p) < n-smSaltLen {
		errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", n-smSaltLen)
		return 0, addr, nil
	}

	c.obfs.Deobfuscate(buf[:n], p)

	return n - smSaltLen, addr, nil
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if smSaltLen+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", smSaltLen+len(p), " ", finalmask.UDPSize)
		return 0, io.ErrShortWrite
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:smSaltLen+len(p)]
		copy(buf[smSaltLen:], p)
		p = buf[smSaltLen:]
	}

	c.obfs.Obfuscate(p, buf)

	_, err = c.PacketConn.WriteTo(buf[:smSaltLen+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
