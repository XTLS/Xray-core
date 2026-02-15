package salamander

import (
	"context"
	go_errors "errors"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type obfsPacketConn struct {
	first     bool
	leaveSize int32

	net.PacketConn
	obfs *SalamanderObfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, errors.New("salamander err").Base(err)
	}

	conn := &obfsPacketConn{
		first:     first,
		leaveSize: leaveSize,

		PacketConn: raw,
		obfs:       ob,
	}

	if first {
		conn.readBuf = make([]byte, finalmask.UDPSize)
		conn.writeBuf = make([]byte, finalmask.UDPSize)
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *obfsPacketConn) Size() int32 {
	return smSaltLen
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		for {
			n, addr, err = c.PacketConn.ReadFrom(c.readBuf)
			if err != nil {
				var ne net.Error
				if go_errors.As(err, &ne) {
					c.readMutex.Unlock()
					return n, addr, err
				}
				errors.LogDebug(context.Background(), addr, " mask read err ", err)
				continue
			}

			if n < int(c.Size()) {
				errors.LogDebug(context.Background(), addr, " mask read err short lenth")
				continue
			}

			if len(p) < n-int(c.Size()) {
				errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", n-int(c.Size()))
				continue
			}

			c.obfs.Deobfuscate(c.readBuf[:n], p)

			c.readMutex.Unlock()
			return n - int(c.Size()), addr, nil
		}
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("short lenth")
	}

	c.obfs.Deobfuscate(p[:n], p)

	return n - int(c.Size()), addr, err
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > finalmask.UDPSize {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		c.obfs.Obfuscate(c.writeBuf[c.leaveSize+c.Size():n], c.writeBuf[c.leaveSize:n])

		nn, err := c.PacketConn.WriteTo(c.writeBuf[:n], addr)

		if err != nil {
			c.writeMutex.Unlock()
			return 0, err
		}

		if nn != n {
			c.writeMutex.Unlock()
			return 0, errors.New("nn != n")
		}

		c.writeMutex.Unlock()
		return len(p), nil
	}

	c.obfs.Obfuscate(p[c.leaveSize+c.Size():], p[c.leaveSize:])

	return c.PacketConn.WriteTo(p, addr)
}
