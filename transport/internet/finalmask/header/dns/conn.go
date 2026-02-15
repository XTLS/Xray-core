package dns

import (
	"context"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
)

func packDomainName(s string, msg []byte) (off1 int, err error) {
	off := 0
	ls := len(s)
	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin int
		bs    []byte
	)
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), errors.New("buffer size too small")
			}

			if bs == nil {
				bs = []byte(s)
			}

			copy(bs[i:ls-1], bs[i+1:])
			ls--
		case '.':
			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return len(msg), errors.New("bad rdata")
			}

			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1+labelLen > len(msg) {
				return len(msg), errors.New("buffer size too small")
			}

			// The following is covered by the length check above.
			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen
			begin = i + 1
		default:
		}
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

type dns struct {
	header []byte
}

func (h *dns) Size() int32 {
	return int32(len(h.header))
}

func (h *dns) Serialize(b []byte) {
	copy(b, h.header)
	binary.BigEndian.PutUint16(b[0:], dice.RollUint16())
}

type dnsConn struct {
	first     bool
	leaveSize int32

	net.PacketConn
	header *dns

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	var header []byte
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Transaction ID
	header = binary.BigEndian.AppendUint16(header, 0x0100) // Flags: Standard query
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Questions
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Answer RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Authority RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Additional RRs
	buf := make([]byte, 0x100)
	off1, err := packDomainName(c.Domain+".", buf)
	if err != nil {
		return nil, err
	}
	header = append(header, buf[:off1]...)
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Type: A
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Class: IN

	conn := &dnsConn{
		first:     first,
		leaveSize: leaveSize,

		PacketConn: raw,
		header: &dns{
			header: header,
		},
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *dnsConn) Size() int32 {
	return c.header.Size()
}

func (c *dnsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

			copy(p, c.readBuf[c.Size():n])

			if len(p) < n-int(c.Size()) {
				c.readMutex.Unlock()
				return len(p), addr, io.ErrShortBuffer
			}

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

	copy(p, p[c.Size():n])

	return n - int(c.Size()), addr, nil
}

func (c *dnsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		c.header.Serialize(c.writeBuf[c.leaveSize : c.leaveSize+c.Size()])

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

	c.header.Serialize(p[c.leaveSize : c.leaveSize+c.Size()])

	return c.PacketConn.WriteTo(p, addr)
}
