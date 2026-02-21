package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
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

func (h *dns) Size() int {
	return len(h.header)
}

func (h *dns) Serialize(b []byte) {
	copy(b, h.header)
	binary.BigEndian.PutUint16(b[0:], dice.RollUint16())
}

type dnsConn struct {
	net.PacketConn
	header *dns
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
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
		PacketConn: raw,
		header: &dns{
			header: header,
		},
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *dnsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	if len(p) < finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	}

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if n < c.header.Size() {
		errors.LogDebug(context.Background(), addr, " mask read err header mismatch")
		return 0, addr, nil
	}

	if len(p) < n-c.header.Size() {
		errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", n-c.header.Size())
		return 0, addr, io.ErrShortBuffer
	}

	copy(p, buf[c.header.Size():n])

	return n - c.header.Size(), addr, nil
}

func (c *dnsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.header.Size()+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", c.header.Size()+len(p), " ", finalmask.UDPSize)
		return 0, io.ErrShortWrite
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:c.header.Size()+len(p)]
	}

	copy(buf[c.header.Size():], p)
	c.header.Serialize(buf)

	_, err = c.PacketConn.WriteTo(buf[:c.header.Size()+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
