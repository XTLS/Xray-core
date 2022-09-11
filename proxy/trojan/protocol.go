package trojan

import (
	"context"
	"encoding/binary"
	fmt "fmt"
	"io"
	"runtime"
	"syscall"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/xtls"
)

var (
	crlf = []byte{'\r', '\n'}

	addrParser = protocol.NewAddressParser(
		protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
		protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
		protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
	)

	xtls_show = false
)

const (
	maxLength = 8192
	// XRS is constant for XTLS splice mode
	XRS = "xtls-rprx-splice"
	// XRD is constant for XTLS direct mode
	XRD = "xtls-rprx-direct"
	// XRO is constant for XTLS origin mode
	XRO = "xtls-rprx-origin"

	commandTCP byte = 1
	commandUDP byte = 3

	// for XTLS
	commandXRD byte = 0xf0 // XTLS direct mode
	commandXRO byte = 0xf1 // XTLS origin mode
)

// ConnWriter is TCP Connection Writer Wrapper for trojan protocol
type ConnWriter struct {
	io.Writer
	Target     net.Destination
	Account    *MemoryAccount
	Flow       string
	headerSent bool
}

// Write implements io.Writer
func (c *ConnWriter) Write(p []byte) (n int, err error) {
	if !c.headerSent {
		if err := c.writeHeader(); err != nil {
			return 0, newError("failed to write request header").Base(err)
		}
	}

	return c.Writer.Write(p)
}

// WriteMultiBuffer implements buf.Writer
func (c *ConnWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	for _, b := range mb {
		if !b.IsEmpty() {
			if _, err := c.Write(b.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *ConnWriter) writeHeader() error {
	buffer := buf.StackNew()
	defer buffer.Release()

	command := commandTCP
	if c.Target.Network == net.Network_UDP {
		command = commandUDP
	} else if c.Flow == XRD {
		command = commandXRD
	} else if c.Flow == XRO {
		command = commandXRO
	}

	if _, err := buffer.Write(c.Account.Key); err != nil {
		return err
	}
	if _, err := buffer.Write(crlf); err != nil {
		return err
	}
	if err := buffer.WriteByte(command); err != nil {
		return err
	}
	if err := addrParser.WriteAddressPort(&buffer, c.Target.Address, c.Target.Port); err != nil {
		return err
	}
	if _, err := buffer.Write(crlf); err != nil {
		return err
	}

	_, err := c.Writer.Write(buffer.Bytes())
	if err == nil {
		c.headerSent = true
	}

	return err
}

// PacketWriter UDP Connection Writer Wrapper for trojan protocol
type PacketWriter struct {
	io.Writer
	Target net.Destination
}

// WriteMultiBuffer implements buf.Writer
func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		target := &w.Target
		if b.UDP != nil {
			target = b.UDP
		}
		if _, err := w.writePacket(b.Bytes(), *target); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

func (w *PacketWriter) writePacket(payload []byte, dest net.Destination) (int, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	length := len(payload)
	lengthBuf := [2]byte{}
	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	if err := addrParser.WriteAddressPort(&buffer, dest.Address, dest.Port); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(lengthBuf[:]); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(crlf); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(payload); err != nil {
		return 0, err
	}
	_, err := w.Write(buffer.Bytes())
	if err != nil {
		return 0, err
	}

	return length, nil
}

// ConnReader is TCP Connection Reader Wrapper for trojan protocol
type ConnReader struct {
	io.Reader
	Target       net.Destination
	Flow         string
	headerParsed bool
}

// ParseHeader parses the trojan protocol header
func (c *ConnReader) ParseHeader() error {
	var crlf [2]byte
	var command [1]byte
	var hash [56]byte
	if _, err := io.ReadFull(c.Reader, hash[:]); err != nil {
		return newError("failed to read user hash").Base(err)
	}

	if _, err := io.ReadFull(c.Reader, crlf[:]); err != nil {
		return newError("failed to read crlf").Base(err)
	}

	if _, err := io.ReadFull(c.Reader, command[:]); err != nil {
		return newError("failed to read command").Base(err)
	}

	network := net.Network_TCP
	if command[0] == commandUDP {
		network = net.Network_UDP
	} else if command[0] == commandXRD {
		c.Flow = XRD
	} else if command[0] == commandXRO {
		c.Flow = XRO
	}

	addr, port, err := addrParser.ReadAddressPort(nil, c.Reader)
	if err != nil {
		return newError("failed to read address and port").Base(err)
	}
	c.Target = net.Destination{Network: network, Address: addr, Port: port}

	if _, err := io.ReadFull(c.Reader, crlf[:]); err != nil {
		return newError("failed to read crlf").Base(err)
	}

	c.headerParsed = true
	return nil
}

// Read implements io.Reader
func (c *ConnReader) Read(p []byte) (int, error) {
	if !c.headerParsed {
		if err := c.ParseHeader(); err != nil {
			return 0, err
		}
	}

	return c.Reader.Read(p)
}

// ReadMultiBuffer implements buf.Reader
func (c *ConnReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, err := b.ReadFrom(c)
	return buf.MultiBuffer{b}, err
}

// PacketReader is UDP Connection Reader Wrapper for trojan protocol
type PacketReader struct {
	io.Reader
}

// ReadMultiBuffer implements buf.Reader
func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	addr, port, err := addrParser.ReadAddressPort(nil, r)
	if err != nil {
		return nil, newError("failed to read address and port").Base(err)
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, newError("failed to read payload length").Base(err)
	}

	remain := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if remain > maxLength {
		return nil, newError("oversize payload")
	}

	var crlf [2]byte
	if _, err := io.ReadFull(r, crlf[:]); err != nil {
		return nil, newError("failed to read crlf").Base(err)
	}

	dest := net.UDPDestination(addr, port)
	var mb buf.MultiBuffer
	for remain > 0 {
		length := buf.Size
		if remain < length {
			length = remain
		}

		b := buf.New()
		b.UDP = &dest
		mb = append(mb, b)
		n, err := b.ReadFullFrom(r, int32(length))
		if err != nil {
			buf.ReleaseMulti(mb)
			return nil, newError("failed to read payload").Base(err)
		}

		remain -= int(n)
	}

	return mb, nil
}

func ReadV(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn *xtls.Conn, rawConn syscall.RawConn, counter stats.Counter, sctx context.Context) error {
	err := func() error {
		var ct stats.Counter
		for {
			if conn.DirectIn {
				conn.DirectIn = false
				if sctx != nil {
					if inbound := session.InboundFromContext(sctx); inbound != nil && inbound.Conn != nil {
						iConn := inbound.Conn
						statConn, ok := iConn.(*stat.CounterConnection)
						if ok {
							iConn = statConn.Connection
						}
						if xc, ok := iConn.(*xtls.Conn); ok {
							iConn = xc.NetConn()
						}
						if tc, ok := iConn.(*net.TCPConn); ok {
							if conn.SHOW {
								fmt.Println(conn.MARK, "Splice")
							}
							runtime.Gosched() // necessary
							w, err := tc.ReadFrom(conn.NetConn())
							if counter != nil {
								counter.Add(w)
							}
							if statConn != nil && statConn.WriteCounter != nil {
								statConn.WriteCounter.Add(w)
							}
							return err
						} else {
							panic("XTLS Splice: not TCP inbound")
						}
					} else {
						// panic("XTLS Splice: nil inbound or nil inbound.Conn")
					}
				}
				reader = buf.NewReadVReader(conn.NetConn(), rawConn, nil)
				ct = counter
				if conn.SHOW {
					fmt.Println(conn.MARK, "ReadV")
				}
			}
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				if ct != nil {
					ct.Add(int64(buffer.Len()))
				}
				timer.Update()
				if werr := writer.WriteMultiBuffer(buffer); werr != nil {
					return werr
				}
			}
			if err != nil {
				return err
			}
		}
	}()
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}
