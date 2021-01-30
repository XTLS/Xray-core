package outbound

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
	"time"
)

type OutboundConn struct {
	conn            net.Conn
	header          *protocol.RequestHeader
	isHeaderWritten bool
	isHeaderRead    bool
	addrParser      protocol.AddressSerializer
}

func NewOutboundConn(conn net.Conn, header *protocol.RequestHeader) *OutboundConn {
	return &OutboundConn{
		conn:            conn,
		header:          header,
		isHeaderWritten: false,
		isHeaderRead:    false,
		addrParser: protocol.NewAddressParser(
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
			protocol.PortThenAddress(),
		),
	}
}

func (c *OutboundConn) writeHeader() error {
	buffer := buf.StackNew()
	defer buffer.Release()

	// Write version number
	if err := buffer.WriteByte(c.header.Version); err != nil {
		return err
	}

	// Write UUID
	if _, err := buffer.Write(c.header.User.Account.(*vless.MemoryAccount).ID.Bytes()); err != nil {
		return err
	}

	// Write addon - default to 0 for now
	if err := buffer.WriteByte(0); err != nil {
		return err
	}

	// Write Protobuf
	// pass

	// Write command byte
	if err := buffer.WriteByte(byte(c.header.Command)); err != nil {
		return err
	}

	// Write port number and address
	if err := c.addrParser.WriteAddressPort(&buffer, c.header.Address, c.header.Port); err != nil {
		return newError("failed to write address and port").Base(err)
	}

	// Write header to connection
	_, err := c.conn.Write(buffer.Bytes())
	if err != nil {
		return newError("failed to write header").Base(err).AtError()
	}
	c.isHeaderWritten = true
	return nil
}

func (c *OutboundConn) readHeader() error {
	buffer := make([]byte, 2)
	if _, err := c.conn.Read(buffer); err != nil {
		return err
	}
	version := buffer[0]
	if version != c.header.Version {
		return newError("incorrect VLESS protocol version")
	}
	c.isHeaderRead = true
	return nil
}

func (c *OutboundConn) Write(b []byte) (int, error) {
	if !c.isHeaderWritten {
		if err := c.writeHeader(); err != nil {
			return 0, err
		}
	}
	n, err := c.conn.Write(b)
	return n, err
}

func (c *OutboundConn) Read(b []byte) (int, error) {
	if !c.isHeaderRead {
		if err := c.readHeader(); err != nil {
			return 0, err
		}
	}
	n, err := c.conn.Read(b)
	return n, err
}

func (c *OutboundConn) Close() error {
	return c.conn.Close()
}

func (c *OutboundConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *OutboundConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *OutboundConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *OutboundConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *OutboundConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
