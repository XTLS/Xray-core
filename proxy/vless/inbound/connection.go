package inbound

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

type InboundConn struct {
	conn            net.Conn
	header          *protocol.RequestHeader
	isHeaderWritten bool
	isHeaderRead    bool
	validator       *vless.Validator
	addrParser      protocol.AddressSerializer
}

func NewInboundConn(conn net.Conn, validator *vless.Validator) *InboundConn {
	return &InboundConn{
		conn:            conn,
		header:          new(protocol.RequestHeader),
		isHeaderWritten: false,
		// TODO: set this to false so that the connection object can parse the header
		isHeaderRead: true,
		validator:    validator,
		addrParser: protocol.NewAddressParser(
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
			protocol.PortThenAddress(),
		),
	}
}

func (c *InboundConn) writeHeader() error {
	buffer := buf.StackNew()
	defer buffer.Release()

	// Write version number
	if err := buffer.WriteByte(c.header.Version); err != nil {
		return newError("failed to write response version").Base(err)
	}

	// Write addon size
	if err := buffer.WriteByte(0); err != nil {
		return newError("failed to write response addon size").Base(err)
	}

	// Write response header to connection
	if _, err := c.conn.Write(buffer.Bytes()); err != nil {
		return newError("failed to write response header").Base(err)
	}

	c.isHeaderWritten = true
	return nil
}

func (c *InboundConn) readHeader() error {
	buffer := buf.StackNew()
	defer buffer.Release()

	// Parse VLESS version number
	if _, err := buffer.ReadFullFrom(c.conn, 1); err != nil {
		return newError("failed to read request version").Base(err)
	}
	c.header.Version = buffer.Byte(0)
	buffer.Clear()

	// Parse header for version 1 of VLESS protocol
	switch c.header.Version {
	case 0:
		// Parse and validate UUID
		var id [16]byte
		if _, err := buffer.ReadFullFrom(c.conn, 16); err != nil {
			return newError("failed to read request user id").Base(err)
		}
		copy(id[:], buffer.Bytes())
		if c.header.User = c.validator.Get(id); c.header.User == nil {
			return newError("invalid request user id")
		}

		// Decode header addon - pass for now
		//requestAddons, err := DecodeHeaderAddons(&buffer, reader)
		//if err != nil {
		//	return newError("failed to decode request header addons").Base(err)
		//}
		_, _ = buffer.ReadFullFrom(c.conn, 1)

		// Parse VLESS command byte
		buffer.Clear()
		if _, err := buffer.ReadFullFrom(c.conn, 1); err != nil {
			return newError("failed to read request command").Base(err)
		}
		c.header.Command = protocol.RequestCommand(buffer.Byte(0))

		// Parse port and address
		buffer.Clear()
		switch c.header.Command {
		case protocol.RequestCommandMux:
			c.header.Address = net.DomainAddress("v1.mux.cool")
			c.header.Port = 0
		case protocol.RequestCommandTCP, protocol.RequestCommandUDP, protocol.RequestCommandSmux:
			if addr, port, err := addrParser.ReadAddressPort(&buffer, c.conn); err == nil {
				c.header.Address = addr
				c.header.Port = port
			}
		}
		if c.header.Address == nil {
			return newError("invalid request address")
		}
	default:
		return newError("invalid request version")
	}

	// Set header read
	c.isHeaderRead = true
	return nil
}

func (c *InboundConn) GetHeader() (*protocol.RequestHeader, error) {
	if !c.isHeaderRead {
		if err := c.readHeader(); err != nil {
			return nil, err
		}
	}
	return c.header, nil
}

func (c *InboundConn) Write(b []byte) (int, error) {
	if !c.isHeaderWritten {
		if err := c.writeHeader(); err != nil {
			return 0, err
		}
	}
	n, err := c.conn.Write(b)
	return n, err
}

func (c *InboundConn) Read(b []byte) (int, error) {
	if !c.isHeaderRead {
		if err := c.readHeader(); err != nil {
			return 0, err
		}
	}
	n, err := c.conn.Read(b)
	return n, err
}

func (c *InboundConn) Close() error {
	return c.conn.Close()
}
