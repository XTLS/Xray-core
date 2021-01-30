package simplesocks

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/simplesocks"
)

type OutboundConn struct {
	conn            net.Conn
	header          simplesocks.Header
	isHeaderWritten bool
	addrParser      protocol.AddressSerializer
}

func NewOutboundConn(conn net.Conn, command simplesocks.Command, atype simplesocks.Type, address net.Address, port net.Port) *OutboundConn {
	return &OutboundConn{
		conn: conn,
		header: simplesocks.Header{
			Command: command,
			Atype:   atype,
			Address: address,
			Port:    port,
		},
		isHeaderWritten: false,
		addrParser: protocol.NewAddressParser(
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
		),
	}
}

func (c *OutboundConn) writeHeader() error {
	b := buf.StackNew()
	defer b.Release()

	if err := b.WriteByte(byte(c.header.Command)); err != nil {
		return err
	}

	if err := c.addrParser.WriteAddressPort(&b, c.header.Address, c.header.Port); err != nil {
		return err
	}

	if _, err := c.conn.Write(b.Bytes()); err != nil {
		return err
	}

	c.isHeaderWritten = true
	return nil
}

func (c *OutboundConn) Write(p []byte) (n int, err error) {
	if !c.isHeaderWritten {
		if err := c.writeHeader(); err != nil {
			return 0, err
		}
	}
	return c.conn.Write(p)
}

func (c *OutboundConn) Read(p []byte) (n int, err error) {
	return c.conn.Read(p)
}
