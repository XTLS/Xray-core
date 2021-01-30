package simplesocks

import (
	"fmt"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/simplesocks"
)

type InboundConn struct {
	conn         net.Conn
	header       simplesocks.Header
	isHeaderRead bool
	addrParser   protocol.AddressSerializer
}

func NewInboundConn(conn net.Conn) *InboundConn {
	return &InboundConn{
		conn:         conn,
		header:       simplesocks.Header{},
		isHeaderRead: false,
		addrParser: protocol.NewAddressParser(
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
			protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
		),
	}
}

func (c *InboundConn) readHeader() error {
	b := buf.StackNew()
	defer b.Release()

	if _, err := b.ReadFullFrom(c.conn, 1); err != nil {
		return err
	}
	c.header.Command = simplesocks.Command(b.Byte(0))

	b.Clear()
	if addr, port, err := c.addrParser.ReadAddressPort(&b, c.conn); err != nil {
		return err
	} else {
		c.header.Port = port
		c.header.Address = addr
	}

	c.isHeaderRead = true
	fmt.Println("simplesocks", c.header.Address, c.header.Port)
	return nil
}

func (c *InboundConn) GetHeader() (*simplesocks.Header, error) {
	if !c.isHeaderRead {
		if err := c.readHeader(); err != nil {
			return nil, err
		}
	}
	return &c.header, nil
}

func (c *InboundConn) Write(p []byte) (n int, err error) {
	return c.conn.Write(p)
}

func (c *InboundConn) Read(p []byte) (n int, err error) {
	if !c.isHeaderRead {
		if err := c.readHeader(); err != nil {
			return 0, err
		}
	}
	return c.conn.Read(p)
}

func (c *InboundConn) Close() error {
	return c.conn.Close()
}
