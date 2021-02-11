package outbound

import (
	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/xtls"
	"syscall"
	"time"
)

type OutboundConn struct {
	conn   net.Conn
	header *protocol.RequestHeader

	// Reserved for XTLS
	addons  *encoding.Addons
	rawConn syscall.RawConn

	isHeaderWritten bool
	isHeaderRead    bool
	addrParser      protocol.AddressSerializer
}

// Creates an OutboundConn instance to be further analyzed in NewOutboundConn routine
func createOutboundConn(conn net.Conn, header *protocol.RequestHeader) *OutboundConn {
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

// Creates a new property configured OutboundConn instance based on underlying connection, connection header and addons
// and returns error in setting up the connection instance
func NewOutboundConn(conn net.Conn, header *protocol.RequestHeader, addons *encoding.Addons) (*OutboundConn, error) {
	outboundConn := createOutboundConn(conn, header)
	if err := outboundConn.configAddons(addons); err != nil {
		return nil, err
	}
	return outboundConn, nil
}

// Configure the addon information for an existing OutboundConn instance
func (c *OutboundConn) configAddons(addons *encoding.Addons) error {
	iConn := c.conn
	statConn, ok := iConn.(*internet.StatCouterConnection)
	if ok {
		iConn = statConn.Connection
	}

	allowUDP443 := false
	switch addons.Flow {
	case vless.XRO + "-udp443", vless.XRD + "-udp443", vless.XRS + "-udp443":
		allowUDP443 = true
		addons.Flow = addons.Flow[:16]
		fallthrough
	case vless.XRO, vless.XRD, vless.XRS:
		switch c.header.Command {
		case protocol.RequestCommandMux, protocol.RequestCommandSmux:
			return newError(addons.Flow + " doesn't support Mux").AtWarning()
		case protocol.RequestCommandUDP:
			if !allowUDP443 && c.header.Port == 443 {
				return newError(addons.Flow + " stopped UDP/443").AtInfo()
			}
			addons.Flow = ""
		case protocol.RequestCommandTCP:
			if xtlsConn, ok := iConn.(*xtls.Conn); ok {
				xtlsConn.RPRX = true
				xtlsConn.SHOW = xtls_show
				xtlsConn.MARK = "XTLS"
				if addons.Flow == vless.XRS {
					addons.Flow = vless.XRD
				}
				if addons.Flow == vless.XRD {
					xtlsConn.DirectMode = true
					if sc, ok := xtlsConn.Connection.(syscall.Conn); ok {
						c.rawConn, _ = sc.SyscallConn()
					}
				}
			} else {
				return newError(`failed to use ` + addons.Flow + `, maybe "security" is not "xtls"`).AtWarning()
			}
		}
	default:
		if _, ok := iConn.(*xtls.Conn); ok {
			panic(`To avoid misunderstanding, you must fill in VLESS "flow" when using XTLS.`)
		}
	}
	c.addons = addons
	return nil
}

/*
 * +---------+------+------------+------------+-----+------+-----------+----------+
 * | VERSION | UUID | ADDON.SIZE | ADDON.BODY | CMD | PORT | ADDR.TYPE |   ADDR   |
 * +---------+------+------------+------------+-----+------+-----------+----------+
 * |    1    |  1   |     1      |  Variable  |  1  |   2  |     1     | Variable |
 * +---------+------+------------+------------+-----+------+-----------+----------+
 * |                                  Payload                                     |
 * +------------------------------------------------------------------------------+
 * |                                  Variable                                    |
 * +------------------------------------------------------------------------------+
 */
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

	// Write addon size and addon protobuf
	switch c.addons.Flow {
	case vless.XRO, vless.XRD:
		bytes, err := proto.Marshal(c.addons)
		if err != nil {
			return newError("failed to marshal addons protobuf value").Base(err)
		}
		if err := buffer.WriteByte(byte(len(bytes))); err != nil {
			return newError("failed to write addons protobuf length").Base(err)
		}
		if _, err := buffer.Write(bytes); err != nil {
			return newError("failed to write addons protobuf value").Base(err)
		}
	default:
		if err := buffer.WriteByte(0); err != nil {
			return newError("failed to write addons protobuf length").Base(err)
		}
	}

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

/*
 * +---------+-----------+------------+
 * | VERSION |ADDON.SIZE | ADDON.BODY |
 * +---------+-----------+------------+
 * |    1    |     1     | Variable   |
 * +---------+-----------+------------+
 * |            Payload               |
 * +----------------------------------+
 * |            Variable              |
 * +----------------------------------+
 */
func (c *OutboundConn) readHeader() error {
	buffer := buf.StackNew()
	defer buffer.Release()

	// Read and validate version number
	if _, err := buffer.ReadFullFrom(c.conn, 2); err != nil {
		return err
	}
	version := buffer.Byte(0)
	if version != c.header.Version {
		return newError("incorrect VLESS protocol version")
	}

	// Obtain addon size and read addon
	addonSize := int32(buffer.Byte(1))
	if addonSize > 0 {
		if _, err := buffer.ReadFullFrom(c.conn, addonSize); err != nil {
			return err
		}
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

func (c *OutboundConn) ReadV(b []byte) (int, error) {
	// TODO: Add logics for ReadV
	return 0, nil
}

func (c *OutboundConn) Read(b []byte) (int, error) {
	if !c.isHeaderRead {
		if err := c.readHeader(); err != nil {
			return 0, err
		}
	}
	if c.rawConn != nil {
		return c.ReadV(b)
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
