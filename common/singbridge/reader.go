package singbridge

import (
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

var (
	_ buf.Reader        = (*Conn)(nil)
	_ buf.TimeoutReader = (*Conn)(nil)
	_ buf.Writer        = (*Conn)(nil)
	_ buf.Reader        = (*PacketConn)(nil)
	_ buf.TimeoutReader = (*PacketConn)(nil)
	_ buf.Writer        = (*PacketConn)(nil)
)

type Conn struct {
	net.Conn
	writer N.VectorisedWriter
}

func NewConn(conn net.Conn) *Conn {
	writer, _ := bufio.CreateVectorisedWriter(conn)
	return &Conn{
		Conn:   conn,
		writer: writer,
	}
}

func (c *Conn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := buf.ReadBuffer(c.Conn)
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buffer}, nil
}

func (c *Conn) ReadMultiBufferTimeout(duration time.Duration) (buf.MultiBuffer, error) {
	err := c.SetReadDeadline(time.Now().Add(duration))
	if err != nil {
		return nil, err
	}
	defer c.SetReadDeadline(time.Time{})
	return c.ReadMultiBuffer()
}

func (c *Conn) WriteMultiBuffer(bufferList buf.MultiBuffer) error {
	defer buf.ReleaseMulti(bufferList)
	if c.writer != nil {
		bytesList := make([][]byte, len(bufferList))
		for i, buffer := range bufferList {
			bytesList[i] = buffer.Bytes()
		}
		return common.Error(bufio.WriteVectorised(c.writer, bytesList))
	}
	// Since this conn is only used by tun, we don't force buffer writes to merge.
	for _, buffer := range bufferList {
		_, err := c.Conn.Write(buffer.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

type PacketConn struct {
	net.Conn
	destination net.Destination
}

func (c *PacketConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := buf.ReadBuffer(c.Conn)
	if err != nil {
		return nil, err
	}
	buffer.UDP = &c.destination
	return buf.MultiBuffer{buffer}, nil
}

func (c *PacketConn) ReadMultiBufferTimeout(duration time.Duration) (buf.MultiBuffer, error) {
	err := c.SetReadDeadline(time.Now().Add(duration))
	if err != nil {
		return nil, err
	}
	defer c.SetReadDeadline(time.Time{})
	return c.ReadMultiBuffer()
}

func (c *PacketConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb, err := buf.WriteMultiBuffer(c.Conn, mb)
	buf.ReleaseMulti(mb)
	return err
}
