package connection

import (
	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"time"
)

type SmuxConnection struct {
	Conn        internet.Connection
	SmuxSession *smux.Session
}

func (c *SmuxConnection) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *SmuxConnection) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

func (c *SmuxConnection) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *SmuxConnection) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *SmuxConnection) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *SmuxConnection) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *SmuxConnection) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *SmuxConnection) Close() error {
	_ = c.SmuxSession.Close()
	_ = c.Conn.Close()
	return nil
}
