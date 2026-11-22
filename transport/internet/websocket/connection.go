package websocket

import (
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
)

var _ buf.Writer = (*connection)(nil)

// connection is a wrapper for net.Conn over WebSocket connection.
// remoteAddr is used to pass "virtual" remote IP addresses in X-Forwarded-For.
// so we shouldn't directly read it form conn.
type connection struct {
	conn       *websocket.Conn
	reader     io.Reader
	remoteAddr net.Addr
	keepalive  *task.Periodic
}

func NewConnection(conn *websocket.Conn, remoteAddr net.Addr, extraReader io.Reader, heartbeatPeriod uint32) *connection {
	wrappedConn := &connection{
		conn:       conn,
		remoteAddr: remoteAddr,
		reader:     extraReader,
	}
	if heartbeatPeriod != 0 {
		var checked atomic.Bool
		keepalive := task.Periodic{
			Execute: func() error {
				// task.Periodic will try to execute this function immediately, drop it
				if !checked.Load() {
					checked.Store(true)
					return nil
				}
				return conn.WriteControl(websocket.PingMessage, []byte{}, time.Time{})
			},
			Interval: time.Duration(heartbeatPeriod) * time.Second,
		}
		keepalive.Start()
		wrappedConn.keepalive = &keepalive
	}

	return wrappedConn
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			// A close frame with a normal status (1000) or no status (1005) ends
			// the byte stream the same way a FIN does, so report io.EOF instead
			// of an error. Other close codes keep their error semantics.
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseNoStatusReceived) {
				return 0, io.EOF
			}
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Cause(err) == io.EOF {
			c.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (c *connection) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.conn.NextReader()
	if err != nil {
		return nil, err
	}
	c.reader = reader
	return reader, nil
}

// Write implements io.Writer.
func (c *connection) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *connection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *connection) Close() error {
	common.CloseIfExists(c.keepalive)
	var errs []interface{}
	if err := c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5)); err != nil {
		errs = append(errs, err)
	}
	if err := c.conn.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.New("failed to close connection").Base(errors.New(serial.Concat(errs...)))
	}
	return nil
}

func (c *connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
