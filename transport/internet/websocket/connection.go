package websocket

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var _ buf.Writer = (*connection)(nil)

// connection is a wrapper for net.Conn over WebSocket connection.
// remoteAddr is used to pass "virtual" remote IP addresses in X-Forwarded-For.
// so we shouldn't directly read it form conn.
type connection struct {
	conn       *websocket.Conn
	reader     io.Reader
	remoteAddr net.Addr

	// for WaitRead: whether reader has the early data, what conn has read and not returned,
	// and what is left of its frame
	waiter    tls.ReadWaiter
	early     bool
	br        **bufio.Reader
	remaining *int64
}

var logUnknownFields sync.Once

func NewConnection(conn *websocket.Conn, remoteAddr net.Addr, extraReader io.Reader, heartbeatPeriod uint32) *connection {
	if heartbeatPeriod != 0 {
		go func() {
			for {
				time.Sleep(time.Duration(heartbeatPeriod) * time.Second)
				if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Time{}); err != nil {
					break
				}
			}
		}()
	}

	c := &connection{
		conn:       conn,
		remoteAddr: remoteAddr,
		reader:     extraReader,
		early:      extraReader != nil,
		br:         utils.TryAccessField[*bufio.Reader](conn, "br"),
		remaining:  utils.TryAccessField[int64](conn, "readRemaining"),
	}
	if c.br == nil || c.remaining == nil {
		logUnknownFields.Do(func() {
			errors.LogWarning(context.Background(), "unexpected fields in *websocket.Conn, such connections keep more memory than they need")
		})
	}
	return c
}

func (c *connection) WaitRead() {
	if c.br == nil || c.remaining == nil {
		return
	}
	if c.early {
		if r, ok := c.reader.(interface{ Len() int }); !ok || r.Len() > 0 {
			return
		}
	}
	// not in a frame, and nothing read ahead
	if *c.remaining == 0 && (*c.br).Buffered() == 0 {
		conn := c.conn.NetConn()
		if _, ok := conn.(*net.TCPConn); !ok {
			c.waiter.Wait(conn) // TLS gives up what it holds while it waits here and not in its Read
		}
		// the next frame comes into the buffer that c.conn has anyway, and what fails stays with it for Read
		c.Read(nil)
	}
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Cause(err) == io.EOF {
			c.reader = nil
			c.early = false
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
