package lua

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type maskConn struct {
	net.Conn
	engine *engine
	role   string

	auth bool
	wg   sync.WaitGroup
	once sync.Once
}

func newConnClient(c *Config, raw net.Conn) (net.Conn, error) {
	return newConn(c, raw, roleClient)
}

func newConnServer(c *Config, raw net.Conn) (net.Conn, error) {
	return newConn(c, raw, roleServer)
}

func newConn(c *Config, raw net.Conn, role string) (net.Conn, error) {
	engine, err := c.engine()
	if err != nil {
		return nil, errors.New("failed to initialize the script ", c.Script).Base(err)
	}
	if !engine.has(headerHook) {
		return raw, nil
	}

	conn := &maskConn{Conn: raw, engine: engine, role: role}
	conn.wg.Add(1)
	return conn, nil
}

func (c *maskConn) TcpMaskConn() {}

func (c *maskConn) RawConn() net.Conn {
	return c.Conn
}

func (c *maskConn) Splice() bool {
	return true
}

func (c *maskConn) Read(p []byte) (n int, err error) {
	if c.role == roleServer {
		c.handshake()
	}
	c.wg.Wait()

	if !c.auth {
		return 0, errors.New("the script refused the connection")
	}

	return c.Conn.Read(p)
}

func (c *maskConn) Write(p []byte) (n int, err error) {
	if c.role == roleClient {
		c.handshake()
	}
	c.wg.Wait()

	if !c.auth {
		return 0, errors.New("the script refused the connection")
	}

	return c.Conn.Write(p)
}

func (c *maskConn) handshake() {
	c.once.Do(func() {
		defer c.wg.Done()
		if err := c.engine.handshake(c.role, c.Conn, handshakeTimeout); err != nil {
			errors.LogWarningInner(context.Background(), err, "the script refused the connection")
			return
		}
		c.auth = true
	})
}
