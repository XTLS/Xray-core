package custom

import (
	"bytes"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type tcpCustomClient struct {
	clients [][]byte
	servers [][]byte
}

type tcpCustomClientConn struct {
	net.Conn
	header *tcpCustomClient

	auth bool
	wg   sync.WaitGroup
	once sync.Once
}

func NewConnClientTCP(c *TCPConfig, raw net.Conn) (net.Conn, error) {
	conn := &tcpCustomClientConn{
		Conn: raw,
		header: &tcpCustomClient{
			clients: c.Clients,
			servers: c.Servers,
		},
	}

	conn.wg.Add(1)

	return conn, nil
}

func (c *tcpCustomClientConn) TcpMaskConn() {}

func (c *tcpCustomClientConn) RawConn() net.Conn {
	c.wg.Wait()

	return c.Conn
}

func (c *tcpCustomClientConn) Read(p []byte) (n int, err error) {
	c.wg.Wait()

	if !c.auth {
		return 0, errors.New("header auth failed")
	}

	return c.Conn.Read(p)
}

func (c *tcpCustomClientConn) Write(p []byte) (n int, err error) {
	c.once.Do(func() {
		var buf [8192]byte

		i := 0
		j := 0
		for i = range c.header.clients {
			n, err = c.Conn.Write(c.header.clients[i])
			if err != nil {
				c.wg.Done()
				return
			}
			if j < len(c.header.servers) {
				n, err := io.ReadFull(c.Conn, buf[:len(c.header.servers[j])])
				if err != nil {
					c.wg.Done()
					return
				}
				if !bytes.Equal(c.header.servers[j], buf[:n]) {
					c.wg.Done()
					return
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			n, err := io.ReadFull(c.Conn, buf[:len(c.header.servers[j])])
			if err != nil {
				c.wg.Done()
				return
			}
			if !bytes.Equal(c.header.servers[j], buf[:n]) {
				c.wg.Done()
				return
			}
			j++
		}

		c.auth = true
		c.wg.Done()
	})

	c.wg.Wait()

	if !c.auth {
		return 0, errors.New("header auth failed")
	}

	return c.Conn.Write(p)
}

type tcpCustomServer struct {
	clients      [][]byte
	servers      [][]byte
	serversError [][]byte
}

type tcpCustomServerConn struct {
	net.Conn
	header *tcpCustomServer

	auth bool
	wg   sync.WaitGroup
	once sync.Once
}

func NewConnServerTCP(c *TCPConfig, raw net.Conn) (net.Conn, error) {
	conn := &tcpCustomServerConn{
		Conn: raw,
		header: &tcpCustomServer{
			clients:      c.Clients,
			servers:      c.Servers,
			serversError: c.Errors,
		},
	}

	conn.wg.Add(1)

	return conn, nil
}

func (c *tcpCustomServerConn) TcpMaskConn() {}

func (c *tcpCustomServerConn) RawConn() net.Conn {
	c.wg.Wait()

	return c.Conn
}

func (c *tcpCustomServerConn) Read(p []byte) (n int, err error) {
	c.once.Do(func() {
		var buf [8192]byte

		i := 0
		j := 0
		for i = range c.header.clients {
			n, err := io.ReadFull(c.Conn, buf[:len(c.header.clients[i])])
			if err != nil {
				c.wg.Done()
				return
			}
			if !bytes.Equal(c.header.clients[i], buf[:n]) {
				if j < len(c.header.serversError) {
					c.Conn.Write(c.header.serversError[j])
				}
				c.wg.Done()
				return
			}
			if j < len(c.header.servers) {
				n, err = c.Conn.Write(c.header.servers[j])
				if err != nil {
					c.wg.Done()
					return
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			n, err = c.Conn.Write(c.header.servers[j])
			if err != nil {
				c.wg.Done()
				return
			}
			j++
		}

		c.auth = true
		c.wg.Done()
	})

	c.wg.Wait()

	if !c.auth {
		return 0, errors.New("header auth failed")
	}

	return c.Conn.Read(p)
}

func (c *tcpCustomServerConn) Write(p []byte) (n int, err error) {
	c.wg.Wait()

	if !c.auth {
		return 0, errors.New("header auth failed")
	}

	return c.Conn.Write(p)
}
