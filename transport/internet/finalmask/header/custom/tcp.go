package custom

import (
	"hash/crc32"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type tcpCustomClient struct {
	clients   [][]byte
	servers   [][]byte
	checksums []uint32
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

	for i := range c.Servers {
		conn.header.checksums = append(conn.header.checksums, crc32.ChecksumIEEE(c.Servers[i]))
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
			if j < len(c.header.checksums) {
				n, err := io.ReadFull(c.Conn, buf[:len(c.header.servers[j])])
				if err != nil {
					c.wg.Done()
					return
				}
				if c.header.checksums[j] != crc32.ChecksumIEEE(buf[:n]) {
					c.wg.Done()
					return
				}
				j++
			}
		}

		for j < len(c.header.checksums) {
			n, err := io.ReadFull(c.Conn, buf[:len(c.header.servers[j])])
			if err != nil {
				c.wg.Done()
				return
			}
			if c.header.checksums[j] != crc32.ChecksumIEEE(buf[:n]) {
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
	checksums    []uint32
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
			serversError: c.ServersError,
		},
	}

	for i := range c.Clients {
		conn.header.checksums = append(conn.header.checksums, crc32.ChecksumIEEE(c.Clients[i]))
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
		for i = range c.header.checksums {
			n, err := io.ReadFull(c.Conn, buf[:len(c.header.clients[i])])
			if err != nil {
				c.wg.Done()
				return
			}
			if c.header.checksums[i] != crc32.ChecksumIEEE(buf[:n]) {
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
