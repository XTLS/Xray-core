package custom

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type tcpCustomClient struct {
	clients []*TCPSequence
	servers []*TCPSequence
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

	for _, sequence := range conn.header.clients {
		for _, item := range sequence.Items {
			if item.Rand > 0 {
				item.Packet = make([]byte, 0, item.Rand)
			}
		}
	}

	for _, sequence := range conn.header.servers {
		for _, item := range sequence.Items {
			if item.Rand > 0 {
				item.Packet = make([]byte, 0, item.Rand)
			}
		}
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
			for _, item := range c.header.clients[i].Items {
				time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
				if item.Rand > 0 {
					common.Must2(rand.Read(item.Packet))
				}
				n, err = c.Conn.Write(item.Packet)
				if err != nil {
					c.wg.Done()
					return
				}
			}
			if j < len(c.header.servers) {
				for _, item := range c.header.servers[j].Items {
					n, err := io.ReadFull(c.Conn, buf[:len(item.Packet)])
					if err != nil {
						c.wg.Done()
						return
					}
					if item.Rand > 0 {
						if n != len(item.Packet) {
							c.wg.Done()
							return
						}
					} else if !bytes.Equal(item.Packet, buf[:n]) {
						c.wg.Done()
						return
					}
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			for _, item := range c.header.servers[j].Items {
				n, err := io.ReadFull(c.Conn, buf[:len(item.Packet)])
				if err != nil {
					c.wg.Done()
					return
				}
				if item.Rand > 0 {
					if n != len(item.Packet) {
						c.wg.Done()
						return
					}
				} else if !bytes.Equal(item.Packet, buf[:n]) {
					c.wg.Done()
					return
				}
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
	clients []*TCPSequence
	servers []*TCPSequence
	onError []byte
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
			clients: c.Clients,
			servers: c.Servers,
			onError: c.OnError,
		},
	}

	for _, sequence := range conn.header.clients {
		for _, item := range sequence.Items {
			if item.Rand > 0 {
				item.Packet = make([]byte, 0, item.Rand)
			}
		}
	}

	for _, sequence := range conn.header.servers {
		for _, item := range sequence.Items {
			if item.Rand > 0 {
				item.Packet = make([]byte, 0, item.Rand)
			}
		}
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
			for _, item := range c.header.clients[i].Items {
				n, err := io.ReadFull(c.Conn, buf[:len(item.Packet)])
				if err != nil {
					c.wg.Done()
					return
				}
				if item.Rand > 0 {
					if n != len(item.Packet) {
						c.wg.Done()
						return
					}
				} else if !bytes.Equal(item.Packet, buf[:n]) {
					if len(c.header.onError) > 0 {
						c.Conn.Write(c.header.onError)
					}
					c.wg.Done()
					return
				}
			}
			if j < len(c.header.servers) {
				for _, item := range c.header.servers[i].Items {
					time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
					if item.Rand > 0 {
						common.Must2(rand.Read(item.Packet))
					}
					n, err = c.Conn.Write(item.Packet)
					if err != nil {
						c.wg.Done()
						return
					}
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			for _, item := range c.header.servers[i].Items {
				time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
				if item.Rand > 0 {
					common.Must2(rand.Read(item.Packet))
				}
				n, err = c.Conn.Write(item.Packet)
				if err != nil {
					c.wg.Done()
					return
				}
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
