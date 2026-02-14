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
	merged  [][]byte
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

	conn.header.merged = make([][]byte, len(conn.header.clients))
	for index, client := range conn.header.clients {
		for _, item := range client.Sequence {
			if item.Rand > 0 {
				conn.header.merged[index] = append(conn.header.merged[index], make([]byte, item.Rand)...)
			} else {
				conn.header.merged[index] = append(conn.header.merged[index], item.Packet...)
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

func (c *tcpCustomClientConn) Splice() bool {
	type Splice interface{ Splice() bool }
	if v, ok := c.Conn.(Splice); ok {
		return true && v.Splice()
	}
	return true
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
			index := 0
			from := 0
			to := 0
			for to < len(c.header.merged[i]) {
				item := c.header.clients[i].Sequence[index]
				if item.DelayMax > 0 {
					if to > from {
						_, err := c.Conn.Write(c.header.merged[i][from:to])
						if err != nil {
							c.wg.Done()
							return
						}
						from = to
					}
					time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
				}
				length := max(int(item.Rand), len(item.Packet))
				if item.Rand > 0 {
					common.Must2(rand.Read(c.header.merged[i][to : to+length]))
				}
				to += length
				index++
			}
			if to > from {
				_, err := c.Conn.Write(c.header.merged[i][from:to])
				if err != nil {
					c.wg.Done()
					return
				}
				from = to
			}

			if j < len(c.header.servers) {
				for _, item := range c.header.servers[j].Sequence {
					length := max(int(item.Rand), len(item.Packet))
					n, err := io.ReadFull(c.Conn, buf[:length])
					if err != nil {
						c.wg.Done()
						return
					}
					if item.Rand > 0 {
						if n != length {
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
			for _, item := range c.header.servers[j].Sequence {
				length := max(int(item.Rand), len(item.Packet))
				n, err := io.ReadFull(c.Conn, buf[:length])
				if err != nil {
					c.wg.Done()
					return
				}
				if item.Rand > 0 {
					if n != length {
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
	merged  [][]byte
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

	conn.header.merged = make([][]byte, len(conn.header.servers))
	for index, client := range conn.header.servers {
		for _, item := range client.Sequence {
			if item.Rand > 0 {
				conn.header.merged[index] = append(conn.header.merged[index], make([]byte, item.Rand)...)
			} else {
				conn.header.merged[index] = append(conn.header.merged[index], item.Packet...)
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

func (c *tcpCustomServerConn) Splice() bool {
	type Splice interface{ Splice() bool }
	if v, ok := c.Conn.(Splice); ok {
		return true && v.Splice()
	}
	return true
}

func (c *tcpCustomServerConn) Read(p []byte) (n int, err error) {
	c.once.Do(func() {
		var buf [8192]byte

		i := 0
		j := 0
		for i = range c.header.clients {
			for _, item := range c.header.clients[i].Sequence {
				length := max(int(item.Rand), len(item.Packet))
				n, err := io.ReadFull(c.Conn, buf[:length])
				if err != nil {
					c.wg.Done()
					return
				}
				if item.Rand > 0 {
					if n != length {
						if len(c.header.onError) > 0 {
							c.Conn.Write(c.header.onError)
						}
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
				index := 0
				from := 0
				to := 0
				for to < len(c.header.merged[j]) {
					item := c.header.servers[j].Sequence[index]
					if item.DelayMax > 0 {
						if to > from {
							_, err := c.Conn.Write(c.header.merged[j][from:to])
							if err != nil {
								c.wg.Done()
								return
							}
							from = to
						}
						time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
					}
					length := max(int(item.Rand), len(item.Packet))
					if item.Rand > 0 {
						common.Must2(rand.Read(c.header.merged[j][to : to+length]))
					}
					to += length
					index++
				}
				if to > from {
					_, err := c.Conn.Write(c.header.merged[j][from:to])
					if err != nil {
						c.wg.Done()
						return
					}
					from = to
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			index := 0
			from := 0
			to := 0
			for to < len(c.header.merged[j]) {
				item := c.header.servers[j].Sequence[index]
				if item.DelayMax > 0 {
					if to > from {
						_, err := c.Conn.Write(c.header.merged[j][from:to])
						if err != nil {
							c.wg.Done()
							return
						}
						from = to
					}
					time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
				}
				length := max(int(item.Rand), len(item.Packet))
				if item.Rand > 0 {
					common.Must2(rand.Read(c.header.merged[j][to : to+length]))
				}
				to += length
				index++
			}
			if to > from {
				_, err := c.Conn.Write(c.header.merged[j][from:to])
				if err != nil {
					c.wg.Done()
					return
				}
				from = to
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
