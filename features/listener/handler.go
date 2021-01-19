package listener

import (
	"net"

	"github.com/xtls/xray-core/common"
)

type netRecv struct {
	c net.Conn
	e error
}
type multiListener struct {
	net.Listener
	net       chan netRecv
	ext       chan net.Conn
	identifer common.Identifer
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case res := <-m.net:
		return res.c, res.e
	case extc := <-m.ext:
		return extc, nil
	}
}

func (m *multiListener) loop() {
	for {
		conn, err := m.Listener.Accept()
		m.net <- netRecv{conn, err}
		if err != nil {
			break
		}
	}
}

func (m *multiListener) Close() error {
	if err := m.Listener.Close(); err != nil {
		return err
	}
	close(m.net)
	close(m.ext)
	return nil
}

func (m *multiListener) Recv(c net.Conn) {
	m.ext <- c
}
