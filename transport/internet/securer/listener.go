package securer

import "net"

type securerListener struct {
	net.Listener

	securer ConnectionSecurer
}

func NewListener(listener net.Listener, securer ConnectionSecurer) net.Listener {
	return &securerListener{
		Listener: listener,
		securer:  securer,
	}
}

func (l *securerListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.securer.Server(conn)
}
