package sudoku

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// Sudoku in finalmask mode is a pure appearance transform with no standalone handshake.
// TCP always keeps classic sudoku on uplink and uses packed downlink optimization on server writes.
func (c *Config) WrapConnClient(conn net.Conn, dialer *finalmask.Dialer) (net.Conn, error) {
	return newPackedDirectionalConn(conn, c, true)
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return newPackedDirectionalConn(conn, c, false)
}

func newPackedDirectionalConn(raw net.Conn, config *Config, readPacked bool) (net.Conn, error) {
	pureReader, pureWriter, err := newPureReaderWriter(raw, config)
	if err != nil {
		return nil, err
	}
	packedReader, packedWriter, err := newPackedReaderWriter(raw, config)
	if err != nil {
		return nil, err
	}

	reader, writer := pureReader, pureWriter
	if readPacked {
		reader = packedReader
	} else {
		writer = packedWriter
	}

	return newWrappedConn(raw, reader, writer), nil
}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewUDPConn(conn, c)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewUDPConn(conn, c)
}
