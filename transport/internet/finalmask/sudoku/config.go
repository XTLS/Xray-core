package sudoku

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) TCP() {
}

func (c *Config) UDP() {
}

// Sudoku in finalmask mode is a pure appearance transform with no standalone handshake.
// TCP always keeps classic sudoku on uplink and uses packed downlink optimization on server writes.
func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	return newPackedDirectionalConn(raw, c, true)
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return newPackedDirectionalConn(raw, c, false)
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

func (c *Config) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	if level != levelCount {
		return nil, errors.New("sudoku udp mask must be the innermost mask in chain")
	}
	return NewUDPConn(raw, c)
}

func (c *Config) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	if level != levelCount {
		return nil, errors.New("sudoku udp mask must be the innermost mask in chain")
	}
	return NewUDPConn(raw, c)
}
