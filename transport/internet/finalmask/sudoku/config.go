package sudoku

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
)

func (c *Config) TCP() {
}

func (c *Config) UDP() {
}

func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	if c.GetPacked() {
		return newPackedDirectionalConn(raw, c, true)
	}
	return NewTCPConn(raw, c)
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	if c.GetPacked() {
		return newPackedDirectionalConn(raw, c, false)
	}
	return NewTCPConn(raw, c)
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

func (c *Config) WrapPacketConnClient(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error) {
	if !end {
		return nil, errors.New("sudoku udp mask must be the innermost mask in chain")
	}
	return NewUDPConn(raw, c)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error) {
	if !end {
		return nil, errors.New("sudoku udp mask must be the innermost mask in chain")
	}
	return NewUDPConn(raw, c)
}
