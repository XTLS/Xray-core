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
	return NewTCPConn(raw, c)
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return NewTCPConn(raw, c)
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
