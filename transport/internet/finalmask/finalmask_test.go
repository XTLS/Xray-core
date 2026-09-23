package finalmask_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

var errMask = errors.New("mask failed")

type failingMask struct{}

func (failingMask) HandleDial()   {}
func (failingMask) HandleListen() {}

func (failingMask) WrapConnClient(net.Conn, *net.Destination, *finalmask.Dialer) (net.Conn, error) {
	return nil, errMask
}

func (failingMask) WrapConnServer(net.Conn) (net.Conn, error) {
	return nil, errMask
}

func (failingMask) WrapPacketConnClient(net.PacketConn, *net.Destination, *finalmask.Dialer) (net.PacketConn, error) {
	return nil, errMask
}

func (failingMask) WrapPacketConnServer(net.PacketConn, net.Addr, *finalmask.ListenConfig) (net.PacketConn, error) {
	return nil, errMask
}

func TestSelfDialingMaskFailure(t *testing.T) {
	fm := finalmask.NewFinalMask([]finalmask.TCPMask{failingMask{}}, []finalmask.UDPMask{failingMask{}}, nil, nil, nil, nil)
	dest := net.UDPDestination(net.LocalHostIP, 443)

	if _, err := fm.DialTCP(context.Background(), dest); !errors.Is(err, errMask) {
		t.Errorf("DialTCP: got %v, want %v", err, errMask)
	}
	if _, err := fm.DialUDP(context.Background(), dest); !errors.Is(err, errMask) {
		t.Errorf("DialUDP: got %v, want %v", err, errMask)
	}
	if _, err := fm.ListenPacket(context.Background(), &net.UDPAddr{IP: net.LocalHostIP.IP()}); !errors.Is(err, errMask) {
		t.Errorf("ListenPacket: got %v, want %v", err, errMask)
	}
}
