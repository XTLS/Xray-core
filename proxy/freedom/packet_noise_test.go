package freedom

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type noiseTestConn struct{ net.Conn }

func (noiseTestConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

type noiseTestPacket struct {
	net.PacketConn
	entered chan struct{}
}

func (p noiseTestPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	close(p.entered)
	return len(b), nil
}

func TestPacketNoiseDelayStopsWithLeg(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	p := &freedomPacketIO{ctx: ctx, conn: noiseTestConn{}, packet: noiseTestPacket{entered: entered}, h: &Handler{config: &Config{Noises: []*Noise{{Packet: []byte{1}, ApplyTo: "ip", DelayMin: 10000, DelayMax: 10000}}}}}
	done := make(chan error, 1)
	go func() { done <- p.emitNoise() }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("noise delay outlived leg cancellation")
	}
}
