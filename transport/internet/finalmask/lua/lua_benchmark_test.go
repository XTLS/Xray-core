package lua

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type sinkPacketConn struct {
	net.PacketConn
}

func (sinkPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

func (sinkPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func benchmarkWriteTo(b *testing.B, conn net.PacketConn) {
	b.Helper()

	payload := make([]byte, 1200)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(payload, addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSink(b *testing.B) {
	benchmarkWriteTo(b, sinkPacketConn{})
}

func BenchmarkHeader(b *testing.B) {
	conn, err := (&Config{Script: writeScript(b, header)}).WrapPacketConnClient(sinkPacketConn{}, nil, nil)
	require.NoError(b, err)
	benchmarkWriteTo(b, conn)
}

func BenchmarkNoiseHook(b *testing.B) {
	config := &Config{Script: writeScript(b, `
local fm = require("xray.finalmask")

function HandleNoise(plan, address, role)
    plan:Add("\22\3\1")
    plan:AddRandom(fm.RandomBetween(16, 64))
end
`)}
	engine, err := config.engine()
	require.NoError(b, err)

	var noise []scriptPacket
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		noise, err = engine.packets("client", "127.0.0.1:1", noise[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}
