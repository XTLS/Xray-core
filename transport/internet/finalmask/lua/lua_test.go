package lua

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeScript(tb testing.TB, script string) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "mask.lua")
	require.NoError(tb, os.WriteFile(path, []byte(script), 0o600))
	return path
}

type fakePacketConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), p...))
	return len(p), nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (c *fakePacketConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

func packetConn(t *testing.T, script string, reset int32) (net.PacketConn, *fakePacketConn) {
	t.Helper()
	raw := &fakePacketConn{}
	conn, err := (&Config{Script: writeScript(t, script), ResetMax: int64(reset)}).WrapPacketConnClient(raw, nil, nil)
	require.NoError(t, err)
	return conn, raw
}

func connPair(t *testing.T, script string, deadline time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	config := &Config{Script: writeScript(t, script)}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })

	client, err := config.WrapConnClient(clientRaw, nil, nil)
	require.NoError(t, err)
	server, err := config.WrapConnServer(serverRaw)
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(deadline))
	_ = server.SetDeadline(time.Now().Add(deadline))
	return client, server
}

const handshake = `
function HandleHeader(stream, address, role)
    if role == "client" then
        stream:Write("\22\3\1")
        if stream:Read(2) ~= "ok" then
            return "the server did not greet us"
        end
    else
        if stream:Read(3) ~= "\22\3\1" then
            return "the client sent the wrong hello"
        end
        stream:Write("ok")
    end
end
`

const header = `
function HandleHeaderWrite(header, address, role)
    header:Add(role == "client" and "\1\2" or "\3\4")
    header:AddRandom(2)
end

function HandleHeaderRead(packet, address, role)
    local want = role == "client" and "\3\4" or "\1\2"
    if packet:Len() < 4 or not packet:Match(1, want) then
        return nil
    end
    return 4
end
`

func TestHandshake(t *testing.T) {
	client, server := connPair(t, handshake, 5*time.Second)

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	buf := make([]byte, len("payload"))
	_, err := io.ReadFull(server, buf)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.Equal(t, "payload", string(buf))
}

func TestHandshakeRefused(t *testing.T) {
	client, server := connPair(t, `
function HandleHeader(stream, address, role)
    if role == "client" then
        stream:Write("hello")
        stream:Read(2)
    else
        stream:Read(5)
        return "the client is not one of ours"
    end
end
`, 300*time.Millisecond)

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	_, err := server.Read(make([]byte, 8))
	require.Error(t, err, "the server passes no traffic after it refused the handshake")
	require.Error(t, <-writeErr)
}

func TestHeaderRoundTrip(t *testing.T) {
	client, raw := packetConn(t, header, 0)

	_, err := client.WriteTo([]byte("payload"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	sent := raw.packets()
	require.Len(t, sent, 1)
	require.Equal(t, []byte{1, 2}, sent[0][:2])
	require.Equal(t, "payload", string(sent[0][4:]))
}

func TestNoiseBeforeThePayload(t *testing.T) {
	client, raw := packetConn(t, `
local fm = require("xray.finalmask")

function HandleNoise(plan, address, role)
    plan:Add("first")
    plan:AddRandom(fm.RandomBetween(8, 8), 0)
end
`, 0)

	addr := &net.UDPAddr{Port: 1}
	_, err := client.WriteTo([]byte("payload"), addr)
	require.NoError(t, err)
	_, err = client.WriteTo([]byte("again"), addr)
	require.NoError(t, err)

	sent := raw.packets()
	require.Len(t, sent, 4, "noise once per address, then both payloads")
	require.Equal(t, "first", string(sent[0]))
	require.Len(t, sent[1], 8)
	require.Equal(t, "payload", string(sent[2]))
	require.Equal(t, "again", string(sent[3]))
}

func TestScriptNeedsAHook(t *testing.T) {
	_, err := (&Config{Script: writeScript(t, `local fm = require("xray.finalmask")`)}).WrapPacketConnClient(&fakePacketConn{}, nil, nil)
	require.Error(t, err)
}

func TestMaskWithoutItsHookPassesThrough(t *testing.T) {
	raw := &fakePacketConn{}
	conn, err := (&Config{Script: writeScript(t, handshake)}).WrapPacketConnClient(raw, nil, nil)
	require.NoError(t, err)
	require.Equal(t, net.PacketConn(raw), conn, "a handshake only script leaves packets alone")

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	stream, err := (&Config{Script: writeScript(t, header)}).WrapConnClient(clientRaw, nil, nil)
	require.NoError(t, err)
	require.Equal(t, net.Conn(clientRaw), stream, "a packet only script leaves connections alone")
}

func TestNoiseLimits(t *testing.T) {
	for name, script := range map[string]string{
		"too many packets": `function HandleNoise(plan, address, role)
    for i = 1, 65 do plan:Add("n") end
end`,
		"too many bytes": `local fm = require("xray.finalmask")
function HandleNoise(plan, address, role)
    for i = 1, 2 do plan:Add(fm.Random(40000)) end
end`,
		"bad delay": `function HandleNoise(plan, address, role) plan:Add("n", -1) end`,
	} {
		t.Run(name, func(t *testing.T) {
			client, raw := packetConn(t, script, 0)
			_, err := client.WriteTo([]byte("payload"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Equal(t, [][]byte{[]byte("payload")}, raw.packets(), "the payload still goes out without the noise")
		})
	}
}

func TestHeaderLimits(t *testing.T) {
	for name, script := range map[string]string{
		"too long":     `function HandleHeaderWrite(header, address, role) header:AddRandom(1025) end`,
		"not a number": `function HandleHeaderWrite(header, address, role) header:AddRandom(0 / 0) end`,
		"not a string": `function HandleHeaderWrite(header, address, role) header:Add(true) end`,
	} {
		t.Run(name, func(t *testing.T) {
			client, raw := packetConn(t, script, 0)
			n, err := client.WriteTo([]byte("payload"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Zero(t, n, "a packet without its header is dropped")
			require.Empty(t, raw.packets())
		})
	}
}

func TestStreamLimits(t *testing.T) {
	for name, script := range map[string]string{
		"reads too much":  `function HandleHeader(stream, address, role) if role == "server" then stream:Read(65536) end end`,
		"writes too much": `function HandleHeader(stream, address, role) if role == "client" then stream:Write(string.rep("x", 65536)) end end`,
		"bad sleep":       `function HandleHeader(stream, address, role) if role == "client" then stream:Sleep(-1) end end`,
	} {
		t.Run(name, func(t *testing.T) {
			client, server := connPair(t, script, 300*time.Millisecond)
			go client.Write([]byte("payload"))
			_, err := server.Read(make([]byte, 8))
			require.Error(t, err)
		})
	}
}

func TestObjectsAreOnlyLiveInsideTheirHook(t *testing.T) {
	client, raw := packetConn(t, `
local kept

function HandleNoise(plan, address, role)
    kept = plan
    plan:Add("n")
end

function HandleHeaderWrite(header, address, role)
    kept:Add("too late")
end
`, 0)

	_, err := client.WriteTo([]byte("payload"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("n")}, raw.packets(), "the stale plan raises, so the packet is dropped")
}
