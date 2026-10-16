package custom

import (
	"io"
	"net"

	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeScript(tb testing.TB, script string) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "header.lua")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

func scriptPair(t *testing.T, script string, deadline time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	cfg := &TCPConfig{Script: writeScript(t, script)}

	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })

	client, err := cfg.WrapConnClient(clientRaw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := cfg.WrapConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(deadline))
	_ = server.SetDeadline(time.Now().Add(deadline))
	return client, server
}

const handshakeScript = `
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

func TestScriptTCPHandshake(t *testing.T) {
	client, server := scriptPair(t, handshakeScript, 5*time.Second)

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	buf := make([]byte, len("payload"))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if string(buf) != "payload" {
		t.Fatalf("got %q, want the payload", buf)
	}
}

func TestScriptTCPHandshakeRefused(t *testing.T) {
	client, server := scriptPair(t, `
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

	if _, err := server.Read(make([]byte, 8)); err == nil {
		t.Error("the server should not pass traffic after it refused the handshake")
	}
	if err := <-writeErr; err == nil {
		t.Error("the client should not pass traffic once the handshake failed")
	}
}

func TestScriptNeedsAHook(t *testing.T) {
	cfg := &TCPConfig{Script: writeScript(t, `local noise = require("xray.finalmask.noise")`)}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	if _, err := cfg.WrapConnClient(clientRaw, nil, nil); err == nil {
		t.Error("a script without a hook should not wrap a connection")
	}
}

func TestScriptUsesTheNoiseModule(t *testing.T) {
	client, server := scriptPair(t, `
local noise = require("xray.finalmask.noise")

function HandleHeader(stream, address, role)
    if role == "client" then
        stream:Write(noise.Random(noise.RandomBetween(8, 8)))
    else
        if #stream:Read(8) ~= 8 then
            return "short hello"
        end
    end
end
`, 5*time.Second)

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	buf := make([]byte, len("payload"))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestScriptStreamLimits(t *testing.T) {
	for name, script := range map[string]string{
		"reads too much":  `function HandleHeader(stream, address, role) if role == "server" then stream:Read(65536) end end`,
		"writes too much": `function HandleHeader(stream, address, role) if role == "client" then stream:Write(string.rep("x", 65536)) end end`,
		"bad sleep":       `function HandleHeader(stream, address, role) if role == "client" then stream:Sleep(-1) end end`,
	} {
		t.Run(name, func(t *testing.T) {
			client, server := scriptPair(t, script, 300*time.Millisecond)
			go client.Write([]byte("payload"))
			if _, err := server.Read(make([]byte, 8)); err == nil {
				t.Error("expected the handshake to fail")
			}
		})
	}
}

const packetScript = `
function HandleHeaderWrite(header, address, role)
    if role == "client" then
        header:Add("\1\2")
    else
        header:Add("\3\4")
    end
    header:AddRandom(2)
end

function HandleHeaderRead(packet, address, role)
    if packet:Len() < 4 then
        return nil
    end
    if role == "client" then
        if not packet:Match(1, "\3\4") then
            return nil
        end
    elseif not packet:Match(1, "\1\2") then
        return nil
    end
    return 4
end
`

func TestScriptUDPHeader(t *testing.T) {
	cfg := &UDPConfig{Script: writeScript(t, packetScript)}

	clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()

	client, err := cfg.WrapPacketConnClient(clientRaw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := cfg.WrapPacketConnServer(serverRaw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.WriteTo([]byte("ping"), serverRaw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, from, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("the server got %q, want the payload without the header", buf[:n])
	}

	if _, err := server.WriteTo([]byte("pong"), from); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("the client got %q, want the payload without the header", buf[:n])
	}
}

func TestScriptUDPDropsAForeignPacket(t *testing.T) {
	cfg := &UDPConfig{Script: writeScript(t, packetScript)}

	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()
	server, err := cfg.WrapPacketConnServer(serverRaw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = server.SetDeadline(time.Now().Add(300 * time.Millisecond))

	stranger, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	if _, err := stranger.WriteTo([]byte("not ours"), serverRaw.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	if _, _, err := server.ReadFrom(make([]byte, 64)); err == nil {
		t.Error("a packet without the header should be dropped")
	}
}
