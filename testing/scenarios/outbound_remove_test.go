package scenarios

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// These tests remove an outbound through the API while a connection goes
// through it.

func TestRemoveOutboundWireGuard(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := udp.PickPort()
	relay := startPacketRelay(t, serverPort)
	apiPort, clientPort := tcp.PickPort(), tcp.PickPort()
	servers := startXrayFromJSON(t, fmt.Sprintf(`{
	"log": {"loglevel": "info"},
	"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "wireguard", "settings": {
		"secretKey": "CAVR/i06MRIXIAkaxBPcm22HR/4ysXozQts0k70CAFY=", "address": ["10.0.0.1"], "mtu": 1420,
		"peers": [{"publicKey": "E8vVtPmuVMsqokMjuFNAYpNheY+Ks0PIJ4RuyCthAEs=", "allowedIPs": ["10.0.0.2/32"]}]}}],
	"outbounds": [{"protocol": "freedom", "settings": {"redirect": "%s", "finalRules": [{"action": "allow"}]}}]
}`, serverPort, dest.NetAddr()), fmt.Sprintf(`{
	"log": {"loglevel": "info"},
	"api": {"tag": "api", "listen": "127.0.0.1:%d", "services": ["HandlerService"]},
	"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "tunnel", "settings": {"rewriteAddress": "10.0.0.1", "rewritePort": 80, "allowedNetwork": "tcp"}}],
	"outbounds": [{"tag": "out", "protocol": "wireguard", "settings": {
		"secretKey": "wLlk5z+PrEQnnLOBfd8aIe/p+Ly2ukDPBttPpWca2ng=", "address": ["10.0.0.2"], "mtu": 1420, "noKernelTun": true,
		"peers": [{"endpoint": "127.0.0.1:%d", "publicKey": "szB6HtF+/8zWQEljyFKKO8J3PAbnRJvcwTEXhINIkCM=", "allowedIPs": ["0.0.0.0/0"], "keepAlive": 1}]}}]
}`, apiPort, clientPort, relay.port))
	defer CloseAllServers(servers)

	conn := dialWorking(t, clientPort)
	defer conn.Close()

	removeOutbound(t, apiPort, "out")

	if !waitBroken(conn, 5*time.Second) {
		t.Fatal("the connection through the removed outbound still works")
	}
	// The peer has a keepalive of one second; a closed device sends nothing.
	sent := relay.packets.Load()
	time.Sleep(3 * time.Second)
	if n := relay.packets.Load() - sent; n != 0 {
		t.Fatal("the removed outbound still sent ", n, " packets to its peer")
	}
}

func TestRemoveOutboundFreedom(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	apiPort, clientPort := tcp.PickPort(), tcp.PickPort()
	servers := startXrayFromJSON(t, fmt.Sprintf(`{
	"log": {"loglevel": "info"},
	"api": {"tag": "api", "listen": "127.0.0.1:%d", "services": ["HandlerService"]},
	"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1", "rewritePort": %d, "allowedNetwork": "tcp"}}],
	"outbounds": [{"tag": "out", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
}`, apiPort, clientPort, dest.Port))
	defer CloseAllServers(servers)

	conn := dialWorking(t, clientPort)
	defer conn.Close()

	removeOutbound(t, apiPort, "out")

	if !waitBroken(conn, 5*time.Second) {
		t.Fatal("the connection through the removed outbound still works")
	}
}

// TestRemoveOutboundMux feeds the mux outbound from a Shadowsocks inbound,
// which hands it a pipe, so its session lives on in a shared mux connection.
func TestRemoveOutboundMux(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort, apiPort, clientPort, hopPort := tcp.PickPort(), tcp.PickPort(), tcp.PickPort(), tcp.PickPort()
	id := "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b1"
	servers := startXrayFromJSON(t, fmt.Sprintf(`{
	"log": {"loglevel": "info"},
	"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": "%s"}]}}],
	"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
}`, serverPort, id), fmt.Sprintf(`{
	"log": {"loglevel": "info"},
	"api": {"tag": "api", "listen": "127.0.0.1:%d", "services": ["HandlerService"]},
	"inbounds": [
		{"tag": "front", "listen": "127.0.0.1", "port": %d, "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1", "rewritePort": %d, "allowedNetwork": "tcp"}},
		{"tag": "ss", "listen": "127.0.0.1", "port": %d, "protocol": "shadowsocks", "settings": {"method": "aes-128-gcm", "password": "pass", "network": "tcp"}}
	],
	"outbounds": [
		{"tag": "out", "protocol": "vless", "settings": {"address": "127.0.0.1", "port": %d, "id": "%s", "encryption": "none"}, "mux": {"enabled": true}},
		{"tag": "hop", "protocol": "shadowsocks", "settings": {"address": "127.0.0.1", "port": %d, "method": "aes-128-gcm", "password": "pass"}}
	],
	"routing": {"rules": [
		{"inboundTag": ["front"], "outboundTag": "hop"},
		{"inboundTag": ["ss"], "outboundTag": "out"}
	]}
}`, apiPort, clientPort, dest.Port, hopPort, serverPort, id, hopPort))
	defer CloseAllServers(servers)

	conn := dialWorking(t, clientPort)
	defer conn.Close()

	removeOutbound(t, apiPort, "out")

	if !waitBroken(conn, 5*time.Second) {
		t.Fatal("the connection through the removed mux outbound still works")
	}
}

// startXrayFromJSON starts one xray per JSON config and waits for them like
// InitializeServerConfigs does.
func startXrayFromJSON(t *testing.T, configs ...string) []*exec.Cmd {
	t.Helper()
	common.Must(BuildXray())
	var servers []*exec.Cmd
	for _, config := range configs {
		pb, err := confserial.LoadJSONConfig(strings.NewReader(config))
		if err != nil {
			CloseAllServers(servers)
			t.Fatal(err)
		}
		b, err := proto.Marshal(pb)
		common.Must(err)
		server := RunXrayProtobuf(b)
		if err := server.Start(); err != nil {
			CloseAllServers(servers)
			t.Fatal(err)
		}
		servers = append(servers, server)
	}
	time.Sleep(2 * time.Second)
	return servers
}

// dialWorking connects to port and returns once the echo through it works.
func dialWorking(t *testing.T, port net.Port) net.Conn {
	t.Helper()
	var err error
	for range 50 {
		var conn net.Conn
		if conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			if err = testTCPConn2(conn, 64, time.Second)(); err == nil {
				return conn
			}
			conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no echo through port ", port, ": ", err)
	return nil
}

// waitBroken reports whether the echo over conn stops working within timeout.
func waitBroken(conn net.Conn, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if testTCPConn2(conn, 64, time.Second)() != nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// removeOutbound removes the outbound tagged tag through the API.
func removeOutbound(t *testing.T, apiPort net.Port, tag string) {
	t.Helper()
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	common.Must(err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := command.NewHandlerServiceClient(conn).RemoveOutbound(ctx, &command.RemoveOutboundRequest{Tag: tag}); err != nil {
		t.Fatal(err)
	}
}

// packetRelay forwards UDP between one client and a server on localhost and
// counts the packets the client sends.
type packetRelay struct {
	port    net.Port
	packets atomic.Int64
}

func startPacketRelay(t *testing.T, serverPort net.Port) *packetRelay {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	common.Must(err)
	t.Cleanup(func() { conn.Close() })
	r := &packetRelay{port: net.Port(conn.LocalAddr().(*net.UDPAddr).Port)}
	server := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(serverPort)}
	go func() {
		var client *net.UDPAddr
		b := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDP(b)
			if err != nil {
				return
			}
			if from.Port == server.Port {
				if client != nil {
					conn.WriteToUDP(b[:n], client)
				}
				continue
			}
			client = from
			r.packets.Add(1)
			conn.WriteToUDP(b[:n], server)
		}
	}()
	return r
}
