package scenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// These tests remove a user through the API while the user has live
// connections, as panels do once a user runs out of traffic or time.

var removeUserIDs = map[string]string{
	"a": "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b1",
	"b": "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b2",
}

// SS2022 keys: the server's, then one per user.
var (
	removeUserSSKey  = "MTIzNDU2Nzg5MGFiY2RlZg=="
	removeUserSSKeys = map[string]string{"a": "YWFhYWFhYWFhYWFhYWFhYQ==", "b": "YmJiYmJiYmJiYmJiYmJiYg=="}
)

// WireGuard keys of the server, then per user the private key, the public key
// and the tunnel address.
var (
	removeUserWGServer = [2]string{"CAVR/i06MRIXIAkaxBPcm22HR/4ysXozQts0k70CAFY=", "szB6HtF+/8zWQEljyFKKO8J3PAbnRJvcwTEXhINIkCM="}
	removeUserWG       = map[string][3]string{
		"a": {"wLlk5z+PrEQnnLOBfd8aIe/p+Ly2ukDPBttPpWca2ng=", "E8vVtPmuVMsqokMjuFNAYpNheY+Ks0PIJ4RuyCthAEs=", "10.0.0.2"},
		"b": {"ANOI5GOcX1PMYNbUODnBkxYyOfTB5a2VchP8sS7/jGA=", "R0cQLrEa6A8Nmf2aTPakSz6meu+tmt61ki4m4rNaF1g=", "10.0.0.3"},
	}
)

// removeUserServer is the server: an API, the inbounds, and a freedom
// outbound that sends everything to the echo server.
const removeUserServer = `{
	"log": {"loglevel": "info"},
	"api": {"tag": "api", "listen": "127.0.0.1:%d", "services": ["HandlerService"]},
	"inbounds": [%s],
	"outbounds": [{"protocol": "freedom", "settings": {"redirect": "%s", "finalRules": [{"action": "allow"}]}}]
}`

// removeUserClient is the client: what comes in on inbound "a" goes out
// through outbound "a", the same for "b". The target is the WireGuard
// server's tunnel address; the server's freedom redirects it anyway.
const removeUserClient = `{
	"log": {"loglevel": "info"},
	"inbounds": [
		{"tag": "a", "listen": "127.0.0.1", "port": %d, "protocol": "tunnel", "settings": {"rewriteAddress": "10.0.0.1", "rewritePort": 80, "allowedNetwork": "%s"}},
		{"tag": "b", "listen": "127.0.0.1", "port": %d, "protocol": "tunnel", "settings": {"rewriteAddress": "10.0.0.1", "rewritePort": 80, "allowedNetwork": "%s"}}
	],
	"outbounds": [{"tag": "a", %s}, {"tag": "b", %s}],
	"routing": {"rules": [
		{"inboundTag": ["a"], "outboundTag": "a"},
		{"inboundTag": ["b"], "outboundTag": "b"}
	]}
}`

// removeUserInbound is a server inbound; settings is its protocol part.
func removeUserInbound(tag string, port net.Port, settings string) string {
	return fmt.Sprintf(`{"tag": "%s", "listen": "127.0.0.1", "port": %d, %s}`, tag, port, settings)
}

type removeUserCase struct {
	name string
	// network is what the client sends through the proxy, "tcp" or "udp".
	network string
	// udpServer means the server listens on UDP even for TCP traffic.
	udpServer bool
	// inbound is the protocol part of the server inbound, with the users
	// a@test and b@test.
	inbound func(tls string) string
	// outbound is the protocol part of the client outbound for user u ("a" or
	// "b") to a server on port.
	outbound func(u string, port net.Port, tls string) string
}

var removeUserCases = []removeUserCase{
	{
		name:    "VLESS",
		network: "tcp",
		inbound: func(string) string {
			return fmt.Sprintf(`"protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": "%s", "email": "a@test"}, {"id": "%s", "email": "b@test"}]}`, removeUserIDs["a"], removeUserIDs["b"])
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "vless", "settings": {"address": "127.0.0.1", "port": %d, "id": "%s", "encryption": "none"}`, port, removeUserIDs[u])
		},
	},
	{
		name:    "VLESSMux",
		network: "tcp",
		inbound: func(string) string {
			return fmt.Sprintf(`"protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": "%s", "email": "a@test"}, {"id": "%s", "email": "b@test"}]}`, removeUserIDs["a"], removeUserIDs["b"])
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "vless", "settings": {"address": "127.0.0.1", "port": %d, "id": "%s", "encryption": "none"}, "mux": {"enabled": true}`, port, removeUserIDs[u])
		},
	},
	{
		name:    "VLESSVision",
		network: "tcp",
		inbound: func(tls string) string {
			return fmt.Sprintf(`"protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": "%s", "flow": "xtls-rprx-vision", "email": "a@test"}, {"id": "%s", "flow": "xtls-rprx-vision", "email": "b@test"}]}, "streamSettings": {"network": "raw", %s}`, removeUserIDs["a"], removeUserIDs["b"], tls)
		},
		outbound: func(u string, port net.Port, tls string) string {
			return fmt.Sprintf(`"protocol": "vless", "settings": {"address": "127.0.0.1", "port": %d, "id": "%s", "flow": "xtls-rprx-vision", "encryption": "none"}, "streamSettings": {"network": "raw", %s}`, port, removeUserIDs[u], tls)
		},
	},
	{
		name:    "VMess",
		network: "tcp",
		inbound: func(string) string {
			return fmt.Sprintf(`"protocol": "vmess", "settings": {"clients": [{"id": "%s", "email": "a@test"}, {"id": "%s", "email": "b@test"}]}`, removeUserIDs["a"], removeUserIDs["b"])
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "vmess", "settings": {"address": "127.0.0.1", "port": %d, "id": "%s"}`, port, removeUserIDs[u])
		},
	},
	{
		name:    "Trojan",
		network: "tcp",
		inbound: func(string) string {
			return `"protocol": "trojan", "settings": {"clients": [{"password": "pass-a", "email": "a@test"}, {"password": "pass-b", "email": "b@test"}]}`
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "trojan", "settings": {"address": "127.0.0.1", "port": %d, "password": "pass-%s"}`, port, u)
		},
	},
	{
		name:    "ShadowsocksTCP",
		network: "tcp",
		inbound: func(string) string {
			return `"protocol": "shadowsocks", "settings": {"network": "tcp,udp", "clients": [{"method": "aes-128-gcm", "password": "pass-a", "email": "a@test"}, {"method": "aes-128-gcm", "password": "pass-b", "email": "b@test"}]}`
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "shadowsocks", "settings": {"address": "127.0.0.1", "port": %d, "method": "aes-128-gcm", "password": "pass-%s"}`, port, u)
		},
	},
	{
		name:    "ShadowsocksUDP",
		network: "udp",
		inbound: func(string) string {
			return `"protocol": "shadowsocks", "settings": {"network": "tcp,udp", "clients": [{"method": "aes-128-gcm", "password": "pass-a", "email": "a@test"}, {"method": "aes-128-gcm", "password": "pass-b", "email": "b@test"}]}`
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "shadowsocks", "settings": {"address": "127.0.0.1", "port": %d, "method": "aes-128-gcm", "password": "pass-%s"}`, port, u)
		},
	},
	{
		name:    "Shadowsocks2022TCP",
		network: "tcp",
		inbound: func(string) string {
			return fmt.Sprintf(`"protocol": "shadowsocks", "settings": {"method": "2022-blake3-aes-128-gcm", "password": "%s", "network": "tcp,udp", "clients": [{"password": "%s", "email": "a@test"}, {"password": "%s", "email": "b@test"}]}`, removeUserSSKey, removeUserSSKeys["a"], removeUserSSKeys["b"])
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "shadowsocks", "settings": {"address": "127.0.0.1", "port": %d, "method": "2022-blake3-aes-128-gcm", "password": "%s:%s"}`, port, removeUserSSKey, removeUserSSKeys[u])
		},
	},
	{
		name:    "Shadowsocks2022UDP",
		network: "udp",
		inbound: func(string) string {
			return fmt.Sprintf(`"protocol": "shadowsocks", "settings": {"method": "2022-blake3-aes-128-gcm", "password": "%s", "network": "tcp,udp", "clients": [{"password": "%s", "email": "a@test"}, {"password": "%s", "email": "b@test"}]}`, removeUserSSKey, removeUserSSKeys["a"], removeUserSSKeys["b"])
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "shadowsocks", "settings": {"address": "127.0.0.1", "port": %d, "method": "2022-blake3-aes-128-gcm", "password": "%s:%s"}`, port, removeUserSSKey, removeUserSSKeys[u])
		},
	},
	{
		name:      "Hysteria",
		network:   "tcp",
		udpServer: true,
		inbound: func(tls string) string {
			return fmt.Sprintf(`"protocol": "hysteria", "settings": {"version": 2, "clients": [{"auth": "pass-a", "email": "a@test"}, {"auth": "pass-b", "email": "b@test"}]}, "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, %s}`, tls)
		},
		outbound: func(u string, port net.Port, tls string) string {
			return fmt.Sprintf(`"protocol": "hysteria", "settings": {"version": 2, "address": "127.0.0.1", "port": %d}, "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": "pass-%s"}, %s}`, port, u, tls)
		},
	},
	{
		name:      "WireGuard",
		network:   "tcp",
		udpServer: true,
		inbound: func(string) string {
			return fmt.Sprintf(`"protocol": "wireguard", "settings": {"secretKey": "%s", "address": ["10.0.0.1"], "mtu": 1420, "peers": [{"publicKey": "%s", "allowedIPs": ["10.0.0.2/32"], "email": "a@test"}, {"publicKey": "%s", "allowedIPs": ["10.0.0.3/32"], "email": "b@test"}]}`, removeUserWGServer[0], removeUserWG["a"][1], removeUserWG["b"][1])
		},
		outbound: func(u string, port net.Port, _ string) string {
			return fmt.Sprintf(`"protocol": "wireguard", "settings": {"secretKey": "%s", "address": ["%s"], "mtu": 1420, "noKernelTun": true, "peers": [{"endpoint": "127.0.0.1:%d", "publicKey": "%s", "allowedIPs": ["0.0.0.0/0"]}]}`, removeUserWG[u][0], removeUserWG[u][2], port, removeUserWGServer[1])
		},
	},
}

func TestRemoveUser(t *testing.T) {
	for _, c := range removeUserCases {
		t.Run(c.name, func(t *testing.T) {
			testRemoveUser(t, c)
		})
	}
}

func testRemoveUser(t *testing.T, c removeUserCase) {
	echo := startEchoServer(t)
	target := echo.addr
	if c.network == "udp" {
		udpServer := udp.Server{MsgProcessor: xor}
		dest, err := udpServer.Start()
		common.Must(err)
		defer udpServer.Close()
		target = dest.NetAddr()
	}

	pick := tcp.PickPort
	if c.network == "udp" {
		pick = udp.PickPort
	}
	serverPort := tcp.PickPort()
	if c.network == "udp" || c.udpServer {
		serverPort = udp.PickPort()
	}
	apiPort, portA, portB := tcp.PickPort(), pick(), pick()

	tlsServer, tlsClient := removeUserTLS()
	servers := startXrayJSON(t,
		fmt.Sprintf(removeUserServer, apiPort, removeUserInbound("in", serverPort, c.inbound(tlsServer)), target),
		fmt.Sprintf(removeUserClient, portA, c.network, portB, c.network,
			c.outbound("a", serverPort, tlsClient), c.outbound("b", serverPort, tlsClient)),
	)
	defer CloseAllServers(servers)

	connA, upA := dialEcho(t, echo, c.network, portA)
	defer connA.Close()
	connB, upB := dialEcho(t, echo, c.network, portB)
	defer connB.Close()

	removeUser(t, apiPort, "in", "a@test")

	if !waitEnded(connA, 5*time.Second) {
		t.Fatal("the removed user's connection still works")
	}
	if upA != nil {
		select {
		case <-upA.done:
		case <-time.After(5 * time.Second):
			t.Fatal("the server kept the removed user's upstream connection")
		}
	}
	if err := roundTrip(connB, time.Second); err != nil {
		t.Fatal("the other user's connection broke: ", err)
	}
	if upB != nil {
		select {
		case <-upB.done:
			t.Fatal("the server closed the other user's upstream connection")
		default:
		}
	}
	if conn, err := net.Dial(c.network, fmt.Sprintf("127.0.0.1:%d", portA)); err == nil {
		err = roundTrip(conn, 2*time.Second)
		conn.Close()
		if err == nil {
			t.Fatal("the removed user opened a new connection")
		}
	}
}

// TestRemoveUserKeepsOtherInbounds removes a user from one inbound only; the
// same user's connection through another inbound must keep working.
func TestRemoveUserKeepsOtherInbounds(t *testing.T) {
	echo := startEchoServer(t)
	apiPort, port1, port2 := tcp.PickPort(), tcp.PickPort(), tcp.PickPort()
	portA, portB := tcp.PickPort(), tcp.PickPort()
	inbound := fmt.Sprintf(`"protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": "%s", "email": "a@test"}]}`, removeUserIDs["a"])
	outbound := func(port net.Port) string {
		return fmt.Sprintf(`"protocol": "vless", "settings": {"address": "127.0.0.1", "port": %d, "id": "%s", "encryption": "none"}`, port, removeUserIDs["a"])
	}
	servers := startXrayJSON(t,
		fmt.Sprintf(removeUserServer, apiPort, removeUserInbound("in", port1, inbound)+", "+removeUserInbound("in2", port2, inbound), echo.addr),
		fmt.Sprintf(removeUserClient, portA, "tcp", portB, "tcp", outbound(port1), outbound(port2)),
	)
	defer CloseAllServers(servers)

	connA, _ := dialEcho(t, echo, "tcp", portA)
	defer connA.Close()
	connB, upB := dialEcho(t, echo, "tcp", portB)
	defer connB.Close()

	removeUser(t, apiPort, "in", "a@test")

	if !waitEnded(connA, 5*time.Second) {
		t.Fatal("the removed user's connection still works")
	}
	if err := roundTrip(connB, time.Second); err != nil {
		t.Fatal("the user's connection through the other inbound broke: ", err)
	}
	select {
	case <-upB.done:
		t.Fatal("the server closed the user's upstream through the other inbound")
	default:
	}
}

// removeUserTLS returns server and client TLS settings for a fresh
// self-signed certificate for localhost.
func removeUserTLS() (string, string) {
	ct, hash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	lines := func(b []byte) string {
		j, err := json.Marshal(strings.Split(strings.TrimSpace(string(b)), "\n"))
		common.Must(err)
		return string(j)
	}
	return fmt.Sprintf(`"security": "tls", "tlsSettings": {"certificates": [{"certificate": %s, "key": %s}]}`, lines(certPEM), lines(keyPEM)),
		fmt.Sprintf(`"security": "tls", "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": "%s"}`, hex.EncodeToString(hash[:]))
}

// startXrayJSON starts one xray per JSON config and waits for them like
// InitializeServerConfigs does.
func startXrayJSON(t *testing.T, configs ...string) []*exec.Cmd {
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

// echoServer answers each TCP connection with the xor of what it reads, and
// remembers which connection echoed last.
type echoServer struct {
	addr string
	last atomic.Pointer[echoConn]
}

// echoConn is one connection of the echo server; done is closed when it ends.
type echoConn struct {
	done chan struct{}
}

func startEchoServer(t *testing.T) *echoServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	t.Cleanup(func() { l.Close() })
	s := &echoServer{addr: l.Addr().String()}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *echoServer) serve(conn net.Conn) {
	c := &echoConn{done: make(chan struct{})}
	defer close(c.done)
	defer conn.Close()
	b := make([]byte, 32*1024)
	for {
		n, err := conn.Read(b)
		if n > 0 {
			s.last.Store(c)
			if _, err := conn.Write(xor(b[:n])); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// dialEcho connects to the client inbound on port and returns once a round
// trip through the whole chain works. For TCP it also returns the echo
// server's end of the connection.
func dialEcho(t *testing.T, echo *echoServer, network string, port net.Port) (net.Conn, *echoConn) {
	t.Helper()
	var err error
	for range 50 {
		var conn net.Conn
		if conn, err = net.Dial(network, fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			if err = roundTrip(conn, time.Second); err == nil {
				if network == "tcp" {
					return conn, echo.last.Load()
				}
				return conn, nil
			}
			conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no echo through port ", port, ": ", err)
	return nil, nil
}

// roundTrip sends 64 random bytes over conn and checks the echo.
func roundTrip(conn net.Conn, timeout time.Duration) error {
	payload := make([]byte, 64)
	common.Must2(rand.Read(payload))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	response, err := readFrom2(conn, timeout, len(payload))
	if err != nil {
		return err
	}
	if !bytes.Equal(response, xor(payload)) {
		return errors.New("wrong echo")
	}
	return nil
}

// waitEnded reports whether round trips over conn stop working within timeout.
func waitEnded(conn net.Conn, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if roundTrip(conn, time.Second) != nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// removeUser removes email from the inbound tagged tag through the API.
func removeUser(t *testing.T, apiPort net.Port, tag string, email string) {
	t.Helper()
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	common.Must(err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := command.NewHandlerServiceClient(conn).AlterInbound(ctx, &command.AlterInboundRequest{
		Tag:       tag,
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: email}),
	}); err != nil {
		t.Fatal(err)
	}
}
