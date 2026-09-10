package scenarios

import (
	"bytes"
	"encoding/binary"
	"io"
	gonet "net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// startCloseAfterUploadWSServer starts a plain WebSocket server that upgrades
// the connection, counts received payload bytes, and once count >= want,
// optionally sends respond as a final binary message, then performs a
// WebSocket close handshake (close frame + TCP FIN) without sending any VLESS
// response header. This mimics a WS server closing the connection right after
// receiving the full upstream request.
func startCloseAfterUploadWSServer(t *testing.T, want int64, respond []byte) net.Port {
	t.Helper()
	upgrader := gorillaws.Upgrader{
		ReadBufferSize:  4 * 1024,
		WriteBufferSize: 4 * 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	var received int64
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			total := atomic.AddInt64(&received, int64(len(data)))
			if total >= want {
				if len(respond) > 0 {
					conn.WriteMessage(gorillaws.BinaryMessage, respond)
				}
				conn.WriteControl(gorillaws.CloseMessage,
					gorillaws.FormatCloseMessage(gorillaws.CloseNormalClosure, "Bye"),
					time.Now().Add(time.Second))
				return // defer conn.Close() sends the TCP FIN
			}
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().(*gonet.TCPAddr)
	return net.Port(addr.Port)
}

// socks5Connect performs a minimal SOCKS5 TCP CONNECT handshake and returns
// the established connection.
func socks5Connect(t *testing.T, proxyPort net.Port) gonet.Conn {
	t.Helper()
	c, err := gonet.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(proxyPort)))
	common.Must(err)
	_, err = c.Write([]byte{5, 1, 0})
	common.Must(err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(c, greeting)
	common.Must(err)
	if greeting[0] != 5 || greeting[1] != 0 {
		t.Fatal("unexpected socks greeting reply: ", greeting)
	}
	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], 80)
	_, err = c.Write(req)
	common.Must(err)
	reply := make([]byte, 10)
	_, err = io.ReadFull(c, reply)
	common.Must(err)
	if reply[1] != 0 {
		t.Fatal("socks CONNECT failed: ", reply)
	}
	return c
}

func testUploadWithWSServerClose(t *testing.T, payloadSize int, respond []byte) {
	wsPort := startCloseAfterUploadWSServer(t, int64(payloadSize), respond)

	userID := protocol.NewID(uuid.New())
	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(wsPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "websocket",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "websocket",
								Settings:     serial.ToTypedMessage(&websocket.Config{}),
							},
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	conn := socks5Connect(t, clientPort)
	defer conn.Close()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	_, err = conn.Write(payload)
	common.Must(err)

	// After the WS server closes the upstream connection, the client is
	// expected to close the socks inbound connection promptly, so the
	// downstream client (curl-like) sees EOF instead of hanging.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("connection not closed after WS server closed (payload %d bytes): %v", payloadSize, err)
	}
	// The 2-byte VLESS response header is consumed by the client, the body is
	// passed through to the downstream connection.
	var wantDownstream []byte
	if len(respond) >= 2 {
		wantDownstream = respond[2:]
	}
	if !bytes.Equal(data, wantDownstream) {
		t.Fatalf("unexpected downstream data: got %d bytes, want %d", len(data), len(wantDownstream))
	}
}

func TestWSUploadServerCloseSmall(t *testing.T) {
	testUploadWithWSServerClose(t, 8000, nil)
}

func TestWSUploadServerCloseBig(t *testing.T) {
	testUploadWithWSServerClose(t, 20000, nil)
}

// TestWSUploadServerRespondThenCloseBig mirrors the production symptom: the
// server sends a (VLESS) response and then closes the connection after the
// client has uploaded more than one buffer worth of data. The downstream
// client must still receive the full response followed by EOF.
func TestWSUploadServerRespondThenCloseBig(t *testing.T) {
	response := make([]byte, 102)
	response[0] = 0 // VLESS response version
	response[1] = 0 // addons length
	for i := 2; i < len(response); i++ {
		response[i] = byte(i)
	}
	testUploadWithWSServerClose(t, 20000, response)
}
