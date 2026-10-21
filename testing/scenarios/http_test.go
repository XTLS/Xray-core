package scenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	v2http "github.com/xtls/xray-core/proxy/http"
	v2httptest "github.com/xtls/xray-core/testing/servers/http"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestHttpConformance(t *testing.T) {
	httpServerPort := tcp.PickPort()
	httpServer := &v2httptest.Server{
		Port:        httpServerPort,
		PathHandler: make(map[string]http.HandlerFunc),
	}
	_, err := httpServer.Start()
	common.Must(err)
	defer httpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://127.0.0.1:" + serverPort.String())
			},
		}

		client := &http.Client{
			Transport: transport,
		}

		resp, err := client.Get("http://127.0.0.1:" + httpServerPort.String())
		common.Must(err)
		if resp.StatusCode != 200 {
			t.Fatal("status: ", resp.StatusCode)
		}

		content, err := io.ReadAll(resp.Body)
		common.Must(err)
		if string(content) != "Home" {
			t.Fatal("body: ", string(content))
		}
	}
}

func TestHttpError(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: func(msg []byte) []byte {
			return []byte{}
		},
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	time.AfterFunc(time.Second*2, func() {
		tcpServer.ShouldClose = true
	})

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://127.0.0.1:" + serverPort.String())
			},
		}

		client := &http.Client{
			Transport: transport,
		}

		resp, err := client.Get("http://127.0.0.1:" + dest.Port.String())
		if resp != nil && resp.StatusCode != 503 || err != nil && !strings.Contains(err.Error(), "malformed HTTP status code") {
			t.Error("should not receive http response", err)
		}
	}
}

func TestHTTPConnectMethod(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://127.0.0.1:" + serverPort.String())
			},
		}

		client := &http.Client{
			Transport: transport,
		}

		payload := make([]byte, 1024*64)
		common.Must2(rand.Read(payload))

		ctx := context.Background()
		req, err := http.NewRequestWithContext(ctx, "Connect", "http://"+dest.NetAddr()+"/", bytes.NewReader(payload))
		req.Header.Set("X-a", "b")
		req.Header.Set("X-b", "d")
		common.Must(err)

		resp, err := client.Do(req)
		common.Must(err)
		if resp.StatusCode != 200 {
			t.Fatal("status: ", resp.StatusCode)
		}

		content := make([]byte, len(payload))
		common.Must2(io.ReadFull(resp.Body, content))
		if r := cmp.Diff(content, xor(payload)); r != "" {
			t.Fatal(r)
		}
	}
}

func TestHttpPost(t *testing.T) {
	httpServerPort := tcp.PickPort()
	httpServer := &v2httptest.Server{
		Port: httpServerPort,
		PathHandler: map[string]http.HandlerFunc{
			"/testpost": func(w http.ResponseWriter, r *http.Request) {
				payload, err := buf.ReadAllToBytes(r.Body)
				r.Body.Close()

				if err != nil {
					w.WriteHeader(500)
					w.Write([]byte("Unable to read all payload"))
					return
				}
				payload = xor(payload)
				w.Write(payload)
			},
		},
	}

	_, err := httpServer.Start()
	common.Must(err)
	defer httpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://127.0.0.1:" + serverPort.String())
			},
		}

		client := &http.Client{
			Transport: transport,
		}

		payload := make([]byte, 1024*64)
		common.Must2(rand.Read(payload))

		resp, err := client.Post("http://127.0.0.1:"+httpServerPort.String()+"/testpost", "application/x-www-form-urlencoded", bytes.NewReader(payload))
		common.Must(err)
		if resp.StatusCode != 200 {
			t.Fatal("status: ", resp.StatusCode)
		}

		content, err := io.ReadAll(resp.Body)
		common.Must(err)
		if r := cmp.Diff(content, xor(payload)); r != "" {
			t.Fatal(r)
		}
	}
}

func setProxyBasicAuth(req *http.Request, user, pass string) {
	req.SetBasicAuth(user, pass)
	req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	req.Header.Del("Authorization")
}

func TestHttpBasicAuth(t *testing.T) {
	httpServerPort := tcp.PickPort()
	httpServer := &v2httptest.Server{
		Port:        httpServerPort,
		PathHandler: make(map[string]http.HandlerFunc),
	}
	_, err := httpServer.Start()
	common.Must(err)
	defer httpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{
					Accounts: map[string]string{
						"a": "b",
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://127.0.0.1:" + serverPort.String())
			},
		}

		client := &http.Client{
			Transport: transport,
		}

		{
			resp, err := client.Get("http://127.0.0.1:" + httpServerPort.String())
			common.Must(err)
			if resp.StatusCode != 407 {
				t.Fatal("status: ", resp.StatusCode)
			}
		}

		{
			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+httpServerPort.String(), nil)
			common.Must(err)

			setProxyBasicAuth(req, "a", "c")
			resp, err := client.Do(req)
			common.Must(err)
			if resp.StatusCode != 407 {
				t.Fatal("status: ", resp.StatusCode)
			}
		}

		{
			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+httpServerPort.String(), nil)
			common.Must(err)

			setProxyBasicAuth(req, "a", "b")
			resp, err := client.Do(req)
			common.Must(err)
			if resp.StatusCode != 200 {
				t.Fatal("status: ", resp.StatusCode)
			}

			content, err := io.ReadAll(resp.Body)
			common.Must(err)
			if string(content) != "Home" {
				t.Fatal("body: ", string(content))
			}
		}
	}
}

// Server-first protocols (SMTP, FTP, MySQL) send nothing from the client until the server's
// greeting arrives, so the HTTP outbound must not wait for a first payload before dialing.
func TestHTTPOutboundServerFirst(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
		SendFirst:    []byte("send first"),
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&v2http.ClientConfig{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   []byte{127, 0, 0, 1},
		Port: int(clientPort),
	})
	common.Must(err)
	defer conn.Close()

	common.Must(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
	response := make([]byte, 1024)
	nBytes, err := conn.Read(response)
	if err != nil {
		t.Fatal("no server greeting through HTTP outbound: ", err)
	}
	if string(response[:nBytes]) != "send first" {
		t.Fatal("unexpected first response: ", string(response[:nBytes]))
	}
	common.Must(conn.SetReadDeadline(time.Time{}))

	if err := testTCPConn2(conn, 1024, time.Second*5)(); err != nil {
		t.Error(err)
	}
}
