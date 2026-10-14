package scenarios

import (
	"bufio"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
	xproxy "golang.org/x/net/proxy"
)

func TestSocksTCPClosure(t *testing.T) {
	// The direct connection verifies that the OS reports an abort as an error.
	t.Run("direct", func(t *testing.T) {
		testTCPClosure(t, &net.Dialer{Timeout: 5 * time.Second})
	})
	for _, splice := range []string{"disable", "enable"} {
		t.Run(splice, func(t *testing.T) {
			t.Setenv(platform.UseFreedomSplice, splice)
			for _, wrapped := range []bool{false, true} {
				name := "plain"
				if wrapped {
					name = "stats-sniffing"
				}
				t.Run(name, func(t *testing.T) {
					testTCPClosure(t, socksClosureDialer(t, wrapped))
				})
			}
		})
	}
}

func socksClosureDialer(t *testing.T, wrapped bool) xproxy.Dialer {
	t.Helper()
	port := tcp.PickPort()
	receiver := &proxyman.ReceiverConfig{
		PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
		Listen:   net.NewIPOrDomain(net.LocalHostIP),
	}
	server := &socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH}
	config := &core.Config{
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "direct",
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}
	var auth *xproxy.Auth
	if wrapped {
		receiver.SniffingSettings = &proxyman.SniffingConfig{
			Enabled: true, DestinationOverride: []string{"http"}, RouteOnly: true,
		}
		auth = &xproxy.Auth{User: "closure-test", Password: "test"}
		server.AuthType = socks.AuthType_PASSWORD
		server.Accounts = map[string]string{auth.User: auth.Password}
		config.App = []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				Level: map[uint32]*policy.Policy{0: {
					Stats: &policy.Policy_Stats{UserUplink: true, UserDownlink: true},
				}},
				System: &policy.SystemPolicy{Stats: &policy.SystemPolicy_Stats{
					InboundUplink: true, InboundDownlink: true,
					OutboundUplink: true, OutboundDownlink: true,
				}},
			}),
		}
	}
	config.Inbound = []*core.InboundHandlerConfig{{
		Tag: "socks", ReceiverSettings: serial.ToTypedMessage(receiver),
		ProxySettings: serial.ToTypedMessage(server),
	}}
	servers, err := InitializeServerConfigs(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CloseAllServers(servers) })
	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, port).NetAddr(), auth, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}

func testTCPClosure(t *testing.T, dialer xproxy.Dialer) {
	t.Helper()
	for _, fromTarget := range []bool{false, true} {
		name := "client"
		if fromTarget {
			name = "target-http"
		}
		t.Run(name, func(t *testing.T) {
			for _, abort := range []bool{false, true} {
				name := "fin"
				if abort {
					name = "reset"
				}
				t.Run(name, func(t *testing.T) {
					listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP{127, 0, 0, 1}})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					deadline := time.Now().Add(10 * time.Second)
					if err := listener.SetDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					clientConn, err := dialer.Dial("tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer clientConn.Close()
					client := clientConn.(*net.TCPConn)
					if err := client.SetDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					// Send a complete request before accepting, so sniffing can finish.
					request := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
					if _, err := io.WriteString(client, request); err != nil {
						t.Fatal(err)
					}
					target, err := listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					defer target.Close()
					if err := target.SetDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(target, make([]byte, len(request))); err != nil {
						t.Fatal(err)
					}
					if !fromTarget {
						// Ensure the response copier has started before the client FIN
						// sets the downlink-only timeout (splice installs its own timer).
						if _, err := target.Write([]byte{1}); err != nil {
							t.Fatal(err)
						}
						ready := make([]byte, 1)
						if _, err := io.ReadFull(client, ready); err != nil || ready[0] != 1 {
							t.Fatalf("response copier readiness: %v, %v", ready, err)
						}
					}

					sender, receiver := client, io.Reader(target)
					if fromTarget {
						// RFC 9112 section 8: an underlying connection error makes a
						// close-delimited response incomplete. EOF would hide truncation.
						if _, err := io.WriteString(target, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nprefix"); err != nil {
							t.Fatal(err)
						}
						response, err := http.ReadResponse(bufio.NewReader(client), nil)
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						prefix := make([]byte, len("prefix"))
						if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
							t.Fatalf("response prefix: %q, %v", prefix, err)
						}
						sender, receiver = target, response.Body
					}
					// The receiver has consumed all sent bytes before the abort.
					if abort {
						if err := sender.SetLinger(0); err != nil {
							t.Fatal(err)
						}
					}
					if err := sender.Close(); err != nil {
						t.Fatal(err)
					}
					remaining, err := io.ReadAll(receiver)
					if len(remaining) != 0 {
						t.Fatalf("unexpected remaining bytes: %q", remaining)
					}
					if abort {
						var opErr *gonet.OpError
						if !errors.As(err, &opErr) || opErr.Timeout() {
							t.Fatalf("abort must report a connection error, got %v", err)
						}
					} else if err != nil {
						t.Fatalf("ordinary FIN must report EOF, got %v", err)
					}
				})
			}
		})
	}
}
