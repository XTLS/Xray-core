package scenarios

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestShadowsocks2022TCPTeardown(t *testing.T) {
	for _, multiUser := range []bool{false, true} {
		name := "single"
		if multiUser {
			name = "multi"
		}
		t.Run(name, func(t *testing.T) {
			key := make([]byte, 16)
			masterKey := make([]byte, 16)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(masterKey); err != nil {
				t.Fatal(err)
			}
			port := tcp.PickPort()
			settings := serial.ToTypedMessage(&shadowsocks_2022.ServerConfig{
				Method: shadowsocks_2022.MethodAES128GCM, Key: base64.StdEncoding.EncodeToString(key), Network: []net.Network{net.Network_TCP},
			})
			keys := [][]byte{key}
			if multiUser {
				settings = serial.ToTypedMessage(&shadowsocks_2022.MultiUserServerConfig{
					Method: shadowsocks_2022.MethodAES128GCM, Key: base64.StdEncoding.EncodeToString(masterKey), Network: []net.Network{net.Network_TCP},
					Users: []*protocol.User{{Email: "teardown-test", Account: serial.ToTypedMessage(&shadowsocks_2022.Account{Key: base64.StdEncoding.EncodeToString(key)})}},
				})
				keys = [][]byte{masterKey, key}
			}
			servers, err := InitializeServerConfigs(&core.Config{
				App: []*serial.TypedMessage{serial.ToTypedMessage(&policy.Config{
					Level: map[uint32]*policy.Policy{0: {Timeout: &policy.Policy_Timeout{
						ConnectionIdle: &policy.Second{Value: 30},
						UplinkOnly:     &policy.Second{Value: 30},
						DownlinkOnly:   &policy.Second{Value: 30},
					}}},
				})},
				Inbound: []*core.InboundHandlerConfig{{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}),
					ProxySettings:    settings,
				}},
				Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{
					// The destination is a legitimate loopback test peer.
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				})}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer CloseAllServers(servers)
			for _, mode := range []string{"half-close", "close", "reset"} {
				t.Run(mode, func(t *testing.T) {
					testShadowsocks2022Teardown(t, port, keys, mode)
				})
			}
		})
	}
}

func testShadowsocks2022Teardown(t *testing.T, port net.Port, keys [][]byte, mode string) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("request before EOF"), 1024)
	ack := []byte("delayed final response")
	peerDone := make(chan error, 1)
	go func() {
		peer, err := listener.AcceptTCP()
		if err != nil {
			peerDone <- err
			return
		}
		defer peer.Close()
		if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			peerDone <- err
			return
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, got); err != nil {
			peerDone <- err
			return
		}
		if !bytes.Equal(got, payload) {
			peerDone <- io.ErrUnexpectedEOF
			return
		}
		// Prove dispatch and Freedom delivered all request bytes before client teardown.
		if _, err := peer.Write([]byte("ready")); err != nil {
			peerDone <- err
			return
		}
		var extra [1]byte
		_, err = peer.Read(extra[:])
		if err != io.EOF {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			peerDone <- err
			return
		}
		err = nil
		if mode == "half-close" {
			time.Sleep(150 * time.Millisecond)
			_, err = peer.Write(ack)
		}
		peerDone <- err
	}()
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.LocalHostIP.IP(), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	method, err := shadowsocks_2022.GetCipherMethod(shadowsocks_2022.MethodAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, method.KeySaltLength)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	writer, err := shadowsocks_2022.WriteTCPRequest(conn, method, keys, net.DestinationFromAddr(listener.Addr()), salt, payload[:1024])
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload[1024:])); err != nil {
		t.Fatal(err)
	}
	reader, err := shadowsocks_2022.ReadTCPResponse(conn, method, keys[len(keys)-1], salt)
	if err != nil {
		t.Fatal(err)
	}
	buffered := &buf.BufferedReader{Reader: reader}
	var ready [5]byte
	if _, err := io.ReadFull(buffered, ready[:]); err != nil || string(ready[:]) != "ready" {
		t.Fatalf("peer readiness: %q, %v", ready[:], err)
	}
	switch mode {
	case "half-close":
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(buffered)
		if err != nil || !bytes.Equal(got, ack) {
			t.Errorf("EOF-dependent delayed response: %q, %v", got, err)
		}
	case "close":
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	case "reset":
		if err := conn.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-peerDone:
		if err != nil {
			t.Errorf("target request EOF: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("target connection survived client teardown")
	}
}
