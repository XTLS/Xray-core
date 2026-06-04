package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	gonet "net"
	"strconv"
	"testing"
	"time"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	xssh "golang.org/x/crypto/ssh"
)

func TestClientRejectsUDP(t *testing.T) {
	instance := newTestCore(t)
	client, err := NewClient(contextWithCore(instance), &ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
			Port:    22,
			User: &protocol.User{Account: serial.ToTypedMessage(&Account{
				Username: "root",
				Password: "secret",
			})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: xnet.UDPDestination(xnet.DomainAddress("example.com"), 53),
	}})
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: reader, Writer: writer}
	err = client.Process(ctx, link, systemDialer{})
	if err == nil {
		t.Fatal("expected UDP unsupported error")
	}
}

func TestClientForwardsTCPThroughSSH(t *testing.T) {
	echoAddr := startOneShotTCPEchoServer(t)
	sshAddr, password, fingerprint := startDirectTCPIPSSHServer(t)
	instance := newTestCore(t)

	sshHost, sshPortText, err := gonet.SplitHostPort(sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	sshPort, err := strconv.Atoi(sshPortText)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(contextWithCore(instance), &ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.ParseAddress(sshHost)),
			Port:    uint32(sshPort),
			User: &protocol.User{Account: serial.ToTypedMessage(&Account{
				Username:      "root",
				Password:      password,
				HostKeySha256: fingerprint,
			})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	targetHost, targetPortText, err := gonet.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, err := strconv.Atoi(targetPortText)
	if err != nil {
		t.Fatal(err)
	}

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: xnet.TCPDestination(xnet.ParseAddress(targetHost), xnet.Port(targetPort)),
	}})

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Process(ctx, link, systemDialer{})
	}()

	payload := "hello-over-ssh"
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(payload))}); err != nil {
		t.Fatal(err)
	}
	common.Close(uplinkWriter)

	response, err := downlinkReader.ReadMultiBufferTimeout(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(response)
	if got := response.String(); got != payload {
		t.Fatalf("got %q, want %q", got, payload)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish")
	}
}

type systemDialer struct{}

func (systemDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	return internet.DialSystem(ctx, destination, nil)
}

func (systemDialer) DestIpAddress() xnet.IP {
	return nil
}

func (systemDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

func newTestCore(t *testing.T) *core.Instance {
	t.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&policyapp.Config{}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func contextWithCore(instance *core.Instance) context.Context {
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func startOneShotTCPEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(listener) })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer common.Close(conn)
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		_, _ = conn.Write(buffer[:n])
	}()
	return listener.Addr().String()
}

func startDirectTCPIPSSHServer(t *testing.T) (addr string, password string, fingerprint string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	password = "secret"
	config := &xssh.ServerConfig{
		PasswordCallback: func(conn xssh.ConnMetadata, pass []byte) (*xssh.Permissions, error) {
			if conn.User() == "root" && string(pass) == password {
				return nil, nil
			}
			return nil, errors.New("unauthorized")
		},
	}
	config.AddHostKey(signer)

	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Close(listener) })

	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleSSHConn(rawConn, config)
		}
	}()

	return listener.Addr().String(), password, xssh.FingerprintSHA256(signer.PublicKey())
}

func handleSSHConn(rawConn gonet.Conn, config *xssh.ServerConfig) {
	serverConn, channels, requests, err := xssh.NewServerConn(rawConn, config)
	if err != nil {
		common.Close(rawConn)
		return
	}
	go xssh.DiscardRequests(requests)
	go func() {
		defer common.Close(serverConn)
		for newChannel := range channels {
			if newChannel.ChannelType() != "direct-tcpip" {
				_ = newChannel.Reject(xssh.UnknownChannelType, "unsupported channel type")
				continue
			}
			var payload directTCPIPChannelData
			if err := xssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
				_ = newChannel.Reject(xssh.ConnectionFailed, "invalid direct-tcpip payload")
				continue
			}
			targetAddr := gonet.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort)))
			targetConn, err := gonet.Dial("tcp", targetAddr)
			if err != nil {
				_ = newChannel.Reject(xssh.ConnectionFailed, err.Error())
				continue
			}
			channel, channelRequests, err := newChannel.Accept()
			if err != nil {
				common.Close(targetConn)
				continue
			}
			go xssh.DiscardRequests(channelRequests)
			go relaySSHChannel(channel, targetConn)
		}
	}()
}

type directTCPIPChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func relaySSHChannel(channel xssh.Channel, targetConn gonet.Conn) {
	defer common.Close(channel)
	defer common.Close(targetConn)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(channel, targetConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(targetConn, channel)
		done <- struct{}{}
	}()
	<-done
}
