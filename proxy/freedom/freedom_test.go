package freedom_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	apolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

type connectedDialer struct {
	conn stat.Connection
}

func (d connectedDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	return d.conn, nil
}
func (connectedDialer) DestIpAddress() xnet.IP                                { return nil }
func (connectedDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestFreedomRequestEOF(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "stats-TCP"
		if encrypted {
			name = "stats-TLS"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			var clientConn net.Conn = client
			var serverConn net.Conn = server
			if encrypted {
				generated, err := cert.Generate(nil, cert.DNSNames("localhost"))
				if err != nil {
					t.Fatal(err)
				}
				certPEM, keyPEM := generated.ToPEM()
				pair, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM(certPEM)
				clientConn = xtls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost"})
				serverConn = tls.Server(server, &tls.Config{Certificates: []tls.Certificate{pair}})
			}
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte("request"), 1024)
			ack := []byte("delayed ACK")
			peerDone := make(chan error, 1)
			go func() {
				got, err := io.ReadAll(serverConn)
				if err != nil {
					peerDone <- err
					return
				}
				if !bytes.Equal(got, payload) {
					peerDone <- io.ErrUnexpectedEOF
					return
				}
				if encrypted {
					// TLS EOF must come from close_notify, without closing the raw TCP write half.
					server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					var b [1]byte
					_, err = server.Read(b[:])
					if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
						peerDone <- io.ErrClosedPipe
						return
					}
					server.SetReadDeadline(time.Now().Add(3 * time.Second))
				}
				time.Sleep(150 * time.Millisecond)
				_, err = serverConn.Write(ack)
				if err == nil {
					err = serverConn.Close()
				}
				peerDone <- err
			}()
			manager, err := apolicy.New(context.Background(), &apolicy.Config{})
			if err != nil {
				t.Fatal(err)
			}
			handler := new(freedom.Handler)
			if err := handler.Init(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}, manager); err != nil {
				t.Fatal(err)
			}
			request, requestWriter := pipe.New(pipe.WithSizeLimit(-1))
			response, responseWriter := pipe.New(pipe.WithSizeLimit(-1))
			defer request.Interrupt()
			defer response.Interrupt()
			if err := requestWriter.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
				t.Fatal(err)
			}
			requestWriter.Close()
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.DestinationFromAddr(listener.Addr())}})
			ctx = session.ContextWithInbound(ctx, &session.Inbound{})
			readCount, writeCount := new(stats.Counter), new(stats.Counter)
			conn := &stat.CounterConnection{Connection: clientConn, ReadCounter: readCount, WriteCounter: writeCount}
			done := make(chan error, 1)
			go func() {
				done <- handler.Process(ctx, &transport.Link{Reader: request, Writer: responseWriter}, connectedDialer{conn: conn})
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("Freedom did not finish EOF-dependent response")
			}
			mb, err := response.ReadMultiBufferTimeout(time.Second)
			if err != nil {
				t.Fatal(err)
			}
			got := mb.String()
			buf.ReleaseMulti(mb)
			if got != string(ack) {
				t.Fatalf("response: %q", got)
			}
			if readCount.Value() != int64(len(ack)) || writeCount.Value() != int64(len(payload)) {
				t.Fatalf("stats lost across half-close: read=%d write=%d", readCount.Value(), writeCount.Value())
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
