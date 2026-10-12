package xdns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type tunnelObserved struct {
	data    []byte
	address string
	err     error
}

func startPlainTCPGateway(t *testing.T, exchange func(context.Context, []byte) ([]byte, error)) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				for {
					query, err := readDNSFrame(conn)
					if err != nil {
						return
					}
					response, err := exchange(ctx, query)
					if err != nil || writeDNSFrame(conn, response) != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { cancel(); listener.Close(); wg.Wait() })
	return &ResolverProto{Type: "tcp", Addr: listener.Addr().String()}, &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr())
	}}
}

func tunnelReply(data []byte) []byte {
	return append([]byte{0, 255, 0x80}, data[:min(len(data), 80)]...)
}

func TestResolverFullXDNSTunnel(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "quic", "https+h3"} {
		for _, qtype := range []int32{1, 5, 16, 28} {
			t.Run(fmt.Sprintf("%s/%d", protocol, qtype), func(t *testing.T) {
				raw, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				domain := &DomainProto{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{qtype}, Edns0: 4096}
				server, err := NewServer(&Config{Domains: []*DomainProto{domain}}, raw)
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				observed := make(chan tunnelObserved, 16)
				echoDone := make(chan struct{})
				go func() {
					defer close(echoDone)
					buf := make([]byte, 4096)
					for {
						n, addr, err := server.ReadFrom(buf)
						if err != nil {
							return
						}
						data := append([]byte(nil), buf[:n]...)
						_, err = server.WriteTo(tunnelReply(data), addr)
						observed <- tunnelObserved{data, addr.String(), err}
					}
				}()
				t.Cleanup(func() { server.Close(); <-echoDone })
				forward := func(ctx context.Context, query []byte) ([]byte, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, "udp", raw.LocalAddr().String())
					if err != nil {
						return nil, err
					}
					defer conn.Close()
					stop := context.AfterFunc(ctx, func() { conn.Close() })
					defer stop()
					deadline := time.Now().Add(resolverRequestTimeout)
					if d, ok := ctx.Deadline(); ok {
						deadline = d
					}
					conn.SetDeadline(deadline)
					if _, err := conn.Write(query); err != nil {
						return nil, err
					}
					buf := make([]byte, maxDNSMessageSize+1)
					n, err := conn.Read(buf)
					if n > maxDNSMessageSize {
						return nil, fmt.Errorf("oversized response")
					}
					return buf[:n], err
				}
				var resolver *ResolverProto
				var dialer *finalmask.Dialer
				switch protocol {
				case "udp":
					resolver = &ResolverProto{Type: "udp", Addr: raw.LocalAddr().String()}
					dialer = &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
						conn, err := net.ListenPacket("udp", "127.0.0.1:0")
						if err != nil {
							return nil, err
						}
						return &xnet.PacketConnWrapper{PacketConn: conn, Dest: raw.LocalAddr()}, nil
					}}
				case "tcp":
					resolver, dialer = startPlainTCPGateway(t, forward)
				case "tls":
					resolver, dialer = startDoTGateway(t, forward)
				case "quic":
					resolver, dialer = startDoQGateway(t, forward)
				default:
					handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						query, err := io.ReadAll(io.LimitReader(req.Body, maxDNSMessageSize+1))
						if err != nil || len(query) > maxDNSMessageSize {
							http.Error(w, "invalid query", 400)
							return
						}
						response, err := forward(req.Context(), query)
						if err != nil {
							http.Error(w, err.Error(), 502)
							return
						}
						w.Header().Set("Content-Type", "application/dns-message")
						w.Write(response)
					})
					if protocol == "https" {
						_, resolver, dialer = startDoHTestGateway(t, handler)
					} else {
						_, resolver, dialer = startDoH3TestGateway(t, handler)
					}
				}
				clients := make([]net.PacketConn, 2)
				for i := range clients {
					clients[i], err = NewClient(&Config{Domains: []*DomainProto{domain}, Resolvers: []*ResolverProto{resolver}}, dialer)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { clients[i].Close() })
				}
				addresses := make(map[int]string)
				for _, size := range []int{1, 64, 257, 4096} {
					for i, client := range clients {
						data := make([]byte, size)
						for j := range data {
							data[j] = byte(j*37 + size + i*19)
						}
						if n, err := client.WriteTo(data, nil); err != nil || n != len(data) {
							t.Fatalf("client %d send %d: %d, %v", i, size, n, err)
						}
						result := make(chan tunnelObserved, 1)
						go func() {
							buf := make([]byte, 4096)
							n, _, err := client.ReadFrom(buf)
							result <- tunnelObserved{buf[:n], "", err}
						}()
						select {
						case response := <-result:
							if response.err != nil || !bytes.Equal(response.data, tunnelReply(data)) {
								t.Fatalf("client %d downlink %d mismatch: %x, %v", i, size, response.data, response.err)
							}
						case <-time.After(7 * time.Second):
							t.Fatalf("client %d timed out for %d-byte packet", i, size)
						}
						select {
						case packet := <-observed:
							if packet.err != nil || !bytes.Equal(packet.data, data) {
								t.Fatalf("uplink mismatch at %d bytes: %v", size, packet.err)
							}
							if prior, ok := addresses[i]; ok && prior != packet.address {
								t.Fatal("clientID changed")
							}
							addresses[i] = packet.address
						case <-time.After(time.Second):
							t.Fatal("server did not receive the complete packet")
						}
					}
				}
				if addresses[0] == addresses[1] {
					t.Fatal("two clients shared a clientID")
				}
			})
		}
	}
}
