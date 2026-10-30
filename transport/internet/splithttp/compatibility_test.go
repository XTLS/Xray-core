package splithttp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestXHTTPCompatibility(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		modes := []string{"packet-up", "stream-up", "stream-one"}
		if version == "h1" {
			modes = modes[:1]
		}
		for _, mode := range modes {
			for _, separateDownload := range []bool{false, true} {
				if separateDownload && (version != "h2" || mode == "stream-one") {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/separateDownload=%t", version, mode, separateDownload), func(t *testing.T) {
					config := &splithttp.Config{
						Path: "/compatibility", Mode: mode,
						ScMinPostsIntervalMs: &splithttp.RangeConfig{From: 1, To: 1},
						Xmux:                 &splithttp.XmuxConfig{MaxConnections: &splithttp.RangeConfig{From: 1, To: 1}},
					}
					serverSettings := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: config}
					clientSettings := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: config}
					var clientTLS *tls.Config
					port := tcp.PickPort()
					if version != "h1" {
						certificate, fingerprint := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
						clientTLS = &tls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{fingerprint[:]}, NextProtocol: []string{version}}
						serverSettings.SecurityType = "tls"
						serverSettings.SecuritySettings = &tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)}, NextProtocol: []string{version}}
						clientSettings.SecurityType = "tls"
						clientSettings.SecuritySettings = clientTLS
					}
					if version == "h3" {
						port = udp.PickPort()
					}
					listener, err := splithttp.ListenXH(context.Background(), net.LocalHostIP, port, serverSettings, func(conn stat.Connection) {
						go func() {
							defer conn.Close()
							io.Copy(conn, conn)
						}()
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close() })
					if separateDownload {
						security := serial.ToTypedMessage(clientTLS)
						// Both connections reach the same session store through independent HTTP clients.
						config.DownloadSettings = &internet.StreamConfig{
							Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(port), ProtocolName: "splithttp",
							TransportSettings: []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(&splithttp.Config{Path: config.Path})}},
							SecurityType:      security.Type, SecuritySettings: []*serial.TypedMessage{security},
						}
					}
					for range 2 {
						conn, err := splithttp.Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), clientSettings)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { conn.Close() })
						for _, size := range []int{1, 4096, 128 * 1024} {
							payload := make([]byte, size)
							if _, err := rand.Read(payload); err != nil {
								t.Fatal(err)
							}
							result := make(chan error, 1)
							go func() {
								if _, err := conn.Write(payload); err != nil {
									result <- err
									return
								}
								response := make([]byte, len(payload))
								_, err := io.ReadFull(conn, response)
								if err == nil && !bytes.Equal(payload, response) {
									err = fmt.Errorf("%d-byte echo was corrupted", len(payload))
								}
								result <- err
							}()
							select {
							case err := <-result:
								if err != nil {
									t.Fatal(err)
								}
							case <-time.After(5 * time.Second):
								t.Fatalf("%d-byte echo timed out", size)
							}
						}
						if err := conn.Close(); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}
