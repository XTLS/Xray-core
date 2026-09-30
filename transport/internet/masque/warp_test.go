package masque

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	gonet "net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

var (
	warpLocal4 = netip.MustParsePrefix("172.16.0.2/32")
	warpLocal6 = netip.MustParsePrefix("2606:4700:110:8a36::2/128")
	warpRemote = netip.MustParseAddr("1.1.1.1")
)

func newWarpKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func warpServerTLS(t *testing.T, client *ecdsa.PublicKey, alpn string) (*gotls.Config, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := &gotls.Config{
		Certificates: []gotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   gotls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(client) {
				return errors.New("unknown client key")
			}
			return nil
		},
	}
	if alpn != "" {
		config.NextProtos = []string{alpn}
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return config, publicKey, tls.GenerateCertHash(der)
}

func warpStreamSettings(key, publicKey []byte, alpn ...string) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{Host: WarpHost, Path: WarpPath, Warp: &Warp{
			PrivateKey: key,
			PublicKey:  publicKey,
			Address:    []string{warpLocal4.String(), warpLocal6.String()},
		}},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			ServerName:   "consumer-masque.cloudflareclient.com",
			NextProtocol: alpn,
		},
	}
}

func warpPacket(src, dst netip.Addr, payload string) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	copy(b[20:], payload)
	return b
}

func warpCapsule(typ uint64, value []byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(value)))
	return append(b, value...)
}

func readCapsuleTypes(r io.Reader, datagrams chan<- []byte) []uint64 {
	var types []uint64
	p := http3.NewCapsuleParser(r)
	for {
		typ, cr, err := p.Next()
		if err != nil {
			return types
		}
		types = append(types, uint64(typ))
		b, err := io.ReadAll(cr)
		if err != nil {
			return types
		}
		if typ == 0 && datagrams != nil {
			datagrams <- b
		}
	}
}

func checkWarpTunnel(t *testing.T, conn stat.Connection, sent <-chan []byte, reply func([]byte)) {
	t.Helper()
	mconn := conn.(*Conn)
	if want := []netip.Addr{warpLocal4.Addr(), warpLocal6.Addr()}; !slices.Equal(mconn.LocalAddrs(), want) {
		t.Fatalf("local addresses %v, want %v", mconn.LocalAddrs(), want)
	}

	out := warpPacket(warpLocal4.Addr(), warpRemote, "ping")
	if _, err := conn.Write(slices.Clone(out)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sent:
		if got[8] != 63 || !bytes.Equal(got[12:], out[12:]) {
			t.Fatalf("the proxy got % x, want % x with TTL 63", got, out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy got no packet")
	}

	reply(warpPacket(warpRemote, netip.MustParseAddr("172.16.0.3"), "lost"))
	in := warpPacket(warpRemote, warpLocal4.Addr(), "pong")
	reply(in)
	b := make([]byte, 1500)
	done := make(chan error, 1)
	var n int
	go func() {
		var err error
		n, err = conn.Read(b)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b[:n], in) {
			t.Fatalf("read % x, want % x", b[:n], in)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet came back")
	}
}

func TestWarpCertificate(t *testing.T) {
	key, der := newWarpKey(t)
	cert, err := warpCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Fatal("the certificate doesn't carry the WARP key")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatal(err)
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		t.Fatal("the certificate isn't valid now")
	}
	if _, err := warpCertificate([]byte("not a key")); err == nil {
		t.Fatal("expected an error for an invalid key")
	}
}

func TestDialWarpHTTP3(t *testing.T) {
	for _, draft := range []bool{true, false} {
		t.Run(map[bool]string{true: "draft datagrams", false: "RFC 9297 datagrams"}[draft], func(t *testing.T) {
			key, der := newWarpKey(t)
			serverTLS, serverKey, _ := warpServerTLS(t, &key.PublicKey, http3.NextProtoH3)

			sent := make(chan []byte, 1)
			replies := make(chan []byte, 2)
			capsules := make(chan []uint64, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				settings := w.(http3.Settingser)
				<-settings.ReceivedSettings()
				switch {
				case settings.Settings().Other[connectip.SettingDatagramDraft00] != 1:
					t.Error("the client didn't send the draft datagram setting")
				case r.Method != http.MethodConnect, r.Proto != "cf-connect-ip", r.Host != WarpHost, r.URL.Path != WarpPath:
					t.Errorf("unexpected request %s %s %s%s", r.Method, r.Proto, r.Host, r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				str := w.(http3.HTTPStreamer).HTTPStream()
				go func() { capsules <- readCapsuleTypes(str, nil) }()
				b, err := str.ReceiveDatagram(r.Context())
				if err != nil {
					t.Error(err)
					return
				}
				if b[0] != 0 {
					t.Errorf("datagram context ID %d, want 0", b[0])
				}
				sent <- b[1:]
				for range 2 {
					if err := str.SendDatagram(append([]byte{0}, <-replies...)); err != nil {
						t.Error(err)
					}
				}
				<-r.Context().Done()
			})

			udp, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			server := &http3.Server{
				Handler:         handler,
				TLSConfig:       serverTLS,
				QUICConfig:      &quic.Config{EnableDatagrams: true},
				EnableDatagrams: !draft,
			}
			if draft {
				server.AdditionalSettings = map[uint64]uint64{connectip.SettingDatagramDraft00: 1}
			}
			go server.Serve(udp)
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dest := net.UDPDestination(net.LocalHostIP, net.Port(udp.LocalAddr().(*gonet.UDPAddr).Port))
			conn, err := Dial(ctx, dest, warpStreamSettings(der, serverKey))
			if err != nil {
				t.Fatal(err)
			}
			checkWarpTunnel(t, conn, sent, func(b []byte) { replies <- b })
			conn.Close()
			select {
			case types := <-capsules:
				if slices.Contains(types, 2) {
					t.Error("the client sent an ADDRESS_REQUEST")
				}
			case <-time.After(5 * time.Second):
				t.Error("the request stream didn't end")
			}
		})
	}
}

func TestDialWarpHTTP2(t *testing.T) {
	for _, alpn := range []string{http2.NextProtoTLS, ""} {
		t.Run(map[string]string{http2.NextProtoTLS: "h2 ALPN", "": "no ALPN"}[alpn], func(t *testing.T) {
			key, der := newWarpKey(t)
			serverTLS, serverKey, _ := warpServerTLS(t, &key.PublicKey, alpn)

			sent := make(chan []byte, 1)
			replies := make(chan []byte, 2)
			capsules := make(chan []uint64, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method != http.MethodConnect, r.ProtoMajor != 2, r.Host != WarpHost+":443":
					t.Errorf("unexpected request %s %s %s", r.Method, r.Proto, r.Host)
				case r.Header.Get("Cf-Connect-Proto") != "cf-connect-ip", r.Header.Get("Pq-Enabled") != "false":
					t.Errorf("unexpected headers %v", r.Header)
				case r.Header.Get("Capsule-Protocol") != "", r.Header.Get(":protocol") != "":
					t.Errorf("unexpected headers %v", r.Header)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				datagrams := make(chan []byte, 1)
				go func() { capsules <- readCapsuleTypes(r.Body, datagrams) }()
				b := <-datagrams
				if b[0] != 0x45 {
					t.Errorf("the DATAGRAM capsule starts with %#x, want a bare IPv4 packet", b[0])
				}
				sent <- b
				for range 2 {
					w.Write(warpCapsule(0, <-replies))
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			})

			ln, err := gonet.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						tc := gotls.Server(c, serverTLS)
						if err := tc.Handshake(); err != nil {
							return
						}
						(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
					}()
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dest := net.TCPDestination(net.LocalHostIP, net.Port(ln.Addr().(*gonet.TCPAddr).Port))
			conn, err := Dial(ctx, dest, warpStreamSettings(der, serverKey, http2.NextProtoTLS))
			if err != nil {
				t.Fatal(err)
			}
			checkWarpTunnel(t, conn, sent, func(b []byte) { replies <- b })
			conn.Close()
			select {
			case types := <-capsules:
				if slices.Contains(types, 2) {
					t.Error("the client sent an ADDRESS_REQUEST")
				}
			case <-time.After(5 * time.Second):
				t.Error("the request stream didn't end")
			}
		})
	}
}

func TestDialWarpVerification(t *testing.T) {
	key, der := newWarpKey(t)
	serverTLS, serverKey, pin := warpServerTLS(t, &key.PublicKey, http3.NextProtoH3)
	_, otherKey, _ := warpServerTLS(t, &key.PublicKey, http3.NextProtoH3)
	udp, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler:            http.NotFoundHandler(),
		TLSConfig:          serverTLS,
		QUICConfig:         &quic.Config{EnableDatagrams: true},
		AdditionalSettings: map[uint64]uint64{connectip.SettingDatagramDraft00: 1},
	}
	go server.Serve(udp)
	defer server.Close()
	dest := net.UDPDestination(net.LocalHostIP, net.Port(udp.LocalAddr().(*gonet.UDPAddr).Port))

	for _, c := range []struct {
		name      string
		publicKey []byte
		pin       []byte
		want      string
	}{
		{"matching key", serverKey, nil, "404"},
		{"matching key and pin", serverKey, pin, "404"},
		{"other key", otherKey, nil, `doesn't match "publicKey"`},
		{"matching key, other pin", serverKey, make([]byte, 32), "pinnedPeerCertSha256"},
	} {
		t.Run(c.name, func(t *testing.T) {
			settings := warpStreamSettings(der, c.publicKey)
			if c.pin != nil {
				settings.SecuritySettings.(*tls.Config).PinnedPeerCertSha256 = [][]byte{c.pin}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := Dial(ctx, dest, settings)
			if err == nil {
				conn.Close()
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q doesn't mention %q", err, c.want)
			}
		})
	}
}

func TestDialWarpRejectedKey(t *testing.T) {
	_, der := newWarpKey(t)
	other, _ := newWarpKey(t)
	serverTLS, serverKey, _ := warpServerTLS(t, &other.PublicKey, http3.NextProtoH3)
	udp, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler:            http.NotFoundHandler(),
		TLSConfig:          serverTLS,
		QUICConfig:         &quic.Config{EnableDatagrams: true},
		AdditionalSettings: map[uint64]uint64{connectip.SettingDatagramDraft00: 1},
	}
	go server.Serve(udp)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dest := net.UDPDestination(net.LocalHostIP, net.Port(udp.LocalAddr().(*gonet.UDPAddr).Port))
	if conn, err := Dial(ctx, dest, warpStreamSettings(der, serverKey)); err == nil {
		conn.Close()
		t.Fatal("expected the proxy to reject an unknown key")
	}
}
