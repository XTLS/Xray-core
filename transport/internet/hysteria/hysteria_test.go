package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestDatagram(t *testing.T) {
	run := func() (addr net.Addr, recv chan int64, cancel func()) {
		cert, _ := cert.MustGenerate(nil)
		Certificate := [][]byte{cert.Certificate}
		PrivateKey := common.Must2(x509.ParsePKCS8PrivateKey(cert.PrivateKey))

		tlsConf := &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: Certificate,
					PrivateKey:  PrivateKey,
				},
			},
			NextProtos: []string{"h3"},
		}

		quicConf := &quic.Config{
			InitialStreamReceiveWindow:     8388608,
			MaxStreamReceiveWindow:         8388608,
			InitialConnectionReceiveWindow: 8388608 * 5 / 2,
			MaxConnectionReceiveWindow:     8388608 * 5 / 2,
			MaxIdleTimeout:                 30 * time.Second,
			MaxIncomingStreams:             1024,
			DisablePathMTUDiscovery:        runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin",
			EnableDatagrams:                true,
			MaxDatagramFrameSize:           MaxDatagramFrameSize,
			AssumePeerMaxDatagramFrameSize: MaxDatagramFrameSize,
			DisablePathManager:             true,
		}

		pktConn := common.Must2(net.ListenPacket("udp", "127.0.0.1:0"))
		tr := &quic.Transport{Conn: pktConn}
		l := common.Must2(tr.Listen(tlsConf, quicConf))

		recv = make(chan int64)
		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			defer tr.Close()
			defer pktConn.Close()
			defer l.Close()
			defer close(recv)

			var buf [1500]byte
			for {
				conn, err := l.Accept(ctx)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						t.Error(err)
					}
					break
				}
				err = conn.SendDatagram(buf[:])
				var qErr *quic.DatagramTooLargeError
				if !errors.As(err, &qErr) {
					t.Error(err)
				}
				recv <- qErr.MaxDatagramPayloadSize
				defer conn.CloseWithError(0, "")
			}
		}()

		return l.Addr(), recv, cancel
	}

	addr, recv, cancel := run()

	t.Run("With ChromeParrot", func(t *testing.T) {
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
		}

		quicConf := &quic.Config{
			InitialStreamReceiveWindow:     8388608,
			MaxStreamReceiveWindow:         8388608,
			InitialConnectionReceiveWindow: 8388608 * 5 / 2,
			MaxConnectionReceiveWindow:     8388608 * 5 / 2,
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                10 * time.Second,
			DisablePathMTUDiscovery:        runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin",
			ChromeParrot:                   true,
			EnableDatagrams:                true,
			MaxDatagramFrameSize:           MaxDatagramFrameSize,
			OmitMaxDatagramFrameSize:       true,
			DisablePathManager:             true,
		}

		pktConn := common.Must2(net.ListenPacket("udp", "127.0.0.1:0"))
		tr := &quic.Transport{Conn: pktConn, ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{}}
		conn := common.Must2(tr.DialEarly(context.Background(), addr, tlsConf, quicConf))

		defer tr.Close()
		defer pktConn.Close()
		defer conn.CloseWithError(0, "")

		var buf [1500]byte
		err := conn.SendDatagram(buf[:])
		var qErr *quic.DatagramTooLargeError
		if !errors.As(err, &qErr) || qErr.MaxDatagramPayloadSize != 1197 {
			t.Error(err)
		}
		if server := <-recv; server != 1243 {
			t.Error(server)
		}
	})

	t.Run("Without ChromeParrot", func(t *testing.T) {
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		}

		quicConf := &quic.Config{
			InitialStreamReceiveWindow:     8388608,
			MaxStreamReceiveWindow:         8388608,
			InitialConnectionReceiveWindow: 8388608 * 5 / 2,
			MaxConnectionReceiveWindow:     8388608 * 5 / 2,
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                10 * time.Second,
			DisablePathMTUDiscovery:        runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin",
			ChromeParrot:                   false,
			EnableDatagrams:                true,
			MaxDatagramFrameSize:           MaxDatagramFrameSize,
			OmitMaxDatagramFrameSize:       true,
			DisablePathManager:             true,
		}

		pktConn := common.Must2(net.ListenPacket("udp", "127.0.0.1:0"))
		tr := &quic.Transport{Conn: pktConn}
		conn := common.Must2(tr.DialEarly(context.Background(), addr, tlsConf, quicConf))

		defer tr.Close()
		defer pktConn.Close()
		defer conn.CloseWithError(0, "")

		var buf [1500]byte
		err := conn.SendDatagram(buf[:])
		var qErr *quic.DatagramTooLargeError
		if !errors.As(err, &qErr) || qErr.MaxDatagramPayloadSize != 1197 {
			t.Error(err)
		}
		if server := <-recv; server != 1197 {
			t.Error(server)
		}
	})

	cancel()
}
