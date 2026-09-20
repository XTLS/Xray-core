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
	run := func() (addr net.Addr, done chan struct{}) {
		done = make(chan struct{})

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

		go func() {
			conn := common.Must2(l.Accept(context.Background()))
			<-done
			_ = conn.CloseWithError(0, "")
			_ = l.Close()
		}()

		return l.Addr(), done
	}

	addr, done := run()

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
	defer pktConn.Close()
	tr := &quic.Transport{Conn: pktConn, ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{}}
	defer tr.Close()

	conn := common.Must2(tr.DialEarly(context.Background(), addr, tlsConf, quicConf))
	defer conn.CloseWithError(0, "")

	var buf [1500]byte
	err := conn.SendDatagram(buf[:])

	close(done)

	var qErr *quic.DatagramTooLargeError
	if !errors.As(err, &qErr) || qErr.MaxDatagramPayloadSize != 1197 {
		t.Fatal(err)
	}
}
