package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
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
			defer pktConn.Close()
			defer tr.Close()
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

		defer pktConn.Close()
		defer tr.Close()
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

		defer pktConn.Close()
		defer tr.Close()
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

func TestTCPStalledWriteClose(t *testing.T) {
	// The server keeps small receive windows and never reads the first stream,
	// so the client's writes block on the flow control window
	// (xtls/xray-core#7169).
	serverQuicConf := &quic.Config{
		InitialStreamReceiveWindow:     64 * 1024,
		MaxStreamReceiveWindow:         64 * 1024,
		InitialConnectionReceiveWindow: 128 * 1024,
		MaxConnectionReceiveWindow:     128 * 1024,
		MaxIdleTimeout:                 30 * time.Second,
		MaxIncomingStreams:             16,
		DisablePathManager:             true,
	}

	cert, _ := cert.MustGenerate(nil)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Certificate},
				PrivateKey:  common.Must2(x509.ParsePKCS8PrivateKey(cert.PrivateKey)),
			},
		},
		NextProtos: []string{"h3"},
	}

	pktConn := common.Must2(net.ListenPacket("udp", "127.0.0.1:0"))
	tr := &quic.Transport{Conn: pktConn}
	l := common.Must2(tr.Listen(tlsConf, serverQuicConf))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer pktConn.Close()
	defer tr.Close()
	defer l.Close()

	type serverRead struct {
		n   int64
		err error
	}
	serverReadDone := make(chan serverRead, 1)
	go func() {
		conn, err := l.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		// The first stream is never read: its data stays buffered until the
		// client resets it.
		if _, err = conn.AcceptStream(ctx); err != nil {
			return
		}
		stream2, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		n, err := io.Copy(io.Discard, stream2)
		serverReadDone <- serverRead{n: n, err: err}
	}()

	clientPktConn := common.Must2(net.ListenPacket("udp", "127.0.0.1:0"))
	clientTr := &quic.Transport{Conn: clientPktConn}
	conn := common.Must2(clientTr.DialEarly(ctx, l.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{
		MaxIdleTimeout:     30 * time.Second,
		DisablePathManager: true,
	}))
	defer clientPktConn.Close()
	defer clientTr.Close()
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStream()
	common.Must(err)
	iConn := &interConn{
		stream: stream,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
		client: true,
	}

	var writes atomic.Int64
	writeDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 32*1024)
		for {
			if _, err := iConn.Write(payload); err != nil {
				writeDone <- err
				return
			}
			writes.Add(1)
		}
	}()

	select {
	case err := <-writeDone:
		t.Fatalf("write returned early: %v", err)
	case <-time.After(2 * time.Second):
	}

	// Wait until the writer stops making progress, i.e. is blocked on the
	// flow control window.
	stalledDeadline := time.Now().Add(8 * time.Second)
	for {
		before := writes.Load()
		time.Sleep(300 * time.Millisecond)
		if writes.Load() == before {
			break
		}
		if time.Now().After(stalledDeadline) {
			t.Fatal("writer never stopped making progress")
		}
	}

	// Closing must reset the stalled write side: the blocked Write returns and
	// the peer drops the unread data instead of holding it against the
	// connection window.
	if err := iConn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("stalled write returned without an error after close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled write did not return after close")
	}

	stream2, err := conn.OpenStream()
	common.Must(err)
	iConn2 := &interConn{
		stream: stream2,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
		client: true,
	}
	write2Done := make(chan error, 1)
	go func() {
		_, err := iConn2.Write(make([]byte, 16*1024))
		write2Done <- err
	}()
	select {
	case err := <-write2Done:
		if err != nil {
			t.Fatalf("write on a new stream failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write on a new stream blocked: connection window was not released")
	}

	// A cleanly finished stream keeps the plain close: the peer reads the FIN
	// and all the data, not a reset.
	if err := iConn2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case res := <-serverReadDone:
		if res.err != nil {
			t.Fatalf("peer read of the closed stream: %v", res.err)
		}
		if want := int64(16*1024 + 2); res.n != want { // + 2 bytes TCPRequest frame header
			t.Fatalf("peer read %d bytes, want %d", res.n, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not finish reading the closed stream")
	}
}
