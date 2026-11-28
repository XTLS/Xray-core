package httpupgrade_test

import (
	"bufio"
	"context"
	"io"
	stdnet "net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func Test_listenHTTPUpgradeAndDial(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func Test_listenHTTPUpgradeAndDialWithHeaders(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
			Header: map[string]string{
				"User-Agent": "Mozilla",
			},
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func TestDialWithRemoteAddr(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
		SocketSettings: &internet.SocketConfig{
			TrustedXForwardedFor: []string{"X-Forwarded-For"},
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			_, err := c.Read(b[:])
			// common.Must(err)
			if err != nil {
				return
			}

			_, err = c.Write([]byte(c.RemoteAddr().String()))
			common.Must(err)
		}(conn)
	})
	common.Must(err)

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
	})

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "1.1.1.1:0" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(listen.Close())
}

func Test_listenHTTPUpgradeAndDial_TLS(t *testing.T) {
	listenPort := tcp.PickPort()
	if runtime.GOARCH == "arm64" {
		return
	}

	start := time.Now()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrades",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		},
	}
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			_ = conn.Close()
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_ = conn.Close()

	end := time.Now()
	if !end.Before(start.Add(time.Second * 5)) {
		t.Error("end: ", end, " start: ", start)
	}
}

type readerConn struct {
	stdnet.Conn
	r io.Reader
}

func (rc *readerConn) Read(p []byte) (int, error) {
	return rc.r.Read(p)
}

func TestDialPipelinedResponsePayload(t *testing.T) {
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()

		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			srvErr <- err
			return
		}

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: websocket\r\n\r\n" +
			"hello "
		if _, err := conn.Write([]byte(resp)); err != nil {
			srvErr <- err
			return
		}
		if _, err := conn.Write([]byte("world")); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	addr := ln.Addr().(*stdnet.TCPAddr)
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "/httpupgrade"},
	}

	conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(addr.Port)), streamSettings)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", string(got), "hello world")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestConnRFReadBufferedResponses(t *testing.T) {
	const resp101 = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	newReq := func() *http.Request {
		req, err := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
		common.Must(err)
		return req
	}

	t.Run("zero_len_with_pipelined_payload", func(t *testing.T) {
		client, server := stdnet.Pipe()
		defer client.Close()
		go func() {
			defer server.Close()
			_, _ = server.Write([]byte(resp101 + "hello"))
		}()

		c := &ConnRF{Conn: client, Req: newReq(), First: true}
		if n, err := c.Read([]byte{}); err != nil || n != 0 {
			t.Fatalf("zero-len Read got (%d, %v), want (0, nil)", n, err)
		}
		got, err := io.ReadAll(c)
		if err != nil || string(got) != "hello" {
			t.Fatalf("ReadAll got (%q, %v), want (%q, nil)", string(got), err, "hello")
		}
	})

	t.Run("small_len_large_cap", func(t *testing.T) {
		client, server := stdnet.Pipe()
		defer client.Close()
		go func() {
			defer server.Close()
			_, _ = server.Write([]byte(resp101 + "0123456789abcdefXYZ"))
		}()

		c := &ConnRF{Conn: client, Req: newReq(), First: true}
		backing := make([]byte, 32)
		for i := range backing {
			backing[i] = 0xAA
		}
		n, err := c.Read(backing[:1])
		if err != nil || n != 1 || backing[0] != '0' {
			t.Fatalf("first Read got (%d, %q, %v), want (1, '0', nil)", n, backing[:n], err)
		}
		if backing[1] != 0xAA {
			t.Fatalf("Read wrote past len(b): backing[1]=0x%x", backing[1])
		}
		rest, err := io.ReadAll(c)
		if err != nil || string(rest) != "123456789abcdefXYZ" {
			t.Fatalf("rest got (%q, %v), want (%q, nil)", string(rest), err, "123456789abcdefXYZ")
		}
	})

	t.Run("zero_len_does_not_block", func(t *testing.T) {
		client, server := stdnet.Pipe()
		defer client.Close()
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		allowTail := make(chan struct{})
		go func() {
			defer server.Close()
			_, _ = server.Write([]byte(resp101))
			<-allowTail
			_, _ = server.Write([]byte("after"))
		}()

		c := &ConnRF{Conn: client, Req: newReq(), First: true}
		if n, err := c.Read([]byte{}); err != nil || n != 0 {
			close(allowTail)
			t.Fatalf("zero-len Read got (%d, %v), want (0, nil)", n, err)
		}
		close(allowTail)
		got, err := io.ReadAll(c)
		if err != nil || string(got) != "after" {
			t.Fatalf("ReadAll got (%q, %v), want (%q, nil)", string(got), err, "after")
		}
	})

	t.Run("data_and_eof_same_read", func(t *testing.T) {
		c1 := &ConnRF{
			Conn:  &readerConn{r: iotest.DataErrReader(strings.NewReader(resp101))},
			Req:   newReq(),
			First: true,
		}
		if n, err := c1.Read([]byte{}); n != 0 || err != io.EOF {
			t.Fatalf("101+EOF zero-len Read got (%d, %v), want (0, EOF)", n, err)
		}

		// Deliver 101 + payload + sentinel error in one Read, then fail if the
		// underlying reader is touched again before returning that error.
		sentinel := io.ErrUnexpectedEOF
		calls := 0
		oneShot := &readerConn{r: readerFunc(func(p []byte) (int, error) {
			calls++
			if calls == 1 {
				return copy(p, resp101+"hello"), sentinel
			}
			t.Fatalf("unexpected second underlying Read (call %d)", calls)
			return 0, io.EOF
		})}
		c2 := &ConnRF{Conn: oneShot, Req: newReq(), First: true}
		if n, err := c2.Read([]byte{}); n != 0 || err != nil {
			t.Fatalf("101+payload+err zero-len Read got (%d, %v), want (0, nil)", n, err)
		}
		var buf [16]byte
		if n, err := c2.Read(buf[:]); err != nil || string(buf[:n]) != "hello" {
			t.Fatalf("payload Read got (%q, %v), want (%q, nil)", string(buf[:n]), err, "hello")
		}
		if n, err := c2.Read(buf[:]); n != 0 || err != sentinel {
			t.Fatalf("deferred error Read got (%d, %v), want (0, %v)", n, err, sentinel)
		}
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}
