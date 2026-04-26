package custom

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func TestMetadataEvaluatorRejectsUnknownName(t *testing.T) {
	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "be16",
				Args: []*ExprArg{
					{Value: &ExprArg_Metadata{Metadata: "nope"}},
				},
			},
		},
	}

	_, err := evaluateUDPItemsWithContext(items, newEvalContext())
	if err == nil || !strings.Contains(err.Error(), "unknown metadata") {
		t.Fatalf("expected unknown metadata error, got %v", err)
	}
}

func TestMetadataAliasesExposeSrcAndDstNames(t *testing.T) {
	ctx := newEvalContextWithAddrs(
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 3478},
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 54321},
	)

	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "concat",
				Args: []*ExprArg{
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be16",
								Args: []*ExprArg{
									{Value: &ExprArg_Metadata{Metadata: "src_port_u16"}},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be32",
								Args: []*ExprArg{
									{Value: &ExprArg_Metadata{Metadata: "src_ip4_u32"}},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := evaluateUDPItemsWithContext(items, ctx)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{0xD4, 0x31, 203, 0, 113, 9}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected alias output: got=%x want=%x", got, want)
	}
}

func TestMetadataAliasesExposeDstNames(t *testing.T) {
	ctx := newEvalContextWithAddrs(
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 3478},
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 54321},
	)

	items := []*UDPItem{
		{
			Expr: &Expr{
				Op: "concat",
				Args: []*ExprArg{
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be16",
								Args: []*ExprArg{
									{Value: &ExprArg_Metadata{Metadata: "dst_port_u16"}},
								},
							},
						},
					},
					{
						Value: &ExprArg_Expr{
							Expr: &Expr{
								Op: "be32",
								Args: []*ExprArg{
									{Value: &ExprArg_Metadata{Metadata: "dst_ip4_u32"}},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := evaluateUDPItemsWithContext(items, ctx)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{0x0D, 0x96, 10, 0, 0, 1}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected alias output: got=%x want=%x", got, want)
	}
}

func TestMetadataUDPWriteUsesRemotePort(t *testing.T) {
	cfg := &UDPConfig{
		Client: []*UDPItem{
			{
				Expr: &Expr{
					Op: "be16",
					Args: []*ExprArg{
						{Value: &ExprArg_Metadata{Metadata: "remote_port"}},
					},
				},
			},
		},
	}

	clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()

	serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()

	client, err := finalmask.NewUdpmaskManager([]finalmask.Udpmask{cfg}).WrapPacketConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("meta")
	if _, err := client.WriteTo(payload, serverRaw.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	wire := make([]byte, 64)
	_ = serverRaw.SetDeadline(time.Now().Add(time.Second))
	n, _, err := serverRaw.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload)+2 {
		t.Fatalf("unexpected wire size: %d", n)
	}
	wantPort := uint16(serverRaw.LocalAddr().(*net.UDPAddr).Port)
	if got := binary.BigEndian.Uint16(wire[:2]); got != wantPort {
		t.Fatalf("unexpected encoded port: got=%d want=%d", got, wantPort)
	}
	if !bytes.Equal(wire[2:n], payload) {
		t.Fatalf("unexpected payload: %q", wire[2:n])
	}
}

func TestMetadataTCPHandshakeUsesEndpointPorts(t *testing.T) {
	clientCfg := &TCPConfig{
		Clients: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Expr: &Expr{
							Op: "be16",
							Args: []*ExprArg{
								{Value: &ExprArg_Metadata{Metadata: "remote_port"}},
							},
						},
					},
				},
			},
		},
		Servers: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Expr: &Expr{
							Op: "be16",
							Args: []*ExprArg{
								{Value: &ExprArg_Metadata{Metadata: "local_port"}},
							},
						},
					},
				},
			},
		},
	}
	serverCfg := &TCPConfig{
		Clients: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Expr: &Expr{
							Op: "be16",
							Args: []*ExprArg{
								{Value: &ExprArg_Metadata{Metadata: "local_port"}},
							},
						},
					},
				},
			},
		},
		Servers: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Expr: &Expr{
							Op: "be16",
							Args: []*ExprArg{
								{Value: &ExprArg_Metadata{Metadata: "remote_port"}},
							},
						},
					},
				},
			},
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverRawCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		serverRawCh <- conn
	}()

	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()

	var serverRaw net.Conn
	select {
	case serverRaw = <-serverRawCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}
	defer serverRaw.Close()

	client, err := clientCfg.WrapConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := serverCfg.WrapConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("meta"))
		writeErr <- err
	}()

	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, []byte("meta")) {
		t.Fatalf("unexpected payload: %q", buf)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}
