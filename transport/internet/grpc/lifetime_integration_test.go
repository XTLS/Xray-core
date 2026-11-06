package grpc_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	fout "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	transport "github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/stat"
	g "google.golang.org/grpc"
)

type echoService struct {
	encoding.UnimplementedGRPCServiceServer
}

func (echoService) Tun(s g.BidiStreamingServer[encoding.Hunk, encoding.Hunk]) error {
	for {
		v, err := s.Recv()
		if err != nil {
			return err
		}
		if err = s.Send(v); err != nil {
			return err
		}
	}
}

func (echoService) TunMulti(s g.BidiStreamingServer[encoding.MultiHunk, encoding.MultiHunk]) error {
	for {
		v, err := s.Recv()
		if err != nil {
			return err
		}
		if err = s.Send(v); err != nil {
			return err
		}
	}
}

func syntheticServer(t *testing.T) xnet.Destination {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := g.NewServer()
	encoding.RegisterGRPCServiceServerX(srv, echoService{}, "lifetime", "Tun", "TunMulti")
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(ln.Addr().(*net.TCPAddr).Port))
}

func configuredCore(t *testing.T, multi bool) (*core.Instance, internet.Dialer) {
	return configuredCoreWithProxy(t, multi, "")
}

func configuredCoreWithProxy(t *testing.T, multi bool, dialerProxy string) (*core.Instance, internet.Dialer) {
	t.Helper()
	var sockopt *internet.SocketConfig
	if dialerProxy != "" {
		sockopt = &internet.SocketConfig{DialerProxy: dialerProxy}
	}

	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Outbound: []*core.OutboundHandlerConfig{{Tag: "same", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
			SocketSettings: sockopt, ProtocolName: "grpc", TransportSettings: []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&transport.Config{ServiceName: "lifetime", MultiMode: multi})}},
		}}), ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, v.GetFeature(fout.ManagerType()).(fout.Manager).GetHandler("same").(internet.Dialer)
}

func newCore(t *testing.T, multi bool) (*core.Instance, internet.Dialer) {
	t.Helper()
	v, d := configuredCore(t, multi)
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	return v, d
}

func dial(t *testing.T, d internet.Dialer, dest xnet.Destination) stat.Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	c, err := d.Dial(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func echo(t *testing.T, c stat.Connection) {
	t.Helper()
	if _, err := c.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "alive" {
		t.Fatal(string(b))
	}
}

func TestCoreCloseIsolatesGRPCClients(t *testing.T) {
	for _, multi := range []bool{false, true} {
		name := "single"
		if multi {
			name = "multi"
		}
		t.Run(name, func(t *testing.T) {
			dest := syntheticServer(t)
			a, da := newCore(t, multi)
			_, db := newCore(t, multi)
			a1 := dial(t, da, dest)
			a2 := dial(t, da, dest)
			b := dial(t, db, dest)
			echo(t, a1)
			echo(t, a2)
			echo(t, b)
			a1.Close()
			echo(t, a2) // Ending one RPC must preserve its sibling.
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			ended := make(chan error, 1)
			go func() { var b [1]byte; _, err := a2.Read(b[:]); ended <- err }()
			select {
			case err := <-ended:
				if err == nil {
					t.Fatal("closed core still receives")
				}
			case <-time.After(time.Second):
				t.Fatal("core Close left its gRPC stream alive")
			}
			echo(t, b)
			echo(t, dial(t, db, dest)) // B survives and can create another stream.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if c, err := da.Dial(session.ContextWithOutbounds(ctx, []*session.Outbound{{}}), dest); err == nil {
				c.Close()
				t.Fatal("stopped outbound resurrected its gRPC client")
			}
		})
	}
}

// Production libXray creates a fresh Instance for each runXray invocation.
func TestFreshCoreGRPCStarts(t *testing.T) {
	dest := syntheticServer(t)
	for i := 0; i < 10; i++ {
		v, d := newCore(t, false)
		echo(t, dial(t, d, dest))
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

type failingStart struct{ start func() error }

func (f *failingStart) Type() interface{} { return (*failingStart)(nil) }
func (f *failingStart) Start() error      { return f.start() }
func (*failingStart) Close() error        { return nil }

func TestFailedCoreStartGRPCCleanup(t *testing.T) {
	dest := syntheticServer(t)
	v, d := configuredCore(t, false)
	sentinel := errors.New("synthetic feature start failure")
	var c stat.Connection
	if err := v.AddFeature(&failingStart{start: func() error {
		c = dial(t, d, dest)
		echo(t, c)
		return sentinel
	}}); err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); !errors.Is(err, sentinel) {
		t.Fatalf("start result: %v", err)
	}
	// libXray calls Close after a failed Instance.Start.
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { var b [1]byte; _, err := c.Read(b[:]); ended <- err }()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("failed-start stream remained alive")
		}
	case <-time.After(time.Second):
		t.Fatal("failed-start cleanup did not close client")
	}
}
