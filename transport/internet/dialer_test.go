package internet_test

import (
	"context"
	stdnet "net"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}

type markerTcpmask struct {
	clientApplied *atomic.Bool
	serverApplied *atomic.Bool
}

func (m *markerTcpmask) TCP() {}

func (m *markerTcpmask) WrapConnClient(conn stdnet.Conn) (stdnet.Conn, error) {
	if m.clientApplied != nil {
		m.clientApplied.Store(true)
	}
	return conn, nil
}

func (m *markerTcpmask) WrapConnServer(conn stdnet.Conn) (stdnet.Conn, error) {
	if m.serverApplied != nil {
		m.serverApplied.Store(true)
	}
	return conn, nil
}

func TestTcpmaskBDD(t *testing.T) {
	t.Run("GivenTcpmaskManager_WhenDialingTCP_ThenClientMaskIsApplied", func(t *testing.T) {
		var applied atomic.Bool
		mask := &markerTcpmask{clientApplied: &applied}
		manager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{mask})

		protocol := "bdd-tcpmask-dial-" + tcp.PickPort().String()
		if err := RegisterTransportDialer(protocol, func(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error) {
			client, server := stdnet.Pipe()
			go server.Close()
			return client, nil
		}); err != nil {
			t.Fatal(err)
		}

		streamSettings := &MemoryStreamConfig{
			ProtocolName:   protocol,
			TcpmaskManager: manager,
		}
		conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(443)), streamSettings)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()

		if !applied.Load() {
			t.Fatal("client tcp mask should be applied")
		}
	})

	t.Run("GivenTcpmaskManager_WhenListeningTCP_ThenServerMaskIsApplied", func(t *testing.T) {
		var applied atomic.Bool
		mask := &markerTcpmask{serverApplied: &applied}
		manager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{mask})

		protocol := "bdd-tcpmask-listen-" + tcp.PickPort().String()
		if err := RegisterTransportListener(protocol, func(ctx context.Context, address net.Address, port net.Port, settings *MemoryStreamConfig, handler ConnHandler) (Listener, error) {
			client, server := stdnet.Pipe()
			defer server.Close()
			handler(client)
			return &testListener{}, nil
		}); err != nil {
			t.Fatal(err)
		}

		called := atomic.Bool{}
		_, err := ListenTCP(context.Background(), net.LocalHostIP, tcp.PickPort(), &MemoryStreamConfig{
			ProtocolName:   protocol,
			TcpmaskManager: manager,
		}, func(conn stat.Connection) {
			called.Store(true)
			_ = conn.Close()
		})
		if err != nil {
			t.Fatal(err)
		}

		if !applied.Load() {
			t.Fatal("server tcp mask should be applied")
		}
		if !called.Load() {
			t.Fatal("listener handler should be called")
		}
	})
}

type testListener struct{}

func (*testListener) Close() error { return nil }

func (*testListener) Addr() net.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4zero, Port: 0}
}
