package tcp_test

import (
	"context"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/stat"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
)

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
	t.Run("GivenTcpmaskManager_WhenDialingRawTCP_ThenClientMaskIsApplied", func(t *testing.T) {
		server := &tcp.Server{}
		dest, err := server.Start()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()

		var applied atomic.Bool
		mask := &markerTcpmask{clientApplied: &applied}
		manager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{mask})

		conn, err := transtcp.Dial(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), &internet.MemoryStreamConfig{
			ProtocolSettings: &transtcp.Config{},
			TcpmaskManager:   manager,
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()

		if !applied.Load() {
			t.Fatal("client tcp mask should be applied")
		}
	})

	t.Run("GivenTcpmaskManager_WhenListeningRawTCP_ThenServerMaskIsApplied", func(t *testing.T) {
		var applied atomic.Bool
		mask := &markerTcpmask{serverApplied: &applied}
		manager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{mask})

		handlerCalled := make(chan struct{}, 1)
		port := tcp.PickPort()
		listener, err := transtcp.ListenTCP(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
			ProtocolSettings: &transtcp.Config{},
			TcpmaskManager:   manager,
		}, func(conn stat.Connection) {
			_ = conn.Close()
			select {
			case handlerCalled <- struct{}{}:
			default:
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		conn, err := stdnet.DialTimeout("tcp", (&stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(port)}).String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()

		select {
		case <-handlerCalled:
		case <-time.After(2 * time.Second):
			t.Fatal("listener handler should be called")
		}

		if !applied.Load() {
			t.Fatal("server tcp mask should be applied")
		}
	})
}
