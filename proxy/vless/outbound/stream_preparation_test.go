package outbound

import (
	"bytes"
	"context"
	"io"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type shortPreparationPolicy struct{ policy.DefaultManager }

func (shortPreparationPolicy) ForLevel(uint32) policy.Session {
	p := policy.SessionDefault()
	p.Timeouts.ConnectionIdle = 10 * time.Millisecond
	return p
}

type preparationDialer struct {
	internet.Dialer
	conn stat.Connection
}

func (d preparationDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func TestPreparationIdleClosesBlockedHeader(t *testing.T) {
	conn, peer := gonet.Pipe()
	defer conn.Close()
	defer peer.Close()
	account := &vless.MemoryAccount{ID: protocol.NewID(uuid.New())}
	spec := protocol.NewServerSpec(net.TCPDestination(net.LocalHostIP, 1234), &protocol.MemoryUser{Account: account})
	client := &Handler{server: spec, policyManager: shortPreparationPolicy{}}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.LocalHostIP, 4321)}})
	source := exchange.Stream{Reader: bytes.NewReader([]byte("payload")), Writer: io.Discard}
	done := make(chan error, 1)
	go func() { _, err := client.PrepareStream(ctx, &source, preparationDialer{conn: conn}); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked header preparation succeeded")
		}
	case <-time.After(time.Second):
		peer.Close()
		<-done
		t.Fatal("preparation ignored peer idle timeout")
	}
}
