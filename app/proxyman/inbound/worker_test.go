package inbound

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

// closingInbound ends Process once its conn is closed, as an inbound does when
// the conn's user is removed, but only when release lets it.
type closingInbound struct {
	conns   chan stat.Connection
	release chan struct{}
}

func (*closingInbound) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

func (p *closingInbound) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	p.conns <- conn
	reader := buf.NewPacketReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err != nil {
			<-p.release
			return err
		}
	}
}

// A conn closed from outside can be replaced for the same client before its
// Process returns; that Process must not remove the replacement.
func TestUDPWorkerKeepsReplacedConn(t *testing.T) {
	hub, err := udp.ListenUDP(context.Background(), net.LocalHostIP, 0, &internet.MemoryStreamConfig{})
	common.Must(err)
	defer hub.Close()
	p := &closingInbound{conns: make(chan stat.Connection, 2), release: make(chan struct{})}
	w := &udpWorker{
		proxy:      p,
		hub:        hub,
		address:    net.LocalHostIP,
		activeConn: make(map[connID]*udpConn),
		ctx:        context.Background(),
	}
	w.checker = &task.Periodic{Interval: time.Hour, Execute: w.clean}
	defer w.checker.Close()

	source := net.UDPDestination(net.LocalHostIP, 10000)
	w.callback(buf.New(), source, net.Destination{})
	conn1 := <-p.conns
	conn1.Close()
	w.callback(buf.New(), source, net.Destination{})
	conn2 := <-p.conns
	if conn2 == conn1 {
		t.Fatal("closed conn was reused")
	}

	// The first Process returns only now, after its replacement exists.
	p.release <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	w.Lock()
	active := w.activeConn[connID{src: source}]
	w.Unlock()
	if active != conn2 {
		t.Fatal("the closed conn's Process removed its replacement")
	}

	conn2.Close()
	close(p.release)
}
