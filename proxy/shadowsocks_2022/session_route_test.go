package shadowsocks_2022

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/udp"
)

func TestRetiringReplacedUDPSessionKeepsNewOwner(t *testing.T) {
	manager := NewUDPSessionManager(time.Minute)
	old := manager.GetOrCreate(17)
	replacement := &ServerUDPSession{SessionID: old.SessionID, Window: new(SlidingWindow), manager: manager}
	manager.sessions.Store(old.SessionID, replacement)

	old.Close()

	if got := manager.Get(old.SessionID); got != replacement {
		t.Fatalf("retiring old owner changed the replacement: %p", got)
	}
	if old.Commit(1, nil, nil, nil) {
		t.Fatal("the retired session accepted a packet")
	}
}

type testReplyPeer struct {
	stdnet.Conn
	write func([]byte) (int, error)
}

func (p *testReplyPeer) Write(data []byte) (int, error) {
	return p.write(data)
}

func TestSS2022LateOldPeerWriteErrorKeepsReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	manager := NewUDPSessionManager(time.Minute)
	session := manager.GetOrCreate(17)
	inbox := udp.NewPacketInbox(64)
	route := &udpSessionRoute{
		ctx: ctx, cancel: cancel, input: inbox, session: session,
		timer: signal.CancelAfterInactivity(ctx, cancel, time.Minute),
	}
	defer session.Close()
	oldWriting := make(chan struct{})
	releaseOld := make(chan struct{})
	old := &testReplyPeer{write: func(data []byte) (int, error) {
		close(oldWriting)
		select {
		case <-releaseOld:
			return 0, io.ErrClosedPipe
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}}
	replacement := &testReplyPeer{write: func(data []byte) (int, error) {
		if string(data) != "new peer reply" {
			t.Errorf("replacement received %q", data)
		}
		return len(data), nil
	}}
	session.route = route
	session.bindPeer(old)
	firstResult := make(chan error, 1)
	go func() { firstResult <- route.WriteMultiBuffer(buf.MergeBytes(nil, []byte("old peer reply"))) }()
	select {
	case <-oldWriting:
	case <-ctx.Done():
		t.Fatal("old peer write did not start")
	}
	session.dispatchPacket(ctx, replacement, net.UDPDestination(net.LocalHostIP, 5353), nil, nil, nil, buf.FromBytes([]byte("reattach")))
	close(releaseOld)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("old peer failure escaped into the live route: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stale write did not return")
	}
	if manager.Get(session.SessionID) != session || ctx.Err() != nil {
		t.Fatal("old peer write retired the live logical session")
	}
	if err := route.WriteMultiBuffer(buf.MergeBytes(nil, []byte("new peer reply"))); err != nil {
		t.Fatal(err)
	}
}
