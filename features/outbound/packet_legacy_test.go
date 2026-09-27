package outbound

import (
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"testing"
	"time"
)

type packetTestHandler struct {
	Handler
	run func(context.Context, *transport.Link)
}

func (h packetTestHandler) Dispatch(ctx context.Context, l *transport.Link) { h.run(ctx, l) }
func TestPacketLegacyAbortJoinsHandlerAndReleasesTail(t *testing.T) {
	first, tail := buf.New(), buf.New()
	first.Write([]byte("one"))
	tail.Write([]byte("two"))
	exited := make(chan struct{})
	h := packetTestHandler{run: func(ctx context.Context, l *transport.Link) {
		defer close(exited)
		if err := l.Writer.WriteMultiBuffer(buf.MultiBuffer{first, tail}); err != nil {
			return
		}
		<-ctx.Done()
	}}
	leg := PrepareLegacyPacket(context.Background(), h, net.UDPDestination(net.LocalHostIP, 1234))
	defer leg.Abort()
	if n, _, err := leg.Reader.ReadPacket(make([]byte, 8)); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	done := make(chan struct{})
	go func() { leg.Abort(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("legacy abort did not join")
	}
	select {
	case <-exited:
	default:
		t.Fatal("handler outlived leg abort")
	}
	if !tail.IsEmpty() {
		t.Fatal("queued legacy buffer was retained")
	}
}
