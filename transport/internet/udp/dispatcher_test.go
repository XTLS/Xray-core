package udp_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestSameDestinationDispatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024))

	go func() {
		for {
			data, err := uplinkReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			err = downlinkWriter.WriteMultiBuffer(data)
			common.Must(err)
		}
	}()

	var count uint32
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&count, 1)
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	dest := net.UDPDestination(net.LocalHostIP, 53)

	b := buf.New()
	b.WriteString("abcd")

	var msgCount uint32
	dispatcher := NewDispatcher(td, func(ctx context.Context, packet *udp.Packet) {
		atomic.AddUint32(&msgCount, 1)
	})

	dispatcher.Dispatch(ctx, dest, b)
	for i := 0; i < 5; i++ {
		dispatcher.Dispatch(ctx, dest, b)
	}

	time.Sleep(time.Second)
	cancel()

	if count != 1 {
		t.Error("count: ", count)
	}
	if v := atomic.LoadUint32(&msgCount); v != 6 {
		t.Error("msgCount: ", v)
	}
}

// severityLogHandler reports its severity to log.Enabled and keeps every message it gets.
type severityLogHandler struct {
	severity log.Severity
	sync.Mutex
	messages []string
}

func (h *severityLogHandler) Handle(msg log.Message) {
	h.Lock()
	defer h.Unlock()
	h.messages = append(h.messages, msg.String())
}

func (h *severityLogHandler) Severity() log.Severity { return h.severity }

// newDiscardDispatcher logs to handler until the test ends and returns a Dispatcher whose links
// discard what is written to them.
func newDiscardDispatcher(t *testing.T, handler log.Handler) *Dispatcher {
	log.RegisterHandler(handler)
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	reader, writer := pipe.New()
	t.Cleanup(func() { writer.Close() })
	return NewDispatcher(&TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			return &transport.Link{Reader: reader, Writer: buf.Discard}, nil
		},
	}, nil)
}

func TestDispatchAllocs(t *testing.T) {
	dispatcher := newDiscardDispatcher(t, &severityLogHandler{severity: log.Severity_Warning})
	ctx := t.Context()
	dest := net.UDPDestination(net.LocalHostIP, 53)
	payload := buf.FromBytes([]byte("abcd"))
	dispatcher.Dispatch(ctx, dest, payload)

	if n := testing.AllocsPerRun(100, func() { dispatcher.Dispatch(ctx, dest, payload) }); n != 1 {
		t.Error("Dispatch on an established link: ", n, " allocs, want 1 (buf.MultiBuffer{payload})")
	}
}

func TestDispatchDebugLog(t *testing.T) {
	handler := &severityLogHandler{severity: log.Severity_Debug}
	dispatcher := newDiscardDispatcher(t, handler)
	dispatcher.Dispatch(t.Context(), net.UDPDestination(net.LocalHostIP, 53), buf.FromBytes([]byte("abcd")))

	handler.Lock()
	defer handler.Unlock()
	if !slices.ContainsFunc(handler.messages, func(m string) bool {
		return strings.Contains(m, "dispatch request to: udp:127.0.0.1:53")
	}) {
		t.Error("debug log: ", handler.messages)
	}
}
