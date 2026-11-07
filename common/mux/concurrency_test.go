package mux_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// overlapWriter stands for a stateful writer under the mux, such as
// VisionWriter, and counts calls that enter it while another call is inside.
type overlapWriter struct {
	inner    buf.Writer
	active   atomic.Int32
	overlaps atomic.Int32
}

func (w *overlapWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.active.Add(1) > 1 {
		w.overlaps.Add(1)
	}
	time.Sleep(time.Millisecond)
	err := w.inner.WriteMultiBuffer(mb)
	w.active.Add(-1)
	return err
}

const overlapSessions = 16

// runMuxPair connects a ClientWorker and a ServerWorker, opens sessions that
// carry data both ways, and waits until every session got its response.
func runMuxPair(t *testing.T, wrapClient, wrapServer func(buf.Writer) buf.Writer) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			inReader, inWriter := pipe.New(pipe.WithoutSizeLimit())
			outReader, outWriter := pipe.New(pipe.WithoutSizeLimit())
			go func() {
				// answer once the request arrives, then end the session
				if _, err := inReader.ReadMultiBuffer(); err != nil {
					return
				}
				for range 4 {
					outWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))})
				}
				outWriter.Close()
			}()
			return &transport.Link{Reader: outReader, Writer: inWriter}, nil
		},
	}

	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	_, err := mux.NewServerWorker(serverCtx, &dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: wrapServer(downlinkWriter),
	})
	common.Must(err)

	client, err := mux.NewClientWorker(transport.Link{
		Reader: downlinkReader,
		Writer: wrapClient(uplinkWriter),
	}, mux.ClientStrategy{MaxConcurrency: overlapSessions})
	common.Must(err)

	var wg sync.WaitGroup
	for i := range overlapSessions {
		clientCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress("example.com"), net.Port(1000+i)),
		}})
		reqReader, reqWriter := pipe.New(pipe.WithoutSizeLimit())
		respReader, respWriter := pipe.New(pipe.WithoutSizeLimit())
		for range 4 {
			reqWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))})
		}
		if !client.Dispatch(clientCtx, &transport.Link{Reader: reqReader, Writer: respWriter}) {
			t.Fatal("failed to dispatch")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var got int32
			for got < 4*int32(len("response")) {
				mb, err := respReader.ReadMultiBuffer()
				if err != nil {
					t.Error(err)
					return
				}
				got += mb.Len()
				buf.ReleaseMulti(mb)
			}
			reqWriter.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sessions did not finish")
	}
}

func identity(w buf.Writer) buf.Writer { return w }

func TestServerWorkerWritesOneAtATime(t *testing.T) {
	var ow *overlapWriter
	runMuxPair(t, identity, func(w buf.Writer) buf.Writer {
		ow = &overlapWriter{inner: w}
		return ow
	})
	if n := ow.overlaps.Load(); n > 0 {
		t.Errorf("ServerWorker entered its writer concurrently %d times", n)
	}
}

func TestClientWorkerWritesOneAtATime(t *testing.T) {
	var ow *overlapWriter
	runMuxPair(t, func(w buf.Writer) buf.Writer {
		ow = &overlapWriter{inner: w}
		return ow
	}, identity)
	if n := ow.overlaps.Load(); n > 0 {
		t.Errorf("ClientWorker entered its writer concurrently %d times", n)
	}
}
