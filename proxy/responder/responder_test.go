package responder_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/responder"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type writerFunc func(buf.MultiBuffer) error

func (f writerFunc) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return f(mb)
}

func newHandler(t *testing.T, response []byte) *responder.Handler {
	t.Helper()
	handler, err := responder.New(context.Background(), &responder.Config{Response: response})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func responseContext(network net.Network) context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.Destination{Network: network, Address: net.DomainAddress("responder.invalid"), Port: 80},
	}})
}

func TestResponderResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{name: "empty"},
		{name: "binary", response: []byte{0, 255, 128, 1}},
		{name: "large", response: bytes.Repeat([]byte("response\x00\xff"), buf.Size)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler(t, test.response)
			want := string(test.response)
			for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
				t.Run(network.String(), func(t *testing.T) {
					for range 2 {
						var output buf.MultiBufferContainer
						writes := 0
						writer := writerFunc(func(mb buf.MultiBuffer) error {
							writes++
							return output.WriteMultiBuffer(mb)
						})
						ctx := responseContext(network)
						// No reader or dialer: the handler must respond without using either.
						if err := handler.Process(ctx, &transport.Link{Writer: writer}, nil); err != nil {
							t.Fatal(err)
						}
						if writes != 1 || output.MultiBuffer.String() != want {
							t.Fatalf("writes = %d, response length = %d, want one write of %d bytes", writes, output.MultiBuffer.Len(), len(want))
						}
						if got := session.OutboundsFromContext(ctx)[0].Name; got != "responder" {
							t.Fatalf("outbound name = %q, want responder", got)
						}
						if len(output.MultiBuffer) > 0 {
							output.MultiBuffer[0].Bytes()[0] ^= 0xff
						}
						output.Close()
						if string(test.response) != want {
							t.Fatal("sending or modifying the response changed the configured payload")
						}
					}
				})
			}
		})
	}
}

func TestResponderConcurrent(t *testing.T) {
	response := bytes.Repeat([]byte("concurrent response\x00\xff"), buf.Size)
	want := string(response)
	handler := newHandler(t, response)
	for i := range 8 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			var output buf.MultiBufferContainer
			defer output.Close()
			if err := handler.Process(responseContext(net.Network_TCP), &transport.Link{Writer: &output}, nil); err != nil {
				t.Fatal(err)
			}
			if output.MultiBuffer.String() != want {
				t.Fatal("concurrent response mismatch")
			}
			output.MultiBuffer[0].Bytes()[0] ^= 0xff
		})
	}
}

func TestResponderWriteError(t *testing.T) {
	handler := newHandler(t, []byte("response"))
	want := errors.New("write failed")
	writer := writerFunc(func(mb buf.MultiBuffer) error {
		buf.ReleaseMulti(mb)
		return want
	})
	if err := handler.Process(responseContext(net.Network_TCP), &transport.Link{Writer: writer}, nil); !errors.Is(err, want) {
		t.Fatalf("Process returned %v, want %v", err, want)
	}
}

func TestResponderDispatch(t *testing.T) {
	for _, response := range [][]byte{nil, bytes.Repeat([]byte("response\x00\xff"), buf.Size)} {
		name := "large"
		if len(response) == 0 {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			instance, err := core.New(&core.Config{
				App: []*serial.TypedMessage{serial.ToTypedMessage(&proxyman.OutboundConfig{})},
				Outbound: []*core.OutboundHandlerConfig{{
					Tag:           "reply",
					ProxySettings: serial.ToTypedMessage(&responder.Config{Response: response}),
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
			handler := manager.GetHandler("reply")
			if handler == nil {
				t.Fatal("responder handler not registered")
			}
			for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
				t.Run(network.String(), func(t *testing.T) {
					input, upload := pipe.New()
					output, download := pipe.New(pipe.WithoutSizeLimit())
					defer input.Interrupt()
					defer output.Interrupt()
					done := make(chan struct{})
					go func() {
						handler.Dispatch(responseContext(network), &transport.Link{Reader: input, Writer: download})
						close(done)
					}()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("responder did not finish without incoming data")
					}
					// Read after Dispatch returns: normal closure must preserve queued data.
					var actual []byte
					for {
						mb, err := output.ReadMultiBufferTimeout(time.Second)
						actual = append(actual, []byte(mb.String())...)
						buf.ReleaseMulti(mb)
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(actual, response) {
						t.Fatalf("response mismatch: got %d bytes, want %d", len(actual), len(response))
					}
					if err := upload.WriteMultiBuffer(buf.MergeBytes(nil, []byte("late request"))); err != io.ErrClosedPipe {
						t.Fatalf("input was not interrupted: got %v, want %v", err, io.ErrClosedPipe)
					}
				})
			}
		})
	}
}
