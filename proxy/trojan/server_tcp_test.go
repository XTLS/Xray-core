package trojan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

func TestTrojanTCPDispatchLink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	destination := net.TCPDestination(net.DomainAddress("test.invalid"), 443)
	const prefix = "payload buffered with the header"
	const tail = "payload after the timed read"
	const reply = "response after uplink EOF"
	timedOut := make(chan struct{})
	dispatcher := &trojanTestDispatcher{
		dispatchLink: func(ctx context.Context, dest net.Destination, link *transport.Link) error {
			if dest != destination {
				return fmt.Errorf("dispatch destination = %v, want %v", dest, destination)
			}
			reader, ok := link.Reader.(buf.TimeoutReader)
			if !ok {
				return errors.New("TCP link does not implement timed reads")
			}
			input := &buf.BufferedReader{Reader: reader}
			defer func() { buf.ReleaseMulti(input.Buffer) }()
			payload := make([]byte, len(prefix))
			if _, err := io.ReadFull(input, payload); err != nil {
				return err
			}
			if string(payload) != prefix {
				return fmt.Errorf("buffered payload = %q, want %q", payload, prefix)
			}

			first, err := reader.ReadMultiBufferTimeout(20 * time.Millisecond)
			defer buf.ReleaseMulti(first)
			if !first.IsEmpty() || !errors.Is(err, buf.ErrReadTimeout) {
				return fmt.Errorf("timed read = %d bytes, %v", first.Len(), err)
			}
			close(timedOut)

			payload = make([]byte, len(tail))
			if _, err := io.ReadFull(input, payload); err != nil {
				return err
			}
			if string(payload) != tail {
				return fmt.Errorf("payload after timed read = %q, want %q", payload, tail)
			}
			var trailing [1]byte
			if n, err := input.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
				return fmt.Errorf("read after client CloseWrite = %d bytes, %v", n, err)
			}
			response := buf.New()
			if _, err := response.WriteString(reply); err != nil {
				response.Release()
				return err
			}
			return link.Writer.WriteMultiBuffer(buf.MultiBuffer{response})
		},
	}

	client, conn := trojanTestTCPPair(t, ctx)
	header, done := serveTrojanTest(t, ctx, conn, dispatcher)
	var firstWrite bytes.Buffer
	header.Target = destination
	header.Writer = &firstWrite
	if _, err := io.WriteString(header, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := firstWrite.WriteTo(client); err != nil {
		t.Fatal(err)
	}

	select {
	case <-timedOut:
	case err := <-done:
		t.Fatalf("handler finished before timed read: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := io.WriteString(client, tail); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, len(reply))
	if _, err := io.ReadFull(client, payload); err != nil {
		select {
		case handlerErr := <-done:
			t.Fatalf("read response: %v, handler: %v", err, handlerErr)
		default:
			t.Fatal(err)
		}
	}
	if string(payload) != reply {
		t.Fatalf("response = %q, want %q", payload, reply)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := dispatcher.legacyCalls.Load(); got != 0 {
		t.Fatalf("old Dispatch called %d times", got)
	}
}
