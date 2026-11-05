package proxy_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy"
)

// holdFirstWriter keeps the first write off the wire until the second write lands,
// or until a timeout when the second write cannot start before the first one returns.
type holdFirstWriter struct {
	sync.Mutex
	out     bytes.Buffer
	calls   int
	entered chan struct{}
	landed  chan struct{}
}

func (w *holdFirstWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Lock()
	w.calls++
	call := w.calls
	w.Unlock()
	if call == 1 {
		close(w.entered)
		select {
		case <-w.landed:
		case <-time.After(200 * time.Millisecond):
		}
	}
	w.Lock()
	for _, b := range mb {
		w.out.Write(b.Bytes())
	}
	w.Unlock()
	buf.ReleaseMulti(mb)
	if call == 2 {
		close(w.landed)
	}
	return nil
}

// Mux server sessions write to one VisionWriter from their own goroutines.
// Padding state and the order of blocks on the wire have to change together,
// otherwise the reader gets a padding block without the user UUID first and
// passes padding through as payload.
func TestVisionWriterConcurrentWrites(t *testing.T) {
	uuid := []byte("0123456789abcdef")
	under := &holdFirstWriter{entered: make(chan struct{}), landed: make(chan struct{})}
	writer := proxy.NewVisionWriter(under, proxy.NewTrafficState(uuid), false, context.Background(), nil, nil, nil)

	payloads := [][]byte{bytes.Repeat([]byte{'a'}, 40), bytes.Repeat([]byte{'b'}, 40)}
	write := func(p []byte) error {
		b := buf.New()
		b.Write(p)
		return writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		errs <- write(payloads[0])
	}()
	<-under.entered
	wg.Add(1)
	go func() {
		defer wg.Done()
		errs <- write(payloads[1])
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	reader := proxy.NewVisionReader(buf.NewReader(bytes.NewReader(under.out.Bytes())), proxy.NewTrafficState(uuid), false, context.Background(), nil, nil, nil, nil)
	var got bytes.Buffer
	if err := buf.Copy(reader, buf.NewWriter(&got)); err != nil {
		t.Fatal(err)
	}

	ab := append(append([]byte{}, payloads[0]...), payloads[1]...)
	ba := append(append([]byte{}, payloads[1]...), payloads[0]...)
	if !bytes.Equal(got.Bytes(), ab) && !bytes.Equal(got.Bytes(), ba) {
		t.Fatalf("payloads are not intact after unpadding: got %d bytes %q", got.Len(), got.Bytes())
	}
}
