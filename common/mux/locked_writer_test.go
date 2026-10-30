package mux

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func workerWriter(t *testing.T, side string, writer buf.Writer) buf.Writer {
	t.Helper()
	reader, _ := pipe.New()
	link := transport.Link{Reader: reader, Writer: writer}
	if side == "client" {
		worker, err := NewClientWorker(link, ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = worker.Close(); _ = common.Interrupt(reader) })
		return worker.link.Writer
	}
	worker, err := NewServerWorker(context.Background(), nil, &link)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close(); _ = common.Interrupt(reader) })
	if link.Writer != writer {
		t.Fatal("server changed the caller's writer")
	}
	return worker.link.Writer
}

type chunkWriter struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (w *chunkWriter) WriteMultiBuffer(m buf.MultiBuffer) error {
	defer buf.ReleaseMulti(m)
	for _, b := range m {
		w.mu.Lock()
		w.data.Write(b.Bytes())
		w.mu.Unlock()
		runtime.Gosched()
	}
	return nil
}

func TestMuxWriterFrameIntegrity(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			sink := new(chunkWriter)
			out := workerWriter(t, side, sink)
			var wg sync.WaitGroup
			for i := 1; i <= 8; i++ {
				wg.Add(1)
				go func(id byte) {
					defer wg.Done()
					w := NewResponseWriter(uint16(id), out, protocol.TransferTypeStream)
					for j := 0; j < 50; j++ {
						if err := w.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte{id}, 4096))); err != nil {
							t.Error(err)
							return
						}
					}
				}(byte(i))
			}
			wg.Wait()
			r := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(sink.data.Bytes()))}
			counts := map[uint16]int{}
			for i := 0; i < 400; i++ {
				var meta FrameMetadata
				if err := meta.Unmarshal(r, false); err != nil {
					t.Fatal(err)
				}
				if meta.SessionID < 1 || meta.SessionID > 8 {
					t.Fatalf("invalid session %d", meta.SessionID)
				}
				data, err := buf.ReadAllToBytes(&buf.BufferedReader{Reader: NewStreamReader(r)})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, bytes.Repeat([]byte{byte(meta.SessionID)}, 4096)) {
					t.Fatal("interleaved or truncated frame")
				}
				counts[meta.SessionID]++
			}
			for id := uint16(1); id <= 8; id++ {
				if counts[id] != 50 {
					t.Fatalf("lost/duplicated frame for %d: %d", id, counts[id])
				}
			}
			if _, err := r.ReadByte(); err != io.EOF {
				t.Fatalf("trailing data: %v", err)
			}
		})
	}
}

type blockedWriter struct {
	entered chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func (w *blockedWriter) WriteMultiBuffer(m buf.MultiBuffer) error {
	defer buf.ReleaseMulti(m)
	close(w.entered)
	<-w.unblock
	return io.ErrClosedPipe
}

func (w *blockedWriter) Close() error {
	w.once.Do(func() { close(w.unblock) })
	return nil
}

type interruptWriter struct {
	*blockedWriter
	called chan struct{}
}

func (w *interruptWriter) Interrupt() {
	close(w.called)
	_ = w.blockedWriter.Close()
}

func TestMuxWriterBlockedWriteShutdown(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "interrupt"}[interrupt], func(t *testing.T) {
			b := &blockedWriter{entered: make(chan struct{}), unblock: make(chan struct{})}
			defer b.Close()
			var inner buf.Writer = b
			called := make(chan struct{})
			if interrupt {
				inner = &interruptWriter{blockedWriter: b, called: called}
			}
			w := newMuxWriter(inner)
			finished := make(chan error, 1)
			go func() { finished <- w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("test"))}) }()
			select {
			case <-b.entered:
			case <-time.After(time.Second):
				t.Fatal("write did not start")
			}
			stopped := make(chan error, 1)
			go func() {
				if interrupt {
					stopped <- common.Interrupt(w)
				} else {
					stopped <- common.Close(w)
				}
			}()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown blocked behind writer lock")
			}
			select {
			case err := <-finished:
				if err != io.ErrClosedPipe {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("write not unblocked")
			}
			if interrupt {
				select {
				case <-called:
				default:
					t.Fatal("underlying Interrupt not forwarded")
				}
			}
		})
	}
}

func BenchmarkMuxWriter(b *testing.B) {
	for _, size := range []int{128, 4096, 8192} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for _, locked := range []bool{false, true} {
				name := "direct"
				if locked {
					name = "locked"
				}
				b.Run(name, func(b *testing.B) {
					var out buf.Writer = buf.Discard
					if locked {
						out = newMuxWriter(out)
					}
					payload := bytes.Repeat([]byte{1}, size)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.RunParallel(func(pb *testing.PB) {
						writer := NewResponseWriter(1, out, protocol.TransferTypeStream)
						for pb.Next() {
							if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
								b.Error(err)
								return
							}
						}
					})
				})
			}
		})
	}
}
