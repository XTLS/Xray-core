package outbound

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/pipe"
)

// PrepareLegacyPacket is an explicit migration edge for an old handler. Its
// private pipes never receive the association socket, and its Dispatch worker
// must return before the leg finishes aborting. Native Freedom bypasses it.
func PrepareLegacyPacket(parent context.Context, handler Handler, fallback net.Destination) exchange.PacketEndpoint {
	ctx, cancel := context.WithCancel(parent)
	upR, upW := pipe.New(pipe.OptionsFromContext(ctx)...)
	downR, downW := pipe.New(pipe.OptionsFromContext(ctx)...)
	reader := &legacyPacketReader{reader: downR, fallback: fallback}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer common.Close(downW)
		handler.Dispatch(ctx, &transport.Link{Reader: upR, Writer: downW})
	}()
	var once sync.Once
	abort := func() {
		once.Do(func() {
			cancel()
			common.Interrupt(upR)
			common.Interrupt(upW)
			common.Interrupt(downR)
			common.Interrupt(downW)
			reader.release()
			<-done
		})
	}
	return exchange.PacketEndpoint{Reader: reader, Writer: legacyPacketWriter{writer: upW}, Abort: abort}
}

type legacyPacketReader struct {
	mu       sync.Mutex
	reader   buf.Reader
	cache    buf.MultiBuffer
	fallback net.Destination
	closed   bool
}

func (r *legacyPacketReader) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	buf.ReleaseMulti(r.cache)
	r.cache = nil
}

func (r *legacyPacketReader) ReadPacket(p []byte) (int, net.Destination, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, net.Destination{}, io.ErrClosedPipe
	}
	for {
		if len(r.cache) == 0 {
			mb, err := r.reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(mb)
				return 0, net.Destination{}, err
			}
			r.cache = mb
		}
		var b *buf.Buffer
		r.cache, b = buf.SplitFirst(r.cache)
		if b == nil {
			continue
		}
		defer b.Release()
		if int(b.Len()) > len(p) {
			return 0, net.Destination{}, io.ErrShortBuffer
		}
		dest := r.fallback
		if b.UDP != nil {
			dest = *b.UDP
		}
		return copy(p, b.Bytes()), dest, nil
	}
}

type legacyPacketWriter struct{ writer buf.Writer }

func (w legacyPacketWriter) WritePacket(p []byte, dest net.Destination) (int, error) {
	b := buf.FromBytes(append([]byte(nil), p...))
	b.UDP = &dest
	if err := w.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return 0, err
	}
	return len(p), nil
}
