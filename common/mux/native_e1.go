package mux

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/exchange"
)

type nativeChild struct {
	parent    *ServerWorker
	id        uint16
	target    net.Destination
	ctx       context.Context
	cancel    context.CancelFunc
	frames    chan []byte
	inputDone chan struct{}
	inputOnce sync.Once
	endOnce   sync.Once
	current   []byte // only its one transfer reader accesses current
	done      chan struct{}
}

var errNativeFrameBound = errors.New("MUX child frame exceeds input bound")

func (w *ServerWorker) nativeGet(id uint16) *nativeChild {
	w.nativeMu.Lock()
	defer w.nativeMu.Unlock()
	return w.native[id]
}

func (w *ServerWorker) nativeCount() int {
	w.nativeMu.Lock()
	defer w.nativeMu.Unlock()
	return len(w.native)
}

func (w *ServerWorker) nativeAdd(child *nativeChild) error {
	if _, exists := w.sessionManager.Get(child.id); exists {
		return errors.New("MUX child ID already belongs to a legacy session")
	}
	w.nativeMu.Lock()
	defer w.nativeMu.Unlock()
	if _, exists := w.native[child.id]; exists {
		return errors.New("MUX child ID still live or closing")
	}
	if len(w.native) >= maxNativeChildren {
		return errors.New("MUX native child limit reached")
	}
	w.native[child.id] = child
	w.nativeWorkers.Add(1)
	return nil
}

func (w *ServerWorker) nativeRemove(child *nativeChild) {
	w.nativeMu.Lock()
	if w.native[child.id] == child {
		delete(w.native, child.id)
	}
	w.nativeMu.Unlock()
}

func (w *ServerWorker) cancelNativeChildren() {
	w.nativeMu.Lock()
	children := make([]*nativeChild, 0, len(w.native))
	for _, child := range w.native {
		children = append(children, child)
	}
	w.nativeMu.Unlock()
	for _, child := range children {
		child.abort()
	}
}

func (child *nativeChild) closeInput() { child.inputOnce.Do(func() { close(child.inputDone) }) }
func (child *nativeChild) abort()      { child.cancel(); child.closeInput() }

func (child *nativeChild) enqueue(frame []byte) {
	if len(frame) == 0 {
		child.closeInput()
		return
	}
	if child.ctx.Err() != nil {
		return
	}
	select {
	case <-child.inputDone:
		return
	default:
	}
	select {
	case child.frames <- frame:
	default:
		child.abort()
	}
}

func (child *nativeChild) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(child.current) == 0 {
		if err := child.ctx.Err(); err != nil {
			return 0, err
		}
		select {
		case frame := <-child.frames:
			child.current = frame
			continue
		default:
		}
		select {
		case frame := <-child.frames:
			child.current = frame
		case <-child.inputDone:
			if len(child.frames) > 0 {
				continue
			}
			return 0, io.EOF
		case <-child.ctx.Done():
			return 0, child.ctx.Err()
		}
	}
	n := copy(p, child.current)
	child.current = child.current[n:]
	return n, nil
}

func encodeChildData(id uint16, p []byte) ([]byte, error) {
	meta := FrameMetadata{SessionID: id, SessionStatus: SessionStatusKeep}
	meta.Option.Set(OptionData)
	b := buf.NewWithSize(int32(len(p) + 16))
	defer b.Release()
	if err := meta.WriteTo(b); err != nil {
		return nil, err
	}
	if _, err := serial.WriteUint16(b, uint16(len(p))); err != nil {
		return nil, err
	}
	if _, err := b.Write(p); err != nil {
		return nil, err
	}
	return append([]byte(nil), b.Bytes()...), nil
}

func encodeChildEnd(id uint16, failed bool) ([]byte, error) {
	meta := FrameMetadata{SessionID: id, SessionStatus: SessionStatusEnd}
	if failed {
		meta.Option.Set(OptionError)
	}
	b := buf.New()
	defer b.Release()
	if err := meta.WriteTo(b); err != nil {
		return nil, err
	}
	return append([]byte(nil), b.Bytes()...), nil
}

func (child *nativeChild) Write(p []byte) (int, error) {
	accepted := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxNativeFrame {
			chunk = chunk[:maxNativeFrame]
		}
		frame, err := encodeChildData(child.id, chunk)
		if err != nil {
			return accepted, err
		}
		if err = child.parent.frames.submit(child.ctx, frame, false); err != nil {
			return accepted, err
		}
		accepted += len(chunk)
		p = p[len(chunk):]
	}
	return accepted, nil
}

func (child *nativeChild) sendEnd(failed bool) error {
	var endErr error
	child.endOnce.Do(func() {
		frame, err := encodeChildEnd(child.id, failed)
		if err != nil {
			endErr = err
			return
		}
		// END belongs to the carrier even if this child was canceled. FIFO queue
		// acceptance happens before its ID becomes available for reuse.
		endErr = child.parent.frames.submit(child.parent.ctx, frame, true)
	})
	return endErr
}

func (child *nativeChild) run(ctx context.Context, dispatcher routing.StreamDispatcher) {
	defer child.parent.nativeWorkers.Done()
	defer close(child.done)
	defer child.parent.nativeRemove(child)
	timeouts := muxTimeouts(ctx)
	source := exchange.Stream{
		Reader: child, Writer: child,
		InputDone:  child.inputDone,
		Policy:     &timeouts,
		CloseRead:  func() error { child.closeInput(); return nil },
		CloseWrite: func() error { return child.sendEnd(false) },
		Abort:      child.abort,
	}
	err := dispatcher.DispatchStream(child.ctx, child.target, source)
	_ = child.sendEnd(err != nil)
	child.abort()
}

func muxTimeouts(ctx context.Context) policy.Timeout {
	level := uint32(0)
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		level = inbound.User.Level
	}
	timeouts := policy.SessionDefault().Timeouts
	if instance := core.FromContext(ctx); instance != nil {
		if manager, ok := instance.GetFeature(policy.ManagerType()).(policy.Manager); ok {
			timeouts = manager.ForLevel(level).Timeouts
		}
	}
	return timeouts
}

func readNativePayload(reader io.Reader) ([]byte, error) {
	size, err := serial.ReadUint16(reader)
	if err != nil {
		return nil, err
	}
	if size > maxNativeFrame {
		_, drainErr := io.CopyN(io.Discard, reader, int64(size))
		if drainErr != nil {
			return nil, drainErr
		}
		return nil, errNativeFrameBound
	}
	if size == 0 {
		return []byte{}, nil
	}
	frame := make([]byte, size)
	_, err = io.ReadFull(reader, frame)
	return frame, err
}

func (w *ServerWorker) handleNativeNew(ctx context.Context, meta *FrameMetadata, reader io.Reader, dispatcher routing.StreamDispatcher) error {
	if w.nativeGet(meta.SessionID) != nil {
		return errors.New("duplicate native MUX child ID")
	}
	childCtx, cancel := context.WithCancel(ctx)
	child := &nativeChild{parent: w, id: meta.SessionID, target: meta.Target, ctx: childCtx, cancel: cancel, frames: make(chan []byte, childInputFrames), inputDone: make(chan struct{}), done: make(chan struct{})}
	if err := w.nativeAdd(child); err != nil {
		cancel()
		return err
	}
	if meta.Option.Has(OptionData) {
		frame, err := readNativePayload(reader)
		if err != nil {
			if errors.Is(err, errNativeFrameBound) {
				child.abort()
				go child.run(childCtx, dispatcher)
				return nil
			}
			child.abort()
			w.nativeRemove(child)
			close(child.done)
			w.nativeWorkers.Done()
			return err
		}
		child.enqueue(frame)
	}
	go child.run(childCtx, dispatcher)
	return nil
}
