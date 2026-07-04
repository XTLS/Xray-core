package videochannel

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"codeberg.org/rape4me/kc/vp8"
)

// goEncoder is a pure Go VP8 encoder.
type goEncoder struct {
	enc       *vp8.Encoder
	width     int
	height    int
	frameSize int
	closed    atomic.Bool
	mu        sync.Mutex
}

func newGoEncoder(width, height, _ int) *goEncoder {
	enc := vp8.NewEncoder(width, height, 63)
	enc.SetKeyInterval(1)
	return &goEncoder{
		enc:       enc,
		width:     width,
		height:    height,
		frameSize: width * height,
	}
}

func (e *goEncoder) EncodeFrame(frame []byte) ([]byte, error) {
	if e.closed.Load() {
		return nil, ErrTransportClosed
	}
	if len(frame) != e.frameSize {
		return nil, fmt.Errorf("%w: got %d expected %d", ErrUnexpectedFrameSize, len(frame), e.frameSize)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	encoded, err := e.enc.Encode(frame)
	if err != nil {
		return nil, fmt.Errorf("vp8 encode: %w", err)
	}
	return encoded, nil
}

func (e *goEncoder) Close() error {
	e.closed.Store(true)
	return nil
}

// goDecoder is a pure Go VP8 decoder.
type goDecoder struct {
	dec       *vp8.Decoder
	width     int
	height    int
	frameSize int
	frames    chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
	closeCh   chan struct{}
}

func newGoDecoder(width, height int) *goDecoder {
	return &goDecoder{
		dec:       vp8.NewDecoder(),
		width:     width,
		height:    height,
		frameSize: width * height,
		frames:    make(chan []byte, 32),
		closeCh:   make(chan struct{}),
	}
}

func (d *goDecoder) PushSample(sample []byte) error {
	if d.closed.Load() {
		return ErrTransportClosed
	}
	frame, err := d.dec.Decode(sample)
	if err != nil {
		if errors.Is(err, vp8.ErrNoReference) {
			return nil
		}
		return nil
	}
	gray := frame.Grayscale()
	select {
	case d.frames <- gray:
	case <-d.closeCh:
		return ErrTransportClosed
	}
	return nil
}

func (d *goDecoder) PopFrame() ([]byte, error) {
	select {
	case frame, ok := <-d.frames:
		if !ok {
			return nil, ErrTransportClosed
		}
		return frame, nil
	case <-d.closeCh:
		return nil, ErrTransportClosed
	}
}

func (d *goDecoder) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.closeCh)
	})
	return nil
}
