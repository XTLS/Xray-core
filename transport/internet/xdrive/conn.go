package xdrive

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

var placeholderAddr = &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 0}

// Conn is a session in segments, walWriter and walReader, or in slots,
// slotWriter and slotReader
type Conn struct {
	ctx     context.Context
	cancel  context.CancelFunc
	writer  connWriter
	reader  chunkReader
	onClose func()

	readMu  sync.Mutex
	readBuf []byte

	readDeadline  *pipeDeadline
	writeDeadline *pipeDeadline
	closing       chan struct{}

	publishWG sync.WaitGroup // registered before Dial exposes the connection
	closeOnce sync.Once
	closeErr  error
}

type connWriter interface {
	io.WriteCloser
	// writeUntil returns errWriteStopped, with the bytes it took, once either
	// channel is closed
	writeUntil(p []byte, deadline, closing <-chan struct{}) (int, error)
}

type chunkReader interface {
	// chunks is closed when there are no more, then Err says why
	chunks() <-chan []byte
	Err() error
	Wake()
}

func newConn(ctx context.Context, storage Storage, writePrefix, readPrefix string, p params, discard bool, onClose func()) *Conn {
	ctx, cancel := context.WithCancel(ctx)
	return &Conn{
		ctx:     ctx,
		cancel:  cancel,
		writer:  newWALWriter(ctx, storage, writePrefix, p),
		reader:  newWALReader(ctx, storage, readPrefix, p, discard),
		onClose: onClose,

		readDeadline:  newPipeDeadline(),
		writeDeadline: newPipeDeadline(),
		closing:       make(chan struct{}),
	}
}

func newSlotConn(ctx context.Context, store slotStore, write, read slotTable, p params, first []byte, onClose func()) *Conn {
	ctx, fail := context.WithCancelCause(ctx)
	closing := make(chan struct{})
	return &Conn{
		ctx:     ctx,
		cancel:  func() { fail(context.Canceled) },
		writer:  newSlotWriter(ctx, fail, store, write, p),
		reader:  newSlotReader(ctx, fail, store, read, p, first, closing),
		onClose: onClose,

		readDeadline:  newPipeDeadline(),
		writeDeadline: newPipeDeadline(),
		closing:       closing,
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	select {
	case <-c.closing:
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case <-c.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.readBuf) > 0 {
		// Check state again before consuming buffered bytes: deadline or Close
		// may have happened after we filled readBuf but before this Read call.
		select {
		case <-c.closing:
			return 0, io.ErrClosedPipe
		default:
		}
		select {
		case <-c.readDeadline.wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		if len(c.readBuf) == 0 {
			c.readBuf = nil
		}
		return n, nil
	}
	data, err := c.receive()
	if err != nil {
		return 0, err
	}
	c.readBuf = data
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if len(c.readBuf) == 0 {
		c.readBuf = nil
	}
	return n, nil
}

func (c *Conn) receive() ([]byte, error) {
	select {
	case <-c.closing:
		return nil, io.ErrClosedPipe
	default:
	}
	deadline := c.readDeadline.wait()
	select {
	case <-deadline:
		return nil, os.ErrDeadlineExceeded
	default:
	}

	select {
	case data, ok := <-c.reader.chunks():
		if !ok {
			return nil, c.reader.Err()
		}
		return data, nil
	case <-deadline:
		return nil, os.ErrDeadlineExceeded
	case <-c.closing:
		return nil, io.ErrClosedPipe
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	select {
	case <-c.closing:
		return 0, io.ErrClosedPipe
	default:
	}
	deadline := c.writeDeadline.wait()
	select {
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	n, err := c.writer.writeUntil(b, deadline, c.closing)
	if err == errWriteStopped {
		select {
		case <-c.closing:
			err = io.ErrClosedPipe
		default:
			err = os.ErrDeadlineExceeded
		}
	}
	if n > 0 {
		c.reader.Wake()
	}
	return n, err
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closing)
		c.readDeadline.stop()
		c.writeDeadline.stop()
		done := make(chan struct{})
		var result error
		started := time.Now()
		progress := func() time.Time { return started }
		if writer, ok := c.writer.(*slotWriter); ok {
			writer.markProgress()
			reader := c.reader.(*slotReader)
			progress = func() time.Time {
				last := writer.closeProgress()
				// Inbound activity must not hide a stalled outbound writer.
				if credit := reader.drainCredit.Load(); isClosedChan(writer.done) && credit != nil && credit.After(last) {
					return *credit
				}
				return last
			}
		}
		go func() {
			result = c.closeOrdered(c.writer.Close())
			close(done)
		}()
		c.closeErr = waitCloseProgress(done, progress)
		if c.closeErr == nil {
			c.closeErr = result
		}
		c.cancel()
	})
	return c.closeErr
}

func (c *Conn) closeOrdered(err error) error {
	c.publishWG.Wait()
	if err == nil {
		if writer, ok := c.writer.(interface{ Err() error }); ok {
			err = writer.Err()
		}
	}
	if reader, ok := c.reader.(*slotReader); ok && err == nil {
		// Our END says nothing about the peer's outstanding writes. Keep the
		// discard reader and its ACK worker alive through the peer's END.
		// The outer watchdog bounds this wait even if the peer never closes.
		reader.wait()
		err = context.Cause(c.ctx)
	}
	c.cancel()
	if writer, ok := c.writer.(interface{ wait() }); ok {
		writer.wait()
	}
	if reader, ok := c.reader.(interface{ wait() }); ok {
		reader.wait()
	}
	if c.onClose != nil {
		c.onClose()
	}
	return err
}

func (c *Conn) Interrupt() {
	c.cancel()
	c.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return placeholderAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return placeholderAddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t)
	return nil
}

// pipeDeadline is a deadline whose wait channel closes when it passes. Setting
// a new time re-arms it, so a call already waiting on the channel sees the
// change.
type pipeDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	cancel  chan struct{}
	gen     uint64
	stopped bool
}

func newPipeDeadline() *pipeDeadline {
	return &pipeDeadline{cancel: make(chan struct{})}
}

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}

	if d.timer != nil {
		// Stop does not join a callback that has already started; gen makes
		// that callback skip its close, so a channel is closed at most once.
		d.timer.Stop()
		d.timer = nil
		d.gen++
	}

	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel, gen := d.cancel, d.gen
		d.timer = time.AfterFunc(dur, func() {
			d.mu.Lock()
			if d.gen == gen {
				close(cancel)
			}
			d.mu.Unlock()
		})
		return
	}
	if !closed {
		close(d.cancel)
		d.gen++
	}
}

func (d *pipeDeadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.gen++ // an in-flight callback must not close a channel reused later
	d.stopped = true
}

func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
