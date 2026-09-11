package xdrive

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

var placeholderAddr = &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 0}

type Conn struct {
	cancel  context.CancelFunc
	writer  *walWriter
	reader  *walReader
	onClose func()

	readBuf []byte

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
	closeErr  error
}

func newConn(ctx context.Context, storage Storage, writePrefix, readPrefix string, p params, onClose func()) *Conn {
	ctx, cancel := context.WithCancel(ctx)
	return &Conn{
		cancel:  cancel,
		writer:  newWALWriter(ctx, storage, writePrefix, p),
		reader:  newWALReader(ctx, storage, readPrefix, p),
		onClose: onClose,
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(c.readBuf) == 0 {
		data, err := c.receive()
		if err != nil {
			return 0, err
		}
		c.readBuf = data
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) receive() ([]byte, error) {
	deadline := c.getDeadline(true)
	if deadline.IsZero() {
		data, ok := <-c.reader.ch
		if !ok {
			return nil, c.reader.Err()
		}
		return data, nil
	}

	if !time.Now().Before(deadline) {
		return nil, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case data, ok := <-c.reader.ch:
		if !ok {
			return nil, c.reader.Err()
		}
		return data, nil
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if deadline := c.getDeadline(false); !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.writer.Write(b)
	if err == nil {
		c.reader.Wake()
	}
	return n, err
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.writer.Close()
		c.cancel()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr {
	return placeholderAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return placeholderAddr
}

func (c *Conn) getDeadline(read bool) time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if read {
		return c.readDeadline
	}
	return c.writeDeadline
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return nil
}
