package splithttp

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

// downlinkBuffer retains recently written bytes so that a stream-down request
// cut by a middlebox can be replaced by a new one continuing at the offset the
// client actually received. Retention is released as soon as the client
// acknowledges it, so an active session holds only what a cut could lose.
type downlinkBuffer struct {
	access sync.Mutex
	cond   *sync.Cond

	writer *httpServerConn
	gen    uint64

	sent    uint64
	trimmed uint64
	buf     buf.MultiBuffer
	maxBuf  int32

	closed bool
}

func newDownlinkBuffer(maxBuf int32) *downlinkBuffer {
	d := &downlinkBuffer{maxBuf: maxBuf}
	d.cond = sync.NewCond(&d.access)
	return d
}

func (d *downlinkBuffer) checkOffset(clientOffset uint64) error {
	if clientOffset < d.trimmed || clientOffset > d.sent {
		return errors.New("downlink offset ", clientOffset, " outside retained window [", d.trimmed, ", ", d.sent, "]")
	}
	return nil
}

func (d *downlinkBuffer) discard(n int32) {
	for n > 0 && !d.buf.IsEmpty() {
		first := d.buf[0]
		if first.Len() > n {
			first.Advance(n)
			d.trimmed += uint64(n)
			return
		}
		n -= first.Len()
		d.trimmed += uint64(first.Len())
		var released *buf.Buffer
		d.buf, released = buf.SplitFirst(d.buf)
		released.Release()
	}
}

// Write never reports a failing writer: those bytes stay retained and are
// replayed once the client reattaches.
func (d *downlinkBuffer) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	d.access.Lock()
	for !d.closed && d.writer == nil && d.buf.Len()+int32(len(b)) > d.maxBuf {
		d.cond.Wait()
	}
	if d.closed {
		d.access.Unlock()
		return 0, io.ErrClosedPipe
	}
	d.buf = buf.MergeBytes(d.buf, b)
	d.sent += uint64(len(b))
	if over := d.buf.Len() - d.maxBuf; over > 0 {
		d.discard(over)
	}
	writer, gen := d.writer, d.gen
	d.access.Unlock()

	if writer != nil {
		if _, err := writer.Write(b); err != nil {
			d.detach(gen)
		}
	}
	return len(b), nil
}

// Finished reports that the tunnel is over: what is retained is everything the
// client will ever get.
func (d *downlinkBuffer) Finished() (bool, uint64) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.closed, d.sent
}

func (d *downlinkBuffer) CanAttach(clientOffset uint64) error {
	d.access.Lock()
	defer d.access.Unlock()
	return d.checkOffset(clientOffset)
}

func (d *downlinkBuffer) Attach(writer *httpServerConn, clientOffset uint64) error {
	d.access.Lock()
	if err := d.checkOffset(clientOffset); err != nil {
		d.access.Unlock()
		return err
	}
	stale := d.writer
	replay := make([]byte, d.buf.Len())
	d.buf.Copy(replay)
	replay = replay[clientOffset-d.trimmed:]
	d.writer = writer
	d.gen++
	gen := d.gen
	d.cond.Broadcast()
	d.access.Unlock()

	// Closing takes the connection's own lock, which an in-flight Write may
	// hold while it waits for d.access, so it must happen outside the lock.
	if stale != nil {
		stale.Close()
	}

	if len(replay) > 0 {
		if _, err := writer.Write(replay); err != nil {
			d.detach(gen)
			return errors.New("failed to replay downlink").Base(err)
		}
	}
	return nil
}

func (d *downlinkBuffer) detach(gen uint64) {
	d.access.Lock()
	var stale *httpServerConn
	if d.gen == gen && d.writer != nil {
		stale = d.writer
		d.writer = nil
		d.gen++
		d.cond.Broadcast()
	}
	d.access.Unlock()

	if stale != nil {
		stale.Close()
	}
}

// Detach reports whether the stream it retired was the live one: a request
// that only notices its own reset after the client reattached must not be
// mistaken for the session going idle.
func (d *downlinkBuffer) Detach(writer *httpServerConn) bool {
	d.access.Lock()
	defer d.access.Unlock()
	if d.writer != writer {
		return false
	}
	d.writer = nil
	d.gen++
	d.cond.Broadcast()
	return true
}

func (d *downlinkBuffer) Attached() bool {
	d.access.Lock()
	defer d.access.Unlock()
	return d.writer != nil
}

func (d *downlinkBuffer) Ack(received uint64) {
	d.access.Lock()
	if received > d.trimmed && received <= d.sent {
		if drop := int32(received - d.trimmed); drop <= d.buf.Len() {
			d.discard(drop)
			d.cond.Broadcast()
		}
	}
	d.access.Unlock()
}

func (d *downlinkBuffer) Close() error {
	d.access.Lock()
	if d.closed {
		d.access.Unlock()
		return nil
	}
	d.closed = true
	writer := d.writer
	d.writer = nil
	d.cond.Broadcast()
	d.access.Unlock()

	if writer != nil {
		writer.Close()
	}
	return nil
}

// Release returns the retained buffers to the pool once the session is gone.
func (d *downlinkBuffer) Release() {
	d.access.Lock()
	d.buf = buf.ReleaseMulti(d.buf)
	d.access.Unlock()
}
