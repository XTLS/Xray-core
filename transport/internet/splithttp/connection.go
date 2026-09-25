package splithttp

import (
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/bytespool"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
	bulk       bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *splitConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// WriteMultiBuffer writes up to 32 KiB at a time, so the server flushes and
// the client body pipe wakes up once per 32 KiB instead of once per Buffer.
func (c *splitConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if len(mb) == 1 {
		_, err := c.writer.Write(mb[0].Bytes())
		buf.ReleaseMulti(mb)
		return err
	}
	scratch := bytespool.Alloc(32 * 1024)
	defer bytespool.Free(scratch)
	for !mb.IsEmpty() {
		var n int
		mb, n = buf.SplitBytes(mb, scratch)
		if _, err := c.writer.Write(scratch[:n]); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

// ReadMultiBuffer reads into a single Buffer until one comes back full, then
// reads 32 KiB at a time until a read fits into a Buffer again, since every
// h2 body Read may send a WINDOW_UPDATE.
func (c *splitConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !c.bulk {
		b, err := buf.ReadBuffer(c.reader)
		if b == nil {
			return nil, err
		}
		c.bulk = b.IsFull()
		return buf.MultiBuffer{b}, err
	}
	scratch := bytespool.Alloc(32 * 1024)
	defer bytespool.Free(scratch)
	n, err := c.reader.Read(scratch)
	c.bulk = n > buf.Size
	return buf.MergeBytes(nil, scratch[:n]), err
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}
