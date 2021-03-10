package encoding

import (
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net/cnc"
	"io"
	"net"
)

type HunkConn interface {
	Send(*Hunk) error
	Recv() (*Hunk, error)
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

type StreamCloser interface {
	CloseSend() error
}

type HunkReaderWriter struct {
	hc     HunkConn
	cancel context.CancelFunc

	buf   []byte // use buf per conn to avoid unnecessary alloc. **cap(buf) >= 2 * buf.Size**
	index int
}

func NewHunkReadWriter(hc HunkConn, cancel context.CancelFunc) io.ReadWriteCloser {
	return &HunkReaderWriter{hc, cancel, make([]byte, 0, 2*buf.Size), 0}
}

func NewHunkConn(hc HunkConn, cancel context.CancelFunc) net.Conn {
	wrc := NewHunkReadWriter(hc, cancel)
	return cnc.NewConnection(
		cnc.ConnectionInput(wrc),
		cnc.ConnectionOutput(wrc),
		cnc.ConnectionOnClose(wrc),
	)
}

func (h *HunkReaderWriter) forceFetch() error {
	// clean up buffer, safety first!
	h.buf = h.buf[:0]
	h.index = 0

	hunk := new(Hunk)
	hunk.Data = h.buf
	err := h.hc.RecvMsg(hunk)
	if err != nil {
		return newError("failed to fetch hunk from gRPC tunnel").Base(err)
	}

	h.buf = hunk.Data

	return nil
}

func (h *HunkReaderWriter) Read(buf []byte) (int, error) {
	if h.buf == nil {
		if err := h.forceFetch(); err != nil {
			return 0, err
		}
	}
	n := copy(buf, h.buf[h.index:])
	h.index += n

	if h.index >= len(h.buf) {
		h.buf = nil
	}
	return n, nil
}

func (h *HunkReaderWriter) Write(buf []byte) (int, error) {
	err := h.hc.Send(&Hunk{Data: buf[:]})
	if err != nil {
		return 0, newError("failed to send data over gRPC tunnel").Base(err)
	}
	return len(buf), nil
}

func (h *HunkReaderWriter) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	if sc, match := h.hc.(StreamCloser); match {
		return sc.CloseSend()
	}

	return nil
}
