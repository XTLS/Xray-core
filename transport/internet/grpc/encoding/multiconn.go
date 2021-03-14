package encoding

import (
	"context"
	"io"
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/signal/done"
)

type MultiHunkConn interface {
	Send(*MultiHunk) error
	Recv() (*MultiHunk, error)
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

type MultiHunkReaderWriter struct {
	hc     MultiHunkConn
	cancel context.CancelFunc
	done   *done.Instance

	buf [][]byte
}

func NewMultiHunkReadWriter(hc MultiHunkConn, cancel context.CancelFunc) *MultiHunkReaderWriter {
	return &MultiHunkReaderWriter{hc, cancel, done.New(), nil}
}

func NewMultiHunkConn(hc MultiHunkConn, cancel context.CancelFunc) net.Conn {
	wrc := NewMultiHunkReadWriter(hc, cancel)
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(wrc),
		cnc.ConnectionOutputMulti(wrc),
		cnc.ConnectionOnClose(wrc),
	)
}

func (h *MultiHunkReaderWriter) forceFetch() error {
	hunk, err := h.hc.Recv()
	if err != nil {
		if err == io.EOF {
			return err
		}

		return newError("failed to fetch hunk from gRPC tunnel").Base(err)
	}

	h.buf = hunk.Data

	return nil
}

func (h *MultiHunkReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if h.done.Done() {
		return nil, io.EOF
	}

	if err := h.forceFetch(); err != nil {
		return nil, err
	}

	var mb = make(buf.MultiBuffer, 0, len(h.buf))
	for _, b := range h.buf {
		if cap(b) >= buf.Size {
			mb = append(mb, buf.NewExisted(b))
			continue
		}

		nb := buf.New()
		nb.Extend(int32(len(b)))
		copy(nb.Bytes(), b)

		mb = append(mb, nb)
	}
	return mb, nil
}

func (h *MultiHunkReaderWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if h.done.Done() {
		return io.ErrClosedPipe
	}

	hunk := &MultiHunk{Data: make([][]byte, len(mb))}
	for _, b := range mb {
		hunk.Data = append(hunk.Data, b.Bytes())
	}

	err := h.hc.Send(hunk)
	if err != nil {
		return err
	}
	return nil
}

func (h *MultiHunkReaderWriter) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	if sc, match := h.hc.(StreamCloser); match {
		return sc.CloseSend()
	}

	return h.done.Close()
}
