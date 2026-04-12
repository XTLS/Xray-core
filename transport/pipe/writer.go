package pipe

import (
	"github.com/xtls/xray-core/common/buf"
)

// Writer is a buf.Writer that writes data into a pipe.
type Writer struct {
	pipe *pipe
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	mb := make(buf.MultiBuffer, 0, (len(p)+buf.Size-1)/buf.Size)
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > buf.Size {
			chunkSize = buf.Size
		}

		chunk := buf.NewWithSize(int32(chunkSize))
		_, _ = chunk.Write(p[:chunkSize])
		mb = append(mb, chunk)
		p = p[chunkSize:]
	}

	if err := w.pipe.WriteMultiBuffer(mb); err != nil {
		return 0, err
	}

	return total, nil
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.pipe.WriteMultiBuffer(mb)
}

// Close implements io.Closer. After the pipe is closed, writing to the pipe will return io.ErrClosedPipe, while reading will return io.EOF.
func (w *Writer) Close() error {
	return w.pipe.Close()
}

func (w *Writer) Len() int32 {
	return w.pipe.Len()
}

// Interrupt implements common.Interruptible.
func (w *Writer) Interrupt() {
	w.pipe.Interrupt()
}
