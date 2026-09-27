package exchange

import (
	"io"
	"net"

	"github.com/xtls/xray-core/common/buf"
)

// Native vector IO is a leaf, never the execution ABI. Counters and activity
// advance during transfer, not only after io.Copy returns.
func transfer(dst io.Writer, src io.Reader, native, splice bool, update func(), countRead, countWrite func(int64)) error {
	write := func(p []byte) error {
		n, err := writeAll(&countedWriter{Writer: dst, count: countWrite}, p)
		if n > 0 {
			update()
		}
		return err
	}
	readProgress := func(n int64) {
		if n > 0 {
			update()
			if countRead != nil {
				countRead(n)
			}
		}
	}
	writeProgress := func(n int64) {
		if n > 0 {
			update()
			if countWrite != nil {
				countWrite(n)
			}
		}
	}
	if native {
		if in, ok := src.(*Input); ok {
			if len(in.cached) > 0 {
				p := in.cached
				in.cached = nil
				readProgress(int64(len(p)))
				if err := write(p); err != nil {
					return err
				}
			}
			if in.pending != nil {
				err := in.pending
				in.pending = nil
				return err
			}
			src = in.reader
		}
		if splice {
			if handled, err := spliceTransfer(dst, src, readProgress, writeProgress); handled {
				return err
			}
		}
		if raw, ok := src.(*net.TCPConn); ok {
			if _, ok := dst.(*net.TCPConn); ok {
				reader := buf.NewReader(raw)
				vectors := make(net.Buffers, 0, 16)
				for {
					mb, readErr := reader.ReadMultiBuffer()
					readProgress(int64(mb.Len()))
					vectors = vectors[:0]
					for _, b := range mb {
						if b != nil {
							vectors = append(vectors, b.Bytes())
						}
					}
					pending := vectors
					n, writeErr := pending.WriteTo(dst)
					writeProgress(n)
					buf.ReleaseMulti(mb)
					clear(vectors)
					if writeErr != nil {
						return writeErr
					}
					if readErr != nil {
						return readErr
					}
				}
			}
		}
	}
	buffer := transferBuffer.Get().([]byte)
	defer transferBuffer.Put(buffer)
	_, err := io.CopyBuffer(&countedWriter{Writer: dst, count: writeProgress}, &activityReader{Reader: src, update: update, count: countRead}, buffer)
	return err
}
