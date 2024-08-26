package splithttp

import (
	"bytes"
	"io"

	"github.com/xmplusdev/xray-core/common/errors"
)

// in older versions of splithttp, the server would respond with `ok` to flush
// out HTTP response headers early. Response headers and a 200 OK were required
// to initiate the connection. Later versions of splithttp dropped this
// requirement, and in xray 1.8.24 the server stopped sending "ok" if it sees
// x_padding. For compatibility, we need to remove "ok" from the underlying
// reader if it exists, and otherwise forward the stream as-is.
type stripOkReader struct {
	io.ReadCloser
	firstDone  bool
	prefixRead []byte
}

func (r *stripOkReader) Read(b []byte) (int, error) {
	if !r.firstDone {
		r.firstDone = true

		// skip "ok" response
		prefixRead := []byte{0, 0}
		_, err := io.ReadFull(r.ReadCloser, prefixRead)
		if err != nil {
			return 0, errors.New("failed to read initial response").Base(err)
		}

		if !bytes.Equal(prefixRead, []byte("ok")) {
			// we read some garbage byte that may not have been "ok" at
			// all. return a reader that replays what we have read so far
			r.prefixRead = prefixRead
		}
	}

	if len(r.prefixRead) > 0 {
		n := copy(b, r.prefixRead)
		r.prefixRead = r.prefixRead[n:]
		return n, nil
	}

	n, err := r.ReadCloser.Read(b)
	return n, err
}
