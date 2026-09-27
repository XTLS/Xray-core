package exchange

import (
	"errors"
	"io"
	"time"
)

// ReadInitial gives a protocol preparer one bounded chance to coalesce an
// initial payload with its header. A consumed data+error result keeps its
// terminal error for the common transfer owner.
func ReadInitial(source *Stream, timeout time.Duration, maxBytes int32) ([]byte, error) {
	timed, ok := source.Reader.(TimedReader)
	if !ok || maxBytes <= 0 {
		return nil, nil
	}
	p := make([]byte, maxBytes)
	n, err := timed.ReadTimeout(p, timeout)
	if n > 0 && source.CountRead != nil {
		source.CountRead(int64(n))
	}
	if n > 0 && err != nil {
		source.Reader = &pendingReader{Reader: source.Reader, pending: err}
		err = nil
	}
	if err != nil {
		var timeoutError interface{ Timeout() bool }
		if errors.As(err, &timeoutError) && timeoutError.Timeout() {
			return nil, nil
		}
		return nil, err
	}
	return p[:n], nil
}

type pendingReader struct {
	io.Reader
	pending error
}

func (r *pendingReader) Read(p []byte) (int, error) {
	if r.pending != nil {
		err := r.pending
		r.pending = nil
		return 0, err
	}
	return r.Reader.Read(p)
}
