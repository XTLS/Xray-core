package splithttp

import (
	"io"
	"sync"
)

// Close is intentionally not supported by LazyReader because it's not clear
// how CreateReader should be aborted in case of Close. It's best to wrap
// LazyReader in another struct that handles Close correctly, or better, stop
// using LazyReader entirely.
type LazyReader struct {
	readerSync   sync.Mutex
	CreateReader func() (io.Reader, error)
	reader       io.Reader
	readerError  error
}

func (r *LazyReader) getReader() (io.Reader, error) {
	r.readerSync.Lock()
	defer r.readerSync.Unlock()
	if r.reader != nil {
		return r.reader, nil
	}

	if r.readerError != nil {
		return nil, r.readerError
	}

	reader, err := r.CreateReader()
	if err != nil {
		r.readerError = err
		return nil, err
	}

	r.reader = reader
	return reader, nil
}

func (r *LazyReader) Read(b []byte) (int, error) {
	reader, err := r.getReader()
	if err != nil {
		return 0, err
	}
	n, err := reader.Read(b)
	return n, err
}
