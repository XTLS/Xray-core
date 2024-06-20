package splithttp

import (
	"io"
	"sync"
)

type LazyReader struct {
	readerSync   sync.Mutex
	CreateReader func() (io.ReadCloser, error)
	reader       io.ReadCloser
	readerError  error
}

func (r *LazyReader) getReader() (io.ReadCloser, error) {
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

func (r *LazyReader) Close() error {
	r.readerSync.Lock()
	defer r.readerSync.Unlock()

	var err error
	if r.reader != nil {
		err = r.reader.Close()
		r.reader = nil
		r.readerError = newError("closed reader")
	}

	return err
}
