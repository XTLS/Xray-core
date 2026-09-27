// Package exchange owns the lifetime of one routed logical stream. Its boundary
// deliberately does not prescribe a socket, a packet buffer, or a pipe.
package exchange

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
)

// Stream describes only operations owned by this logical exchange. Abort must
// unblock pending I/O; it must not close a shared carrier or a sibling stream.
type Stream struct {
	Reader          io.Reader
	Writer          io.Writer
	CloseRead       func() error
	CloseWrite      func() error
	Abort           func()
	SetReadDeadline func(time.Time) error
	// InputDone is closed when a producer with independent read-ahead observes
	// source EOF. It permits a policy transition while a final write is blocked.
	InputDone <-chan struct{}
	// Policy belongs to this endpoint; ingress and prepared peer policy are distinct.
	Policy     *policy.Timeout
	ReadAhead  *int32
	outputDone func()
	// NativeRead/NativeWrite admit a raw optimized transfer on this endpoint.
	// Codecs and shared carriers leave these false.
	NativeRead  bool
	NativeWrite bool
	Splice      bool // separately admitted by the endpoint's native IO policy
	CountRead   func(int64)
	CountWrite  func(int64)
}

func (s Stream) closeRead() {
	if s.CloseRead != nil {
		_ = s.CloseRead()
	}
}

func (s Stream) closeWrite() error {
	if s.CloseWrite != nil {
		return s.CloseWrite()
	}
	return nil
}

func (s Stream) abort() {
	if s.Abort != nil {
		s.Abort()
	}
}

// ProjectReader/ProjectWriter count logical bytes on temporary Link edges.
func (s Stream) ProjectReader() io.Reader {
	if s.CountRead == nil {
		return s.Reader
	}
	return &countedReader{Reader: s.Reader, count: s.CountRead}
}

func (s Stream) ProjectWriter() io.Writer {
	if s.CountWrite == nil {
		return s.Writer
	}
	return &countedWriter{Writer: s.Writer, count: s.CountWrite}
}

// Run joins both owned directions. Normal EOF waits for the accepted final
// write. Context cancellation or a transfer failure aborts both endpoints.
func Run(ctx context.Context, source, target Stream, idle, downlinkOnly, uplinkOnly time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, idle)
	defer timer.SetTimeout(0)
	setPolicy := timer.SetTimeout
	upDone := make(chan error, 1)
	downDone := make(chan error, 1)
	copyOne := func(dst io.Writer, src io.Reader, native, splice bool, countRead, countWrite func(int64)) error {
		err := transfer(dst, src, native, splice, timer.Update, countRead, countWrite)
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	go func() {
		err := copyOne(target.Writer, source.Reader, source.NativeRead && target.NativeWrite, false, source.CountRead, target.CountWrite)
		source.closeRead()
		if err == nil {
			err = target.closeWrite()
		}
		setPolicy(downlinkOnly)
		upDone <- err
	}()
	go func() {
		err := copyOne(source.Writer, target.Reader, target.NativeRead && source.NativeWrite, target.Splice, target.CountRead, source.CountWrite)
		target.closeRead()
		if err == nil {
			err = source.closeWrite()
		}
		setPolicy(uplinkOnly)
		if source.outputDone != nil {
			source.outputDone()
		}
		downDone <- err
	}()
	var upErr, downErr, firstErr error
	for upDone != nil || downDone != nil {
		select {
		case <-ctx.Done():
			source.abort()
			target.abort()
			if upDone != nil {
				upErr = <-upDone
				upDone = nil
			}
			if downDone != nil {
				downErr = <-downDone
				downDone = nil
			}
			if firstErr != nil {
				return firstErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		case err := <-upDone:
			upErr = err
			upDone = nil
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				cancel()
			}
		case err := <-downDone:
			downErr = err
			downDone = nil
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				cancel()
			}
		}
	}
	if upErr != nil {
		return upErr
	}
	return downErr
}

var transferBuffer = sync.Pool{New: func() any { return make([]byte, 16*1024) }}

type activityReader struct {
	io.Reader
	update func()
	count  func(int64)
}

func (r *activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.update()
		if r.count != nil {
			r.count(int64(n))
		}
	}
	return n, err
}

type countedWriter struct {
	io.Writer
	count func(int64)
}

type countedReader struct {
	io.Reader
	count func(int64)
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.count(int64(n))
	}
	return n, err
}

func (w *countedWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 && w.count != nil {
		w.count(int64(n))
	}
	return n, err
}
