package buf

import (
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
)

type dataHandler func(MultiBuffer)

type copyHandler struct {
	onData []dataHandler
}

// SizeCounter is for counting bytes copied by Copy().
type SizeCounter struct {
	Size int64
}

// CopyOption is an option for copying data.
type CopyOption func(*copyHandler)

// UpdateActivity is a CopyOption to update activity on each data copy operation.
func UpdateActivity(timer signal.ActivityUpdater) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(MultiBuffer) {
			timer.Update()
		})
	}
}

// CountSize is a CopyOption that sums the total size of data copied into the given SizeCounter.
func CountSize(sc *SizeCounter) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(b MultiBuffer) {
			sc.Size += int64(b.Len())
		})
	}
}

// AddToStatCounter a CopyOption add to stat counter
func AddToStatCounter(sc stats.Counter) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(b MultiBuffer) {
			if sc != nil {
				sc.Add(int64(b.Len()))
			}
		})
	}
}

type readError struct {
	error
}

func (e readError) Error() string {
	return e.error.Error()
}

func (e readError) Unwrap() error {
	return e.error
}

// IsReadError returns true if the error in Copy() comes from reading.
func IsReadError(err error) bool {
	_, ok := err.(readError)
	return ok
}

type writeError struct {
	error
}

func (e writeError) Error() string {
	return e.error.Error()
}

func (e writeError) Unwrap() error {
	return e.error
}

// IsWriteError returns true if the error in Copy() comes from writing.
func IsWriteError(err error) bool {
	_, ok := err.(writeError)
	return ok
}

func copyInternal(reader Reader, writer Writer, handler *copyHandler) error {
	for {
		buffer, err := reader.ReadMultiBuffer()
		if !buffer.IsEmpty() {
			for _, handler := range handler.onData {
				handler(buffer)
			}

			if werr := writer.WriteMultiBuffer(buffer); werr != nil {
				return writeError{werr}
			}
		}

		if err != nil {
			return readError{err}
		}
	}
}

// Copy dumps all payload from reader to writer or stops when an error occurs. It returns nil when EOF.
func Copy(reader Reader, writer Writer, options ...CopyOption) error {
	var handler copyHandler
	for _, option := range options {
		option(&handler)
	}
	var err error
	if sReader, ok := reader.(*SingleReader); ok && false {
		err = copyV(sReader, writer, &handler)
	} else {
		err = copyInternal(reader, writer, &handler)
	}
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

var ErrNotTimeoutReader = errors.New("not a TimeoutReader")

func CopyOnceTimeout(reader Reader, writer Writer, timeout time.Duration) error {
	timeoutReader, ok := reader.(TimeoutReader)
	if !ok {
		return ErrNotTimeoutReader
	}
	mb, err := timeoutReader.ReadMultiBufferTimeout(timeout)
	if err != nil {
		return err
	}
	return writer.WriteMultiBuffer(mb)
}

func copyV(r *SingleReader, w Writer, handler *copyHandler) error {
	// channel buffer size is maxBuffer/maxPerPacketLen (ignore the case of many small packets)
	// default buffer size:
	// 0 in ARM MIPS MIPSLE
	// 4kb in ARM64 MIPS64 MIPS64LE
	// 512kb in others
	channelBuffer := (policy.SessionDefault().Buffer.PerConnection) / Size
	if channelBuffer <= 0 {
		channelBuffer = 4
	}
	cache := make(chan *Buffer, channelBuffer)
	stopRead := make(chan struct{})
	var rErr error
	var wErr error
	wg := sync.WaitGroup{}
	wg.Add(2)
	// downlink
	go func() {
		defer wg.Done()
		defer close(cache)
		for {
			b, err := r.readBuffer()
			if err == nil {
				select {
				case cache <- b:
				// must be write error
				case <-stopRead:
					b.Release()
					return
				}
			} else {
				rErr = err
				select {
				case cache <- b:
				case <-stopRead:
					b.Release()
				}
				return
			}
		}
	}()
	// uplink
	go func() {
		defer wg.Done()
		for {
			b, ok := <-cache
			if !ok {
				return
			}
			var buffers = []*Buffer{b}
			for stop := false; !stop; {
				select {
				case b, ok := <-cache:
					if !ok {
						stop = true
						continue
					}
					buffers = append(buffers, b)
				default:
					stop = true
				}
			}
			mb := MultiBuffer(buffers)
			err := w.WriteMultiBuffer(mb)
			for _, handler := range handler.onData {
				handler(mb)
			}
			ReleaseMulti(mb)
			if err != nil {
				wErr = err
				close(stopRead)
				return
			}
		}
	}()
	wg.Wait()
	// drain cache
	for b := range cache {
		b.Release()
	}
	if wErr != nil {
		return writeError{wErr}
	}
	if rErr != nil {
		return readError{rErr}
	}
	return nil
}
