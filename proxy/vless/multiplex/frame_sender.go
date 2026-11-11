package multiplex

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// frameSender owns physical writes for one carrier. A zero native pipe limit
// permits one queued nonempty encoder batch, preserving the two-frame write bound.
type frameSender struct {
	writer       buf.Writer
	reader       *pipe.Reader
	queue        *pipe.Writer
	closeCarrier func()

	admission  sync.Mutex
	submitted  uint64
	completion sync.Mutex
	progress   sync.Cond
	written    uint64
	closed     bool
}

func newFrameSender(writer buf.Writer, closeCarrier func()) *frameSender {
	reader, queue := pipe.New(pipe.WithSizeLimit(0))
	s := &frameSender{writer: writer, reader: reader, queue: queue, closeCarrier: closeCarrier}
	s.progress.L = &s.completion
	go s.run()
	return s
}

// submit takes queue custody, not physical completion. Admission is never needed
// by the drainer or cancellation, including while this call waits for capacity.
func (s *frameSender) submit(mb buf.MultiBuffer) (uint64, error) {
	s.admission.Lock()
	defer s.admission.Unlock()
	size := uint64(mb.Len())
	err := s.queue.WriteMultiBuffer(mb)
	if err == nil {
		s.submitted += size
	}
	return s.submitted, err
}

func (s *frameSender) WriteMultiBuffer(mb buf.MultiBuffer) error {
	_, err := s.submit(mb)
	return err
}

// writeEnd preserves the former physical Close boundary. A peer can observe END
// before this returns; its closed ingress identity remains replaceable meanwhile.
func (s *frameSender) writeEnd(mb buf.MultiBuffer) error {
	ticket, err := s.submit(mb)
	if err != nil {
		return err
	}
	s.completion.Lock()
	defer s.completion.Unlock()
	for s.written < ticket && !s.closed {
		s.progress.Wait()
	}
	if s.written < ticket {
		return io.ErrClosedPipe
	}
	return nil
}

func (s *frameSender) Interrupt() {
	s.completion.Lock()
	if s.closed {
		s.completion.Unlock()
		return
	}
	s.closed = true
	s.progress.Broadcast()
	s.completion.Unlock()
	s.reader.Interrupt()
	common.Interrupt(s.writer)
}

func (s *frameSender) run() {
	defer s.closeCarrier()
	defer s.Interrupt()
	for {
		mb, err := s.reader.ReadMultiBuffer()
		if !mb.IsEmpty() {
			size := uint64(mb.Len())
			if writeErr := s.writer.WriteMultiBuffer(mb); writeErr != nil {
				return
			}
			s.completion.Lock()
			s.written += size
			s.progress.Broadcast()
			s.completion.Unlock()
		}
		if err != nil {
			return
		}
	}
}
