package exchange

import (
	"io"
	"time"
)

// TimedReader provides a bounded read without changing a physical socket's
// deadline. Logical children and independent read-ahead may implement it.
type TimedReader interface {
	ReadTimeout([]byte, time.Duration) (int, error)
}

// Input is the sole owner of bytes read for sniffing and protocol startup.
// It replays exactly what it inspected, including a data+error terminal read.
type Input struct {
	reader      io.Reader
	setDeadline func(time.Time) error
	cached      []byte
	pending     error
}

func NewInput(reader io.Reader, setDeadline func(time.Time) error) *Input {
	return &Input{reader: reader, setDeadline: setDeadline}
}

// NativeWriterTo reports an actual underlying optimized transfer rather than
// the replay wrapper's own WriteTo method.
func (in *Input) NativeWriterTo() bool {
	_, ok := in.reader.(io.WriterTo)
	return ok
}
func (in *Input) Peeked() []byte { return in.cached }

func (in *Input) Peek(maxBytes int, timeout time.Duration) ([]byte, error) {
	if len(in.cached) > 0 || in.pending != nil {
		return in.cached, in.pending
	}
	return in.PeekMore(maxBytes, timeout)
}

// PeekMore extends the retained prefix without advancing the transfer reader.
func (in *Input) PeekMore(maxBytes int, timeout time.Duration) ([]byte, error) {
	if in.pending != nil || len(in.cached) >= maxBytes {
		return in.cached, in.pending
	}
	if maxBytes <= 0 {
		return nil, nil
	}
	p := make([]byte, maxBytes-len(in.cached))
	n, err := in.readTimed(p, timeout)
	if n > 0 {
		in.cached = append(in.cached, p[:n]...)
		in.pending = err
	}
	return in.cached, err
}

func (in *Input) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(in.cached) > 0 {
		n := copy(p, in.cached)
		in.cached = in.cached[n:]
		if len(in.cached) == 0 && in.pending != nil {
			err := in.pending
			in.pending = nil
			return n, err
		}
		return n, nil
	}
	if in.pending != nil {
		err := in.pending
		in.pending = nil
		return 0, err
	}
	return in.reader.Read(p)
}

func (in *Input) ReadTimeout(p []byte, timeout time.Duration) (int, error) {
	if len(in.cached) > 0 || in.pending != nil {
		return in.Read(p)
	}
	return in.readTimed(p, timeout)
}

func (in *Input) readTimed(p []byte, timeout time.Duration) (int, error) {
	if timed, ok := in.reader.(TimedReader); ok {
		return timed.ReadTimeout(p, timeout)
	}
	if in.setDeadline == nil {
		return 0, nil
	}
	if err := in.setDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	defer in.setDeadline(time.Time{})
	return in.reader.Read(p)
}

// WriteTo preserves an underlying native WriterTo after the inspected prefix.
func (in *Input) WriteTo(dst io.Writer) (int64, error) {
	var total int64
	if len(in.cached) > 0 {
		n, err := writeAll(dst, in.cached)
		total += int64(n)
		in.cached = in.cached[n:]
		if err != nil {
			return total, err
		}
	}
	if in.pending != nil {
		err := in.pending
		in.pending = nil
		if err == io.EOF {
			return total, nil
		}
		return total, err
	}
	if wt, ok := in.reader.(io.WriterTo); ok {
		n, err := wt.WriteTo(dst)
		return total + n, err
	}
	n, err := io.Copy(dst, in.reader)
	return total + n, err
}

func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
