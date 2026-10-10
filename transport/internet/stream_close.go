package internet

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

var streamClosers = struct {
	sync.RWMutex
	byProtocol map[string]func(*MemoryStreamConfig) error
}{byProtocol: make(map[string]func(*MemoryStreamConfig) error)}

// RegisterTransportCloser registers the cleanup for a transport's per-config resources.
func RegisterTransportCloser(protocol string, closer func(*MemoryStreamConfig) error) error {
	streamClosers.Lock()
	defer streamClosers.Unlock()
	if closer == nil {
		return errors.New(protocol, " transport closer is nil")
	}
	if _, exists := streamClosers.byProtocol[protocol]; exists {
		return errors.New(protocol, " transport closer already registered")
	}
	streamClosers.byProtocol[protocol] = closer
	return nil
}

// IsClosed reports whether the owner has started releasing this configuration.
func (s *MemoryStreamConfig) IsClosed() bool {
	return s != nil && s.closed.Load()
}

// Close releases the transport state owned by this configuration exactly once.
// A closed configuration cannot be reused for dialing. Concurrent callers wait
// for cleanup to finish and receive the same error.
func (s *MemoryStreamConfig) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		streamClosers.RLock()
		closer := streamClosers.byProtocol[s.ProtocolName]
		streamClosers.RUnlock()
		if closer != nil {
			s.closeErr = closer(s)
		}
	})
	return s.closeErr
}
