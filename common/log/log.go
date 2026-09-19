package log // import "github.com/xtls/xray-core/common/log"

import (
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/serial"
)

// Message is the interface for all log messages.
type Message interface {
	String() string
}

// Handler is the interface for log handler.
type Handler interface {
	Handle(msg Message)
}

// GeneralMessage is a general log message that can contain all kind of content.
type GeneralMessage struct {
	Severity Severity
	Content  interface{}
}

// String implements Message.
func (m *GeneralMessage) String() string {
	return serial.Concat("[", m.Severity, "] ", m.Content)
}

// Record writes a message into log stream.
func Record(msg Message) {
	logHandler.Handle(msg)
}

// Enabled reports whether the current handler accepts general messages at severity.
// Handlers may implement Enabled(Severity) bool to allow early filtering.
// Handlers without it are always enabled.
func Enabled(severity Severity) bool {
	if handler := handlerSnapshot.Load(); handler != nil {
		if h, ok := (*handler).(interface{ Enabled(Severity) bool }); ok {
			return h.Enabled(severity)
		}
	}
	return true
}

var (
	logHandler      syncHandler
	handlerSnapshot atomic.Pointer[Handler]
)

// RegisterHandler registers a new handler as current log handler. Previous registered handler will be discarded.
func RegisterHandler(handler Handler) {
	if handler == nil {
		panic("Log handler is nil")
	}
	logHandler.Lock()
	defer logHandler.Unlock()

	logHandler.Handler = handler
	handlerSnapshot.Store(&handler)
}

type syncHandler struct {
	sync.RWMutex
	Handler
}

func (h *syncHandler) Handle(msg Message) {
	h.RLock()
	defer h.RUnlock()

	if h.Handler != nil {
		h.Handler.Handle(msg)
	}
}
