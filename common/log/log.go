package log // import "github.com/xtls/xray-core/common/log"

import (
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
	if h := logHandler.Load(); h != nil {
		(*h).Handle(msg)
	}
}

type SeverityLogger interface {
	Handler
	Severity() Severity
}

// Enabled reports whether messages of the severity are logged. Hot paths check it before a log
// call: its arguments are boxed even when the message is dropped.
func Enabled(severity Severity) bool {
	if h := logHandler.Load(); h != nil {
		if sh, ok := (*h).(SeverityLogger); ok {
			return sh.Severity() >= severity
		}
	}
	// log everything by default
	return true
}

var logHandler atomic.Pointer[Handler]

// RegisterHandler registers a new handler as current log handler. Previous registered handler will be discarded.
func RegisterHandler(handler Handler) {
	if handler == nil {
		panic("Log handler is nil")
	}
	logHandler.Store(&handler)
}
