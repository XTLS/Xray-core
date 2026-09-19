package errors_test

import (
	"context"
	"io"
	"sync"
	"testing"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
)

type recordingHandler struct {
	message *log.GeneralMessage
}

func (h *recordingHandler) Handle(msg log.Message) {
	h.message = msg.(*log.GeneralMessage)
}

type levelHandler struct {
	recordingHandler
	level log.Severity
}

func (h *levelHandler) Enabled(severity log.Severity) bool {
	return severity <= h.level
}

type countingContext struct {
	context.Context
	reads int
}

func (c *countingContext) Value(key interface{}) interface{} {
	c.reads++
	return c.Context.Value(key)
}

func TestLogFiltering(t *testing.T) {
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	for _, tc := range []struct {
		name     string
		level    log.Severity
		inner    error
		log      func(context.Context, error, ...interface{})
		severity log.Severity
		enabled  bool
	}{
		{"debug disabled", log.Severity_Warning, nil, errors.LogDebugInner, log.Severity_Debug, false},
		{"info disabled", log.Severity_Warning, nil, errors.LogInfoInner, log.Severity_Info, false},
		{"nested severity", log.Severity_Warning, errors.New("inner").AtDebug().Base(errors.New("cause").AtError()), errors.LogDebugInner, log.Severity_Error, true},
		{"plain error disabled", log.Severity_Info, io.EOF, errors.LogDebugInner, log.Severity_Debug, false},
		{"plain error enabled", log.Severity_Debug, io.EOF, errors.LogDebugInner, log.Severity_Debug, true},
		{"outer severity", log.Severity_Warning, errors.New("inner").AtDebug(), errors.LogWarningInner, log.Severity_Warning, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &levelHandler{level: tc.level}
			log.RegisterHandler(h)
			ctx := &countingContext{Context: c.ContextWithID(context.Background(), 123)}
			tc.log(ctx, tc.inner, "message")
			if !tc.enabled {
				if h.message != nil || ctx.reads != 0 {
					t.Fatal("disabled log was prepared or handled")
				}
				return
			}
			if h.message == nil || h.message.Severity != tc.severity {
				t.Fatalf("message = %v, want severity %v", h.message, tc.severity)
			}
			want := "[" + tc.severity.String() + "] [123] common/errors_test: message"
			if tc.inner != nil {
				want += " > " + tc.inner.Error()
			}
			if got := h.message.String(); got != want {
				t.Fatalf("message = %q, want %q", got, want)
			}
		})
	}
}

func TestLogHandlerReplacement(t *testing.T) {
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	log.RegisterHandler(&levelHandler{level: log.Severity_Error})
	errors.LogDebug(context.Background(), "disabled")
	var h recordingHandler // A handler without Enabled must still receive all levels.
	log.RegisterHandler(&h)
	errors.LogDebug(context.Background(), "enabled")
	if h.message == nil || h.message.String() != "[Debug] common/errors_test: enabled" {
		t.Fatalf("legacy handler received %v", h.message)
	}
}

func TestLogConcurrentHandlerReplacement(t *testing.T) {
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	log.RegisterHandler(&recordingHandler{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			errors.LogDebug(context.Background(), "message")
		}
	})
	for range 1000 {
		log.RegisterHandler(&levelHandler{level: log.Severity_Warning})
		log.RegisterHandler(&recordingHandler{})
	}
	wg.Wait()
}
