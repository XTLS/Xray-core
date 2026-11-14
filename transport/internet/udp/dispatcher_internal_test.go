package udp

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// Gate the read so cancellation happens after handleInput's context check.
type gatedInput struct {
	*pipe.Reader
	started chan struct{}
	release chan struct{}
	err     error
}

func (r *gatedInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.started)
	<-r.release
	if r.err != nil {
		return nil, r.err
	}
	return r.Reader.ReadMultiBuffer()
}

type inputLog struct {
	sync.Mutex
	messages []*log.GeneralMessage
}

func (l *inputLog) Handle(m log.Message) {
	l.Lock()
	defer l.Unlock()
	if m, ok := m.(*log.GeneralMessage); ok {
		l.messages = append(l.messages, m)
	}
}

func TestHandleInputTermination(t *testing.T) {
	logger := new(inputLog)
	log.RegisterHandler(logger)
	// This package does not run logging tests in parallel.
	t.Cleanup(func() { log.RegisterHandler(new(inputLog)) })
	for _, tc := range []struct {
		name        string
		localClose  bool
		idleTimeout bool
		cancelOnly  bool
		err         error
		wantInfo    bool
		wantDebug   bool
	}{
		{name: "local close interrupts pipe", localClose: true, wantDebug: true},
		{name: "idle timeout interrupts pipe", idleTimeout: true, wantDebug: true},
		{name: "wrapped local pipe error", localClose: true, err: fmt.Errorf("read: %w", io.ErrClosedPipe), wantDebug: true},
		{name: "remote pipe interruption", err: io.ErrClosedPipe, wantInfo: true},
		{name: "parent cancellation alone", cancelOnly: true, err: io.ErrClosedPipe, wantInfo: true},
		{name: "error during local close", localClose: true, err: io.ErrUnexpectedEOF, wantInfo: true},
		{name: "error during parent cancellation", cancelOnly: true, err: io.ErrUnexpectedEOF, wantInfo: true},
		{name: "normal EOF", err: io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger.Lock()
			logger.messages = nil
			logger.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader, writer := pipe.New()
			input := &gatedInput{Reader: reader, started: make(chan struct{}), release: make(chan struct{}), err: tc.err}
			entry := &connEntry{link: &transport.Link{Reader: input, Writer: writer}, cancel: cancel}
			entry.timer = signal.CancelAfterInactivity(ctx, entry.terminate, time.Hour)
			done := make(chan struct{})
			closeCount := 0
			go func() {
				defer close(done)
				handleInput(ctx, entry, net.Destination{}, nil, func() error { closeCount++; return nil })
			}()
			select {
			case <-input.started:
			case <-time.After(5 * time.Second):
				t.Fatal("read did not start")
			}
			if tc.localClose {
				var closing sync.WaitGroup
				closing.Add(2)
				for range 2 {
					go func() { defer closing.Done(); entry.Close() }()
				}
				closing.Wait()
			}
			if tc.idleTimeout {
				entry.timer.SetTimeout(time.Millisecond)
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("idle timer did not cancel the session")
				}
			}
			if tc.cancelOnly {
				cancel()
			}
			close(input.release)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("input handler did not terminate")
			}
			if closeCount != 1 {
				t.Fatalf("close callback count = %d, want 1", closeCount)
			}
			logger.Lock()
			defer logger.Unlock()
			var gotInfo, gotDebug bool
			for _, m := range logger.messages {
				if strings.Contains(m.String(), "failed to handle UDP input") && m.Severity <= log.Severity_Info {
					gotInfo = true
				}
				if m.Severity == log.Severity_Debug {
					gotDebug = true
				}
			}
			if gotInfo != tc.wantInfo || gotDebug != tc.wantDebug {
				t.Fatalf("info failure = %v, debug = %v; want %v, %v; logs: %v", gotInfo, gotDebug, tc.wantInfo, tc.wantDebug, logger.messages)
			}
		})
	}
}
