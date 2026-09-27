package exchange

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/signal"
)

var ErrHandled = errors.New("local stream outcome completed")

// GuardPreparation applies the peer's idle policy while its startup write is
// still owned by preparation. Finish stops and joins the cancellation callback
// before a successful handoff; abandoning a blocked preparation is not allowed.
func GuardPreparation(parent context.Context, abort func(), idle time.Duration) func() error {
	ctx, cancel := context.WithCancel(parent)
	timer := signal.CancelAfterInactivity(ctx, cancel, idle)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); abort() })
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			if !stop() {
				<-done
			}
			result = ctx.Err()
			timer.SetTimeout(0)
			cancel()
		})
		return result
	}
}

// Discard consumes an already selected local outcome without repeating routing
// or preparation. Expiry interrupts the actual source, not a byte adapter.
func Discard(source Stream, delay time.Duration) error {
	done := make(chan struct{})
	timer := time.AfterFunc(delay, func() { defer close(done); source.abort() })
	_, _ = io.Copy(io.Discard, source.ProjectReader())
	if !timer.Stop() {
		<-done
	}
	return ErrHandled
}

// Admit owns ingress policy through routing, preparation and transfer. Producer
// EOF and completion of the peer's final write are separate policy events.
func Admit(parent context.Context, source Stream) (context.Context, Stream, func()) {
	ctx, cancel := context.WithCancel(parent)
	var timer *signal.ActivityTimer
	if source.Policy != nil {
		timer = signal.CancelAfterInactivity(ctx, cancel, source.Policy.ConnectionIdle)
	}
	var ahead *Ahead
	originalAbort := source.Abort
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			if ahead != nil {
				ahead.Stop()
			}
			if originalAbort != nil {
				originalAbort()
			}
		})
	}
	if source.ReadAhead != nil {
		reader := source.Reader
		if timer != nil {
			reader = &activityReader{Reader: reader, update: timer.Update}
		}
		ahead, _ = NewAhead(ctx, reader, *source.ReadAhead)
		source.Reader, source.InputDone = ahead, ahead.InputDone()
		source.NativeRead = false
	}
	source.Abort = abort
	aborted := make(chan struct{})
	stopAbort := context.AfterFunc(ctx, func() { defer close(aborted); abort() })
	watched := make(chan struct{})
	if timer != nil {
		p := *source.Policy
		inputDone := source.InputDone
		go func() {
			defer close(watched)
			select {
			case <-inputDone:
				timer.SetTimeout(p.DownlinkOnly)
			case <-ctx.Done():
			}
		}()
		previous := source.CountWrite
		source.CountWrite = func(n int64) {
			timer.Update()
			if previous != nil {
				previous(n)
			}
		}
		source.outputDone = func() { timer.SetTimeout(p.UplinkOnly) }
	} else {
		close(watched)
	}
	return ctx, source, func() {
		cancel()
		if !stopAbort() {
			<-aborted
		}
		abort()
		if ahead != nil {
			ahead.Join()
		}
		<-watched
		if timer != nil {
			timer.SetTimeout(0)
		}
	}
}
