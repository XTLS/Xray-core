package retry // import "github.com/xtls/xray-core/common/retry"

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var ErrRetryFailed = errors.New("all retry attempts failed")

// Strategy is a way to retry on a specific function.
type Strategy interface {
	// On performs a retry on a specific function, until it doesn't return any error.
	On(func() error) error
}

type retryer struct {
	ctx          context.Context
	totalAttempt int
	nextDelay    func() uint32
}

// On implements Strategy.On.
func (r *retryer) On(method func() error) error {
	attempt := 0
	accumulatedError := make([]error, 0, r.totalAttempt)
	for attempt < r.totalAttempt {
		if r.ctx != nil && r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		err := method()
		if err == nil {
			return nil
		}
		numErrors := len(accumulatedError)
		if numErrors == 0 || err.Error() != accumulatedError[numErrors-1].Error() {
			accumulatedError = append(accumulatedError, err)
		}
		delay := time.Duration(r.nextDelay()) * time.Millisecond
		if err := wait(r.ctx, delay); err != nil {
			return err
		}
		attempt++
	}
	return errors.New(accumulatedError).Base(ErrRetryFailed)
}

func wait(ctx context.Context, delay time.Duration) error {
	if ctx == nil {
		time.Sleep(delay)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay == 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// Timed returns a retry strategy with fixed interval.
func Timed(attempts int, delay uint32) Strategy {
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			return delay
		},
	}
}

func ExponentialBackoff(attempts int, delay uint32) Strategy {
	return ExponentialBackoffContext(nil, attempts, delay)
}

// ExponentialBackoffContext stops waiting and admitting attempts when ctx is canceled.
func ExponentialBackoffContext(ctx context.Context, attempts int, delay uint32) Strategy {
	nextDelay := uint32(0)
	return &retryer{
		ctx:          ctx,
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			r := nextDelay
			nextDelay += delay
			return r
		},
	}
}
