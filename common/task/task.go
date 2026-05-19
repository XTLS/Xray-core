package task

import (
	"context"

	"github.com/xtls/xray-core/common/signal/semaphore"
)

// OnSuccess executes g() after f() returns nil.
func OnSuccess(f func(context.Context) error, g func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := f(ctx); err != nil {
			return err
		}
		return g(ctx)
	}
}

// CloseCtx returns a task that closes v.
func CloseCtx(v interface{}) func(context.Context) error {
	return func(context.Context) error {
		return Close(v)()
	}
}

// RunContext executes tasks in parallel with a cancellable context.
// The first error is returned; cancel is invoked so sibling tasks observe ctx.Done().
func RunContext(ctx context.Context, tasks ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := len(tasks)
	s := semaphore.New(n)
	done := make(chan error, 1)

	for _, task := range tasks {
		<-s.Wait()
		go func(f func(context.Context) error) {
			err := f(ctx)
			if err == nil {
				s.Signal()
				return
			}
			select {
			case done <- err:
			default:
			}
			cancel()
		}(task)
	}

	for i := 0; i < n; i++ {
		select {
		case err := <-done:
			return err
		default:
		}
		select {
		case err := <-done:
			return err
		case <-s.Wait():
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// Run executes a list of tasks in parallel, returns the first error encountered or nil if all tasks pass.
func Run(ctx context.Context, tasks ...func() error) error {
	wrapped := make([]func(context.Context) error, len(tasks))
	for i, task := range tasks {
		f := task
		wrapped[i] = func(context.Context) error { return f() }
	}
	return RunContext(ctx, wrapped...)
}
