package task

import "context"

// Adapt wraps a legacy task so it can run under RunContext.
// Cancellation is observed only after the task returns unless it checks ctx itself.
func Adapt(f func() error) func(context.Context) error {
	return func(context.Context) error {
		return f()
	}
}
