package core

import (
	"context"
)

// xrayKeyType is the key type of Instance in Context.
type xrayKeyType int

const xrayKey xrayKeyType = 1

// FromContext returns an Instance from the given context, or nil if the context doesn't contain one.
func FromContext(ctx context.Context) *Instance {
	if s, ok := ctx.Value(xrayKey).(*Instance); ok {
		return s
	}
	return nil
}

// MustFromContext returns an Instance from the given context, or panics if not present.
func MustFromContext(ctx context.Context) *Instance {
	x := FromContext(ctx)
	if x == nil {
		panic("X is not in context.")
	}
	return x
}

// ToContext returns ctx from the given context, or creates an Instance if the context doesn't find that.
func ToContext(ctx context.Context, v *Instance) context.Context {
	if FromContext(ctx) != v {
		ctx = context.WithValue(ctx, xrayKey, v)
	}
	return ctx
}
