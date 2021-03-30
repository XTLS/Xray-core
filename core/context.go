package core

import (
	"context"
)

// XrayKey is the key type of Instance in Context, exported for test.
type XrayKey int

// XrayKeyValue const is the key value of Instance in Context, exported for test.
const XrayKeyValue XrayKey = 1

// FromContext returns an Instance from the given context, or nil if the context doesn't contain one.
func FromContext(ctx context.Context) *Instance {
	if s, ok := ctx.Value(XrayKeyValue).(*Instance); ok {
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
