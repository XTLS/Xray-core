package ctx

import (
	"context"
)

type key int

const (
	requireDatagram key = iota
)

func ContextWithRequireDatagram(ctx context.Context, udp bool) context.Context {
	if !udp {
		return ctx
	}
	return context.WithValue(ctx, requireDatagram, struct{}{})
}

func RequireDatagramFromContext(ctx context.Context) bool {
	_, ok := ctx.Value(requireDatagram).(struct{})
	return ok
}
