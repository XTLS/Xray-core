package router

import (
	"context"
	"time"

	"github.com/xtls/xray-core/features/routing"
)

// Owned by one route selection, never by a matcher or a shared DNS job. Rules
// (including the second IpIfNonMatch pass) share one deadline instead of adding
// a full budget for each matcher. DNS context wrappers are rewrapped by Router.
type asyncDNSRouteWaitContext struct {
	routing.Context
	connection context.Context
	deadline   time.Time
}

func asyncDNSConnectionContext(ctx routing.Context) context.Context {
	if source, ok := ctx.(interface{ GetRouteContext() context.Context }); ok {
		if connection := source.GetRouteContext(); connection != nil {
			return connection
		}
	}
	return context.Background()
}

func (ctx *asyncDNSRouteWaitContext) GetRouteContext() context.Context { return ctx.connection }

func asyncDNSWaitDeadline(ctx routing.Context, now time.Time, budget time.Duration) (time.Time, context.Context) {
	connection := asyncDNSConnectionContext(ctx)
	deadline := now.Add(budget)
	if aggregate, ok := ctx.(*asyncDNSRouteWaitContext); ok {
		if aggregate.deadline.IsZero() {
			aggregate.deadline = deadline
		}
		deadline = minTime(deadline, aggregate.deadline)
	}
	if connectionDeadline, ok := connection.Deadline(); ok {
		deadline = minTime(deadline, connectionDeadline)
	}
	return deadline, connection
}
