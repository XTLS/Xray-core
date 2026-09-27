//go:build ignore

package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
)

type nativeGuard struct {
	outbound.Handler
	native                      outbound.StreamHandler
	admitted, completed, legacy atomic.Int64
}

func (g *nativeGuard) Dispatch(context.Context, *transport.Link) {
	g.legacy.Add(1)
	panic("selected E1 stream entered legacy Dispatch")
}

func (g *nativeGuard) DispatchStream(ctx context.Context, s exchange.Stream) error {
	g.admitted.Add(1)
	defer g.completed.Add(1)
	return g.native.DispatchStream(ctx, s)
}

func init() {
	installNativeGuard = func(instance *core.Instance) {
		manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
		real := manager.GetHandler("egress")
		native, ok := real.(outbound.StreamHandler)
		if !ok {
			panic("real outbound has no stream admission")
		}
		guard := &nativeGuard{Handler: real, native: native}
		if err := manager.RemoveHandler(context.Background(), "egress"); err != nil {
			panic(err)
		}
		if err := manager.AddHandler(context.Background(), guard); err != nil {
			panic(err)
		}
		verifyNativeGuard = func() map[string]int64 {
			until := time.Now().Add(time.Second)
			for guard.completed.Load() != guard.admitted.Load() && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if guard.legacy.Load() != 0 || guard.completed.Load() != guard.admitted.Load() || guard.admitted.Load() == 0 {
				panic(fmt.Sprintf("native=%d completed=%d legacy=%d", guard.admitted.Load(), guard.completed.Load(), guard.legacy.Load()))
			}
			return map[string]int64{"admitted": guard.admitted.Load(), "handler_returned": guard.completed.Load(), "legacy": guard.legacy.Load()}
		}
	}
}
