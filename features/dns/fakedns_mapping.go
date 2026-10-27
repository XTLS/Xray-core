package dns

import (
	"context"

	"github.com/xtls/xray-core/common/net"
)

// FakeDNSEngineContext is an optional mapping capability for engines that perform
// I/O. Callers should use it to preserve request cancellation and backend errors.
// The context-free engine interfaces remain supported for local implementations.
type FakeDNSEngineContext interface {
	Allocate(context.Context, string, bool, bool) ([]net.Address, error)
	ReverseLookup(context.Context, net.Address) (string, error)
}

// FakeDNSPoolProvider optionally exposes the initialized CIDRs of an engine.
// The returned slice is owned by the caller. It contains no mapping entries.
type FakeDNSPoolProvider interface {
	GetFakeIPRanges() []string
}
