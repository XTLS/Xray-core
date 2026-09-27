package tun

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Stack interface implement ip protocol stack, bridging raw network packets and data streams
type Stack interface {
	Start() error
	Close() error
}

// StackOptions for the stack implementation
type StackOptions struct {
	Tun         Tun
	MTU         uint32
	IdleTimeout time.Duration
	// Backend selects the concrete Stack implementation, see NewStack.
	Backend string
}

const (
	// StackGVisor selects the full-featured gVisor based stack (default).
	StackGVisor = "gvisor"
	// StackSystem selects the lightweight, Xray-native stack, see newSystemStack.
	StackSystem = "system"
)

// NewStack builds the ip stack selected by options.Backend.
//
// gVisor (the default/"gvisor" backend) is a general purpose stack, built
// with the semantics needed for a real, lossy public network in mind:
// congestion control, SACK/RACK loss recovery, retransmission timers, etc.
// TUN traffic instead travels over a local, kernel-to-userspace channel that
// neither reorders nor drops packets in normal operation, so none of that
// complexity is actually required to shuffle bytes between it and the
// dispatcher. The "system" backend trades gVisor's generality for a much
// smaller, more direct code path tailored to that trusted, in-order channel:
// no congestion control, no SACK/RACK, minimal buffering, and a plain RTO
// timer as a safety net for the rare real loss, rather than a full
// re-implementation of one. See stack_system.go for details.
func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	switch options.Backend {
	case "", StackGVisor:
		return newGVisorStack(ctx, options, handler)
	case StackSystem:
		return newSystemStack(ctx, options, handler)
	default:
		return nil, errors.New("unknown tun stack: ", options.Backend)
	}
}
