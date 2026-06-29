package tun

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// Stack interface implement ip protocol stack, bridging raw network packets and data streams
type Stack interface {
	Start() error
	Close() error
}

// StackOptions for the stack implementation
type StackOptions struct {
	Tun         Tun
	IdleTimeout time.Duration
}

// StackHandler is the callback interface for the IP stack to notify the upper layer.
type StackHandler interface {
	HandleTCP(ctx context.Context, conn net.Conn, src, dst net.Destination) error
	HandleUDP(ctx context.Context, data []byte, src, dst net.Destination, writeBack func([]byte) error) error
}
