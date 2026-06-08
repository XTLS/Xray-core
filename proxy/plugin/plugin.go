package plugin

import (
	"context"
	"sync"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

type OutboundHandlerFunc func(ctx context.Context, dest v2net.Destination, link *transport.Link) error

type OnPluginRegisteredFunc func(tag string, name string, params string)

var (
	handlersMu sync.RWMutex
	handlers   = make(map[string]OutboundHandlerFunc)

	onPluginRegisteredMu sync.Mutex
	onPluginRegistered   OnPluginRegisteredFunc
)

func RegisterHandler(name string, handler OutboundHandlerFunc) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	handlers[name] = handler
}

func GetHandler(name string) OutboundHandlerFunc {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	return handlers[name]
}

func SetOnPluginRegistered(cb OnPluginRegisteredFunc) {
	onPluginRegisteredMu.Lock()
	defer onPluginRegisteredMu.Unlock()
	onPluginRegistered = cb
}

func TriggerOnPluginRegistered(tag string, name string, params string) {
	onPluginRegisteredMu.Lock()
	cb := onPluginRegistered
	onPluginRegisteredMu.Unlock()
	if cb != nil {
		cb(tag, name, params)
	}
}
