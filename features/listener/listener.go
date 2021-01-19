package listener

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features"
)

type MultiListener interface {
	Recv(net.Conn)
	net.Listener
}

type ListenerManager interface {
	features.Feature

	GetListener(common.Identifer) MultiListener
	NewTLSListener(context.Context, net.Listener, *tls.Config) net.Listener
	NewListener(context.Context, net.Listener) net.Listener
}

func ManagerType() interface{} {
	return (*ListenerManager)(nil)
}

type IdentiferKey int

const listenerIdentiferKey IdentiferKey = iota

type DefaultListenerManager struct {
	listeners map[common.Identifer]MultiListener
	sync.Mutex
}

// Type implements common.HasType.
func (*DefaultListenerManager) Type() interface{} {
	return ManagerType()
}

func (m *DefaultListenerManager) GetListener(idf common.Identifer) MultiListener {
	m.Lock()
	defer m.Unlock()
	if l, found := m.listeners[idf]; found {
		return l
	}
	return nil
}

func (m *DefaultListenerManager) NewTLSListener(ctx context.Context, l net.Listener, tc *tls.Config) net.Listener {
	return m.NewListener(ctx, tls.NewListener(l, tc))
}

func (m *DefaultListenerManager) NewListener(ctx context.Context, l net.Listener) net.Listener {
	idf := ListenerIdentiferFromContext(ctx)
	if idf != "" {
		m.Lock()
		defer m.Unlock()
		if _, found := m.listeners[idf]; found {
			return l
		}

		l := &multiListener{
			Listener:  l,
			net:       make(chan netRecv, 10),
			ext:       make(chan net.Conn),
			identifer: idf,
		}
		go l.loop()
		m.listeners[idf] = l
		return l
	}
	return l
}

// Start implements common.Runnable.
func (*DefaultListenerManager) Start() error { return nil }

// Close implements common.Closable.
func (m *DefaultListenerManager) Close() (err error) {
	for _, listener := range m.listeners {
		err = listener.Close()
	}
	return
}

// ContextWithListenerIdentifer returns a new context with listener identifer
func ContextWithListenerIdentifer(ctx context.Context, i common.Identifer) context.Context {
	return context.WithValue(ctx, listenerIdentiferKey, i)
}

// ListenerIdentiferFromContext returns listener identifer in this context, or "" if not contained.
func ListenerIdentiferFromContext(ctx context.Context) common.Identifer {
	if key, ok := ctx.Value(listenerIdentiferKey).(common.Identifer); ok {
		return key
	}
	return ""
}

func NewListenerManager() ListenerManager {
	m := new(DefaultListenerManager)
	m.listeners = make(map[common.Identifer]MultiListener)
	return m
}
