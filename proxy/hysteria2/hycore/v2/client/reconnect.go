package client

import (
	"net"
	"sync"

	coreErrs "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/errors"
)

// reconnectableClientImpl is a wrapper of Client, which can reconnect when the connection is closed,
// except when the caller explicitly calls Close() to permanently close this client.
type reconnectableClientImpl struct {
	configFunc    func() (*Config, error)           // called before connecting
	connectedFunc func(Client, *HandshakeInfo, int) // called when successfully connected
	client        Client
	count         int
	m             sync.Mutex
	closed        bool // permanent close
}

// NewReconnectableClient creates a reconnectable client.
// If lazy is true, the client will not connect until the first call to TCP() or UDP().
// We use a function for config mainly to delay config evaluation
// (which involves DNS resolution) until the actual connection attempt.
func NewReconnectableClient(configFunc func() (*Config, error), connectedFunc func(Client, *HandshakeInfo, int), lazy bool) (Client, error) {
	rc := &reconnectableClientImpl{
		configFunc:    configFunc,
		connectedFunc: connectedFunc,
	}
	if !lazy {
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

func (rc *reconnectableClientImpl) reconnect() error {
	if rc.client != nil {
		_ = rc.client.Close()
	}
	var info *HandshakeInfo
	config, err := rc.configFunc()
	if err != nil {
		return err
	}
	rc.client, info, err = NewClient(config)
	if err != nil {
		return err
	} else {
		rc.count++
		if rc.connectedFunc != nil {
			rc.connectedFunc(rc, info, rc.count)
		}
		return nil
	}
}

// clientDo calls f with the current client.
// If the client is nil, it will first reconnect.
// It will also detect if the client is closed, and if so,
// set it to nil for reconnect next time.
func (rc *reconnectableClientImpl) clientDo(f func(Client) (interface{}, error)) (interface{}, error) {
	rc.m.Lock()
	if rc.closed {
		rc.m.Unlock()
		return nil, coreErrs.ClosedError{}
	}
	if rc.client == nil {
		// No active connection, connect first
		if err := rc.reconnect(); err != nil {
			rc.m.Unlock()
			return nil, err
		}
	}
	client := rc.client
	rc.m.Unlock()

	ret, err := f(client)
	if _, ok := err.(coreErrs.ClosedError); ok {
		// Connection closed, set client to nil for reconnect next time
		rc.m.Lock()
		if rc.client == client {
			// This check is in case the client is already changed by another goroutine
			rc.client = nil
		}
		rc.m.Unlock()
	}
	return ret, err
}

func (rc *reconnectableClientImpl) TCP(addr string) (net.Conn, error) {
	if c, err := rc.clientDo(func(client Client) (interface{}, error) {
		return client.TCP(addr)
	}); err != nil {
		return nil, err
	} else {
		return c.(net.Conn), nil
	}
}

func (rc *reconnectableClientImpl) UDP() (HyUDPConn, error) {
	if c, err := rc.clientDo(func(client Client) (interface{}, error) {
		return client.UDP()
	}); err != nil {
		return nil, err
	} else {
		return c.(HyUDPConn), nil
	}
}

func (rc *reconnectableClientImpl) Close() error {
	rc.m.Lock()
	defer rc.m.Unlock()
	rc.closed = true
	if rc.client != nil {
		return rc.client.Close()
	}
	return nil
}
