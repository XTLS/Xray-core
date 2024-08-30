package splithttp

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/done"
)

type muxRoundTripper struct {
	inner          http.RoundTripper
	OpenRequests   atomic.Int32
	leftUsage      int32
	expirationTime time.Time
}

func (c *muxRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	c.OpenRequests.Add(1)
	done := done.New()

	go func() {
		select {
		case <-request.Context().Done():
		case <-done.Wait():
		}

		c.OpenRequests.Add(-1)
	}()

	response, err := c.inner.RoundTrip(request)
	if err != nil {
		done.Close()
	}

	response.Body = &bodyCloser{ReadCloser: response.Body, done: done}
	return response, err
}

type bodyCloser struct {
	io.ReadCloser
	done *done.Instance
}

func (b *bodyCloser) Close() error {
	b.done.Close()
	return b.ReadCloser.Close()
}

type muxManager struct {
	sync.Mutex
	newClientFn   func() http.RoundTripper
	config        Multiplexing
	concurrency   int32
	connections   int32
	dialerClients []*muxRoundTripper
}

func NewMuxManager(config Multiplexing, newClient func() http.RoundTripper) *muxManager {
	return &muxManager{
		config:        config,
		concurrency:   config.GetNormalizedConcurrency().roll(),
		connections:   config.GetNormalizedConnections().roll(),
		newClientFn:   newClient,
		dialerClients: make([]*muxRoundTripper, 0),
	}
}

func (m *muxManager) RoundTrip(request *http.Request) (*http.Response, error) {
	client := m.GetClient(request.Context())
	return client.RoundTrip(request)
}

func (m *muxManager) GetClient(ctx context.Context) *muxRoundTripper {
	m.Lock()
	defer m.Unlock()

	m.removeExpiredConnections(ctx)

	if m.connections > 0 && len(m.dialerClients) < int(m.connections) {
		errors.LogDebug(ctx, "httpMux: creating client, connections=", len(m.dialerClients))
		return m.newClient()
	}

	if len(m.dialerClients) == 0 {
		errors.LogDebug(ctx, "httpMux: creating client because dialerClients is empty, connections=", len(m.dialerClients))
		return m.newClient()
	}

	clients := make([]*muxRoundTripper, 0)
	if m.concurrency > 0 {
		for _, client := range m.dialerClients {
			openRequests := client.OpenRequests.Load()
			if openRequests < m.concurrency {
				clients = append(clients, client)
			}
		}
	} else {
		clients = m.dialerClients
	}

	if len(clients) == 0 {
		errors.LogDebug(ctx, "httpMux: creating client because concurrency was hit, total clients=", len(m.dialerClients))
		return m.newClient()
	}

	client := clients[rand.Intn(len(clients))]
	if client.leftUsage > 0 {
		client.leftUsage -= 1
	}
	return client
}

func (m *muxManager) newClient() *muxRoundTripper {
	leftUsage := int32(-1)
	if x := m.config.GetNormalizedRequestsPerConnection().roll(); x > 0 {
		leftUsage = x - 1
	}
	expirationTime := time.UnixMilli(0)
	if x := m.config.GetNormalizedConnectionLifetimeMs().roll(); x > 0 {
		expirationTime = time.Now().Add(time.Duration(x) * time.Millisecond)
	}

	client := &muxRoundTripper{
		inner:          m.newClientFn(),
		leftUsage:      leftUsage,
		expirationTime: expirationTime,
	}
	m.dialerClients = append(m.dialerClients, client)
	return client
}

func (m *muxManager) removeExpiredConnections(ctx context.Context) {
	for i := 0; i < len(m.dialerClients); i++ {
		client := m.dialerClients[i]
		if client.leftUsage == 0 || (client.expirationTime != time.UnixMilli(0) && time.Now().After(client.expirationTime)) {
			errors.LogDebug(ctx, "httpMux: removing client, leftUsage = ", client.leftUsage, ", expirationTime = ", client.expirationTime)
			m.dialerClients = append(m.dialerClients[:i], m.dialerClients[i+1:]...)
			i--
		}
	}
}
