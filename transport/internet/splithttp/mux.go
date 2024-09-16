package splithttp

import (
	"context"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

type muxResource struct {
	Resource       interface{}
	OpenRequests   atomic.Int32
	leftUsage      int32
	expirationTime time.Time
}

type muxManager struct {
	newResourceFn func() interface{}
	config        Multiplexing
	concurrency   int32
	connections   int32
	instances     []*muxResource
}

func NewMuxManager(config Multiplexing, newResource func() interface{}) *muxManager {
	return &muxManager{
		config:        config,
		concurrency:   config.GetNormalizedMaxConcurrency().roll(),
		connections:   config.GetNormalizedMaxConnections().roll(),
		newResourceFn: newResource,
		instances:     make([]*muxResource, 0),
	}
}

func (m *muxManager) GetResource(ctx context.Context) *muxResource {
	m.removeExpiredConnections(ctx)

	if m.connections > 0 && len(m.instances) < int(m.connections) {
		errors.LogDebug(ctx, "xmux: creating client, connections=", len(m.instances))
		return m.newResource()
	}

	if len(m.instances) == 0 {
		errors.LogDebug(ctx, "xmux: creating client because instances is empty, connections=", len(m.instances))
		return m.newResource()
	}

	clients := make([]*muxResource, 0)
	if m.concurrency > 0 {
		for _, client := range m.instances {
			openRequests := client.OpenRequests.Load()
			if openRequests < m.concurrency {
				clients = append(clients, client)
			}
		}
	} else {
		clients = m.instances
	}

	if len(clients) == 0 {
		errors.LogDebug(ctx, "xmux: creating client because concurrency was hit, total clients=", len(m.instances))
		return m.newResource()
	}

	client := clients[rand.Intn(len(clients))]
	if client.leftUsage > 0 {
		client.leftUsage -= 1
	}
	return client
}

func (m *muxManager) newResource() *muxResource {
	leftUsage := int32(-1)
	if x := m.config.GetNormalizedCMaxReuseTimes().roll(); x > 0 {
		leftUsage = x - 1
	}
	expirationTime := time.UnixMilli(0)
	if x := m.config.GetNormalizedCMaxLifetimeMs().roll(); x > 0 {
		expirationTime = time.Now().Add(time.Duration(x) * time.Millisecond)
	}

	client := &muxResource{
		Resource:       m.newResourceFn(),
		leftUsage:      leftUsage,
		expirationTime: expirationTime,
	}
	m.instances = append(m.instances, client)
	return client
}

func (m *muxManager) removeExpiredConnections(ctx context.Context) {
	for i := 0; i < len(m.instances); i++ {
		client := m.instances[i]
		if client.leftUsage == 0 || (client.expirationTime != time.UnixMilli(0) && time.Now().After(client.expirationTime)) {
			errors.LogDebug(ctx, "xmux: removing client, leftUsage = ", client.leftUsage, ", expirationTime = ", client.expirationTime)
			m.instances = append(m.instances[:i], m.instances[i+1:]...)
			i--
		}
	}
}
