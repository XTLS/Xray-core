package splithttp

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type muxDialerClient struct {
	*DefaultDialerClient
	leftUsage      int32
	expirationTime time.Time
}

type muxManager struct {
	sync.Mutex
	config        *Multiplexing
	dialerClients []muxDialerClient
}

func newMuxManager(config *Multiplexing) *muxManager {
	return &muxManager{
		config:        config,
		dialerClients: make([]muxDialerClient, 0),
	}
}

func (m *muxManager) getClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) *muxDialerClient {
	m.Lock()
	defer m.Unlock()
	if len(m.dialerClients) > 0 {
		m.removeExpiredConnections()
	}
	switch m.config.GetMode() {
	case Multiplexing_PREFER_EXTISTING:
		return m.dialPreferExisting(ctx, dest, streamSettings)
	case Multiplexing_PREFER_NEW:
		return m.dialPreferNew(ctx, dest, streamSettings)
	default:
		return &muxDialerClient{
			DefaultDialerClient: createHTTPClient(ctx, dest, streamSettings),
		}
	}
}

func (m *muxManager) dialPreferExisting(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) *muxDialerClient {
	for {
		for _, client := range m.dialerClients {
			if m.canReuseClient(client) {
				client.leftUsage--
				return &client
			}
		}
		if int32(len(m.dialerClients)) >= m.config.GetMaxConnections() || m.config.GetMaxConnections() == 0 {
			if streamSettings.ProtocolSettings.(*Config).GetNormalizedScMinPostsIntervalMs().From > 0 {
				time.Sleep(time.Duration(streamSettings.ProtocolSettings.(*Config).GetNormalizedScMinPostsIntervalMs().roll()) * time.Millisecond)
			}
			continue
		}
		break
	}
	return m.newClient(ctx, dest, streamSettings)
}

func (m *muxManager) dialPreferNew(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) *muxDialerClient {
	for {
		if int32(len(m.dialerClients)) < m.config.MaxConnections || m.config.MaxConnections == 0 {
			return m.newClient(ctx, dest, streamSettings)
		}

		for _, client := range m.dialerClients {
			if m.canReuseClient(client) {
				client.leftUsage--
				return &client
			}
		}
		if streamSettings.ProtocolSettings.(*Config).GetNormalizedScMinPostsIntervalMs().From > 0 {
			time.Sleep(time.Duration(streamSettings.ProtocolSettings.(*Config).GetNormalizedScMinPostsIntervalMs().roll()) * time.Millisecond)
		}
		continue
	}
}

func (m *muxManager) newClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) *muxDialerClient {
	m.Lock()
	defer m.Unlock()

	Client := muxDialerClient{
		DefaultDialerClient: createHTTPClient(ctx, dest, streamSettings),
		leftUsage:           m.config.GetNormalizedMaxConnectionConcurrency().roll(),
		expirationTime:      time.Now().Add(time.Duration(m.config.GetNormalizedConnectionLifetime().roll()) * time.Second),
	}
	m.dialerClients = append(m.dialerClients, Client)
	return &Client
}

func (m *muxManager) removeExpiredConnections() {
	m.Lock()
	defer m.Unlock()

	for i := 0; i < len(m.dialerClients); i++ {
		client := m.dialerClients[i]
		if time.Now().After(client.expirationTime) || client.leftUsage <= 0 {
			m.dialerClients = append(m.dialerClients[:i], m.dialerClients[i+1:]...)
			i--
		}
	}
}

func (m *muxManager) canReuseClient(c muxDialerClient) bool {
	return c.leftUsage > 0 && time.Now().Before(c.expirationTime)
}
