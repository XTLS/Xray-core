package realm

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/libp2p/go-nat"
)

const (
	defaultPortMapTimeout  = 10 * time.Second
	defaultPortMapLifetime = 10 * time.Minute

	portMapDescription = "hysteria-realm"
	portMapProtocol    = "udp"
)

var ErrInvalidPortMapConfig = errors.New("invalid port mapping config")

type PortMapConfig struct {
	Timeout  time.Duration
	Lifetime time.Duration
}

func (c PortMapConfig) withDefaults() (PortMapConfig, error) {
	if c.Timeout == 0 {
		c.Timeout = defaultPortMapTimeout
	}
	if c.Timeout < 0 {
		return c, fmt.Errorf("%w: timeout must not be negative", ErrInvalidPortMapConfig)
	}
	if c.Lifetime == 0 {
		c.Lifetime = defaultPortMapLifetime
	}
	if c.Lifetime < 0 {
		return c, fmt.Errorf("%w: lifetime must not be negative", ErrInvalidPortMapConfig)
	}
	return c, nil
}

// PortMapper maintains a UDP port mapping on the local gateway via UPnP or
// NAT-PMP. It does not renew the mapping by itself; the caller is expected
// to call Renew periodically (typically every Lifetime/2).
type PortMapper struct {
	gateway      nat.NAT
	internalPort int
	config       PortMapConfig

	mu           sync.Mutex
	externalAddr netip.AddrPort
}

// NewPortMapper discovers the local gateway and maps internalPort for UDP.
// It blocks for up to 2x config.Timeout (discovery + mapping).
func NewPortMapper(ctx context.Context, internalPort int, config PortMapConfig) (*PortMapper, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return nil, fmt.Errorf("%w: invalid internal port %d", ErrInvalidPortMapConfig, internalPort)
	}
	config, err := config.withDefaults()
	if err != nil {
		return nil, err
	}

	discoverCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	gateway, err := nat.DiscoverGateway(discoverCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("gateway discovery failed: %w", err)
	}

	m := &PortMapper{
		gateway:      gateway,
		internalPort: internalPort,
		config:       config,
	}
	if _, err := m.Renew(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// Renew (re-)requests the port mapping and refreshes the external address.
// It reports whether the external address changed since the last call.
func (m *PortMapper) Renew(ctx context.Context) (bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()
	externalPort, err := m.gateway.AddPortMapping(opCtx, portMapProtocol, m.internalPort, portMapDescription, m.config.Lifetime)
	if err != nil {
		return false, fmt.Errorf("add port mapping failed: %w", err)
	}
	externalIP, err := m.gateway.GetExternalAddress()
	if err != nil {
		return false, fmt.Errorf("get external address failed: %w", err)
	}
	addr, ok := netip.AddrFromSlice(externalIP)
	if !ok || addr.IsUnspecified() || addr.IsLoopback() {
		return false, fmt.Errorf("gateway returned unusable external address: %s", externalIP)
	}
	externalAddr := netip.AddrPortFrom(addr.Unmap(), uint16(externalPort))

	m.mu.Lock()
	changed := externalAddr != m.externalAddr
	m.externalAddr = externalAddr
	m.mu.Unlock()
	return changed, nil
}

// ExternalAddr returns the gateway's external IP and the mapped external port.
func (m *PortMapper) ExternalAddr() netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.externalAddr
}

// InternalPort returns the mapped local UDP port.
func (m *PortMapper) InternalPort() int {
	return m.internalPort
}

// Lifetime returns the effective mapping lease duration.
func (m *PortMapper) Lifetime() time.Duration {
	return m.config.Lifetime
}

// GatewayType returns the protocol used to talk to the gateway ("UPnP" or "NAT-PMP").
func (m *PortMapper) GatewayType() string {
	return m.gateway.Type()
}

// Close removes the port mapping from the gateway. Best-effort.
func (m *PortMapper) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()
	return m.gateway.DeletePortMapping(ctx, portMapProtocol, m.internalPort)
}
