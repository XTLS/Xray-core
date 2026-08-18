package splithttp

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	Running      atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
	NotUsed      atomic.Bool
}

func (c *XmuxClient) AddRunning() {
	c.Running.Add(1)
}

func (c *XmuxClient) DoneRunning() {
	c.Running.Add(-1)
	c.maybeClose()
}

// close the XmuxConn if it is not used and has no running requests
func (c *XmuxClient) maybeClose() {
	if c.NotUsed.Load() && c.Running.Load() <= 0 {
		common.Close(c.XmuxConn)
	}
}

type XmuxManager struct {
	xmuxConfig  XmuxConfig
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	draining    *XmuxClient
}

func NewXmuxManager(xmuxConfig XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
	}
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient { // when locking
	// Planned fixed-pool rotation is make-before-break, but only one old
	// carrier drains at a time. This bounds a maxConnections=N pool to N+1
	// physical carriers during graceful rotation instead of letting multiple
	// generations accumulate when long-lived flows pin old carriers.
	if m.connections > 0 && m.draining != nil && (m.draining.Running.Load() <= 0 || m.draining.XmuxConn.IsClosed()) {
		m.draining.NotUsed.Store(true)
		m.draining.maybeClose()
		m.draining = nil
	}

	now := time.Now()
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		closed := xmuxClient.XmuxConn.IsClosed()
		exhausted := xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && now.After(xmuxClient.UnreusableAt))

		if closed {
			errors.LogDebug(ctx, "XMUX: removing closed xmuxClient, Running = ", xmuxClient.Running.Load())
			xmuxClient.NotUsed.Store(true)
			xmuxClient.maybeClose()
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
			continue
		}

		if exhausted {
			if m.connections > 0 && xmuxClient.Running.Load() > 0 {
				if m.draining == nil {
					errors.LogDebug(ctx, "XMUX: serial-draining xmuxClient, Running = ", xmuxClient.Running.Load(),
						", leftUsage = ", xmuxClient.leftUsage,
						", LeftRequests = ", xmuxClient.LeftRequests.Load(),
						", UnreusableAt = ", xmuxClient.UnreusableAt)
					xmuxClient.NotUsed.Store(true)
					xmuxClient.maybeClose()
					m.draining = xmuxClient
					m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
					continue
				}

				// Another carrier is already draining. Keep this expired carrier
				// active temporarily; it will become the next rotation candidate.
				i++
				continue
			}

			errors.LogDebug(ctx, "XMUX: removing exhausted xmuxClient, Running = ", xmuxClient.Running.Load(),
				", leftUsage = ", xmuxClient.leftUsage,
				", LeftRequests = ", xmuxClient.LeftRequests.Load(),
				", UnreusableAt = ", xmuxClient.UnreusableAt)
			xmuxClient.NotUsed.Store(true)
			xmuxClient.maybeClose()
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
			continue
		}
		i++
	}

	if len(m.xmuxClients) == 0 {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because xmuxClients is empty")
		return m.newXmuxClient()
	}

	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because fixed pool has a free active slot, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClient()
	}

	xmuxClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.Running.Load() < m.concurrency {
				xmuxClients = append(xmuxClients, xmuxClient)
			}
		}
	} else if m.connections > 0 {
		// Keep new proxy flows spread across the least-loaded active carriers.
		// Each flow remains pinned to the chosen XmuxClient for its lifetime.
		minRunning := int32(math.MaxInt32)
		for _, xmuxClient := range m.xmuxClients {
			running := xmuxClient.Running.Load()
			if running < minRunning {
				minRunning = running
				xmuxClients = xmuxClients[:0]
			}
			if running == minRunning {
				xmuxClients = append(xmuxClients, xmuxClient)
			}
		}
	} else {
		xmuxClients = m.xmuxClients
	}

	if len(xmuxClients) == 0 {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because maxConcurrency was hit, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClient()
	}

	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(xmuxClients))))
	xmuxClient := xmuxClients[i.Int64()]
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	return xmuxClient
}
