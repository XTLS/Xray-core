package splithttp

import (
	"context"
	"crypto/rand"
	stderrors "errors"
	"math"
	"math/big"
	"sync"
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
	closeOnce    sync.Once
	closeErr     error
	onClose      func()
	owner        *XmuxManager
}

func (c *XmuxClient) AddRunning() {
	c.Running.Add(1)
}

func (c *XmuxClient) TryAddRunning() bool {
	c.owner.access.Lock()
	defer c.owner.access.Unlock()
	if c.owner.closed || c.NotUsed.Load() || c.XmuxConn.IsClosed() {
		return false
	}
	c.Running.Add(1)
	return true
}

func (c *XmuxClient) DoneRunning() {
	c.Running.Add(-1)
	c.maybeClose()
}

// close the XmuxConn if it is not used and has no running requests
func (c *XmuxClient) maybeClose() {
	if c.NotUsed.Load() && c.Running.Load() <= 0 {
		c.close()
	}
}

func (c *XmuxClient) close() error {
	c.closeOnce.Do(func() {
		c.closeErr = common.Close(c.XmuxConn)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}

type XmuxManager struct {
	xmuxConfig  XmuxConfig
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	access      sync.Mutex
	allClients  map[*XmuxClient]struct{}
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

func NewXmuxManager(xmuxConfig XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
		allClients:  make(map[*XmuxClient]struct{}),
	}
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
		owner:     m,
	}
	xmuxClient.onClose = func() {
		m.access.Lock()
		delete(m.allClients, xmuxClient)
		m.access.Unlock()
	}
	m.allClients[xmuxClient] = struct{}{}
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

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	return m.getXmuxClient(ctx, false)
}

func (m *XmuxManager) GetXmuxClientForRequest(ctx context.Context) *XmuxClient {
	return m.getXmuxClient(ctx, true)
}

func (m *XmuxManager) getXmuxClient(ctx context.Context, reserve bool) (selected *XmuxClient) {
	m.access.Lock()
	var retired []*XmuxClient
	defer func() {
		if reserve && selected != nil {
			selected.AddRunning()
		}
		m.access.Unlock()
		for _, client := range retired {
			client.maybeClose()
		}
	}()
	if m.closed {
		return nil
	}
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			errors.LogDebug(ctx, "XMUX: removing xmuxClient, IsClosed() = ", xmuxClient.XmuxConn.IsClosed(),
				", Running = ", xmuxClient.Running.Load(),
				", leftUsage = ", xmuxClient.leftUsage,
				", LeftRequests = ", xmuxClient.LeftRequests.Load(),
				", UnreusableAt = ", xmuxClient.UnreusableAt)
			xmuxClient.NotUsed.Store(true)
			retired = append(retired, xmuxClient)
			copy(m.xmuxClients[i:], m.xmuxClients[i+1:])
			m.xmuxClients[len(m.xmuxClients)-1] = nil
			m.xmuxClients = m.xmuxClients[:len(m.xmuxClients)-1]
		} else {
			i++
		}
	}

	if len(m.xmuxClients) == 0 {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because xmuxClients is empty")
		return m.newXmuxClient()
	}

	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because maxConnections was not hit, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClient()
	}

	xmuxClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.Running.Load() < m.concurrency {
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

// Retired clients can still carry active requests, so they stay owned until
// their last request exits and are also closed when the outbound is removed.
func (m *XmuxManager) Close() error {
	m.closeOnce.Do(func() {
		m.access.Lock()
		m.closed = true
		clients := make([]*XmuxClient, 0, len(m.allClients))
		for client := range m.allClients {
			clients = append(clients, client)
		}
		m.xmuxClients = nil
		m.access.Unlock()
		for _, client := range clients {
			client.NotUsed.Store(true)
			m.closeErr = stderrors.Join(m.closeErr, client.close())
		}
	})
	return m.closeErr
}
