package olcrtc

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/bridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is the olcrtc outbound handler. It lazily brings up a single shared
// WebRTC carrier to the configured room and multiplexes every outbound
// connection as an independent stream over it.
type Client struct {
	config        *ClientConfig
	policyManager policy.Manager

	mu     sync.Mutex
	client *bridge.Client
}

// NewClient creates an olcrtc outbound handler from config.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	h := &Client{config: config}
	if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
		h.policyManager = pm
		return nil
	}); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Client) policy() policy.Session {
	return h.policyManager.ForLevel(0)
}

// ensureClient starts the shared carrier on first use. The carrier is bound to
// a background context so it persists across individual connections until the
// handler is closed.
func (h *Client) ensureClient() (*bridge.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client != nil {
		return h.client, nil
	}
	c, err := bridge.StartClient(context.Background(), clientBridgeConfig(h.config))
	if err != nil {
		return nil, err
	}
	h.client = c
	return c, nil
}

// Process implements proxy.Outbound. It dials the target over the carrier and
// pipes the transport link against the resulting tunnel stream.
func (h *Client) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "olcrtc"
	dest := ob.Target
	if dest.Network != net.Network_TCP {
		return errors.New("olcrtc only supports TCP, got ", dest.Network)
	}

	c, err := h.ensureClient()
	if err != nil {
		return errors.New("olcrtc: carrier not ready").Base(err)
	}

	errors.LogInfo(ctx, "olcrtc: dialing tunnel to ", dest)
	conn, err := c.DialContext(ctx, dest.Address.String(), int(dest.Port))
	if err != nil {
		return errors.New("olcrtc: failed to dial ", dest).Base(err)
	}
	defer conn.Close()

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if err := buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport response").Base(err)
		}
		return nil
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(link.Writer))); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

// Close shuts down the shared carrier.
func (h *Client) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client == nil {
		return nil
	}
	err := h.client.Close()
	h.client = nil
	return err
}
