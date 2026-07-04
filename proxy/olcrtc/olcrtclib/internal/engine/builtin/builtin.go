// Package builtin wires the built-in auth providers to their engines and
// registers a name-keyed factory that transports use to obtain an
// [engine.Session]. The factory replaces the former carrier layer: when
// the auth provider is "none" the caller supplies engine/URL/token
// directly; otherwise the named provider issues credentials and the
// matching engine is constructed.
package builtin

import (
	"context"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth"
	authJitsi "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth/jitsi"
	authTelemost "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth/telemost"
	authWBStream "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth/wbstream"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	_ "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/goolom"  // register goolom engine via init
	_ "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/jitsi"   // register jitsi engine via init
	_ "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/livekit" // register livekit engine via init
)

// ErrCarrierNotFound is returned when an unregistered carrier name is requested.
var ErrCarrierNotFound = errors.New("carrier not found")

// ErrAuthFailed wraps an auth provider rejection. It pairs with the inner
// provider error returned from [Open].
var ErrAuthFailed = errors.New("carrier auth failed")

// Config holds the inputs to [Open]. The fields mirror the subset of
// transport.Config that engines consume.
type Config struct {
	RoomURL             string
	Name                string
	OnData              func([]byte)
	OnPeerData          func(peerID string, data []byte)
	DNSServer           string
	ProxyAddr           string
	ProxyPort           int
	RequireTargetedPeer bool
	// Engine, URL, Token are honoured only for the "none" carrier (direct
	// engine access); other carriers derive them from their auth provider.
	Engine string
	URL    string
	Token  string
	// AuthToken is an optional pre-issued account token forwarded to the auth
	// provider so it can act as that account instead of running its guest
	// flow (e.g. a WB Stream account token). Empty uses the guest flow.
	AuthToken string
}

// Factory creates an engine session for a given carrier.
type Factory func(ctx context.Context, cfg Config) (engine.Session, error)

var registry = map[string]Factory{} //nolint:gochecknoglobals // package-level registry

// Register adds a carrier factory.
func Register(name string, f Factory) {
	registry[name] = f
}

// Open looks up the carrier factory and creates an engine session.
func Open(ctx context.Context, name string, cfg Config) (engine.Session, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCarrierNotFound, name)
	}
	return f(ctx, cfg)
}

// Available reports all registered carrier names.
func Available() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// RegisterDefaults wires the built-in carriers: jitsi, telemost, wbstream
// and "none" (direct engine access).
func RegisterDefaults() {
	registerEngineAuth("wbstream", authWBStream.Provider{})
	registerEngineAuth("telemost", authTelemost.Provider{})
	registerEngineAuth("jitsi", authJitsi.Provider{})
	registerDirect("none")
}

// registerDirect registers a carrier that skips auth: the caller supplies
// engine/URL/token directly via [Config].
func registerDirect(name string) {
	Register(name, func(ctx context.Context, cfg Config) (engine.Session, error) {
		engineName := cfg.Engine
		if engineName == "" {
			engineName = "livekit"
		}
		sess, err := engine.New(ctx, engineName, engine.Config{
			URL:                 cfg.URL,
			Token:               cfg.Token,
			Name:                cfg.Name,
			OnData:              cfg.OnData,
			OnPeerData:          cfg.OnPeerData,
			DNSServer:           cfg.DNSServer,
			ProxyAddr:           cfg.ProxyAddr,
			ProxyPort:           cfg.ProxyPort,
			RequireTargetedPeer: cfg.RequireTargetedPeer,
		})
		if err != nil {
			return nil, fmt.Errorf("engine new: %w", err)
		}
		return sess, nil
	})
}

// registerEngineAuth registers a carrier that resolves credentials through an
// auth provider and connects via the engine the auth provider reports.
func registerEngineAuth(name string, provider auth.Provider) {
	Register(name, func(ctx context.Context, cfg Config) (engine.Session, error) {
		authCfg := auth.Config{
			RoomURL:   cfg.RoomURL,
			Name:      cfg.Name,
			Token:     cfg.AuthToken,
			DNSServer: cfg.DNSServer,
			ProxyAddr: cfg.ProxyAddr,
			ProxyPort: cfg.ProxyPort,
		}
		creds, err := provider.Issue(ctx, authCfg)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		sess, err := engine.New(ctx, provider.Engine(), engine.Config{
			URL:                 creds.URL,
			Token:               creds.Token,
			Name:                cfg.Name,
			Extra:               creds.Extra,
			OnData:              cfg.OnData,
			OnPeerData:          cfg.OnPeerData,
			DNSServer:           cfg.DNSServer,
			ProxyAddr:           cfg.ProxyAddr,
			ProxyPort:           cfg.ProxyPort,
			RequireTargetedPeer: cfg.RequireTargetedPeer,
			Refresh: func(ctx context.Context) (engine.Credentials, error) {
				fresh, err := provider.Issue(ctx, authCfg)
				if err != nil {
					return engine.Credentials{}, fmt.Errorf("auth refresh: %w", err)
				}
				return engine.Credentials{URL: fresh.URL, Token: fresh.Token, Extra: fresh.Extra}, nil
			},
		})
		if err != nil {
			return nil, fmt.Errorf("engine new: %w", err)
		}
		return sess, nil
	})
}
