package selector

import (
    "context"
    "sync"

    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/features/outbound"
    "github.com/xtls/xray-core/transport"
)

// Selector is an outbound handler that can switch between multiple outbound proxies.
type Selector struct {
    sync.RWMutex
    config      *Config
    outboundMgr outbound.Manager
    proxies     map[string]core.OutboundHandler // Map tag to handler instance
    currentTag  string
}

// New creates a new Selector instance.
func New(ctx context.Context, config *Config) (*Selector, error) {
    s := &Selector{
        config:  config,
        proxies: make(map[string]core.OutboundHandler),
    }
    
    // Set the default proxy. It will be validated in Start().
    s.currentTag = config.GetDefaultProxy()
    
    return s, nil
}

// Implement core.OutboundHandler
func (s *Selector) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
    s.RLock()
    handler, found := s.proxies[s.currentTag]
    s.RUnlock()

    if !found {
        return newError("selected outbound " + s.currentTag + " not found")
    }

    // Delegate the Process call to the current selected handler
    return handler.Process(ctx, link, dialer)
}

// Implement core.Linkable
func (s *Selector) Link(hom outbound.HandlerManager) {
    s.outboundMgr = hom
}

// Implement core.Feature
// Start() is called after all outbounds are initialized. Here we can get handler instances.
func (s *Selector) Start() error {
    s.Lock()
    defer s.Unlock()

    for _, tag := range s.config.Proxies {
        handler := s.outboundMgr.GetHandler(tag)
        if handler == nil {
            return newError("outbound " + tag + " not found")
        }
        s.proxies[tag] = handler
    }
    
    // Validate default proxy
    if _, found := s.proxies[s.currentTag]; !found && s.currentTag != "" {
       return newError("default outbound " + s.currentTag + " not found in proxies list")
    }

    return nil
}

func (s *Selector) Close() error {
    return nil
}

// --- API Methods ---
// These will be called by our gRPC service later.

func (s *Selector) GetProxies() []string {
    return s.config.Proxies
}

func (s *Selector) GetCurrent() string {
    s.RLock()
    defer s.RUnlock()
    return s.currentTag
}

func (s *Selector) SetProxy(tag string) error {
    s.Lock()
    defer s.Unlock()

    if _, found := s.proxies[tag]; !found {
        return newError("outbound " + tag + " not found in selector list")
    }

    s.currentTag = tag
    return nil
}