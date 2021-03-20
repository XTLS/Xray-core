package routing

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/outbound"
)

// Router is a feature to choose an outbound tag for the given request.
//
// xray:api:stable
type Router interface {
	features.Feature
	Manager

	// PickRoute returns a route decision based on the given routing context.
	PickRoute(ctx Context) (Route, error)
}

// Route is the routing result of Router feature.
//
// xray:api:stable
type Route interface {
	// A Route is also a routing context.
	Context

	// GetOutboundGroupTags returns the detoured outbound group tags in sequence before a final outbound is chosen.
	GetOutboundGroupTags() []string

	// GetOutboundTag returns the tag of the outbound the connection was dispatched to.
	GetOutboundTag() string
}

// RouterType return the type of Router interface. Can be used to implement common.HasType.
//
// xray:api:stable
func RouterType() interface{} {
	return (*Router)(nil)
}

// DefaultRouter is an implementation of Router, which always returns ErrNoClue for routing decisions.
type DefaultRouter struct{}

// Type implements common.HasType.
func (DefaultRouter) Type() interface{} {
	return RouterType()
}

// PickRoute implements Router.
func (DefaultRouter) PickRoute(ctx Context) (Route, error) {
	return nil, common.ErrNoClue
}

// AddRoutingRule implements Router.
func (DefaultRouter) AddRoutingRule(ctx context.Context, routingRule interface{}) error {
	return common.ErrNoClue
}

// AlterRoutingRule implements Router.
func (DefaultRouter) AlterRoutingRule(ctx context.Context, tag string, routingRule interface{}) error {
	return common.ErrNoClue
}

// RemoveRoutingRule implements Router.
func (DefaultRouter) RemoveRoutingRule(ctx context.Context, tag string) error {
	return common.ErrNoClue
}

// AddBalancingRule implements Router.
func (DefaultRouter) AddBalancingRule(ctx context.Context, balancingRule interface{}, handler outbound.Manager) error {
	return common.ErrNoClue
}

// AlterBalancingRule implements Router.
func (DefaultRouter) AlterBalancingRule(ctx context.Context, tag string, balancingRule interface{}, handler outbound.Manager) error {
	return common.ErrNoClue
}

// RemoveBalancingRule implements Router.
func (DefaultRouter) RemoveBalancingRule(ctx context.Context, tag string) error {
	return common.ErrNoClue
}

// Start implements common.Runnable.
func (DefaultRouter) Start() error {
	return nil
}

// Close implements common.Closable.
func (DefaultRouter) Close() error {
	return nil
}

// Manager is a feature that manages Router rule.
//
// xray:api:alpha
type Manager interface {
	features.Feature
	// AddRoutingRule adds the given routing rule into this Manager.
	AddRoutingRule(ctx context.Context, routingRule interface{}) error
	// AlterRoutingRule Modifies the specified routing rule
	AlterRoutingRule(ctx context.Context, tag string, routingRule interface{}) error
	// RemoveRoutingRule Remove the specified routing rule
	RemoveRoutingRule(ctx context.Context, tag string) error
	// AddBalancingRule adds the given balancing rules to this manager.
	AddBalancingRule(ctx context.Context, balancingRule interface{}, handler outbound.Manager) error
	// AlterBalancingRule Modifies the specified balancing rule
	AlterBalancingRule(ctx context.Context, tag string, balancingRule interface{}, handler outbound.Manager) error
	// RemoveBalancingRule Remove the specified balancing rule
	RemoveBalancingRule(ctx context.Context, tag string) error
}
