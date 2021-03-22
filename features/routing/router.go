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

// AddRule implements Router.
func (DefaultRouter) AddRule(ctx context.Context, index int32, routingRule interface{}) error {
	return common.ErrNoClue
}

// AlterRule implements Router.
func (DefaultRouter) AlterRule(ctx context.Context, tag string, routingRule interface{}) error {
	return common.ErrNoClue
}

// RemoveRule implements Router.
func (DefaultRouter) RemoveRule(ctx context.Context, tag string) error {
	return common.ErrNoClue
}

// SetRules implements Router.
func (DefaultRouter) SetRules(ctx context.Context, rules interface{}) error {
	return common.ErrNoClue
}

// GetRules implements Router.
func (DefaultRouter) GetRules(ctx context.Context) (interface{}, error) {
	return nil, common.ErrNoClue
}

// GetRule implements Router.
func (DefaultRouter) GetRule(ctx context.Context, tag string) (interface{}, error) {
	return nil, common.ErrNoClue
}

// AddBalancer implements Router.
func (DefaultRouter) AddBalancer(ctx context.Context, balancingRule interface{}, handler outbound.Manager) error {
	return common.ErrNoClue
}

// AlterBalancer implements Router.
func (DefaultRouter) AlterBalancer(ctx context.Context, tag string, balancingRule interface{}, handler outbound.Manager) error {
	return common.ErrNoClue
}

// RemoveBalancer implements Router.
func (DefaultRouter) RemoveBalancer(ctx context.Context, tag string) error {
	return common.ErrNoClue
}

// GetBalancers implements Router.
func (DefaultRouter) GetBalancers(ctx context.Context) (interface{}, error) {
	return nil, common.ErrNoClue
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
	// AddRule adds the given routing rule into this Manager.
	AddRule(ctx context.Context, index int32, routingRule interface{}) error
	// AlterRule Modifies the specified routing rule
	AlterRule(ctx context.Context, tag string, routingRule interface{}) error
	// RemoveRule Remove the specified routing rule
	RemoveRule(ctx context.Context, tag string) error
	// SetRules
	SetRules(ctx context.Context, rules interface{}) error
	// GetRules
	GetRules(ctx context.Context) (interface{}, error)
	// GetRule
	GetRule(ctx context.Context, tag string) (interface{}, error)

	// Balancer adds the given balancing rules to this manager.
	AddBalancer(ctx context.Context, balancingRule interface{}, handler outbound.Manager) error
	// AlterBalancer Modifies the specified balancing rule
	AlterBalancer(ctx context.Context, tag string, balancingRule interface{}, handler outbound.Manager) error
	// RemoveBalancer Remove the specified balancing rule
	RemoveBalancer(ctx context.Context, tag string) error
	// GetBalancers
	GetBalancers(ctx context.Context) (interface{}, error)
}
