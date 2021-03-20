package router

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	"sync"
)

// Router is an implementation of routing.Router.
type Router struct {
	access         sync.RWMutex
	domainStrategy Config_DomainStrategy
	rules          map[string]*Rule
	balancers      map[string]*Balancer
	dns            dns.Client
	Tag            string
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
}

// Init initializes the Router.
func (r *Router) Init(config *Config, d dns.Client, ohm outbound.Manager) error {
	r.domainStrategy = config.DomainStrategy
	r.dns = d

	r.access.Lock()
	defer r.access.Unlock()
	r.balancers = make(map[string]*Balancer)
	for _, rule := range config.BalancingRule {
		balancer, err := rule.Build(ohm)
		if err != nil {
			return err
		}
		r.balancers[rule.Tag] = balancer
	}

	r.rules = make(map[string]*Rule)
	for _, rule := range config.Rule {
		cond, err := rule.BuildCondition()
		if err != nil {
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				return newError("balancer ", btag, " not found")
			}
			rr.Balancer = brule
			rr.TargetTag = btag
		} else {
			rr.TargetTag = rule.GetTargetTag().(*RoutingRule_OutboundTag).OutboundTag
		}

		if len(rr.Tag) == 0 {
			u := uuid.New()
			rr.Tag = u.String()
		}

		r.rules[rr.Tag] = rr
	}

	return nil
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTargetTag()
	if err != nil {
		return nil, err
	}
	return &Route{Context: ctx, outboundTag: tag}, nil
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	if r.domainStrategy == Config_IpOnDemand {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	r.access.RLock()
	defer r.access.RUnlock()

	for _, rule := range r.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range r.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

// AddRoutingRule implement the manager interface.
func (r *Router) AddRoutingRule(ctx context.Context, routingRule interface{}) error {
	rr := routingRule.(*RoutingRule)
	rule, err := rr.Build(r)
	if err != nil {
		return err
	}
	r.access.Lock()
	defer r.access.Unlock()

	r.rules[rule.Tag] = rule
	newError("Rule has been added through the API. [", rule.Tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// AlterRoutingRule implement the manager interface.
func (r *Router) AlterRoutingRule(ctx context.Context, tag string, routingRule interface{}) error {
	if _, found := r.rules[tag]; !found {
		return newError("tag not found: " + tag)
	}

	rr := routingRule.(*RoutingRule)
	// Removing the tag ensures that Build works properly
	rr.Tag = ""
	rule, err := rr.Build(r)
	if err != nil {
		return err
	}
	r.access.Lock()
	defer r.access.Unlock()

	rule.Tag = tag
	r.rules[tag] = rule
	newError("The rules have been modified through the API. [", rule.Tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// RemoveRoutingRule implement the manager interface.
func (r *Router) RemoveRoutingRule(ctx context.Context, tag string) error {
	if _, found := r.rules[tag]; !found {
		return newError("tag not found: " + tag)
	}
	r.access.Lock()
	defer r.access.Unlock()

	delete(r.rules, tag)
	newError("The rule has been removed through the API. [", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// AddBalancingRule implement the manager interface.
func (r *Router) AddBalancingRule(ctx context.Context, balancingRule interface{}, om outbound.Manager) error {
	br := balancingRule.(*BalancingRule)
	balancer, err := br.Build(om)
	if err != nil {
		return err
	}
	r.access.Lock()
	defer r.access.Unlock()

	r.balancers[br.Tag] = balancer
	newError("Rule has been added through the API. [", br.Tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// AlterBalancingRule implement the manager interface.
func (r *Router) AlterBalancingRule(ctx context.Context, tag string, balancingRule interface{}, om outbound.Manager) error {
	if _, found := r.balancers[tag]; !found {
		return newError("tag not found: " + tag)
	}

	br := balancingRule.(*BalancingRule)
	balancer, err := br.Build(om)
	if err != nil {
		return err
	}
	r.access.Lock()
	defer r.access.Unlock()

	r.balancers[tag] = balancer
	newError("The rules have been modified through the API. [", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// RemoveBalancingRule implement the manager interface.
func (r *Router) RemoveBalancingRule(ctx context.Context, tag string) error {
	if _, found := r.balancers[tag]; !found {
		return newError("tag not found: " + tag)
	}
	r.access.Lock()
	defer r.access.Unlock()

	delete(r.balancers, tag)
	newError("The rule has been removed through the API. [", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// Start implements common.Runnable.
func (*Router) Start() error {
	return nil
}

// Close implements common.Closable.
func (*Router) Close() error {
	return nil
}

// Type implement common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager) error {
			return r.Init(config.(*Config), d, ohm)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
