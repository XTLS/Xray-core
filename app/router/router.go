package router

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
)

// Router is an implementation of routing.Router.
type Router struct {
	access         sync.RWMutex
	domainStrategy Config_DomainStrategy
	rules          []*Rule
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

	r.rules = make([]*Rule, 0, len(config.Rule))
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

		r.rules = append(r.rules, rr)
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

// FindRule
func (r *Router) FindRule(tag string) (idx int, rule *Rule) {
	idx = -1
	for k, v := range r.rules {
		if v.Tag == tag {
			idx = k
			rule = v
		}
	}
	return
}

// AddRule implement the manager interface.
// Index less than 1 or more than len(r.rules) is append to the end
func (r *Router) AddRule(ctx context.Context, index int32, routingRule interface{}) error {
	rr := routingRule.(*RoutingRule)

	if len(rr.Tag) > 0 {
		idx, _ := r.FindRule(rr.Tag)
		if idx != -1 {
			return newError("existing tag found: " + rr.Tag)
		}
	}

	rule, err := rr.Build(r)
	if err != nil {
		return err
	}
	r.access.Lock()
	defer r.access.Unlock()

	if len(r.rules) < int(index) || index < 1 {
		// index must be greater than zero
		// API rules must have precedence
		r.rules = append(r.rules, rule)
	} else {
		// Insert to the specified location
		temp := make([]*Rule, 0, len(r.rules)+1)
		temp = append(r.rules[:index], rule)
		temp = append(temp, r.rules[index:]...)
		r.rules = temp
	}

	newError("RoutingRule has been added through the API. [", rule.Tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// AlterRule implement the manager interface.
func (r *Router) AlterRule(ctx context.Context, tag string, routingRule interface{}) error {
	idx, rule := r.FindRule(tag)
	if idx == -1 {
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
	r.rules[idx] = rule
	newError("The RoutingRule have been modified through the API. [", rule.Tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// RemoveRule implement the manager interface.
func (r *Router) RemoveRule(ctx context.Context, tag string) error {
	idx, rule := r.FindRule(tag)
	if idx == -1 {
		return newError("tag not found: " + tag)
	}
	r.access.Lock()
	defer r.access.Unlock()

	// remove rule
	r.rules = append(r.rules[:idx], r.rules[idx+1:]...)
	newError("The RoutingRule has been removed through the API. [", rule.Tag, "] ").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// SetRules not implement .
func (r *Router) SetRules(ctx context.Context, rules interface{}) error {
	rrs := rules.([]*RoutingRule)

	if len(rrs) == 0 {
		return newError("Add at least one routing rule")
	}

	temp := make([]*Rule, 0, len(rrs))
	for _, v := range rrs {
		rr, err := v.Build(r)
		if err != nil {
			return err
		}
		temp = append(temp, rr)
	}

	r.access.Lock()
	defer r.access.Unlock()

	r.rules = temp
	newError("Set [", len(temp), "] routing rules through the API").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// GetRules not implement .
func (r *Router) GetRules(ctx context.Context) (interface{}, error) {
	return nil, newError("not implement.")
}

// GetRule implement the manager interface.
func (r *Router) GetRule(ctx context.Context, tag string) (interface{}, error) {
	return nil, newError("not implement.")
}

// AddBalancer implement the manager interface.
func (r *Router) AddBalancer(ctx context.Context, balancingRule interface{}, om outbound.Manager) error {
	br := balancingRule.(*BalancingRule)
	if _, found := r.balancers[br.Tag]; found {
		return newError("existing tag found: " + br.Tag)
	}

	balancer, err := br.Build(om)
	if err != nil {
		return err
	}
	r.access.Lock()
	defer r.access.Unlock()

	r.balancers[br.Tag] = balancer
	newError("BalancingRule has been added through the API. [", br.Tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// AlterBalancer implement the manager interface.
func (r *Router) AlterBalancer(ctx context.Context, tag string, balancingRule interface{}, om outbound.Manager) error {
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

	// Update RoutingRle bind Balancing
	for _, v := range r.rules {
		if v.Balancer == r.balancers[tag] {
			v.Balancer = balancer
		}
	}

	r.balancers[tag] = balancer
	newError("The BalancingRule have been modified through the API. [", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// RemoveBalancer implement the manager interface.
func (r *Router) RemoveBalancer(ctx context.Context, tag string) error {
	if _, found := r.balancers[tag]; !found {
		return newError("tag not found: " + tag)
	}
	r.access.Lock()
	defer r.access.Unlock()

	// Update RoutingRle bind Balancing
	for _, v := range r.rules {
		if v.Balancer == r.balancers[tag] {
			v.Balancer = nil
		}
	}

	delete(r.balancers, tag)
	newError("The BalancingRule has been removed through the API. [", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// GetBalancers not implement.
func (r *Router) GetBalancers(ctx context.Context) (interface{}, error) {
	return nil, newError("not implement.")
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
