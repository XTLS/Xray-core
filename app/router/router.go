package router

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	"google.golang.org/protobuf/proto"
)

// Router is an implementation of routing.Router.
type Router struct {
	domainStrategy Config_DomainStrategy
	rules          []*Rule
	ruleConfigs    []*RoutingRule
	balancers      map[string]*Balancer
	dns            dns.Client

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	mu         sync.Mutex
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.domainStrategy = config.DomainStrategy
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher

	r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
	for _, rule := range config.BalancingRule {
		balancer, err := rule.Build(ohm, dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(ctx)
		r.balancers[rule.Tag] = balancer
	}

	r.rules = make([]*Rule, 0, len(config.Rule))
	for _, rule := range config.Rule {
		cond, err := rule.BuildCondition()
		if err != nil {
			r.closeWebhooks()
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				r.closeWebhooks()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				r.closeWebhooks()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		r.rules = append(r.rules, rr)
	}
	r.ruleConfigs = cloneRules(config.Rule)

	return nil
}

func cloneRules(rules []*RoutingRule) []*RoutingRule {
	cloned := make([]*RoutingRule, len(rules))
	for index, rule := range rules {
		if rule != nil {
			cloned[index] = proto.Clone(rule).(*RoutingRule)
		}
	}
	return cloned
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	originalCtx := ctx
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	if c, ok := inst.(*Config); ok {
		return r.ReloadRules(c, shouldAppend)
	}
	return errors.New("AddRule: config type error")
}

// AddRuleAt inserts all rules in config before the rule at index.
func (r *Router) AddRuleAt(config *serial.TypedMessage, index uint32) error {
	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	c, ok := inst.(*Config)
	if !ok {
		return errors.New("AddRuleAt: config type error")
	}
	return r.InsertRules(c, index)
}

func (r *Router) InsertRules(config *Config, index uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	insertAt := int(index)
	if insertAt > len(r.rules) {
		return errors.New("rule index out of range: ", index, ", current rule count: ", len(r.rules))
	}
	if len(config.Rule) == 0 {
		return errors.New("no routing rules to insert")
	}

	balancers := make(map[string]*Balancer, len(r.balancers)+len(config.BalancingRule))
	for tag, balancer := range r.balancers {
		balancers[tag] = balancer
	}
	for _, balancingRule := range config.BalancingRule {
		if _, found := balancers[balancingRule.Tag]; found {
			return errors.New("duplicate balancer tag: ", balancingRule.Tag)
		}
		balancer, err := balancingRule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(r.ctx)
		balancers[balancingRule.Tag] = balancer
	}

	ruleTags := make(map[string]struct{}, len(r.rules)+len(config.Rule))
	for _, rule := range r.rules {
		if rule.RuleTag != "" {
			ruleTags[rule.RuleTag] = struct{}{}
		}
	}

	insertedRules := make([]*Rule, 0, len(config.Rule))
	closeInsertedWebhooks := func() {
		for _, rule := range insertedRules {
			if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
	}
	for _, ruleConfig := range config.Rule {
		ruleTag := ruleConfig.GetRuleTag()
		if ruleTag != "" {
			if _, found := ruleTags[ruleTag]; found {
				closeInsertedWebhooks()
				return errors.New("duplicate ruleTag ", ruleTag)
			}
			ruleTags[ruleTag] = struct{}{}
		}

		condition, err := ruleConfig.BuildCondition()
		if err != nil {
			closeInsertedWebhooks()
			return err
		}
		rule := &Rule{
			Condition: condition,
			Tag:       ruleConfig.GetTag(),
			RuleTag:   ruleTag,
		}
		if webhook := ruleConfig.GetWebhook(); webhook != nil {
			notifier, err := NewWebhookNotifier(webhook)
			if err != nil {
				closeInsertedWebhooks()
				return err
			}
			rule.Webhook = notifier
		}
		if balancingTag := ruleConfig.GetBalancingTag(); balancingTag != "" {
			balancer, found := balancers[balancingTag]
			if !found {
				if rule.Webhook != nil {
					rule.Webhook.Close()
				}
				closeInsertedWebhooks()
				return errors.New("balancer ", balancingTag, " not found")
			}
			rule.Balancer = balancer
		}
		insertedRules = append(insertedRules, rule)
	}

	rules := make([]*Rule, 0, len(r.rules)+len(insertedRules))
	rules = append(rules, r.rules[:insertAt]...)
	rules = append(rules, insertedRules...)
	rules = append(rules, r.rules[insertAt:]...)

	insertedConfigs := cloneRules(config.Rule)
	ruleConfigs := make([]*RoutingRule, 0, len(r.ruleConfigs)+len(insertedConfigs))
	ruleConfigs = append(ruleConfigs, r.ruleConfigs[:insertAt]...)
	ruleConfigs = append(ruleConfigs, insertedConfigs...)
	ruleConfigs = append(ruleConfigs, r.ruleConfigs[insertAt:]...)

	r.balancers = balancers
	r.rules = rules
	r.ruleConfigs = ruleConfigs
	return nil
}

func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !shouldAppend {
		for _, rule := range r.rules {
			if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
		r.rules = make([]*Rule, 0, len(config.Rule))
	}
	for _, rule := range config.BalancingRule {
		_, found := r.balancers[rule.Tag]
		if found {
			return errors.New("duplicate balancer tag")
		}
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(r.ctx)
		r.balancers[rule.Tag] = balancer
	}

	startIdx := len(r.rules)
	closeNewWebhooks := func() {
		for i := startIdx; i < len(r.rules); i++ {
			if r.rules[i].Webhook != nil {
				r.rules[i].Webhook.Close()
			}
		}
		r.rules = r.rules[:startIdx]
	}

	for _, rule := range config.Rule {
		if r.RuleExists(rule.GetRuleTag()) {
			closeNewWebhooks()
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			closeNewWebhooks()
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		if wh := rule.GetWebhook(); wh != nil {
			notifier, err := NewWebhookNotifier(wh)
			if err != nil {
				closeNewWebhooks()
				return err
			}
			rr.Webhook = notifier
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				if rr.Webhook != nil {
					rr.Webhook.Close()
				}
				closeNewWebhooks()
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		r.rules = append(r.rules, rr)
	}
	if shouldAppend {
		r.ruleConfigs = append(r.ruleConfigs, cloneRules(config.Rule)...)
	} else {
		r.ruleConfigs = cloneRules(config.Rule)
	}

	return nil
}

func (r *Router) RuleExists(tag string) bool {
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag == tag {
				return true
			}
		}
	}
	return false
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newRules := []*Rule{}
	newRuleConfigs := []*RoutingRule{}
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag != tag {
				newRules = append(newRules, rule)
			} else if rule.Webhook != nil {
				rule.Webhook.Close()
			}
		}
		for _, ruleConfig := range r.ruleConfigs {
			if ruleConfig.GetRuleTag() != tag {
				newRuleConfigs = append(newRuleConfigs, ruleConfig)
			}
		}
		r.rules = newRules
		r.ruleConfigs = newRuleConfigs
		return nil
	}
	return errors.New("empty tag name!")
}

// RemoveRuleAt removes the rule at a zero-based index.
func (r *Router) RemoveRuleAt(index uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	removeAt := int(index)
	if removeAt >= len(r.rules) || removeAt >= len(r.ruleConfigs) {
		return errors.New("rule index out of range: ", index, ", current rule count: ", len(r.rules))
	}
	if rule := r.rules[removeAt]; rule.Webhook != nil {
		rule.Webhook.Close()
	}
	r.rules = append(r.rules[:removeAt], r.rules[removeAt+1:]...)
	r.ruleConfigs = append(r.ruleConfigs[:removeAt], r.ruleConfigs[removeAt+1:]...)
	return nil
}

// ListRuleConfigs returns complete rule configurations in evaluation order.
func (r *Router) ListRuleConfigs() []*serial.TypedMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	configs := make([]*serial.TypedMessage, 0, len(r.ruleConfigs))
	for _, rule := range r.ruleConfigs {
		configs = append(configs, serial.ToTypedMessage(rule))
	}
	return configs
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()

	if r.domainStrategy == Config_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	for _, rule := range r.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
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

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// closeWebhooks closes all webhook notifiers in the current rule set.
func (r *Router) closeWebhooks() {
	for _, rule := range r.rules {
		if rule.Webhook != nil {
			rule.Webhook.Close()
		}
	}
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeWebhooks()
	return nil
}

// Type implements common.HasType.
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

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
