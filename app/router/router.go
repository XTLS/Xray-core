package router

//go:generate go run github.com/xmplusdev/xray-core/common/errors/errorgen

import (
	"context"
	sync "sync"
	"sort"
	
	"github.com/xmplusdev/xray-core/common"
	"github.com/xmplusdev/xray-core/common/errors"
	"github.com/xmplusdev/xray-core/common/serial"
	"github.com/xmplusdev/xray-core/core"
	"github.com/xmplusdev/xray-core/features/dns"
	"github.com/xmplusdev/xray-core/features/outbound"
	"github.com/xmplusdev/xray-core/features/routing"
	routing_dns "github.com/xmplusdev/xray-core/features/routing/dns"
)

// Router is an implementation of routing.Router.
type Router struct {
	domainStrategy Config_DomainStrategy
	rules          []*Rule
	balancers      map[string]*Balancer
	dns            dns.Client

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	mu         sync.Mutex
	tag2indexmap map[string]int
	index2tag    map[int]string
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
}

func NewRouter() *Router {
	con := NewConditionChan()
	con.Add(NewInboundTagMatcher([]string{"asdf"}))
	con.Add(NewProtocolMatcher([]string{"tls"}))
	con.Add(NewUserMatcher([]string{"bge"}))
	return &Router{
		domainStrategy:     Config_AsIs,
		rules:              []*Rule{&Rule{Condition: con}},
		balancers:          map[string]*Balancer{},
		tag2indexmap: map[string]int{},
		index2tag:    map[int]string{},
	}
}

func RemoveDuplicateRule(users []string) []string {
	sort.Strings(users)
	j := 0
	for i := 1; i < len(users); i++ {
		if users[j] == users[i] {
			continue
		}
		j++
		users[j] = users[i]
	}
	return users[:j+1]
}

func (r *Router) AddUserRule(tag string, email []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if index, ok := r.tag2indexmap[tag]; ok {
		if conditioncan, ok := r.rules[index].Condition.(*ConditionChan); ok {
			for _, condition := range *conditioncan {
				if usermatcher, ok := condition.(*UserMatcher); ok {
					usermatcher.user = RemoveDuplicateRule(append(usermatcher.user, email...))
					break
				}
			}
		} else if usermatcher, ok := r.rules[index].Condition.(*UserMatcher); ok {
			usermatcher.user = RemoveDuplicateRule(append(usermatcher.user, email...))

		}
	} else {
		tagStartIndex := len(r.rules)
		r.tag2indexmap[tag] = tagStartIndex
		r.index2tag[tagStartIndex] = tag
		r.rules = append(r.rules, &Rule{Condition: NewUserMatcher(email), Tag: tag})
	}
}

func (r *Router) RemoveUserRule(Users []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed_index := make([]int, 0, len(r.rules))
	for _, email := range Users {
		for _, rl := range r.rules {
			conditions, ok := rl.Condition.(*ConditionChan)
			if ok {
				for _, v := range *conditions {
					usermatcher, ok := v.(*UserMatcher)
					if ok {
						index := -1
						for i, e := range usermatcher.user {
							if e == email {
								index = i
								break
							}
						}
						if index != -1 {
							usermatcher.user = append(usermatcher.user[:index], usermatcher.user[index+1:]...)
						}
						break
					}
				}
			} else {
				if usermatcher, ok := rl.Condition.(*UserMatcher); ok {
					index := -1
					for i, e := range usermatcher.user {
						if e == email {
							index = i
							break
						}
					}
					if index != -1 {
						usermatcher.user = append(usermatcher.user[:index], usermatcher.user[index+1:]...)
					}
				}
			}

		}
	}
	
	for index, rl := range r.rules {
		conditions, ok := rl.Condition.(*ConditionChan)
		if ok {
			for _, v := range *conditions {
				usermatcher, ok := v.(*UserMatcher)
				if ok {
					if len(usermatcher.user) == 0 {
						removed_index = append(removed_index, index)
						break
					}

				}
			}
		} else {
			usermatcher, ok := rl.Condition.(*UserMatcher)
			if ok {
				if len(usermatcher.user) == 0 {
					removed_index = append(removed_index, index)
				}
			}
		}

	} 
	
	newRules := make([]*Rule, len(r.rules) - len(removed_index))
	m := make(map[int]bool, len(r.rules))
	for _, reomve := range removed_index {
		m[reomve] = true
	}
	
	start := 0
	for index, rl := range r.rules {
		if !m[index] {
			newRules[start] = rl
			start += 1
		}
	}
	
	newtag2indexmap := make(map[string]int, len(newRules))
	newindex2tag := make(map[int]string, len(newRules))
	for index, rule := range newRules {
		newtag2indexmap[rule.Tag] = index
		newindex2tag[index] = rule.Tag
	}
	
	r.rules = newRules
	r.tag2indexmap = newtag2indexmap
	r.index2tag = newindex2tag
	return
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.domainStrategy = config.DomainStrategy
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher

	r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
	r.tag2indexmap = map[string]int{}
	r.index2tag = map[int]string{}
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
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
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
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	return &Route{Context: ctx, outboundTag: tag}, nil
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

func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !shouldAppend {
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

	for _, rule := range config.Rule {
		if r.RuleExists(rule.GetRuleTag()) {
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			return err
		}
		rr := &Rule{
			Condition: cond,
			Tag:       rule.GetTag(),
			RuleTag:   rule.GetRuleTag(),
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := r.balancers[btag]
			if !found {
				return errors.New("balancer ", btag, " not found")
			}
			rr.Balancer = brule
		}
		r.rules = append(r.rules, rr)
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
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag != tag {
				newRules = append(newRules, rule)
			}
		}
		r.rules = newRules
		return nil
	}
	return errors.New("empty tag name!")

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

// Close implements common.Closable.
func (r *Router) Close() error {
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
