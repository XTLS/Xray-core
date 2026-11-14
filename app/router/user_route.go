package router

import (
	"github.com/xtls/xray-core/features/routing"
)

type ruleSet struct {
	rules      []*Rule
	userRoutes *userRouteRules
}

type userRouteRule struct {
	condition Condition
	ranges    [][2]uint32
}

type userRouteRules struct{ rules []*userRouteRule }

type userRouteContext struct {
	routing.Context
	tag, email string
}

func (c userRouteContext) GetInboundTag() string { return c.tag }
func (c userRouteContext) GetUser() string       { return c.email }

func (r *Router) UserRouteRules() routing.UserRouteRules {
	if rules := r.rules.Load(); rules != nil {
		return rules.userRoutes
	}
	return nil
}

func (r *Router) publishRules(rules []*Rule) {
	snapshot := &userRouteRules{}
	if r.script == nil {
		for _, rule := range rules {
			if rule.userRoutes != nil {
				snapshot.rules = append(snapshot.rules, rule.userRoutes)
			}
		}
	}
	r.rules.Store(&ruleSet{rules, snapshot})
}

func compileUserRoutes(rule *RoutingRule) *userRouteRule {
	if rule.UserRouteList == nil {
		return nil
	}
	result := &userRouteRule{condition: NewConditionChan()}
	conditions := result.condition.(*ConditionChan)
	if len(rule.InboundTag) > 0 {
		conditions.Add(NewInboundTagMatcher(rule.InboundTag))
	}
	if len(rule.UserEmail) > 0 {
		conditions.Add(NewUserMatcher(rule.UserEmail))
	}
	for _, interval := range rule.UserRouteList.Range {
		result.ranges = append(result.ranges, [2]uint32{interval.From, interval.To})
	}
	return result
}

func (r *userRouteRules) ForUser(tag, email string) []uint16 {
	if len(r.rules) == 0 {
		return nil
	}
	var selected [65536]bool
	ctx := userRouteContext{tag: tag, email: email}
	for _, rule := range r.rules {
		if !rule.condition.Apply(ctx) {
			continue
		}
		for _, interval := range rule.ranges {
			for value := interval[0]; value <= interval[1]; value++ {
				selected[value] = true
			}
		}
	}
	var values []uint16
	for value, enabled := range selected {
		if enabled {
			values = append(values, uint16(value))
		}
	}
	return values
}
