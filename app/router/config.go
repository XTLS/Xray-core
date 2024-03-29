package router

import (
	"regexp"
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

type Rule struct {
	Tag       string
	RuleTag   string
	Balancer  *Balancer
	Condition Condition
}

func (r *Rule) GetTag() (string, error) {
	if r.Balancer != nil {
		return r.Balancer.PickOutbound()
	}
	return r.Tag, nil
}

// Apply checks rule matching of current routing context.
func (r *Rule) Apply(ctx routing.Context) bool {
	return r.Condition.Apply(ctx)
}

func (rr *RoutingRule) BuildCondition() (Condition, error) {
	conds := NewConditionChan()

	if len(rr.Domain) > 0 {
		switch rr.DomainMatcher {
		case "linear":
			matcher, err := NewDomainMatcher(rr.Domain)
			if err != nil {
				return nil, newError("failed to build domain condition").Base(err)
			}
			conds.Add(matcher)
		case "mph", "hybrid":
			fallthrough
		default:
			matcher, err := NewMphMatcherGroup(rr.Domain)
			if err != nil {
				return nil, newError("failed to build domain condition with MphDomainMatcher").Base(err)
			}
			newError("MphDomainMatcher is enabled for ", len(rr.Domain), " domain rule(s)").AtDebug().WriteToLog()
			conds.Add(matcher)
		}
	}

	if len(rr.UserEmail) > 0 {
		conds.Add(NewUserMatcher(rr.UserEmail))
	}

	if len(rr.InboundTag) > 0 {
		conds.Add(NewInboundTagMatcher(rr.InboundTag))
	}

	if rr.PortList != nil {
		conds.Add(NewPortMatcher(rr.PortList, false))
	} else if rr.PortRange != nil {
		conds.Add(NewPortMatcher(&net.PortList{Range: []*net.PortRange{rr.PortRange}}, false))
	}

	if rr.SourcePortList != nil {
		conds.Add(NewPortMatcher(rr.SourcePortList, true))
	}

	if len(rr.Networks) > 0 {
		conds.Add(NewNetworkMatcher(rr.Networks))
	} else if rr.NetworkList != nil {
		conds.Add(NewNetworkMatcher(rr.NetworkList.Network))
	}

	if len(rr.Geoip) > 0 {
		cond, err := NewMultiGeoIPMatcher(rr.Geoip, false)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	} else if len(rr.Cidr) > 0 {
		cond, err := NewMultiGeoIPMatcher([]*GeoIP{{Cidr: rr.Cidr}}, false)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	}

	if len(rr.SourceGeoip) > 0 {
		cond, err := NewMultiGeoIPMatcher(rr.SourceGeoip, true)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	} else if len(rr.SourceCidr) > 0 {
		cond, err := NewMultiGeoIPMatcher([]*GeoIP{{Cidr: rr.SourceCidr}}, true)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	}

	if len(rr.Protocol) > 0 {
		conds.Add(NewProtocolMatcher(rr.Protocol))
	}

	if len(rr.Attributes) > 0 {
		configuredKeys := make(map[string]*regexp.Regexp)
		for key, value := range rr.Attributes {
			configuredKeys[strings.ToLower(key)] = regexp.MustCompile(value)
		}
		conds.Add(&AttributeMatcher{configuredKeys})
	}

	if conds.Len() == 0 {
		return nil, newError("this rule has no effective fields").AtWarning()
	}

	return conds, nil
}

// Build builds the balancing rule
func (br *BalancingRule) Build(ohm outbound.Manager, dispatcher routing.Dispatcher) (*Balancer, error) {
	switch strings.ToLower(br.Strategy) {
	case "leastping":
		return &Balancer{
			selectors:   br.OutboundSelector,
			strategy:    &LeastPingStrategy{},
			fallbackTag: br.FallbackTag,
			ohm:         ohm,
		}, nil
	case "roundrobin":
		return &Balancer{
			selectors:   br.OutboundSelector,
			strategy:    &RoundRobinStrategy{},
			fallbackTag: br.FallbackTag,
			ohm:         ohm,
		}, nil
	case "leastload":
		i, err := br.StrategySettings.GetInstance()
		if err != nil {
			return nil, err
		}
		s, ok := i.(*StrategyLeastLoadConfig)
		if !ok {
			return nil, newError("not a StrategyLeastLoadConfig").AtError()
		}
		leastLoadStrategy := NewLeastLoadStrategy(s)
		return &Balancer{
			selectors:   br.OutboundSelector,
			ohm:         ohm,
			fallbackTag: br.FallbackTag,
			strategy:    leastLoadStrategy,
		}, nil
	case "random":
		fallthrough
	case "":
		return &Balancer{
			selectors:   br.OutboundSelector,
			ohm:         ohm,
			fallbackTag: br.FallbackTag,
			strategy:    &RandomStrategy{},
		}, nil
	default:
		return nil, newError("unrecognized balancer type")
	}
}
