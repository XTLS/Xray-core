package router

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
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
			strategy:    &RoundRobinStrategy{FallbackTag: br.FallbackTag},
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
			return nil, errors.New("not a StrategyLeastLoadConfig").AtError()
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
			strategy:    &RandomStrategy{FallbackTag: br.FallbackTag},
		}, nil
	default:
		return nil, errors.New("unrecognized balancer type")
	}
}
