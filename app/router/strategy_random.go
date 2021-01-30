package router

import (
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/features/routing"
)

// RandomStrategy represents a random balancing strategy
type RandomStrategy struct{}

// GetInformation implements the routing.BalancingStrategy.
func (s *RandomStrategy) GetInformation(tags []string) *routing.StrategyInfo {
	items := make([]*routing.OutboundInfo, 0)
	for _, tag := range tags {
		items = append(items, &routing.OutboundInfo{Tag: tag})
	}
	return &routing.StrategyInfo{
		Settings:    []string{"random"},
		ValueTitles: nil,
		Selects:     items,
		Others:      nil,
	}
}

// SelectAndPick implements the routing.BalancingStrategy.
func (s *RandomStrategy) SelectAndPick(candidates []string) string {
	return s.Pick(candidates)
}

// Pick implements the routing.BalancingStrategy.
func (s *RandomStrategy) Pick(candidates []string) string {
	count := len(candidates)
	if count == 0 {
		// goes to fallbackTag
		return ""
	}
	return candidates[dice.Roll(count)]
}
