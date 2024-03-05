package router

import (
	"github.com/xtls/xray-core/common/dice"
)

// RandomStrategy represents a random balancing strategy
type RandomStrategy struct{}

func (s *RandomStrategy) GetPrincipleTarget(strings []string) []string {
	return strings
}

func (s *RandomStrategy) PickOutbound(candidates []string) string {
	count := len(candidates)
	if count == 0 {
		// goes to fallbackTag
		return ""
	}
	return candidates[dice.Roll(count)]
}
