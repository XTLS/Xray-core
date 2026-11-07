package router

import (
	"math/rand/v2"

	"github.com/xtls/xray-core/common/errors"
)

const weightedPickMinExpected = 256

func (s *LeastLoadStrategy) useWeightedPick() bool {
	return s.settings.Expected >= weightedPickMinExpected
}

func (s *LeastLoadStrategy) logWeightedPick() {
	if s.useWeightedPick() {
		errors.LogInfo(s.ctx, "least load: weighted pick enabled, expected=", s.settings.Expected)
	}
}

func (s *LeastLoadStrategy) weightedPick(selects []*node) *node {
	if len(selects) == 1 {
		return selects[0]
	}
	weights := make([]float64, len(selects))
	total := 0.0
	for i, n := range selects {
		cost := s.costs.Get(n.Tag)
		if cost <= 0 {
			cost = 1
		}
		weights[i] = 1 / cost
		total += weights[i]
	}
	r := rand.Float64() * total
	for i, w := range weights {
		r -= w
		if r < 0 {
			return selects[i]
		}
	}
	return selects[len(selects)-1]
}
