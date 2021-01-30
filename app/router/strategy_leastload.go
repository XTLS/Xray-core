package router

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/features/routing"
)

const (
	rttFailed = time.Duration(math.MaxInt64 - iota)
	rttUntested
	rttUnqualified
)

// LeastLoadStrategy represents a random balancing strategy
type LeastLoadStrategy struct {
	*HealthPing

	settings *StrategyLeastLoadConfig
	costs    *WeightManager
}

// NewLeastLoadStrategy creates a new LeastLoadStrategy with settings
func NewLeastLoadStrategy(settings *StrategyLeastLoadConfig, dispatcher routing.Dispatcher) *LeastLoadStrategy {
	return &LeastLoadStrategy{
		HealthPing: NewHealthPing(settings.HealthCheck, dispatcher),
		settings:   settings,
		costs: NewWeightManager(
			settings.Costs, 1,
			func(value, cost float64) float64 {
				return value * math.Pow(cost, 0.5)
			},
		),
	}
}

// node is a minimal copy of HealthCheckResult
// we don't use HealthCheckResult directly because
// it may change by health checker during routing
type node struct {
	Tag              string
	CountAll         int
	CountFail        int
	RTTAverage       time.Duration
	RTTDeviation     time.Duration
	RTTDeviationCost time.Duration

	applied time.Duration
}

// GetInformation implements the routing.BalancingStrategy.
func (s *LeastLoadStrategy) GetInformation(tags []string) *routing.StrategyInfo {
	qualified, others := s.getNodes(tags, time.Duration(s.settings.MaxRTT))
	selects := s.selectLeastLoad(qualified)
	// append qualified but not selected outbounds to others
	others = append(others, qualified[len(selects):]...)
	leastloadSort(others)
	titles, sl := s.getNodesInfo(selects)
	_, ot := s.getNodesInfo(others)
	return &routing.StrategyInfo{
		Settings:    s.getSettings(),
		ValueTitles: titles,
		Selects:     sl,
		Others:      ot,
	}
}

// SelectAndPick implements the routing.BalancingStrategy.
func (s *LeastLoadStrategy) SelectAndPick(candidates []string) string {
	qualified, _ := s.getNodes(candidates, time.Duration(s.settings.MaxRTT))
	selects := s.selectLeastLoad(qualified)
	count := len(selects)
	if count == 0 {
		// goes to fallbackTag
		return ""
	}
	return selects[dice.Roll(count)].Tag
}

// Pick implements the routing.BalancingStrategy.
func (s *LeastLoadStrategy) Pick(candidates []string) string {
	count := len(candidates)
	if count == 0 {
		// goes to fallbackTag
		return ""
	}
	return candidates[dice.Roll(count)]
}

// selectLeastLoad selects nodes according to Baselines and Expected Count.
//
// The strategy always improves network response speed, not matter which mode below is configurated.
// But they can still have different priorities.
//
// 1. Bandwidth priority: no Baseline + Expected Count > 0.: selects `Expected Count` of nodes.
// (one if Expected Count <= 0)
//
// 2. Bandwidth priority advanced: Baselines + Expected Count > 0.
// Select `Expected Count` amount of nodes, and also those near them according to baselines.
// In other words, it selects according to different Baselines, until one of them matches
// the Expected Count, if no Baseline matches, Expected Count applied.
//
// 3. Speed priority: Baselines + `Expected Count <= 0`.
// go through all baselines until find selects, if not, select none. Used in combination
// with 'balancer.fallbackTag', it means: selects qualified nodes or use the fallback.
func (s *LeastLoadStrategy) selectLeastLoad(nodes []*node) []*node {
	if len(nodes) == 0 {
		newError("least load: no qualified outbound").AtInfo().WriteToLog()
		return nil
	}
	expected := int(s.settings.Expected)
	availableCount := len(nodes)
	if expected > availableCount {
		return nodes
	}

	if expected <= 0 {
		expected = 1
	}
	if len(s.settings.Baselines) == 0 {
		return nodes[:expected]
	}

	count := 0
	// go through all base line until find expected selects
	for _, b := range s.settings.Baselines {
		baseline := time.Duration(b)
		for i := 0; i < availableCount; i++ {
			if nodes[i].applied > baseline {
				break
			}
			count = i + 1
		}
		// don't continue if find expected selects
		if count >= expected {
			newError("applied baseline: ", baseline).AtDebug().WriteToLog()
			break
		}
	}
	if s.settings.Expected > 0 && count < expected {
		count = expected
	}
	return nodes[:count]
}

func (s *LeastLoadStrategy) getNodes(candidates []string, maxRTT time.Duration) ([]*node, []*node) {
	s.access.Lock()
	defer s.access.Unlock()
	results := s.Results
	qualified := make([]*node, 0)
	unqualified := make([]*node, 0)
	failed := make([]*node, 0)
	untested := make([]*node, 0)
	others := make([]*node, 0)
	for _, tag := range candidates {
		r, ok := results[tag]
		if !ok {
			untested = append(untested, &node{
				Tag:              tag,
				RTTDeviationCost: 0,
				RTTDeviation:     0,
				RTTAverage:       0,
				applied:          rttUntested,
			})
			continue
		}
		stats := r.Get()
		node := &node{
			Tag:              tag,
			RTTDeviationCost: time.Duration(s.costs.Apply(tag, float64(stats.Deviation))),
			RTTDeviation:     stats.Deviation,
			RTTAverage:       stats.Average,
			CountAll:         stats.All,
			CountFail:        stats.Fail,
		}
		switch {
		case stats.All == 0:
			node.applied = rttUntested
			untested = append(untested, node)
		case maxRTT > 0 && stats.Average > maxRTT:
			node.applied = rttUnqualified
			unqualified = append(unqualified, node)
		case float64(stats.Fail)/float64(stats.All) > float64(s.settings.Tolerance):
			node.applied = rttFailed
			if stats.All-stats.Fail == 0 {
				// no good, put them after has-good nodes
				node.RTTDeviationCost = rttFailed
				node.RTTDeviation = rttFailed
				node.RTTAverage = rttFailed
			}
			failed = append(failed, node)
		default:
			node.applied = node.RTTDeviationCost
			qualified = append(qualified, node)
		}
	}
	if len(qualified) > 0 {
		leastloadSort(qualified)
		others = append(others, unqualified...)
		others = append(others, untested...)
		others = append(others, failed...)
	} else {
		qualified = untested
		others = append(others, unqualified...)
		others = append(others, failed...)
	}
	return qualified, others
}

func (s *LeastLoadStrategy) getSettings() []string {
	settings := make([]string, 0)
	sb := new(strings.Builder)
	for i, b := range s.settings.Baselines {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(time.Duration(b).String())
	}
	baselines := sb.String()
	if baselines == "" {
		baselines = "none"
	}
	maxRTT := time.Duration(s.settings.MaxRTT).String()
	if s.settings.MaxRTT == 0 {
		maxRTT = "none"
	}
	settings = append(settings, fmt.Sprintf(
		"leastload, expected: %d, baselines: %s, max rtt: %s, tolerance: %.2f",
		s.settings.Expected,
		baselines,
		maxRTT,
		s.settings.Tolerance,
	))
	settings = append(settings, fmt.Sprintf(
		"health ping, interval: %s, sampling: %d, timeout: %s, destination: %s",
		s.HealthPing.Settings.Interval,
		s.HealthPing.Settings.SamplingCount,
		s.HealthPing.Settings.Timeout,
		s.HealthPing.Settings.Destination,
	))
	return settings
}

func (s *LeastLoadStrategy) getNodesInfo(nodes []*node) ([]string, []*routing.OutboundInfo) {
	titles := []string{"   ", "RTT STD+C    ", "RTT STD.     ", "RTT Avg.     ", "Hit  ", "Cost "}
	hasCost := len(s.settings.Costs) > 0
	if !hasCost {
		titles = []string{"   ", "RTT STD.     ", "RTT Avg.     ", "Hit  "}
	}
	items := make([]*routing.OutboundInfo, 0)
	for _, node := range nodes {
		item := &routing.OutboundInfo{
			Tag: node.Tag,
		}
		var status string
		cost := fmt.Sprintf("%.2f", s.costs.Get(node.Tag))
		switch node.applied {
		case rttFailed:
			status = "x"
		case rttUntested:
			status = "?"
		case rttUnqualified:
			status = ">"
		default:
			status = "OK"
		}
		if hasCost {
			item.Values = []string{
				status,
				durationString(node.RTTDeviationCost),
				durationString(node.RTTDeviation),
				durationString(node.RTTAverage),
				fmt.Sprintf("%d/%d", node.CountAll-node.CountFail, node.CountAll),
				cost,
			}
		} else {
			item.Values = []string{
				status,
				durationString(node.RTTDeviation),
				durationString(node.RTTAverage),
				fmt.Sprintf("%d/%d", node.CountAll-node.CountFail, node.CountAll),
			}
		}
		items = append(items, item)
	}
	return titles, items
}

func durationString(d time.Duration) string {
	if d <= 0 || d > time.Hour {
		return "-"
	}
	return d.String()
}

func leastloadSort(nodes []*node) {
	sort.Slice(nodes, func(i, j int) bool {
		left := nodes[i]
		right := nodes[j]
		if left.applied != right.applied {
			return left.applied < right.applied
		}
		if left.RTTDeviationCost != right.RTTDeviationCost {
			return left.RTTDeviationCost < right.RTTDeviationCost
		}
		if left.RTTAverage != right.RTTAverage {
			return left.RTTAverage < right.RTTAverage
		}
		if left.CountFail != right.CountFail {
			return left.CountFail < right.CountFail
		}
		if left.CountAll != right.CountAll {
			return left.CountAll > right.CountAll
		}
		return left.Tag < right.Tag
	})
}
