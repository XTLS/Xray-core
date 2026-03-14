package router

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

// LeastLoadStrategy represents a least load balancing strategy
type LeastLoadStrategy struct {
	settings *StrategyLeastLoadConfig
	costs    *WeightManager

	observer extension.Observatory

	ctx context.Context

	selectionLock  sync.Mutex
	lastSelected   string
	softFailStreak int32
	softFailAt     int64
}

func (l *LeastLoadStrategy) GetPrincipleTarget(strings []string) []string {
	var ret []string
	current, _, _ := l.getSelectionState()
	nodes, _, _ := l.pickOutbounds(strings, current)
	for _, v := range nodes {
		ret = append(ret, v.Tag)
	}
	return ret
}

// NewLeastLoadStrategy creates a new LeastLoadStrategy with settings
func NewLeastLoadStrategy(settings *StrategyLeastLoadConfig) *LeastLoadStrategy {
	return &LeastLoadStrategy{
		settings: settings,
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
	HasHealthPing    bool
	CountAll         int
	CountFail        int
	RTTAverage       time.Duration
	RTTDeviation     time.Duration
	RTTDeviationCost time.Duration
}

type candidateState struct {
	node                *node
	observed            bool
	qualified           bool
	alive               bool
	hasHealthPing       bool
	sampleCount         int
	lastTryTime         int64
	rejectedByMaxRTT    bool
	rejectedByTolerance bool
}

type candidateSet struct {
	qualified               []*node
	states                  map[string]*candidateState
	hasCandidateObservation bool
	observationReady        bool
}

func (s *LeastLoadStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
		s.observer = observatory
		return nil
	}))
}

func (s *LeastLoadStrategy) PickOutbound(candidates []string) string {
	current, streak, softFailAt := s.getSelectionState()
	selects, canColdStart, states := s.pickOutbounds(candidates, current)
	count := len(selects)
	if tag := s.pickStickyQualified(selects, current); tag != "" {
		s.setLastSelected(tag)
		return tag
	}
	if tag, ok := s.pickSoftFailedCurrent(candidates, current, streak, softFailAt, states, true); ok {
		return tag
	}
	if count == 0 {
		s.resetSoftFailState()
		if !canColdStart {
			// goes to fallbackTag
			return ""
		}
		tag := s.pickColdStartCandidate(candidates, current)
		if tag != "" {
			s.setLastSelected(tag)
		}
		return tag
	}
	tag := selects[dice.Roll(count)].Tag
	s.setLastSelected(tag)
	return tag
}

func (s *LeastLoadStrategy) pickOutbounds(candidates []string, current string) ([]*node, bool, map[string]*candidateState) {
	candidateSet := s.getNodes(candidates, time.Duration(s.settings.MaxRTT))
	qualified := s.applyCandidateWarmup(candidateSet.qualified, candidateSet.states, current)
	selects := s.selectLeastLoad(qualified)
	return selects, candidateSet.observationReady && !candidateSet.hasCandidateObservation, candidateSet.states
}

// selectLeastLoad selects nodes according to Baselines and Expected Count.
//
// The strategy always improves network response speed, not matter which mode below is configured.
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
		errors.LogInfo(s.ctx, "least load: no qualified outbound")
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
		for i := count; i < availableCount; i++ {
			if nodes[i].RTTDeviationCost >= baseline {
				break
			}
			count = i + 1
		}
		// don't continue if find expected selects
		if count >= expected {
			errors.LogDebug(s.ctx, "applied baseline: ", baseline)
			break
		}
	}
	if s.settings.Expected > 0 && count < expected {
		count = expected
	}
	return nodes[:count]
}

func (s *LeastLoadStrategy) getNodes(candidates []string, maxRTT time.Duration) *candidateSet {
	if s.observer == nil {
		errors.LogError(s.ctx, "observer is nil")
		return &candidateSet{qualified: make([]*node, 0), states: make(map[string]*candidateState)}
	}
	observeResult, err := s.observer.GetObservation(s.ctx)
	if err != nil {
		errors.LogInfoInner(s.ctx, err, "cannot get observation")
		return &candidateSet{qualified: make([]*node, 0), states: make(map[string]*candidateState)}
	}

	results := observeResult.(*observatory.ObservationResult)

	outboundlist := outboundList(candidates)

	var ret []*node
	states := make(map[string]*candidateState, len(candidates))
	hasCandidateObservation := false

	for _, v := range results.Status {
		if !outboundlist.contains(v.OutboundTag) {
			continue
		}

		hasCandidateObservation = true
		state := &candidateState{
			observed:      true,
			alive:         v.Alive,
			hasHealthPing: v.GetHealthPing() != nil,
			lastTryTime:   v.GetLastTryTime(),
		}
		states[v.OutboundTag] = state

		if !v.Alive {
			continue
		}

		record := s.buildNode(v)
		state.node = record
		state.sampleCount = record.CountAll
		if maxRTT != 0 && v.Delay >= maxRTT.Milliseconds() {
			state.rejectedByMaxRTT = true
			continue
		}
		if s.exceedsTolerance(v) {
			state.rejectedByTolerance = true
			continue
		}
		state.qualified = true
		ret = append(ret, record)
	}

	leastloadSort(ret)
	return &candidateSet{
		qualified:               ret,
		states:                  states,
		hasCandidateObservation: hasCandidateObservation,
		observationReady:        true,
	}
}

func (s *LeastLoadStrategy) exceedsTolerance(status *observatory.OutboundStatus) bool {
	if status.GetHealthPing() == nil || status.GetHealthPing().GetAll() <= 0 || s.settings.GetTolerance() <= 0 {
		return false
	}
	failRatio := float32(status.GetHealthPing().GetFail()) / float32(status.GetHealthPing().GetAll())
	return failRatio > s.settings.GetTolerance()
}

func (s *LeastLoadStrategy) buildNode(status *observatory.OutboundStatus) *node {
	record := &node{
		Tag:              status.OutboundTag,
		CountAll:         1,
		CountFail:        1,
		RTTAverage:       time.Duration(status.Delay) * time.Millisecond,
		RTTDeviation:     time.Duration(status.Delay) * time.Millisecond,
		RTTDeviationCost: time.Duration(s.costs.Apply(status.OutboundTag, float64(time.Duration(status.Delay)*time.Millisecond))),
	}

	if status.HealthPing != nil {
		record.HasHealthPing = true
		record.RTTAverage = time.Duration(status.HealthPing.Average)
		record.RTTDeviation = time.Duration(status.HealthPing.Deviation)
		record.RTTDeviationCost = time.Duration(s.costs.Apply(status.OutboundTag, float64(status.HealthPing.Deviation)))
		record.CountAll = int(status.HealthPing.All)
		record.CountFail = int(status.HealthPing.Fail)
	}
	return record
}

func (s *LeastLoadStrategy) applyCandidateWarmup(nodes []*node, states map[string]*candidateState, current string) []*node {
	if len(nodes) == 0 || s.settings.GetMinSamples() <= 0 || current == "" {
		return nodes
	}
	currentState, found := states[current]
	if !found || !currentState.qualified {
		return nodes
	}

	filtered := make([]*node, 0, len(nodes))
	minSamples := int(s.settings.GetMinSamples())
	for _, candidate := range nodes {
		if candidate.Tag == current {
			filtered = append(filtered, candidate)
			continue
		}
		state := states[candidate.Tag]
		if state == nil || !state.hasHealthPing || state.sampleCount >= minSamples {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func (s *LeastLoadStrategy) pickStickyQualified(nodes []*node, current string) string {
	if len(nodes) == 0 {
		return ""
	}
	for _, node := range nodes {
		if node.Tag == current {
			return current
		}
	}
	return ""
}

func (s *LeastLoadStrategy) pickSoftFailedCurrent(candidates []string, current string, streak int32, softFailAt int64, states map[string]*candidateState, mutate bool) (string, bool) {
	if current == "" || s.settings.GetSoftFailGrace() <= 0 || !outboundList(candidates).contains(current) {
		return "", false
	}
	state := states[current]
	if state == nil || !state.softRejected() || state.lastTryTime == 0 {
		return "", false
	}

	nextStreak := streak
	if state.lastTryTime != softFailAt {
		nextStreak++
	}
	if nextStreak <= 0 {
		nextStreak = 1
	}
	if nextStreak > s.settings.GetSoftFailGrace() {
		return "", false
	}
	if mutate {
		s.setSoftFailState(current, nextStreak, state.lastTryTime)
	}
	return current, true
}

func (s *LeastLoadStrategy) pickColdStartCandidate(candidates []string, current string) string {
	for _, candidate := range candidates {
		if candidate == current {
			return current
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	fallbacks := append([]string(nil), candidates...)
	sort.Strings(fallbacks)
	return fallbacks[0]
}

func (s *LeastLoadStrategy) getSelectionState() (string, int32, int64) {
	s.selectionLock.Lock()
	defer s.selectionLock.Unlock()
	return s.lastSelected, s.softFailStreak, s.softFailAt
}

func (s *LeastLoadStrategy) setLastSelected(tag string) {
	s.selectionLock.Lock()
	defer s.selectionLock.Unlock()
	s.lastSelected = tag
	s.softFailStreak = 0
	s.softFailAt = 0
}

func (s *LeastLoadStrategy) setSoftFailState(tag string, streak int32, softFailAt int64) {
	s.selectionLock.Lock()
	defer s.selectionLock.Unlock()
	s.lastSelected = tag
	s.softFailStreak = streak
	s.softFailAt = softFailAt
}

func (s *LeastLoadStrategy) resetSoftFailState() {
	s.selectionLock.Lock()
	defer s.selectionLock.Unlock()
	s.softFailStreak = 0
	s.softFailAt = 0
}

func leastloadSort(nodes []*node) {
	sort.Slice(nodes, func(i, j int) bool {
		left := nodes[i]
		right := nodes[j]
		if left.RTTDeviationCost != right.RTTDeviationCost {
			return left.RTTDeviationCost < right.RTTDeviationCost
		}
		if left.RTTAverage != right.RTTAverage {
			return left.RTTAverage < right.RTTAverage
		}
		if leftRatio, rightRatio, ok := compareFailRatio(left, right); ok && leftRatio != rightRatio {
			return leftRatio < rightRatio
		}
		if left.CountAll != right.CountAll {
			return left.CountAll > right.CountAll
		}
		if left.CountFail != right.CountFail {
			return left.CountFail < right.CountFail
		}
		return left.Tag < right.Tag
	})
}

func compareFailRatio(left *node, right *node) (float64, float64, bool) {
	leftRatio, leftOK := left.failRatio()
	rightRatio, rightOK := right.failRatio()
	if !leftOK || !rightOK {
		return 0, 0, false
	}
	return leftRatio, rightRatio, true
}

func (n *node) failRatio() (float64, bool) {
	if !n.HasHealthPing || n.CountAll <= 0 {
		return 0, false
	}
	return float64(n.CountFail) / float64(n.CountAll), true
}

func (c *candidateState) softRejected() bool {
	if c == nil {
		return false
	}
	return c.alive && !c.qualified && (c.rejectedByMaxRTT || c.rejectedByTolerance)
}
