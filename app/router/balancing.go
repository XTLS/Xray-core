package router

import (
	"context"
	sync "sync"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

type BalancingStrategy interface {
	PickOutbound([]string) string
}

// ContextAwareBalancingStrategy 允许策略在选择出站时使用路由上下文。
// 不需要上下文的现有策略仍沿用 BalancingStrategy。
type ContextAwareBalancingStrategy interface {
	PickOutboundForContext([]string, routing.Context) string
}

type BalancingPrincipleTarget interface {
	GetPrincipleTarget([]string) []string
}

type RoundRobinStrategy struct {
	FallbackTag string

	ctx         context.Context
	observatory extension.Observatory
	mu          sync.Mutex
	index       int
}

func (s *RoundRobinStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if len(s.FallbackTag) > 0 {
		common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
			s.observatory = observatory
			return nil
		}))
	}
}

func (s *RoundRobinStrategy) GetPrincipleTarget(strings []string) []string {
	return strings
}

func (s *RoundRobinStrategy) PickOutbound(tags []string) string {
	tags = filterAliveOutbounds(s.ctx, s.observatory, tags)

	n := len(tags)
	if n == 0 {
		// goes to fallbackTag
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tag := tags[s.index%n]
	s.index = (s.index + 1) % n
	return tag
}

// filterAliveOutbounds 使用观测结果筛选支持 fallback 的策略候选项。
// 观测结果中不存在的候选项仍视为可用，以保持原有 random 和 roundrobin 行为。
func filterAliveOutbounds(ctx context.Context, observatoryFeature extension.Observatory, candidates []string) []string {
	if observatoryFeature == nil {
		return candidates
	}

	observeReport, err := observatoryFeature.GetObservation(ctx)
	if err != nil {
		return candidates
	}
	result, ok := observeReport.(*observatory.ObservationResult)
	if !ok || result == nil {
		return candidates
	}

	statusMap := make(map[string]*observatory.OutboundStatus, len(result.Status))
	for _, outboundStatus := range result.Status {
		if outboundStatus != nil {
			statusMap[outboundStatus.OutboundTag] = outboundStatus
		}
	}

	aliveTags := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		outboundStatus, found := statusMap[candidate]
		if !found || outboundStatus.Alive {
			aliveTags = append(aliveTags, candidate)
		}
	}
	return aliveTags
}

type Balancer struct {
	selectors   []string
	strategy    BalancingStrategy
	ohm         outbound.Manager
	fallbackTag string

	override override
}

// PickOutbound picks the tag of a outbound
func (b *Balancer) PickOutbound() (string, error) {
	return b.PickOutboundForContext(nil)
}

// PickOutboundForContext 在策略支持时使用路由上下文选择出站标签。
func (b *Balancer) PickOutboundForContext(ctx routing.Context) (string, error) {
	candidates, err := b.SelectOutbounds()
	if err != nil {
		if b.fallbackTag != "" {
			errors.LogInfo(context.Background(), "fallback to [", b.fallbackTag, "], due to error: ", err)
			return b.fallbackTag, nil
		}
		return "", err
	}
	var tag string
	if o := b.override.Get(); o != "" {
		tag = o
	} else if strategy, ok := b.strategy.(ContextAwareBalancingStrategy); ok {
		tag = strategy.PickOutboundForContext(candidates, ctx)
	} else {
		tag = b.strategy.PickOutbound(candidates)
	}
	if tag == "" {
		if b.fallbackTag != "" {
			errors.LogInfo(context.Background(), "fallback to [", b.fallbackTag, "], due to empty tag returned")
			return b.fallbackTag, nil
		}
		// will use default handler
		return "", errors.New("balancing strategy returns empty tag")
	}
	return tag, nil
}

func (b *Balancer) InjectContext(ctx context.Context) {
	if contextReceiver, ok := b.strategy.(extension.ContextReceiver); ok {
		contextReceiver.InjectContext(ctx)
	}
}

// SelectOutbounds select outbounds with selectors of the Balancer
func (b *Balancer) SelectOutbounds() ([]string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	tags := hs.Select(b.selectors)
	return tags, nil
}

// GetPrincipleTarget implements routing.BalancerPrincipleTarget
func (r *Router) GetPrincipleTarget(tag string) ([]string, error) {
	if b, ok := r.balancers[tag]; ok {
		if s, ok := b.strategy.(BalancingPrincipleTarget); ok {
			candidates, err := b.SelectOutbounds()
			if err != nil {
				return nil, errors.New("unable to select outbounds").Base(err)
			}
			return s.GetPrincipleTarget(candidates), nil
		}
		return nil, errors.New("unsupported GetPrincipleTarget")
	}
	return nil, errors.New("cannot find tag")
}

// SetOverrideTarget implements routing.BalancerOverrider
func (r *Router) SetOverrideTarget(tag, target string) error {
	if b, ok := r.balancers[tag]; ok {
		b.override.Put(target)
		return nil
	}
	return errors.New("cannot find tag")
}

// GetOverrideTarget implements routing.BalancerOverrider
func (r *Router) GetOverrideTarget(tag string) (string, error) {
	if b, ok := r.balancers[tag]; ok {
		return b.override.Get(), nil
	}
	return "", errors.New("cannot find tag")
}
