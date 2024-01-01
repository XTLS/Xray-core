package router

import (
	"context"
	sync "sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
)

type BalancingStrategy interface {
	PickOutbound([]string) string
}

type RandomStrategy struct{}

func (s *RandomStrategy) PickOutbound(tags []string) string {
	n := len(tags)
	if n == 0 {
		panic("0 tags")
	}

	return tags[dice.Roll(n)]
}

type RoundRobinStrategy struct {
	mu         sync.Mutex
	tags       []string
	index      int
	roundRobin *RoundRobinStrategy
}

func NewRoundRobin(tags []string) *RoundRobinStrategy {
	return &RoundRobinStrategy{
		tags: tags,
	}
}
func (r *RoundRobinStrategy) NextTag() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	tags := r.tags[r.index]
	r.index = (r.index + 1) % len(r.tags)
	return tags
}

func (s *RoundRobinStrategy) PickOutbound(tags []string) string {
	if len(tags) == 0 {
		panic("0 tags")
	}
	if s.roundRobin == nil {
		s.roundRobin = NewRoundRobin(tags)
	}
	tag := s.roundRobin.NextTag()

	return tag
}

type Balancer struct {
	selectors atomic.Pointer[[]string]
	strategy  BalancingStrategy
	ohm       outbound.Manager
}

func (b *Balancer) PickOutbound() (string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return "", newError("outbound.Manager is not a HandlerSelector")
	}
	tags := hs.Select(*b.selectors.Load())
	if len(tags) == 0 {
		return "", newError("no available outbounds selected")
	}
	tag := b.strategy.PickOutbound(tags)
	if tag == "" {
		return "", newError("balancing strategy returns empty tag")
	}
	return tag, nil
}

func (b *Balancer) InjectContext(ctx context.Context) {
	if contextReceiver, ok := b.strategy.(extension.ContextReceiver); ok {
		contextReceiver.InjectContext(ctx)
	}
}
