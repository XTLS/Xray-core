package router

import (
	"context"
	"slices"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/routing"
)

// ConsistentHashStrategy 使用 rendezvous hash，让同一目标稳定选择同一出站，
// 并尽量减少候选出站变化时的映射迁移。
type ConsistentHashStrategy struct {
	FallbackTag string

	ctx         context.Context
	observatory extension.Observatory
}

func (s *ConsistentHashStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if len(s.FallbackTag) > 0 {
		common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
			s.observatory = observatory
			return nil
		}))
	}
}

func (s *ConsistentHashStrategy) PickOutbound(candidates []string) string {
	return s.pickOutbound(candidates, "")
}

func (s *ConsistentHashStrategy) PickOutboundForContext(candidates []string, ctx routing.Context) string {
	return s.pickOutbound(candidates, consistentHashTarget(ctx))
}

func (s *ConsistentHashStrategy) pickOutbound(candidates []string, target string) string {
	selected := pickConsistentHashOutbound(target, candidates)
	if selected == "" {
		return ""
	}

	// 主出站失活时不重新散列到其他主候选项，而是返回空标签，
	// 将故障切换交给 Balancer.fallbackTag 处理。
	if !slices.Contains(filterAliveOutbounds(s.ctx, s.observatory, candidates), selected) {
		return ""
	}
	return selected
}

func consistentHashTarget(ctx routing.Context) string {
	if ctx == nil {
		return ""
	}

	if domain := strings.TrimSuffix(strings.ToLower(ctx.GetTargetDomain()), "."); domain != "" {
		return "domain\x00" + domain
	}

	for _, ip := range ctx.GetTargetIPs() {
		if ipv4 := ip.To4(); ipv4 != nil {
			return "ip\x00" + string(ipv4)
		}
		if ipv6 := ip.To16(); ipv6 != nil {
			return "ip\x00" + string(ipv6)
		}
	}
	return ""
}

func pickConsistentHashOutbound(target string, candidates []string) string {
	var selected string
	var bestScore uint64
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		score := rendezvousHashScore(target, candidate)
		if selected == "" || score > bestScore || score == bestScore && candidate < selected {
			selected = candidate
			bestScore = score
		}
	}
	return selected
}

func rendezvousHashScore(target, candidate string) uint64 {
	const (
		offset64 = uint64(14695981039346656037)
		prime64  = uint64(1099511628211)
	)

	hash := offset64
	for i := 0; i < len(target); i++ {
		hash ^= uint64(target[i])
		hash *= prime64
	}
	// 分隔目标和出站标签，避免字符串拼接产生歧义。
	hash ^= 0
	hash *= prime64
	for i := 0; i < len(candidate); i++ {
		hash ^= uint64(candidate[i])
		hash *= prime64
	}
	// 对 FNV-1a 结果做最终混合，改善 rendezvous hash 的分布均匀性。
	hash ^= hash >> 33
	hash *= 0xff51afd7ed558ccd
	hash ^= hash >> 33
	hash *= 0xc4ceb9fe1a85ec53
	hash ^= hash >> 33
	return hash
}
