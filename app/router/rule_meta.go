package router

import (
	"github.com/xtls/xray-core/features/routing"
)

// ruleMeta holds inexpensive predicates extracted from a rule for fast rejection.
type ruleMeta struct {
	inboundTags  map[string]struct{} // nil = no inbound tag constraint
	hasNetwork   bool
	network      NetworkMatcher
	requiresUser bool
	requiresProto bool
}

func buildRuleMeta(cond Condition) *ruleMeta {
	chanCond, ok := cond.(*ConditionChan)
	if !ok || chanCond == nil {
		return nil
	}
	meta := &ruleMeta{}
	for _, c := range *chanCond {
		switch v := c.(type) {
		case *InboundTagMatcher:
			if meta.inboundTags == nil {
				meta.inboundTags = make(map[string]struct{}, len(v.tags))
			}
			for _, tag := range v.tags {
				meta.inboundTags[tag] = struct{}{}
			}
		case NetworkMatcher:
			meta.hasNetwork = true
			meta.network = v
		case *UserMatcher:
			meta.requiresUser = true
		case *ProtocolMatcher:
			meta.requiresProto = true
		}
	}
	if meta.inboundTags == nil && !meta.hasNetwork && !meta.requiresUser && !meta.requiresProto {
		return nil
	}
	return meta
}

func (m *ruleMeta) couldMatch(ctx routing.Context) bool {
	if m == nil {
		return true
	}
	if m.inboundTags != nil {
		if _, ok := m.inboundTags[ctx.GetInboundTag()]; !ok {
			return false
		}
	}
	if m.hasNetwork && !m.network.Apply(ctx) {
		return false
	}
	if m.requiresUser && len(ctx.GetUser()) == 0 {
		return false
	}
	if m.requiresProto && len(ctx.GetProtocol()) == 0 {
		return false
	}
	return true
}

// routeIndex orders rule indices for inbound-specific and global rules.
type routeIndex struct {
	globalIndices []int
	byInbound     map[string][]int
}

func buildRouteIndex(rules []*Rule) *routeIndex {
	idx := &routeIndex{
		byInbound: make(map[string][]int),
	}
	for i, rule := range rules {
		if rule.meta != nil && rule.meta.inboundTags != nil {
			for tag := range rule.meta.inboundTags {
				idx.byInbound[tag] = append(idx.byInbound[tag], i)
			}
			continue
		}
		idx.globalIndices = append(idx.globalIndices, i)
	}
	return idx
}

func (idx *routeIndex) candidateIndices(inboundTag string) []int {
	if idx == nil {
		return nil
	}
	inbound := idx.byInbound[inboundTag]
	if len(inbound) == 0 {
		return idx.globalIndices
	}
	if len(idx.globalIndices) == 0 {
		return inbound
	}
	merged := make([]int, 0, len(idx.globalIndices)+len(inbound))
	gi, ii := 0, 0
	for gi < len(idx.globalIndices) && ii < len(inbound) {
		if idx.globalIndices[gi] < inbound[ii] {
			merged = append(merged, idx.globalIndices[gi])
			gi++
		} else {
			merged = append(merged, inbound[ii])
			ii++
		}
	}
	merged = append(merged, idx.globalIndices[gi:]...)
	merged = append(merged, inbound[ii:]...)
	return merged
}
