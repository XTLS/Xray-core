package router

import (
	"context"
	"sort"
	"strings"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

// how long a recovered outbound must stay alive before we switch back to it
const failoverRevertAfter = 30 * time.Second

// FailoverStrategy always picks the first alive outbound, in the order of
// the balancer selectors. It switches to the next one as soon as the current
// is dead, and goes back to a higher one only after it stays alive for
// failoverRevertAfter, so a flapping server won't keep changing the exit.
type FailoverStrategy struct {
	selectors []string
	now       func() time.Time

	ctx         context.Context
	observatory extension.Observatory

	mu         sync.Mutex
	current    string
	aliveSince map[string]time.Time
}

// NewFailoverStrategy creates a new FailoverStrategy with selectors as priority
func NewFailoverStrategy(selectors []string) *FailoverStrategy {
	return &FailoverStrategy{
		selectors:  selectors,
		now:        time.Now,
		aliveSince: make(map[string]time.Time),
	}
}

func (s *FailoverStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
		s.observatory = observatory
		return nil
	}))
}

func (s *FailoverStrategy) GetPrincipleTarget(strings []string) []string {
	return s.sortByPriority(strings)
}

func (s *FailoverStrategy) PickOutbound(candidates []string) string {
	candidates = s.sortByPriority(candidates)
	alive := s.getAlive(candidates)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, tag := range candidates {
		if !alive[tag] {
			delete(s.aliveSince, tag)
		} else if _, found := s.aliveSince[tag]; !found {
			s.aliveSince[tag] = now
		}
	}

	currentIndex := -1
	for i, tag := range candidates {
		if tag == s.current && alive[tag] {
			currentIndex = i
			break
		}
	}

	for i, tag := range candidates {
		if !alive[tag] {
			continue
		}
		// higher than current but just came back, wait a bit more
		if currentIndex >= 0 && i < currentIndex && now.Sub(s.aliveSince[tag]) < failoverRevertAfter {
			continue
		}
		if tag != s.current {
			errors.LogInfo(s.ctx, "failover from [", s.current, "] to [", tag, "]")
			s.current = tag
		}
		return tag
	}

	// goes to fallbackTag
	s.current = ""
	return ""
}

// sortByPriority sorts by index of the first matching selector, then by tag
func (s *FailoverStrategy) sortByPriority(tags []string) []string {
	priority := func(tag string) int {
		for i, selector := range s.selectors {
			if strings.HasPrefix(tag, selector) {
				return i
			}
		}
		return len(s.selectors)
	}
	sorted := append([]string(nil), tags...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if pi, pj := priority(sorted[i]), priority(sorted[j]); pi != pj {
			return pi < pj
		}
		return sorted[i] < sorted[j]
	})
	return sorted
}

func (s *FailoverStrategy) getAlive(tags []string) map[string]bool {
	alive := make(map[string]bool, len(tags))
	// unfound candidate is considered alive
	for _, tag := range tags {
		alive[tag] = true
	}
	if s.observatory == nil {
		return alive
	}
	observeReport, err := s.observatory.GetObservation(s.ctx)
	if err != nil {
		errors.LogInfoInner(s.ctx, err, "cannot get observer report")
		return alive
	}
	if result, ok := observeReport.(*observatory.ObservationResult); ok {
		for _, v := range result.Status {
			if _, found := alive[v.OutboundTag]; found {
				alive[v.OutboundTag] = v.Alive
			}
		}
	}
	return alive
}
