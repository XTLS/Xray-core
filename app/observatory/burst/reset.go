package burst

import (
	"sort"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/outbound"
)

// matchTag reports whether tag equals one of tags or starts with one of prefixes.
func matchTag(tag string, tags, prefixes []string) bool {
	for _, t := range tags {
		if tag == t {
			return true
		}
	}
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(tag, p) {
			return true
		}
	}
	return false
}

// ResetResults clears health results of outbounds matching tags or prefixes
// and returns the cleared tags, sorted. Saved results are updated at once,
// so a restart does not bring the old samples back.
func (h *HealthPing) ResetResults(tags, prefixes []string) []string {
	var cleared []string
	h.access.Lock()
	for tag := range h.Results {
		if matchTag(tag, tags, prefixes) {
			delete(h.Results, tag)
			cleared = append(cleared, tag)
		}
	}
	h.access.Unlock()
	sort.Strings(cleared)
	if len(cleared) > 0 && h.persistPath != "" {
		h.saveResults(h.persistPath)
	}
	return cleared
}

// Reset clears health results of observed outbounds matching tags or
// prefixes and starts a one-time check of them in background, so they get
// back to the balancer without waiting for the next scheduled round
// (an outbound without results is skipped by leastLoad). The check obeys
// the usual limits (startCheck per tag family). Returns the reset tags.
func (o *Observer) Reset(tags, prefixes []string) []string {
	var recheck []string
	if hs, ok := o.ohm.(outbound.HandlerSelector); ok && o.config != nil && len(o.config.SubjectSelector) > 0 {
		for _, tag := range hs.Select(o.config.SubjectSelector) {
			if matchTag(tag, tags, prefixes) {
				recheck = append(recheck, tag)
			}
		}
	}
	reset := o.hp.ResetResults(tags, prefixes)
	seen := make(map[string]bool, len(reset))
	for _, t := range reset {
		seen[t] = true
	}
	for _, t := range recheck {
		if !seen[t] {
			seen[t] = true
			reset = append(reset, t)
		}
	}
	sort.Strings(reset)
	errors.LogInfo(o.ctx, "burst observatory: reset results of ", len(reset), " outbounds, rechecking ", len(recheck))
	if len(recheck) > 0 {
		go o.hp.Check(recheck)
	}
	return reset
}
