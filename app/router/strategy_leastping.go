package router

import (
	"context"
	"math"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

// leastPingFailureTolerance is the fraction of recent health-check probes an
// outbound may fail before leastPing stops treating it as a low-latency
// candidate. The burst observatory derives Delay from the average of only the
// successful probes, so an outbound that is being throttled or blocked can keep
// a very low Delay while dropping most of its traffic. When reliability data is
// available, excluding such outbounds prevents leastPing from locking onto a
// fast-but-mostly-dead tunnel. The bar is deliberately lenient: only genuinely
// flaky outbounds are skipped, and if every candidate is flaky the selection
// falls back to the original lowest-Delay behavior, so the result is never
// worse than a pure least-ping pick.
const leastPingFailureTolerance = 0.5

type LeastPingStrategy struct {
	ctx         context.Context
	observatory extension.Observatory
}

func (l *LeastPingStrategy) GetPrincipleTarget(strings []string) []string {
	return []string{l.PickOutbound(strings)}
}

func (l *LeastPingStrategy) InjectContext(ctx context.Context) {
	l.ctx = ctx
	common.Must(core.RequireFeatures(l.ctx, func(observatory extension.Observatory) error {
		l.observatory = observatory
		return nil
	}))
}

func (l *LeastPingStrategy) PickOutbound(candidates []string) string {
	if l.observatory == nil {
		errors.LogError(l.ctx, "observer is nil")
		return ""
	}
	observeReport, err := l.observatory.GetObservation(l.ctx)
	if err != nil {
		errors.LogInfoInner(l.ctx, err, "cannot get observer report")
		return ""
	}
	result, ok := observeReport.(*observatory.ObservationResult)
	if !ok {
		// No way to understand observeReport
		return ""
	}
	return pickLeastPing(result.Status, candidates)
}

// pickLeastPing chooses the lowest-latency outbound among the alive candidates.
// It skips outbounds whose recent health-check failure rate exceeds
// leastPingFailureTolerance (when such data is available) and breaks exact Delay
// ties in favor of the lower latency deviation (the steadier outbound). If the
// reliability filter removes every candidate, it falls back to the lowest-Delay
// alive outbound, reproducing the previous behavior so the result is never worse
// than a pure least-ping selection.
func pickLeastPing(status []*observatory.OutboundStatus, candidates []string) string {
	cand := outboundList(candidates)

	reliableTag := ""
	reliableDelay := int64(math.MaxInt64)
	reliableDeviation := int64(math.MaxInt64)

	fallbackTag := ""
	fallbackDelay := int64(math.MaxInt64)

	for _, v := range status {
		if !v.Alive || !cand.contains(v.OutboundTag) {
			continue
		}

		// Lowest-Delay alive outbound, ignoring reliability. This reproduces
		// the original least-ping selection and is used as a safe fallback when
		// no outbound passes the reliability filter below.
		if v.Delay < fallbackDelay {
			fallbackTag = v.OutboundTag
			fallbackDelay = v.Delay
		}

		// Skip outbounds that fail most of their recent probes. Without health
		// statistics (e.g. the plain observer, which leaves HealthPing nil)
		// every alive outbound stays eligible, preserving previous behavior.
		deviation := int64(math.MaxInt64)
		if v.HealthPing != nil {
			deviation = v.HealthPing.Deviation
			if v.HealthPing.All > 0 &&
				float64(v.HealthPing.Fail)/float64(v.HealthPing.All) > leastPingFailureTolerance {
				continue
			}
		}

		if v.Delay < reliableDelay || (v.Delay == reliableDelay && deviation < reliableDeviation) {
			reliableTag = v.OutboundTag
			reliableDelay = v.Delay
			reliableDeviation = deviation
		}
	}

	if reliableTag != "" {
		return reliableTag
	}
	return fallbackTag
}

type outboundList []string

func (o outboundList) contains(name string) bool {
	for _, v := range o {
		if v == name {
			return true
		}
	}
	return false
}
