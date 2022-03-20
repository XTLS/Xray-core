package router

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

type LeastPingStrategyConfig struct {
	CacheTTL int16 `json:"cacheTTL"`
}

type LeastPingStrategy struct {
	ctx              context.Context
	observatory      extension.Observatory
	cacheTTL         time.Duration
	cacheValidBefore time.Time
	selectedOutbound string
}

func (l *LeastPingStrategy) InjectContext(ctx context.Context) {
	l.ctx = ctx
}

func (l *LeastPingStrategy) LoadSettings(settings []byte) error {
	if settings == nil {
		return nil
	}

	var config LeastPingStrategyConfig
	err := json.Unmarshal(settings, &config)
	if err != nil {
		return newError("can not unmarshal least ping settings").Base(err).AtError()
	}
	if config.CacheTTL < 0 {
		config.CacheTTL = 0
	}
	
	l.cacheTTL = time.Duration(config.CacheTTL) * time.Second

	return nil
}

func (l *LeastPingStrategy) PickOutbound(strings []string) string {
	// return cached selected outbound if it's valid
	now := time.Now()
	if l.selectedOutbound != "" && now.Before(l.cacheValidBefore) {
		//newError("use cached selected outbound ", l.selectedOutbound).AtInfo().WriteToLog()
		return l.selectedOutbound
	}

	if l.observatory == nil {
		common.Must(core.RequireFeatures(l.ctx, func(observatory extension.Observatory) error {
			l.observatory = observatory
			return nil
		}))
	}

	observeReport, err := l.observatory.GetObservation(l.ctx)
	if err != nil {
		newError("cannot get observe report").Base(err).WriteToLog()
		return ""
	}
	outboundsList := outboundList(strings)
	if result, ok := observeReport.(*observatory.ObservationResult); ok {
		status := result.Status
		leastPing := int64(99999999)
		selectedOutboundName := ""
		for _, v := range status {
			if outboundsList.contains(v.OutboundTag) && v.Alive && v.Delay < leastPing {
				selectedOutboundName = v.OutboundTag
				leastPing = v.Delay
			}
		}

		// cache selected outbound
		if selectedOutboundName != "" {
			l.selectedOutbound = selectedOutboundName
			l.cacheValidBefore = now.Add(l.cacheTTL)
		}
		newError("new selected outbound ", l.selectedOutbound, ", valid before ", l.cacheValidBefore.String()).AtInfo().WriteToLog()
		return selectedOutboundName
	}

	//No way to understand observeReport
	return ""
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
