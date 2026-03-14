package burst

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

type Observer struct {
	config *Config
	ctx    context.Context

	statusLock sync.RWMutex
	status     []*observatory.OutboundStatus
	hp         *HealthPing

	finished *done.Instance

	ohm outbound.Manager
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.RLock()
	defer o.statusLock.RUnlock()
	return &observatory.ObservationResult{Status: cloneObservationStatuses(o.status)}, nil
}

func (o *Observer) createResult() []*observatory.OutboundStatus {
	var result []*observatory.OutboundStatus
	o.hp.access.Lock()
	defer o.hp.access.Unlock()
	tags := make([]string, 0, len(o.hp.Results))
	for name := range o.hp.Results {
		tags = append(tags, name)
	}
	sort.Strings(tags)
	for _, name := range tags {
		value := o.hp.Results[name]
		stats := value.GetWithCache()
		lastTryTime, lastSeenTime := value.LatestTimes()
		status := observatory.OutboundStatus{
			Alive:           stats.All != stats.Fail,
			Delay:           stats.Average.Milliseconds(),
			LastErrorReason: "",
			OutboundTag:     name,
			LastSeenTime:    unixOrZero(lastSeenTime),
			LastTryTime:     unixOrZero(lastTryTime),
			HealthPing: &observatory.HealthPingMeasurementResult{
				All:       int64(stats.All),
				Fail:      int64(stats.Fail),
				Deviation: int64(stats.Deviation),
				Average:   int64(stats.Average),
				Max:       int64(stats.Max),
				Min:       int64(stats.Min),
			},
		}
		result = append(result, &status)
	}
	return result
}

func unixOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	if o.config != nil && len(o.config.SubjectSelector) != 0 {
		o.finished = done.New()
		o.hp.StartScheduler(o.selectOutbounds, o.refreshSnapshot)
	}
	return nil
}

func (o *Observer) Close() error {
	if o.finished != nil {
		o.hp.StopScheduler()
		return o.finished.Close()
	}
	return nil
}

func (o *Observer) selectOutbounds() ([]string, error) {
	hs, ok := o.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	return hs.Select(o.config.SubjectSelector), nil
}

func (o *Observer) refreshSnapshot() {
	o.setStatusSnapshot(o.createResult())
}

func (o *Observer) setStatusSnapshot(status []*observatory.OutboundStatus) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	o.status = status
}

func cloneObservationStatuses(statuses []*observatory.OutboundStatus) []*observatory.OutboundStatus {
	clones := make([]*observatory.OutboundStatus, 0, len(statuses))
	for _, status := range statuses {
		if status == nil {
			continue
		}
		cloned := *status
		if status.HealthPing != nil {
			healthPing := *status.HealthPing
			cloned.HealthPing = &healthPing
		}
		clones = append(clones, &cloned)
	}
	return clones
}

func New(ctx context.Context, config *Config) (*Observer, error) {
	var outboundManager outbound.Manager
	var dispatcher routing.Dispatcher
	err := core.RequireFeatures(ctx, func(om outbound.Manager, rd routing.Dispatcher) {
		outboundManager = om
		dispatcher = rd
	})
	if err != nil {
		return nil, errors.New("Cannot get depended features").Base(err)
	}
	hp := NewHealthPing(ctx, dispatcher, config.PingConfig)
	return &Observer{
		config: config,
		ctx:    ctx,
		ohm:    outboundManager,
		hp:     hp,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
