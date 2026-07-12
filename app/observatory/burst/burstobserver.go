package burst

import (
	"context"
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

	statusLock sync.Mutex
	hp         *HealthPing
	updates    extension.ObservatoryUpdateDispatcher

	finished *done.Instance

	ohm outbound.Manager
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	return &observatory.ObservationResult{Status: o.createResult()}, nil
}

func (o *Observer) SubscribeObservationUpdates(listener func()) func() {
	return o.updates.SubscribeObservationUpdates(listener)
}

func (o *Observer) ObservationProbeDeadline() time.Duration {
	if o.hp == nil || o.hp.Settings == nil || o.hp.Settings.Timeout <= 0 {
		return 0
	}
	deadline := o.hp.Settings.Timeout
	if o.hp.Settings.Connectivity != "" {
		deadline += o.hp.Settings.Timeout
	}
	return deadline
}

func (o *Observer) Check(tag []string) {
	o.hp.Check(tag)
}

func (o *Observer) createResult() []*observatory.OutboundStatus {
	var result []*observatory.OutboundStatus
	o.hp.access.Lock()
	defer o.hp.access.Unlock()
	for name, value := range o.hp.Results {
		status := observatory.OutboundStatus{
			Alive:           value.getStatistics().All != value.getStatistics().Fail,
			Delay:           value.getStatistics().Average.Milliseconds(),
			LastErrorReason: "",
			OutboundTag:     name,
			LastSeenTime:    0,
			LastTryTime:     0,
			HealthPing: &observatory.HealthPingMeasurementResult{
				All:       int64(value.getStatistics().All),
				Fail:      int64(value.getStatistics().Fail),
				Deviation: int64(value.getStatistics().Deviation),
				Average:   int64(value.getStatistics().Average),
				Max:       int64(value.getStatistics().Max),
				Min:       int64(value.getStatistics().Min),
			},
		}
		result = append(result, &status)
	}
	return result
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	if o.config != nil && len(o.config.SubjectSelector) != 0 {
		o.finished = done.New()
		o.hp.StartScheduler(func() ([]string, error) {
			hs, ok := o.ohm.(outbound.HandlerSelector)
			if !ok {
				return nil, errors.New("outbound.Manager is not a HandlerSelector")
			}

			outbounds := hs.Select(o.config.SubjectSelector)
			return outbounds, nil
		})
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
	observer := &Observer{
		config: config,
		ctx:    ctx,
		ohm:    outboundManager,
		hp:     hp,
	}
	hp.onUpdate = observer.updates.NotifyObservationUpdate
	return observer, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
