package burst

import (
	"context"
	"sort"
	"sync"

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

	finished *done.Instance

	ohm outbound.Manager
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	return &observatory.ObservationResult{Status: o.createResult()}, nil
}

func (o *Observer) Check(tag []string) {
	o.hp.Check(tag)
}

func (o *Observer) selectOutbounds(tags []string) ([]string, error) {
	if len(tags) == 0 {
		hs, ok := o.ohm.(outbound.HandlerSelector)
		if !ok {
			return nil, errors.New("outbound.Manager is not a HandlerSelector")
		}
		tags = hs.Select(o.config.SubjectSelector)
	}

	unique := make(map[string]struct{}, len(tags))
	selected := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag == "" {
			return nil, errors.New("outbound tag cannot be empty")
		}
		if o.ohm.GetHandler(tag) == nil {
			return nil, errors.New("outbound not found: ", tag)
		}
		if _, found := unique[tag]; found {
			continue
		}
		unique[tag] = struct{}{}
		selected = append(selected, tag)
	}
	sort.Strings(selected)
	return selected, nil
}

func (o *Observer) CheckObservation(ctx context.Context, tags []string) (proto.Message, error) {
	selected, err := o.selectOutbounds(tags)
	if err != nil {
		return nil, err
	}
	if err := o.hp.CheckContext(ctx, selected); err != nil {
		return nil, err
	}
	return o.GetObservation(ctx)
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
