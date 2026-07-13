package burst

import (
	"context"
	"math"
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

	probeAccess     sync.Mutex
	probeCancel     context.CancelFunc
	probeDone       chan struct{}
	manualChecks    int
	probePublishing bool
	closed          bool
}

var _ extension.ObservatoryBatchProbe = (*Observer)(nil)

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
	o.probeAccess.Lock()
	if o.closed || o.probeDone != nil || o.probePublishing {
		o.probeAccess.Unlock()
		return
	}
	o.manualChecks++
	o.probeAccess.Unlock()
	defer func() {
		o.probeAccess.Lock()
		o.manualChecks--
		o.probeAccess.Unlock()
	}()
	o.hp.Check(tag)
}

func validateBatchProbeParameters(maxConcurrency, samples int) error {
	if maxConcurrency <= 0 {
		return errors.New("outbound probe concurrency must be positive")
	}
	if samples <= 0 {
		return errors.New("outbound probe sample count must be positive")
	}
	return nil
}

func normalizeBatchProbeTags(tags []string) ([]string, error) {
	uniqueTags := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if tag == "" {
			return nil, errors.New("outbound probe tag is empty")
		}
		if _, found := seen[tag]; found {
			continue
		}
		seen[tag] = struct{}{}
		uniqueTags = append(uniqueTags, tag)
	}
	return uniqueTags, nil
}

func (o *Observer) prepareBatchProbe(tags []string, maxConcurrency, samples int) ([]string, error) {
	if err := validateBatchProbeParameters(maxConcurrency, samples); err != nil {
		return nil, err
	}
	if o.config != nil && len(o.config.SubjectSelector) != 0 {
		return nil, errors.New("one-shot outbound probing requires an observer without scheduled selectors")
	}
	if o.hp == nil {
		return nil, errors.New("outbound probe health checker is unavailable")
	}
	if o.ohm == nil {
		return nil, errors.New("outbound manager is unavailable")
	}

	uniqueTags, err := normalizeBatchProbeTags(tags)
	if err != nil {
		return nil, err
	}
	for _, tag := range uniqueTags {
		if o.ohm.GetHandler(tag) == nil {
			return nil, errors.New("outbound probe handler not found: ", tag)
		}
	}
	return uniqueTags, nil
}

// ProbeOutboundsDeadline reports the configured worst-case batch probe budget.
// Each worker owns a complete tag and samples it serially; failed samples may
// also consume one direct-connectivity timeout before they can be classified.
func (o *Observer) ProbeOutboundsDeadline(tags []string, maxConcurrency, samples int) (time.Duration, error) {
	uniqueTags, err := o.prepareBatchProbe(tags, maxConcurrency, samples)
	if err != nil {
		return 0, err
	}
	if len(uniqueTags) == 0 {
		return 0, nil
	}
	if o.hp.Settings == nil || o.hp.Settings.Timeout <= 0 {
		return 0, errors.New("outbound probe timeout must be positive")
	}

	perSample := o.hp.Settings.Timeout
	if o.hp.Settings.Connectivity != "" {
		if perSample > time.Duration(math.MaxInt64)-perSample {
			return 0, errors.New("outbound probe deadline exceeds time.Duration")
		}
		perSample += perSample
	}
	workers := min(maxConcurrency, len(uniqueTags))
	waves := 1 + (len(uniqueTags)-1)/workers
	steps := int64(waves)
	if int64(samples) > math.MaxInt64/steps {
		return 0, errors.New("outbound probe deadline exceeds time.Duration")
	}
	steps *= int64(samples)
	if int64(perSample) > math.MaxInt64/steps {
		return 0, errors.New("outbound probe deadline exceeds time.Duration")
	}
	return time.Duration(steps * int64(perSample)), nil
}

// ProbeOutbounds runs a one-shot probe batch without starting another Xray
// instance. Configure this observer without subject selectors when using it as
// an embedder-controlled probe feature; scheduled and one-shot observation are
// intentionally kept mutually exclusive so their result sets cannot race.
func (o *Observer) ProbeOutbounds(ctx context.Context, tags []string, maxConcurrency, samples int) error {
	if ctx == nil {
		return errors.New("outbound probe context is nil")
	}
	uniqueTags, err := o.prepareBatchProbe(tags, maxConcurrency, samples)
	if err != nil {
		return err
	}

	o.probeAccess.Lock()
	if o.closed {
		o.probeAccess.Unlock()
		return errors.New("outbound observer is closed")
	}
	if o.probeDone != nil {
		o.probeAccess.Unlock()
		return errors.New("an outbound probe batch is already running")
	}
	if o.manualChecks != 0 {
		o.probeAccess.Unlock()
		return errors.New("a manual outbound check is already running")
	}
	if o.probePublishing {
		o.probeAccess.Unlock()
		return errors.New("outbound probe results are being published")
	}
	probeCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	o.probeCancel = cancel
	o.probeDone = done
	o.probeAccess.Unlock()

	publishUpdate := false
	defer func() {
		cancel()
		o.probeAccess.Lock()
		if o.probeDone == done {
			o.probeCancel = nil
			o.probeDone = nil
		}
		close(done)
		o.probePublishing = publishUpdate
		o.probeAccess.Unlock()
		// Publish only after the probe is no longer marked as running. An
		// embedder may synchronously close the core from an update listener;
		// notifying earlier would make Close wait for this same goroutine.
		if publishUpdate {
			func() {
				defer func() {
					o.probeAccess.Lock()
					o.probePublishing = false
					o.probeAccess.Unlock()
				}()
				o.updates.NotifyObservationUpdate()
			}()
		}
	}()

	err = o.hp.ProbeOutbounds(probeCtx, uniqueTags, maxConcurrency, samples)
	publishUpdate = err == nil
	return err
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
	o.probeAccess.Lock()
	o.closed = true
	cancel := o.probeCancel
	done := o.probeDone
	o.probeAccess.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}

	if o.finished != nil {
		o.hp.StopScheduler()
		return o.finished.Close()
	}
	if o.hp != nil {
		o.hp.cancelCtx()
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
