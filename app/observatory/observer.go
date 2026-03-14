package observatory

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
	"google.golang.org/protobuf/proto"
)

type Observer struct {
	config *Config
	ctx    context.Context

	statusLock sync.RWMutex
	status     []*OutboundStatus

	finished *done.Instance

	ohm        outbound.Manager
	dispatcher routing.Dispatcher

	probeFunc func(string) ProbeResult
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.RLock()
	defer o.statusLock.RUnlock()
	return &ObservationResult{Status: cloneOutboundStatuses(o.status)}, nil
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	if o.config != nil && len(o.config.SubjectSelector) != 0 {
		o.finished = done.New()
		go o.background()
	}
	return nil
}

func (o *Observer) Close() error {
	if o.finished != nil {
		return o.finished.Close()
	}
	return nil
}

func (o *Observer) background() {
	sleepTime := time.Second * 10
	if o.config.ProbeInterval != 0 {
		sleepTime = time.Duration(o.config.ProbeInterval)
	}

	for !o.finished.Done() {
		outbounds, err := o.selectOutboundsSnapshot()
		if err != nil {
			errors.LogInfoInner(o.ctx, err, "failed to select outbounds for observatory")
			return
		}

		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
		}

		statuses, completed := o.buildStatusSnapshot(outbounds, sleepTime)
		if !completed {
			return
		}
		o.setStatusSnapshot(statuses)

		if !o.waitForNextCycle(sleepTime) {
			return
		}
	}
}

func (o *Observer) selectOutboundsSnapshot() ([]string, error) {
	hs, ok := o.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	return hs.Select(o.config.SubjectSelector), nil
}

func (o *Observer) probe(outbound string) ProbeResult {
	errorCollectorForRequest := newErrorCollector()

	httpTransport := http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, nil
		},
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			var connection net.Conn
			taskErr := task.Run(ctx, func() error {
				// MUST use Xray's built in context system
				dest, err := v2net.ParseDestination(network + ":" + addr)
				if err != nil {
					return errors.New("cannot understand address").Base(err)
				}
				trackedCtx := session.TrackedConnectionError(o.ctx, errorCollectorForRequest)
				conn, err := tagged.Dialer(trackedCtx, o.dispatcher, dest, outbound)
				if err != nil {
					return errors.New("cannot dial remote address ", dest).Base(err)
				}
				connection = conn
				return nil
			})
			if taskErr != nil {
				return nil, errors.New("cannot finish connection").Base(taskErr)
			}
			return connection, nil
		},
		TLSHandshakeTimeout: time.Second * 5,
	}
	httpClient := &http.Client{
		Transport: &httpTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: time.Second * 5,
	}
	var GETTime time.Duration
	err := task.Run(o.ctx, func() error {
		startTime := time.Now()
		probeURL := "https://www.google.com/generate_204"
		if o.config.ProbeUrl != "" {
			probeURL = o.config.ProbeUrl
		}
		req, _ := http.NewRequest(http.MethodGet, probeURL, nil)
		req.Header.Set("User-Agent", utils.ChromeUA)
		response, err := httpClient.Do(req)
		if err != nil {
			return errors.New("outbound failed to relay connection").Base(err)
		}
		if response.Body != nil {
			response.Body.Close()
		}
		endTime := time.Now()
		GETTime = endTime.Sub(startTime)
		return nil
	})
	if err != nil {
		var errorMessage = "the outbound " + outbound + " is dead: GET request failed:" + err.Error() + "with outbound handler report underlying connection failed"
		errors.LogInfoInner(o.ctx, errorCollectorForRequest.UnderlyingError(), errorMessage)
		return ProbeResult{Alive: false, LastErrorReason: errorMessage}
	}
	errors.LogInfo(o.ctx, "the outbound ", outbound, " is alive:", GETTime.Seconds())
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}
}

func (o *Observer) buildStatusSnapshot(outbounds []string, interval time.Duration) ([]*OutboundStatus, bool) {
	previous := o.statusByTag()
	results := make(map[string]ProbeResult, len(outbounds))

	if o.config.EnableConcurrency {
		ch := make(chan probeResult, len(outbounds))
		doneWait := o.finishedWait()
		for _, outbound := range outbounds {
			go func(tag string) {
				ch <- probeResult{
					tag:    tag,
					result: o.runProbe(tag),
				}
			}(outbound)
		}

		for range outbounds {
			select {
			case result := <-ch:
				results[result.tag] = result.result
			case <-doneWait:
				return nil, false
			}
		}
		return o.composeStatusSnapshot(outbounds, results, previous), true
	}

	for idx, outbound := range outbounds {
		results[outbound] = o.runProbe(outbound)
		if idx < len(outbounds)-1 && !o.waitForNextCycle(interval) {
			return nil, false
		}
	}
	return o.composeStatusSnapshot(outbounds, results, previous), true
}

func (o *Observer) composeStatusSnapshot(outbounds []string, results map[string]ProbeResult, previous map[string]*OutboundStatus) []*OutboundStatus {
	statuses := make([]*OutboundStatus, 0, len(outbounds))
	for _, outbound := range outbounds {
		result, ok := results[outbound]
		if !ok {
			continue
		}
		statuses = append(statuses, buildOutboundStatus(outbound, result, previous[outbound]))
	}
	return statuses
}

func (o *Observer) setStatusSnapshot(status []*OutboundStatus) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	o.status = status
}

func (o *Observer) statusByTag() map[string]*OutboundStatus {
	o.statusLock.RLock()
	defer o.statusLock.RUnlock()
	statusMap := make(map[string]*OutboundStatus, len(o.status))
	for _, status := range o.status {
		statusMap[status.OutboundTag] = status
	}
	return statusMap
}

func (o *Observer) waitForNextCycle(interval time.Duration) bool {
	if interval <= 0 {
		return o.finished == nil || !o.finished.Done()
	}
	if o.finished == nil {
		time.Sleep(interval)
		return true
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-o.finished.Wait():
		return false
	}
}

func (o *Observer) finishedWait() <-chan struct{} {
	if o.finished == nil {
		return nil
	}
	return o.finished.Wait()
}

func (o *Observer) runProbe(outbound string) ProbeResult {
	if o.probeFunc != nil {
		return o.probeFunc(outbound)
	}
	return o.probe(outbound)
}

func buildOutboundStatus(outbound string, result ProbeResult, previous *OutboundStatus) *OutboundStatus {
	now := time.Now().Unix()
	status := &OutboundStatus{
		Alive:           result.Alive,
		Delay:           result.Delay,
		LastErrorReason: result.LastErrorReason,
		OutboundTag:     outbound,
		LastTryTime:     now,
	}
	if result.Alive {
		status.LastSeenTime = now
		status.LastErrorReason = ""
		return status
	}
	status.Delay = 99999999
	if previous != nil {
		status.LastSeenTime = previous.LastSeenTime
	}
	return status
}

func cloneOutboundStatuses(statuses []*OutboundStatus) []*OutboundStatus {
	clones := make([]*OutboundStatus, 0, len(statuses))
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

type probeResult struct {
	tag    string
	result ProbeResult
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
	return &Observer{
		config:     config,
		ctx:        ctx,
		ohm:        outboundManager,
		dispatcher: dispatcher,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
