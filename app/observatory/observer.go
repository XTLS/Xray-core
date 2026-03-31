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

	statusLock sync.Mutex
	status     []*OutboundStatus
	echStatus  map[string]extension.ECHStatus

	finished *done.Instance

	ohm        outbound.Manager
	dispatcher routing.Dispatcher
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()

	return &ObservationResult{Status: cloneAndSortOutboundStatuses(o.status)}, nil
}

func (o *Observer) GetOutboundECHStatus(ctx context.Context) (map[string]extension.ECHStatus, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()

	if len(o.echStatus) == 0 {
		return nil, nil
	}

	snapshot := make(map[string]extension.ECHStatus, len(o.echStatus))
	for tag, status := range o.echStatus {
		snapshot[tag] = status
	}
	return snapshot, nil
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
	for !o.finished.Done() {
		hs, ok := o.ohm.(outbound.HandlerSelector)
		if !ok {
			errors.LogInfo(o.ctx, "outbound.Manager is not a HandlerSelector")
			return
		}

		outbounds := hs.Select(o.config.SubjectSelector)

		o.updateStatus(outbounds)

		sleepTime := time.Second * 10
		if o.config.ProbeInterval != 0 {
			sleepTime = time.Duration(o.config.ProbeInterval)
		}

		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
			for _, v := range outbounds {
				result, echStatus := o.probe(v)
				o.updateStatusForResult(v, &result, echStatus)
				if o.finished.Done() {
					return
				}
				time.Sleep(sleepTime)
			}
			continue
		}

		ch := make(chan struct{}, len(outbounds))

		for _, v := range outbounds {
			go func(v string) {
				result, echStatus := o.probe(v)
				o.updateStatusForResult(v, &result, echStatus)
				ch <- struct{}{}
			}(v)
		}

		for range outbounds {
			select {
			case <-ch:
			case <-o.finished.Wait():
				return
			}
		}
		time.Sleep(sleepTime)
	}
}

func (o *Observer) updateStatus(outbounds []string) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()

	allowed := make(map[string]struct{}, len(outbounds))
	for _, outbound := range outbounds {
		allowed[outbound] = struct{}{}
	}

	for tag := range o.echStatus {
		if _, ok := allowed[tag]; !ok {
			delete(o.echStatus, tag)
		}
	}

	if len(o.status) == 0 {
		return
	}

	filtered := o.status[:0]
	for _, status := range o.status {
		if status == nil {
			continue
		}
		if _, ok := allowed[status.OutboundTag]; ok {
			filtered = append(filtered, status)
		}
	}

	for i := len(filtered); i < len(o.status); i++ {
		o.status[i] = nil
	}
	o.status = filtered
}

func (o *Observer) probe(outbound string) (ProbeResult, extension.ECHStatus) {
	errorCollectorForRequest := newErrorCollector()
	echCollectorForRequest := newECHCollector()

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
				trackedCtx = session.TrackedOutboundECHStatus(trackedCtx, echCollectorForRequest)
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
		utils.TryDefaultHeadersWith(req.Header, "nav")
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
		return ProbeResult{Alive: false, LastErrorReason: errorMessage}, echCollectorForRequest.Status()
	}
	errors.LogInfo(o.ctx, "the outbound ", outbound, " is alive:", GETTime.Seconds())
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}, echCollectorForRequest.Status()
}

func (o *Observer) updateStatusForResult(outbound string, result *ProbeResult, echStatus extension.ECHStatus) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	var status *OutboundStatus
	if location := o.findStatusLocationLockHolderOnly(outbound); location != -1 {
		status = o.status[location]
	} else {
		status = &OutboundStatus{}
		o.status = append(o.status, status)
	}

	status.LastTryTime = time.Now().Unix()
	status.OutboundTag = outbound
	status.Alive = result.Alive
	if result.Alive {
		status.Delay = result.Delay
		status.LastSeenTime = status.LastTryTime
		status.LastErrorReason = ""
	} else {
		status.LastErrorReason = result.LastErrorReason
		status.Delay = 99999999
	}

	if o.echStatus == nil {
		o.echStatus = make(map[string]extension.ECHStatus)
	}
	echStatus.LastTryTime = status.LastTryTime
	echStatus.Accepted = echStatus.Accepted && result.Alive
	if echStatus.Accepted {
		echStatus.LastSeenTime = status.LastTryTime
	} else {
		echStatus.LastSeenTime = 0
	}
	o.echStatus[outbound] = echStatus
}

func (o *Observer) findStatusLocationLockHolderOnly(outbound string) int {
	for i, v := range o.status {
		if v.OutboundTag == outbound {
			return i
		}
	}
	return -1
}

func cloneAndSortOutboundStatuses(statuses []*OutboundStatus) []*OutboundStatus {
	if len(statuses) == 0 {
		return nil
	}

	snapshot := make([]*OutboundStatus, 0, len(statuses))
	for _, status := range statuses {
		if status == nil {
			continue
		}
		snapshot = append(snapshot, cloneOutboundStatus(status))
	}

	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].OutboundTag < snapshot[j].OutboundTag
	})

	return snapshot
}

func cloneOutboundStatus(status *OutboundStatus) *OutboundStatus {
	if status == nil {
		return nil
	}

	cloned := *status
	if status.HealthPing != nil {
		healthPing := *status.HealthPing
		cloned.HealthPing = &healthPing
	}

	return &cloned
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
