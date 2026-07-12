package observatory

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"slices"
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

	finished *done.Instance

	ohm        outbound.Manager
	dispatcher routing.Dispatcher
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	return proto.Clone(&ObservationResult{Status: o.status}), nil
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
	outbounds, err := o.selectOutbounds(tags)
	if err != nil {
		return nil, err
	}

	// The RPC context does not carry the Xray instance stored in o.ctx. Tagged
	// dialing requires that value, so keep o.ctx as the value-bearing parent and
	// only propagate cancellation from the caller.
	probeCtx, cancel := context.WithCancel(o.ctx)
	stopCancellation := context.AfterFunc(ctx, cancel)
	defer func() {
		stopCancellation()
		cancel()
	}()

	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, outboundTag := range outbounds {
		wg.Add(1)
		go func(tag string) {
			defer wg.Done()
			result, err := o.probe(probeCtx, tag)
			if err != nil {
				return
			}
			o.updateStatusForResult(tag, &result)
		}(outboundTag)
	}
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return o.GetObservation(ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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

		o.clearRemovedOutbounds(outbounds)

		sleepTime := time.Second * 10
		if o.config.ProbeInterval != 0 {
			sleepTime = time.Duration(o.config.ProbeInterval)
		}

		if !o.config.EnableConcurrency {
			sort.Strings(outbounds)
			for _, v := range outbounds {
				result, err := o.probe(o.ctx, v)
				if err == nil {
					o.updateStatusForResult(v, &result)
				}
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
				result, err := o.probe(o.ctx, v)
				if err == nil {
					o.updateStatusForResult(v, &result)
				}
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

func (o *Observer) clearRemovedOutbounds(outbounds []string) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	if len(o.status) == 0 {
		return
	}
	var pruned []*OutboundStatus
	for _, status := range o.status {
		if slices.Contains(outbounds, status.OutboundTag) {
			pruned = append(pruned, status)
		}
	}
	o.status = pruned
}

func (o *Observer) probe(ctx context.Context, outbound string) (ProbeResult, error) {
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
				trackedCtx := session.TrackedConnectionError(ctx, errorCollectorForRequest)
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
	err := task.Run(ctx, func() error {
		startTime := time.Now()
		probeURL := "https://www.google.com/generate_204"
		if o.config.ProbeUrl != "" {
			probeURL = o.config.ProbeUrl
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
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
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ProbeResult{}, ctxErr
		}
		errorMessage := "the outbound " + outbound + " is dead: GET request failed:" + err.Error() + "with outbound handler report underlying connection failed"
		errors.LogInfoInner(o.ctx, errorCollectorForRequest.UnderlyingError(), errorMessage)
		return ProbeResult{Alive: false, LastErrorReason: errorMessage}, nil
	}
	errors.LogInfo(o.ctx, "the outbound ", outbound, " is alive:", GETTime.Seconds())
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}, nil
}

func (o *Observer) updateStatusForResult(outbound string, result *ProbeResult) {
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
}

func (o *Observer) findStatusLocationLockHolderOnly(outbound string) int {
	for i, v := range o.status {
		if v.OutboundTag == outbound {
			return i
		}
	}
	return -1
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
