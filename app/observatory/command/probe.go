package command

import (
	"context"
	"crypto/rand"
	stderrors "errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Limits and defaults of ProbeOutbound.
const (
	probeDefaultSamples     = 3
	probeMaxSamples         = 10
	probeDefaultInterval    = 200 * time.Millisecond
	probeMaxInterval        = 5 * time.Second
	probeDefaultTimeout     = 5 * time.Second
	probeMaxTimeout         = 30 * time.Second
	probeMaxTotal           = 120 * time.Second
	probeDefaultDestination = "https://connectivitycheck.gstatic.com/generate_204"
	probeMaxErrorLen        = 300
)

// probeDefaulter is implemented by burstObservatory: pingConfig.destination
// and pingConfig.timeout are the defaults of a probe.
type probeDefaulter interface {
	ProbeDefaults() (string, time.Duration)
}

// probeParams are validated parameters of one ProbeOutbound call.
type probeParams struct {
	destination string
	method      string
	timeout     time.Duration
	interval    time.Duration
	samples     int
}

func (s *service) probeParams(request *ProbeOutboundRequest) (*probeParams, error) {
	p := &probeParams{
		destination: probeDefaultDestination,
		method:      "HEAD",
		timeout:     probeDefaultTimeout,
		interval:    probeDefaultInterval,
		samples:     probeDefaultSamples,
	}
	if d, ok := s.observatory.(probeDefaulter); ok {
		dest, timeout := d.ProbeDefaults()
		if dest != "" {
			p.destination = dest
		}
		if timeout > 0 && timeout <= probeMaxTimeout {
			p.timeout = timeout
		}
	}
	if request.Destination != "" {
		p.destination = strings.TrimSpace(request.Destination)
	}
	u, err := url.Parse(p.destination)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, status.Error(codes.InvalidArgument, "destination must be an http:// or https:// URL")
	}
	if m := strings.ToUpper(strings.TrimSpace(request.Method)); m != "" {
		if m != "HEAD" && m != "GET" {
			return nil, status.Error(codes.InvalidArgument, "method must be HEAD or GET")
		}
		p.method = m
	}
	if request.TimeoutMs > 0 {
		p.timeout = time.Duration(request.TimeoutMs) * time.Millisecond
		if p.timeout > probeMaxTimeout {
			return nil, status.Errorf(codes.InvalidArgument, "timeout_ms is over %d", probeMaxTimeout.Milliseconds())
		}
	}
	if request.IntervalMs > 0 {
		p.interval = time.Duration(request.IntervalMs) * time.Millisecond
		if p.interval > probeMaxInterval {
			return nil, status.Errorf(codes.InvalidArgument, "interval_ms is over %d", probeMaxInterval.Milliseconds())
		}
	}
	if request.Samples > 0 {
		if request.Samples > probeMaxSamples {
			return nil, status.Errorf(codes.InvalidArgument, "samples is over %d", probeMaxSamples)
		}
		p.samples = int(request.Samples)
	}
	if p.total() > probeMaxTotal {
		return nil, status.Errorf(codes.InvalidArgument, "samples × (timeout + interval) is over %s", probeMaxTotal)
	}
	return p, nil
}

func (p *probeParams) total() time.Duration {
	return time.Duration(p.samples) * (p.timeout + p.interval)
}

// ProbeOutbound implements ObservatoryServiceServer.
func (s *service) ProbeOutbound(ctx context.Context, request *ProbeOutboundRequest) (resp *ProbeOutboundResponse, err error) {
	hasTag, hasOutbound := request.Tag != "", request.Outbound != nil
	if hasTag == hasOutbound {
		return nil, status.Error(codes.InvalidArgument, "set exactly one of tag and outbound")
	}
	if hasTag && outbound.IsProbeTag(request.Tag) {
		return nil, status.Errorf(codes.InvalidArgument, "tag prefix %s is reserved", outbound.ProbeTagPrefix)
	}
	if s.ohm == nil || s.dispatcher == nil || s.ctx == nil {
		return nil, status.Error(codes.FailedPrecondition, "outbound manager is not available")
	}
	p, err := s.probeParams(request)
	if err != nil {
		return nil, err
	}
	if !s.probeMu.TryLock() {
		return nil, status.Error(codes.ResourceExhausted, "another probe is running")
	}
	defer s.probeMu.Unlock()

	// a panic must not bring Xray down; the temporary outbound is removed
	// by its own defer, which runs before this one
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(s.ctx, "probe outbound: panic: ", r)
			resp, err = nil, status.Errorf(codes.Internal, "probe failed: %v", r)
		}
	}()

	pctx, cancel := context.WithTimeout(s.ctx, p.total()+5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	resp = &ProbeOutboundResponse{Destination: p.destination, Method: p.method}
	tag := request.Tag
	name := tag
	if hasTag {
		if s.ohm.GetHandler(tag) == nil {
			return nil, status.Errorf(codes.NotFound, "outbound not found: %s", tag)
		}
		resp.Tag = tag
	} else {
		h, err := s.addTemporary(request.Outbound)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		tag = h.Tag()
		name = "(new " + request.Outbound.GetTag() + ")"
		defer func() {
			if werr := s.removeTemporary(h); werr != nil {
				errors.LogWarning(s.ctx, "probe outbound: ", werr)
				if resp != nil {
					resp.Warnings = append(resp.Warnings, werr.Error())
				}
			}
		}()
	}

	ok := 0
	for i := 0; i < p.samples; i++ {
		if i > 0 {
			select {
			case <-pctx.Done():
			case <-time.After(p.interval):
			}
		}
		if pctx.Err() != nil {
			break
		}
		rtt, code, err := burst.ProbeOnce(pctx, s.dispatcher, tag, p.destination, p.method, p.timeout)
		sample := &ProbeSample{HttpStatus: int32(code)}
		if err != nil {
			sample.Error = probeErrorText(err)
		} else {
			sample.Ok = true
			sample.RttMs = rtt.Milliseconds()
			ok++
		}
		resp.Samples = append(resp.Samples, sample)
	}
	if cerr := ctx.Err(); cerr != nil {
		return nil, status.FromContextError(cerr).Err()
	}
	errors.LogInfo(s.ctx, "probe outbound ", name, ": ", len(resp.Samples), " samples, ok ", ok)
	return resp, nil
}

// addTemporary creates an outbound from config under a free reserved tag
// and adds it to the outbound manager, the same way as AddOutbound does.
func (s *service) addTemporary(config *core.OutboundHandlerConfig) (outbound.Handler, error) {
	for attempt := 0; attempt < 5; attempt++ {
		tag := outbound.ProbeTagPrefix + randomProbeSuffix()
		if s.ohm.GetHandler(tag) != nil {
			continue
		}
		cfg := proto.Clone(config).(*core.OutboundHandlerConfig)
		cfg.Tag = tag
		raw, err := core.CreateObject(s.v, cfg)
		if err != nil {
			s.dropCounters(tag)
			return nil, err
		}
		h, ok := raw.(outbound.Handler)
		if !ok {
			s.dropCounters(tag)
			return nil, stderrors.New("not an outbound handler")
		}
		if err := s.ohm.AddHandler(s.ctx, h); err != nil {
			// the manager keeps a handler that failed to start: take it out
			if s.ohm.GetHandler(tag) == h {
				s.ohm.RemoveHandler(s.ctx, tag)
				h.Close()
				s.dropCounters(tag)
				return nil, err
			}
			h.Close()
			if strings.Contains(err.Error(), "existing tag") {
				// another outbound took the tag meanwhile: its counters stay
				continue
			}
			s.dropCounters(tag)
			return nil, err
		}
		return h, nil
	}
	return nil, stderrors.New("no free temporary tag")
}

// removeTemporary takes the temporary outbound out of the manager and
// closes it.
func (s *service) removeTemporary(h outbound.Handler) error {
	tag := h.Tag()
	err := s.ohm.RemoveHandler(s.ctx, tag)
	h.Close()
	s.dropCounters(tag)
	if err == nil && s.ohm.GetHandler(tag) != nil {
		err = stderrors.New("still present")
	}
	if err != nil {
		return fmt.Errorf("temporary outbound %s was not removed: %v", tag, err)
	}
	return nil
}

// dropCounters unregisters the traffic counters that creating an outbound
// registers for its tag (with outbound stats enabled in policy).
func (s *service) dropCounters(tag string) {
	sm, ok := s.v.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok || sm == nil {
		return
	}
	for _, dir := range []string{"uplink", "downlink"} {
		name := "outbound>>>" + tag + ">>>traffic>>>" + dir
		if sm.GetCounter(name) != nil {
			sm.UnregisterCounter(name)
		}
	}
}

func randomProbeSuffix() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// probeErrorText returns a short error text without the request URL, which
// may carry secrets.
func probeErrorText(err error) string {
	var uerr *url.Error
	if stderrors.As(err, &uerr) && uerr.Err != nil {
		err = uerr.Err
	}
	text := err.Error()
	if len(text) > probeMaxErrorLen {
		text = text[:probeMaxErrorLen] + "…"
	}
	return text
}
