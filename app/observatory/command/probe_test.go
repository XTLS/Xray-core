package command

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newProbeService starts an Xray instance with a freedom outbound "direct",
// a blackhole outbound "block", burstObservatory without a scheduler and
// outbound traffic stats, and returns the ObservatoryService of it.
func newProbeService(t *testing.T, pingDestination string) (*service, *core.Instance) {
	t.Helper()
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{Stats: &policy.SystemPolicy_Stats{
					OutboundUplink: true, OutboundDownlink: true,
				}},
			}),
			serial.ToTypedMessage(&burst.Config{
				PingConfig: &burst.HealthPingConfig{
					Destination:   pingDestination,
					Interval:      int64(time.Hour),
					SamplingCount: 4,
					Timeout:       int64(2 * time.Second),
				},
			}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
			{Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	obj, err := core.CreateObject(v, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := obj.(*service)
	if s.ohm == nil || s.dispatcher == nil || s.observatory == nil {
		t.Fatal("service features are not resolved")
	}
	return s, v
}

func target204(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// closedURL returns an http URL of a local port nobody listens on.
func closedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "http://" + addr + "/generate_204"
}

func freedomConfig(tag string) *core.OutboundHandlerConfig {
	return &core.OutboundHandlerConfig{Tag: tag, ProxySettings: serial.ToTypedMessage(&freedom.Config{})}
}

func codeOf(err error) codes.Code {
	return status.Code(err)
}

func probeTags(s *service) []string {
	var tags []string
	for _, h := range s.ohm.ListHandlers(context.Background()) {
		if outbound.IsProbeTag(h.Tag()) {
			tags = append(tags, h.Tag())
		}
	}
	return tags
}

func TestProbeByTagSuccess(t *testing.T) {
	srv := target204(t)
	s, _ := newProbeService(t, "")
	resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
		Tag: "direct", Destination: srv.URL + "/generate_204", Samples: 3, IntervalMs: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Tag != "direct" || resp.Method != "HEAD" || len(resp.Samples) != 3 {
		t.Fatalf("unexpected response %v", resp)
	}
	for i, sm := range resp.Samples {
		if !sm.Ok || sm.HttpStatus != 204 || sm.Error != "" || sm.RttMs < 0 {
			t.Errorf("sample %d: %v", i, sm)
		}
	}
}

func TestProbeDefaultsFromObservatory(t *testing.T) {
	srv := target204(t)
	s, _ := newProbeService(t, srv.URL+"/from-observatory")
	resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{Tag: "direct", Samples: 1})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Destination != srv.URL+"/from-observatory" || !resp.Samples[0].Ok {
		t.Fatalf("unexpected response %v", resp)
	}
}

func TestProbeByTagGet(t *testing.T) {
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	s, _ := newProbeService(t, "")
	resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
		Tag: "direct", Destination: srv.URL, Method: "get", Samples: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if method != "GET" || resp.Method != "GET" || !resp.Samples[0].Ok || resp.Samples[0].HttpStatus != 200 {
		t.Fatalf("method %s, response %v", method, resp)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	s, _ := newProbeService(t, "")
	resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
		Tag: "direct", Destination: closedURL(t), Samples: 2, IntervalMs: 10, TimeoutMs: 3000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Samples) != 2 {
		t.Fatalf("samples %v", resp.Samples)
	}
	for _, sm := range resp.Samples {
		if sm.Ok || sm.Error == "" || sm.HttpStatus != 0 {
			t.Errorf("sample %v, want a failure", sm)
		}
		if strings.Contains(sm.Error, "127.0.0.1") && strings.Contains(sm.Error, "/generate_204") {
			t.Errorf("error text carries the URL: %q", sm.Error)
		}
	}
}

func TestProbeTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	s, _ := newProbeService(t, "")
	start := time.Now()
	resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
		Tag: "direct", Destination: srv.URL, Samples: 1, TimeoutMs: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Samples[0].Ok || resp.Samples[0].Error == "" {
		t.Errorf("sample %v, want a timeout", resp.Samples[0])
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("probe took %s", d)
	}
}

func TestProbeBlackholeIsFailedSample(t *testing.T) {
	srv := target204(t)
	s, _ := newProbeService(t, "")
	resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
		Tag: "block", Destination: srv.URL, Samples: 1, TimeoutMs: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Samples[0].Ok {
		t.Errorf("blackhole answered: %v", resp.Samples[0])
	}
}

func TestProbeInvalidArguments(t *testing.T) {
	s, _ := newProbeService(t, "")
	cases := map[string]*ProbeOutboundRequest{
		"nothing":        {},
		"both":           {Tag: "direct", Outbound: freedomConfig("x")},
		"reserved tag":   {Tag: outbound.ProbeTagPrefix + "abc"},
		"ftp":            {Tag: "direct", Destination: "ftp://example.com/"},
		"no scheme":      {Tag: "direct", Destination: "example.com/generate_204"},
		"no host":        {Tag: "direct", Destination: "http:///x"},
		"method":         {Tag: "direct", Method: "POST"},
		"samples":        {Tag: "direct", Samples: 11},
		"timeout":        {Tag: "direct", TimeoutMs: 30001},
		"interval":       {Tag: "direct", IntervalMs: 5001},
		"total duration": {Tag: "direct", Samples: 10, TimeoutMs: 30000, IntervalMs: 1000},
	}
	for name, req := range cases {
		if _, err := s.ProbeOutbound(context.Background(), req); codeOf(err) != codes.InvalidArgument {
			t.Errorf("%s: got %v, want InvalidArgument", name, err)
		}
	}
}

func TestProbeUnknownTag(t *testing.T) {
	s, _ := newProbeService(t, "")
	_, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{Tag: "nope"})
	if codeOf(err) != codes.NotFound || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("got %v, want NotFound naming the tag", err)
	}
}

func TestProbeTemporaryRemovedAfterSuccessAndFailure(t *testing.T) {
	srv := target204(t)
	s, v := newProbeService(t, "")
	sm := v.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	for _, dest := range []string{srv.URL, closedURL(t)} {
		resp, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
			Outbound: freedomConfig("mine"), Destination: dest, Samples: 1, TimeoutMs: 2000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Tag != "" || len(resp.Warnings) != 0 {
			t.Errorf("tag %q warnings %v, want none", resp.Tag, resp.Warnings)
		}
		if left := probeTags(s); len(left) != 0 {
			t.Errorf("temporary outbounds left: %v", left)
		}
		if s.ohm.GetHandler("mine") != nil {
			t.Error("the tag from the description was added")
		}
	}
	// no traffic counters of temporary outbounds are left
	sm.VisitCounters(func(name string, _ featurestats.Counter) bool {
		if strings.Contains(name, outbound.ProbeTagPrefix) {
			t.Errorf("counter left: %s", name)
		}
		return true
	})
}

func TestProbeTemporaryConfigError(t *testing.T) {
	s, _ := newProbeService(t, "")
	before := len(s.ohm.ListHandlers(context.Background()))
	_, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
		Outbound: &core.OutboundHandlerConfig{
			Tag:           "bad",
			ProxySettings: &serial.TypedMessage{Type: "xray.no.such.Config"},
		},
	})
	if codeOf(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
	if after := len(s.ohm.ListHandlers(context.Background())); after != before {
		t.Errorf("handlers %d -> %d", before, after)
	}
}

// blockingTarget answers only after release is closed and reports every
// request on started.
func blockingTarget(t *testing.T) (srv *httptest.Server, started chan struct{}, release chan struct{}) {
	t.Helper()
	started = make(chan struct{}, 16)
	release = make(chan struct{})
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return
}

func TestProbeTemporaryCancelled(t *testing.T) {
	srv, started, release := blockingTarget(t)
	defer close(release)
	s, _ := newProbeService(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.ProbeOutbound(ctx, &ProbeOutboundRequest{
			Outbound: freedomConfig("mine"), Destination: srv.URL, Samples: 3, TimeoutMs: 10000,
		})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	if len(probeTags(s)) != 1 {
		t.Fatalf("temporary outbound is not there during the probe: %v", probeTags(s))
	}
	cancel()
	select {
	case err := <-done:
		if codeOf(err) != codes.Canceled {
			t.Errorf("got %v, want Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not stop on cancel")
	}
	if left := probeTags(s); len(left) != 0 {
		t.Errorf("temporary outbounds left: %v", left)
	}
}

func TestProbeTemporaryHiddenAndObservatoryUntouched(t *testing.T) {
	srv, started, release := blockingTarget(t)
	ok := target204(t)
	s, _ := newProbeService(t, ok.URL)
	obs := s.observatory.(*burst.Observer)
	obs.Check([]string{"direct"})
	before, err := s.GetOutboundStatus(context.Background(), &GetOutboundStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Status.Status) != 1 {
		t.Fatalf("observatory results before: %v", before.Status.Status)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{
			Outbound: freedomConfig("mine"), Destination: srv.URL, Samples: 1, TimeoutMs: 10000,
		})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not start")
	}
	if len(probeTags(s)) != 1 {
		t.Fatal("temporary outbound is not there during the probe")
	}
	hs := s.ohm.(outbound.HandlerSelector)
	for _, sel := range [][]string{{""}, {"x"}, {outbound.ProbeTagPrefix}} {
		for _, tag := range hs.Select(sel) {
			if outbound.IsProbeTag(tag) {
				t.Errorf("Select(%v) returned %s", sel, tag)
			}
		}
	}
	during, _ := s.GetOutboundStatus(context.Background(), &GetOutboundStatusRequest{})
	for _, st := range during.Status.Status {
		if outbound.IsProbeTag(st.OutboundTag) {
			t.Errorf("GetOutboundStatus reports %s", st.OutboundTag)
		}
	}

	// a second probe at the same time is refused
	if _, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{Tag: "direct", Destination: ok.URL}); codeOf(err) != codes.ResourceExhausted {
		t.Errorf("parallel probe: got %v, want ResourceExhausted", err)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// probing an observed outbound by tag does not touch its results either
	if _, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{Tag: "direct", Destination: ok.URL, Samples: 2, IntervalMs: 10}); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetOutboundStatus(context.Background(), &GetOutboundStatusRequest{})
	if !reflect.DeepEqual(statusSummary(before.Status), statusSummary(after.Status)) {
		t.Errorf("observatory results changed:\n%v\n%v", statusSummary(before.Status), statusSummary(after.Status))
	}
	// the cached selection does not keep the removed temporary outbound
	if tags := hs.Select([]string{""}); !reflect.DeepEqual(tags, []string{"block", "direct"}) {
		t.Errorf("Select after probe: %v", tags)
	}
}

func statusSummary(r *observatory.ObservationResult) []string {
	var out []string
	for _, st := range r.Status {
		hp := st.HealthPing
		out = append(out, fmt.Sprint(st.OutboundTag, st.Alive, hp.All, hp.Fail, hp.Average, hp.Min, hp.Max))
	}
	sort.Strings(out)
	return out
}

func TestProbeParallelCallsDoNotPileUp(t *testing.T) {
	srv, started, release := blockingTarget(t)
	s, _ := newProbeService(t, "")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{Tag: "direct", Destination: srv.URL, Samples: 1, TimeoutMs: 10000})
	}()
	<-started
	refused := 0
	for i := 0; i < 5; i++ {
		if _, err := s.ProbeOutbound(context.Background(), &ProbeOutboundRequest{Tag: "direct", Destination: srv.URL}); codeOf(err) == codes.ResourceExhausted {
			refused++
		}
	}
	close(release)
	wg.Wait()
	if refused != 5 {
		t.Errorf("refused %d of 5 parallel probes", refused)
	}
}

func TestProbeErrorText(t *testing.T) {
	long := strings.Repeat("x", 500)
	if got := probeErrorText(errors.New(long)); len(got) > probeMaxErrorLen+4 {
		t.Errorf("error text not shortened: %d", len(got))
	}
}
