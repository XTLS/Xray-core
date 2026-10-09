package router

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/protobuf/proto"
)

type testObservatory struct {
	alive map[string]bool
}

func (o *testObservatory) Type() interface{} { return extension.ObservatoryType() }
func (o *testObservatory) Start() error      { return nil }
func (o *testObservatory) Close() error      { return nil }

func (o *testObservatory) GetObservation(context.Context) (proto.Message, error) {
	result := &observatory.ObservationResult{}
	for tag, alive := range o.alive {
		result.Status = append(result.Status, &observatory.OutboundStatus{OutboundTag: tag, Alive: alive})
	}
	return result, nil
}

func newTestFailover(selectors []string, alive map[string]bool, now *time.Time) *FailoverStrategy {
	s := NewFailoverStrategy(selectors)
	s.ctx = context.Background()
	s.observatory = &testObservatory{alive: alive}
	s.now = func() time.Time { return *now }
	return s
}

func TestFailoverPriority(t *testing.T) {
	now := time.Now()
	s := newTestFailover([]string{"m-", "z-", "a-"}, map[string]bool{}, &now)
	// outbound manager returns them sorted by tag
	tags := []string{"a-3", "m-1", "z-2"}

	if actual := s.PickOutbound(tags); actual != "m-1" {
		t.Errorf("expected: m-1, actual: %v", actual)
	}
	if actual := s.GetPrincipleTarget(tags); len(actual) != 1 || actual[0] != "m-1" {
		t.Errorf("expected: [m-1], actual: %v", actual)
	}
	if actual := s.sortByPriority(tags); actual[0] != "m-1" || actual[1] != "z-2" || actual[2] != "a-3" {
		t.Errorf("expected: [m-1 z-2 a-3], actual: %v", actual)
	}
}

func TestFailoverSwitch(t *testing.T) {
	now := time.Now()
	alive := map[string]bool{"p1": true, "p2": true, "p3": true}
	s := newTestFailover([]string{"p1", "p2", "p3"}, alive, &now)
	tags := []string{"p1", "p2", "p3"}

	check := func(expected string) {
		t.Helper()
		if actual := s.PickOutbound(tags); actual != expected {
			t.Errorf("expected: %v, actual: %v", expected, actual)
		}
	}

	check("p1")
	alive["p1"] = false
	check("p2")
	alive["p2"] = false
	check("p3")

	// p1 is back, but not for long enough
	alive["p1"] = true
	now = now.Add(25 * time.Second)
	check("p3")

	// down again, so it starts over
	alive["p1"] = false
	check("p3")
	alive["p1"] = true
	now = now.Add(10 * time.Second)
	check("p3")

	now = now.Add(failoverRevertAfter)
	check("p1")
}

func TestFailoverNoneAlive(t *testing.T) {
	now := time.Now()
	alive := map[string]bool{"p1": false, "p2": false}
	s := newTestFailover([]string{"p"}, alive, &now)
	tags := []string{"p1", "p2"}

	if actual := s.PickOutbound(tags); actual != "" {
		t.Errorf("expected empty for fallbackTag, actual: %v", actual)
	}
	alive["p2"] = true
	if actual := s.PickOutbound(tags); actual != "p2" {
		t.Errorf("expected: p2, actual: %v", actual)
	}
}

func TestFailoverBuild(t *testing.T) {
	rule := &BalancingRule{Tag: "b", OutboundSelector: []string{"p1", "p2"}, Strategy: "failover", FallbackTag: "direct"}
	balancer, err := rule.Build(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := balancer.strategy.(*FailoverStrategy); !ok {
		t.Errorf("expected: *FailoverStrategy, actual: %T", balancer.strategy)
	}
	if balancer.fallbackTag != "direct" {
		t.Errorf("expected: direct, actual: %v", balancer.fallbackTag)
	}
}
