package command

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/protobuf/proto"
)

type fakeObservatory struct {
	result      *observatory.ObservationResult
	checkedTags []string
}

func (f *fakeObservatory) Type() interface{} { return extension.ObservatoryType() }
func (f *fakeObservatory) Start() error      { return nil }
func (f *fakeObservatory) Close() error      { return nil }

func (f *fakeObservatory) GetObservation(context.Context) (proto.Message, error) {
	return proto.Clone(f.result), nil
}

func (f *fakeObservatory) CheckObservation(_ context.Context, tags []string) (proto.Message, error) {
	f.checkedTags = append([]string(nil), tags...)
	return proto.Clone(f.result), nil
}

func TestGetOutboundStatusFiltersAndSorts(t *testing.T) {
	observer := &fakeObservatory{result: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
		{OutboundTag: "proxy-b", Alive: true, Delay: 20},
		{OutboundTag: "proxy-a", Alive: true, Delay: 10},
		{OutboundTag: "proxy-c", Alive: false},
	}}}
	server := &service{observatory: observer}

	response, err := server.GetOutboundStatus(context.Background(), &GetOutboundStatusRequest{
		OutboundTags: []string{"proxy-b", "proxy-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Status.Status) != 2 {
		t.Fatalf("got %d statuses, want 2", len(response.Status.Status))
	}
	if response.Status.Status[0].OutboundTag != "proxy-a" || response.Status.Status[1].OutboundTag != "proxy-b" {
		t.Fatalf("statuses are not sorted: %v", response.Status.Status)
	}
}

func TestProbeOutboundStatusPassesSelectedTags(t *testing.T) {
	observer := &fakeObservatory{result: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
		{OutboundTag: "proxy-a", Alive: true},
		{OutboundTag: "proxy-b", Alive: true},
	}}}
	server := &service{observatory: observer}

	response, err := server.ProbeOutboundStatus(context.Background(), &ProbeOutboundStatusRequest{
		OutboundTags: []string{"proxy-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(observer.checkedTags) != 1 || observer.checkedTags[0] != "proxy-b" {
		t.Fatalf("unexpected checked tags: %v", observer.checkedTags)
	}
	if len(response.Status.Status) != 1 || response.Status.Status[0].OutboundTag != "proxy-b" {
		t.Fatalf("unexpected response: %v", response.Status.Status)
	}
}
