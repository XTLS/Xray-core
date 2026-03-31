package router

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/protobuf/proto"
)

type fakeECHObservatory struct {
	status map[string]extension.ECHStatus
}

func (f *fakeECHObservatory) Start() error { return nil }

func (f *fakeECHObservatory) Close() error { return nil }

func (f *fakeECHObservatory) Type() interface{} { return extension.ObservatoryType() }

func (f *fakeECHObservatory) GetObservation(ctx context.Context) (proto.Message, error) {
	return nil, nil
}

func (f *fakeECHObservatory) GetOutboundECHStatus(ctx context.Context) (map[string]extension.ECHStatus, error) {
	return f.status, nil
}

func TestPreferECHAcceptedCandidatesReturnsAcceptedSubset(t *testing.T) {
	observer := &fakeECHObservatory{
		status: map[string]extension.ECHStatus{
			"a": {Accepted: true},
			"b": {Accepted: false},
			"c": {Accepted: true},
		},
	}

	got := preferECHAcceptedCandidates(context.Background(), observer, []string{"a", "b", "c"})
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("unexpected preferred candidates: got %v, want [a c]", got)
	}
}

func TestPreferECHAcceptedCandidatesFallsBackToOriginalCandidates(t *testing.T) {
	observer := &fakeECHObservatory{
		status: map[string]extension.ECHStatus{
			"a": {Accepted: false},
			"b": {Accepted: false},
		},
	}

	got := preferECHAcceptedCandidates(context.Background(), observer, []string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected fallback candidates: got %v, want [a b]", got)
	}
}
