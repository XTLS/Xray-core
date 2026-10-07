package router

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAsyncDNSPoolLateOutcomeDisjointPartition(t *testing.T) {
	ready := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 5000}
	cases := []struct {
		name       string
		response   *asyncDNSClassifierResponse
		err, cause error
		want       string
	}{
		{"ready", ready, nil, nil, "success"},
		{"pending", &asyncDNSClassifierResponse{State: "pending"}, nil, nil, "success"},
		{"stale", &asyncDNSClassifierResponse{State: "stale", Route: "ru", StaleTTLMillis: 5000}, nil, nil, "success"},
		{"invalid-nil-error", &asyncDNSClassifierResponse{State: "ready", Route: "invalid"}, nil, nil, "failure"},
		{"invalid-nil-response", nil, nil, nil, "failure"},
		{"timeout", nil, context.DeadlineExceeded, nil, "failure"},
		{"transport", nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: errors.New("controlled failure")}, nil, "failure"},
		{"http", nil, &asyncDNSFetchError{kind: asyncDNSFailureHTTP, statusCode: 503}, nil, "failure"},
		{"invalid-error", nil, &asyncDNSFetchError{kind: asyncDNSFailureInvalidResponse}, nil, "failure"},
		{"request", nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest}, nil, "failure"},
		{"winner-cancel", nil, context.Canceled, asyncDNSPoolWinnerCancel, "winner"},
		{"terminal-cancel", nil, context.Canceled, asyncDNSPoolTerminalCancel, "terminal"},
		{"caller-cancel", nil, context.Canceled, nil, "caller"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &asyncDNSEndpointPool{states: []asyncDNSEndpointState{{endpoint: "exact", metrics: &asyncDNSPoolEndpointCounters{}}}}
			p.startAttempt("exact", false)
			before := p.endpointStats()[0]
			if before.Started != 1 || before.Attempts != 0 || before.ElapsedGT150 != 0 || before.SuccessGT150+before.WinnerCanceledGT150+before.OperationCanceledGT150+before.CallerCanceledGT150+before.FailureGT150 != 0 {
				t.Fatalf("inflight fabricated terminal outcome: %+v", before)
			}
			p.observeCause("exact", tc.response, tc.err, 151*time.Millisecond, tc.cause)
			s := p.endpointStats()[0]
			buckets := map[string]uint64{"success": s.SuccessGT150, "winner": s.WinnerCanceledGT150, "terminal": s.OperationCanceledGT150, "caller": s.CallerCanceledGT150, "failure": s.FailureGT150}
			for name, n := range buckets {
				want := uint64(0)
				if name == tc.want {
					want = 1
				}
				if n != want {
					t.Fatalf("wrong disjoint bucket %s=%d want=%d: %+v", name, n, want, s)
				}
			}
			if s.Started != 1 || s.Attempts != 1 || s.ElapsedGT150 != 1 || s.SuccessGT150+s.WinnerCanceledGT150+s.OperationCanceledGT150+s.CallerCanceledGT150+s.FailureGT150 != s.ElapsedGT150 {
				t.Fatalf("late partition mismatch: %+v", s)
			}
			if s.Attempts != s.Successes+s.Timeout+s.Canceled+s.Transport+s.HTTP+s.Invalid+s.Request+s.WinnerCanceled+s.OperationCanceled {
				t.Fatalf("terminal partition mismatch: %+v", s)
			}
		})
	}
}

func TestAsyncDNSPoolLateBoundaryPreservesOriginalHistogram(t *testing.T) {
	p := &asyncDNSEndpointPool{states: []asyncDNSEndpointState{{endpoint: "exact", metrics: &asyncDNSPoolEndpointCounters{}}}}
	for _, ms := range []int{50, 100, 150, 151} {
		p.startAttempt("exact", false)
		p.observeCause("exact", nil, context.Canceled, time.Duration(ms)*time.Millisecond, asyncDNSPoolWinnerCancel)
	}
	s := p.endpointStats()[0]
	if s.Started != 4 || s.Attempts != 4 || s.WinnerCanceled != 4 || s.ElapsedLE50 != 1 || s.ElapsedLE100 != 2 || s.ElapsedLE150 != 3 || s.ElapsedGT150 != 1 || s.WinnerCanceledGT150 != 1 || s.SuccessGT150+s.OperationCanceledGT150+s.CallerCanceledGT150+s.FailureGT150 != 0 {
		t.Fatalf("original histogram changed: %+v", s)
	}
}
