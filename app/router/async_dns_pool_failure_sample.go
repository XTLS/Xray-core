package router

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net"
	"sync"
	"time"
)

// Scalar-only diagnostic data. No endpoint string or caller payload enters this
// type, including on error paths. Existing route/endpoint schemas are unchanged.
type asyncDNSPoolCandidateSample struct {
	Index, Ordinal        int
	Failures              uint8
	KnownFailed, Selected bool
	Cooldown              int64
}
type asyncDNSPoolAttemptSample struct {
	Index, Ordinal                                 int
	KnownFailed, Hedge                             bool
	Launch, Remaining, ChildBudget, TerminalOffset int64
	Phase                                          int
	Acquire, Wrote, FirstByte                      int64
	Reused                                         bool
	NetOp                                          int
	Terminal, Cause                                string
}
type asyncDNSPoolFailureSample struct {
	Budget, Elapsed int64
	Deadline        bool
	MaxConcurrent   int
	Terminal        string
	Candidates      []asyncDNSPoolCandidateSample
	Attempts        []asyncDNSPoolAttemptSample
}
type asyncDNSPoolFailureBuffer struct {
	mu        sync.Mutex
	samples   [8]string
	count     int
	discarded uint64
}

func (b *asyncDNSPoolFailureBuffer) add(s asyncDNSPoolFailureSample) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count == len(b.samples) {
		b.discarded++
		return
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 4096 || !s.valid() {
		b.discarded++
		return
	}
	b.samples[b.count] = string(raw)
	b.count++
}

func (b *asyncDNSPoolFailureBuffer) take() ([]string, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := append([]string(nil), b.samples[:b.count]...)
	discarded := b.discarded
	b.samples = [8]string{}
	b.count, b.discarded = 0, 0
	return out, discarded
}

func asyncDNSPoolDiagnosticOutcome(r *asyncDNSClassifierResponse, err, cause error) string {
	if err == nil {
		if r == nil {
			return "invalid"
		}
		return "success"
	}
	if stderrors.Is(err, context.Canceled) {
		switch cause {
		case asyncDNSPoolWinnerCancel:
			return "winner_cancel"
		case asyncDNSPoolTerminalCancel:
			return "terminal_cancel"
		}
		return "caller_cancel"
	}
	var n net.Error
	if stderrors.Is(err, context.DeadlineExceeded) || stderrors.As(err, &n) && n.Timeout() {
		return "deadline"
	}
	var f *asyncDNSFetchError
	if stderrors.As(err, &f) {
		switch f.kind {
		case asyncDNSFailureHTTP:
			if f.statusCode == 401 || f.statusCode == 403 {
				return "http_auth"
			}
			if asyncDNSPoolRetryable(err) {
				return "http_retryable"
			}
			return "http_terminal"
		case asyncDNSFailureRequest:
			return "request"
		case asyncDNSFailureInvalidResponse:
			return "invalid"
		}
	}
	return "transport"
}

func asyncDNSPoolDiagnosticCause(cause error) string {
	switch cause {
	case nil:
		return "none"
	case asyncDNSPoolWinnerCancel:
		return "winner"
	case asyncDNSPoolTerminalCancel:
		return "terminal"
	case context.DeadlineExceeded:
		return "deadline"
	default:
		return "caller"
	}
}

func diagnosticTerminalValid(s string) bool {
	switch s {
	case "success", "invalid", "winner_cancel", "terminal_cancel", "caller_cancel", "deadline", "http_auth", "http_retryable", "http_terminal", "request", "transport":
		return true
	}
	return false
}

func (s asyncDNSPoolFailureSample) valid() bool {
	if !diagnosticTerminalValid(s.Terminal) || s.Terminal == "success" || len(s.Candidates) > 6 || len(s.Attempts) > 6 || s.MaxConcurrent > asyncDNSPoolMaxConcurrent || s.MaxConcurrent < 0 {
		return false
	}
	for _, c := range s.Candidates {
		if c.Index < 0 || c.Index >= 6 || c.Ordinal < -1 || c.Ordinal >= 6 || c.Failures > 6 || c.Cooldown < 0 {
			return false
		}
	}
	for _, a := range s.Attempts {
		if a.Index < 0 || a.Index >= 6 || a.Ordinal < 0 || a.Ordinal >= 6 || a.Phase < 0 || a.Phase >= asyncDNSHTTPPhaseCount || a.NetOp < 0 || a.NetOp > 4 || !diagnosticTerminalValid(a.Terminal) {
			return false
		}
		switch a.Cause {
		case "none", "winner", "terminal", "caller", "deadline":
		default:
			return false
		}
	}
	return true
}

type (
	asyncDNSPoolTraceKey    struct{}
	asyncDNSPoolTraceSample struct {
		mu                         sync.Mutex
		phase, netOp               int
		acquired, wrote, firstByte time.Time
		reused                     bool
	}
)

func (s *asyncDNSPoolTraceSample) set(t *asyncDNSHTTPAttemptTrace, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase, s.acquired, s.wrote, s.firstByte, s.reused = t.latest, t.acquired, t.wrote, t.firstByte, t.reused
	var op *net.OpError
	if stderrors.As(err, &op) {
		switch op.Op {
		case "dial":
			s.netOp = 1
		case "read":
			s.netOp = 2
		case "write":
			s.netOp = 3
		default:
			s.netOp = 4
		}
	}
}

func (s *asyncDNSPoolTraceSample) copyTo(a *asyncDNSPoolAttemptSample, started time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.Phase, a.NetOp, a.Reused = s.phase, s.netOp, s.reused
	if !s.acquired.IsZero() {
		a.Acquire = s.acquired.Sub(started).Microseconds()
	}
	if !s.wrote.IsZero() {
		a.Wrote = s.wrote.Sub(started).Microseconds()
	}
	if !s.firstByte.IsZero() {
		a.FirstByte = s.firstByte.Sub(started).Microseconds()
	}
}
