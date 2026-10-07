package router

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"time"
)

// Missing callbacks/durations are -1, not zero. Offsets use Go's monotonic
// clock. TCP_INFO is observational: RTT on reused connections is historical,
// and unavailable snapshots do not imply a healthy network.
type asyncDNSTCPInfo struct {
	Status                                                   string
	RTTMicros, RTOmicros, Unacked, Retransmits, TotalRetrans int64
}

func asyncDNSTCPUnavailable(status string) asyncDNSTCPInfo {
	return asyncDNSTCPInfo{status, -1, -1, -1, -1, -1}
}

type asyncDNSHTTPErrorSample struct {
	At                                                                           time.Time
	Outcome, NetOp                                                               string
	Phase                                                                        int
	Reused                                                                       bool
	AcquireMicros, AcquiredAtMicros, WroteAtMicros, FirstByteAtMicros, EndMicros int64
	TCPAcquire, TCPFailure                                                       asyncDNSTCPInfo
	RetransDelta                                                                 int64
	HTTPStatus                                                                   int
	AttemptDeadlineRemainingMicros                                               int64
}

func asyncDNSOffset(start, at time.Time) int64 {
	if start.IsZero() || at.IsZero() {
		return -1
	}
	return at.Sub(start).Microseconds()
}

func (t *asyncDNSHTTPAttemptTrace) recordErrorSample(err error, end time.Time) {
	// Called under the attempt lock; callbacks cannot race timing/connection reads.
	sample := asyncDNSHTTPErrorSample{
		At: end.UTC(), Outcome: "transport", NetOp: "none", Phase: t.latest, Reused: t.reused,
		AcquireMicros: asyncDNSOffset(t.acquireStarted, t.acquired), AcquiredAtMicros: asyncDNSOffset(t.started, t.acquired),
		WroteAtMicros: asyncDNSOffset(t.started, t.wrote), FirstByteAtMicros: asyncDNSOffset(t.started, t.firstByte), EndMicros: asyncDNSOffset(t.started, end),
		TCPAcquire: t.tcpAtAcquire, TCPFailure: asyncDNSReadTCPInfo(t.conn), RetransDelta: -1, AttemptDeadlineRemainingMicros: -1,
	}
	if !t.deadline.IsZero() {
		sample.AttemptDeadlineRemainingMicros = t.deadline.Sub(end).Microseconds()
	}
	if sample.TCPAcquire.Status == "" {
		sample.TCPAcquire = asyncDNSTCPUnavailable("unavailable")
	}
	var network net.Error
	var failure *asyncDNSFetchError
	switch {
	case stderrors.Is(err, context.Canceled):
		sample.Outcome = "cancel"
	case stderrors.Is(err, context.DeadlineExceeded) || stderrors.As(err, &network) && network.Timeout():
		sample.Outcome = "timeout"
	case stderrors.As(err, &failure):
		switch failure.kind {
		case asyncDNSFailureHTTP:
			sample.Outcome = "http"
			switch failure.statusCode {
			case 401, 403, 429, 502, 503, 504:
				sample.HTTPStatus = failure.statusCode
			default:
				sample.HTTPStatus = -1
			}
		case asyncDNSFailureInvalidResponse:
			sample.Outcome = "invalid"
		case asyncDNSFailureRequest:
			sample.Outcome = "request"
		}
	}
	var op *net.OpError
	if stderrors.As(err, &op) {
		switch op.Op {
		case "dial", "read", "write":
			sample.NetOp = op.Op
		default:
			sample.NetOp = "other"
		}
	}
	sample.RetransDelta = asyncDNSTCPRetransDelta(sample.TCPAcquire, sample.TCPFailure)
	c := t.counters
	c.samplesMu.Lock()
	defer c.samplesMu.Unlock()
	if c.sampleCount == len(c.samples) {
		c.sampleDiscarded++
		return
	}
	c.samples[c.sampleCount] = sample
	c.sampleCount++
}

// Drain only from the existing minute logger, never from Stats(). Four per
// configured endpoint (at most six) bounds retained samples at 24 per interval.
func (c *asyncDNSHTTPTraceCounters) takeErrorSamples() ([]asyncDNSHTTPErrorSample, uint64) {
	c.samplesMu.Lock()
	defer c.samplesMu.Unlock()
	samples := append([]asyncDNSHTTPErrorSample(nil), c.samples[:c.sampleCount]...)
	discarded := c.sampleDiscarded
	clear(c.samples[:])
	c.sampleCount = 0
	c.sampleDiscarded = 0
	return samples, discarded
}

func (s asyncDNSHTTPErrorSample) logLine(matcher uint64, index int) string {
	return fmt.Sprintf("async DNS HTTP error sample matcher=%d endpointIndex=%d at=%s outcome=%s phase=%d netOp=%s reused=%t acquireMicros=%d acquiredAtMicros=%d wroteAtMicros=%d firstByteAtMicros=%d endMicros=%d tcpAcquire=%s tcpFailure=%s acquireRTTMicros=%d acquireRTOMicros=%d acquireUnacked=%d acquireRetransmits=%d acquireTotalRetrans=%d failureRTTMicros=%d failureRTOMicros=%d failureUnacked=%d failureRetransmits=%d failureTotalRetrans=%d retransDelta=%d httpStatus=%d attemptDeadlineRemainingMicros=%d", matcher, index, s.At.Format(time.RFC3339Nano), s.Outcome, s.Phase, s.NetOp, s.Reused, s.AcquireMicros, s.AcquiredAtMicros, s.WroteAtMicros, s.FirstByteAtMicros, s.EndMicros, s.TCPAcquire.Status, s.TCPFailure.Status, s.TCPAcquire.RTTMicros, s.TCPAcquire.RTOmicros, s.TCPAcquire.Unacked, s.TCPAcquire.Retransmits, s.TCPAcquire.TotalRetrans, s.TCPFailure.RTTMicros, s.TCPFailure.RTOmicros, s.TCPFailure.Unacked, s.TCPFailure.Retransmits, s.TCPFailure.TotalRetrans, s.RetransDelta, s.HTTPStatus, s.AttemptDeadlineRemainingMicros)
}

// Only paired observations of the same existing connection have a delta.
func asyncDNSTCPRetransDelta(acquired, failed asyncDNSTCPInfo) int64 {
	if acquired.Status != "available" || failed.Status != "available" || acquired.TotalRetrans < 0 || failed.TotalRetrans < acquired.TotalRetrans {
		return -1
	}
	return failed.TotalRetrans - acquired.TotalRetrans
}
