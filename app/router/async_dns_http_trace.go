package router

import (
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

// Fixed client phases, independent of existing error/outcome counters. Header
// waiting includes transit/auth/handler time; it is not server latency.
const (
	asyncDNSHTTPRequest = iota
	asyncDNSHTTPAcquire
	asyncDNSHTTPWrite
	asyncDNSHTTPHeaders
	asyncDNSHTTPFirstByte
	asyncDNSHTTPBody
	asyncDNSHTTPDecode
	asyncDNSHTTPComplete
	asyncDNSHTTPPhaseCount
)

type asyncDNSHTTPTraceCounters struct {
	samplesMu                                             sync.Mutex
	samples                                               [4]asyncDNSHTTPErrorSample
	sampleCount                                           int
	sampleDiscarded                                       uint64
	phases                                                [asyncDNSHTTPPhaseCount]atomic.Uint64
	newConn, reusedConn, firstByte                        atomic.Uint64
	acquireLE50, acquireLE100, acquireLE150, acquireGT150 atomic.Uint64
	netNone, netDial, netRead, netWrite, netOther         atomic.Uint64
}
type asyncDNSHTTPTraceStats struct {
	Phases                                                                     [asyncDNSHTTPPhaseCount]uint64
	FirstByte                                                                  uint64
	NewConn, ReusedConn, AcquireLE50, AcquireLE100, AcquireLE150, AcquireGT150 uint64
	NetNone, NetDial, NetRead, NetWrite, NetOther                              uint64
}

func (c *asyncDNSHTTPTraceCounters) snapshot() asyncDNSHTTPTraceStats {
	s := asyncDNSHTTPTraceStats{FirstByte: c.firstByte.Load(), NewConn: c.newConn.Load(), ReusedConn: c.reusedConn.Load(), AcquireLE50: c.acquireLE50.Load(), AcquireLE100: c.acquireLE100.Load(), AcquireLE150: c.acquireLE150.Load(), AcquireGT150: c.acquireGT150.Load(), NetNone: c.netNone.Load(), NetDial: c.netDial.Load(), NetRead: c.netRead.Load(), NetWrite: c.netWrite.Load(), NetOther: c.netOther.Load()}
	for i := range s.Phases {
		s.Phases[i] = c.phases[i].Load()
	}
	return s
}

func (s asyncDNSHTTPTraceStats) logSuffix() string {
	return fmt.Sprintf(" phaseRequest=%d phaseAcquire=%d phaseWrite=%d phaseHeaders=%d phaseFirstByte=%d phaseBody=%d phaseDecode=%d phaseComplete=%d newConnections=%d reusedConnections=%d firstResponseBytes=%d acquireLE50Millis=%d acquireLE100Millis=%d acquireLE150Millis=%d acquireGT150Millis=%d netOpNone=%d netOpDial=%d netOpRead=%d netOpWrite=%d netOpOther=%d", s.Phases[0], s.Phases[1], s.Phases[2], s.Phases[3], s.Phases[4], s.Phases[5], s.Phases[6], s.Phases[7], s.NewConn, s.ReusedConn, s.FirstByte, s.AcquireLE50, s.AcquireLE100, s.AcquireLE150, s.AcquireGT150, s.NetNone, s.NetDial, s.NetRead, s.NetWrite, s.NetOther)
}

type asyncDNSHTTPAttemptTrace struct {
	counters                            *asyncDNSHTTPTraceCounters
	mu                                  sync.Mutex
	latest                              int
	acquireStarted                      time.Time
	finished                            bool
	firstByteSeen                       bool
	started, acquired, wrote, firstByte time.Time
	deadline                            time.Time
	conn                                net.Conn
	reused                              bool
	tcpAtAcquire                        asyncDNSTCPInfo
}

func (m *AsyncDNSRouteMatcher) newHTTPAttemptTrace(endpoint string) *asyncDNSHTTPAttemptTrace {
	if m.pool == nil {
		return nil
	}
	for i := range m.pool.states {
		if m.pool.states[i].endpoint == endpoint {
			return &asyncDNSHTTPAttemptTrace{counters: &m.pool.states[i].metrics.trace, started: time.Now()}
		}
	}
	return nil
}

func (t *asyncDNSHTTPAttemptTrace) phase(phase int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.finished && phase > t.latest {
		t.latest = phase
	}
}

func (t *asyncDNSHTTPAttemptTrace) request(req *http.Request) *http.Request {
	if t == nil {
		return req
	}
	t.deadline, _ = req.Context().Deadline()
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.finished {
				t.acquireStarted = time.Now()
				t.latest = asyncDNSHTTPAcquire
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.finished {
				return
			}
			t.latest = asyncDNSHTTPWrite
			t.acquired = time.Now()
			t.conn, t.reused = info.Conn, info.Reused
			t.tcpAtAcquire = asyncDNSReadTCPInfo(info.Conn)
			if info.Reused {
				t.counters.reusedConn.Add(1)
			} else {
				t.counters.newConn.Add(1)
			}
			// Completed GetConn→GotConn acquisition only. Failed acquisition has
			// phaseAcquire but no duration bucket; total attempt elapsed is separate.
			if !t.acquireStarted.IsZero() {
				elapsed := t.acquired.Sub(t.acquireStarted)
				if elapsed <= 50*time.Millisecond {
					t.counters.acquireLE50.Add(1)
				}
				if elapsed <= 100*time.Millisecond {
					t.counters.acquireLE100.Add(1)
				}
				if elapsed <= 150*time.Millisecond {
					t.counters.acquireLE150.Add(1)
				} else {
					t.counters.acquireGT150.Add(1)
				}
			}
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.finished && !t.firstByteSeen {
				t.firstByteSeen = true
				t.firstByte = time.Now()
				t.counters.firstByte.Add(1)
				if t.latest < asyncDNSHTTPFirstByte {
					t.latest = asyncDNSHTTPFirstByte
				}
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				t.mu.Lock()
				if !t.finished {
					t.wrote = time.Now()
					if t.latest < asyncDNSHTTPHeaders {
						t.latest = asyncDNSHTTPHeaders
					}
				}
				t.mu.Unlock()
			}
		},
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}

func (t *asyncDNSHTTPAttemptTrace) finish(err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finished = true
	t.counters.phases[t.latest].Add(1)
	if err != nil {
		t.recordErrorSample(err, time.Now())
	}
	var op *net.OpError
	if !stderrors.As(err, &op) {
		t.counters.netNone.Add(1)
		return
	}
	switch op.Op {
	case "dial":
		t.counters.netDial.Add(1)
	case "read":
		t.counters.netRead.Add(1)
	case "write":
		t.counters.netWrite.Add(1)
	default:
		t.counters.netOther.Add(1)
	}
}
