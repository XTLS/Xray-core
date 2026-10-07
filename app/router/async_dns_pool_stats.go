package router

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// At most six configured indices; no endpoint URLs, domains, tokens or errors.
// Elapsed includes client Do and body decode, not server processing latency.
type asyncDNSPoolEndpointCounters struct {
	trace                                                           asyncDNSHTTPTraceCounters
	attempts, successes, pending, timeout, canceled, transport      atomic.Uint64
	http, invalid, request, cooldownSkips                           atomic.Uint64
	http401, http403, http429, http502, http503, http504, httpOther atomic.Uint64
	elapsedLE50, elapsedLE100, elapsedLE150, elapsedGT150           atomic.Uint64
}

type asyncDNSPoolEndpointStats struct {
	Trace                                                           asyncDNSHTTPTraceStats
	Attempts, Successes, Pending, Timeout, Canceled, Transport      uint64
	HTTP, Invalid, Request, CooldownSkips                           uint64
	HTTP401, HTTP403, HTTP429, HTTP502, HTTP503, HTTP504, HTTPOther uint64
	ElapsedLE50, ElapsedLE100, ElapsedLE150, ElapsedGT150           uint64
}

func (p *asyncDNSEndpointPool) observe(endpoint string, response *asyncDNSClassifierResponse, err error, elapsed time.Duration) {
	for i := range p.states {
		if p.states[i].endpoint != endpoint {
			continue
		}
		c := p.states[i].metrics
		c.attempts.Add(1)
		if elapsed <= 50*time.Millisecond {
			c.elapsedLE50.Add(1)
		}
		if elapsed <= 100*time.Millisecond {
			c.elapsedLE100.Add(1)
		}
		if elapsed <= 150*time.Millisecond {
			c.elapsedLE150.Add(1)
		} else {
			c.elapsedGT150.Add(1)
		}
		if err == nil {
			outcome := classifyAsyncDNSResponse(response, elapsed)
			if outcome == asyncDNSResponseInvalid {
				c.invalid.Add(1)
			} else {
				c.successes.Add(1)
				if outcome == asyncDNSResponsePending {
					c.pending.Add(1)
				}
			}
			return
		}
		// Same precedence as recordFetchError; a recovered attempt remains visible.
		var networkError net.Error
		var failure *asyncDNSFetchError
		switch {
		case stderrors.Is(err, context.Canceled):
			c.canceled.Add(1)
		case stderrors.Is(err, context.DeadlineExceeded) || stderrors.As(err, &networkError) && networkError.Timeout():
			c.timeout.Add(1)
		case stderrors.As(err, &failure) && failure.kind == asyncDNSFailureHTTP:
			c.http.Add(1)
			switch failure.statusCode {
			case 401:
				c.http401.Add(1)
			case 403:
				c.http403.Add(1)
			case 429:
				c.http429.Add(1)
			case 502:
				c.http502.Add(1)
			case 503:
				c.http503.Add(1)
			case 504:
				c.http504.Add(1)
			default:
				c.httpOther.Add(1)
			}
		case failure != nil && failure.kind == asyncDNSFailureInvalidResponse:
			c.invalid.Add(1)
		case failure != nil && failure.kind == asyncDNSFailureRequest:
			c.request.Add(1)
		default:
			c.transport.Add(1)
		}
		return
	}
}

func (p *asyncDNSEndpointPool) endpointStats() []asyncDNSPoolEndpointStats {
	out := make([]asyncDNSPoolEndpointStats, len(p.states))
	for i := range p.states {
		c := p.states[i].metrics
		out[i] = asyncDNSPoolEndpointStats{
			Trace: c.trace.snapshot(), Attempts: c.attempts.Load(), Successes: c.successes.Load(), Pending: c.pending.Load(),
			Timeout: c.timeout.Load(), Canceled: c.canceled.Load(), Transport: c.transport.Load(),
			HTTP: c.http.Load(), Invalid: c.invalid.Load(), Request: c.request.Load(), CooldownSkips: c.cooldownSkips.Load(),
			HTTP401: c.http401.Load(), HTTP403: c.http403.Load(), HTTP429: c.http429.Load(), HTTP502: c.http502.Load(), HTTP503: c.http503.Load(), HTTP504: c.http504.Load(), HTTPOther: c.httpOther.Load(),
			ElapsedLE50: c.elapsedLE50.Load(), ElapsedLE100: c.elapsedLE100.Load(), ElapsedLE150: c.elapsedLE150.Load(), ElapsedGT150: c.elapsedGT150.Load(),
		}
	}
	return out
}

func (s asyncDNSPoolEndpointStats) logLine(matcher uint64, index int) string {
	return fmt.Sprintf("async DNS pool endpoint stats matcherID=%d endpointIndex=%d attempts=%d successes=%d pending=%d timeoutErrors=%d canceledErrors=%d transportErrors=%d httpErrors=%d invalidResponses=%d requestErrors=%d cooldownSkips=%d http401=%d http403=%d http429=%d http502=%d http503=%d http504=%d httpOther=%d elapsedLE50Millis=%d elapsedLE100Millis=%d elapsedLE150Millis=%d elapsedGT150Millis=%d", matcher, index, s.Attempts, s.Successes, s.Pending, s.Timeout, s.Canceled, s.Transport, s.HTTP, s.Invalid, s.Request, s.CooldownSkips, s.HTTP401, s.HTTP403, s.HTTP429, s.HTTP502, s.HTTP503, s.HTTP504, s.HTTPOther, s.ElapsedLE50, s.ElapsedLE100, s.ElapsedLE150, s.ElapsedGT150) + s.Trace.logSuffix()
}
