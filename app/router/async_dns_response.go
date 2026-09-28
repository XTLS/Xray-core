package router

import (
	"context"
	stderrors "errors"
	"net"
	"time"
)

type asyncDNSResponseOutcome uint8

const (
	asyncDNSResponseInvalid asyncDNSResponseOutcome = iota
	asyncDNSResponseFresh
	asyncDNSResponseStale
	asyncDNSResponsePending
	asyncDNSResponseExpired
)

// A valid reply can be successful without providing a usable fresh result.
// Validate the wire shape before classifying expiration as a normal outcome.
func classifyAsyncDNSResponse(response *asyncDNSClassifierResponse, elapsed time.Duration) asyncDNSResponseOutcome {
	if response == nil || len(response.Generation) > 128 {
		return asyncDNSResponseInvalid
	}
	if response.State == "pending" {
		if response.Route != "" || response.Generation != "" || response.TTLMillis != 0 || response.StaleTTLMillis != 0 {
			return asyncDNSResponseInvalid
		}
		return asyncDNSResponsePending
	}
	if response.Route != "ru" && response.Route != "other" {
		return asyncDNSResponseInvalid
	}
	switch response.State {
	case "ready":
		if response.TTLMillis == 0 || response.StaleTTLMillis > 0 && response.StaleTTLMillis < response.TTLMillis {
			return asyncDNSResponseInvalid
		}
		if time.Duration(response.TTLMillis)*time.Millisecond <= elapsed {
			return asyncDNSResponseExpired
		}
		return asyncDNSResponseFresh
	case "stale":
		if response.TTLMillis != 0 || response.StaleTTLMillis == 0 {
			return asyncDNSResponseInvalid
		}
		return asyncDNSResponseStale
	default:
		return asyncDNSResponseInvalid
	}
}

type asyncDNSFailureKind uint8

const (
	asyncDNSFailureTransport asyncDNSFailureKind = iota
	asyncDNSFailureHTTP
	asyncDNSFailureInvalidResponse
	asyncDNSFailureRequest
)

type asyncDNSFetchError struct {
	kind asyncDNSFailureKind
	err  error
}

func (e *asyncDNSFetchError) Error() string { return e.err.Error() }
func (e *asyncDNSFetchError) Unwrap() error { return e.err }

// Counters contain only fixed categories, never error text, URLs or domains.
func (m *AsyncDNSRouteMatcher) recordFetchError(err error) {
	m.stats.errors.Add(1)
	var networkError net.Error
	switch {
	case stderrors.Is(err, context.Canceled):
		m.stats.canceledErrors.Add(1)
		return
	case stderrors.Is(err, context.DeadlineExceeded) || stderrors.As(err, &networkError) && networkError.Timeout():
		m.stats.timeoutErrors.Add(1)
		return
	}
	var failure *asyncDNSFetchError
	if stderrors.As(err, &failure) {
		switch failure.kind {
		case asyncDNSFailureHTTP:
			m.stats.httpErrors.Add(1)
			return
		case asyncDNSFailureInvalidResponse:
			m.stats.invalidResponses.Add(1)
			return
		case asyncDNSFailureRequest:
			m.stats.requestErrors.Add(1)
			return
		}
	}
	m.stats.transportErrors.Add(1)
}

func (m *AsyncDNSRouteMatcher) recordResponse(outcome asyncDNSResponseOutcome) {
	if outcome == asyncDNSResponseInvalid {
		m.stats.errors.Add(1)
		m.stats.invalidResponses.Add(1)
		return
	}
	m.stats.successes.Add(1)
	switch outcome {
	case asyncDNSResponseFresh:
		m.stats.freshResponses.Add(1)
	case asyncDNSResponseStale:
		m.stats.staleResponses.Add(1)
	case asyncDNSResponsePending:
		m.stats.pendingResponses.Add(1)
	case asyncDNSResponseExpired:
		m.stats.expiredResponses.Add(1)
	}
}
