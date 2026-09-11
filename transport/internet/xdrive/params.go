package xdrive

import "time"

const (
	defaultSegmentBytes    = 512 * 1024
	defaultFlushInterval   = 20 * time.Millisecond
	defaultMinPollInterval = 50 * time.Millisecond
	defaultMaxPollInterval = 500 * time.Millisecond
	defaultEagerWindow     = 2 * time.Second
	defaultHoleTimeout     = 30 * time.Second
	defaultSessionTTL      = 5 * time.Minute
	defaultConcurrency     = 8

	maxSegmentBytes = 16 * 1024 * 1024
	maxConcurrency  = 64

	maxCoalescedTicks = 8
)

type params struct {
	segmentBytes    int
	flushInterval   time.Duration
	minPollInterval time.Duration
	maxPollInterval time.Duration
	eagerWindow     time.Duration
	holeTimeout     time.Duration
	sessionTTL      time.Duration
	concurrency     int
}

func paramsFromConfig(config *Config) params {
	p := params{
		segmentBytes:    defaultSegmentBytes,
		flushInterval:   defaultFlushInterval,
		minPollInterval: defaultMinPollInterval,
		maxPollInterval: defaultMaxPollInterval,
		eagerWindow:     defaultEagerWindow,
		holeTimeout:     defaultHoleTimeout,
		sessionTTL:      defaultSessionTTL,
		concurrency:     defaultConcurrency,
	}

	if config.SegmentBytes > 0 {
		p.segmentBytes = int(config.SegmentBytes)
		if p.segmentBytes > maxSegmentBytes {
			p.segmentBytes = maxSegmentBytes
		}
	}
	if config.FlushIntervalMs > 0 {
		p.flushInterval = time.Duration(config.FlushIntervalMs) * time.Millisecond
	}
	if config.PollIntervalMs > 0 {
		p.minPollInterval = time.Duration(config.PollIntervalMs) * time.Millisecond
	}
	if config.MaxPollIntervalMs > 0 {
		p.maxPollInterval = time.Duration(config.MaxPollIntervalMs) * time.Millisecond
	}
	if p.maxPollInterval < p.minPollInterval {
		p.maxPollInterval = p.minPollInterval
	}
	if config.EagerWindowMs > 0 {
		p.eagerWindow = time.Duration(config.EagerWindowMs) * time.Millisecond
	}
	if config.HoleTimeoutMs > 0 {
		p.holeTimeout = time.Duration(config.HoleTimeoutMs) * time.Millisecond
	}
	if config.SessionTtlSeconds > 0 {
		p.sessionTTL = time.Duration(config.SessionTtlSeconds) * time.Second
	}
	if config.Concurrency > 0 {
		p.concurrency = int(config.Concurrency)
		if p.concurrency > maxConcurrency {
			p.concurrency = maxConcurrency
		}
	}
	return p
}
