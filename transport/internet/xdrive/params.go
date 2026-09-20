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
)

type params struct {
	names
	segmentBytes    int
	flushInterval   time.Duration
	minPollInterval time.Duration
	maxPollInterval time.Duration
	eagerWindow     time.Duration
	holeTimeout     time.Duration
	sessionTTL      time.Duration
	concurrency     int
}

func millis(value uint32, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func seconds(value uint32, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return time.Duration(value) * time.Second
}

func capped(value uint32, fallback, limit int) int {
	if value == 0 {
		return fallback
	}
	if int(value) > limit {
		return limit
	}
	return int(value)
}

func paramsFromConfig(c *Config) params {
	p := params{
		names:           namesFromConfig(c),
		segmentBytes:    capped(c.SegmentBytes, defaultSegmentBytes, maxSegmentBytes),
		flushInterval:   millis(c.FlushIntervalMs, defaultFlushInterval),
		minPollInterval: millis(c.PollIntervalMs, defaultMinPollInterval),
		maxPollInterval: millis(c.MaxPollIntervalMs, defaultMaxPollInterval),
		eagerWindow:     millis(c.EagerWindowMs, defaultEagerWindow),
		holeTimeout:     millis(c.HoleTimeoutMs, defaultHoleTimeout),
		sessionTTL:      seconds(c.SessionTtlSeconds, defaultSessionTTL),
		concurrency:     capped(c.Concurrency, defaultConcurrency, maxConcurrency),
	}
	if p.maxPollInterval < p.minPollInterval {
		p.maxPollInterval = p.minPollInterval
	}
	return p
}
