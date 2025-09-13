// Advanced Monitoring and Metrics Collection for Production
package sush

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector provides comprehensive performance monitoring
type MetricsCollector struct {
	// Connection metrics
	ActiveConnections    int64
	TotalConnections     int64
	ConnectionsPerSecond float64

	// Traffic metrics
	BytesReceived   int64
	BytesSent       int64
	PacketsReceived int64
	PacketsSent     int64

	// Performance metrics
	AverageLatency time.Duration
	P95Latency     time.Duration
	P99Latency     time.Duration

	// Error metrics
	ConnectionErrors int64
	ProtocolErrors   int64
	TimeoutErrors    int64

	// Resource metrics
	MemoryUsage               int64
	BufferPoolHitRate         float64
	ConnectionPoolUtilization float64

	// Security metrics
	AuthenticationFailures int64
	DoSAttemptsBlocked     int64
	InvalidRequests        int64

	// Internal state
	mu             sync.RWMutex
	latencyBuckets []time.Duration
	startTime      time.Time
	lastUpdateTime time.Time
}

// LatencyTracker tracks request latencies for percentile calculations
type LatencyTracker struct {
	mu         sync.RWMutex
	samples    []time.Duration
	maxSamples int
	index      int
	full       bool
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker(maxSamples int) *LatencyTracker {
	return &LatencyTracker{
		samples:    make([]time.Duration, maxSamples),
		maxSamples: maxSamples,
	}
}

// Record adds a latency sample
func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.samples[lt.index] = latency
	lt.index++
	if lt.index >= lt.maxSamples {
		lt.index = 0
		lt.full = true
	}
}

// GetPercentile calculates the specified percentile
func (lt *LatencyTracker) GetPercentile(percentile float64) time.Duration {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	size := lt.index
	if lt.full {
		size = lt.maxSamples
	}

	if size == 0 {
		return 0
	}

	// Create a copy for sorting
	samples := make([]time.Duration, size)
	copy(samples, lt.samples[:size])

	// Simple insertion sort for small arrays
	for i := 1; i < len(samples); i++ {
		key := samples[i]
		j := i - 1
		for j >= 0 && samples[j] > key {
			samples[j+1] = samples[j]
			j--
		}
		samples[j+1] = key
	}

	index := int(float64(len(samples)-1) * percentile / 100.0)
	return samples[index]
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		startTime:      time.Now(),
		lastUpdateTime: time.Now(),
		latencyBuckets: make([]time.Duration, 0, 1000),
	}
}

// RecordConnection records a new connection
func (mc *MetricsCollector) RecordConnection() {
	atomic.AddInt64(&mc.ActiveConnections, 1)
	atomic.AddInt64(&mc.TotalConnections, 1)
}

// RecordConnectionClosed records a connection closure
func (mc *MetricsCollector) RecordConnectionClosed() {
	atomic.AddInt64(&mc.ActiveConnections, -1)
}

// RecordTraffic records traffic statistics
func (mc *MetricsCollector) RecordTraffic(bytesReceived, bytesSent int64) {
	atomic.AddInt64(&mc.BytesReceived, bytesReceived)
	atomic.AddInt64(&mc.BytesSent, bytesSent)
	atomic.AddInt64(&mc.PacketsReceived, 1)
	atomic.AddInt64(&mc.PacketsSent, 1)
}

// RecordLatency records request latency
func (mc *MetricsCollector) RecordLatency(latency time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Keep only recent samples for percentile calculation
	if len(mc.latencyBuckets) >= 1000 {
		// Remove oldest 10% to make room
		copy(mc.latencyBuckets, mc.latencyBuckets[100:])
		mc.latencyBuckets = mc.latencyBuckets[:900]
	}

	mc.latencyBuckets = append(mc.latencyBuckets, latency)
}

// RecordError records different types of errors
func (mc *MetricsCollector) RecordError(errorType string) {
	switch errorType {
	case "connection":
		atomic.AddInt64(&mc.ConnectionErrors, 1)
	case "protocol":
		atomic.AddInt64(&mc.ProtocolErrors, 1)
	case "timeout":
		atomic.AddInt64(&mc.TimeoutErrors, 1)
	case "auth":
		atomic.AddInt64(&mc.AuthenticationFailures, 1)
	case "dos":
		atomic.AddInt64(&mc.DoSAttemptsBlocked, 1)
	case "invalid":
		atomic.AddInt64(&mc.InvalidRequests, 1)
	}
}

// UpdateResourceMetrics updates resource utilization metrics
func (mc *MetricsCollector) UpdateResourceMetrics(memoryUsage int64, bufferHitRate, poolUtilization float64) {
	atomic.StoreInt64(&mc.MemoryUsage, memoryUsage)

	mc.mu.Lock()
	mc.BufferPoolHitRate = bufferHitRate
	mc.ConnectionPoolUtilization = poolUtilization
	mc.mu.Unlock()
}

// GetSnapshot returns a snapshot of current metrics
func (mc *MetricsCollector) GetSnapshot() MetricsSnapshot {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	now := time.Now()
	uptime := now.Sub(mc.startTime)

	// Calculate connections per second
	totalConnections := atomic.LoadInt64(&mc.TotalConnections)
	connectionsPerSecond := float64(totalConnections) / uptime.Seconds()

	// Calculate latency percentiles
	p95 := mc.calculatePercentile(95.0)
	p99 := mc.calculatePercentile(99.0)
	avg := mc.calculateAverage()

	return MetricsSnapshot{
		Timestamp: now,
		Uptime:    uptime,

		// Connection metrics
		ActiveConnections:    atomic.LoadInt64(&mc.ActiveConnections),
		TotalConnections:     totalConnections,
		ConnectionsPerSecond: connectionsPerSecond,

		// Traffic metrics
		BytesReceived:   atomic.LoadInt64(&mc.BytesReceived),
		BytesSent:       atomic.LoadInt64(&mc.BytesSent),
		PacketsReceived: atomic.LoadInt64(&mc.PacketsReceived),
		PacketsSent:     atomic.LoadInt64(&mc.PacketsSent),

		// Performance metrics
		AverageLatency: avg,
		P95Latency:     p95,
		P99Latency:     p99,

		// Error metrics
		ConnectionErrors:       atomic.LoadInt64(&mc.ConnectionErrors),
		ProtocolErrors:         atomic.LoadInt64(&mc.ProtocolErrors),
		TimeoutErrors:          atomic.LoadInt64(&mc.TimeoutErrors),
		AuthenticationFailures: atomic.LoadInt64(&mc.AuthenticationFailures),
		DoSAttemptsBlocked:     atomic.LoadInt64(&mc.DoSAttemptsBlocked),
		InvalidRequests:        atomic.LoadInt64(&mc.InvalidRequests),

		// Resource metrics
		MemoryUsage:               atomic.LoadInt64(&mc.MemoryUsage),
		BufferPoolHitRate:         mc.BufferPoolHitRate,
		ConnectionPoolUtilization: mc.ConnectionPoolUtilization,
	}
}

// calculatePercentile calculates latency percentile (requires mu lock)
func (mc *MetricsCollector) calculatePercentile(percentile float64) time.Duration {
	if len(mc.latencyBuckets) == 0 {
		return 0
	}

	// Create sorted copy
	sorted := make([]time.Duration, len(mc.latencyBuckets))
	copy(sorted, mc.latencyBuckets)

	// Simple sort for small arrays
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	index := int(float64(len(sorted)-1) * percentile / 100.0)
	return sorted[index]
}

// calculateAverage calculates average latency (requires mu lock)
func (mc *MetricsCollector) calculateAverage() time.Duration {
	if len(mc.latencyBuckets) == 0 {
		return 0
	}

	var total time.Duration
	for _, latency := range mc.latencyBuckets {
		total += latency
	}

	return total / time.Duration(len(mc.latencyBuckets))
}

// MetricsSnapshot represents a point-in-time snapshot of metrics
type MetricsSnapshot struct {
	Timestamp time.Time
	Uptime    time.Duration

	// Connection metrics
	ActiveConnections    int64
	TotalConnections     int64
	ConnectionsPerSecond float64

	// Traffic metrics
	BytesReceived   int64
	BytesSent       int64
	PacketsReceived int64
	PacketsSent     int64

	// Performance metrics
	AverageLatency time.Duration
	P95Latency     time.Duration
	P99Latency     time.Duration

	// Error metrics
	ConnectionErrors       int64
	ProtocolErrors         int64
	TimeoutErrors          int64
	AuthenticationFailures int64
	DoSAttemptsBlocked     int64
	InvalidRequests        int64

	// Resource metrics
	MemoryUsage               int64
	BufferPoolHitRate         float64
	ConnectionPoolUtilization float64
}

// String provides a human-readable representation of metrics
func (ms MetricsSnapshot) String() string {
	return fmt.Sprintf(`
Sush Protocol Metrics Snapshot
====================================
Timestamp: %s
Uptime: %v

Connections:
   Active: %d
   Total: %d  
   Rate: %.2f/sec

Traffic:
   Received: %s
   Sent: %s
   Packets: %d in, %d out

Performance:
   Avg Latency: %v
   P95 Latency: %v
   P99 Latency: %v

Errors:
   Connection: %d
   Protocol: %d
   Timeout: %d
   Auth Failures: %d
   DoS Blocked: %d
   Invalid Requests: %d

Resources:
   Memory: %s
   Buffer Pool Hit Rate: %.1f%%
   Connection Pool Utilization: %.1f%%
`,
		ms.Timestamp.Format(time.RFC3339),
		ms.Uptime,
		ms.ActiveConnections,
		ms.TotalConnections,
		ms.ConnectionsPerSecond,
		formatBytes(ms.BytesReceived),
		formatBytes(ms.BytesSent),
		ms.PacketsReceived,
		ms.PacketsSent,
		ms.AverageLatency,
		ms.P95Latency,
		ms.P99Latency,
		ms.ConnectionErrors,
		ms.ProtocolErrors,
		ms.TimeoutErrors,
		ms.AuthenticationFailures,
		ms.DoSAttemptsBlocked,
		ms.InvalidRequests,
		formatBytes(ms.MemoryUsage),
		ms.BufferPoolHitRate,
		ms.ConnectionPoolUtilization,
	)
}

// formatBytes formats byte counts in human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// HealthChecker provides system health monitoring
type HealthChecker struct {
	metrics    *MetricsCollector
	thresholds HealthThresholds
}

// HealthThresholds defines acceptable operational thresholds
type HealthThresholds struct {
	MaxErrorRate         float64       // Max error rate percentage
	MaxLatencyP95        time.Duration // Max acceptable P95 latency
	MaxMemoryUsage       int64         // Max memory usage in bytes
	MinConnectionPoolHit float64       // Min connection pool hit rate
	MaxConnectionsPerSec float64       // Max sustainable connections/sec
}

// HealthStatus represents the current system health
type HealthStatus struct {
	Overall   string            `json:"overall"`
	Checks    map[string]string `json:"checks"`
	Metrics   MetricsSnapshot   `json:"metrics"`
	Timestamp time.Time         `json:"timestamp"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(metrics *MetricsCollector) *HealthChecker {
	return &HealthChecker{
		metrics: metrics,
		thresholds: HealthThresholds{
			MaxErrorRate:         5.0, // 5% error rate
			MaxLatencyP95:        100 * time.Millisecond,
			MaxMemoryUsage:       1024 * 1024 * 1024, // 1GB
			MinConnectionPoolHit: 80.0,               // 80% hit rate
			MaxConnectionsPerSec: 1000.0,             // 1000 conn/sec
		},
	}
}

// CheckHealth performs comprehensive health check
func (hc *HealthChecker) CheckHealth() HealthStatus {
	snapshot := hc.metrics.GetSnapshot()
	checks := make(map[string]string)

	// Check error rate
	totalRequests := snapshot.TotalConnections
	totalErrors := snapshot.ConnectionErrors + snapshot.ProtocolErrors + snapshot.TimeoutErrors
	errorRate := 0.0
	if totalRequests > 0 {
		errorRate = float64(totalErrors) / float64(totalRequests) * 100.0
	}

	if errorRate <= hc.thresholds.MaxErrorRate {
		checks["error_rate"] = "healthy"
	} else {
		checks["error_rate"] = fmt.Sprintf("unhealthy: %.2f%% > %.2f%%", errorRate, hc.thresholds.MaxErrorRate)
	}

	// Check latency
	if snapshot.P95Latency <= hc.thresholds.MaxLatencyP95 {
		checks["latency"] = "healthy"
	} else {
		checks["latency"] = fmt.Sprintf("unhealthy: %v > %v", snapshot.P95Latency, hc.thresholds.MaxLatencyP95)
	}

	// Check memory usage
	if snapshot.MemoryUsage <= hc.thresholds.MaxMemoryUsage {
		checks["memory"] = "healthy"
	} else {
		checks["memory"] = fmt.Sprintf("unhealthy: %s > %s",
			formatBytes(snapshot.MemoryUsage),
			formatBytes(hc.thresholds.MaxMemoryUsage))
	}

	// Check connection pool performance
	if snapshot.ConnectionPoolUtilization >= hc.thresholds.MinConnectionPoolHit {
		checks["connection_pool"] = "healthy"
	} else {
		checks["connection_pool"] = fmt.Sprintf("degraded: %.1f%% < %.1f%%",
			snapshot.ConnectionPoolUtilization, hc.thresholds.MinConnectionPoolHit)
	}

	// Determine overall health
	overall := "healthy"
	for _, status := range checks {
		if status != "healthy" {
			if overall == "healthy" {
				overall = "degraded"
			}
			if status[:9] == "unhealthy" {
				overall = "unhealthy"
				break
			}
		}
	}

	return HealthStatus{
		Overall:   overall,
		Checks:    checks,
		Metrics:   snapshot,
		Timestamp: time.Now(),
	}
}
