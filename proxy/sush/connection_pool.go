// Advanced Connection Pooling and Resource Management for Production
package sush

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionPool manages a pool of connections with lifecycle management
type ConnectionPool struct {
	// Pool configuration
	maxConnections    int32
	maxIdleTime       time.Duration
	maxLifetime       time.Duration
	healthCheckPeriod time.Duration

	// Pool state
	activeConnections int32
	idleConnections   chan *PooledConnection
	allConnections    sync.Map // map[*PooledConnection]bool

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool

	// Statistics
	stats ConnectionPoolStats
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	conn       net.Conn
	createdAt  time.Time
	lastUsedAt time.Time
	usageCount int64
	isHealthy  atomic.Bool
	pool       *ConnectionPool
}

// ConnectionPoolStats tracks pool performance
type ConnectionPoolStats struct {
	mu                 sync.RWMutex
	TotalConnections   int64
	ActiveConnections  int64
	IdleConnections    int64
	ConnectionsReused  int64
	ConnectionsCreated int64
	ConnectionsClosed  int64
	HealthChecksPassed int64
	HealthChecksFailed int64
}

// ConnectionPoolConfig configuration for connection pool
type ConnectionPoolConfig struct {
	MaxConnections    int32         `json:"max_connections"`
	MaxIdleTime       time.Duration `json:"max_idle_time"`
	MaxLifetime       time.Duration `json:"max_lifetime"`
	HealthCheckPeriod time.Duration `json:"health_check_period"`
}

// NewConnectionPool creates a new connection pool with advanced lifecycle management
func NewConnectionPool(config *ConnectionPoolConfig) *ConnectionPool {
	if config.MaxConnections <= 0 {
		config.MaxConnections = 100
	}
	if config.MaxIdleTime <= 0 {
		config.MaxIdleTime = 5 * time.Minute
	}
	if config.MaxLifetime <= 0 {
		config.MaxLifetime = 30 * time.Minute
	}
	if config.HealthCheckPeriod <= 0 {
		config.HealthCheckPeriod = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := &ConnectionPool{
		maxConnections:    config.MaxConnections,
		maxIdleTime:       config.MaxIdleTime,
		maxLifetime:       config.MaxLifetime,
		healthCheckPeriod: config.HealthCheckPeriod,
		idleConnections:   make(chan *PooledConnection, config.MaxConnections),
		ctx:               ctx,
		cancel:            cancel,
	}

	// Start background maintenance goroutines
	pool.wg.Add(2)
	go pool.healthChecker()
	go pool.lifetimeManager()

	return pool
}

// Acquire gets a connection from the pool or creates a new one
func (p *ConnectionPool) Acquire(network, address string) (*PooledConnection, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	// Try to get from idle pool first
	select {
	case conn := <-p.idleConnections:
		if conn.isHealthy.Load() && time.Since(conn.lastUsedAt) < p.maxIdleTime {
			conn.lastUsedAt = time.Now()
			atomic.AddInt64(&conn.usageCount, 1)
			atomic.AddInt64(&p.stats.ConnectionsReused, 1)
			return conn, nil
		}
		// Connection is stale, close it
		conn.Close()
	default:
		// No idle connections available
	}

	// Check if we can create a new connection
	current := atomic.LoadInt32(&p.activeConnections)
	if current >= p.maxConnections {
		return nil, ErrPoolExhausted
	}

	// Create new connection
	rawConn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	conn := &PooledConnection{
		conn:       rawConn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		usageCount: 1,
		pool:       p,
	}
	conn.isHealthy.Store(true)

	// Register connection
	p.allConnections.Store(conn, true)
	atomic.AddInt32(&p.activeConnections, 1)
	atomic.AddInt64(&p.stats.ConnectionsCreated, 1)

	return conn, nil
}

// Release returns a connection to the pool
func (p *ConnectionPool) Release(conn *PooledConnection) {
	if p.closed.Load() || !conn.isHealthy.Load() {
		conn.Close()
		return
	}

	conn.lastUsedAt = time.Now()

	// Try to return to idle pool
	select {
	case p.idleConnections <- conn:
		// Successfully returned to pool
	default:
		// Pool is full, close the connection
		conn.Close()
	}
}

// Close gracefully shuts down the connection pool
func (p *ConnectionPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	// Cancel background goroutines
	p.cancel()

	// Close all idle connections
	close(p.idleConnections)
	for conn := range p.idleConnections {
		conn.Close()
	}

	// Close all active connections
	p.allConnections.Range(func(key, value interface{}) bool {
		if conn, ok := key.(*PooledConnection); ok {
			conn.Close()
		}
		return true
	})

	// Wait for background goroutines to finish
	p.wg.Wait()

	return nil
}

// GetStats returns current pool statistics
func (p *ConnectionPool) GetStats() ConnectionPoolStats {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()

	stats := p.stats
	stats.ActiveConnections = int64(atomic.LoadInt32(&p.activeConnections))
	stats.IdleConnections = int64(len(p.idleConnections))

	return stats
}

// healthChecker periodically checks connection health
func (p *ConnectionPool) healthChecker() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.healthCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.performHealthChecks()
		}
	}
}

// lifetimeManager manages connection lifetime
func (p *ConnectionPool) lifetimeManager() {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanupExpiredConnections()
		}
	}
}

// performHealthChecks checks the health of idle connections
func (p *ConnectionPool) performHealthChecks() {
	// Drain idle connections for health checks
	var toCheck []*PooledConnection
	for {
		select {
		case conn := <-p.idleConnections:
			toCheck = append(toCheck, conn)
		default:
			goto checkHealth
		}
	}

checkHealth:
	for _, conn := range toCheck {
		if p.isConnectionHealthy(conn) {
			atomic.AddInt64(&p.stats.HealthChecksPassed, 1)
			// Return healthy connection to pool
			select {
			case p.idleConnections <- conn:
			default:
				conn.Close() // Pool full
			}
		} else {
			atomic.AddInt64(&p.stats.HealthChecksFailed, 1)
			conn.Close()
		}
	}
}

// cleanupExpiredConnections removes connections that exceeded max lifetime
func (p *ConnectionPool) cleanupExpiredConnections() {
	now := time.Now()

	p.allConnections.Range(func(key, value interface{}) bool {
		if conn, ok := key.(*PooledConnection); ok {
			if now.Sub(conn.createdAt) > p.maxLifetime {
				conn.isHealthy.Store(false)
				p.allConnections.Delete(conn)
				// The connection will be closed when released or during health check
			}
		}
		return true
	})
}

// isConnectionHealthy performs a simple health check on a connection
func (p *ConnectionPool) isConnectionHealthy(conn *PooledConnection) bool {
	// Simple health check: try to set read deadline
	err := conn.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		return false
	}

	// Reset deadline
	conn.conn.SetReadDeadline(time.Time{})
	return true
}

// PooledConnection methods

// Read implements net.Conn
func (pc *PooledConnection) Read(b []byte) (n int, err error) {
	if !pc.isHealthy.Load() {
		return 0, ErrConnectionUnhealthy
	}
	return pc.conn.Read(b)
}

// Write implements net.Conn
func (pc *PooledConnection) Write(b []byte) (n int, err error) {
	if !pc.isHealthy.Load() {
		return 0, ErrConnectionUnhealthy
	}
	return pc.conn.Write(b)
}

// Close releases the connection back to the pool
func (pc *PooledConnection) Close() error {
	if pc.pool != nil && pc.isHealthy.Load() {
		pc.pool.Release(pc)
		return nil
	}

	// Actually close the underlying connection
	pc.isHealthy.Store(false)
	if pc.pool != nil {
		pc.pool.allConnections.Delete(pc)
		atomic.AddInt32(&pc.pool.activeConnections, -1)
		atomic.AddInt64(&pc.pool.stats.ConnectionsClosed, 1)
	}

	return pc.conn.Close()
}

// LocalAddr implements net.Conn
func (pc *PooledConnection) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

// RemoteAddr implements net.Conn
func (pc *PooledConnection) RemoteAddr() net.Addr {
	return pc.conn.RemoteAddr()
}

// SetDeadline implements net.Conn
func (pc *PooledConnection) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (pc *PooledConnection) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (pc *PooledConnection) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}

// Errors
var (
	ErrPoolClosed          = fmt.Errorf("connection pool is closed")
	ErrPoolExhausted       = fmt.Errorf("connection pool exhausted")
	ErrConnectionUnhealthy = fmt.Errorf("connection is unhealthy")
)
