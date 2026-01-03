package sim

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

type Config struct {
	Latency   time.Duration
	Jitter    time.Duration
	Blackhole bool    // If true, writes succeed but data is lost
	RSTProb   float64 // Probability of RST
}

type FaultyConn struct {
	net.Conn
	config Config
	mu     sync.Mutex
}

func Wrap(c net.Conn, config Config) *FaultyConn {
	return &FaultyConn{Conn: c, config: config}
}

func (c *FaultyConn) SetConfig(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = cfg
}

func (c *FaultyConn) delay(cfg Config) {
	if cfg.Latency > 0 {
		d := cfg.Latency
		if cfg.Jitter > 0 {
			j := time.Duration(rand.Int63n(int64(cfg.Jitter)))
			if rand.Intn(2) == 0 {
				d += j
			} else {
				d -= j
			}
		}
		if d > 0 {
			time.Sleep(d)
		}
	}
}

func (c *FaultyConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	cfg := c.config
	c.mu.Unlock()

	if rand.Float64() < cfg.RSTProb {
		c.Conn.Close()
		return 0, errors.New("connection reset by peer")
	}

	c.delay(cfg)

	if cfg.Blackhole {
		return len(b), nil
	}

	return c.Conn.Write(b)
}

func (c *FaultyConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	cfg := c.config
	c.mu.Unlock()

	if rand.Float64() < cfg.RSTProb {
		c.Conn.Close()
		return 0, errors.New("connection reset by peer")
	}

	// Delay on read too?
	// c.delay(cfg)
    // If we delay write, read is delayed naturally?
    // But if we want symmetric latency?
    // Let's delay only Write for simplicity (Send delay).

	return c.Conn.Read(b)
}
