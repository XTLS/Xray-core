package xmc

import (
	"net"
	"sync"
	"time"
)

const handshakeTimeout = 2 * time.Minute

type connectionDeadlines struct {
	mu sync.Mutex
	c  net.Conn

	read      time.Time
	write     time.Time
	handshake time.Time
}

func newConnectionDeadlines(c net.Conn) *connectionDeadlines {
	return &connectionDeadlines{c: c}
}

func (d *connectionDeadlines) beginHandshake() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.handshake = time.Now().Add(handshakeTimeout)
	if err := d.applyLocked(); err != nil {
		d.handshake = time.Time{}
		_ = d.applyLocked()
		return err
	}
	return nil
}

func (d *connectionDeadlines) endHandshake() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.handshake = time.Time{}
	return d.applyLocked()
}

func (d *connectionDeadlines) setDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.read = t
	d.write = t
	return d.applyLocked()
}

func (d *connectionDeadlines) setReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.read = t
	return d.c.SetReadDeadline(earlierDeadline(d.read, d.handshake))
}

func (d *connectionDeadlines) setWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.write = t
	return d.c.SetWriteDeadline(earlierDeadline(d.write, d.handshake))
}

func (d *connectionDeadlines) applyLocked() error {
	if err := d.c.SetReadDeadline(earlierDeadline(d.read, d.handshake)); err != nil {
		return err
	}
	return d.c.SetWriteDeadline(earlierDeadline(d.write, d.handshake))
}

func earlierDeadline(user, internal time.Time) time.Time {
	if internal.IsZero() {
		return user
	}
	if user.IsZero() || internal.Before(user) {
		return internal
	}
	return user
}
