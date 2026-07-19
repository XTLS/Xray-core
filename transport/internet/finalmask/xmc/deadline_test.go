package xmc

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestConnectionDeadlinesRestoreCallerValues(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	recording := &deadlineRecordingConn{Conn: client}
	deadlines := newConnectionDeadlines(recording)
	callerDeadline := time.Now().Add(10 * time.Minute)
	if err := deadlines.setDeadline(callerDeadline); err != nil {
		t.Fatal(err)
	}
	if err := deadlines.beginHandshake(); err != nil {
		t.Fatal(err)
	}

	read, write := recording.currentDeadlines()
	if !read.Before(callerDeadline) || !write.Before(callerDeadline) {
		t.Fatalf("handshake deadlines = %s/%s, caller = %s", read, write, callerDeadline)
	}

	shortReadDeadline := time.Now().Add(time.Second)
	if err := deadlines.setReadDeadline(shortReadDeadline); err != nil {
		t.Fatal(err)
	}
	read, _ = recording.currentDeadlines()
	if !read.Equal(shortReadDeadline) {
		t.Fatalf("read deadline = %s, want %s", read, shortReadDeadline)
	}

	if err := deadlines.endHandshake(); err != nil {
		t.Fatal(err)
	}
	read, write = recording.currentDeadlines()
	if !read.Equal(shortReadDeadline) || !write.Equal(callerDeadline) {
		t.Fatalf("restored deadlines = %s/%s, want %s/%s", read, write, shortReadDeadline, callerDeadline)
	}
}

type deadlineRecordingConn struct {
	net.Conn
	mu    sync.Mutex
	read  time.Time
	write time.Time
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.read = t
	c.write = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.read = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineRecordingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.write = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *deadlineRecordingConn) currentDeadlines() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read, c.write
}
