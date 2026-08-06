package splithttp

import (
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestH1UploadPoolClosesIdleConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pool := newH1UploadPool(20 * time.Millisecond)
	conn := NewH1Conn(client)
	if !pool.Add(conn) {
		t.Fatal("Add() rejected an open pool")
	}
	pool.Release(conn)
	defer pool.Close()

	server.SetReadDeadline(time.Now().Add(time.Second))
	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("idle connection was not closed: %v", err)
	}
}

func TestH1UploadPoolGetCancelsIdleClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pool := newH1UploadPool(time.Hour)
	conn := NewH1Conn(client)
	if !pool.Add(conn) {
		t.Fatal("Add() rejected an open pool")
	}
	pool.Release(conn)
	pool.mu.Lock()
	generation := pool.conns[conn].generation
	pool.mu.Unlock()

	conn = pool.Get()
	if conn == nil {
		t.Fatal("Get() returned no connection")
	}
	defer conn.Close()

	pool.closeIdle(conn, generation)
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := server.Read(buffer)
		readDone <- err
	}()

	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatalf("connection was closed while checked out: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("failed to read checked-out connection: %v", err)
	}
}

func TestDefaultDialerClientCloseClosesIdleConnections(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pool := newH1UploadPool(time.Hour)
	conn := NewH1Conn(client)
	if !pool.Add(conn) {
		t.Fatal("Add() rejected an open pool")
	}
	pool.Release(conn)
	clientUnderTest := &DefaultDialerClient{
		client:        &http.Client{},
		uploadRawPool: pool,
	}
	if err := clientUnderTest.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	server.SetReadDeadline(time.Now().Add(time.Second))
	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("idle connection was not closed: %v", err)
	}
}

func TestH1UploadPoolCloseClosesCheckedOutConnections(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pool := newH1UploadPool(time.Hour)
	conn := NewH1Conn(client)
	if !pool.Add(conn) {
		t.Fatal("Add() rejected an open pool")
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	server.SetReadDeadline(time.Now().Add(time.Second))
	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("checked-out connection was not closed: %v", err)
	}

	pool.Release(conn)
}
