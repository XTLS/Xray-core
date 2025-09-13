// package sush implements fallback and active probing resistance
package sush

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

// FallbackManager manages fallback mechanisms
type FallbackManager struct {
	config *FallbackConfig
}

// FallbackConfig represents fallback configuration
type FallbackConfig struct {
	Dest    string `json:"dest"`
	Type    string `json:"type"`
	Timeout int    `json:"timeout"`
	Retries int    `json:"retries"`
}

// NewFallbackManager creates a new fallback manager
func NewFallbackManager(config *FallbackConfig) *FallbackManager {
	return &FallbackManager{
		config: config,
	}
}

// HandleFallback handles non-Sush traffic
func (fm *FallbackManager) HandleFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	switch fm.config.Type {
	case "http":
		return fm.handleHTTPFallback(ctx, conn, reader)
	case "tcp":
		return fm.handleTCPFallback(ctx, conn, reader)
	case "websocket":
		return fm.handleWebSocketFallback(ctx, conn, reader)
	default:
		return fm.handleHTTPFallback(ctx, conn, reader)
	}
}

// handleHTTPFallback handles HTTP fallback
func (fm *FallbackManager) handleHTTPFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	// Parse fallback URL
	fallbackURL, err := url.Parse(fm.config.Dest)
	if err != nil {
		return fmt.Errorf("invalid fallback URL: %w", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(fallbackURL)

	// Create custom connection that includes peeked data
	customConn := &peekedConn{
		Conn:   conn,
		reader: reader,
	}

	// Create HTTP server
	server := &http.Server{
		Handler:     proxy,
		ReadTimeout: time.Duration(fm.config.Timeout) * time.Second,
	}

	// Create a single connection listener
	listener := &singleConnListener{conn: customConn}

	// Handle the connection
	return server.Serve(listener)
}

// handleTCPFallback handles TCP fallback
func (fm *FallbackManager) handleTCPFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	// Parse fallback destination
	fallbackAddr, err := net.ResolveTCPAddr("tcp", fm.config.Dest)
	if err != nil {
		return fmt.Errorf("invalid fallback address: %w", err)
	}

	// Create connection to fallback destination
	fallbackConn, err := net.DialTCP("tcp", nil, fallbackAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to fallback: %w", err)
	}
	defer fallbackConn.Close()

	// Create custom connection with peeked data
	customConn := &peekedConn{
		Conn:   conn,
		reader: reader,
	}

	// Proxy data between connections
	return fm.proxyConnections(ctx, customConn, fallbackConn)
}

// handleWebSocketFallback handles WebSocket fallback
func (fm *FallbackManager) handleWebSocketFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	// WebSocket fallback implementation
	// This would involve WebSocket handshake and proxying
	return fmt.Errorf("WebSocket fallback not implemented")
}

// proxyConnections proxies data between two connections
func (fm *FallbackManager) proxyConnections(ctx context.Context, conn1, conn2 net.Conn) error {
	done := make(chan error, 2)

	// Proxy from conn1 to conn2
	go func() {
		_, err := io.Copy(conn2, conn1)
		done <- err
	}()

	// Proxy from conn2 to conn1
	go func() {
		_, err := io.Copy(conn1, conn2)
		done <- err
	}()

	// Wait for one connection to close
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// peekedConn wraps a connection with a buffered reader
type peekedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads from the buffered reader
func (pc *peekedConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

// ActiveProbeDetector detects active probing attempts
type ActiveProbeDetector struct {
	patterns [][]byte
	timeout  time.Duration
}

// NewActiveProbeDetector creates a new active probe detector
func NewActiveProbeDetector() *ActiveProbeDetector {
	return &ActiveProbeDetector{
		patterns: [][]byte{
			[]byte("GET / HTTP/1.1"),
			[]byte("POST / HTTP/1.1"),
			[]byte("HEAD / HTTP/1.1"),
			[]byte("OPTIONS / HTTP/1.1"),
		},
		timeout: 5 * time.Second,
	}
}

// IsActiveProbe checks if the data looks like an active probe
func (apd *ActiveProbeDetector) IsActiveProbe(data []byte) bool {
	// Check for common probe patterns
	for _, pattern := range apd.patterns {
		if len(data) >= len(pattern) {
			if string(data[:len(pattern)]) == string(pattern) {
				return true
			}
		}
	}

	// Check for suspicious characteristics
	if len(data) < 10 || len(data) > 1024 {
		return true
	}

	// Check for non-printable characters (might be binary data)
	printableCount := 0
	for _, b := range data {
		if b >= 32 && b <= 126 {
			printableCount++
		}
	}

	// If less than 80% printable, might be a probe
	if float64(printableCount)/float64(len(data)) < 0.8 {
		return true
	}

	return false
}

// PlausibleDeniabilityManager manages plausible deniability
type PlausibleDeniabilityManager struct {
	fallbackMgr   *FallbackManager
	probeDetector *ActiveProbeDetector
}

// NewPlausibleDeniabilityManager creates a new plausible deniability manager
func NewPlausibleDeniabilityManager(fallbackConfig *FallbackConfig) *PlausibleDeniabilityManager {
	return &PlausibleDeniabilityManager{
		fallbackMgr:   NewFallbackManager(fallbackConfig),
		probeDetector: NewActiveProbeDetector(),
	}
}

// HandleConnection handles a connection with plausible deniability
func (pdm *PlausibleDeniabilityManager) HandleConnection(ctx context.Context, conn net.Conn, reader *bufio.Reader, issush bool) error {
	if issush {
		// This is a legitimate Sush connection
		return nil
	}

	// Check if this looks like an active probe
	peekedData, err := reader.Peek(1024)
	if err != nil {
		// If we can't peek, assume it's not a probe
		return pdm.fallbackMgr.HandleFallback(ctx, conn, reader)
	}

	if pdm.probeDetector.IsActiveProbe(peekedData) {
		// This looks like an active probe, use fallback
		return pdm.fallbackMgr.HandleFallback(ctx, conn, reader)
	}

	// Regular fallback for non-Sush traffic
	return pdm.fallbackMgr.HandleFallback(ctx, conn, reader)
}

// singleConnListener implements net.Listener for a single connection
type singleConnListener struct {
	conn net.Conn
	used bool
	mu   sync.Mutex
}

func (scl *singleConnListener) Accept() (net.Conn, error) {
	scl.mu.Lock()
	defer scl.mu.Unlock()

	if scl.used {
		return nil, io.EOF
	}
	scl.used = true
	return scl.conn, nil
}

func (scl *singleConnListener) Close() error {
	return scl.conn.Close()
}

func (scl *singleConnListener) Addr() net.Addr {
	return scl.conn.LocalAddr()
}
