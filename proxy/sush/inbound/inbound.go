// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package inbound implements the Sush inbound handler for Xray-core
package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Local type definitions to avoid circular imports

// SushUser represents a Sush user locally
type SushUser struct {
	Account *Account
	Email   string
}

// Account represents a Sush account locally
type Account struct {
	Id     string
	Policy string
}

// Session represents a Sush session locally
type Session struct {
	SharedKey    []byte
	LastActivity time.Time
	User         *SushUser
}

// Frame represents a Sush frame locally
type Frame struct {
	Magic    uint32
	Version  uint8
	Command  uint8
	Length   uint16
	Sequence uint32
	Payload  []byte
}

// Frame command constants
const (
	CmdData        = 0x01
	CmdPaddingCtrl = 0x02
	CmdTimingCtrl  = 0x03
	CmdClose       = 0x04
)

// Frame constants
const (
	FrameHeaderSize  = 12
	MinHandshakeSize = 3
	SushMagicNumber  = 0x53555348 // "SUSH" in hex
)

// HandshakeManager manages handshakes locally
type HandshakeManager struct {
	psk []byte
}

// MemoryValidator validates users locally
type MemoryValidator struct {
	users map[string]*SushUser
	mu    sync.RWMutex
}

// CryptoManager manages encryption locally
type CryptoManager struct {
	key []byte
}

// Handler implements the enhanced Sush inbound handler
type Handler struct {
	users        map[string]*SushUser
	fallback     *FallbackConfig
	psk          []byte
	handshakeMgr *HandshakeManager
	validator    *MemoryValidator
	stats        *HandlerStats
	mu           sync.RWMutex
}

// FallbackConfig represents enhanced fallback configuration
type FallbackConfig struct {
	Dest         string            `json:"dest"`
	Type         string            `json:"type"` // "http", "tcp", "static"
	Path         string            `json:"path,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	StatusCode   int               `json:"status_code,omitempty"`
	ResponseBody string            `json:"response_body,omitempty"`
}

// Config represents the inbound configuration for Sush
type Config struct {
	Users    []*UserConfig   `json:"users"`
	Fallback *FallbackConfig `json:"fallback,omitempty"`
	PSK      string          `json:"psk"`
}

// UserConfig represents a Sush user configuration
type UserConfig struct {
	ID     string `json:"id"`
	Email  string `json:"email,omitempty"`
	Policy string `json:"policy,omitempty"`
}

// HandlerStats tracks overall handler performance
type HandlerStats struct {
	SushConnections     uint64
	FallbackConnections uint64
	HandshakeFailures   uint64
	TotalBytesProcessed uint64
	ActiveConnections   int64
	HTTPFallbacks       uint64
	TCPFallbacks        uint64
	StaticResponses     uint64
	mu                  sync.RWMutex
}

// NewHandshakeManager creates a new handshake manager
func NewHandshakeManager(psk []byte) *HandshakeManager {
	return &HandshakeManager{psk: psk}
}

// NewMemoryValidator creates a new memory validator
func NewMemoryValidator() *MemoryValidator {
	return &MemoryValidator{
		users: make(map[string]*SushUser),
	}
}

// Add adds a user to the validator
func (mv *MemoryValidator) Add(user *SushUser) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	mv.users[user.Account.Id] = user
}

// Validate validates a user
func (mv *MemoryValidator) Validate(id string) (*SushUser, bool) {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	user, exists := mv.users[id]
	return user, exists
}

// NewCryptoManager creates a new crypto manager
func NewCryptoManager(key []byte) (*CryptoManager, error) {
	return &CryptoManager{key: key}, nil
}

// EncryptFrame encrypts a frame (placeholder)
func (cm *CryptoManager) EncryptFrame(frame *Frame) error {
	// Placeholder encryption
	return nil
}

// DecryptFrame decrypts a frame (placeholder)
func (cm *CryptoManager) DecryptFrame(frame *Frame) error {
	// Placeholder decryption
	return nil
}

// IsSushHandshake checks if data contains a Sush handshake
func IsSushHandshake(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// Check for magic number in different endianness
	magic := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	return magic == SushMagicNumber
}

// NewFrame creates a new frame
func NewFrame(command uint8, payload []byte) *Frame {
	return &Frame{
		Magic:   SushMagicNumber,
		Version: 1,
		Command: command,
		Length:  uint16(FrameHeaderSize + len(payload)),
		Payload: payload,
	}
}

// Marshal marshals a frame to bytes
func (f *Frame) Marshal() []byte {
	data := make([]byte, f.Length)
	// Write header
	data[0] = byte(f.Magic >> 24)
	data[1] = byte(f.Magic >> 16)
	data[2] = byte(f.Magic >> 8)
	data[3] = byte(f.Magic)
	data[4] = f.Version
	data[5] = f.Command
	data[6] = byte(f.Length >> 8)
	data[7] = byte(f.Length)
	data[8] = byte(f.Sequence >> 24)
	data[9] = byte(f.Sequence >> 16)
	data[10] = byte(f.Sequence >> 8)
	data[11] = byte(f.Sequence)
	// Write payload
	copy(data[FrameHeaderSize:], f.Payload)
	return data
}

// Unmarshal unmarshals bytes to a frame
func (f *Frame) Unmarshal(data []byte) error {
	if len(data) < FrameHeaderSize {
		return fmt.Errorf("data too short for frame header")
	}
	f.Magic = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	f.Version = data[4]
	f.Command = data[5]
	f.Length = uint16(data[6])<<8 | uint16(data[7])
	f.Sequence = uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11])
	return nil
}

// ServerHandshake performs server-side handshake
func (hm *HandshakeManager) ServerHandshake(ctx context.Context, conn net.Conn, validator *MemoryValidator) (*Session, error) {
	// Simplified handshake - read user ID
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	userID := string(buffer[:n])
	user, exists := validator.Validate(userID)
	if !exists {
		return nil, fmt.Errorf("invalid user: %s", userID)
	}

	// Generate shared key (simplified)
	sharedKey := make([]byte, 32)
	if _, err := rand.Read(sharedKey); err != nil {
		return nil, err
	}

	session := &Session{
		SharedKey:    sharedKey,
		LastActivity: time.Now(),
		User:         user,
	}

	return session, nil
}

// NewSushHandler creates a new enhanced Sush inbound handler
func NewSushHandler(ctx context.Context, config *Config) (*Handler, error) {
	// Create user validator
	validator := NewMemoryValidator()

	// Create PSK (in production, this should be properly derived)
	psk := []byte(config.PSK)

	// Create handshake manager
	handshakeMgr := NewHandshakeManager(psk)

	handler := &Handler{
		users:        make(map[string]*SushUser),
		fallback:     config.Fallback,
		psk:          psk,
		handshakeMgr: handshakeMgr,
		validator:    validator,
		stats:        &HandlerStats{},
	}

	// Add users to handler
	for _, userConfig := range config.Users {
		account := &Account{
			Id:     userConfig.ID,
			Policy: userConfig.Policy,
		}

		user := &SushUser{
			Account: account,
			Email:   userConfig.Email,
		}

		handler.users[userConfig.ID] = user
		validator.Add(user)
	}

	return handler, nil
}

// Network returns the supported networks
func (h *Handler) Network() []string {
	return []string{"tcp", "udp"}
}

// Process handles incoming connections with improved protocol detection
func (h *Handler) Process(ctx context.Context, conn net.Conn) error {
	// Update active connections counter
	h.stats.mu.Lock()
	h.stats.ActiveConnections++
	h.stats.mu.Unlock()

	defer func() {
		h.stats.mu.Lock()
		h.stats.ActiveConnections--
		h.stats.mu.Unlock()
	}()

	// Set connection timeout for initial detection
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Wrap connection in buffered reader for efficient peeking
	bufferedReader := bufio.NewReader(conn)

	// Peek at initial bytes to detect protocol - OPTIMIZED
	peekSize := 16 // Only peek what we need for magic number detection
	initialBytes, err := bufferedReader.Peek(peekSize)
	if err != nil && err != io.EOF {
		// If peeking fails, try fallback
		return h.handleFallback(ctx, conn, nil)
	}

	// Quick magic number check - OPTIMIZED
	if len(initialBytes) >= 3 && IsSushHandshake(initialBytes) {
		// This is Sush traffic
		h.stats.mu.Lock()
		h.stats.SushConnections++
		h.stats.mu.Unlock()

		// Remove read deadline for handshake
		conn.SetReadDeadline(time.Time{})

		return h.processsushConnection(ctx, bufferedReader, conn)
	} else {
		// Not Sush traffic - handle as fallback
		h.stats.mu.Lock()
		h.stats.FallbackConnections++
		h.stats.mu.Unlock()

		// Remove read deadline for fallback
		conn.SetReadDeadline(time.Time{})

		return h.handleFallback(ctx, conn, bufferedReader)
	}
}

// processsushConnection processes a Sush protocol connection
func (h *Handler) processsushConnection(ctx context.Context, reader *bufio.Reader, conn net.Conn) error {
	// Create buffered connection wrapper
	buffConn := &BufferedConn{Conn: conn, reader: reader}

	// Perform handshake
	session, err := h.handshakeMgr.ServerHandshake(ctx, buffConn, h.validator)
	if err != nil {
		h.stats.mu.Lock()
		h.stats.HandshakeFailures++
		h.stats.mu.Unlock()

		fmt.Printf("Sush handshake failed: %v\n", err)
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Process the session
	return h.processSession(ctx, session, reader, conn)
}

// processSession processes an established Sush session
func (h *Handler) processSession(ctx context.Context, session *Session, reader *bufio.Reader, conn net.Conn) error {
	// Create crypto manager
	cryptoMgr, err := NewCryptoManager(session.SharedKey)
	if err != nil {
		return fmt.Errorf("failed to create crypto manager: %w", err)
	}

	// Create frame reader/writer
	frameReader := NewFrameReader(reader, cryptoMgr)
	frameWriter := NewFrameWriter(conn, cryptoMgr)

	// Start processing data stream
	return h.processDataStream(ctx, session, frameReader, frameWriter)
}

// processDataStream processes the data stream
func (h *Handler) processDataStream(ctx context.Context, session *Session, reader *FrameReader, writer *FrameWriter) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read frame
		frame, err := reader.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read frame: %w", err)
		}

		// Process frame based on command
		switch frame.Command {
		case CmdData:
			err = h.processDataFrame(ctx, frame, writer)
		case CmdPaddingCtrl:
			err = h.processPaddingControl(frame)
		case CmdTimingCtrl:
			err = h.processTimingControl(frame)
		case CmdClose:
			return nil // Close connection
		default:
			fmt.Printf("Unknown frame command: %d\n", frame.Command)
		}

		if err != nil {
			return fmt.Errorf("failed to process frame: %w", err)
		}

		// Update session activity
		session.LastActivity = time.Now()

		// Update stats
		h.stats.mu.Lock()
		h.stats.TotalBytesProcessed += uint64(len(frame.Payload))
		h.stats.mu.Unlock()
	}
}

// processDataFrame processes a data frame
func (h *Handler) processDataFrame(ctx context.Context, frame *Frame, writer *FrameWriter) error {
	// For demo purposes, just echo the data back
	responseFrame := NewFrame(CmdData, frame.Payload)
	return writer.WriteFrame(responseFrame)
}

// processPaddingControl processes padding control command
func (h *Handler) processPaddingControl(frame *Frame) error {
	// Parse padding parameters from payload
	return nil
}

// processTimingControl processes timing control command
func (h *Handler) processTimingControl(frame *Frame) error {
	// Parse timing parameters from payload
	return nil
}

// handleFallback handles non-Sush traffic with improved efficiency - SECURE!
func (h *Handler) handleFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	if h.fallback == nil {
		return h.sendDefaultResponse(conn)
	}

	switch h.fallback.Type {
	case "http":
		return h.handleHTTPFallback(ctx, conn, reader)
	case "tcp":
		return h.handleTCPFallback(ctx, conn, reader)
	case "static":
		return h.handleStaticFallback(conn)
	default:
		return h.handleHTTPFallback(ctx, conn, reader) // Default to HTTP
	}
}

// handleHTTPFallback handles HTTP fallback using standard net/http - SECURE!
func (h *Handler) handleHTTPFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	h.stats.mu.Lock()
	h.stats.HTTPFallbacks++
	h.stats.mu.Unlock()

	var reqReader io.Reader = conn
	if reader != nil {
		reqReader = reader
	}

	// DoS protection: Limit request size to prevent memory exhaustion
	const maxRequestSize = 64 * 1024 // 64KB maximum request size
	limitedReader := io.LimitReader(reqReader, maxRequestSize)

	// Read HTTP request using standard library - SECURE!
	req, err := http.ReadRequest(bufio.NewReader(limitedReader))
	if err != nil {
		return h.handleStaticFallback(conn) // Fallback to static response
	}
	defer req.Body.Close()

	// Update request URL to point to fallback destination
	req.URL.Scheme = "http"
	req.URL.Host = h.fallback.Dest
	req.RequestURI = ""

	// Add custom headers if configured
	for key, value := range h.fallback.Headers {
		req.Header.Set(key, value)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true, // Close connections after use
		},
	}

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		return h.handleStaticFallback(conn)
	}
	defer resp.Body.Close()

	// Write response to client
	return resp.Write(conn)
}

// handleTCPFallback handles raw TCP fallback - IMPROVED
func (h *Handler) handleTCPFallback(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	h.stats.mu.Lock()
	h.stats.TCPFallbacks++
	h.stats.mu.Unlock()

	// Connect to fallback destination
	destConn, err := net.DialTimeout("tcp", h.fallback.Dest, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to fallback destination: %w", err)
	}
	defer destConn.Close()

	// If there's buffered data, forward it first
	if reader != nil {
		// Read any buffered data and forward it
		buffered := reader.Buffered()
		if buffered > 0 {
			data := make([]byte, buffered)
			if _, err := reader.Read(data); err == nil {
				destConn.Write(data)
			}
		}
	}

	// Start bidirectional forwarding
	errChan := make(chan error, 2)

	// Client to destination
	go func() {
		var src io.Reader = conn
		if reader != nil {
			src = reader
		}
		_, err := io.Copy(destConn, src)
		errChan <- err
	}()

	// Destination to client
	go func() {
		_, err := io.Copy(conn, destConn)
		errChan <- err
	}()

	// Wait for first error (connection close)
	return <-errChan
}

// handleStaticFallback sends a static response
func (h *Handler) handleStaticFallback(conn net.Conn) error {
	h.stats.mu.Lock()
	h.stats.StaticResponses++
	h.stats.mu.Unlock()

	statusCode := 200
	responseBody := "OK"

	if h.fallback != nil {
		if h.fallback.StatusCode > 0 {
			statusCode = h.fallback.StatusCode
		}
		if h.fallback.ResponseBody != "" {
			responseBody = h.fallback.ResponseBody
		}
	}

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	response += "Content-Type: text/plain\r\n"
	response += fmt.Sprintf("Content-Length: %d\r\n", len(responseBody))
	response += "Connection: close\r\n"

	// Add custom headers if configured
	if h.fallback != nil && h.fallback.Headers != nil {
		for key, value := range h.fallback.Headers {
			response += fmt.Sprintf("%s: %s\r\n", key, value)
		}
	}

	response += "\r\n" + responseBody

	_, err := conn.Write([]byte(response))
	return err
}

// sendDefaultResponse sends a default response when no fallback is available
func (h *Handler) sendDefaultResponse(conn net.Conn) error {
	response := "HTTP/1.1 200 OK\r\n"
	response += "Content-Type: text/plain\r\n"
	response += "Content-Length: 13\r\n"
	response += "Connection: close\r\n"
	response += "\r\n"
	response += "Hello, World!"

	_, err := conn.Write([]byte(response))
	return err
}

// BufferedConn wraps a net.Conn with buffered reading capability
type BufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (bc *BufferedConn) Read(p []byte) (n int, err error) {
	return bc.reader.Read(p)
}

// GetStats returns handler statistics
func (h *Handler) GetStats() HandlerStats {
	h.stats.mu.RLock()
	defer h.stats.mu.RUnlock()
	return *h.stats
}

// FrameReader reads and decrypts Sush frames
type FrameReader struct {
	reader    *bufio.Reader
	cryptoMgr *CryptoManager
}

// NewFrameReader creates a new frame reader
func NewFrameReader(reader *bufio.Reader, cryptoMgr *CryptoManager) *FrameReader {
	return &FrameReader{
		reader:    reader,
		cryptoMgr: cryptoMgr,
	}
}

// ReadFrame reads and decrypts a frame
func (fr *FrameReader) ReadFrame() (*Frame, error) {
	// Read frame header
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(fr.reader, header); err != nil {
		return nil, err
	}

	// Parse frame
	frame := &Frame{}
	if err := frame.Unmarshal(header); err != nil {
		return nil, err
	}

	// Read payload
	if frame.Length > FrameHeaderSize {
		payloadSize := frame.Length - FrameHeaderSize
		frame.Payload = make([]byte, payloadSize)
		if _, err := io.ReadFull(fr.reader, frame.Payload); err != nil {
			return nil, err
		}
	}

	// Decrypt frame
	if err := fr.cryptoMgr.DecryptFrame(frame); err != nil {
		return nil, err
	}

	return frame, nil
}

// FrameWriter writes and encrypts Sush frames
type FrameWriter struct {
	conn      net.Conn
	cryptoMgr *CryptoManager
}

// NewFrameWriter creates a new frame writer
func NewFrameWriter(conn net.Conn, cryptoMgr *CryptoManager) *FrameWriter {
	return &FrameWriter{
		conn:      conn,
		cryptoMgr: cryptoMgr,
	}
}

// WriteFrame encrypts and writes a frame
func (fw *FrameWriter) WriteFrame(frame *Frame) error {
	// Encrypt frame
	if err := fw.cryptoMgr.EncryptFrame(frame); err != nil {
		return err
	}

	// Marshal frame
	data := frame.Marshal()

	// Write to connection
	_, err := fw.conn.Write(data)
	return err
}
