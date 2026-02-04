package xdrive

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const protocolName = "xdrive"

// DriveService defines the interface for remote storage services
type DriveService interface {
	// Login authenticates with the service (no-op for local)
	Login(ctx context.Context) error
	// Upload creates a file with the given name and content
	Upload(ctx context.Context, name string, data []byte) error
	// List returns files matching the prefix, created within the given duration
	List(ctx context.Context, prefix string, within time.Duration) ([]FileInfo, error)
	// Download retrieves the content of a file
	Download(ctx context.Context, name string) ([]byte, error)
	// Delete removes a file
	Delete(ctx context.Context, name string) error
}

// FileInfo represents information about a file
type FileInfo struct {
	Name      string
	CreatedAt time.Time
}

// LocalDriveService implements DriveService using the local filesystem
type LocalDriveService struct {
	remoteFolder string
	mu           sync.RWMutex
}

// NewLocalDriveService creates a new LocalDriveService
func NewLocalDriveService(remoteFolder string) *LocalDriveService {
	return &LocalDriveService{
		remoteFolder: remoteFolder,
	}
}

// Login is a no-op for local filesystem
func (s *LocalDriveService) Login(ctx context.Context) error {
	// Ensure the folder exists
	return os.MkdirAll(s.remoteFolder, 0755)
}

// Upload creates a file with the given name and content
func (s *LocalDriveService) Upload(ctx context.Context, name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := filepath.Join(s.remoteFolder, name)
	return os.WriteFile(filePath, data, 0644)
}

// List returns files matching the prefix, created within the given duration
func (s *LocalDriveService) List(ctx context.Context, prefix string, within time.Duration) ([]FileInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.remoteFolder)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	cutoff := time.Now().Add(-within)
	var files []FileInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			continue
		}
		files = append(files, FileInfo{
			Name:      name,
			CreatedAt: info.ModTime(),
		})
	}

	return files, nil
}

// Download retrieves the content of a file
func (s *LocalDriveService) Download(ctx context.Context, name string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := filepath.Join(s.remoteFolder, name)
	return os.ReadFile(filePath)
}

// Delete removes a file
func (s *LocalDriveService) Delete(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := filepath.Join(s.remoteFolder, name)
	err := os.Remove(filePath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ParseFileName parses a filename in format: sessionID-direction-seq
// Returns sessionID, direction ("up" or "down"), sequence number
func ParseFileName(name string) (sessionID string, direction string, seq int64, ok bool) {
	// Remove extension if any
	name = strings.TrimSuffix(name, filepath.Ext(name))

	parts := strings.Split(name, "-")
	if len(parts) < 7 { // UUID has 5 parts + direction + seq = at least 7
		return "", "", 0, false
	}

	// UUID is the first 5 parts joined by "-"
	sessionID = strings.Join(parts[:5], "-")

	// Validate it's a UUID
	if _, err := uuid.ParseString(sessionID); err != nil {
		return "", "", 0, false
	}

	direction = parts[5]
	if direction != "up" && direction != "down" {
		return "", "", 0, false
	}

	seq, err := strconv.ParseInt(parts[6], 10, 64)
	if err != nil {
		return "", "", 0, false
	}

	return sessionID, direction, seq, true
}

// MakeFileName creates a filename in format: sessionID-direction-seq
func MakeFileName(sessionID, direction string, seq int64) string {
	return fmt.Sprintf("%s-%s-%d", sessionID, direction, seq)
}

// XdriveConnection represents a connection over the XDRIVE transport
type XdriveConnection struct {
	ctx        context.Context
	cancel     context.CancelFunc
	service    DriveService
	sessionID  string
	isClient   bool // true for client, false for server
	readDone   *done.Instance
	writeDone  *done.Instance
	readBuf    []byte
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readSeq    int64
	writeSeq   int64
	localAddr  net.Addr
	remoteAddr net.Addr
}

// newXdriveConnection creates a new XdriveConnection
func newXdriveConnection(ctx context.Context, service DriveService, sessionID string, isClient bool) *XdriveConnection {
	ctx, cancel := context.WithCancel(ctx)
	return &XdriveConnection{
		ctx:       ctx,
		cancel:    cancel,
		service:   service,
		sessionID: sessionID,
		isClient:  isClient,
		readDone:  done.New(),
		writeDone: done.New(),
	}
}

// Read reads data from the connection by polling for files
func (c *XdriveConnection) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// If we have buffered data, return it first
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Determine which direction to read from
	// Client reads "down" (server to client), server reads "up" (client to server)
	readDirection := "down"
	if !c.isClient {
		readDirection = "up"
	}

	prefix := fmt.Sprintf("%s-%s-", c.sessionID, readDirection)

	// Poll for the expected file with timeout
	pollInterval := 100 * time.Millisecond
	timeout := 10 * time.Second
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-c.ctx.Done():
			return 0, io.EOF
		case <-c.readDone.Wait():
			return 0, io.EOF
		default:
		}

		// List files within retention window
		files, err := c.service.List(c.ctx, prefix, 10*time.Second)
		if err != nil {
			return 0, err
		}

		// Sort files by sequence number
		sort.Slice(files, func(i, j int) bool {
			_, _, seqI, _ := ParseFileName(files[i].Name)
			_, _, seqJ, _ := ParseFileName(files[j].Name)
			return seqI < seqJ
		})

		// Look for the expected sequence file
		for _, file := range files {
			_, _, seq, ok := ParseFileName(file.Name)
			if !ok {
				continue
			}

			if seq == c.readSeq {
				// Found the expected file, download it
				data, err := c.service.Download(c.ctx, file.Name)
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return 0, err
				}

				// Delete the file after reading
				c.service.Delete(c.ctx, file.Name)

				c.readSeq++

				// Copy to buffer
				n := copy(b, data)
				if n < len(data) {
					c.readBuf = data[n:]
				}
				return n, nil
			}
		}

		time.Sleep(pollInterval)
	}

	return 0, errors.New("read timeout")
}

// Write writes data to the connection by creating files
func (c *XdriveConnection) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	select {
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	case <-c.writeDone.Wait():
		return 0, io.ErrClosedPipe
	default:
	}

	// Determine which direction to write
	// Client writes "up" (client to server), server writes "down" (server to client)
	writeDirection := "up"
	if !c.isClient {
		writeDirection = "down"
	}

	fileName := MakeFileName(c.sessionID, writeDirection, c.writeSeq)

	err := c.service.Upload(c.ctx, fileName, b)
	if err != nil {
		return 0, err
	}

	c.writeSeq++
	return len(b), nil
}

// Close closes the connection
func (c *XdriveConnection) Close() error {
	c.readDone.Close()
	c.writeDone.Close()
	c.cancel()
	return nil
}

// LocalAddr returns the local address
func (c *XdriveConnection) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return &net.TCPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0}
}

// RemoteAddr returns the remote address
func (c *XdriveConnection) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return &net.TCPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0}
}

// SetDeadline sets the deadline for the connection
func (c *XdriveConnection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline for the connection
func (c *XdriveConnection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline for the connection
func (c *XdriveConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
	common.Must(internet.RegisterTransportListener(protocolName, Serve))
}

// createDriveService creates a DriveService based on the configuration
func createDriveService(config *Config) (DriveService, error) {
	switch config.Service {
	case "local":
		return NewLocalDriveService(config.RemoteFolder), nil
	case "Google Drive":
		// Placeholder for Google Drive implementation
		return nil, errors.New("Google Drive service not yet implemented")
	default:
		return nil, errors.New("unsupported service: " + config.Service)
	}
}

// Dial creates a client connection to the XDRIVE transport
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	// Validate secrets - for client, secrets[0] should be "client"
	if len(config.Secrets) == 0 || config.Secrets[0] != "client" {
		return nil, errors.New("client must have secrets[0] set to 'client'")
	}

	service, err := createDriveService(config)
	if err != nil {
		return nil, err
	}

	if err := service.Login(ctx); err != nil {
		return nil, errors.New("failed to login to drive service").Base(err)
	}

	// Generate a new session ID for this connection
	newUUID := uuid.New()
	sessionID := newUUID.String()

	errors.LogInfo(ctx, fmt.Sprintf("XDRIVE client dialing with session %s to folder %s", sessionID, config.RemoteFolder))

	conn := newXdriveConnection(ctx, service, sessionID, true)
	return stat.Connection(conn), nil
}

// Server represents an XDRIVE server listener
type Server struct {
	ctx       context.Context
	cancel    context.CancelFunc
	config    *Config
	service   DriveService
	addConn   internet.ConnHandler
	sessions  sync.Map // sessionID -> *XdriveConnection
	closeDone *done.Instance
}

// Close closes the server
func (s *Server) Close() error {
	s.closeDone.Close()
	s.cancel()
	return nil
}

// Addr returns the address the server is listening on
func (s *Server) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0}
}

// Serve creates a server listener for the XDRIVE transport
func Serve(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	// Validate secrets - for server, secrets[0] should be "server"
	if len(config.Secrets) == 0 || config.Secrets[0] != "server" {
		return nil, errors.New("server must have secrets[0] set to 'server'")
	}

	service, err := createDriveService(config)
	if err != nil {
		return nil, err
	}

	if err := service.Login(ctx); err != nil {
		return nil, errors.New("failed to login to drive service").Base(err)
	}

	ctx, cancel := context.WithCancel(ctx)

	server := &Server{
		ctx:       ctx,
		cancel:    cancel,
		config:    config,
		service:   service,
		addConn:   addConn,
		closeDone: done.New(),
	}

	errors.LogInfo(ctx, fmt.Sprintf("XDRIVE server listening on folder %s", config.RemoteFolder))

	// Start polling for new connections
	go server.pollForConnections()

	// Start cleanup routine for old files
	go server.cleanupOldFiles()

	return server, nil
}

// pollForConnections polls the folder for new upload files indicating new connections
func (s *Server) pollForConnections() {
	pollInterval := 500 * time.Millisecond
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.closeDone.Wait():
			return
		case <-ticker.C:
			s.checkForNewConnections()
		}
	}
}

// checkForNewConnections checks for files from new client sessions
func (s *Server) checkForNewConnections() {
	// List all files within the retention window
	files, err := s.service.List(s.ctx, "", 10*time.Second)
	if err != nil {
		errors.LogWarning(s.ctx, "failed to list files: ", err)
		return
	}

	// Track seen session IDs
	seenSessions := make(map[string]bool)

	for _, file := range files {
		sessionID, direction, _, ok := ParseFileName(file.Name)
		if !ok {
			continue
		}

		// Only process "up" files (client to server)
		if direction != "up" {
			continue
		}

		// Check if we already have a session for this ID
		if seenSessions[sessionID] {
			continue
		}
		seenSessions[sessionID] = true

		if _, loaded := s.sessions.Load(sessionID); loaded {
			continue
		}

		// New session detected, create a connection
		conn := newXdriveConnection(s.ctx, s.service, sessionID, false)
		s.sessions.Store(sessionID, conn)

		errors.LogInfo(s.ctx, fmt.Sprintf("XDRIVE server accepted new connection: %s", sessionID))

		// Handle the connection
		s.addConn(stat.Connection(conn))
	}
}

// cleanupOldFiles removes files older than the retention window
func (s *Server) cleanupOldFiles() {
	cleanupInterval := 5 * time.Second
	retentionWindow := 10 * time.Second
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.closeDone.Wait():
			return
		case <-ticker.C:
			s.doCleanup(retentionWindow)
		}
	}
}

// doCleanup removes files older than the retention window
func (s *Server) doCleanup(retentionWindow time.Duration) {
	localService, ok := s.service.(*LocalDriveService)
	if !ok {
		return
	}

	localService.mu.Lock()
	defer localService.mu.Unlock()

	entries, err := os.ReadDir(localService.remoteFolder)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-retentionWindow)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			filePath := filepath.Join(localService.remoteFolder, entry.Name())
			os.Remove(filePath)
		}
	}
}
