// Package outbound implements the Sush outbound handler for Xray-core
package outbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/sush"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler implements the Sush outbound handler
type Handler struct {
	policyManager policy.Manager
	server        *protocol.ServerSpec
	account       *Account
	psk           []byte
	handshakeMgr  *sush.HandshakeManager
	mu            sync.RWMutex
}

// NewHandler creates a new Sush outbound handler
func NewHandler(ctx context.Context, config *Config) (*Handler, error) {
	// Get policy manager
	policyManager := core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)

	// Create server spec
	server := protocol.ServerSpec{
		Address: config.Address,
		Port:    config.Port,
		User:    config.User,
	}

	// Get account
	account := config.User.Account.(*Account)

	// Create PSK (in production, this should be properly derived)
	psk := []byte(config.PSK)

	handler := &Handler{
		policyManager: policyManager,
		server:        &server,
		account:       account,
		psk:           psk,
		handshakeMgr:  sushewHandshakeManager(psk),
	}

	return handler, nil
}

// Process handles outbound connections
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Get destination from context
	dest := session.DestinationFromContext(ctx)

	// Create connection to server
	conn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}
	defer conn.Close()

	// Perform handshake
	userID := [16]byte(h.account.ID)
	policyReq := &susholicyRequest{
		PreferredPolicy: h.account.Policy,
		CustomParams:    h.account.CustomParams,
		Timestamp:       uint64(time.Now().Unix()),
	}

	session, err := h.handshakeMgr.ClientHandshake(ctx, conn, userID, policyReq)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Create crypto manager
	cryptoMgr, err := sushewCryptoManager(session.SharedKey)
	if err != nil {
		return fmt.Errorf("failed to create crypto manager: %w", err)
	}

	// Create traffic morpher
	morpher := sushewAdvancedTrafficMorpher(&susushfficShapingConfig{
		EnableMorphing: true,
		Profile:        session.Policy.ApprovedPolicy,
	})

	// Create frame reader/writer
	frameReader := NewFrameReader(bufio.NewReader(conn), cryptoMgr)
	frameWriter := NewFrameWriter(conn, cryptoMgr)

	// Start processing
	return task.Run(ctx, func() error {
		return h.processDataStream(ctx, session, link, frameReader, frameWriter, morpher)
	})
}

// processDataStream processes the data stream
func (h *Handler) processDataStream(ctx context.Context, session *sushession, link *transport.Link, reader *FrameReader, writer *FrameWriter, morpher *susushancedTrafficMorpher) error {
	// Start goroutines for bidirectional data flow
	done := signal.NewDone()

	// Upstream to downstream
	go func() {
		defer done.Signal()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Read from upstream
			buffer := buf.New()
			if _, err := buffer.ReadFrom(link.Reader); err != nil {
				if err != io.EOF {
					log.Record(&log.GeneralMessage{
						Severity: log.Severity_Warning,
						Content:  fmt.Sprintf("Failed to read from upstream: %v", err),
					})
				}
				buffer.Release()
				return
			}

			// Create destination frame
			destFrame, err := h.createDestinationFrame(buffer.Bytes())
			if err != nil {
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Warning,
					Content:  fmt.Sprintf("Failed to create destination frame: %v", err),
				})
				buffer.Release()
				continue
			}

			// Apply traffic morphing
			morphedData := morpher.MorphPacket(destFrame.Payload, true)
			destFrame.Payload = morphedData

			// Send frame
			if err := writer.WriteFrame(destFrame); err != nil {
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Warning,
					Content:  fmt.Sprintf("Failed to write frame: %v", err),
				})
				buffer.Release()
				return
			}

			buffer.Release()
		}
	}()

	// Downstream to upstream
	go func() {
		defer done.Signal()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Read frame
			frame, err := reader.ReadFrame()
			if err != nil {
				if err != io.EOF {
					log.Record(&log.GeneralMessage{
						Severity: log.Severity_Warning,
						Content:  fmt.Sprintf("Failed to read frame: %v", err),
					})
				}
				return
			}

			// Process frame
			switch frame.Command {
			case sushmdData:
				// Write data to downstream
				if _, err := link.Writer.Write(frame.Payload); err != nil {
					log.Record(&log.GeneralMessage{
						Severity: log.Severity_Warning,
						Content:  fmt.Sprintf("Failed to write to downstream: %v", err),
					})
					return
				}

			case sushmdPaddingCtrl:
				// Handle padding control
				h.handlePaddingControl(frame, morpher)

			case sushmdTimingCtrl:
				// Handle timing control
				h.handleTimingControl(frame, morpher)

			case sushmdClose:
				// Close connection
				return

			default:
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Warning,
					Content:  fmt.Sprintf("Unknown frame command: %d", frame.Command),
				})
			}
		}
	}()

	// Wait for completion
	<-done.Wait()
	return nil
}

// createDestinationFrame creates a frame with destination information
func (h *Handler) createDestinationFrame(data []byte) (*sushrame, error) {
	// Get destination from context
	dest := session.DestinationFromContext(context.Background())

	// Create destination payload
	var payload []byte

	switch dest.Address.Family() {
	case net.AddressFamilyIPv4:
		// IPv4 address
		payload = append(payload, 0x01) // Address type
		payload = append(payload, dest.Address.IP()...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(dest.Port))

	case net.AddressFamilyIPv6:
		// IPv6 address
		payload = append(payload, 0x04) // Address type
		payload = append(payload, dest.Address.IP()...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(dest.Port))

	case net.AddressFamilyDomain:
		// Domain name
		domain := dest.Address.Domain()
		payload = append(payload, 0x03) // Address type
		payload = append(payload, byte(len(domain)))
		payload = append(payload, []byte(domain)...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(dest.Port))

	default:
		return nil, fmt.Errorf("unsupported address family: %v", dest.Address.Family())
	}

	// Append actual data
	payload = append(payload, data...)

	// Create frame
	frame := sushewFrame(susushData, payload)
	return frame, nil
}

// handlePaddingControl handles padding control commands
func (h *Handler) handlePaddingControl(frame *sushrame, morpher *susushancedTrafficMorpher) {
	// Parse padding parameters from payload
	// This would contain instructions for how to pad future packets
	// For now, we just log it
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Received padding control command",
	})
}

// handleTimingControl handles timing control commands
func (h *Handler) handleTimingControl(frame *sushrame, morpher *susushancedTrafficMorpher) {
	// Parse timing parameters from payload
	// This would contain instructions for inter-packet delays
	// For now, we just log it
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Received timing control command",
	})
}

// FrameReader reads and decrypts Sush frames
type FrameReader struct {
	reader    *bufio.Reader
	cryptoMgr *sushryptoManager
}

// NewFrameReader creates a new frame reader
func NewFrameReader(reader *bufio.Reader, cryptoMgr *sushryptoManager) *FrameReader {
	return &FrameReader{
		reader:    reader,
		cryptoMgr: cryptoMgr,
	}
}

// ReadFrame reads and decrypts a frame
func (fr *FrameReader) ReadFrame() (*sushrame, error) {
	// Read frame header
	header := make([]byte, sushrameHeaderSize+12) // +12 for nonce
	if _, err := io.ReadFull(fr.reader, header); err != nil {
		return nil, err
	}

	// Parse frame
	frame := &sushrame{}
	if err := frame.Unmarshal(header); err != nil {
		return nil, err
	}

	// Read payload
	if frame.Length > 0 {
		frame.Payload = make([]byte, frame.Length)
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
	conn      internet.Connection
	cryptoMgr *sushryptoManager
}

// NewFrameWriter creates a new frame writer
func NewFrameWriter(conn internet.Connection, cryptoMgr *sushryptoManager) *FrameWriter {
	return &FrameWriter{
		conn:      conn,
		cryptoMgr: cryptoMgr,
	}
}

// WriteFrame encrypts and writes a frame
func (fw *FrameWriter) WriteFrame(frame *sushrame) error {
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
