// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// package sush implements the Sush proxy protocol
// Sush is a next-generation proxy protocol designed for maximum stealth
// and resistance against advanced traffic analysis and censorship.
package sush

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// Protocol constants
const (
	// Sush protocol version
	ProtocolVersion = 1

	// Frame header size (2 bytes length + 1 byte command)
	FrameHeaderSize = 3

	// Maximum frame payload size
	MaxFrameSize = 65535

	// Minimum handshake size for protocol detection
	MinHandshakeSize = 64

	// Magic number for Sush protocol identification
	MagicNumber = 0x5355 // "SU" in hex
)

// Command types for frame control
const (
	CmdData        = 0x01 // Regular data payload
	CmdPaddingCtrl = 0x02 // Padding control command
	CmdTimingCtrl  = 0x03 // Timing control command
	CmdClose       = 0x04 // Connection close
	CmdPolicyReq   = 0x05 // Policy request
	CmdPolicyGrant = 0x06 // Policy grant
)

// Traffic morphing policies
const (
	PolicyRaw         = "raw"                // No morphing
	PolicyHTTP2API    = "mimic-http2-api"    // Mimic HTTP/2 API calls
	PolicyVideoStream = "mimic-video-stream" // Mimic video streaming
	PolicyGitPush     = "mimic-git-push"     // Mimic Git push operations
	PolicyZoomCall    = "mimic-zoom-call"    // Mimic Zoom video calls
)

// Frame represents a Sush protocol frame
type Frame struct {
	Length  uint16 // Payload length
	Command uint8  // Command type
	Payload []byte // Encrypted payload
	Nonce   []byte // Nonce for encryption (12 bytes for ChaCha20-Poly1305)
}

// HandshakeRequest represents the initial handshake from client
type HandshakeRequest struct {
	Magic        uint16   // Protocol magic number
	Version      uint8    // Protocol version
	ClientPubKey [32]byte // X25519 public key
	UserID       [16]byte // User UUID
	Timestamp    uint64   // Unix timestamp
	PolicyReq    []byte   // Encrypted policy request
	Nonce        [12]byte // Nonce for this handshake
}

// HandshakeResponse represents the server's response to handshake
type HandshakeResponse struct {
	Magic        uint16   // Protocol magic number
	Version      uint8    // Protocol version
	ServerPubKey [32]byte // X25519 public key
	PolicyGrant  []byte   // Encrypted policy grant
	Nonce        [12]byte // Nonce for this response
}

// PolicyRequest contains traffic morphing preferences
type PolicyRequest struct {
	PreferredPolicy string            `json:"policy"`
	CustomParams    map[string]string `json:"params,omitempty"`
	Timestamp       uint64            `json:"timestamp"`
}

// PolicyGrant contains approved traffic morphing parameters
type PolicyGrant struct {
	ApprovedPolicy string            `json:"policy"`
	Parameters     map[string]string `json:"params"`
	ValidUntil     uint64            `json:"valid_until"`
}

// TrafficProfile represents statistical characteristics of a traffic type
type TrafficProfile struct {
	Name          string    `json:"name"`
	PacketSizes   []int     `json:"packet_sizes"`   // Distribution of packet sizes
	Intervals     []float64 `json:"intervals"`      // Distribution of inter-packet intervals
	BurstPatterns []int     `json:"burst_patterns"` // Burst size patterns
	DirectionBias float64   `json:"direction_bias"` // Upload/download ratio
}

// Session represents an active Sush session
type Session struct {
	ID             string
	UserID         [16]byte
	SharedKey      [32]byte
	Policy         *PolicyGrant
	TrafficProfile *TrafficProfile
	CreatedAt      time.Time
	LastActivity   time.Time
}

// NewFrame creates a new Sush frame
func NewFrame(command uint8, payload []byte) *Frame {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	return &Frame{
		Length:  uint16(len(payload)),
		Command: command,
		Payload: payload,
		Nonce:   nonce,
	}
}

// Marshal serializes the frame to bytes
func (f *Frame) Marshal() []byte {
	buf := make([]byte, FrameHeaderSize+len(f.Payload)+len(f.Nonce))

	// Write header
	binary.BigEndian.PutUint16(buf[0:2], f.Length)
	buf[2] = f.Command

	// Write nonce
	copy(buf[3:15], f.Nonce)

	// Write payload
	copy(buf[15:], f.Payload)

	return buf
}

// Unmarshal deserializes bytes to frame
func (f *Frame) Unmarshal(data []byte) error {
	if len(data) < FrameHeaderSize+12 {
		return fmt.Errorf("frame too short")
	}

	f.Length = binary.BigEndian.Uint16(data[0:2])
	f.Command = data[2]

	if len(data) < 15 {
		return fmt.Errorf("incomplete frame: need at least 15 bytes, got %d", len(data))
	}
	if len(data) < 15+int(f.Length) {
		return fmt.Errorf("incomplete frame: need %d bytes, got %d", 15+int(f.Length), len(data))
	}

	f.Nonce = make([]byte, 12)
	copy(f.Nonce, data[3:15])

	f.Payload = make([]byte, f.Length)
	copy(f.Payload, data[15:15+f.Length])

	return nil
}

// IsSushHandshake checks if the given data matches Sush handshake pattern
func IsSushHandshake(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	magic := binary.BigEndian.Uint16(data[0:2])
	version := data[2]
	return magic == MagicNumber && version == ProtocolVersion
}

// GetTrafficProfile returns a predefined traffic profile
func GetTrafficProfile(policy string) *TrafficProfile {
	switch policy {
	case PolicyHTTP2API:
		return &TrafficProfile{
			Name:          "HTTP/2 API",
			PacketSizes:   []int{64, 128, 256, 512, 1024, 2048},
			Intervals:     []float64{0.1, 0.5, 1.0, 2.0, 5.0},
			BurstPatterns: []int{1, 2, 4, 8},
			DirectionBias: 0.3, // 30% upload, 70% download
		}
	case PolicyVideoStream:
		return &TrafficProfile{
			Name:          "Video Stream",
			PacketSizes:   []int{1024, 1400, 1500, 1600},
			Intervals:     []float64{0.016, 0.033, 0.066}, // 60fps, 30fps, 15fps
			BurstPatterns: []int{1, 2, 3},
			DirectionBias: 0.1, // 10% upload, 90% download
		}
	case PolicyGitPush:
		return &TrafficProfile{
			Name:          "Git Push",
			PacketSizes:   []int{256, 512, 1024, 2048, 4096, 8192},
			Intervals:     []float64{0.5, 1.0, 2.0, 5.0, 10.0},
			BurstPatterns: []int{1, 4, 8, 16, 32},
			DirectionBias: 0.8, // 80% upload, 20% download
		}
	case PolicyZoomCall:
		return &TrafficProfile{
			Name:          "Zoom Call",
			PacketSizes:   []int{200, 400, 800, 1200, 1400},
			Intervals:     []float64{0.02, 0.04, 0.08, 0.1},
			BurstPatterns: []int{1, 2, 3, 4},
			DirectionBias: 0.5, // 50% upload, 50% download
		}
	default:
		return &TrafficProfile{
			Name:          "Raw",
			PacketSizes:   []int{64, 128, 256, 512, 1024, 1400, 1500},
			Intervals:     []float64{0.001, 0.01, 0.1, 1.0},
			BurstPatterns: []int{1, 2, 4, 8, 16},
			DirectionBias: 0.5,
		}
	}
}
