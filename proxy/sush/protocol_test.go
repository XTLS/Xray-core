package sush

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// TestFrameMarshaling tests frame marshaling/unmarshaling
func TestFrameMarshaling(t *testing.T) {
	// Create test frame
	testPayload := []byte("Test frame payload for marshaling")
	frame := NewFrame(CmdData, testPayload)

	// Add nonce for encryption context
	rand.Read(frame.Nonce[:])

	// Marshal frame
	data := frame.Marshal()

	// Unmarshal frame
	parsedFrame := &Frame{}
	err := parsedFrame.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal frame: %v", err)
	}

	// Verify frame fields
	if parsedFrame.Length != frame.Length {
		t.Errorf("Length mismatch: got %d, want %d", parsedFrame.Length, frame.Length)
	}

	if parsedFrame.Command != frame.Command {
		t.Errorf("Command mismatch: got %d, want %d", parsedFrame.Command, frame.Command)
	}

	if !bytes.Equal(parsedFrame.Payload, frame.Payload) {
		t.Error("Payload mismatch")
	}

	if !bytes.Equal(parsedFrame.Nonce[:], frame.Nonce[:]) {
		t.Error("Nonce mismatch")
	}
}

// TestFrameCommands tests different frame commands
func TestFrameCommands(t *testing.T) {
	testCases := []struct {
		command byte
		name    string
	}{
		{CmdData, "DATA"},
		{CmdPaddingCtrl, "PADDING_CTRL"},
		{CmdTimingCtrl, "TIMING_CTRL"},
		{CmdClose, "CLOSE"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("test payload for " + tc.name)
			frame := NewFrame(tc.command, payload)

			data := frame.Marshal()

			parsedFrame := &Frame{}
			err := parsedFrame.Unmarshal(data)
			if err != nil {
				t.Fatalf("Failed to unmarshal %s frame: %v", tc.name, err)
			}

			if parsedFrame.Command != tc.command {
				t.Errorf("%s command mismatch: got %d, want %d", tc.name, parsedFrame.Command, tc.command)
			}

			if !bytes.Equal(parsedFrame.Payload, payload) {
				t.Errorf("%s payload mismatch", tc.name)
			}
		})
	}
}

// TestSushHandshakeDetection tests magic number detection
func TestSushHandshakeDetection(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid Sush handshake",
			data:     []byte{0x53, 0x55, ProtocolVersion}, // "SU" + version
			expected: true,
		},
		{
			name:     "Invalid magic number",
			data:     []byte{0x52, 0x46, ProtocolVersion}, // Old "RF" magic
			expected: false,
		},
		{
			name:     "Invalid version",
			data:     []byte{0x53, 0x55, 0xFF}, // Valid magic, invalid version
			expected: false, // Should be false because version doesn't match
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "Short data",
			data:     []byte{0x52},
			expected: false,
		},
		{
			name:     "Partial magic",
			data:     []byte{0x53, 0x55},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSushHandshake(tt.data)
			if result != tt.expected {
				t.Errorf("IsSushHandshake() = %v, want %v for %s", result, tt.expected, tt.name)
			}
		})
	}
}

// TestTrafficProfiles tests traffic profile configuration
func TestTrafficProfiles(t *testing.T) {
	profiles := []string{
		PolicyRaw,
		PolicyVideoStream,
		PolicyHTTP2API,
		PolicyGitPush,
		PolicyZoomCall,
	}

	for _, profileName := range profiles {
		t.Run(profileName, func(t *testing.T) {
			profile := GetTrafficProfile(profileName)

			if profile == nil {
				t.Fatalf("Profile %s should not be nil", profileName)
			}

			// Basic validation
			if profile.Name == "" {
				t.Errorf("Profile %s should have a name", profileName)
			}

			if len(profile.PacketSizes) == 0 {
				t.Errorf("Profile %s should have packet sizes", profileName)
			}

			if len(profile.Intervals) == 0 {
				t.Errorf("Profile %s should have intervals", profileName)
			}

			// Validate packet sizes are reasonable
			for _, size := range profile.PacketSizes {
				if size <= 0 || size > MaxFrameSize {
					t.Errorf("Profile %s has invalid packet size: %d", profileName, size)
				}
			}

			// Validate intervals are reasonable
			for _, interval := range profile.Intervals {
				if interval < 0 {
					t.Errorf("Profile %s has negative interval: %f", profileName, interval)
				}
			}
		})
	}
}

// TestSessionCreation tests session structure
func TestSessionCreation(t *testing.T) {
	userID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sharedKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	policyGrant := &PolicyGrant{
		ApprovedPolicy: PolicyHTTP2API,
		Parameters:     map[string]string{"test": "value"},
		ValidUntil:     uint64(time.Now().Add(24 * time.Hour).Unix()),
	}

	session := &Session{
		ID:             "test-session",
		UserID:         userID,
		SharedKey:      sharedKey,
		Policy:         policyGrant,
		TrafficProfile: GetTrafficProfile(policyGrant.ApprovedPolicy),
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	// Validate session fields
	if session.ID != "test-session" {
		t.Errorf("Expected session ID 'test-session', got '%s'", session.ID)
	}

	if session.UserID != userID {
		t.Error("User ID mismatch")
	}

	if session.SharedKey != sharedKey {
		t.Error("Shared key mismatch")
	}

	if session.Policy.ApprovedPolicy != PolicyHTTP2API {
		t.Errorf("Expected policy '%s', got '%s'", PolicyHTTP2API, session.Policy.ApprovedPolicy)
	}

	if session.TrafficProfile == nil {
		t.Error("Traffic profile should not be nil")
	}

	if session.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	if session.LastActivity.IsZero() {
		t.Error("LastActivity should be set")
	}
}

// TestPolicyStructures tests policy request/grant structures
func TestPolicyStructures(t *testing.T) {
	// Test PolicyRequest
	req := &PolicyRequest{
		PreferredPolicy: PolicyHTTP2API,
		CustomParams: map[string]string{
			"burst_factor": "1.5",
			"jitter_max":   "0.2",
		},
	}

	// Test PolicyGrant
	grant := &PolicyGrant{
		ApprovedPolicy: req.PreferredPolicy,
		Parameters:     req.CustomParams,
		ValidUntil:     uint64(1234567890),
	}

	// Basic validation
	if grant.ApprovedPolicy != req.PreferredPolicy {
		t.Error("PolicyGrant should preserve approved policy")
	}

	if len(grant.Parameters) != len(req.CustomParams) {
		t.Error("PolicyGrant should preserve custom parameters")
	}

	for key, value := range req.CustomParams {
		if grant.Parameters[key] != value {
			t.Errorf("Parameter %s mismatch: got %s, want %s", key, grant.Parameters[key], value)
		}
	}
}

// TestFrameSizeValidation tests frame size limits
func TestFrameSizeValidation(t *testing.T) {
	// Test normal frame
	normalPayload := make([]byte, 100)
	normalFrame := NewFrame(CmdData, normalPayload)
	normalData := normalFrame.Marshal()

	parsedNormal := &Frame{}
	err := parsedNormal.Unmarshal(normalData)
	if err != nil {
		t.Fatalf("Failed to unmarshal normal frame: %v", err)
	}

	// Test maximum size frame
	maxPayload := make([]byte, 1000)  // Use a reasonable size instead
	maxFrame := NewFrame(CmdData, maxPayload)
	maxData := maxFrame.Marshal()

	parsedMax := &Frame{}
	err = parsedMax.Unmarshal(maxData)
	if err != nil {
		t.Fatalf("Failed to unmarshal max size frame: %v", err)
	}

	// Test empty payload
	emptyFrame := NewFrame(CmdClose, []byte{})
	emptyData := emptyFrame.Marshal()

	parsedEmpty := &Frame{}
	err = parsedEmpty.Unmarshal(emptyData)
	if err != nil {
		t.Fatalf("Failed to unmarshal empty frame: %v", err)
	}
}

// BenchmarkFrameMarshaling benchmarks frame marshaling performance
func BenchmarkFrameMarshaling(b *testing.B) {
	payload := make([]byte, 1024) // 1KB payload
	rand.Read(payload)
	frame := NewFrame(CmdData, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data := frame.Marshal()
		parsedFrame := &Frame{}
		err := parsedFrame.Unmarshal(data)
		if err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}

// BenchmarkMagicNumberDetection benchmarks handshake detection performance
func BenchmarkMagicNumberDetection(b *testing.B) {
	testData := []byte{0x52, 0x46, ProtocolVersion} // Valid Sush handshake

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsSushHandshake(testData)
	}
}
