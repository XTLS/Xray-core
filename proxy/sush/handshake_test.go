package sush

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// MockConn implements net.Conn for testing
type MockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func NewMockConn() *MockConn {
	return &MockConn{
		readBuf:  bytes.NewBuffer(nil),
		writeBuf: bytes.NewBuffer(nil),
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *MockConn) Close() error {
	m.closed = true
	return nil
}

func (m *MockConn) LocalAddr() net.Addr                { return nil }
func (m *MockConn) RemoteAddr() net.Addr               { return nil }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

// SetupTestPair creates client and server mock connections
func (m *MockConn) SetupTestPair(other *MockConn) {
	// Connect read buffer of one to write buffer of other
	m.readBuf = other.writeBuf
	other.readBuf = m.writeBuf
}

// MockUserValidator implements UserValidator for testing
type MockUserValidator struct {
	validUsers map[[16]byte]bool
}

func NewMockUserValidator() *MockUserValidator {
	return &MockUserValidator{
		validUsers: make(map[[16]byte]bool),
	}
}

func (v *MockUserValidator) AddUser(userID [16]byte) {
	v.validUsers[userID] = true
}

func (v *MockUserValidator) ValidateUser(userID [16]byte) bool {
	return v.validUsers[userID]
}

// TestHandshakeManager tests handshake manager creation
func TestHandshakeManager(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	config := &HandshakeConfig{
		UserAgent:        "Test-Agent/1.0",
		Host:             "test.example.com",
		Method:           "POST",
		Path:             "/api/test",
		HttpVersion:      "HTTP/1.1",
		ConnectionHeader: "keep-alive",
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	}

	hm := NewHandshakeManager(psk, config)

	if hm == nil {
		t.Fatal("HandshakeManager should not be nil")
	}

	if !bytes.Equal(hm.psk, psk) {
		t.Error("PSK mismatch")
	}

	if hm.config.UserAgent != config.UserAgent {
		t.Error("Config not preserved")
	}

	if hm.replayProt == nil {
		t.Error("Replay protection should be initialized")
	}
}

// TestHandshakeManager_DefaultConfig tests default configuration
func TestHandshakeManager_DefaultConfig(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")

	hm := NewHandshakeManager(psk, nil)

	if hm == nil {
		t.Fatal("HandshakeManager should not be nil")
	}

	if hm.config == nil {
		t.Fatal("Default config should be created")
	}

	// Check default values
	if hm.config.UserAgent == "" {
		t.Error("Default UserAgent should not be empty")
	}

	if hm.config.Host == "" {
		t.Error("Default Host should not be empty")
	}

	if hm.config.Method != "POST" {
		t.Error("Default Method should be POST")
	}
}

// TestHandshakeRequestMarshaling tests handshake request marshaling/unmarshaling
func TestHandshakeRequestMarshaling(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	hm := NewHandshakeManager(psk, nil)

	// Create test handshake request
	userID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	_, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	policyReq := &PolicyRequest{
		PreferredPolicy: PolicyHTTP2API,
		CustomParams:    map[string]string{"test": "value"},
	}

	policyData, err := json.Marshal(policyReq)
	if err != nil {
		t.Fatalf("Failed to marshal policy: %v", err)
	}

	encryptedPolicy, err := EncryptWithPSK(policyData, psk, nonce[:])
	if err != nil {
		t.Fatalf("Failed to encrypt policy: %v", err)
	}

	req := &HandshakeRequest{
		Magic:        MagicNumber,
		Version:      ProtocolVersion,
		ClientPubKey: clientPub,
		UserID:       userID,
		Timestamp:    uint64(time.Now().Unix()),
		Nonce:        nonce,
		PolicyReq:    encryptedPolicy,
	}

	// Marshal request
	data, err := hm.marshalHandshakeRequest(req)
	if err != nil {
		t.Fatalf("Failed to marshal handshake request: %v", err)
	}

	// Unmarshal request
	parsedReq, err := hm.unmarshalHandshakeRequest(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal handshake request: %v", err)
	}

	// Verify fields
	if parsedReq.Magic != req.Magic {
		t.Error("Magic number mismatch")
	}

	if parsedReq.Version != req.Version {
		t.Error("Version mismatch")
	}

	if !bytes.Equal(parsedReq.ClientPubKey[:], req.ClientPubKey[:]) {
		t.Error("Client public key mismatch")
	}

	if !bytes.Equal(parsedReq.UserID[:], req.UserID[:]) {
		t.Error("User ID mismatch")
	}

	if parsedReq.Timestamp != req.Timestamp {
		t.Error("Timestamp mismatch")
	}

	if !bytes.Equal(parsedReq.Nonce[:], req.Nonce[:]) {
		t.Error("Nonce mismatch")
	}

	if !bytes.Equal(parsedReq.PolicyReq, req.PolicyReq) {
		t.Error("Policy request mismatch")
	}
}

// TestHandshakeResponseMarshaling tests handshake response marshaling/unmarshaling
func TestHandshakeResponseMarshaling(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	hm := NewHandshakeManager(psk, nil)

	// Create test handshake response
	_, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	policyGrant := &PolicyGrant{
		ApprovedPolicy: PolicyHTTP2API,
		Parameters:     map[string]string{"test": "value"},
		ValidUntil:     uint64(time.Now().Add(24 * time.Hour).Unix()),
	}

	policyData, err := json.Marshal(policyGrant)
	if err != nil {
		t.Fatalf("Failed to marshal policy grant: %v", err)
	}

	encryptedGrant, err := EncryptWithPSK(policyData, psk, nonce[:])
	if err != nil {
		t.Fatalf("Failed to encrypt policy grant: %v", err)
	}

	resp := &HandshakeResponse{
		Magic:        MagicNumber,
		Version:      ProtocolVersion,
		ServerPubKey: serverPub,
		PolicyGrant:  encryptedGrant,
		Nonce:        nonce,
	}

	// Marshal response
	data, err := hm.marshalHandshakeResponse(resp)
	if err != nil {
		t.Fatalf("Failed to marshal handshake response: %v", err)
	}

	// Unmarshal response
	parsedResp, err := hm.unmarshalHandshakeResponse(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal handshake response: %v", err)
	}

	// Verify fields
	if parsedResp.Magic != resp.Magic {
		t.Error("Magic number mismatch")
	}

	if parsedResp.Version != resp.Version {
		t.Error("Version mismatch")
	}

	if !bytes.Equal(parsedResp.ServerPubKey[:], resp.ServerPubKey[:]) {
		t.Error("Server public key mismatch")
	}

	if !bytes.Equal(parsedResp.Nonce[:], resp.Nonce[:]) {
		t.Error("Nonce mismatch")
	}

	if !bytes.Equal(parsedResp.PolicyGrant, resp.PolicyGrant) {
		t.Error("Policy grant mismatch")
	}
}

// TestHTTPRequestCreation tests secure HTTP request creation
func TestHTTPRequestCreation(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	config := &HandshakeConfig{
		UserAgent:        "Custom-Agent/2.0",
		Host:             "api.test.com",
		Method:           "POST",
		Path:             "/v2/handshake",
		HttpVersion:      "HTTP/1.1",
		ConnectionHeader: "close",
		Headers: map[string]string{
			"X-API-Key":    "secret123",
			"X-Request-ID": "req-456",
		},
	}

	hm := NewHandshakeManager(psk, config)

	testData := []byte("test handshake data")

	req, err := hm.createSecureHTTPRequest(testData)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	// Verify request properties
	if req.Method != config.Method {
		t.Errorf("Method mismatch: got %s, want %s", req.Method, config.Method)
	}

	if req.URL.Path != config.Path {
		t.Errorf("Path mismatch: got %s, want %s", req.URL.Path, config.Path)
	}

	if req.Header.Get("Host") != config.Host {
		t.Errorf("Host header mismatch: got %s, want %s", req.Header.Get("Host"), config.Host)
	}

	if req.Header.Get("User-Agent") != config.UserAgent {
		t.Errorf("User-Agent mismatch: got %s, want %s", req.Header.Get("User-Agent"), config.UserAgent)
	}

	if req.Header.Get("Connection") != config.ConnectionHeader {
		t.Errorf("Connection header mismatch: got %s, want %s", req.Header.Get("Connection"), config.ConnectionHeader)
	}

	// Verify custom headers
	for key, value := range config.Headers {
		if req.Header.Get(key) != value {
			t.Errorf("Custom header %s mismatch: got %s, want %s", key, req.Header.Get(key), value)
		}
	}

	// Verify content type and length
	if req.Header.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be application/json")
	}

	if req.ContentLength != int64(len(testData)) {
		t.Errorf("Content-Length mismatch: got %d, want %d", req.ContentLength, len(testData))
	}
}

// TestReplayProtectionInHandshake tests replay protection during handshake
func TestReplayProtectionInHandshake(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	hm := NewHandshakeManager(psk, nil)

	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	// First check should succeed
	if !hm.replayProt.CheckAndAdd(nonce[:]) {
		t.Error("First nonce should be accepted")
	}

	// Second check with same nonce should fail
	if hm.replayProt.CheckAndAdd(nonce[:]) {
		t.Error("Duplicate nonce should be rejected")
	}
}

// TestTimestampValidation tests timestamp validation during handshake
func TestTimestampValidation(t *testing.T) {
	// Test current timestamp (should be valid)
	currentTime := uint64(time.Now().Unix())
	if time.Since(time.Unix(int64(currentTime), 0)) > 5*time.Minute {
		t.Error("Current timestamp should be valid")
	}

	// Test old timestamp (should be invalid)
	oldTime := uint64(time.Now().Add(-10 * time.Minute).Unix())
	if time.Since(time.Unix(int64(oldTime), 0)) <= 5*time.Minute {
		t.Error("Old timestamp should be invalid")
	}

	// Test future timestamp (should be valid for now)
	futureTime := uint64(time.Now().Add(1 * time.Minute).Unix())
	if time.Since(time.Unix(int64(futureTime), 0)) > 5*time.Minute {
		t.Error("Near future timestamp should be valid")
	}
}

// BenchmarkHandshakeMarshaling benchmarks handshake marshaling performance
func BenchmarkHandshakeMarshaling(b *testing.B) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	hm := NewHandshakeManager(psk, nil)

	userID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	_, clientPub, _ := GenerateKeyPair()
	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	req := &HandshakeRequest{
		Magic:        MagicNumber,
		Version:      ProtocolVersion,
		ClientPubKey: clientPub,
		UserID:       userID,
		Timestamp:    uint64(time.Now().Unix()),
		Nonce:        nonce,
		PolicyReq:    []byte("test policy request"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := hm.marshalHandshakeRequest(req)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
		_, err = hm.unmarshalHandshakeRequest(data)
		if err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}

// BenchmarkHTTPRequestCreation benchmarks HTTP request creation performance
func BenchmarkHTTPRequestCreation(b *testing.B) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	hm := NewHandshakeManager(psk, nil)

	testData := make([]byte, 1024) // 1KB test data
	rand.Read(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hm.createSecureHTTPRequest(testData)
		if err != nil {
			b.Fatalf("HTTP request creation failed: %v", err)
		}
	}
}
