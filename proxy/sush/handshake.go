// package sush implements the secure implicit handshake mechanism
package sush

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// HandshakeManager manages the implicit handshake process
type HandshakeManager struct {
	psk        []byte // Pre-shared key for policy encryption
	replayProt *ReplayProtection
	config     *HandshakeConfig // Configuration for customizable headers
}

// NewHandshakeManager creates a new handshake manager
func NewHandshakeManager(psk []byte, config *HandshakeConfig) *HandshakeManager {
	if config == nil {
		config = &HandshakeConfig{
			UserAgent:        "Mozilla/5.0 (compatible; Sush/1.0)",
			Host:             "api.example.com",
			Method:           "POST",
			Path:             "/api/v1/data",
			HttpVersion:      "HTTP/1.1",
			ConnectionHeader: "keep-alive",
		}
	}
	return &HandshakeManager{
		psk:        psk,
		replayProt: NewReplayProtection(5 * time.Minute),
		config:     config,
	}
}

// ClientHandshake performs the client-side handshake
func (hm *HandshakeManager) ClientHandshake(ctx context.Context, conn net.Conn, userID [16]byte, policyReq *PolicyRequest) (*Session, error) {
	// Generate key pair
	clientPriv, clientPub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate nonce
	clientNonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create handshake request
	req := &HandshakeRequest{
		Magic:        MagicNumber,
		Version:      ProtocolVersion,
		ClientPubKey: clientPub,
		UserID:       userID,
		Timestamp:    uint64(time.Now().Unix()),
		Nonce:        clientNonce,
	}

	// Encrypt policy request
	policyData, err := json.Marshal(policyReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy request: %w", err)
	}

	req.PolicyReq, err = EncryptWithPSK(policyData, hm.psk, clientNonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt policy request: %w", err)
	}

	// Marshal handshake request
	reqData, err := hm.marshalHandshakeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal handshake request: %w", err)
	}

	// Create HTTP request using standard library
	httpReq, err := hm.createSecureHTTPRequest(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Write HTTP request to connection
	if err := httpReq.Write(conn); err != nil {
		return nil, fmt.Errorf("failed to send handshake request: %w", err)
	}

	// Read HTTP response using standard library
	resp, err := http.ReadResponse(bufio.NewReader(conn), httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse handshake response
	handshakeResp, err := hm.unmarshalHandshakeResponse(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse handshake response: %w", err)
	}

	// Verify response
	if handshakeResp.Magic != MagicNumber || handshakeResp.Version != ProtocolVersion {
		return nil, fmt.Errorf("invalid handshake response")
	}

	// Compute shared secret
	sharedSecret, err := ComputeSharedSecret(clientPriv, handshakeResp.ServerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive session key
	sessionKey := DeriveSessionKey(sharedSecret, clientNonce, handshakeResp.Nonce)

	// Decrypt policy grant
	policyGrantData, err := DecryptWithPSK(handshakeResp.PolicyGrant, hm.psk, handshakeResp.Nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt policy grant: %w", err)
	}

	var policyGrant PolicyGrant
	if err := json.Unmarshal(policyGrantData, &policyGrant); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy grant: %w", err)
	}

	// Create session
	session := &Session{
		ID:             generateSessionID(),
		UserID:         userID,
		SharedKey:      sessionKey,
		Policy:         &policyGrant,
		TrafficProfile: GetTrafficProfile(policyGrant.ApprovedPolicy),
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	return session, nil
}

// ServerHandshake performs the server-side handshake
func (hm *HandshakeManager) ServerHandshake(ctx context.Context, conn net.Conn, validator UserValidator) (*Session, error) {
	// Read HTTP request using standard library - SECURE!
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP request: %w", err)
	}
	defer req.Body.Close()

	// Read request body containing handshake data
	handshakeData, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Parse handshake request
	handshakeReq, err := hm.unmarshalHandshakeRequest(handshakeData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse handshake request: %w", err)
	}

	// Verify handshake
	if handshakeReq.Magic != MagicNumber || handshakeReq.Version != ProtocolVersion {
		return nil, fmt.Errorf("invalid handshake request")
	}

	// Check for replay attacks
	if !hm.replayProt.CheckAndAdd(handshakeReq.Nonce[:]) {
		return nil, fmt.Errorf("replay attack detected")
	}

	// Validate timestamp (prevent old requests)
	if time.Since(time.Unix(int64(handshakeReq.Timestamp), 0)) > 5*time.Minute {
		return nil, fmt.Errorf("handshake request too old")
	}

	// Authenticate user
	if !validator.ValidateUser(handshakeReq.UserID) {
		return nil, fmt.Errorf("user authentication failed")
	}

	// Decrypt policy request
	policyData, err := DecryptWithPSK(handshakeReq.PolicyReq, hm.psk, handshakeReq.Nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt policy request: %w", err)
	}

	var policyReq PolicyRequest
	if err := json.Unmarshal(policyData, &policyReq); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy request: %w", err)
	}

	// Generate server key pair
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key pair: %w", err)
	}

	// Generate server nonce
	serverNonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	// Create policy grant
	policyGrant := &PolicyGrant{
		ApprovedPolicy: policyReq.PreferredPolicy,
		Parameters:     policyReq.CustomParams,
		ValidUntil:     uint64(time.Now().Add(24 * time.Hour).Unix()),
	}

	// Encrypt policy grant
	policyGrantData, err := json.Marshal(policyGrant)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy grant: %w", err)
	}

	encryptedPolicyGrant, err := EncryptWithPSK(policyGrantData, hm.psk, serverNonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt policy grant: %w", err)
	}

	// Create handshake response
	resp := &HandshakeResponse{
		Magic:        MagicNumber,
		Version:      ProtocolVersion,
		ServerPubKey: serverPub,
		PolicyGrant:  encryptedPolicyGrant,
		Nonce:        serverNonce,
	}

	// Marshal handshake response
	respData, err := hm.marshalHandshakeResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal handshake response: %w", err)
	}

	// Send HTTP response using standard library - SECURE!
	httpResp := &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(respData)),
		ContentLength: int64(len(respData)),
	}

	// Set security headers
	httpResp.Header.Set("Content-Type", "application/json")
	httpResp.Header.Set("Server", "nginx/1.18.0")
	httpResp.Header.Set("Connection", "keep-alive")
	httpResp.Header.Set("Cache-Control", "no-cache")

	// Write HTTP response
	if err := httpResp.Write(conn); err != nil {
		return nil, fmt.Errorf("failed to send handshake response: %w", err)
	}

	// Compute shared secret
	sharedSecret, err := ComputeSharedSecret(serverPriv, handshakeReq.ClientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive session key
	sessionKey := DeriveSessionKey(sharedSecret, handshakeReq.Nonce, serverNonce)

	// Create session
	session := &Session{
		ID:             generateSessionID(),
		UserID:         handshakeReq.UserID,
		SharedKey:      sessionKey,
		Policy:         policyGrant,
		TrafficProfile: GetTrafficProfile(policyGrant.ApprovedPolicy),
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	return session, nil
}

// UserValidator interface for user authentication
type UserValidator interface {
	ValidateUser(userID [16]byte) bool
}

// createSecureHTTPRequest creates an HTTP request using configurable headers
func (hm *HandshakeManager) createSecureHTTPRequest(data []byte) (*http.Request, error) {
	// Use configured path or default
	path := hm.config.Path
	if path == "" {
		path = "/api/v1/data"
	}

	// Create request using standard library
	req, err := http.NewRequest(hm.config.Method, path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set configurable headers
	req.Header.Set("Host", hm.config.Host)
	req.Header.Set("User-Agent", hm.config.UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", hm.config.ConnectionHeader)

	// Add custom headers to avoid fingerprinting
	for key, value := range hm.config.Headers {
		req.Header.Set(key, value)
	}

	// Set content length
	req.ContentLength = int64(len(data))

	return req, nil
}

// marshalHandshakeRequest marshals a handshake request to bytes
func (hm *HandshakeManager) marshalHandshakeRequest(req *HandshakeRequest) ([]byte, error) {
	buf := make([]byte, 2+1+32+16+8+12+len(req.PolicyReq))
	offset := 0

	// Magic number
	binary.BigEndian.PutUint16(buf[offset:], req.Magic)
	offset += 2

	// Version
	buf[offset] = req.Version
	offset++

	// Client public key
	copy(buf[offset:], req.ClientPubKey[:])
	offset += 32

	// User ID
	copy(buf[offset:], req.UserID[:])
	offset += 16

	// Timestamp
	binary.BigEndian.PutUint64(buf[offset:], req.Timestamp)
	offset += 8

	// Nonce
	copy(buf[offset:], req.Nonce[:])
	offset += 12

	// Policy request
	copy(buf[offset:], req.PolicyReq)

	return buf, nil
}

// unmarshalHandshakeRequest unmarshals bytes to handshake request
func (hm *HandshakeManager) unmarshalHandshakeRequest(data []byte) (*HandshakeRequest, error) {
	if len(data) < 2+1+32+16+8+12 {
		return nil, fmt.Errorf("handshake request too short")
	}

	req := &HandshakeRequest{}
	offset := 0

	// Magic number
	req.Magic = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Version
	req.Version = data[offset]
	offset++

	// Client public key
	copy(req.ClientPubKey[:], data[offset:offset+32])
	offset += 32

	// User ID
	copy(req.UserID[:], data[offset:offset+16])
	offset += 16

	// Timestamp
	req.Timestamp = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Nonce
	copy(req.Nonce[:], data[offset:offset+12])
	offset += 12

	// Policy request (remaining data)
	req.PolicyReq = make([]byte, len(data)-offset)
	copy(req.PolicyReq, data[offset:])

	return req, nil
}

// marshalHandshakeResponse marshals a handshake response to bytes
func (hm *HandshakeManager) marshalHandshakeResponse(resp *HandshakeResponse) ([]byte, error) {
	buf := make([]byte, 2+1+32+12+len(resp.PolicyGrant))
	offset := 0

	// Magic number
	binary.BigEndian.PutUint16(buf[offset:], resp.Magic)
	offset += 2

	// Version
	buf[offset] = resp.Version
	offset++

	// Server public key
	copy(buf[offset:], resp.ServerPubKey[:])
	offset += 32

	// Nonce
	copy(buf[offset:], resp.Nonce[:])
	offset += 12

	// Policy grant
	copy(buf[offset:], resp.PolicyGrant)

	return buf, nil
}

// unmarshalHandshakeResponse unmarshals bytes to handshake response
func (hm *HandshakeManager) unmarshalHandshakeResponse(data []byte) (*HandshakeResponse, error) {
	if len(data) < 2+1+32+12 {
		return nil, fmt.Errorf("handshake response too short")
	}

	resp := &HandshakeResponse{}
	offset := 0

	// Magic number
	resp.Magic = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Version
	resp.Version = data[offset]
	offset++

	// Server public key
	copy(resp.ServerPubKey[:], data[offset:offset+32])
	offset += 32

	// Nonce
	copy(resp.Nonce[:], data[offset:offset+12])
	offset += 12

	// Policy grant (remaining data)
	resp.PolicyGrant = make([]byte, len(data)-offset)
	copy(resp.PolicyGrant, data[offset:])

	return resp, nil
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("session-%x", b[:8])
}
