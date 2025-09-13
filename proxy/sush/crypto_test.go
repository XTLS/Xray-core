package sush

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// TestKeyGeneration tests X25519 key pair generation
func TestKeyGeneration(t *testing.T) {
	priv1, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}

	// Keys should be different
	if bytes.Equal(priv1[:], priv2[:]) {
		t.Error("Private keys should be different")
	}
	if bytes.Equal(pub1[:], pub2[:]) {
		t.Error("Public keys should be different")
	}

	// Test shared secret computation (ECDH)
	shared1, err := ComputeSharedSecret(priv1, pub2)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 1: %v", err)
	}

	shared2, err := ComputeSharedSecret(priv2, pub1)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 2: %v", err)
	}

	// Shared secrets should be equal
	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Error("Shared secrets should be equal")
	}
}

// TestCryptoManager tests the complete cryptographic flow
func TestCryptoManager(t *testing.T) {
	// Create test key
	key := [32]byte{}
	rand.Read(key[:])

	// Create crypto manager
	cryptoMgr, err := NewCryptoManager(key)
	if err != nil {
		t.Fatalf("Failed to create crypto manager: %v", err)
	}

	// Test data
	testData := []byte("Hello, Sush Protocol! This is a test message for encryption.")
	nonce := make([]byte, 12)
	rand.Read(nonce)
	additionalData := []byte("test-additional-data")

	// Encrypt data
	encrypted, err := cryptoMgr.Encrypt(testData, nonce, additionalData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt data
	decrypted, err := cryptoMgr.Decrypt(encrypted, nonce, additionalData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(testData, decrypted) {
		t.Error("Decrypted data does not match original")
	}
}

// TestFrameEncryption tests frame encryption/decryption
func TestFrameEncryption(t *testing.T) {
	// Create crypto manager
	key := [32]byte{}
	rand.Read(key[:])

	cryptoMgr, err := NewCryptoManager(key)
	if err != nil {
		t.Fatalf("Failed to create crypto manager: %v", err)
	}

	// Create test frame
	frame := NewFrame(CmdData, []byte("Test frame payload for encryption"))
	originalPayload := make([]byte, len(frame.Payload))
	copy(originalPayload, frame.Payload)

	// Encrypt frame
	err = cryptoMgr.EncryptFrame(frame)
	if err != nil {
		t.Fatalf("Failed to encrypt frame: %v", err)
	}

	// Verify payload is encrypted (changed)
	if bytes.Equal(frame.Payload, originalPayload) {
		t.Error("Frame payload should be encrypted")
	}

	// Decrypt frame
	err = cryptoMgr.DecryptFrame(frame)
	if err != nil {
		t.Fatalf("Failed to decrypt frame: %v", err)
	}

	// Verify payload is restored
	if !bytes.Equal(frame.Payload, originalPayload) {
		t.Error("Frame decryption failed")
	}
}

// TestPSKEncryption tests PSK-based encryption/decryption
func TestPSKEncryption(t *testing.T) {
	psk := []byte("my-secret-key-32-bytes-long!!!!")
	nonce := make([]byte, 12)
	rand.Read(nonce)

	testData := []byte("Test data for PSK encryption")

	// Encrypt with PSK
	encrypted, err := EncryptWithPSK(testData, psk, nonce)
	if err != nil {
		t.Fatalf("Failed to encrypt with PSK: %v", err)
	}

	// Decrypt with PSK
	decrypted, err := DecryptWithPSK(encrypted, psk, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt with PSK: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(testData, decrypted) {
		t.Error("PSK decrypted data does not match original")
	}

	// Test with wrong PSK
	wrongPSK := []byte("wrong-secret-key-32-bytes-long!!")
	_, err = DecryptWithPSK(encrypted, wrongPSK, nonce)
	if err == nil {
		t.Error("Decryption with wrong PSK should fail")
	}

	// Test with wrong nonce
	wrongNonce := make([]byte, 12)
	rand.Read(wrongNonce)
	_, err = DecryptWithPSK(encrypted, psk, wrongNonce)
	if err == nil {
		t.Error("Decryption with wrong nonce should fail")
	}
}

// TestReplayProtection tests replay attack protection
func TestReplayProtection(t *testing.T) {
	replayProt := NewReplayProtection(1 * time.Second)

	// Generate test nonce
	nonce := make([]byte, 12)
	rand.Read(nonce)

	// First attempt should succeed
	if !replayProt.CheckAndAdd(nonce) {
		t.Error("First nonce should be accepted")
	}

	// Second attempt with same nonce should fail
	if replayProt.CheckAndAdd(nonce) {
		t.Error("Duplicate nonce should be rejected")
	}

	// Different nonce should succeed
	nonce2 := make([]byte, 12)
	rand.Read(nonce2)

	if !replayProt.CheckAndAdd(nonce2) {
		t.Error("Different nonce should be accepted")
	}

	// Test expiration
	time.Sleep(1100 * time.Millisecond) // Wait for expiration

	// Original nonce should be accepted again after expiration
	if !replayProt.CheckAndAdd(nonce) {
		t.Error("Expired nonce should be accepted again")
	}
}

// TestSessionKeyDerivation tests session key derivation
func TestSessionKeyDerivation(t *testing.T) {
	// Generate test data
	sharedSecret := [32]byte{}
	rand.Read(sharedSecret[:])

	clientNonce := [12]byte{}
	rand.Read(clientNonce[:])

	serverNonce := [12]byte{}
	rand.Read(serverNonce[:])

	// Derive session keys
	sessionKey1 := DeriveSessionKey(sharedSecret, clientNonce, serverNonce)
	sessionKey2 := DeriveSessionKey(sharedSecret, clientNonce, serverNonce)

	// Should be deterministic
	if !bytes.Equal(sessionKey1[:], sessionKey2[:]) {
		t.Error("Session key derivation should be deterministic")
	}

	// Different nonces should produce different keys
	differentNonce := [12]byte{}
	rand.Read(differentNonce[:])
	sessionKey3 := DeriveSessionKey(sharedSecret, differentNonce, serverNonce)

	if bytes.Equal(sessionKey1[:], sessionKey3[:]) {
		t.Error("Different nonces should produce different session keys")
	}
}

// BenchmarkEncryption benchmarks encryption performance
func BenchmarkEncryption(b *testing.B) {
	key := [32]byte{}
	rand.Read(key[:])

	cryptoMgr, err := NewCryptoManager(key)
	if err != nil {
		b.Fatalf("Failed to create crypto manager: %v", err)
	}

	testData := make([]byte, 1024) // 1KB test data
	rand.Read(testData)

	nonce := make([]byte, 12)
	rand.Read(nonce)
	additionalData := []byte("benchmark-data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := cryptoMgr.Encrypt(testData, nonce, additionalData)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
		_, err = cryptoMgr.Decrypt(encrypted, nonce, additionalData)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkKeyGeneration benchmarks key generation performance
func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateKeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}
