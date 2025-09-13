// package sush implements cryptographic operations for the Sush protocol
package sush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// CryptoManager handles all cryptographic operations for Sush
type CryptoManager struct {
	aead cipher.AEAD
	key  [32]byte
}

// NewCryptoManager creates a new crypto manager with the given key
func NewCryptoManager(key [32]byte) (*CryptoManager, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &CryptoManager{
		aead: aead,
		key:  key,
	}, nil
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (private, public [32]byte, err error) {
	_, err = rand.Read(private[:])
	if err != nil {
		return
	}

	curve25519.ScalarBaseMult(&public, &private)
	return
}

// ComputeSharedSecret computes the shared secret using X25519
func ComputeSharedSecret(private, public [32]byte) ([32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &private, &public)
	return shared, nil
}

// DeriveSessionKey derives a session key from shared secret and handshake data
func DeriveSessionKey(sharedSecret [32]byte, clientNonce, serverNonce [12]byte) [32]byte {
	// Use HKDF to derive session key
	salt := make([]byte, 32)
	copy(salt[:16], clientNonce[:])
	copy(salt[16:], serverNonce[:])

	info := []byte("Sush-session-key-v1")
	hkdf := hkdf.New(sha256.New, sharedSecret[:], salt, info)

	var sessionKey [32]byte
	hkdf.Read(sessionKey[:])
	return sessionKey
}

// Encrypt encrypts data using ChaCha20-Poly1305
func (cm *CryptoManager) Encrypt(plaintext []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes")
	}

	ciphertext := cm.aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts data using ChaCha20-Poly1305
func (cm *CryptoManager) Decrypt(ciphertext []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes")
	}

	plaintext, err := cm.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptFrame encrypts a frame payload
func (cm *CryptoManager) EncryptFrame(frame *Frame) error {
	additionalData := make([]byte, 3)
	binary.BigEndian.PutUint16(additionalData[0:2], frame.Length)
	additionalData[2] = frame.Command

	encrypted, err := cm.Encrypt(frame.Payload, frame.Nonce, additionalData)
	if err != nil {
		return err
	}

	frame.Payload = encrypted
	// Don't change frame.Length - keep original for decryption
	return nil
}

// DecryptFrame decrypts a frame payload
func (cm *CryptoManager) DecryptFrame(frame *Frame) error {
	additionalData := make([]byte, 3)
	binary.BigEndian.PutUint16(additionalData[0:2], frame.Length)
	additionalData[2] = frame.Command

	decrypted, err := cm.Decrypt(frame.Payload, frame.Nonce, additionalData)
	if err != nil {
		return err
	}

	frame.Payload = decrypted
	// Don't change frame.Length - it should remain the original
	return nil
}

// EncryptWithPSK encrypts data with a pre-shared key (for policy requests)
func EncryptWithPSK(plaintext []byte, psk []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes")
	}

	// Derive key from PSK
	key := sha256.Sum256(psk)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptWithPSK decrypts data with a pre-shared key
func DecryptWithPSK(ciphertext []byte, psk []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes")
	}

	// Derive key from PSK
	key := sha256.Sum256(psk)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GenerateNonce generates a random 12-byte nonce
func GenerateNonce() ([12]byte, error) {
	var nonce [12]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// VerifyHMAC verifies HMAC-SHA256 signature
func VerifyHMAC(data, key, signature []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)

	return subtle.ConstantTimeCompare(signature, expectedMAC) == 1
}

// GenerateHMAC generates HMAC-SHA256 signature
func GenerateHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ConstantTimeCompare performs constant-time comparison
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ReplayProtection provides protection against replay attacks
type ReplayProtection struct {
	seenNonces map[string]time.Time
	maxAge     time.Duration
}

// NewReplayProtection creates a new replay protection instance
func NewReplayProtection(maxAge time.Duration) *ReplayProtection {
	return &ReplayProtection{
		seenNonces: make(map[string]time.Time),
		maxAge:     maxAge,
	}
}

// CheckAndAdd checks if a nonce has been seen before and adds it
func (rp *ReplayProtection) CheckAndAdd(nonce []byte) bool {
	nonceStr := string(nonce)
	now := time.Now()

	// Clean up old nonces
	for n, t := range rp.seenNonces {
		if now.Sub(t) > rp.maxAge {
			delete(rp.seenNonces, n)
		}
	}

	// Check if nonce exists
	if _, exists := rp.seenNonces[nonceStr]; exists {
		return false // Replay detected
	}

	// Add nonce
	rp.seenNonces[nonceStr] = now
	return true // New nonce
}
