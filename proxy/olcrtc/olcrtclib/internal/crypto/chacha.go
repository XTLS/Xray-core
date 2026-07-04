// Package crypto provides cryptographic functions.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// WireOverhead is the number of bytes added to each encrypted message.
const WireOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

var (
	// ErrInvalidKeySize is returned when the encryption key is not 32 bytes.
	ErrInvalidKeySize = errors.New("invalid key size")
	// ErrCiphertextTooShort is returned when the ciphertext is shorter than the nonce size.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// nonceSaltSize is the prefix of the XChaCha20 24-byte nonce that is
// chosen randomly once at Cipher construction. The remaining 8 bytes
// hold a monotonic counter incremented on every Encrypt call. With a
// fresh per-Cipher salt and a 64-bit counter, the (salt, counter) pair
// is unique for every encryption operation as long as the same Cipher
// instance is used (>10^19 messages before counter wrap).
const nonceSaltSize = chacha20poly1305.NonceSizeX - 8

// Cipher provides AEAD encryption and decryption using XChaCha20-Poly1305.
//
// Nonces are generated deterministically as `salt || counter` where the
// salt is a per-instance random 16-byte prefix and the counter is a
// monotonic 64-bit suffix. This avoids the syscall + global lock that
// crypto/rand.Read would impose on every encrypt call, which dominated
// the data-plane CPU profile under sustained throughput.
//
// The wire format is unchanged: ciphertexts are still [24-byte nonce]
// [encrypted payload][16-byte tag], so a peer using the previous
// random-nonce implementation can decrypt messages produced here, and
// vice versa.
type Cipher struct {
	aead    cipher.AEAD
	salt    [nonceSaltSize]byte
	counter atomic.Uint64
}

// NewCipher creates a new Cipher instance with the given 32-byte key.
func NewCipher(keyStr string) (*Cipher, error) {
	key := []byte(keyStr)
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead: %w", err)
	}

	c := &Cipher{aead: aead}
	if _, err := rand.Read(c.salt[:]); err != nil {
		return nil, fmt.Errorf("failed to seed nonce salt: %w", err)
	}

	return c, nil
}

// Encrypt encrypts plaintext and prepends a deterministic per-message
// nonce (random per-instance salt + monotonic counter).
//
// Allocates a single output buffer sized exactly for the resulting
// ciphertext, so AEAD.Seal does not have to grow the slice.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()

	// One alloc, sized for the full output: nonce || sealed(plaintext+tag).
	out := make([]byte, nonceSize, nonceSize+len(plaintext)+overhead)

	copy(out[:nonceSaltSize], c.salt[:])
	binary.BigEndian.PutUint64(out[nonceSaltSize:nonceSize], c.counter.Add(1))

	return c.aead.Seal(out, out[:nonceSize], plaintext, nil), nil
}

// Decrypt decrypts ciphertext that has a nonce prepended.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.DecryptInto(nil, ciphertext)
}

// DecryptInto appends the decrypted plaintext to dst (which can be nil)
// and returns the extended slice. Pass a buffer with enough spare
// capacity from a sync.Pool to avoid per-call allocations on the hot
// path: the AEAD primitive will write the plaintext in place when
// cap(dst) >= len(ciphertext) - WireOverhead.
func (c *Cipher) DecryptInto(dst, ciphertext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	res, err := c.aead.Open(dst, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return res, nil
}
