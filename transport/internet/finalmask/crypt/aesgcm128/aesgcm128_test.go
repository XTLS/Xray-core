package aesgcm128

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xtls/xray-core/common/crypto"
)

func TestAesGcm128InPlace(t *testing.T) {
	hashedPsk := sha256.Sum256([]byte("psk"))
	aead := crypto.NewAesGcm(hashedPsk[:16])

	plain := []byte("plain")

	encrypted := make([]byte, 2048)

	nonceSize := aead.NonceSize()
	nonce := encrypted[:nonceSize]
	rand.Read(nonce)

	ciphertext := aead.Seal(encrypted[nonceSize:nonceSize], nonce, plain, nil)

	assert.Equal(t, &ciphertext[0], &encrypted[nonceSize])
	assert.Equal(t, ciphertext, encrypted[nonceSize:len(ciphertext)+nonceSize])
	assert.Equal(t, len(ciphertext)+nonceSize, len(plain)+nonceSize+aead.Overhead())

	plaintext, _ := aead.Open(encrypted[0:0], encrypted[:nonceSize], encrypted[nonceSize:len(ciphertext)+nonceSize], nil)
	assert.Equal(t, plain, plaintext)
	assert.Equal(t, &plaintext[0], &encrypted[0])
	assert.Equal(t, plaintext, encrypted[:len(plaintext)])
}
