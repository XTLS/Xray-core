package simple

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleInPlace(t *testing.T) {
	aead := &simple{}

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
