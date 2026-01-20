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
	copy(encrypted[nonceSize:], plain)
	plaintext := encrypted[nonceSize : nonceSize+len(plain)]

	sealed := aead.Seal(plaintext[:0], nonce, plaintext, nil)

	assert.Equal(t, &sealed[0], &plaintext[0])
	assert.Equal(t, sealed, encrypted[nonceSize:nonceSize+aead.Overhead()+len(plain)])

	opened, _ := aead.Open(encrypted[0:0], encrypted[:nonceSize], encrypted[nonceSize:nonceSize+aead.Overhead()+len(plain)], nil)
	assert.Equal(t, plain, opened)
	assert.Equal(t, &opened[0], &encrypted[0])
	assert.Equal(t, opened, encrypted[:len(opened)])
}
