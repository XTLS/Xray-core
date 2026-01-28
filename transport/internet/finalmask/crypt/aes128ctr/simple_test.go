package aes128ctr_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xtls/xray-core/transport/internet/finalmask/crypt/aes128ctr"
)

func TestAes128CtrBounce(t *testing.T) {
	aead := aes128ctr.NewSimple()
	buf := make([]byte, aead.NonceSize()+aead.Overhead())
	for i := 0; i < 1000; i++ {
		_, _ = rand.Read(buf)
		_, err := aead.Open(buf[:0], nil, buf, nil)
		assert.NotEqual(t, err, nil)
	}
}
