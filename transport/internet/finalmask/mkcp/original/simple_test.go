package original_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
)

func TestOriginalBounce(t *testing.T) {
	aead := original.NewSimple()
	buf := make([]byte, aead.NonceSize()+aead.Overhead())
	for i := 0; i < 1000; i++ {
		_, _ = rand.Read(buf)
		_, err := aead.Open(buf[:0], nil, buf, nil)
		assert.NotEqual(t, err, nil)
	}
}
