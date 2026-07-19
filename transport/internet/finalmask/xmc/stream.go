// Minecraft stream cipher
package xmc

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

type cryptoStream struct {
	stream cipher.Stream
	r      io.Reader
	w      io.Writer
	mu     sync.Mutex
}

func newCryptoReader(r io.Reader, sharedSecret []byte) (*cryptoStream, error) {
	blockCipher, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}

	stream := newCFB8Decrypt(blockCipher, sharedSecret)

	return &cryptoStream{stream: stream, r: r}, nil
}

func (c *cryptoStream) Read(b []byte) (int, error) {
	if c.r == nil {
		panic("read on a write-only crypto stream")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	n, err := c.r.Read(b)
	if n > 0 {
		c.stream.XORKeyStream(b[:n], b[:n])
	}
	if err != nil {
		if err == io.EOF {
			return n, io.EOF
		}
		return n, fmt.Errorf("crypto reader: read: %w", err)
	}

	return n, nil
}

func newCryptoWriter(w io.Writer, sharedSecret []byte) (*cryptoStream, error) {
	blockCipher, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}

	stream := newCFB8Encrypt(blockCipher, sharedSecret)

	return &cryptoStream{stream: stream, w: w}, nil
}

func (c *cryptoStream) Write(b []byte) (int, error) {
	if c.w == nil {
		panic("write on a read-only crypto stream")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	encrypted := make([]byte, len(b))
	c.stream.XORKeyStream(encrypted, b)

	if err := writeFull(c.w, encrypted); err != nil {
		return 0, fmt.Errorf("crypto writer: write: %w", err)
	}

	return len(b), nil
}
