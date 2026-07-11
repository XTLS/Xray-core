// Minecraft stream cipher
package xmc

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

type cryptoStream struct {
	stream cipher.Stream
	r      io.Reader
	w      io.Writer
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

	n, err := c.r.Read(b)
	if err != nil {
		return 0, fmt.Errorf("crypto reader: read: %w", err)
	}

	c.stream.XORKeyStream(b[:n], b[:n])

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

	encrypted := make([]byte, len(b))
	c.stream.XORKeyStream(encrypted, b)

	n, err := c.w.Write(encrypted)
	if err != nil {
		return 0, fmt.Errorf("crypto writer: write: %w", err)
	}

	return n, nil
}
