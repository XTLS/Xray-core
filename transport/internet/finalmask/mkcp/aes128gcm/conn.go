package aes128gcm

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type aes128gcmConn struct {
	net.PacketConn
	aead cipher.AEAD
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	hashedPsk := sha256.Sum256([]byte(c.Password))

	conn := &aes128gcmConn{
		PacketConn: raw,
		aead:       crypto.NewAesGcm(hashedPsk[:16]),
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *aes128gcmConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if len(p) < finalmask.UDPSize {
		buf := make([]byte, finalmask.UDPSize)

		n, addr, err = c.PacketConn.ReadFrom(buf)
		if err != nil || n == 0 {
			return n, addr, err
		}

		if n < c.aead.NonceSize()+c.aead.Overhead() {
			errors.LogDebug(context.Background(), addr, " mask read err aead short lenth ", n)
			return 0, addr, nil
		}

		nonceSize := c.aead.NonceSize()
		nonce := buf[:nonceSize]
		ciphertext := buf[nonceSize:n]
		plaintext, err := c.aead.Open(p[:0], nonce, ciphertext, nil)
		if err != nil {
			errors.LogDebug(context.Background(), addr, " mask read err aead open ", err)
			return 0, addr, nil
		}

		if len(plaintext) > len(p) {
			errors.LogDebug(context.Background(), addr, " mask read err short buffer ", len(p), " ", len(plaintext))
			return 0, addr, io.ErrShortBuffer
		}

		return n - c.aead.NonceSize() - c.aead.Overhead(), addr, nil
	}

	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil || n == 0 {
		return n, addr, err
	}

	if n < c.aead.NonceSize()+c.aead.Overhead() {
		errors.LogDebug(context.Background(), addr, " mask read err aead short lenth ", n)
		return 0, addr, nil
	}

	nonceSize := c.aead.NonceSize()
	nonce := p[:nonceSize]
	ciphertext := p[nonceSize:n]
	_, err = c.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		errors.LogDebug(context.Background(), addr, " mask read err aead open ", err)
		return 0, addr, nil
	}

	copy(p, p[nonceSize:n-c.aead.Overhead()])

	return n - c.aead.NonceSize() - c.aead.Overhead(), addr, nil
}

func (c *aes128gcmConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.aead.NonceSize()+c.aead.Overhead()+len(p) > finalmask.UDPSize {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", c.aead.NonceSize()+c.aead.Overhead()+len(p), " ", finalmask.UDPSize)
		return 0, io.ErrShortWrite
	}

	var buf []byte
	if cap(p) != finalmask.UDPSize {
		buf = make([]byte, finalmask.UDPSize)
	} else {
		buf = p[:c.aead.NonceSize()+c.aead.Overhead()+len(p)]
		copy(buf[c.aead.NonceSize():], p)
		p = buf[c.aead.NonceSize() : c.aead.NonceSize()+len(p)]
	}

	nonceSize := c.aead.NonceSize()
	nonce := buf[:nonceSize]
	common.Must2(rand.Read(nonce))
	ciphertext := buf[nonceSize : c.aead.NonceSize()+c.aead.Overhead()+len(p)]
	_ = c.aead.Seal(ciphertext[:0], nonce, p, nil)

	_, err = c.PacketConn.WriteTo(buf[:c.aead.NonceSize()+c.aead.Overhead()+len(p)], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
