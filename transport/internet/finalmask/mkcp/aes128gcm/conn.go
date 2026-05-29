package aes128gcm

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
)

type aes128gcmConn struct {
	net.PacketConn
	aead cipher.AEAD
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	hashedPsk := sha256.Sum256([]byte(c.Password))
	return &aes128gcmConn{
		PacketConn: raw,
		aead:       crypto.NewAesGcm(hashedPsk[:16]),
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *aes128gcmConn) Size() int {
	return c.aead.NonceSize()
}

func (c *aes128gcmConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()
	_, err = c.aead.Open(p[nonceSize:nonceSize], p[:nonceSize], p[nonceSize:], nil)
	if err != nil {
		return 0, nil, err
	}
	return len(p) - nonceSize - overhead, nil, nil
}

func (c *aes128gcmConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()
	common.Must2(rand.Read(p[:nonceSize]))
	_ = c.aead.Seal(p[nonceSize:nonceSize], p[:nonceSize], p[nonceSize:], nil)
	return len(p) + overhead, nil
}
