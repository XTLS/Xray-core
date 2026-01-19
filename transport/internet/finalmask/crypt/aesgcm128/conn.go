package aesgcm128

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type aesgcm128Conn struct {
	first     bool
	leaveSize int32

	conn net.PacketConn
	aead cipher.AEAD
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	hashedSeed := sha256.Sum256([]byte(c.Psk))
	return &aesgcm128Conn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		aead: crypto.NewAesGcm(hashedSeed[:16]),
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *aesgcm128Conn) Size() int32 {
	return int32(c.aead.NonceSize()) + int32(c.aead.Overhead())
}

func (c *aesgcm128Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) && (len(p) != 8192) {
		b := buf.StackNew()
		defer b.Release()
		bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
	}

	n, addr, err = c.conn.ReadFrom(bufp)
	if err != nil {
		return n, addr, err
	}

	nonceSize := c.aead.NonceSize()
	nonce := bufp[:c.leaveSize+int32(nonceSize)]
	ciphertext := bufp[int32(nonceSize):n]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, addr, errors.New("aead open").Base(err)
	}

	nn := copy(p, plaintext)
	if nn != len(plaintext) {
		return 0, addr, errors.New("nn != len(plaintext)")
	}

	return nn, addr, nil
}

func (c *aesgcm128Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	data := p
	bufp := p
	if c.first && (c.leaveSize+c.Size() > 0) {
		if len(p) != 8192 {
			b := buf.StackNew()
			defer b.Release()
			bufp = b.Extend(c.leaveSize + c.Size() + int32(len(p)))
		}
		copy(bufp[c.leaveSize+c.Size():], p)
	} else {
		data = p[c.leaveSize+c.Size():]
	}

	nonceSize := c.aead.NonceSize()
	nonce := bufp[c.leaveSize : c.leaveSize+int32(nonceSize)]
	common.Must2(rand.Read(nonce))
	plaintext := data
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	nn := copy(bufp[c.leaveSize+int32(nonceSize):], ciphertext)
	if nn != len(ciphertext) {
		return 0, errors.New("nn != len(ciphertext)")
	}
	nn += int(c.leaveSize) + nonceSize

	if _, err := c.conn.WriteTo(bufp[:nn], addr); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *aesgcm128Conn) Close() error {
	return c.conn.Close()
}

func (c *aesgcm128Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *aesgcm128Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *aesgcm128Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *aesgcm128Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
