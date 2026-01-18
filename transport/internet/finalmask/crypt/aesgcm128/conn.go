package aesgcm128

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type aesgcm128Conn struct {
	conn net.PacketConn
	aead cipher.AEAD
}

func NewConn(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	hashedSeed := sha256.Sum256([]byte(c.Seed))
	return &aesgcm128Conn{
		conn: raw,
		aead: crypto.NewAesGcm(hashedSeed[:16]),
	}, nil
}

func (c *aesgcm128Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	nonceSize := c.aead.NonceSize()
	overhead := c.aead.Overhead()
	if len(p) <= nonceSize+overhead {
		return 0, addr, errors.New("aead len(p)")
	}
	out, err := c.aead.Open(p[nonceSize:nonceSize], p[:nonceSize], p[nonceSize:n], nil)
	if err != nil {
		return 0, addr, errors.New("aead open").Base(err)
	}

	n = copy(p, out)
	if n != len(out) {
		return 0, addr, io.ErrShortBuffer
	}
	return n, addr, err
}

func (c *aesgcm128Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := buf.StackNew()
	defer b.Release()

	nonceSize := c.aead.NonceSize()
	common.Must2(b.ReadFullFrom(rand.Reader, int32(nonceSize)))
	nonce := b.BytesFrom(int32(-nonceSize))

	encrypted := b.Extend(int32(c.aead.Overhead() + len(p)))
	encrypted = c.aead.Seal(encrypted[:0], nonce, p, nil)

	return c.conn.WriteTo(b.Bytes(), addr)
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
