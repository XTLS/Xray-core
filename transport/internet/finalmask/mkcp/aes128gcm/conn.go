package aes128gcm

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	sync "sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type aes128gcmConn struct {
	first     bool
	leaveSize int32

	conn net.PacketConn
	aead cipher.AEAD

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	hashedPsk := sha256.Sum256([]byte(c.Password))

	conn := &aes128gcmConn{
		first:     first,
		leaveSize: leaveSize,

		conn: raw,
		aead: crypto.NewAesGcm(hashedPsk[:16]),
	}

	if first {
		conn.readBuf = make([]byte, 8192)
		conn.writeBuf = make([]byte, 8192)
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.PacketConn, first bool, leaveSize int32) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *aes128gcmConn) Size() int32 {
	return int32(c.aead.NonceSize()) + int32(c.aead.Overhead())
}

func (c *aes128gcmConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.first {
		c.readMutex.Lock()

		n, addr, err = c.conn.ReadFrom(c.readBuf)
		if err != nil {
			c.readMutex.Unlock()
			return n, addr, err
		}

		if n < int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("aead").Base(io.ErrShortBuffer)
		}

		if len(p) < n-int(c.Size()) {
			c.readMutex.Unlock()
			return 0, addr, errors.New("aead").Base(io.ErrShortBuffer)
		}

		nonceSize := c.aead.NonceSize()
		nonce := c.readBuf[:nonceSize]
		ciphertext := c.readBuf[nonceSize:n]
		_, err = c.aead.Open(p[:0], nonce, ciphertext, nil)
		if err != nil {
			c.readMutex.Unlock()
			return 0, addr, errors.New("aead open").Base(err)
		}

		c.readMutex.Unlock()
		return n - int(c.Size()), addr, nil
	}

	n, addr, err = c.conn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if n < int(c.Size()) {
		return 0, addr, errors.New("aead").Base(io.ErrShortBuffer)
	}

	nonceSize := c.aead.NonceSize()
	nonce := p[:nonceSize]
	ciphertext := p[nonceSize:n]
	_, err = c.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return 0, addr, errors.New("aead open").Base(err)
	}
	copy(p, p[nonceSize:n-c.aead.Overhead()])

	return n - int(c.Size()), addr, nil
}

func (c *aes128gcmConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.first {
		if c.leaveSize+c.Size()+int32(len(p)) > 8192 {
			return 0, errors.New("too many masks")
		}

		c.writeMutex.Lock()

		n = copy(c.writeBuf[c.leaveSize+int32(c.aead.NonceSize()):], p)
		// n = copy(c.writeBuf[c.leaveSize+c.Size():], p)
		n += int(c.leaveSize) + int(c.Size())

		nonceSize := c.aead.NonceSize()
		nonce := c.writeBuf[c.leaveSize : c.leaveSize+int32(nonceSize)]
		common.Must2(rand.Read(nonce))
		// copy(c.writeBuf[c.leaveSize+int32(nonceSize):], c.writeBuf[c.leaveSize+c.Size():n])
		plaintext := c.writeBuf[c.leaveSize+int32(nonceSize) : n-c.aead.Overhead()]
		_ = c.aead.Seal(plaintext[:0], nonce, plaintext, nil)

		nn, err := c.conn.WriteTo(c.writeBuf[:n], addr)

		if err != nil {
			c.writeMutex.Unlock()
			return 0, err
		}

		if nn != n {
			c.writeMutex.Unlock()
			return 0, errors.New("nn != n")
		}

		c.writeMutex.Unlock()
		return len(p), nil
	}

	nonceSize := c.aead.NonceSize()
	nonce := p[c.leaveSize : c.leaveSize+int32(nonceSize)]
	common.Must2(rand.Read(nonce))
	copy(p[c.leaveSize+int32(nonceSize):], p[c.leaveSize+c.Size():])
	plaintext := p[c.leaveSize+int32(nonceSize) : len(p)-c.aead.Overhead()]
	_ = c.aead.Seal(plaintext[:0], nonce, plaintext, nil)

	return c.conn.WriteTo(p, addr)
}

func (c *aes128gcmConn) Close() error {
	return c.conn.Close()
}

func (c *aes128gcmConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *aes128gcmConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *aes128gcmConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *aes128gcmConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
