package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var MaxNonce = bytes.Repeat([]byte{255}, 12)

func EncodeHeader(h []byte, t byte, l int) {
	switch t {
	case 1:
		h[0] = 1
		h[1] = 1
		h[2] = 1
	case 0:
		h[0] = 0
		h[1] = 0
		h[2] = 0
	case 23:
		h[0] = 23
		h[1] = 3
		h[2] = 3
	}
	h[3] = byte(l >> 8)
	h[4] = byte(l)
}

func DecodeHeader(h []byte) (t byte, l int, err error) {
	l = int(h[3])<<8 | int(h[4])
	if h[0] == 23 && h[1] == 3 && h[2] == 3 {
		t = 23
	} else if h[0] == 0 && h[1] == 0 && h[2] == 0 {
		t = 0
	} else if h[0] == 1 && h[1] == 1 && h[2] == 1 {
		t = 1
	} else {
		l = 0
	}
	if l < 17 || l > 17000 { // TODO: TLSv1.3 max length
		err = errors.New("invalid header: ", fmt.Sprintf("%v", h[:5])) // DO NOT CHANGE: relied by client's Read()
	}
	return
}

func ReadAndDecodeHeader(conn net.Conn) (h []byte, t byte, l int, err error) {
	h = make([]byte, 5)
	if _, err = io.ReadFull(conn, h); err != nil {
		return
	}
	t, l, err = DecodeHeader(h)
	return
}

func ReadAndDiscardPaddings(conn net.Conn) (h []byte, t byte, l int, err error) {
	for {
		if h, t, l, err = ReadAndDecodeHeader(conn); err != nil || t != 23 {
			return
		}
		if _, err = io.ReadFull(conn, make([]byte, l)); err != nil {
			return
		}
	}
}

func NewAead(c byte, secret, salt, info []byte) (aead cipher.AEAD) {
	key := make([]byte, 32)
	hkdf.New(sha256.New, secret, salt, info).Read(key)
	if c&1 == 1 {
		block, _ := aes.NewCipher(key)
		aead, _ = cipher.NewGCM(block)
	} else {
		aead, _ = chacha20poly1305.New(key)
	}
	return
}

func IncreaseNonce(nonce []byte) {
	for i := range 12 {
		nonce[11-i]++
		if nonce[11-i] != 0 {
			break
		}
	}
}
