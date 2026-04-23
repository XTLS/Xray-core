// Package noise provides a net.Conn-like interface for a
// Noise_NK_25519_ChaChaPoly_BLAKE2s. It encodes Noise messages onto a reliable
// stream using 16-bit length prefixes.
//
// https://noiseprotocol.org/noise.html
package noise

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// The length of public and private keys as returned by GeneratePrivkey.
const KeyLen = 32

const (
	MsgTypeHandshakeInit = 1
	MsgTypeHandshakeResp = 2
	MsgTypeTransport     = 4
)

// cipherSuite represents 25519_ChaChaPoly_BLAKE2s.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

func ReadMessageFrom(conn net.PacketConn) (byte, []byte, net.Addr, error) {
	var buf [1500]byte
	for {
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			return 0, nil, nil, err
		}
		if n >= 1 {
			return buf[0], buf[1:n], addr, nil
		}
	}
}

// newConfig instantiates configuration settings that are common to clients and
// servers.
func newConfig() noise.Config {
	return noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeNK,
		Prologue:    []byte("Champa 2021-06-17"),
	}
}

// GeneratePrivkey generates a private key. The corresponding private key can be
// generated using PubkeyFromPrivkey.
func GeneratePrivkey() ([]byte, error) {
	pair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	return pair.Private, err
}

// PubkeyFromPrivkey returns the public key that corresponds to privkey.
func PubkeyFromPrivkey(privkey []byte) []byte {
	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pubkey
}

// ReadKey reads a hex-encoded key from r. r must consist of a single line, with
// or without a '\n' line terminator. The line must consist of KeyLen
// hex-encoded bytes.
func ReadKey(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(io.LimitReader(r, 100))
	line, err := br.ReadString('\n')
	if err == io.EOF {
		err = nil
	}
	if err == nil {
		// Check that we're at EOF.
		_, err = br.ReadByte()
		if err == io.EOF {
			err = nil
		} else if err == nil {
			err = fmt.Errorf("file contains more than one line")
		}
	}
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\n")
	return DecodeKey(line)
}

// WriteKey writes the hex-encoded key in a single line to w.
func WriteKey(w io.Writer, key []byte) error {
	_, err := fmt.Fprintf(w, "%x\n", key)
	return err
}

// DecodeKey decodes a hex-encoded private or public key.
func DecodeKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err == nil && len(key) != KeyLen {
		err = fmt.Errorf("length is %d, expected %d", len(key), KeyLen)
	}
	return key, err
}

// EncodeKey encodes a hex-encoded private or public key.
func EncodeKey(key []byte) string {
	return hex.EncodeToString(key)
}
