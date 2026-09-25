package rawpacket

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// Frame layout (all integers big-endian):
//
//	0:4   magic (0x58445250 "XRDP")
//	4:1   version (1)
//	5:1   flags
//	6:2   reserved (zero)
//	8:16  session ID (random, chosen by the client per connection)
//	16:4  sequence number (per direction, starting at 0)
//	20:2  payload length
//	22:8  nonce (seq BE || direction byte || zeros)
//	30:   AES-256-GCM ciphertext || tag
//
// The header prefix (bytes 0..22) is authenticated as GCM AAD, so any
// modification of magic/version/flags/reserved/session/seq/len is
// detected. Direction byte in the nonce: 0 = client->relay, 1 = relay->client.
const (
	frameMagic     uint32 = 0x58445250
	frameVersion   byte   = 1
	frameHeaderLen        = 30
	frameTagLen           = 16
	frameNonceLen         = 8
	frameAADLen           = 22
	frameOverhead         = frameHeaderLen + frameTagLen

	frameFlagKeepalive byte = 0x01
	frameFlagServer    byte = 0x02

	// frameMaxPayload caps each datagram so the full frame fits inside a
	// single unfragmented packet on typical links (1400 + 46 < 1480).
	frameMaxPayload = 1400
)

var (
	errFrameShort  = errors.New("rawpacket: frame too short")
	errFrameBad    = errors.New("rawpacket: invalid frame")
	errFrameAuth   = errors.New("rawpacket: frame authentication failed")
	errFrameReplay = errors.New("rawpacket: frame replay rejected")
)

// replayWindow is a sliding-window anti-replay filter for a single
// direction of a session (RFC 4303 style). The window covers the highest
// received sequence number and the replayWindowSize-1 sequence numbers
// below it, so packets may arrive up to replayWindowSize-1 out of order.
// Every sequence number is accepted exactly once.
type replayWindow struct {
	base   uint32
	bitmap uint64
}

const replayWindowSize = 64

// accept reports whether seq has not been seen before. Bit i of bitmap
// records seq = base - (replayWindowSize - 1 - i); bit 63 is base.
func (w *replayWindow) accept(seq uint32) bool {
	if w.base == 0 && w.bitmap == 0 {
		w.base = seq
		w.bitmap = 1 << (replayWindowSize - 1)
		return true
	}
	diff := int32(seq - w.base)
	switch {
	case diff > 0:
		if diff < int32(replayWindowSize) {
			// Advance: old entries shift down, new seq lands on top.
			w.bitmap >>= uint(diff)
			w.bitmap |= 1 << (replayWindowSize - 1)
		} else {
			// Jump: the whole old window is discarded.
			w.bitmap = 1 << (replayWindowSize - 1)
		}
		w.base = seq
		return true
	case diff < 0:
		offset := int32(replayWindowSize) - 1 + diff
		if offset < 0 {
			return false
		}
		bit := uint64(1) << uint(offset)
		if w.bitmap&bit != 0 {
			return false
		}
		w.bitmap |= bit
		return true
	default:
		// seq == base: duplicate unless the top bit is somehow clear.
		if w.bitmap&(1<<(replayWindowSize-1)) != 0 {
			return false
		}
		w.bitmap |= 1 << (replayWindowSize - 1)
		return true
	}
}

// frameCrypto owns the per-session keys and per-direction sequence/replay
// state. One instance exists per session on each side. The two directions
// have independent mutexes so uplink and downlink never contend.
type frameCrypto struct {
	sid        [8]byte
	clientAEAD cipher.AEAD
	serverAEAD cipher.AEAD

	clientSeq uint32
	serverSeq uint32
	clientRep replayWindow
	serverRep replayWindow

	clientMu sync.Mutex
	serverMu sync.Mutex
}

func newFrameCrypto(psk []byte, sid [8]byte) (*frameCrypto, error) {
	clientKey, err := deriveFrameKey(psk, sid, []byte("rawpacket-client-v1"))
	if err != nil {
		return nil, err
	}
	serverKey, err := deriveFrameKey(psk, sid, []byte("rawpacket-server-v1"))
	if err != nil {
		return nil, err
	}
	clientAEAD, err := newGCM(clientKey)
	if err != nil {
		return nil, err
	}
	serverAEAD, err := newGCM(serverKey)
	if err != nil {
		return nil, err
	}
	return &frameCrypto{
		sid:        sid,
		clientAEAD: clientAEAD,
		serverAEAD: serverAEAD,
	}, nil
}

func deriveFrameKey(psk []byte, sid [8]byte, info []byte) ([]byte, error) {
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, psk, sid[:], info)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, frameNonceLen)
}

func newSessionID() ([8]byte, error) {
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return sid, err
	}
	return sid, nil
}

func frameNonce(seq uint32, server bool) [frameNonceLen]byte {
	var n [frameNonceLen]byte
	binary.BigEndian.PutUint32(n[0:4], seq)
	if server {
		n[4] = 1
	}
	return n
}

// seal builds and encrypts one frame from payload. server selects the
// relay->client direction. The sequence counter and replay window are
// updated. Payload is capped at frameMaxPayload.
func (f *frameCrypto) seal(server bool, payload []byte, keepalive bool) ([]byte, error) {
	if len(payload) > frameMaxPayload {
		return nil, errors.New("rawpacket: payload exceeds frameMaxPayload")
	}
	if server {
		f.serverMu.Lock()
		defer f.serverMu.Unlock()
	} else {
		f.clientMu.Lock()
		defer f.clientMu.Unlock()
	}

	seq := f.clientSeq
	var aead cipher.AEAD
	if server {
		seq = f.serverSeq
		f.serverSeq++
		aead = f.serverAEAD
	} else {
		seq = f.clientSeq
		f.clientSeq++
		aead = f.clientAEAD
	}

	flags := byte(0)
	if server {
		flags |= frameFlagServer
	}
	if keepalive {
		flags |= frameFlagKeepalive
	}

	out := make([]byte, frameHeaderLen+len(payload)+frameTagLen)
	binary.BigEndian.PutUint32(out[0:4], frameMagic)
	out[4] = frameVersion
	out[5] = flags
	// 6:7 reserved
	copy(out[8:16], f.sid[:])
	binary.BigEndian.PutUint32(out[16:20], seq)
	binary.BigEndian.PutUint16(out[20:22], uint16(len(payload)))

	nonce := frameNonce(seq, server)
	aead.Seal(out[frameHeaderLen:frameHeaderLen], nonce[:], payload, out[:frameAADLen])
	return out, nil
}

// open parses, authenticates and decrypts one frame. server selects the
// direction the frame is expected from. The returned payload is freshly
// allocated and safe to retain.
func (f *frameCrypto) open(b []byte, server bool) (payload []byte, flags byte, err error) {
	if len(b) < frameHeaderLen+frameTagLen {
		return nil, 0, errFrameShort
	}
	if binary.BigEndian.Uint32(b[0:4]) != frameMagic || b[4] != frameVersion {
		return nil, 0, errFrameBad
	}
	flags = b[5]
	if (flags&frameFlagServer != 0) != server {
		return nil, 0, errFrameBad
	}
	pLen := int(binary.BigEndian.Uint16(b[20:22]))
	if pLen != len(b)-frameHeaderLen-frameTagLen {
		return nil, 0, errFrameBad
	}
	seq := binary.BigEndian.Uint32(b[16:20])

	if server {
		f.serverMu.Lock()
		defer f.serverMu.Unlock()
	} else {
		f.clientMu.Lock()
		defer f.clientMu.Unlock()
	}

	var aead cipher.AEAD
	var rep *replayWindow
	if server {
		aead = f.serverAEAD
		rep = &f.serverRep
	} else {
		aead = f.clientAEAD
		rep = &f.clientRep
	}
	if !rep.accept(seq) {
		return nil, 0, errFrameReplay
	}
	nonce := frameNonce(seq, server)
	ct := b[frameHeaderLen : frameHeaderLen+pLen+frameTagLen]
	pt, err := aead.Open(nil, nonce[:], ct, b[:frameAADLen])
	if err != nil {
		return nil, 0, errFrameAuth
	}
	return pt, flags, nil
}

// frameSessionID extracts the session ID from a frame header without
// decrypting it. Returns false for non-frame traffic (which the relay must
// silently ignore: real TLS, kernel noise, etc.).
func frameSessionID(b []byte) (sid [8]byte, ok bool) {
	if len(b) < frameHeaderLen {
		return sid, false
	}
	if binary.BigEndian.Uint32(b[0:4]) != frameMagic || b[4] != frameVersion {
		return sid, false
	}
	copy(sid[:], b[8:16])
	return sid, true
}

// sealSplit splits a large payload into frames of at most maxPayload and
// seals each one in sequence order.
func (f *frameCrypto) sealSplit(server bool, payload []byte, maxPayload int, keepalive bool) ([][]byte, error) {
	if maxPayload <= 0 {
		maxPayload = frameMaxPayload
	}
	if len(payload) == 0 {
		frame, err := f.seal(server, nil, keepalive)
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil
	}
	frames := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		frame, err := f.seal(server, chunk, false)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
		payload = payload[len(chunk):]
	}
	return frames, nil
}
