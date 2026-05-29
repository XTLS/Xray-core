package realm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const (
	MaxPunchPadding = 1024

	punchSaltLen = 8
	// Plain punch payload before obfs:
	// 8-byte magic, 1-byte type, 16-byte nonce, then 0..1024 random padding bytes.
	punchHeaderLen  = 25
	punchMinWireLen = punchSaltLen + punchHeaderLen
	punchMaxWireLen = punchMinWireLen + MaxPunchPadding
)

var (
	ErrInvalidPunchPacket = errors.New("invalid punch packet")

	punchMagic = [8]byte{'H', 'Y', 'R', 'L', 'M', 'v', '1', 0}
)

type PunchPacketType byte

const (
	PunchPacketHello PunchPacketType = 0x01
	PunchPacketAck   PunchPacketType = 0x02
)

type PunchPacket struct {
	Type          PunchPacketType
	PaddingLength int
}

func EncodePunchPacket(packetType PunchPacketType, meta PunchMetadata) ([]byte, error) {
	if !validPunchPacketType(packetType) {
		return nil, fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	}
	nonce, obfsKey, err := decodePunchMetadata(meta)
	if err != nil {
		return nil, err
	}
	paddingLength, err := randomPaddingLength()
	if err != nil {
		return nil, err
	}
	plain := make([]byte, punchHeaderLen+paddingLength)
	copy(plain[:len(punchMagic)], punchMagic[:])
	plain[len(punchMagic)] = byte(packetType)
	copy(plain[len(punchMagic)+1:punchHeaderLen], nonce)
	if paddingLength > 0 {
		if _, err := rand.Read(plain[punchHeaderLen:]); err != nil {
			return nil, err
		}
	}
	packet := make([]byte, punchSaltLen+len(plain))
	if _, err := rand.Read(packet[:punchSaltLen]); err != nil {
		return nil, err
	}
	copy(packet[punchSaltLen:], plain)
	xorPunchPacket(packet[punchSaltLen:], obfsKey, packet[:punchSaltLen])
	return packet, nil
}

func DecodePunchPacket(packet []byte, meta PunchMetadata) (PunchPacket, error) {
	if len(packet) < punchMinWireLen {
		return PunchPacket{}, fmt.Errorf("%w: packet too short", ErrInvalidPunchPacket)
	}
	if len(packet) > punchMaxWireLen {
		return PunchPacket{}, fmt.Errorf("%w: packet too long", ErrInvalidPunchPacket)
	}
	nonce, obfsKey, err := decodePunchMetadata(meta)
	if err != nil {
		return PunchPacket{}, err
	}
	salt := packet[:punchSaltLen]
	plain := append([]byte(nil), packet[punchSaltLen:]...)
	xorPunchPacket(plain, obfsKey, salt)
	if !bytes.Equal(plain[:len(punchMagic)], punchMagic[:]) {
		return PunchPacket{}, fmt.Errorf("%w: bad magic", ErrInvalidPunchPacket)
	}
	packetType := PunchPacketType(plain[len(punchMagic)])
	if !validPunchPacketType(packetType) {
		return PunchPacket{}, fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	}
	if !bytes.Equal(plain[len(punchMagic)+1:punchHeaderLen], nonce) {
		return PunchPacket{}, fmt.Errorf("%w: nonce mismatch", ErrInvalidPunchPacket)
	}
	return PunchPacket{
		Type:          packetType,
		PaddingLength: len(plain) - punchHeaderLen,
	}, nil
}

func decodePunchMetadata(meta PunchMetadata) (nonce, obfsKey []byte, err error) {
	nonce, err = decodeHexSize("nonce", meta.Nonce, PunchNonceSize)
	if err != nil {
		return nil, nil, err
	}
	obfsKey, err = decodeHexSize("obfs", meta.Obfs, PunchObfsKeySize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, obfsKey, nil
}

func decodeHexSize(name, value string, size int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", ErrInvalidPunchPacket, name)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: invalid %s length", ErrInvalidPunchPacket, name)
	}
	return b, nil
}

func randomPaddingLength() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(MaxPunchPadding+1))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func xorPunchPacket(packet, obfsKey, salt []byte) {
	h := sha256.New()
	_, _ = h.Write(obfsKey)
	_, _ = h.Write(salt)
	mask := h.Sum(nil)
	for i := range packet {
		packet[i] ^= mask[i%len(mask)]
	}
}

func validPunchPacketType(packetType PunchPacketType) bool {
	return packetType == PunchPacketHello || packetType == PunchPacketAck
}
