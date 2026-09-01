package quic

import (
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"io"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
	"golang.org/x/crypto/hkdf"
)

type SniffHeader struct {
	domain string
}

func (s SniffHeader) Protocol() string {
	return "quic"
}

func (s SniffHeader) Domain() string {
	return s.domain
}

var (
	errNotQUIC        = errors.New("not quic")
	errNotQUICInitial = errors.New("not initial packet")
)

type quicVersionSpec struct {
	ver         uint32
	typeInitial byte
	initialSalt []byte
	labelPrefix string
}

var (
	quicDraft29 = quicVersionSpec{
		ver:         0xff00001d,
		typeInitial: 0b00,
		initialSalt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelPrefix: "quic",
	}
	quicV1 = quicVersionSpec{
		ver:         0x1,
		typeInitial: 0b00,
		initialSalt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelPrefix: "quic",
	}
	quicV2 = quicVersionSpec{
		ver:         0x6b3343cf,
		typeInitial: 0b01,
		initialSalt: []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		labelPrefix: "quicv2",
	}

	quicVersionSpecMap = map[uint32]*quicVersionSpec{
		quicDraft29.ver: &quicDraft29,
		quicV1.ver:      &quicV1,
		quicV2.ver:      &quicV2,
	}
)

func SniffQUIC(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	// Crypto data separated across packets
	cryptoLen := int32(0)
	cryptoDataBuf := buf.NewWithSize(32767)
	defer cryptoDataBuf.Release()
	cache := buf.New()
	defer cache.Release()

	// Parse QUIC packets
	for len(b) > 0 {
		buffer := buf.FromBytes(b)
		typeByte, err := buffer.ReadByte()
		if err != nil {
			return nil, errNotQUIC
		}

		isLongHeader := typeByte&0x80 > 0
		if !isLongHeader || typeByte&0x40 == 0 {
			return nil, errNotQUICInitial
		}

		vb, err := buffer.ReadBytes(4)
		if err != nil {
			return nil, errNotQUIC
		}

		versionNumber := binary.BigEndian.Uint32(vb)
		var s *quicVersionSpec
		if v, ok := quicVersionSpecMap[versionNumber]; ok {
			s = v
		} else {
			return nil, errNotQUIC
		}

		var destConnID []byte
		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQUIC
		} else if destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
			return nil, errNotQUIC
		}

		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQUIC
		} else if common.Error2(buffer.ReadBytes(int32(l))) != nil {
			return nil, errNotQUIC
		}

		packetType := (typeByte & 0x30) >> 4
		isQUICInitial := packetType == s.typeInitial

		if isQUICInitial { // Only initial packets have token, see https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
			tokenLen, err := readShortQUICVarint(buffer)
			if err != nil || tokenLen > int32(len(b)) {
				return nil, errNotQUIC
			}

			if _, err = buffer.ReadBytes(tokenLen); err != nil {
				return nil, errNotQUIC
			}
		}

		packetLen, err := readShortQUICVarint(buffer)
		if err != nil {
			return nil, errNotQUIC
		}
		// packetLen is impossible to be shorter than this
		if packetLen < 4 {
			return nil, errNotQUIC
		}

		hdrLen := len(b) - int(buffer.Len())
		if len(b) < hdrLen+int(packetLen) {
			return nil, common.ErrNoClue // Not enough data to read as a QUIC packet. QUIC is UDP-based, so this is unlikely to happen.
		}

		restPayload := b[hdrLen+int(packetLen):]
		if !isQUICInitial { // Skip this packet if it's not initial packet
			b = restPayload
			continue
		}

		salt := s.initialSalt
		label := s.labelPrefix
		initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
		secret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())
		hpKey := hkdfExpandLabel(secret, label+" hp", 16)
		block, err := aes.NewCipher(hpKey)
		if err != nil {
			return nil, err
		}
		if len(b) < hdrLen+4+block.BlockSize() {
			return nil, errNotQUIC
		}
		cache.Clear()
		mask := cache.Extend(int32(block.BlockSize()))
		block.Encrypt(mask, b[hdrLen+4:hdrLen+4+len(mask)])
		b[0] ^= mask[0] & 0xf
		packetNumberLength := int(b[0]&0x3 + 1)
		for i := range packetNumberLength {
			b[hdrLen+i] ^= mask[i+1]
		}

		key := hkdfExpandLabel(secret, label+" key", 16)
		iv := hkdfExpandLabel(secret, label+" iv", 12)
		cipher := AEADAESGCMTLS13(key, iv)

		nonce := cache.Extend(int32(cipher.NonceSize()))
		_, err = buffer.Read(nonce[len(nonce)-packetNumberLength:])
		if err != nil {
			return nil, err
		}

		extHdrLen := hdrLen + packetNumberLength
		data := b[extHdrLen : int(packetLen)+hdrLen]
		decrypted, err := cipher.Open(b[extHdrLen:extHdrLen], nonce, data, b[:extHdrLen])
		if err != nil {
			return nil, err
		}
		buffer = buf.FromBytes(decrypted)
		for !buffer.IsEmpty() {
			frameType, _ := buffer.ReadByte()
			for frameType == 0x0 && !buffer.IsEmpty() {
				frameType, _ = buffer.ReadByte()
			}
			switch frameType {
			case 0x00: // PADDING frame
			case 0x01: // PING frame
			case 0x02, 0x03: // ACK frame
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Largest Acknowledged
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Delay
					return nil, io.ErrUnexpectedEOF
				}
				ackRangeCount, err := readShortQUICVarint(buffer) // Field: ACK Range Count
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: First ACK Range
					return nil, io.ErrUnexpectedEOF
				}
				for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Range -> Gap
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Range -> ACK Range Length
						return nil, io.ErrUnexpectedEOF
					}
				}
				if frameType == 0x03 {
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
						return nil, io.ErrUnexpectedEOF
					}
				}
			case 0x06: // CRYPTO frame, we will use this frame
				offset, err := readShortQUICVarint(buffer) // Field: Offset
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				length, err := readShortQUICVarint(buffer) // Field: Length
				if err != nil || length > buffer.Len() {
					return nil, io.ErrUnexpectedEOF
				}
				currentCryptoLen := int32(offset + length)
				if cryptoLen < currentCryptoLen {
					if cryptoDataBuf.Cap() < currentCryptoLen {
						return nil, io.ErrShortBuffer
					}
					cryptoDataBuf.Extend(currentCryptoLen - cryptoLen)
					cryptoLen = currentCryptoLen
				}
				if _, err := buffer.Read(cryptoDataBuf.BytesRange(offset, currentCryptoLen)); err != nil { // Field: Crypto Data
					return nil, io.ErrUnexpectedEOF
				}
			case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Error Code
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Frame Type
					return nil, io.ErrUnexpectedEOF
				}
				length, err := readShortQUICVarint(buffer) // Field: Reason Phrase Length
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err := buffer.ReadBytes(int32(length)); err != nil { // Field: Reason Phrase
					return nil, io.ErrUnexpectedEOF
				}
			default:
				// Only above frame types are permitted in initial packet.
				// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
				return nil, errNotQUICInitial
			}
		}

		tlsHdr := &ptls.SniffHeader{}
		err = ptls.ReadClientHello(cryptoDataBuf.BytesRange(0, cryptoLen), tlsHdr)
		if err != nil {
			// The crypto data may have not been fully recovered in current packets,
			// So we continue to sniff rest packets.
			b = restPayload
			continue
		}
		return &SniffHeader{domain: tlsHdr.Domain()}, nil
	}
	// All payload is parsed as valid QUIC packets, but we need more packets for crypto data to read client hello.
	return nil, protocol.ErrProtoNeedMoreData
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	b := make([]byte, 0, 2+1+6+len(label)+1)
	b = binary.BigEndian.AppendUint16(b, uint16(length))
	b = append(b, byte(6+len(label)))
	b = append(b, "tls13 "...)
	b = append(b, label...)
	b = append(b, 0) // context

	out := make([]byte, length)
	n, err := hkdf.Expand(crypto.SHA256.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// readShortQUICVarint wraps quicvarint.Read with a max limit for length related fields.
// we only handle QUIC Initial so these numbers should not exceed 65535
// returns int32 to reduce type conversion
func readShortQUICVarint(reader io.ByteReader) (int32, error) {
	v, err := quicvarint.Read(reader)
	if err != nil {
		return 0, err
	}
	if v > 65535 {
		// not used(
		return 0, errNotQUICInitial
	}
	return int32(v), nil
}
