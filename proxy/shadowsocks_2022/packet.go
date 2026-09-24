package shadowsocks_2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	mrand "math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

type UDPCodec struct {
	method           *CipherMethod
	psk              []byte
	blockCipher      cipher.Block
	chachaCipher     cipher.AEAD
	clientBodyCipher cipher.AEAD
	clientSessionID  uint64
	nextPacketID     atomic.Uint64
	sessions         *UDPSessionManager
}

type UDPPacketCodec = UDPCodec
type UDPServerCodec = UDPCodec

func newUDPCodec(method *CipherMethod, psk []byte) (*UDPCodec, error) {
	c := &UDPCodec{
		method: method,
		psk:    psk,
	}
	var err error
	if method.IsChaCha {
		c.chachaCipher, err = method.NewUDPCipher(psk)
	} else {
		c.blockCipher, err = method.NewBlock(psk)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func NewUDPPacketCodec(method *CipherMethod, psk []byte) (*UDPCodec, error) {
	c, err := newUDPCodec(method, psk)
	if err != nil {
		return nil, err
	}
	var sessID [8]byte
	if _, err := io.ReadFull(rand.Reader, sessID[:]); err != nil {
		return nil, err
	}
	c.clientSessionID = binary.BigEndian.Uint64(sessID[:])

	if !method.IsChaCha {
		clientBodyKey := DeriveSessionSubKey(psk, sessID[:], method.KeySaltLength)
		c.clientBodyCipher, err = method.NewAEAD(clientBodyKey)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func NewUDPServerCodec(method *CipherMethod, psk []byte, sessionTimeout time.Duration) (*UDPCodec, error) {
	c, err := newUDPCodec(method, psk)
	if err != nil {
		return nil, err
	}
	c.sessions = NewUDPSessionManager(sessionTimeout)
	return c, nil
}

func (c *UDPCodec) EncodeClientPacket(dest net.Destination, payload []byte) (*buf.Buffer, error) {
	packetID := c.nextPacketID.Add(1)
	sessID := c.clientSessionID

	// Padding determination (e.g. DNS port 53 disguise)
	var paddingLen int
	if dest.Port == 53 && len(payload) < MaxPaddingLength {
		paddingLen = mrand.IntN(MaxPaddingLength-len(payload)) + 1
	}

	addrPortLen := AddrPortLength(dest)

	if c.method.IsChaCha {
		// ChaCha20 mode: 24-byte nonce + plaintext header (27B) + padding + dest + payload + AEAD tag (16B)
		totalLen := PacketNonceSize + 27 + paddingLen + addrPortLen + len(payload) + AEADTagSize
		if totalLen > buf.Size {
			return nil, ErrPacketTooLarge
		}

		outBuf := buf.New()

		var nonce [PacketNonceSize]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			outBuf.Release()
			return nil, err
		}
		outBuf.Write(nonce[:])

		var hdr [16 + 1 + 8 + 2]byte
		binary.BigEndian.PutUint64(hdr[0:8], sessID)
		binary.BigEndian.PutUint64(hdr[8:16], packetID)
		hdr[16] = HeaderTypeClient
		binary.BigEndian.PutUint64(hdr[17:25], uint64(time.Now().Unix()))
		binary.BigEndian.PutUint16(hdr[25:27], uint16(paddingLen))
		outBuf.Write(hdr[:])
		if paddingLen > 0 {
			outBuf.Write(zeroPadding[:paddingLen])
		}

		if err := WriteAddressPort(outBuf, dest); err != nil {
			outBuf.Release()
			return nil, err
		}
		outBuf.Write(payload)

		plainBytes := outBuf.Bytes()[PacketNonceSize:]
		outBuf.Extend(int32(c.chachaCipher.Overhead()))
		c.chachaCipher.Seal(plainBytes[:0], nonce[:], plainBytes, nil)
		return outBuf, nil
	}

	// AES mode:
	// 16B Encrypted Header + (11B header + padding + dest + payload + 16B AEAD tag)
	totalLen := 16 + 11 + paddingLen + addrPortLen + len(payload) + AEADTagSize
	if totalLen > buf.Size {
		return nil, ErrPacketTooLarge
	}

	outBuf := buf.New()

	var rawHeader [16]byte
	binary.BigEndian.PutUint64(rawHeader[:8], sessID)
	binary.BigEndian.PutUint64(rawHeader[8:16], packetID)

	var encryptedHeader [16]byte
	c.blockCipher.Encrypt(encryptedHeader[:], rawHeader[:])
	outBuf.Write(encryptedHeader[:])

	bodyAead := c.clientBodyCipher
	if bodyAead == nil {
		bodyKey := DeriveSessionSubKey(c.psk, rawHeader[:8], c.method.KeySaltLength)
		var err error
		bodyAead, err = c.method.NewAEAD(bodyKey)
		if err != nil {
			outBuf.Release()
			return nil, err
		}
	}

	var hdr [1 + 8 + 2]byte
	hdr[0] = HeaderTypeClient
	binary.BigEndian.PutUint64(hdr[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(hdr[9:11], uint16(paddingLen))
	outBuf.Write(hdr[:])
	if paddingLen > 0 {
		outBuf.Write(zeroPadding[:paddingLen])
	}

	if err := WriteAddressPort(outBuf, dest); err != nil {
		outBuf.Release()
		return nil, err
	}
	outBuf.Write(payload)

	plainBytes := outBuf.Bytes()[16:]
	bodyNonce := rawHeader[4:16]
	outBuf.Extend(int32(bodyAead.Overhead()))
	bodyAead.Seal(plainBytes[:0], bodyNonce, plainBytes, nil)
	return outBuf, nil
}

type DecodedUDPPacket struct {
	SessionID   uint64
	PacketID    uint64
	HeaderType  byte
	Timestamp   uint64
	Destination net.Destination
	Payload     []byte
}

func parseAddressPort(data []byte) (net.Destination, int, error) {
	if len(data) < 1 {
		return net.Destination{}, 0, ErrPacketTooShort
	}
	switch data[0] {
	case 1: // IPv4
		if len(data) < 1+4+2 {
			return net.Destination{}, 0, ErrPacketTooShort
		}
		ip := net.IPAddress(data[1:5])
		port := binary.BigEndian.Uint16(data[5:7])
		return net.UDPDestination(ip, net.Port(port)), 7, nil
	case 4: // IPv6
		if len(data) < 1+16+2 {
			return net.Destination{}, 0, ErrPacketTooShort
		}
		ip := net.IPAddress(data[1:17])
		port := binary.BigEndian.Uint16(data[17:19])
		return net.UDPDestination(ip, net.Port(port)), 19, nil
	case 3: // Domain
		if len(data) < 2 {
			return net.Destination{}, 0, ErrPacketTooShort
		}
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return net.Destination{}, 0, ErrPacketTooShort
		}
		domain := string(data[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(data[2+domainLen : 2+domainLen+2])
		return net.UDPDestination(net.DomainAddress(domain), net.Port(port)), 2 + domainLen + 2, nil
	default:
		return net.Destination{}, 0, errors.New("unknown address type")
	}
}

func parsePlainUDPPacket(sessionID, packetID uint64, bodyPlain []byte) (DecodedUDPPacket, error) {
	if len(bodyPlain) < 1+8+2 {
		return DecodedUDPPacket{}, ErrPacketTooShort
	}

	headerType := bodyPlain[0]
	epoch := binary.BigEndian.Uint64(bodyPlain[1:9])
	diff := int(math.Abs(float64(time.Now().Unix() - int64(epoch))))
	if diff > 30 {
		return DecodedUDPPacket{}, ErrBadTimestamp
	}

	offset := 9
	if headerType == HeaderTypeServer {
		if len(bodyPlain) < offset+8+2 {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}
		offset += 8 // skip clientSessionID
	}

	paddingLen := int(binary.BigEndian.Uint16(bodyPlain[offset : offset+2]))
	offset += 2

	if len(bodyPlain) < offset+paddingLen {
		return DecodedUDPPacket{}, ErrNoPadding
	}
	offset += paddingLen

	dest, addrLen, err := parseAddressPort(bodyPlain[offset:])
	if err != nil {
		return DecodedUDPPacket{}, err
	}
	payload := bodyPlain[offset+addrLen:]

	return DecodedUDPPacket{
		SessionID:   sessionID,
		PacketID:    packetID,
		HeaderType:  headerType,
		Timestamp:   epoch,
		Destination: dest,
		Payload:     payload,
	}, nil
}

func (c *UDPCodec) DecodePacket(data []byte) (DecodedUDPPacket, error) {
	if len(data) < PacketMinimalHeaderSize {
		return DecodedUDPPacket{}, ErrPacketTooShort
	}

	if c.method.IsChaCha {
		if len(data) < PacketNonceSize+AEADTagSize {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}
		nonce := data[:PacketNonceSize]
		ciphertext := data[PacketNonceSize:]
		plain, err := c.chachaCipher.Open(ciphertext[:0], nonce, ciphertext, nil)
		if err != nil {
			return DecodedUDPPacket{}, errors.New("failed to decrypt chacha udp packet").Base(err)
		}
		if len(plain) < 16+1+8+2 {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}

		sessionID := binary.BigEndian.Uint64(plain[:8])
		packetID := binary.BigEndian.Uint64(plain[8:16])

		if c.sessions != nil {
			sessionItem, _ := c.sessions.GetOrCreate(sessionID)
			sessionItem.Lock()
			if !sessionItem.Window.CheckAndAdd(packetID) {
				sessionItem.Unlock()
				return DecodedUDPPacket{}, ErrPacketIdNotUnique
			}
			sessionItem.Unlock()
		}

		return parsePlainUDPPacket(sessionID, packetID, plain[16:])
	}

	// AES mode
	var rawHeader [16]byte
	c.blockCipher.Decrypt(rawHeader[:], data[:16])
	sessionID := binary.BigEndian.Uint64(rawHeader[:8])
	packetID := binary.BigEndian.Uint64(rawHeader[8:16])

	var bodyAead cipher.AEAD
	var sessionItem *ServerUDPSession

	if c.sessions != nil {
		sessionItem, _ = c.sessions.GetOrCreate(sessionID)
		sessionItem.Lock()
		if !sessionItem.Window.Check(packetID) {
			sessionItem.Unlock()
			return DecodedUDPPacket{}, ErrPacketIdNotUnique
		}
		sessionItem.Unlock()

		bodyAead = sessionItem.GetRemoteCipher()
		if bodyAead == nil {
			bodyKey := DeriveSessionSubKey(c.psk, rawHeader[:8], c.method.KeySaltLength)
			var err error
			bodyAead, err = c.method.NewAEAD(bodyKey)
			if err != nil {
				return DecodedUDPPacket{}, err
			}
			sessionItem.SetRemoteCipher(bodyAead)
		}
	} else {
		bodyKey := DeriveSessionSubKey(c.psk, rawHeader[:8], c.method.KeySaltLength)
		var err error
		bodyAead, err = c.method.NewAEAD(bodyKey)
		if err != nil {
			return DecodedUDPPacket{}, err
		}
	}

	bodyNonce := rawHeader[4:16]
	bodyCipher := data[16:]
	bodyPlain, err := bodyAead.Open(bodyCipher[:0], bodyNonce, bodyCipher, nil)
	if err != nil {
		return DecodedUDPPacket{}, errors.New("failed to decrypt aes udp body").Base(err)
	}

	if sessionItem != nil {
		sessionItem.Lock()
		sessionItem.Window.Add(packetID)
		sessionItem.Unlock()
	}

	return parsePlainUDPPacket(sessionID, packetID, bodyPlain)
}

func (c *UDPCodec) Sessions() *UDPSessionManager {
	return c.sessions
}

func (s *ServerUDPSession) EnsureServerState(method *CipherMethod, headerBlock cipher.Block, chachaCipher cipher.AEAD, psk []byte) error {
	s.Lock()
	defer s.Unlock()
	if s.ServerSessionID != 0 {
		return nil
	}
	var sidBuf [8]byte
	for {
		if _, err := io.ReadFull(rand.Reader, sidBuf[:]); err != nil {
			return err
		}
		s.ServerSessionID = binary.BigEndian.Uint64(sidBuf[:])
		if s.ServerSessionID != 0 {
			break
		}
	}
	if method.IsChaCha {
		s.ServerChaCha = chachaCipher
	} else {
		s.ServerBlockCipher = headerBlock
		bodyKey := DeriveSessionSubKey(psk, sidBuf[:], method.KeySaltLength)
		bodyAead, err := method.NewAEAD(bodyKey)
		if err != nil {
			s.ServerSessionID = 0
			return err
		}
		s.ServerCipher = bodyAead
	}
	return nil
}

func (s *ServerUDPSession) EncodeServerPacket(method *CipherMethod, clientSessionID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	serverSessionID := s.ServerSessionID
	serverPacketID := s.ServerPacketID.Add(1)

	if method.IsChaCha {
		var nonce [PacketNonceSize]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			return nil, err
		}

		plainBuf := buf.New()
		defer plainBuf.Release()

		var hdr [16 + 1 + 8 + 8 + 2]byte
		binary.BigEndian.PutUint64(hdr[0:8], serverSessionID)
		binary.BigEndian.PutUint64(hdr[8:16], serverPacketID)
		hdr[16] = HeaderTypeServer
		binary.BigEndian.PutUint64(hdr[17:25], uint64(time.Now().Unix()))
		binary.BigEndian.PutUint64(hdr[25:33], clientSessionID)
		binary.BigEndian.PutUint16(hdr[33:35], 0)
		plainBuf.Write(hdr[:])

		if err := WriteAddressPort(plainBuf, dest); err != nil {
			return nil, err
		}
		plainBuf.Write(payload)

		sealed := s.ServerChaCha.Seal(nil, nonce[:], plainBuf.Bytes(), nil)
		res := make([]byte, PacketNonceSize+len(sealed))
		copy(res[:PacketNonceSize], nonce[:])
		copy(res[PacketNonceSize:], sealed)
		return res, nil
	}

	// AES mode
	var rawHeader [16]byte
	binary.BigEndian.PutUint64(rawHeader[:8], serverSessionID)
	binary.BigEndian.PutUint64(rawHeader[8:16], serverPacketID)

	var encryptedHeader [16]byte
	s.ServerBlockCipher.Encrypt(encryptedHeader[:], rawHeader[:])

	bodyBuf := buf.New()
	defer bodyBuf.Release()

	var hdr [1 + 8 + 8 + 2]byte
	hdr[0] = HeaderTypeServer
	binary.BigEndian.PutUint64(hdr[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint64(hdr[9:17], clientSessionID)
	binary.BigEndian.PutUint16(hdr[17:19], 0)
	bodyBuf.Write(hdr[:])

	if err := WriteAddressPort(bodyBuf, dest); err != nil {
		return nil, err
	}
	bodyBuf.Write(payload)

	bodyNonce := rawHeader[4:16]
	sealedBody := s.ServerCipher.Seal(nil, bodyNonce, bodyBuf.Bytes(), nil)

	res := make([]byte, 16+len(sealedBody))
	copy(res[:16], encryptedHeader[:])
	copy(res[16:], sealedBody)
	return res, nil
}

func EncodeServerPacket(method *CipherMethod, headerBlock cipher.Block, chachaAEAD cipher.AEAD, psk []byte, clientSessionID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	tempSession := &ServerUDPSession{SessionID: clientSessionID}
	if err := tempSession.EnsureServerState(method, headerBlock, chachaAEAD, psk); err != nil {
		return nil, err
	}
	return tempSession.EncodeServerPacket(method, clientSessionID, dest, payload)
}

func (c *UDPCodec) EncodeServerPacket(clientSessionID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	if c.sessions != nil {
		sessionItem, _ := c.sessions.GetOrCreate(clientSessionID)
		if err := sessionItem.EnsureServerState(c.method, c.blockCipher, c.chachaCipher, c.psk); err != nil {
			return nil, err
		}
		return sessionItem.EncodeServerPacket(c.method, clientSessionID, dest, payload)
	}
	return EncodeServerPacket(c.method, c.blockCipher, c.chachaCipher, c.psk, clientSessionID, dest, payload)
}

func (c *UDPCodec) EncodePacket(clientSessionID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	return c.EncodeServerPacket(clientSessionID, dest, payload)
}

type UDPWriter struct {
	Writer      io.Writer
	Destination net.Destination
	Codec       *UDPPacketCodec
}

func (w *UDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		dest := w.Destination
		if b.UDP != nil {
			dest = *b.UDP
		}
		pktBuf, err := w.Codec.EncodeClientPacket(dest, b.Bytes())
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		_, writeErr := w.Writer.Write(pktBuf.Bytes())
		pktBuf.Release()
		if writeErr != nil {
			buf.ReleaseMulti(mb)
			return writeErr
		}
	}
	return nil
}

type UDPReader struct {
	Reader io.Reader
	Codec  *UDPPacketCodec
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		buffer := buf.New()
		_, err := buffer.ReadFrom(r.Reader)
		if err != nil {
			buffer.Release()
			return nil, err
		}

		decoded, err := r.Codec.DecodePacket(buffer.Bytes())
		if err != nil {
			buffer.Release()
			continue
		}
		buffer.Clear()
		buffer.Write(decoded.Payload)
		dest := decoded.Destination
		buffer.UDP = &dest
		return buf.MultiBuffer{buffer}, nil
	}
}
