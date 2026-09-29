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
	method       *CipherMethod
	pskList      [][]byte
	psk          []byte
	blockCipher  cipher.Block
	blockCiphers []cipher.Block
	chachaCipher cipher.AEAD
	sessions     *UDPSessionManager
}

type (
	UDPPacketCodec = UDPCodec
	UDPServerCodec = UDPCodec
)

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

func NewUDPPacketCodec(method *CipherMethod, pskList [][]byte) (*UDPCodec, error) {
	if method.IsChaCha && len(pskList) > 1 {
		return nil, errors.New("multi-key is not supported for chacha20-poly1305")
	}
	finalPSK := pskList[len(pskList)-1]
	c, err := newUDPCodec(method, finalPSK)
	if err != nil {
		return nil, err
	}
	c.pskList = pskList
	if len(pskList) > 1 {
		c.blockCiphers = make([]cipher.Block, len(pskList))
		for i, psk := range pskList {
			c.blockCiphers[i], err = method.NewBlock(psk)
			if err != nil {
				return nil, err
			}
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

func (c *UDPCodec) Sessions() *UDPSessionManager {
	return c.sessions
}

func (c *UDPCodec) GetSession(sessionID uint64) *ServerUDPSession {
	if c.sessions == nil {
		return nil
	}
	return c.sessions.GetOrCreate(sessionID)
}

type DecodedUDPPacket struct {
	SessionID       uint64
	PacketID        uint64
	HeaderType      byte
	Timestamp       uint64
	ClientSessionID uint64
	Destination     net.Destination
	Payload         []byte
}

func DecryptUDPEIH(block cipher.Block, rawHeader, eih []byte) [AESBlockSize]byte {
	var decryptedHash [AESBlockSize]byte
	block.Decrypt(decryptedHash[:], eih)
	for k := 0; k < AESBlockSize; k++ {
		decryptedHash[k] ^= rawHeader[k]
	}
	return decryptedHash
}

func ParseAddressPort(data []byte) (net.Destination, int, error) {
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
	if headerType != HeaderTypeClient && headerType != HeaderTypeServer {
		return DecodedUDPPacket{}, ErrBadHeaderType
	}
	epoch := binary.BigEndian.Uint64(bodyPlain[1:9])
	diff := int(math.Abs(float64(time.Now().Unix() - int64(epoch))))
	if diff > 30 {
		return DecodedUDPPacket{}, ErrBadTimestamp
	}

	offset := 9
	var clientSessionID uint64
	if headerType == HeaderTypeServer {
		if len(bodyPlain) < offset+8+2 {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}
		clientSessionID = binary.BigEndian.Uint64(bodyPlain[offset : offset+8])
		offset += 8
	}

	paddingLen := int(binary.BigEndian.Uint16(bodyPlain[offset : offset+2]))
	offset += 2

	if len(bodyPlain) < offset+paddingLen {
		return DecodedUDPPacket{}, ErrNoPadding
	}
	offset += paddingLen

	dest, addrLen, err := ParseAddressPort(bodyPlain[offset:])
	if err != nil {
		return DecodedUDPPacket{}, err
	}
	payload := bodyPlain[offset+addrLen:]

	return DecodedUDPPacket{
		SessionID:       sessionID,
		PacketID:        packetID,
		HeaderType:      headerType,
		Timestamp:       epoch,
		ClientSessionID: clientSessionID,
		Destination:     dest,
		Payload:         payload,
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
		plain, err := c.chachaCipher.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return DecodedUDPPacket{}, errors.New("failed to decrypt chacha udp packet").Base(err)
		}
		if len(plain) < 16+1+8+2 {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}

		sessionID := binary.BigEndian.Uint64(plain[:8])
		packetID := binary.BigEndian.Uint64(plain[8:16])

		sessionItem := c.sessions.GetOrCreate(sessionID)
		if !sessionItem.CheckPacketID(packetID) {
			return DecodedUDPPacket{}, ErrPacketIdNotUnique
		}

		decoded, err := parsePlainUDPPacket(sessionID, packetID, plain[16:])
		if err != nil {
			return DecodedUDPPacket{}, err
		}

		if decoded.HeaderType != HeaderTypeClient {
			return DecodedUDPPacket{}, ErrBadHeaderType
		}

		sessionItem.AddPacketID(packetID)
		return decoded, nil
	}

	// AES mode
	var rawHeader [16]byte
	c.blockCipher.Decrypt(rawHeader[:], data[:16])
	sessionID := binary.BigEndian.Uint64(rawHeader[:8])
	packetID := binary.BigEndian.Uint64(rawHeader[8:16])

	sessionItem := c.sessions.GetOrCreate(sessionID)
	if !sessionItem.CheckPacketID(packetID) {
		return DecodedUDPPacket{}, ErrPacketIdNotUnique
	}

	return sessionItem.DecryptAESPayload(c.method, c.psk, sessionID, packetID, rawHeader[:], data[16:])
}

func (s *ServerUDPSession) DecryptAESPayload(method *CipherMethod, psk []byte, sessionID, packetID uint64, rawHeader, bodyCipher []byte) (DecodedUDPPacket, error) {
	bodyAead := s.clientBodyCipher
	isNewCipher := false
	if bodyAead == nil {
		bodyKey := DeriveSessionSubKey(psk, rawHeader[:8], method.KeySaltLength)
		var err error
		bodyAead, err = method.NewAEAD(bodyKey)
		if err != nil {
			return DecodedUDPPacket{}, err
		}
		isNewCipher = true
	}

	bodyNonce := rawHeader[4:16]
	bodyPlain, err := bodyAead.Open(nil, bodyNonce, bodyCipher, nil)
	if err != nil {
		return DecodedUDPPacket{}, errors.New("failed to decrypt aes udp body").Base(err)
	}

	decoded, err := parsePlainUDPPacket(sessionID, packetID, bodyPlain)
	if err != nil {
		return DecodedUDPPacket{}, err
	}

	if decoded.HeaderType != HeaderTypeClient {
		return DecodedUDPPacket{}, ErrBadHeaderType
	}

	s.AddPacketID(packetID)

	if isNewCipher {
		s.clientBodyCipher = bodyAead
	}

	return decoded, nil
}

func (s *ServerUDPSession) EnsureServerState(method *CipherMethod, psk []byte) error {
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
		var err error
		s.serverChaCha, err = method.NewUDPCipher(psk)
		return err
	}

	var err error
	s.serverHeaderBlock, err = method.NewBlock(psk)
	if err != nil {
		s.ServerSessionID = 0
		return err
	}
	bodyKey := DeriveSessionSubKey(psk, sidBuf[:], method.KeySaltLength)
	s.serverBodyCipher, err = method.NewAEAD(bodyKey)
	if err != nil {
		s.ServerSessionID = 0
		return err
	}
	return nil
}

func (s *ServerUDPSession) EncodeServerPacket(method *CipherMethod, clientSessionID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	serverSessionID := s.ServerSessionID
	serverPacketID := s.ServerPacketID.Add(1) - 1

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

		sealed := s.serverChaCha.Seal(nil, nonce[:], plainBuf.Bytes(), nil)
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
	s.serverHeaderBlock.Encrypt(encryptedHeader[:], rawHeader[:])

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
	sealedBody := s.serverBodyCipher.Seal(nil, bodyNonce, bodyBuf.Bytes(), nil)

	res := make([]byte, 16+len(sealedBody))
	copy(res[:16], encryptedHeader[:])
	copy(res[16:], sealedBody)
	return res, nil
}

func (c *UDPCodec) EncodeServerPacket(clientSessionID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	return c.sessions.EncodeServerPacket(c.method, c.psk, clientSessionID, dest, payload)
}

type serverSessionState struct {
	sessionID uint64
	window    *SlidingWindow
	cipher    cipher.AEAD
	lastSeen  atomic.Int64
}

func (st *serverSessionState) check(packetID uint64) bool {
	if st.window == nil {
		st.window = new(SlidingWindow)
	}
	return st.window.Check(packetID)
}

func (st *serverSessionState) add(packetID uint64) {
	if st.window == nil {
		st.window = new(SlidingWindow)
	}
	st.window.Add(packetID)
}

type ClientUDPSession struct {
	codec            *UDPCodec
	clientSessionID  uint64
	nextPacketID     atomic.Uint64
	clientBodyCipher cipher.AEAD
	current          atomic.Pointer[serverSessionState]
	old              atomic.Pointer[serverSessionState]
}

func (c *UDPCodec) NewClientSession() (*ClientUDPSession, error) {
	var sessID [8]byte
	if _, err := io.ReadFull(rand.Reader, sessID[:]); err != nil {
		return nil, err
	}
	clientSessionID := binary.BigEndian.Uint64(sessID[:])

	var clientBodyCipher cipher.AEAD
	var err error
	if !c.method.IsChaCha {
		finalPSK := c.psk
		clientBodyKey := DeriveSessionSubKey(finalPSK, sessID[:], c.method.KeySaltLength)
		clientBodyCipher, err = c.method.NewAEAD(clientBodyKey)
		if err != nil {
			return nil, err
		}
	}

	return &ClientUDPSession{
		codec:            c,
		clientSessionID:  clientSessionID,
		clientBodyCipher: clientBodyCipher,
	}, nil
}

func (s *ClientUDPSession) getServerSession(sessionID uint64, now int64) (*serverSessionState, error) {
	cur := s.current.Load()
	if cur != nil && cur.sessionID == sessionID {
		return cur, nil
	}

	old := s.old.Load()
	if old != nil && old.sessionID == sessionID {
		if now-old.lastSeen.Load() > 60 {
			s.old.CompareAndSwap(old, nil)
			return nil, errors.New("old server session expired")
		}
		return old, nil
	}

	// New server session:
	// Spec §3.2.4: reject newer server sessions when the last packet received from the old session is less than 1 minute old.
	if old != nil && now-old.lastSeen.Load() < 60 {
		return nil, errors.New("newer server session rejected: old session is less than 1 minute old")
	}

	var bodyAead cipher.AEAD
	if !s.codec.method.IsChaCha {
		var sessBytes [8]byte
		binary.BigEndian.PutUint64(sessBytes[:], sessionID)
		bodyKey := DeriveSessionSubKey(s.codec.psk, sessBytes[:], s.codec.method.KeySaltLength)
		var err error
		bodyAead, err = s.codec.method.NewAEAD(bodyKey)
		if err != nil {
			return nil, err
		}
	}

	newState := &serverSessionState{
		sessionID: sessionID,
		cipher:    bodyAead,
	}
	newState.lastSeen.Store(now)

	if cur == nil {
		s.current.CompareAndSwap(nil, newState)
		return s.current.Load(), nil
	}

	s.old.Store(cur)
	s.current.Store(newState)
	return newState, nil
}

func (s *ClientUDPSession) ClientSessionID() uint64 {
	return s.clientSessionID
}

func (s *ClientUDPSession) EncodePacket(dest net.Destination, payload []byte) (*buf.Buffer, error) {
	packetID := s.nextPacketID.Add(1) - 1
	sessID := s.clientSessionID

	var paddingLen int
	if dest.Port == 53 && len(payload) < MaxPaddingLength {
		paddingLen = mrand.IntN(MaxPaddingLength) + 1
	}

	addrPortLen := AddrPortLength(dest)

	if s.codec.method.IsChaCha {
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
		outBuf.Extend(int32(s.codec.chachaCipher.Overhead()))
		s.codec.chachaCipher.Seal(plainBytes[:0], nonce[:], plainBytes, nil)
		return outBuf, nil
	}

	// AES mode
	var sessBytes [8]byte
	binary.BigEndian.PutUint64(sessBytes[:], sessID)

	var rawHeader [16]byte
	copy(rawHeader[:8], sessBytes[:])
	binary.BigEndian.PutUint64(rawHeader[8:16], packetID)

	eihCount := 0
	if len(s.codec.pskList) > 1 {
		eihCount = len(s.codec.pskList) - 1
	}

	totalLen := 16 + eihCount*16 + 11 + paddingLen + addrPortLen + len(payload) + AEADTagSize
	if totalLen > buf.Size {
		return nil, ErrPacketTooLarge
	}

	outBuf := buf.New()

	if len(s.codec.pskList) > 1 {
		var encryptedHeader [16]byte
		s.codec.blockCiphers[0].Encrypt(encryptedHeader[:], rawHeader[:])
		outBuf.Write(encryptedHeader[:])

		for i := 0; i < len(s.codec.pskList)-1; i++ {
			nextPSK := s.codec.pskList[i+1]
			pskHash := DeriveUserPSKHash(nextPSK)
			var eihPlain [16]byte
			for k := 0; k < 16; k++ {
				eihPlain[k] = pskHash[k] ^ rawHeader[k]
			}
			var encryptedEIH [16]byte
			s.codec.blockCiphers[i].Encrypt(encryptedEIH[:], eihPlain[:])
			outBuf.Write(encryptedEIH[:])
		}
	} else {
		var encryptedHeader [16]byte
		s.codec.blockCipher.Encrypt(encryptedHeader[:], rawHeader[:])
		outBuf.Write(encryptedHeader[:])
	}

	bodyAead := s.clientBodyCipher

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

	headerOffset := 16 + eihCount*16
	plainBytes := outBuf.Bytes()[headerOffset:]
	bodyNonce := rawHeader[4:16]
	outBuf.Extend(int32(bodyAead.Overhead()))
	bodyAead.Seal(plainBytes[:0], bodyNonce, plainBytes, nil)
	return outBuf, nil
}

func (s *ClientUDPSession) DecodePacket(data []byte) (DecodedUDPPacket, error) {
	if len(data) < PacketMinimalHeaderSize {
		return DecodedUDPPacket{}, ErrPacketTooShort
	}

	if s.codec.method.IsChaCha {
		if len(data) < PacketNonceSize+AEADTagSize {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}
		nonce := data[:PacketNonceSize]
		ciphertext := data[PacketNonceSize:]
		plain, err := s.codec.chachaCipher.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return DecodedUDPPacket{}, errors.New("failed to decrypt chacha udp packet").Base(err)
		}
		if len(plain) < 16+1+8+2 {
			return DecodedUDPPacket{}, ErrPacketTooShort
		}

		sessionID := binary.BigEndian.Uint64(plain[:8])
		packetID := binary.BigEndian.Uint64(plain[8:16])

		now := time.Now().Unix()
		st, err := s.getServerSession(sessionID, now)
		if err != nil {
			return DecodedUDPPacket{}, err
		}
		if !st.check(packetID) {
			return DecodedUDPPacket{}, ErrPacketIdNotUnique
		}

		decoded, err := parsePlainUDPPacket(sessionID, packetID, plain[16:])
		if err != nil {
			return DecodedUDPPacket{}, err
		}

		if decoded.HeaderType != HeaderTypeServer {
			return DecodedUDPPacket{}, ErrBadHeaderType
		}
		if decoded.ClientSessionID != s.clientSessionID {
			return DecodedUDPPacket{}, errors.New("client session ID mismatch")
		}

		st.add(packetID)
		st.lastSeen.Store(now)

		return decoded, nil
	}

	// AES mode
	var rawHeader [16]byte
	s.codec.blockCipher.Decrypt(rawHeader[:], data[:16])
	sessionID := binary.BigEndian.Uint64(rawHeader[:8])
	packetID := binary.BigEndian.Uint64(rawHeader[8:16])

	now := time.Now().Unix()
	st, err := s.getServerSession(sessionID, now)
	if err != nil {
		return DecodedUDPPacket{}, err
	}
	if !st.check(packetID) {
		return DecodedUDPPacket{}, ErrPacketIdNotUnique
	}
	bodyAead := st.cipher

	bodyNonce := rawHeader[4:16]
	bodyCipher := data[16:]
	bodyPlain, err := bodyAead.Open(nil, bodyNonce, bodyCipher, nil)
	if err != nil {
		return DecodedUDPPacket{}, errors.New("failed to decrypt aes udp body").Base(err)
	}

	decoded, err := parsePlainUDPPacket(sessionID, packetID, bodyPlain)
	if err != nil {
		return DecodedUDPPacket{}, err
	}

	if decoded.HeaderType != HeaderTypeServer {
		return DecodedUDPPacket{}, ErrBadHeaderType
	}
	if decoded.ClientSessionID != s.clientSessionID {
		return DecodedUDPPacket{}, errors.New("client session ID mismatch")
	}

	st.add(packetID)
	st.lastSeen.Store(now)

	return decoded, nil
}

type UDPWriter struct {
	Writer      io.Writer
	Destination net.Destination
	Session     *ClientUDPSession
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
		pktBuf, err := w.Session.EncodePacket(dest, b.Bytes())
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
	Reader  io.Reader
	Session *ClientUDPSession
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		buffer := buf.New()
		_, err := buffer.ReadFrom(r.Reader)
		if err != nil {
			buffer.Release()
			return nil, err
		}

		decoded, err := r.Session.DecodePacket(buffer.Bytes())
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
