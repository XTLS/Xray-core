package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
	protocol.WithAddressTypeParser(func(b byte) byte {
		return b & 0x0F
	}),
)

func IncreaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// WriteAddressPort writes a destination address and port in SOCKS5 format
func WriteAddressPort(w io.Writer, dest net.Destination) error {
	return addrParser.WriteAddressPort(w, dest.Address, dest.Port)
}

// AddrPortLength returns the serialized length of a destination in SOCKS5 format
func AddrPortLength(dest net.Destination) int {
	switch dest.Address.Family() {
	case net.AddressFamilyIPv4:
		return 1 + 4 + 2
	case net.AddressFamilyDomain:
		return 1 + 1 + len(dest.Address.Domain()) + 2
	case net.AddressFamilyIPv6:
		return 1 + 16 + 2
	default:
		return 0
	}
}

type StreamWriter struct {
	writer io.Writer
	cipher cipher.AEAD
	nonce  [StreamNonceSize]byte
	lenBuf [2]byte
	buf    []byte
}

func NewStreamWriter(w io.Writer, c cipher.AEAD) *StreamWriter {
	return &StreamWriter{
		writer: w,
		cipher: c,
		buf:    make([]byte, 0, MaxPacketSize+2+2*AEADTagSize),
	}
}

func (w *StreamWriter) Nonce() []byte {
	return w.nonce[:]
}

func (w *StreamWriter) WriteChunk(payload []byte) error {
	payloadLen := len(payload)
	if payloadLen == 0 {
		return nil
	}
	if payloadLen > MaxPacketSize {
		return errors.New("payload exceeds MaxPacketSize")
	}

	binary.BigEndian.PutUint16(w.lenBuf[:], uint16(payloadLen))
	w.buf = w.cipher.Seal(w.buf[:0], w.nonce[:], w.lenBuf[:], nil)
	IncreaseNonce(w.nonce[:])

	w.buf = w.cipher.Seal(w.buf, w.nonce[:], payload, nil)
	IncreaseNonce(w.nonce[:])

	_, err := w.writer.Write(w.buf)
	return err
}

func (w *StreamWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxPacketSize {
			chunkSize = MaxPacketSize
		}
		if err := w.WriteChunk(p[:chunkSize]); err != nil {
			return 0, err
		}
		p = p[chunkSize:]
	}
	return n, nil
}

func (w *StreamWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		p := b.Bytes()
		for len(p) > 0 {
			chunkSize := len(p)
			if chunkSize > MaxPacketSize {
				chunkSize = MaxPacketSize
			}
			if err := w.WriteChunk(p[:chunkSize]); err != nil {
				return err
			}
			p = p[chunkSize:]
		}
	}
	return nil
}

type StreamReader struct {
	reader io.Reader
	cipher cipher.AEAD
	nonce  [StreamNonceSize]byte
	lenBuf [2 + AEADTagSize]byte
	buffer []byte
	cached int
	offset int
}

func NewStreamReader(r io.Reader, c cipher.AEAD) *StreamReader {
	return &StreamReader{
		reader: r,
		cipher: c,
		buffer: make([]byte, MaxPacketSize+AEADTagSize),
	}
}

func (r *StreamReader) Nonce() []byte {
	return r.nonce[:]
}

func (r *StreamReader) Read(p []byte) (int, error) {
	if r.cached > 0 {
		n := copy(p, r.buffer[r.offset:r.offset+r.cached])
		r.cached -= n
		r.offset += n
		return n, nil
	}

	// Read 2-byte length + AEAD tag (18 bytes)
	if _, err := io.ReadFull(r.reader, r.lenBuf[:]); err != nil {
		return 0, err
	}

	decryptedLen, err := r.cipher.Open(r.lenBuf[:0], r.nonce[:], r.lenBuf[:], nil)
	if err != nil {
		return 0, errors.New("failed to decrypt chunk length").Base(err)
	}
	IncreaseNonce(r.nonce[:])

	payloadLen := int(binary.BigEndian.Uint16(decryptedLen))
	if payloadLen == 0 || payloadLen > MaxPacketSize {
		return 0, ErrInvalidRequest
	}

	chunkEnd := payloadLen + AEADTagSize
	if _, err := io.ReadFull(r.reader, r.buffer[:chunkEnd]); err != nil {
		return 0, err
	}

	decryptedPayload, err := r.cipher.Open(r.buffer[:0], r.nonce[:], r.buffer[:chunkEnd], nil)
	if err != nil {
		return 0, errors.New("failed to decrypt chunk payload").Base(err)
	}
	IncreaseNonce(r.nonce[:])

	r.cached = len(decryptedPayload)
	r.offset = 0

	n := copy(p, r.buffer[r.offset:r.offset+r.cached])
	r.cached -= n
	r.offset += n
	return n, nil
}

func (r *StreamReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.cached > 0 {
		mb := buf.MergeBytes(nil, r.buffer[r.offset:r.offset+r.cached])
		r.cached = 0
		r.offset = 0
		return mb, nil
	}

	if _, err := io.ReadFull(r.reader, r.lenBuf[:]); err != nil {
		return nil, err
	}

	decryptedLen, err := r.cipher.Open(r.lenBuf[:0], r.nonce[:], r.lenBuf[:], nil)
	if err != nil {
		return nil, errors.New("failed to decrypt chunk length").Base(err)
	}
	IncreaseNonce(r.nonce[:])

	payloadLen := int(binary.BigEndian.Uint16(decryptedLen))
	if payloadLen == 0 || payloadLen > MaxPacketSize {
		return nil, ErrInvalidRequest
	}

	chunkEnd := payloadLen + AEADTagSize
	if _, err := io.ReadFull(r.reader, r.buffer[:chunkEnd]); err != nil {
		return nil, err
	}

	decryptedPayload, err := r.cipher.Open(r.buffer[:0], r.nonce[:], r.buffer[:chunkEnd], nil)
	if err != nil {
		return nil, errors.New("failed to decrypt chunk payload").Base(err)
	}
	IncreaseNonce(r.nonce[:])

	mb := buf.MergeBytes(nil, decryptedPayload)
	return mb, nil
}

type ClientRequestHeader struct {
	Destination net.Destination
	EarlyData   []byte
}

func ReadClientRequestHeaderWithFixed(reader *StreamReader, fixedChunk []byte) (*ClientRequestHeader, error) {
	plainFixed, err := reader.cipher.Open(fixedChunk[:0], reader.Nonce(), fixedChunk, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt client request header").Base(err)
	}
	IncreaseNonce(reader.Nonce())

	if plainFixed[0] != HeaderTypeClient {
		return nil, ErrBadHeaderType
	}

	epoch := binary.BigEndian.Uint64(plainFixed[1:9])
	diff := int(math.Abs(float64(time.Now().Unix() - int64(epoch))))
	if diff > 30 {
		return nil, ErrBadTimestamp
	}

	varHeaderLen := int(binary.BigEndian.Uint16(plainFixed[9:11]))
	if varHeaderLen == 0 {
		return nil, ErrInvalidRequest
	}

	var stackVarChunk [512]byte
	var varChunkCipher []byte
	needed := varHeaderLen + AEADTagSize
	if needed <= len(stackVarChunk) {
		varChunkCipher = stackVarChunk[:needed]
	} else {
		varChunkCipher = make([]byte, needed)
	}
	if _, err := io.ReadFull(reader.reader, varChunkCipher); err != nil {
		return nil, err
	}

	plainVar, err := reader.cipher.Open(varChunkCipher[:0], reader.Nonce(), varChunkCipher, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt variable request header").Base(err)
	}
	IncreaseNonce(reader.Nonce())

	dest, addrLen, err := ParseAddressPort(plainVar)
	if err != nil {
		return nil, err
	}
	dest.Network = net.Network_TCP

	offset := addrLen
	if len(plainVar) < offset+2 {
		return nil, ErrPacketTooShort
	}
	paddingLen := int(binary.BigEndian.Uint16(plainVar[offset : offset+2]))
	offset += 2

	if len(plainVar) < offset+paddingLen {
		return nil, ErrNoPadding
	}
	offset += paddingLen

	var earlyData []byte
	var payloadLen int
	if len(plainVar) > offset {
		earlyData = plainVar[offset:]
		payloadLen = len(earlyData)
	}

	// SIP022 §3.1.4: Servers MUST reject the request if the variable-length header chunk does not contain payload and the padding length is 0.
	if paddingLen == 0 && payloadLen == 0 {
		return nil, errors.New("request without payload and padding is not allowed")
	}

	return &ClientRequestHeader{
		Destination: dest,
		EarlyData:   earlyData,
	}, nil
}

// WriteTCPRequest writes the Shadowsocks 2022 request header into w and returns a body writer.
func WriteTCPRequest(w io.Writer, method *CipherMethod, pskList [][]byte, dest net.Destination, clientSalt []byte, payload []byte) (buf.Writer, error) {
	finalPSK := pskList[len(pskList)-1]
	sessionKey := DeriveSessionSubKey(finalPSK, clientSalt, method.KeySaltLength)
	aead, err := method.NewAEAD(sessionKey)
	if err != nil {
		return nil, err
	}

	writer := NewStreamWriter(w, aead)

	payloadLen := len(payload)
	var paddingLen int
	if payloadLen < MaxPaddingLength {
		paddingLen = mrand.IntN(MaxPaddingLength) + 1
	}
	addrPortLen := AddrPortLength(dest)
	varHeaderLen := addrPortLen + 2 + paddingLen + payloadLen

	totalHandshakeLen := int32(method.KeySaltLength + len(pskList)*AESBlockSize + RequestHeaderFixedChunkLength + AEADTagSize + varHeaderLen + AEADTagSize)
	handshakeBuf := buf.NewWithSize(totalHandshakeLen)
	defer handshakeBuf.Release()

	handshakeBuf.Write(clientSalt)

	for i, currPSK := range pskList[:len(pskList)-1] {
		identitySubkey := DeriveIdentitySubKey(currPSK, clientSalt, method.KeySaltLength)
		block, err := method.NewBlock(identitySubkey)
		if err != nil {
			return nil, err
		}
		nextPSK := pskList[i+1]
		pskHash := DeriveUserPSKHash(nextPSK)
		var encryptedEIH [AESBlockSize]byte
		block.Encrypt(encryptedEIH[:], pskHash[:])
		handshakeBuf.Write(encryptedEIH[:])
	}

	var fixedHeaderPlaintext [RequestHeaderFixedChunkLength]byte
	fixedHeaderPlaintext[0] = HeaderTypeClient
	binary.BigEndian.PutUint64(fixedHeaderPlaintext[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(fixedHeaderPlaintext[9:11], uint16(varHeaderLen))

	fixedChunk := writer.cipher.Seal(nil, writer.nonce[:], fixedHeaderPlaintext[:], nil)
	IncreaseNonce(writer.nonce[:])
	handshakeBuf.Write(fixedChunk)

	varHeaderBuf := buf.NewWithSize(int32(varHeaderLen))
	defer varHeaderBuf.Release()

	if err := WriteAddressPort(varHeaderBuf, dest); err != nil {
		return nil, err
	}

	var padLenBytes [2]byte
	binary.BigEndian.PutUint16(padLenBytes[:], uint16(paddingLen))
	varHeaderBuf.Write(padLenBytes[:])

	if paddingLen > 0 {
		varHeaderBuf.Write(zeroPadding[:paddingLen])
	}

	if payloadLen > 0 {
		varHeaderBuf.Write(payload)
	}

	varChunk := writer.cipher.Seal(nil, writer.nonce[:], varHeaderBuf.Bytes(), nil)
	IncreaseNonce(writer.nonce[:])
	handshakeBuf.Write(varChunk)

	if _, err := w.Write(handshakeBuf.Bytes()); err != nil {
		return nil, err
	}

	return writer, nil
}

// ReadTCPResponse reads and verifies the server's handshake response and returns a reader for the stream.
func ReadTCPResponse(r io.Reader, method *CipherMethod, psk []byte, clientSalt []byte) (buf.Reader, error) {
	fixedPlainLen := 1 + 8 + method.KeySaltLength + 2
	chunkCipherLen := fixedPlainLen + AEADTagSize
	headerLen := method.KeySaltLength + chunkCipherLen

	// Single read call for Salt + Fixed-length response header chunk per SIP022 §3.1.4
	var headerBuf [128]byte
	headerSlice := headerBuf[:headerLen]
	n, err := r.Read(headerSlice)
	if err != nil || n < headerLen {
		return nil, errors.New("failed to read complete server response header")
	}

	serverSaltSlice := headerSlice[:method.KeySaltLength]
	chunkSlice := headerSlice[method.KeySaltLength:headerLen]

	sessionKey := DeriveSessionSubKey(psk, serverSaltSlice, method.KeySaltLength)
	aead, err := method.NewAEAD(sessionKey)
	if err != nil {
		return nil, err
	}

	reader := NewStreamReader(r, aead)

	decryptedFixed, err := reader.cipher.Open(chunkSlice[:0], reader.nonce[:], chunkSlice, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt server response header").Base(err)
	}
	IncreaseNonce(reader.nonce[:])

	if decryptedFixed[0] != HeaderTypeServer {
		return nil, ErrBadHeaderType
	}

	serverEpoch := binary.BigEndian.Uint64(decryptedFixed[1:9])
	diff := int(math.Abs(float64(time.Now().Unix() - int64(serverEpoch))))
	if diff > 30 {
		return nil, ErrBadTimestamp
	}

	echoedSalt := decryptedFixed[9 : 9+method.KeySaltLength]
	for i := 0; i < method.KeySaltLength; i++ {
		if echoedSalt[i] != clientSalt[i] {
			return nil, errors.New("bad request salt")
		}
	}

	initialPayloadLen := int(binary.BigEndian.Uint16(decryptedFixed[9+method.KeySaltLength : 11+method.KeySaltLength]))
	if initialPayloadLen > 0 {
		initialCipherLen := initialPayloadLen + AEADTagSize
		if _, err := io.ReadFull(r, reader.buffer[:initialCipherLen]); err != nil {
			return nil, err
		}
		decryptedInitial, err := reader.cipher.Open(reader.buffer[:0], reader.nonce[:], reader.buffer[:initialCipherLen], nil)
		if err != nil {
			return nil, errors.New("failed to decrypt initial response payload").Base(err)
		}
		IncreaseNonce(reader.nonce[:])
		reader.cached = len(decryptedInitial)
		reader.offset = 0
	}

	return reader, nil
}

// ServerStreamWriter lazily sends the response header along with the first payload chunk per SIP022 §3.1.2 & §3.1.4.
type ServerStreamWriter struct {
	mu           sync.Mutex
	w            io.Writer
	method       *CipherMethod
	psk          []byte
	clientSalt   []byte
	streamWriter *StreamWriter
}

func NewServerStreamWriter(w io.Writer, method *CipherMethod, psk []byte, clientSalt []byte) *ServerStreamWriter {
	return &ServerStreamWriter{
		w:          w,
		method:     method,
		psk:        psk,
		clientSalt: clientSalt,
	}
}

func (s *ServerStreamWriter) sendHeaderWithFirstPayload(payload []byte) (*StreamWriter, error) {
	var serverSalt [32]byte
	serverSaltSlice := serverSalt[:s.method.KeySaltLength]
	if _, err := io.ReadFull(rand.Reader, serverSaltSlice); err != nil {
		return nil, err
	}

	respKey := DeriveSessionSubKey(s.psk, serverSaltSlice, s.method.KeySaltLength)
	respAead, err := s.method.NewAEAD(respKey)
	if err != nil {
		return nil, err
	}
	sw := NewStreamWriter(s.w, respAead)

	totalHeaderLen := int32(s.method.KeySaltLength + 1 + 8 + s.method.KeySaltLength + 2 + AEADTagSize + len(payload) + AEADTagSize)
	outBuf := buf.NewWithSize(totalHeaderLen)
	defer outBuf.Release()

	outBuf.Write(serverSaltSlice)

	var fixedRespPlain [1 + 8 + 32 + 2]byte
	fixedRespSlice := fixedRespPlain[:1+8+s.method.KeySaltLength+2]
	fixedRespSlice[0] = HeaderTypeServer
	binary.BigEndian.PutUint64(fixedRespSlice[1:9], uint64(time.Now().Unix()))
	copy(fixedRespSlice[9:9+s.method.KeySaltLength], s.clientSalt)
	binary.BigEndian.PutUint16(fixedRespSlice[9+s.method.KeySaltLength:11+s.method.KeySaltLength], uint16(len(payload)))

	fixedRespChunk := sw.cipher.Seal(nil, sw.nonce[:], fixedRespSlice, nil)
	IncreaseNonce(sw.nonce[:])
	outBuf.Write(fixedRespChunk)

	if len(payload) > 0 {
		payloadChunk := sw.cipher.Seal(nil, sw.nonce[:], payload, nil)
		IncreaseNonce(sw.nonce[:])
		outBuf.Write(payloadChunk)
	}

	if _, err := s.w.Write(outBuf.Bytes()); err != nil {
		return nil, err
	}
	return sw, nil
}

func (s *ServerStreamWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	if s.streamWriter == nil {
		s.mu.Lock()
		if s.streamWriter == nil {
			firstBuf := mb[0]
			firstBytes := firstBuf.Bytes()
			chunkSize := len(firstBytes)
			if chunkSize > MaxPacketSize {
				chunkSize = MaxPacketSize
			}
			firstPayload := firstBytes[:chunkSize]
			sw, err := s.sendHeaderWithFirstPayload(firstPayload)
			if err != nil {
				s.mu.Unlock()
				buf.ReleaseMulti(mb)
				return err
			}
			s.streamWriter = sw

			firstBuf.Advance(int32(chunkSize))
			if firstBuf.IsEmpty() {
				firstBuf.Release()
				mb = mb[1:]
			}
		}
		s.mu.Unlock()
		if len(mb) == 0 {
			return nil
		}
	}

	return s.streamWriter.WriteMultiBuffer(mb)
}

func (s *ServerStreamWriter) Write(p []byte) (int, error) {
	n := len(p)
	if s.streamWriter == nil {
		s.mu.Lock()
		if s.streamWriter == nil {
			chunkSize := len(p)
			if chunkSize > MaxPacketSize {
				chunkSize = MaxPacketSize
			}
			firstPayload := p[:chunkSize]
			sw, err := s.sendHeaderWithFirstPayload(firstPayload)
			if err != nil {
				s.mu.Unlock()
				return 0, err
			}
			s.streamWriter = sw
			p = p[chunkSize:]
		}
		s.mu.Unlock()
		if len(p) == 0 {
			return n, nil
		}
	}

	_, err := s.streamWriter.Write(p)
	return n, err
}

func (s *ServerStreamWriter) Close() error {
	if s.streamWriter == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.streamWriter == nil {
			sw, err := s.sendHeaderWithFirstPayload(nil)
			if err != nil {
				return err
			}
			s.streamWriter = sw
		}
	}
	return nil
}

// InitServerStream decrypts the client request header, verifies the timestamp and replay filter,
// and returns a StreamReader for subsequent stream chunks.
func InitServerStream(conn net.Conn, method *CipherMethod, psk, saltSlice []byte, salt [32]byte, fixedChunk []byte, saltFilter *antireplay.ReplayFilter[[32]byte]) (*StreamReader, *ClientRequestHeader, error) {
	sessionKey := DeriveSessionSubKey(psk, saltSlice, method.KeySaltLength)
	aead, err := method.NewAEAD(sessionKey)
	if err != nil {
		return nil, nil, err
	}

	reader := NewStreamReader(conn, aead)

	reqHeader, err := ReadClientRequestHeaderWithFixed(reader, fixedChunk)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})

	if !saltFilter.Check(salt) {
		return nil, nil, ErrSaltNotUnique
	}
	return reader, reqHeader, nil
}

func TransportTCP(ctx context.Context, sessionPolicy policy.Session, reader buf.Reader, writer buf.Writer, link *transport.Link) error {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if c, ok := writer.(io.Closer); ok {
			defer c.Close()
		}
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	return task.Run(ctx, requestDone, responseDoneAndCloseWriter)
}
