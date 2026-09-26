package shadowsocks_2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	mrand "math/rand"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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

// ReadAddressPort reads a destination address and port in SOCKS5 format
func ReadAddressPort(r io.Reader) (net.Destination, error) {
	addr, port, err := addrParser.ReadAddressPort(nil, r)
	if err != nil {
		return net.Destination{}, err
	}
	return net.TCPDestination(addr, port), nil
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
		if err := w.WriteChunk(b.Bytes()); err != nil {
			return err
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
	if payloadLen == 0 {
		return 0, nil
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
		b := buf.New()
		b.Write(r.buffer[r.offset : r.offset+r.cached])
		r.cached = 0
		r.offset = 0
		return buf.MultiBuffer{b}, nil
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
	if payloadLen == 0 {
		return nil, nil
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

	b := buf.New()
	b.Write(decryptedPayload)
	return buf.MultiBuffer{b}, nil
}

type ClientRequestHeader struct {
	Destination net.Destination
	EarlyData   []byte
}

func ReadClientRequestHeader(conn io.Reader, reader *StreamReader) (*ClientRequestHeader, error) {
	var fixedBuf [RequestHeaderFixedChunkLength + AEADTagSize]byte
	if _, err := io.ReadFull(conn, fixedBuf[:]); err != nil {
		return nil, err
	}

	plainFixed, err := reader.cipher.Open(fixedBuf[:0], reader.Nonce(), fixedBuf[:], nil)
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
	if _, err := io.ReadFull(conn, varChunkCipher); err != nil {
		return nil, err
	}

	plainVar, err := reader.cipher.Open(varChunkCipher[:0], reader.Nonce(), varChunkCipher, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt variable request header").Base(err)
	}
	IncreaseNonce(reader.Nonce())

	b := buf.New()
	b.Write(plainVar)
	defer b.Release()

	dest, err := ReadAddressPort(b)
	if err != nil {
		return nil, err
	}

	var padLenBytes [2]byte
	if _, err := b.Read(padLenBytes[:]); err != nil {
		return nil, err
	}
	paddingLen := int(binary.BigEndian.Uint16(padLenBytes[:]))
	if int(b.Len()) < paddingLen {
		return nil, ErrNoPadding
	}
	if paddingLen > 0 {
		b.Advance(int32(paddingLen))
	}

	var earlyData []byte
	if b.Len() > 0 {
		earlyData = make([]byte, b.Len())
		copy(earlyData, b.Bytes())
	}

	return &ClientRequestHeader{
		Destination: dest,
		EarlyData:   earlyData,
	}, nil
}

// ClientHandshake writes the full client request header to w
func ClientHandshake(w io.Writer, method *CipherMethod, pskList [][]byte, dest net.Destination, payload []byte) ([]byte, *StreamWriter, error) {
	salt := make([]byte, method.KeySaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	writer, err := WriteTCPRequest(w, method, pskList, dest, salt, payload)
	if err != nil {
		return nil, nil, err
	}
	return salt, writer.(*StreamWriter), nil
}

// ClientVerifyServerResponse reads and verifies the server's handshake response
func ClientVerifyServerResponse(r io.Reader, method *CipherMethod, psk []byte, clientSalt []byte) (*StreamReader, []byte, error) {
	reader, err := ReadTCPResponse(r, method, psk, clientSalt)
	if err != nil {
		return nil, nil, err
	}
	sr := reader.(*StreamReader)
	var initialPayload []byte
	if sr.cached > 0 {
		initialPayload = make([]byte, sr.cached)
		copy(initialPayload, sr.buffer[sr.offset:sr.offset+sr.cached])
	}
	return sr, initialPayload, nil
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

	handshakeBuf := buf.New()
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

	payloadLen := len(payload)
	var paddingLen int
	if payloadLen < MaxPaddingLength {
		paddingLen = mrand.Intn(MaxPaddingLength-payloadLen) + 1
	}
	addrPortLen := AddrPortLength(dest)
	varHeaderLen := addrPortLen + 2 + paddingLen + payloadLen

	var fixedHeaderPlaintext [RequestHeaderFixedChunkLength]byte
	fixedHeaderPlaintext[0] = HeaderTypeClient
	binary.BigEndian.PutUint64(fixedHeaderPlaintext[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(fixedHeaderPlaintext[9:11], uint16(varHeaderLen))

	fixedChunk := writer.cipher.Seal(nil, writer.nonce[:], fixedHeaderPlaintext[:], nil)
	IncreaseNonce(writer.nonce[:])
	handshakeBuf.Write(fixedChunk)

	varHeaderBuf := buf.New()
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
	var serverSalt [32]byte
	serverSaltSlice := serverSalt[:method.KeySaltLength]
	if _, err := io.ReadFull(r, serverSaltSlice); err != nil {
		return nil, err
	}

	sessionKey := DeriveSessionSubKey(psk, serverSaltSlice, method.KeySaltLength)
	aead, err := method.NewAEAD(sessionKey)
	if err != nil {
		return nil, err
	}

	reader := NewStreamReader(r, aead)

	fixedPlainLen := 1 + 8 + method.KeySaltLength + 2
	chunkCipherLen := fixedPlainLen + AEADTagSize
	var chunkBuf [64]byte
	chunkSlice := chunkBuf[:chunkCipherLen]
	if _, err := io.ReadFull(r, chunkSlice); err != nil {
		return nil, err
	}

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

// WriteTCPResponse writes the server handshake response and returns a body writer for server stream.
func WriteTCPResponse(w io.Writer, method *CipherMethod, psk []byte, clientSalt []byte, initialPayload []byte) (buf.Writer, error) {
	var serverSalt [32]byte
	serverSaltSlice := serverSalt[:method.KeySaltLength]
	if _, err := io.ReadFull(rand.Reader, serverSaltSlice); err != nil {
		return nil, err
	}

	respKey := DeriveSessionSubKey(psk, serverSaltSlice, method.KeySaltLength)
	respAead, err := method.NewAEAD(respKey)
	if err != nil {
		return nil, err
	}
	writer := NewStreamWriter(w, respAead)

	respBuf := buf.New()
	defer respBuf.Release()

	respBuf.Write(serverSaltSlice)

	var fixedRespPlain [1 + 8 + 32 + 2]byte
	fixedRespSlice := fixedRespPlain[:1+8+method.KeySaltLength+2]
	fixedRespSlice[0] = HeaderTypeServer
	binary.BigEndian.PutUint64(fixedRespSlice[1:9], uint64(time.Now().Unix()))
	copy(fixedRespSlice[9:9+method.KeySaltLength], clientSalt)
	binary.BigEndian.PutUint16(fixedRespSlice[9+method.KeySaltLength:11+method.KeySaltLength], uint16(len(initialPayload)))

	fixedRespChunk := writer.cipher.Seal(nil, writer.nonce[:], fixedRespSlice, nil)
	IncreaseNonce(writer.nonce[:])
	respBuf.Write(fixedRespChunk)

	if len(initialPayload) > 0 {
		initialChunk := writer.cipher.Seal(nil, writer.nonce[:], initialPayload, nil)
		IncreaseNonce(writer.nonce[:])
		respBuf.Write(initialChunk)
	}

	if _, err := w.Write(respBuf.Bytes()); err != nil {
		return nil, err
	}

	return writer, nil
}
