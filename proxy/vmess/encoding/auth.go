package encoding

import (
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"hash/fnv"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	vmessaead "github.com/xtls/xray-core/proxy/vmess/aead"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// Authenticate authenticates a byte array using Fnv hash.
func Authenticate(b []byte) uint32 {
	fnv1hash := fnv.New32a()
	common.Must2(fnv1hash.Write(b))
	return fnv1hash.Sum32()
}

// GenerateChacha20Poly1305Key generates a 32-byte key from a given 16-byte array.
func GenerateChacha20Poly1305Key(b []byte) []byte {
	key := make([]byte, 32)
	t := md5.Sum(b)
	copy(key, t[:])
	t = md5.Sum(key[:16])
	copy(key[16:], t[:])
	return key
}

type ShakeSizeParser struct {
	shake  sha3.ShakeHash
	buffer [2]byte
}

func NewShakeSizeParser(nonce []byte) *ShakeSizeParser {
	shake := sha3.NewShake128()
	common.Must2(shake.Write(nonce))
	return &ShakeSizeParser{
		shake: shake,
	}
}

func (*ShakeSizeParser) SizeBytes() int32 {
	return 2
}

func (s *ShakeSizeParser) next() uint16 {
	common.Must2(s.shake.Read(s.buffer[:]))
	return binary.BigEndian.Uint16(s.buffer[:])
}

func (s *ShakeSizeParser) Decode(b []byte) (uint16, error) {
	mask := s.next()
	size := binary.BigEndian.Uint16(b)
	return mask ^ size, nil
}

func (s *ShakeSizeParser) Encode(size uint16, b []byte) []byte {
	mask := s.next()
	binary.BigEndian.PutUint16(b, mask^size)
	return b[:2]
}

func (s *ShakeSizeParser) NextPaddingLen() uint16 {
	return s.next() % 64
}

func (s *ShakeSizeParser) MaxPaddingLen() uint16 {
	return 64
}

type AEADSizeParser struct {
	crypto.AEADChunkSizeParser
}

func NewAEADSizeParser(auth *crypto.AEADAuthenticator) *AEADSizeParser {
	return &AEADSizeParser{crypto.AEADChunkSizeParser{Auth: auth}}
}

type bodySizeParser interface {
	crypto.ChunkSizeEncoder
	crypto.ChunkSizeDecoder
}

func newBodyCodec(request *protocol.RequestHeader, bodyKey, bodyIV, requestKey, requestIV []byte) (*crypto.AEADAuthenticator, bodySizeParser, crypto.PaddingLengthGenerator, error) {
	var sizes bodySizeParser = crypto.PlainChunkSizeParser{}
	if request.Option.Has(protocol.RequestOptionChunkMasking) {
		sizes = NewShakeSizeParser(bodyIV)
	}
	var padding crypto.PaddingLengthGenerator
	if request.Option.Has(protocol.RequestOptionGlobalPadding) {
		var ok bool
		padding, ok = sizes.(crypto.PaddingLengthGenerator)
		if !ok {
			return nil, nil, nil, errors.New("invalid option: RequestOptionGlobalPadding")
		}
	}

	var newAEAD func([]byte) cipher.AEAD
	switch request.Security {
	case protocol.SecurityType_AES128_GCM:
		newAEAD = crypto.NewAesGcm
	case protocol.SecurityType_CHACHA20_POLY1305:
		newAEAD = func(key []byte) cipher.AEAD {
			aead, err := chacha20poly1305.New(GenerateChacha20Poly1305Key(key))
			common.Must(err)
			return aead
		}
	default:
		return nil, nil, nil, errors.New("invalid option: Security")
	}

	auth := newBodyAuthenticator(newAEAD(bodyKey), bodyIV)
	if request.Option.Has(protocol.RequestOptionAuthenticatedLength) {
		// Both directions authenticate lengths with the request key and IV.
		lengthKey := vmessaead.KDF16(requestKey, "auth_len")
		sizes = NewAEADSizeParser(newBodyAuthenticator(newAEAD(lengthKey), requestIV))
	}
	return auth, sizes, padding, nil
}

func newBodyAuthenticator(aead cipher.AEAD, iv []byte) *crypto.AEADAuthenticator {
	return &crypto.AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateChunkNonce(iv, uint32(aead.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
}
