package gametunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
)

// ====================================================================
// Криптография GameTunnel
// ====================================================================
//
// Обмен ключами: X25519 (Curve25519 ECDH)
//   - Клиент и сервер генерируют эфемерные пары ключей
//   - Вычисляют общий секрет через ECDH
//   - Если задан PSK (pre-shared key), он подмешивается в derivation
//
// Деривация ключей: HKDF-SHA256
//   - Из общего секрета + PSK выводятся два ключа:
//     - Client → Server key
//     - Server → Client key
//   - Каждое направление имеет свой ключ (предотвращает reflection attacks)
//
// Шифрование: ChaCha20-Poly1305 (RFC 8439)
//   - AEAD: шифрование + аутентификация в одном
//   - Nonce: 12 байт = 8 байт zeros + 4 байта Packet Number
//   - Быстрый на всём железе (не требует AES-NI)
//   - Additional Data: заголовок пакета (flags + version + connID)
//
// ====================================================================

const (
	// KeySize - размер ключа ChaCha20-Poly1305
	KeySize = chacha20poly1305.KeySize // 32 bytes

	// NonceSize - размер nonce ChaCha20-Poly1305
	NonceSize = chacha20poly1305.NonceSize // 12 bytes

	// Curve25519KeySize - размер ключа Curve25519
	Curve25519KeySize = 32

	// HKDFInfoClient - HKDF info для ключа шифрования клиент → сервер
	HKDFInfoClient = "gametunnel client-to-server"

	// HKDFInfoServer - HKDF info для ключа шифрования сервер → клиент
	HKDFInfoServer = "gametunnel server-to-client"

	// HKDFSalt - статическая соль для HKDF
	// В реальном протоколе можно обновлять при ротации ключей
	HKDFSalt = "GameTunnel-v1-salt"
)

// KeyPair - пара ключей Curve25519 для обмена ключами
type KeyPair struct {
	// PrivateKey - секретный ключ (32 байта)
	PrivateKey [Curve25519KeySize]byte

	// PublicKey - публичный ключ (32 байта)
	PublicKey [Curve25519KeySize]byte
}

// SessionKeys - ключи шифрования для сессии
// Разные ключи для разных направлений предотвращают reflection attacks
type SessionKeys struct {
	// SendKey - ключ для шифрования исходящих пакетов
	SendKey [KeySize]byte

	// RecvKey - ключ для расшифровки входящих пакетов
	RecvKey [KeySize]byte

	// sendCipher - AEAD cipher для шифрования
	sendCipher cipher.AEAD

	// recvCipher - AEAD cipher для расшифровки
	recvCipher cipher.AEAD
}

// HandshakePayload - данные, передаваемые в пакете хэндшейка
type HandshakePayload struct {
	// PublicKey - публичный ключ Curve25519 отправителя
	PublicKey [Curve25519KeySize]byte

	// Timestamp - время отправки (Unix timestamp, 8 байт)
	// Используется для защиты от replay старых хэндшейков
	Timestamp uint64

	// Random - 32 случайных байта для энтропии
	Random [32]byte
}

// GenerateKeyPair создаёт новую пару ключей Curve25519
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	// Генерируем случайный приватный ключ
	_, err := rand.Read(kp.PrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	// Clamp private key (стандартная процедура для Curve25519)
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Вычисляем публичный ключ
	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute public key: %w", err)
	}
	copy(kp.PublicKey[:], pub)

	return kp, nil
}

// ComputeSharedSecret вычисляет общий секрет ECDH
// myPrivate - наш приватный ключ
// theirPublic - публичный ключ другой стороны
func ComputeSharedSecret(myPrivate, theirPublic [Curve25519KeySize]byte) ([Curve25519KeySize]byte, error) {
	var shared [Curve25519KeySize]byte

	result, err := curve25519.X25519(myPrivate[:], theirPublic[:])
	if err != nil {
		return shared, fmt.Errorf("ECDH: %w", err)
	}

	// Проверяем, что результат не нулевой (low-order point attack)
	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return shared, errors.New("ECDH: computed shared secret is zero (possible attack)")
	}

	copy(shared[:], result)
	return shared, nil
}

// DeriveSessionKeys выводит ключи шифрования из общего секрета
// isClient определяет порядок ключей:
//   - Client: SendKey = client-to-server, RecvKey = server-to-client
//   - Server: SendKey = server-to-client, RecvKey = client-to-server
func DeriveSessionKeys(sharedSecret [Curve25519KeySize]byte, psk string, isClient bool) (*SessionKeys, error) {
	// Формируем входной ключевой материал: sharedSecret + PSK (если есть)
	ikm := make([]byte, Curve25519KeySize)
	copy(ikm, sharedSecret[:])

	salt := []byte(HKDFSalt)

	// Если есть PSK - подмешиваем его в соль
	// Это обеспечивает двухфакторную защиту:
	// - Даже если ECDH скомпрометирован, без PSK расшифровка невозможна
	// - Даже если PSK утёк, без приватного ключа ECDH расшифровка невозможна
	if psk != "" {
		pskHash := sha256.Sum256([]byte(psk))
		combined := make([]byte, len(salt)+len(pskHash))
		copy(combined, salt)
		copy(combined[len(salt):], pskHash[:])
		salt = combined
	}

	// Выводим два ключа через HKDF
	clientToServerKey := make([]byte, KeySize)
	serverToClientKey := make([]byte, KeySize)

	// Ключ клиент → сервер
	hkdfReader := hkdf.New(sha256.New, ikm, salt, []byte(HKDFInfoClient))
	if _, err := io.ReadFull(hkdfReader, clientToServerKey); err != nil {
		return nil, fmt.Errorf("derive client-to-server key: %w", err)
	}

	// Ключ сервер → клиент
	hkdfReader = hkdf.New(sha256.New, ikm, salt, []byte(HKDFInfoServer))
	if _, err := io.ReadFull(hkdfReader, serverToClientKey); err != nil {
		return nil, fmt.Errorf("derive server-to-client key: %w", err)
	}

	sk := &SessionKeys{}

	if isClient {
		copy(sk.SendKey[:], clientToServerKey)
		copy(sk.RecvKey[:], serverToClientKey)
	} else {
		copy(sk.SendKey[:], serverToClientKey)
		copy(sk.RecvKey[:], clientToServerKey)
	}

	// Инициализируем AEAD ciphers
	var err error
	sk.sendCipher, err = chacha20poly1305.New(sk.SendKey[:])
	if err != nil {
		return nil, fmt.Errorf("create send cipher: %w", err)
	}

	sk.recvCipher, err = chacha20poly1305.New(sk.RecvKey[:])
	if err != nil {
		return nil, fmt.Errorf("create recv cipher: %w", err)
	}

	return sk, nil
}

// Encrypt шифрует payload пакета
// packetNumber используется для построения nonce
// additionalData - заголовок пакета (аутентифицируется, но не шифруется)
func (sk *SessionKeys) Encrypt(payload []byte, packetNumber uint32, additionalData []byte) ([]byte, error) {
	nonce := buildNonce(packetNumber)

	// ChaCha20-Poly1305 AEAD:
	// - Шифрует payload
	// - Аутентифицирует additionalData + payload
	// - Добавляет 16-байтный Poly1305 tag
	ciphertext := sk.sendCipher.Seal(nil, nonce, payload, additionalData)

	return ciphertext, nil
}

// Decrypt расшифровывает payload пакета
func (sk *SessionKeys) Decrypt(ciphertext []byte, packetNumber uint32, additionalData []byte) ([]byte, error) {
	nonce := buildNonce(packetNumber)

	plaintext, err := sk.recvCipher.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed (possible tampering or wrong key)")
	}

	return plaintext, nil
}

// buildNonce создаёт 12-байтный nonce из номера пакета
// Формат: [0x00 * 8][PacketNumber BigEndian * 4]
// Первые 8 байт - нули, последние 4 - номер пакета
// Это гарантирует уникальность nonce для каждого пакета
func buildNonce(packetNumber uint32) []byte {
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint32(nonce[8:], packetNumber)
	return nonce
}

// MarshalHandshake сериализует HandshakePayload в байты
// Формат: [PublicKey 32][Timestamp 8][Random 32] = 72 байта
func (h *HandshakePayload) Marshal() []byte {
	buf := make([]byte, Curve25519KeySize+8+32)
	offset := 0

	copy(buf[offset:], h.PublicKey[:])
	offset += Curve25519KeySize

	binary.BigEndian.PutUint64(buf[offset:], h.Timestamp)
	offset += 8

	copy(buf[offset:], h.Random[:])

	return buf
}

// UnmarshalHandshake десериализует HandshakePayload из байтов
func UnmarshalHandshake(data []byte) (*HandshakePayload, error) {
	expectedSize := Curve25519KeySize + 8 + 32
	if len(data) < expectedSize {
		return nil, fmt.Errorf("handshake payload too short: %d bytes, expected %d",
			len(data), expectedSize)
	}

	h := &HandshakePayload{}
	offset := 0

	copy(h.PublicKey[:], data[offset:offset+Curve25519KeySize])
	offset += Curve25519KeySize

	h.Timestamp = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(h.Random[:], data[offset:offset+32])

	return h, nil
}

// NewHandshakePayload создаёт HandshakePayload с текущим временем
func NewHandshakePayload(publicKey [Curve25519KeySize]byte, timestamp uint64) *HandshakePayload {
	h := &HandshakePayload{
		PublicKey: publicKey,
		Timestamp: timestamp,
	}

	// Заполняем Random криптографически случайными байтами
	rand.Read(h.Random[:])

	return h
}
