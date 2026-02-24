package gametunnel

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
)

// ====================================================================
// Формат пакета GameTunnel (QUIC-мимикрия)
// ====================================================================
//
// Пакет GameTunnel маскируется под QUIC Long Header Packet (RFC 9000).
// DPI-системы видят валидный QUIC-трафик на UDP-порту.
//
// Структура пакета:
// +--------+----------+--------+-----------+----------+---------+---------+----------+
// | Flags  | Version  | DCID   | Pkt Num   | Payload  | Padding | Pad Len | Auth Tag |
// | 1 byte | 4 bytes  | N bytes| 4 bytes   | variable | variable| 2 bytes | 16 bytes |
// +--------+----------+--------+-----------+----------+---------+---------+----------+
//
// Flags byte (маскируется под QUIC Form Bit + Fixed Bit):
//   Bit 7 (Form):      1 = Long Header (как QUIC Initial)
//   Bit 6 (Fixed):     1 = Fixed bit (всегда 1 в QUIC)
//   Bits 5-4 (Type):   Тип пакета GameTunnel
//                       00 = Data
//                       01 = Handshake
//                       10 = KeepAlive
//                       11 = Control
//   Bit 3 (Padding):   1 = пакет содержит padding
//   Bits 2-0:          Зарезервированы (заполняются случайно)
//
// Version (4 bytes): фейковая версия QUIC
//   0x00000001 - QUIC v1 (RFC 9000)
//   Это делает пакет неотличимым от настоящего QUIC Initial
//
// DCID (Connection ID, N bytes): идентификатор сессии
//   Длина задаётся в конфиге (по умолчанию 8 байт)
//   Генерируется при хэндшейке, уникален для каждой сессии
//
// Packet Number (4 bytes): порядковый номер пакета
//   Шифруется отдельно для защиты от replay-атак
//   Монотонно возрастает в рамках сессии
//
// Payload (variable): зашифрованные данные
//   Шифруется ChaCha20-Poly1305
//   Nonce = Packet Number (расширенный до 12 байт)
//
// Padding (variable): случайные байты для маскировки размера
//   Присутствует только если Flags.Padding = 1
//   Размер - случайный в диапазоне [PaddingMinSize, PaddingMaxSize]
//
// Padding Length (2 bytes): длина padding
//   Присутствует только если Flags.Padding = 1
//   Little-endian uint16
//
// Auth Tag (16 bytes): Poly1305 authentication tag
//   Обеспечивает целостность всего пакета
//   Генерируется ChaCha20-Poly1305 AEAD
// ====================================================================

// Типы пакетов GameTunnel
type PacketType uint8

const (
	// PacketType_DATA - пакет с полезными данными
	PacketType_DATA PacketType = 0x00

	// PacketType_HANDSHAKE - пакет хэндшейка (обмен ключами)
	PacketType_HANDSHAKE PacketType = 0x01

	// PacketType_KEEPALIVE - keep-alive для поддержания NAT и детекции обрыва
	PacketType_KEEPALIVE PacketType = 0x02

	// PacketType_CONTROL - управляющий пакет (закрытие, ошибки, смена ключей)
	PacketType_CONTROL PacketType = 0x03
)

// Константы протокола
const (
	// FakeQUICVersion - фейковая версия QUIC v1 (RFC 9000)
	FakeQUICVersion uint32 = 0x00000001

	// MinPacketSize - минимальный размер пакета GameTunnel
	// flags(1) + version(4) + min_connid(4) + pktnum(4) + auth_tag(16)
	MinPacketSize = 29

	// AuthTagSize - размер Poly1305 authentication tag
	AuthTagSize = 16

	// PacketNumberSize - размер номера пакета
	PacketNumberSize = 4

	// VersionSize - размер поля версии
	VersionSize = 4

	// FlagsSize - размер поля флагов
	FlagsSize = 1

	// PaddingLengthSize - размер поля длины padding
	PaddingLengthSize = 2

	// PayloadLengthSize - размер поля длины payload
	PayloadLengthSize = 2

	// MaxPacketSize - максимальный размер пакета (MTU limit)
	MaxPacketSize = 1500

	// QUIC Long Header mask bits
	FlagFormBit    = 0x80 // Bit 7: Long Header form
	FlagFixedBit   = 0x40 // Bit 6: Fixed bit (always 1)
	FlagTypeMask   = 0x30 // Bits 5-4: Packet type
	FlagTypeShift  = 4
	FlagPaddingBit = 0x08 // Bit 3: Padding present
	FlagReserved   = 0x07 // Bits 2-0: Reserved (random)
)

// Packet - структура пакета GameTunnel в памяти
type Packet struct {
	// Type - тип пакета (Data, Handshake, KeepAlive, Control)
	Type PacketType

	// ConnectionID - идентификатор сессии
	ConnectionID []byte

	// PacketNumber - порядковый номер пакета в сессии
	PacketNumber uint32

	// Payload - полезная нагрузка (до шифрования - открытый текст, после - шифротекст)
	Payload []byte

	// HasPadding - содержит ли пакет padding
	HasPadding bool

	// StreamID - идентификатор потока для мультиплексирования
	// Находится внутри зашифрованного payload
	StreamID uint16
}

// PacketHeader - заголовок пакета для сериализации/десериализации
type PacketHeader struct {
	Flags        byte
	Version      uint32
	ConnectionID []byte
	PacketNumber uint32
}

// EncodeFlags кодирует флаги пакета в один байт
// Результат выглядит как валидный QUIC Long Header первый байт
func (p *Packet) EncodeFlags() byte {
	flags := byte(0)

	// Устанавливаем Form bit = 1 (Long Header, как QUIC Initial)
	flags |= FlagFormBit

	// Устанавливаем Fixed bit = 1 (обязательно для QUIC)
	flags |= FlagFixedBit

	// Тип пакета в биты 5-4
	flags |= byte(p.Type&0x03) << FlagTypeShift

	// Флаг padding
	if p.HasPadding {
		flags |= FlagPaddingBit
	}

	// Reserved bits = 0 (для совместимости с AEAD additional data)

	return flags
}

// DecodeFlags декодирует флаги из первого байта пакета
func DecodeFlags(flags byte) (packetType PacketType, hasPadding bool, err error) {
	// Проверяем Form bit - должен быть 1 (Long Header)
	if flags&FlagFormBit == 0 {
		return 0, false, errors.New("invalid packet: Form bit is 0, expected Long Header")
	}

	// Проверяем Fixed bit - должен быть 1
	if flags&FlagFixedBit == 0 {
		return 0, false, errors.New("invalid packet: Fixed bit is 0")
	}

	// Извлекаем тип пакета
	packetType = PacketType((flags & FlagTypeMask) >> FlagTypeShift)

	// Извлекаем флаг padding
	hasPadding = (flags & FlagPaddingBit) != 0

	return packetType, hasPadding, nil
}

// Marshal сериализует пакет в байты для отправки по сети
// Возвращает пакет БЕЗ шифрования - шифрование выполняется отдельно в crypto.go
// Формат: [flags][version][connID][pktNum][payloadLen][payload][padding][padLen]
func (p *Packet) Marshal(config *Config) ([]byte, error) {
	connIDLen := int(config.ConnectionIdLength)

	if len(p.ConnectionID) != connIDLen {
		return nil, fmt.Errorf("connection ID length mismatch: got %d, expected %d",
			len(p.ConnectionID), connIDLen)
	}

	// Рассчитываем размер padding
	paddingSize := 0
	if p.HasPadding && config.EnablePadding {
		minPad := int(config.PaddingMinSize)
		maxPad := int(config.PaddingMaxSize)
		if maxPad > minPad {
			paddingSize = minPad + mrand.Intn(maxPad-minPad)
		} else {
			paddingSize = minPad
		}
	}

	// Общий размер пакета
	totalSize := FlagsSize + VersionSize + connIDLen + PacketNumberSize +
		PayloadLengthSize + len(p.Payload)

	if p.HasPadding && paddingSize > 0 {
		totalSize += paddingSize + PaddingLengthSize
	}

// Разрешаем любой размер — UDP сам фрагментирует если нужно
	// Чанкинг в Write/SendToSession контролирует размер
	_ = MaxPacketSize

	buf := make([]byte, totalSize)
	offset := 0

	// 1. Flags
	buf[offset] = p.EncodeFlags()
	offset += FlagsSize

	// 2. Fake QUIC Version
	binary.BigEndian.PutUint32(buf[offset:], FakeQUICVersion)
	offset += VersionSize

	// 3. Connection ID
	copy(buf[offset:], p.ConnectionID)
	offset += connIDLen

	// 4. Packet Number
	binary.BigEndian.PutUint32(buf[offset:], p.PacketNumber)
	offset += PacketNumberSize

	// 5. Payload Length
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(p.Payload)))
	offset += PayloadLengthSize

	// 6. Payload
	copy(buf[offset:], p.Payload)
	offset += len(p.Payload)

	// 7. Padding + Padding Length (если есть)
	if p.HasPadding && paddingSize > 0 {
		// Заполняем padding случайными байтами
		padding := make([]byte, paddingSize)
		rand.Read(padding)
		copy(buf[offset:], padding)
		offset += paddingSize

		// Длина padding
		binary.BigEndian.PutUint16(buf[offset:], uint16(paddingSize))
		offset += PaddingLengthSize
	}

	return buf[:offset], nil
}

// Unmarshal десериализует пакет из байтов, полученных из сети
// Ожидает пакет ПОСЛЕ расшифровки
func Unmarshal(data []byte, connIDLen int) (*Packet, error) {
	if len(data) < FlagsSize+VersionSize+connIDLen+PacketNumberSize+PayloadLengthSize {
		return nil, fmt.Errorf("packet too short: %d bytes, minimum %d",
			len(data), FlagsSize+VersionSize+connIDLen+PacketNumberSize+PayloadLengthSize)
	}

	p := &Packet{}
	offset := 0

	// 1. Flags
	flags := data[offset]
	offset += FlagsSize

	pktType, hasPadding, err := DecodeFlags(flags)
	if err != nil {
		return nil, fmt.Errorf("decode flags: %w", err)
	}
	p.Type = pktType
	p.HasPadding = hasPadding

	// 2. Version - проверяем, но не сохраняем (всегда FakeQUICVersion)
	version := binary.BigEndian.Uint32(data[offset:])
	if version != FakeQUICVersion {
		return nil, fmt.Errorf("unsupported version: 0x%08x", version)
	}
	offset += VersionSize

	// 3. Connection ID
	p.ConnectionID = make([]byte, connIDLen)
	copy(p.ConnectionID, data[offset:offset+connIDLen])
	offset += connIDLen

	// 4. Packet Number
	p.PacketNumber = binary.BigEndian.Uint32(data[offset:])
	offset += PacketNumberSize

	// 5. Payload Length
	if offset+PayloadLengthSize > len(data) {
		return nil, errors.New("packet truncated: missing payload length")
	}
	payloadLen := binary.BigEndian.Uint16(data[offset:])
	offset += PayloadLengthSize

	// 6. Payload
	if offset+int(payloadLen) > len(data) {
		return nil, fmt.Errorf("packet truncated: payload length %d, available %d",
			payloadLen, len(data)-offset)
	}
	p.Payload = make([]byte, payloadLen)
	copy(p.Payload, data[offset:offset+int(payloadLen)])
	offset += int(payloadLen)

	// 7. Padding - пропускаем (нам не нужно содержимое)
	// Padding используется только для маскировки размера пакета

	return p, nil
}

// NewDataPacket создаёт пакет с данными
func NewDataPacket(connID []byte, pktNum uint32, payload []byte, enablePadding bool) *Packet {
	return &Packet{
		Type:         PacketType_DATA,
		ConnectionID: connID,
		PacketNumber: pktNum,
		Payload:      payload,
		HasPadding:   enablePadding,
	}
}

// NewHandshakePacket создаёт пакет хэндшейка
func NewHandshakePacket(connID []byte, pktNum uint32, payload []byte) *Packet {
	// Хэндшейк всегда с padding для маскировки размера ключей
	return &Packet{
		Type:         PacketType_HANDSHAKE,
		ConnectionID: connID,
		PacketNumber: pktNum,
		Payload:      payload,
		HasPadding:   true,
	}
}

// NewKeepAlivePacket создаёт keep-alive пакет
func NewKeepAlivePacket(connID []byte, pktNum uint32) *Packet {
	return &Packet{
		Type:         PacketType_KEEPALIVE,
		ConnectionID: connID,
		PacketNumber: pktNum,
		Payload:      []byte{}, // Keep-alive не несёт данных
		HasPadding:   true,     // Но padding добавляем для маскировки
	}
}

// NewControlPacket создаёт управляющий пакет
func NewControlPacket(connID []byte, pktNum uint32, payload []byte) *Packet {
	return &Packet{
		Type:         PacketType_CONTROL,
		ConnectionID: connID,
		PacketNumber: pktNum,
		Payload:      payload,
		HasPadding:   false,
	}
}

// GenerateConnectionID генерирует криптографически случайный Connection ID
func GenerateConnectionID(length int) ([]byte, error) {
	if length < 4 || length > 20 {
		return nil, fmt.Errorf("connection ID length must be 4-20, got %d", length)
	}
	id := make([]byte, length)
	_, err := rand.Read(id)
	if err != nil {
		return nil, fmt.Errorf("generate connection ID: %w", err)
	}
	return id, nil
}

// IsQUICLike проверяет, выглядит ли первый байт как QUIC Long Header
// Используется для быстрой фильтрации входящих пакетов
func IsQUICLike(firstByte byte) bool {
	// QUIC Long Header: Form bit = 1, Fixed bit = 1
	return (firstByte & (FlagFormBit | FlagFixedBit)) == (FlagFormBit | FlagFixedBit)
}
