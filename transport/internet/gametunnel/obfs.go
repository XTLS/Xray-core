package gametunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"time"
)

// ====================================================================
// Обфускация GameTunnel
// ====================================================================
//
// Этот модуль отвечает за маскировку трафика GameTunnel
// под легитимные протоколы (QUIC, WebRTC DTLS).
//
// Цель: DPI-системы (ТСПУ, GFW и т.д.) не должны отличить
// трафик GameTunnel от настоящего QUIC/WebRTC.
//
// Три режима:
//   1. QUIC Mimic - основной, маскировка под QUIC v1 (RFC 9000)
//   2. WebRTC Mimic - маскировка под DTLS (RFC 6347)
//   3. Raw - без обфускации
//
// Каждый режим реализует интерфейс Obfuscator:
//   - Wrap()   - оборачивает исходящий пакет
//   - Unwrap() - снимает обёртку с входящего пакета
//
// ====================================================================

// Obfuscator - интерфейс обфускации
type Obfuscator interface {
	// Wrap оборачивает пакет GameTunnel в обфускационную обёртку
	// Возвращает данные, готовые к отправке по UDP
	Wrap(packet []byte) ([]byte, error)

	// Unwrap снимает обфускационную обёртку
	// Возвращает оригинальный пакет GameTunnel
	Unwrap(data []byte) ([]byte, error)

	// Name возвращает имя обфускатора
	Name() string
}

// NewObfuscator создаёт обфускатор по режиму из конфига
func NewObfuscator(mode ObfuscationMode) Obfuscator {
	switch mode {
	case ObfuscationMode_QUIC_MIMIC:
		return &QUICObfuscator{}
	case ObfuscationMode_WEBRTC_MIMIC:
		return &WebRTCObfuscator{}
	case ObfuscationMode_RAW:
		return &RawObfuscator{}
	default:
		return &QUICObfuscator{}
	}
}

// ====================================================================
// QUIC Obfuscator - маскировка под QUIC v1
// ====================================================================
//
// Стратегия: наши пакеты УЖЕ имеют QUIC-подобный заголовок
// (см. packet.go), но продвинутый DPI может проверять
// дополнительные поля. Этот обфускатор добавляет:
//
//   1. DCID Length byte - QUIC Long Header содержит длину DCID
//      перед самим DCID. Мы вставляем этот байт.
//
//   2. SCID (Source Connection ID) - фейковый SCID с длиной,
//      как в настоящем QUIC Initial.
//
//   3. Token Length + Token - QUIC Initial может содержать
//      retry token. Мы ставим длину 0.
//
//   4. Payload Length - как в настоящем QUIC, используем
//      variable-length integer encoding.
//
// Результат: побайтовая структура идентична настоящему
// QUIC Initial Packet. Даже Wireshark декодирует его как QUIC.
//
// ====================================================================

// QUIC версии для рандомизации
var quicVersions = []uint32{
	0x00000001, // QUIC v1 (RFC 9000) - основной
	0x6B3343CF, // QUIC v2 (RFC 9369)
}

// QUICObfuscator маскирует трафик под QUIC
type QUICObfuscator struct{}

func (o *QUICObfuscator) Name() string {
	return "quic-mimic"
}

// Wrap оборачивает пакет GameTunnel в полноценный QUIC Initial Packet
//
// Формат настоящего QUIC Long Header (Initial):
// +--------+----------+--------+------+--------+------+---------+-----------+---------+
// | Flags  | Version  | DCID   | DCID | SCID   | SCID | Token   | Payload   | Payload |
// | 1 byte | 4 bytes  | Len 1B | var  | Len 1B | var  | Len var | Len var   | var     |
// +--------+----------+--------+------+--------+------+---------+-----------+---------+
//
func (o *QUICObfuscator) Wrap(packet []byte) ([]byte, error) {
	if len(packet) < FlagsSize+VersionSize {
		return nil, fmt.Errorf("packet too short for QUIC wrapping: %d bytes", len(packet))
	}

	// Извлекаем компоненты из нашего пакета
	flags := packet[0]
	// Пропускаем version (4 bytes) - мы запишем свою
	originalData := packet[FlagsSize+VersionSize:] // всё после flags+version

	// Определяем длину Connection ID из данных
	// (первые N байт originalData - это Connection ID)
	// Для правильного расчёта нам нужно знать connIDLen,
	// но мы можем работать с фиксированным размером.
	// Берём стандартный QUIC DCID length = 8
	dcidLen := byte(8)
	if len(originalData) < int(dcidLen) {
		return nil, fmt.Errorf("packet too short for DCID")
	}

	dcid := originalData[:dcidLen]
	restData := originalData[dcidLen:] // pktNum + payloadLen + payload + padding

	// Генерируем фейковый SCID (Source Connection ID)
	// QUIC Initial обычно имеет SCID длиной 8-20 байт
	scidLen := byte(8)
	scid := make([]byte, scidLen)
	rand.Read(scid)

	// Выбираем версию QUIC
	version := quicVersions[mrand.Intn(len(quicVersions))]

	// Собираем QUIC Initial Packet
	// Размер: flags(1) + version(4) + dcidLen(1) + dcid(N) + scidLen(1) + scid(N) + tokenLen(varint) + payloadLen(varint) + rest
	//
	// Token Length = 0 (no retry token)
	// Payload Length = len(restData) в QUIC variable-length integer

	payloadLenEncoded := encodeQUICVarint(uint64(len(restData)))

	totalSize := 1 + 4 + 1 + int(dcidLen) + 1 + int(scidLen) + 1 + len(payloadLenEncoded) + len(restData)
	buf := make([]byte, totalSize)
	offset := 0

	// 1. Flags - сохраняем наши флаги (уже QUIC-совместимые)
	buf[offset] = flags
	offset++

	// 2. Version
	binary.BigEndian.PutUint32(buf[offset:], version)
	offset += 4

	// 3. DCID Length
	buf[offset] = dcidLen
	offset++

	// 4. DCID
	copy(buf[offset:], dcid)
	offset += int(dcidLen)

	// 5. SCID Length
	buf[offset] = scidLen
	offset++

	// 6. SCID
	copy(buf[offset:], scid)
	offset += int(scidLen)

	// 7. Token Length = 0 (variable-length integer, 1 byte)
	buf[offset] = 0x00
	offset++

	// 8. Payload Length (QUIC variable-length integer)
	copy(buf[offset:], payloadLenEncoded)
	offset += len(payloadLenEncoded)

	// 9. Rest of packet (pktNum + payloadLen + payload + padding)
	copy(buf[offset:], restData)
	offset += len(restData)

	return buf[:offset], nil
}

// Unwrap снимает QUIC-обёртку и восстанавливает пакет GameTunnel
func (o *QUICObfuscator) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 7 { // минимум: flags + version + dcidLen + scidLen
		return nil, fmt.Errorf("QUIC packet too short: %d bytes", len(data))
	}

	offset := 0

	// 1. Flags
	flags := data[offset]
	offset++

	// 2. Version (пропускаем, мы используем свою)
	offset += 4

	// 3. DCID Length
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated: missing DCID length")
	}
	dcidLen := int(data[offset])
	offset++

	// 4. DCID
	if offset+dcidLen > len(data) {
		return nil, fmt.Errorf("truncated: DCID extends beyond packet")
	}
	dcid := data[offset : offset+dcidLen]
	offset += dcidLen

	// 5. SCID Length
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated: missing SCID length")
	}
	scidLen := int(data[offset])
	offset++

	// 6. SCID (пропускаем)
	if offset+scidLen > len(data) {
		return nil, fmt.Errorf("truncated: SCID extends beyond packet")
	}
	offset += scidLen

	// 7. Token Length (variable-length integer)
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated: missing token length")
	}
	tokenLen, tokenLenSize, err := decodeQUICVarint(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("decode token length: %w", err)
	}
	offset += tokenLenSize

	// 8. Token (пропускаем)
	if offset+int(tokenLen) > len(data) {
		return nil, fmt.Errorf("truncated: token extends beyond packet")
	}
	offset += int(tokenLen)

	// 9. Payload Length (variable-length integer)
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated: missing payload length")
	}
	_, payloadLenSize, err := decodeQUICVarint(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("decode payload length: %w", err)
	}
	offset += payloadLenSize

	// 10. Rest of packet - это наш оригинальный payload
	restData := data[offset:]

	// Восстанавливаем оригинальный формат GameTunnel:
	// flags + version + connID + restData
	result := make([]byte, FlagsSize+VersionSize+dcidLen+len(restData))
	resultOffset := 0

	result[resultOffset] = flags
	resultOffset++

	binary.BigEndian.PutUint32(result[resultOffset:], FakeQUICVersion)
	resultOffset += VersionSize

	copy(result[resultOffset:], dcid)
	resultOffset += dcidLen

	copy(result[resultOffset:], restData)

	return result, nil
}

// ====================================================================
// WebRTC Obfuscator - маскировка под DTLS (WebRTC)
// ====================================================================
//
// Стратегия: маскировка под DTLS 1.2 record,
// который используется в WebRTC для шифрования медиа.
// Мобильные операторы и DPI обычно не блокируют DTLS,
// потому что он нужен для видеозвонков (Zoom, Teams, WhatsApp).
//
// Формат DTLS Record:
//   ContentType(1) + Version(2) + Epoch(2) + SeqNum(6) + Length(2) + Data
//
// ====================================================================

const (
	// DTLS content types
	dtlsContentTypeApplicationData = 23 // Application Data

	// DTLS versions
	dtlsVersion12Major = 0xFE
	dtlsVersion12Minor = 0xFD // DTLS 1.2 = {0xFE, 0xFD}
)

// WebRTCObfuscator маскирует трафик под DTLS
type WebRTCObfuscator struct {
	epoch uint16
}

func (o *WebRTCObfuscator) Name() string {
	return "webrtc-mimic"
}

// Wrap оборачивает пакет в DTLS Application Data record
func (o *WebRTCObfuscator) Wrap(packet []byte) ([]byte, error) {
	// DTLS Record Header:
	// ContentType (1 byte): 23 = Application Data
	// Version (2 bytes): {0xFE, 0xFD} = DTLS 1.2
	// Epoch (2 bytes): counter
	// Sequence Number (6 bytes): packet counter
	// Length (2 bytes): length of data
	// Data: our packet

	headerSize := 1 + 2 + 2 + 6 + 2 // 13 bytes
	totalSize := headerSize + len(packet)

	buf := make([]byte, totalSize)
	offset := 0

	// Content Type
	buf[offset] = dtlsContentTypeApplicationData
	offset++

	// Version: DTLS 1.2
	buf[offset] = dtlsVersion12Major
	buf[offset+1] = dtlsVersion12Minor
	offset += 2

	// Epoch
	binary.BigEndian.PutUint16(buf[offset:], o.epoch)
	offset += 2

	// Sequence Number (6 bytes) - используем текущее время как основу
	// Это выглядит реалистично для DPI
	seqNum := uint64(time.Now().UnixNano()) & 0xFFFFFFFFFFFF
	buf[offset] = byte(seqNum >> 40)
	buf[offset+1] = byte(seqNum >> 32)
	buf[offset+2] = byte(seqNum >> 24)
	buf[offset+3] = byte(seqNum >> 16)
	buf[offset+4] = byte(seqNum >> 8)
	buf[offset+5] = byte(seqNum)
	offset += 6

	// Length
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(packet)))
	offset += 2

	// Data
	copy(buf[offset:], packet)

	return buf, nil
}

// Unwrap снимает DTLS-обёртку
func (o *WebRTCObfuscator) Unwrap(data []byte) ([]byte, error) {
	headerSize := 13 // DTLS record header

	if len(data) < headerSize {
		return nil, fmt.Errorf("DTLS record too short: %d bytes", len(data))
	}

	// Проверяем Content Type
	if data[0] != dtlsContentTypeApplicationData {
		return nil, fmt.Errorf("unexpected DTLS content type: %d", data[0])
	}

	// Проверяем версию
	if data[1] != dtlsVersion12Major || data[2] != dtlsVersion12Minor {
		return nil, fmt.Errorf("unexpected DTLS version: %d.%d", data[1], data[2])
	}

	// Читаем длину
	payloadLen := binary.BigEndian.Uint16(data[11:13])

	if int(payloadLen) > len(data)-headerSize {
		return nil, fmt.Errorf("DTLS payload length mismatch: declared %d, available %d",
			payloadLen, len(data)-headerSize)
	}

	// Возвращаем payload
	return data[headerSize : headerSize+int(payloadLen)], nil
}

// ====================================================================
// Raw Obfuscator - без обфускации
// ====================================================================

// RawObfuscator передаёт пакеты как есть
type RawObfuscator struct{}

func (o *RawObfuscator) Name() string {
	return "raw"
}

func (o *RawObfuscator) Wrap(packet []byte) ([]byte, error) {
	return packet, nil
}

func (o *RawObfuscator) Unwrap(data []byte) ([]byte, error) {
	return data, nil
}

// ====================================================================
// Утилиты QUIC Variable-Length Integer Encoding
// ====================================================================
//
// QUIC использует variable-length integer для кодирования чисел.
// Первые 2 бита определяют длину:
//   00 = 1 byte  (6-bit value, max 63)
//   01 = 2 bytes (14-bit value, max 16383)
//   10 = 4 bytes (30-bit value, max 1073741823)
//   11 = 8 bytes (62-bit value, max 4611686018427387903)
//
// ====================================================================

// encodeQUICVarint кодирует число в QUIC variable-length integer
func encodeQUICVarint(value uint64) []byte {
	if value <= 63 {
		// 1 byte: 00xxxxxx
		return []byte{byte(value)}
	}
	if value <= 16383 {
		// 2 bytes: 01xxxxxx xxxxxxxx
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(value)|0x4000)
		return buf
	}
	if value <= 1073741823 {
		// 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(value)|0x80000000)
		return buf
	}
	// 8 bytes: 11xxxxxx ...
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value|0xC000000000000000)
	return buf
}

// decodeQUICVarint декодирует QUIC variable-length integer
// Возвращает значение и количество прочитанных байт
func decodeQUICVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data for varint decoding")
	}

	prefix := data[0] >> 6

	switch prefix {
	case 0: // 1 byte
		return uint64(data[0] & 0x3F), 1, nil

	case 1: // 2 bytes
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("truncated 2-byte varint")
		}
		value := binary.BigEndian.Uint16(data[:2]) & 0x3FFF
		return uint64(value), 2, nil

	case 2: // 4 bytes
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("truncated 4-byte varint")
		}
		value := binary.BigEndian.Uint32(data[:4]) & 0x3FFFFFFF
		return uint64(value), 4, nil

	case 3: // 8 bytes
		if len(data) < 8 {
			return 0, 0, fmt.Errorf("truncated 8-byte varint")
		}
		value := binary.BigEndian.Uint64(data[:8]) & 0x3FFFFFFFFFFFFFFF
		return uint64(value), 8, nil
	}

	return 0, 0, fmt.Errorf("invalid varint prefix: %d", prefix)
}

// ====================================================================
// Packet Size Randomization
// ====================================================================
//
// DPI может анализировать распределение размеров пакетов.
// Настоящий QUIC имеет характерное распределение.
// Эти функции помогают имитировать его.
//
// ====================================================================

// QUICPacketSizeDistribution - типичные размеры QUIC Initial пакетов
// Источник: анализ реального QUIC-трафика Chrome → Google
var QUICPacketSizeDistribution = []struct {
	Min    int
	Max    int
	Weight int
}{
	{1200, 1280, 40}, // QUIC Initial (padded to >= 1200 bytes по RFC)
	{40, 100, 25},    // ACK-only packets
	{100, 500, 20},   // Small data transfers
	{500, 1200, 15},  // Medium data transfers
}

// GetTargetPaddedSize возвращает целевой размер пакета с padding,
// имитирующий распределение размеров настоящего QUIC-трафика
func GetTargetPaddedSize(payloadSize int, mtu int) int {
	// Для маленьких пакетов (< 100 bytes, типично для игр) -
	// добавляем padding до случайного размера из диапазона ACK-like
	if payloadSize < 100 {
		target := 40 + mrand.Intn(60) // 40-100 bytes
		if target < payloadSize {
			target = payloadSize
		}
		return target
	}

	// Для средних пакетов - padding до случайного среднего размера
	if payloadSize < 500 {
		target := 100 + mrand.Intn(400) // 100-500 bytes
		if target < payloadSize {
			target = payloadSize
		}
		return target
	}

	// Для больших пакетов - padding до MTU-like размера
	target := 1200 + mrand.Intn(80) // 1200-1280 bytes (QUIC Initial range)
	if target > mtu {
		target = mtu
	}
	if target < payloadSize {
		target = payloadSize
	}

	return target
}
