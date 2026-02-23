package gametunnel

import (
	"github.com/xtls/xray-core/transport/internet"
)

// ObfuscationMode определяет режим маскировки трафика
type ObfuscationMode int32

const (
	// ObfuscationMode_QUIC_MIMIC - маскировка под QUIC (основной режим)
	// Пакеты выглядят как валидный QUIC Long Header для DPI
	ObfuscationMode_QUIC_MIMIC ObfuscationMode = 0

	// ObfuscationMode_WEBRTC_MIMIC - маскировка под WebRTC DTLS
	// Хорошо подходит для мобильных сетей, выглядит как видеозвонок
	ObfuscationMode_WEBRTC_MIMIC ObfuscationMode = 1

	// ObfuscationMode_RAW - без обфускации, максимальная скорость
	// Для сетей без DPI, минимальный оверхед
	ObfuscationMode_RAW ObfuscationMode = 2
)

// PriorityMode определяет режим приоритизации трафика
type PriorityMode int32

const (
	// PriorityMode_NONE - без приоритизации, все пакеты равны
	PriorityMode_NONE PriorityMode = 0

	// PriorityMode_GAMING - приоритет маленьким частым пакетам (игры, VoIP)
	// Пакеты < 256 байт получают высокий приоритет
	PriorityMode_GAMING PriorityMode = 1

	// PriorityMode_STREAMING - приоритет потоковому трафику
	// Оптимизация под видео/аудио стриминг
	PriorityMode_STREAMING PriorityMode = 2
)

// Config - конфигурация транспорта GameTunnel
// Используется как на сервере (Listener), так и на клиенте (Dialer)
//
// Пример JSON-конфигурации для xray-core:
//
//	{
//	    "transport": {
//	        "type": "gametunnel",
//	        "gametunnelSettings": {
//	            "obfuscation": "quic",
//	            "priority": "gaming",
//	            "mtu": 1400,
//	            "maxStreams": 16,
//	            "connectionIdLength": 8,
//	            "enablePadding": true,
//	            "paddingRange": [40, 200],
//	            "handshakeTimeout": 5,
//	            "keepAliveInterval": 15,
//	            "key": "my-secret-preshared-key"
//	        }
//	    }
//	}
type Config struct {
	// Obfuscation - режим маскировки трафика
	// "quic" (по умолчанию), "webrtc", "raw"
	Obfuscation ObfuscationMode `json:"obfuscation"`

	// Priority - режим приоритизации пакетов
	// "none" (по умолчанию), "gaming", "streaming"
	Priority PriorityMode `json:"priority"`

	// MTU - максимальный размер пакета (без IP/UDP заголовков)
	// По умолчанию 1400 - безопасное значение для большинства сетей
	// Для мобильных сетей лучше 1280
	// Диапазон: 576-1500
	MTU uint32 `json:"mtu"`

	// MaxStreams - максимальное количество мультиплексированных потоков
	// в одном соединении. По умолчанию 16.
	// Каждый поток - независимый канал данных
	// Диапазон: 1-256
	MaxStreams uint32 `json:"maxStreams"`

	// ConnectionIdLength - длина Connection ID в байтах
	// Используется для идентификации сессии и маршрутизации пакетов
	// По умолчанию 8 байт (как в QUIC)
	// Диапазон: 4-20
	ConnectionIdLength uint32 `json:"connectionIdLength"`

	// EnablePadding - добавлять случайный padding к пакетам
	// Защищает от анализа по размеру пакетов
	// Увеличивает трафик, но затрудняет fingerprinting
	EnablePadding bool `json:"enablePadding"`

	// PaddingMinSize - минимальный размер padding в байтах
	// По умолчанию 40
	PaddingMinSize uint32 `json:"paddingMinSize"`

	// PaddingMaxSize - максимальный размер padding в байтах
	// По умолчанию 200
	PaddingMaxSize uint32 `json:"paddingMaxSize"`

	// HandshakeTimeout - таймаут хэндшейка в секундах
	// Если за это время хэндшейк не завершён - соединение сбрасывается
	// По умолчанию 5 секунд
	HandshakeTimeout uint32 `json:"handshakeTimeout"`

	// KeepAliveInterval - интервал keep-alive пакетов в секундах
	// Поддерживает NAT-маппинг и определяет обрыв соединения
	// По умолчанию 15 секунд
	// 0 - отключить keep-alive
	KeepAliveInterval uint32 `json:"keepAliveInterval"`

	// Key - pre-shared key для дополнительной аутентификации
	// Используется вместе с Curve25519 для двухфакторной защиты
	// Клиент и сервер должны иметь одинаковый ключ
	// Если пустой - используется только Curve25519
	Key string `json:"key"`
}

// DefaultConfig возвращает конфигурацию по умолчанию
// с оптимальными настройками для gaming-трафика
func DefaultConfig() *Config {
	return &Config{
		Obfuscation:        ObfuscationMode_QUIC_MIMIC,
		Priority:           PriorityMode_GAMING,
		MTU:                1400,
		MaxStreams:          16,
		ConnectionIdLength: 8,
		EnablePadding:      true,
		PaddingMinSize:     40,
		PaddingMaxSize:     200,
		HandshakeTimeout:   5,
		KeepAliveInterval:  15,
		Key:                "",
	}
}

// Validate проверяет корректность конфигурации
func (c *Config) Validate() error {
	if c.MTU < 576 || c.MTU > 1500 {
		c.MTU = 1400
	}
	if c.MaxStreams == 0 || c.MaxStreams > 256 {
		c.MaxStreams = 16
	}
	if c.ConnectionIdLength < 4 || c.ConnectionIdLength > 20 {
		c.ConnectionIdLength = 8
	}
	if c.PaddingMinSize > c.PaddingMaxSize {
		c.PaddingMinSize = 40
		c.PaddingMaxSize = 200
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5
	}
	return nil
}

// GetMaxPayloadSize возвращает максимальный размер полезной нагрузки
// с учётом заголовков GameTunnel и обфускации
func (c *Config) GetMaxPayloadSize() uint32 {
	// Заголовок GameTunnel: flags(1) + version(4) + connID(var) + pktNum(4) + payloadLen(2)
	headerSize := uint32(1 + 4 + c.ConnectionIdLength + 4 + 2)
	// Auth tag: Poly1305 = 16 байт
	authTagSize := uint32(16)
	// Максимальный padding (учитываем worst case)
	maxPaddingOverhead := uint32(0)
	if c.EnablePadding {
		maxPaddingOverhead = 2 // 2 байта на длину padding
	}

	return c.MTU - headerSize - authTagSize - maxPaddingOverhead
}

// ObfuscationModeFromString парсит строковое значение режима обфускации
func ObfuscationModeFromString(s string) ObfuscationMode {
	switch s {
	case "quic", "quic-mimic", "QUIC":
		return ObfuscationMode_QUIC_MIMIC
	case "webrtc", "webrtc-mimic", "WEBRTC":
		return ObfuscationMode_WEBRTC_MIMIC
	case "raw", "none", "RAW":
		return ObfuscationMode_RAW
	default:
		return ObfuscationMode_QUIC_MIMIC
	}
}

// PriorityModeFromString парсит строковое значение режима приоритизации
func PriorityModeFromString(s string) PriorityMode {
	switch s {
	case "gaming", "game", "GAMING":
		return PriorityMode_GAMING
	case "streaming", "stream", "STREAMING":
		return PriorityMode_STREAMING
	case "none", "off", "NONE":
		return PriorityMode_NONE
	default:
		return PriorityMode_NONE
	}
}

func init() {
	// Регистрируем конфиг GameTunnel в реестре xray-core
	internet.RegisterProtocolConfigCreator(
		"gametunnel",
		func() interface{} {
			return DefaultConfig()
		},
	)
}
