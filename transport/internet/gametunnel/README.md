# GameTunnel - UDP Transport for Xray-core

**Обфускационный UDP-транспорт для xray-core, оптимизированный под онлайн-игры.**

GameTunnel маскирует VPN-трафик под легитимный QUIC или WebRTC (DTLS), что делает его крайне сложным для обнаружения и блокировки DPI-системами.

## Особенности

- **UDP-based** - минимальная задержка, идеально для онлайн-игр
- **QUIC-мимикрия** - трафик неотличим от настоящего QUIC для DPI
- **WebRTC-мимикрия** - альтернативная маскировка под DTLS (видеозвонки)
- **ChaCha20-Poly1305** - быстрое AEAD-шифрование на любом железе
- **X25519 Key Exchange** - безопасный обмен ключами за 1-RTT
- **Pre-Shared Key** - опциональная двухфакторная защита
- **Приоритизация трафика** - игровые пакеты обрабатываются первыми
- **Connection Migration** - бесшовное переключение WiFi/Mobile
- **Мультиплексирование** - несколько потоков в одном соединении
- **Padding** - маскировка размеров пакетов

## Архитектура

```
┌─────────────────────────────────────────────────────┐
│                    Xray-core                         │
│  ┌──────────┐                      ┌──────────────┐ │
│  │  VLESS    │                      │   Routing    │ │
│  │ Protocol  │                      │   Engine     │ │
│  └────┬─────┘                      └──────┬───────┘ │
│       │                                    │         │
│  ┌────┴────────────────────────────────────┴───────┐ │
│  │            GameTunnel Transport                  │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │ │
│  │  │ Priority │ │  Crypto  │ │   Obfuscation    │ │ │
│  │  │  Queue   │ │ ChaCha20 │ │  QUIC / WebRTC   │ │ │
│  │  └──────────┘ └──────────┘ └──────────────────┘ │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │ │
│  │  │   Hub    │ │  Packet  │ │   Session Mgr    │ │ │
│  │  │ (Server) │ │  Format  │ │  + KeepAlive     │ │ │
│  │  └──────────┘ └──────────┘ └──────────────────┘ │ │
│  └──────────────────┬──────────────────────────────┘ │
│                     │                                 │
└─────────────────────┼─────────────────────────────────┘
                      │ UDP Socket
                 ┌────┴────┐
                 │ Network │
                 └─────────┘
```

## Структура файлов

```
transport/internet/gametunnel/
├── config.go          # Конфигурация транспорта
├── config.proto       # Protobuf-определение конфига
├── packet.go          # Формат пакета (QUIC-совместимый)
├── crypto.go          # X25519 + ChaCha20-Poly1305
├── obfs.go            # Обфускация (QUIC/WebRTC/Raw)
├── priority.go        # Приоритизация трафика
├── hub.go             # Менеджер сессий (сервер)
├── listener.go        # Серверная сторона (xray-core Listener)
├── dialer.go          # Клиентская сторона (xray-core Dialer)
├── gametunnel_test.go # Тесты + бенчмарки
└── README.md          # Документация
```

## Формат пакета

```
GameTunnel Packet (маскируется под QUIC Long Header):
+--------+----------+--------+-----------+----------+---------+----------+
| Flags  | Version  | ConnID | Pkt Num   | Payload  | Padding | Auth Tag |
| 1 byte | 4 bytes  | 8 bytes| 4 bytes   | variable | variable| 16 bytes |
+--------+----------+--------+-----------+----------+---------+----------+
     │
     └─► Bit 7-6: Form+Fixed (= QUIC Long Header)
         Bit 5-4: Packet Type (Data/Handshake/KeepAlive/Control)
         Bit 3:   Padding flag
         Bit 2-0: Random (anti-fingerprint)
```

## Хэндшейк

```
Client                                 Server
  │                                      │
  │  Client Hello (QUIC Initial)         │
  │  [PublicKey + Timestamp + Random]     │
  ├─────────────────────────────────────►│
  │                                      │
  │  Server Hello (QUIC Initial)         │
  │  [PublicKey + Timestamp + Random]     │
  │◄─────────────────────────────────────┤
  │                                      │
  │  ══ Shared Secret (X25519 ECDH) ══   │
  │  ══ Session Keys (HKDF-SHA256)  ══   │
  │                                      │
  │  Encrypted Data ◄──────────────────► │
  │  (ChaCha20-Poly1305)                 │
```

## Интеграция в Xray-core

### 1. Клонируем форк

```bash
git clone https://github.com/YOUR_USERNAME/gametunnel-core.git
cd gametunnel-core
```

### 2. Добавляем GameTunnel в TransportProtocol enum

В файле `transport/internet/config.proto`:

```protobuf
enum TransportProtocol {
  TCP = 0;
  UDP = 1;
  MKCP = 2;
  WebSocket = 3;
  HTTP = 4;
  HTTPUpgrade = 6;
  SplitHTTP = 7;
  GameTunnel = 8;  // ← Добавляем
}
```

### 3. Регистрируем импорт

В файле `main/distro/all/all.go` добавляем:

```go
import (
    _ "github.com/xtls/xray-core/transport/internet/gametunnel"
)
```

### 4. Собираем

```bash
go build -o xray ./main
```

## Пример конфигурации

### Сервер (xray-core config.json)

```json
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "your-uuid-here",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "priority": "gaming",
          "mtu": 1400,
          "key": "your-preshared-key",
          "enable_padding": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
```

### Клиент (xray-core config.json)

```json
{
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "your-server.com",
            "port": 443,
            "users": [
              {
                "id": "your-uuid-here",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "priority": "gaming",
          "key": "your-preshared-key"
        }
      }
    }
  ]
}
```

## Тестирование

```bash
cd transport/internet/gametunnel
go test -v ./...
go test -bench=. -benchmem ./...
```

## Лицензия

MPL-2.0 (совместимо с xray-core)

## Дорожная карта

- [x] Ядро протокола (packet, crypto)
- [x] Обфускация (QUIC, WebRTC, Raw)
- [x] Приоритизация трафика
- [x] Диалер и Листенер для xray-core
- [x] Unit-тесты и бенчмарки
- [ ] Интеграция с protobuf (code generation)
- [ ] Форк 3x-ui с UI для GameTunnel
- [ ] Сборка кастомного xray-core
- [ ] Установочный скрипт
- [ ] Клиентская сборка v2rayN
- [ ] Ротация ключей шифрования
- [ ] FEC (Forward Error Correction) для потерянных пакетов
- [ ] Congestion control
