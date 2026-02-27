# GameTunnel Transport

UDP-based транспортный слой для Xray-core с поддержкой имитации QUIC Long Header и DTLS (WebRTC).  
Предназначен для сценариев, где требуется низкая задержка, стабильность при потерях пакетов и высоком пинге.

## Основные характеристики

- UDP-транспорт с минимальными накладными расходами
- Совместимость с форматом QUIC Long Header и DTLS для работы с существующими сетевыми стеками
- Шифрование ChaCha20-Poly1305 + обмен ключами X25519
- Поддержка опционального pre-shared key
- Приоритизация пакетов для реального времени и высокоприоритетного трафика
- Поддержка connection migration
- Мультиплексирование потоков
- Адаптивный padding для изменения размеров пакетов

## Архитектура (упрощённо)

```
Клиент/Сервер
    │
    ▼
UDP-пакеты → GameTunnel Header → Шифрование (ChaCha20-Poly1305) → QUIC/DTLS-совместимый формат
    │
    ▼
Сеть (с возможными потерями и высокой задержкой)
    │
    ▼
Приём → Дешифрование → Восстановление приоритета → Передача в Xray
```

## Структура файлов

```
transport/internet/gametunnel/
├── config.go          // Конфигурация транспорта
├── config.proto       // Protobuf-определения
├── conn.go            // Управление соединениями
├── header.go          // Формат заголовка пакета
├── packet.go          // Работа с пакетами
├── server.go          // Серверная часть
├── client.go          // Клиентская часть
└── README.md          // Эта документация
```

## Формат пакета

Пакет состоит из:

1. GameTunnel Header (переменной длины)
2. Зашифрованные данные (ChaCha20-Poly1305)

Header совместим с форматом QUIC Long Header / DTLS для повышения совместимости с сетевыми устройствами.

## Хэндшейк

- Обмен ключами через X25519
- Опциональная проверка pre-shared key
- Установка параметров соединения (MTU, приоритет и т.д.)

## Интеграция в Xray-core

1. Добавить в `transport/internet/config.proto`:

```proto
GameTunnel = 8;
```

2. Импортировать в `main/distro/all/all.go`:

```go
_ "github.com/it2konst/gametunnel-core/transport/internet/gametunnel"
```

(или в твоём форке — путь к твоему репозиторию)

## Пример конфигурации

**Серверная сторона** (inbound):

```json
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "mtu": 1400,
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

**Клиентская сторона** (outbound):

```json
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "example.com",
            "port": 443,
            "users": [
              {
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic"
        }
      }
    }
  ]
}
