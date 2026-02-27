# gametunnel-core

Форк [Xray-core](https://github.com/XTLS/Xray-core) с дополнительным UDP-транспортом **GameTunnel**.

GameTunnel - это транспортный слой на базе UDP с поддержкой имитации QUIC и DTLS (WebRTC), низкой задержкой и приоритизацией пакетов. Подходит для сценариев, где важна минимальная латентность и стабильность соединения при высоком пинге или потерях.

## Основные характеристики транспорта GameTunnel

- UDP-based транспорт
- Имитация QUIC Long Header / DTLS для совместимости с сетевыми стеками
- Шифрование ChaCha20-Poly1305 + обмен ключами X25519
- Опциональный pre-shared key
- Приоритизация пакетов (поддержка игрового / реал-тайм трафика)
- Поддержка connection migration
- Мультиплексирование потоков
- Адаптивный padding

## Установка и сборка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/it2konst/gametunnel-core.git
   cd gametunnel-core
   ```

2. Соберите бинарник:
   ```bash
   go build -o xray ./main
   ```

   Или используйте теги для оптимизации:
   ```bash
   go build -o xray -trimpath -ldflags "-s -w" ./main
   ```

## Пример конфигурации (gametunnel)

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
          "priority": "gaming",
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
          "obfuscation": "quic",
          "priority": "gaming"
        }
      }
    }
  ]
}
```

## Подробная документация по транспорту

→ [transport/internet/gametunnel/README.md](./transport/internet/gametunnel/README.md)  
(техническое описание протокола, формат пакета, хэндшейк, структура кода)

## Лицензия

MPL 2.0 (как и оригинальный Xray-core)
