# 🎮 GameTunnel Core

UDP-транспорт для [xray-core](https://github.com/XTLS/Xray-core), оптимизированный для низкой задержки в онлайн-играх и стриминге.

## Особенности

- **UDP-транспорт** - минимальная задержка, без overhead TCP
- **QUIC-подобная структура пакетов** - естественный вид трафика
- **ChaCha20-Poly1305** - аутентифицированное шифрование
- **Curve25519** - обмен ключами с Perfect Forward Secrecy
- **PSK (Pre-Shared Key)** - дополнительный уровень аутентификации
- **Padding** - маскировка размеров пакетов
- **Цепочки серверов** - маршрутизация через несколько узлов
- **Совместимость с xray-core** - работает как обычный транспорт (tcp, ws, kcp, ...)

## Зачем нужен GameTunnel

Для сценариев, где важна **низкая задержка и стабильность**:

- 🎮 Подключение к игровым серверам в другом регионе
- 🎬 Стриминг видео без буферизации
- 📡 Удалённый рабочий стол
- 🌐 Доступ к собственной инфраструктуре

В отличие от TCP-транспортов, GameTunnel работает поверх UDP и не страдает от head-of-line blocking.

## Установка (сервер)

```bash
# Скачиваем бинарник
curl -LO https://github.com/it2konst/gametunnel-core/releases/latest/download/xray-gametunnel-linux-amd64.tar.gz
tar xzf xray-gametunnel-linux-amd64.tar.gz
chmod +x xray-gametunnel
sudo cp xray-gametunnel /usr/local/bin/

# Генерируем UUID
xray-gametunnel uuid
```

Поддерживаемые ОС: Ubuntu 22.04+, Debian 12+.

## Конфигурация сервера

```bash
sudo nano /etc/xray-gametunnel.json
```

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "YOUR_UUID", "flow": "" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "priority": "gaming",
          "mtu": 1400,
          "enablePadding": true,
          "keepAliveInterval": 15,
          "key": "YOUR_SECRET_KEY"
        }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
```

> **Важно:** `key` должен совпадать на сервере и клиенте. `flow` должен быть пустым.

## Systemd сервис

```bash
sudo tee /etc/systemd/system/xray-gametunnel.service > /dev/null << 'EOF'
[Unit]
Description=Xray GameTunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/xray-gametunnel run -c /etc/xray-gametunnel.json
Restart=on-failure
RestartSec=3
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now xray-gametunnel
```

## Клиент

### Вариант 1 - Терминал

```json
{
  "inbounds": [
    { "port": 10808, "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "SERVER_IP",
            "port": 443,
            "users": [{ "id": "YOUR_UUID", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": {
        "network": "gametunnel",
        "gametunnelSettings": {
          "obfuscation": "quic",
          "priority": "gaming",
          "mtu": 1400,
          "enablePadding": true,
          "keepAliveInterval": 15,
          "key": "YOUR_SECRET_KEY"
        }
      }
    }
  ]
}
```

```bash
./xray-gametunnel run -c client.json
curl --socks5-hostname 127.0.0.1:10808 https://ifconfig.me
```

### Вариант 2 - GUI (v2rayN)

См. [gametunnel-client](https://github.com/it2konst/gametunnel-client) - форк v2rayN с поддержкой GameTunnel в интерфейсе.

При настройке в v2rayN:

- **Транспорт:** gametunnel
- **Flow:** оставить пустым
- **Path:** ваш ключ шифрования (key)

## Цепочки серверов

GameTunnel поддерживает маршрутизацию через несколько узлов:

```
Клиент → GameTunnel(UDP) → Сервер A → VLESS(TCP) → Сервер B → интернет
```

На промежуточном сервере A укажите outbound на сервер B:

```json
{
  "outbounds": [
    {
      "tag": "next-hop",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "SERVER_B_IP",
            "port": 8443,
            "users": [{ "id": "UUID_B", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": { "network": "tcp" }
    }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["gt-in"], "outboundTag": "next-hop" }
    ]
  }
}
```

## Сборка из исходников

```bash
git clone https://github.com/it2konst/gametunnel-core.git
cd gametunnel-core
CGO_ENABLED=0 go build -o xray-gametunnel -trimpath -ldflags="-s -w" -v ./main
./xray-gametunnel version
```

Требуется Go 1.22+.

## Архитектура

```
  Клиент                    Сервер
┌─────────┐   UDP/443    ┌───────────┐
│  VLESS  │◄────────────►│   VLESS   │
│  + GT   │   ChaCha20   │   + GT    │
│transport│   Poly1305   │ transport │
└─────────┘              └───────────┘
     │                         │
  SOCKS5                    Freedom
  :10808                   (интернет)
```

**Handshake:** Curve25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305
**Пакеты:** QUIC Long Header формат с padding и рандомизацией
**Payload:** чанкинг до 1200 байт для совместимости с MTU

## Параметры gametunnelSettings

| Параметр           | По умолчанию | Описание                                     |
| ------------------ | ------------ | -------------------------------------------- |
| obfuscation        | `quic`       | Режим маскировки: `quic`, `webrtc`, `raw`    |
| priority           | `gaming`     | Приоритизация: `gaming`, `streaming`, `none` |
| mtu                | `1400`       | Максимальный размер UDP-пакета               |
| enablePadding      | `true`       | Добавлять случайный padding                  |
| keepAliveInterval  | `15`         | Интервал keep-alive (секунды)                |
| key                | `""`         | Pre-shared key для аутентификации            |
| maxStreams         | `16`         | Макс. мультиплексированных потоков           |
| connectionIdLength | `8`          | Длина Connection ID (байт)                   |

## Полезные команды

```bash
# Статус сервера
sudo systemctl status xray-gametunnel

# Логи
sudo journalctl -u xray-gametunnel -f

# Мониторинг трафика
sudo tcpdump -i any udp port 443 -c 20 -n

# Проверка конфигурации
xray-gametunnel run -test -c /etc/xray-gametunnel.json
```

## Лицензия

MPL-2.0 - наследуется от [xray-core](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
