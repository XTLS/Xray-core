# 🎮 GameTunnel Core

UDP-транспорт для [xray-core](https://github.com/XTLS/Xray-core), оптимизированный для низкой задержки в онлайн-играх и стриминге.

## Особенности

- **UDP-транспорт** - минимальная задержка, без overhead TCP
- **QUIC-подобная структура пакетов** - естественный вид трафика
- **ChaCha20-Poly1305** - аутентифицированное шифрование
- **Curve25519** - обмен ключами с Perfect Forward Secrecy
- **PSK (Pre-Shared Key)** - дополнительный уровень аутентификации
- **Padding** - маскировка размеров пакетов
- **Совместимость с xray-core** - работает как обычный транспорт (tcp, ws, kcp, ...)

## Зачем нужен GameTunnel

Для сценариев, где важна **низкая задержка**:

- 🎮 Подключение к игровым серверам в другом регионе
- 🎬 Стриминг видео без буферизации
- 📡 Удалённый рабочий стол
- 🌐 Доступ к собственной инфраструктуре

В отличие от TCP-транспортов, GameTunnel работает поверх UDP и не страдает от head-of-line blocking.

## Установка (сервер)

```bash
# Скачиваем бинарник
curl -LO https://github.com/it2konst/gametunnel-core/releases/download/v0.1.1/xray-gametunnel-linux-amd64.tar.gz
tar xzf xray-gametunnel-linux-amd64.tar.gz
chmod +x xray-gametunnel
sudo cp xray-gametunnel /usr/local/bin/
```

## Конфигурация сервера

```bash
sudo nano /etc/xray-gametunnel.json
```

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
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
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
```

```bash
# Генерируем UUID
xray-gametunnel uuid
```

## Systemd сервис

```bash
sudo cat > /etc/systemd/system/xray-gametunnel.service << 'EOF'
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

```bash
./xray-gametunnel run -c client.json
curl --socks5-hostname 127.0.0.1:10808 https://ifconfig.me
```

### Вариант 2 - GUI (v2rayN)

См. [gametunnel-client](https://github.com/it2konst/gametunnel-client) - форк v2rayN с поддержкой GameTunnel в интерфейсе.

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
  Клиент                     Сервер
┌─────────┐   UDP/443    ┌─────────────┐
│  VLESS  │◄────────────►│    VLESS    │
│  + GT   │   ChaCha20   │    + GT     │
│transport│   Poly1305   │  transport  │
└─────────┘              └─────────────┘
     │                          │
   SOCKS5                    Freedom
   :10808                   (интернет)
```

**Handshake:** Curve25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305  
**Пакеты:** QUIC Long Header формат с padding и рандомизацией

## Полезные команды

```bash
# Статус сервера
sudo systemctl status xray-gametunnel

# Логи
sudo journalctl -u xray-gametunnel -f

# Мониторинг трафика
sudo tcpdump -i any udp port 443 -c 20 -n
```

## Лицензия

MPL-2.0 - наследуется от [xray-core](https://github.com/XTLS/Xray-core/blob/main/LICENSE).

## Связанные проекты

- [gametunnel-client](https://github.com/it2konst/gametunnel-client) - GUI-клиент (форк v2rayN)
