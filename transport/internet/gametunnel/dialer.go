package gametunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ====================================================================
// Dialer - клиентская сторона транспорта GameTunnel
// ====================================================================
//
// Dialer устанавливает UDP-соединение с сервером GameTunnel:
//   1. Создаёт UDP-сокет
//   2. Генерирует пару ключей Curve25519
//   3. Отправляет Client Hello (публичный ключ в QUIC-обёртке)
//   4. Получает Server Hello (публичный ключ сервера)
//   5. Вычисляет общий секрет и деривирует ключи
//   6. Возвращает GameTunnelClientConn, готовый к работе
//
// После хэндшейка:
//   - xray-core пишет данные → шифруются → отправляются по UDP
//   - UDP-пакеты от сервера → расшифровываются → читаются xray-core
//
// ====================================================================

// GameTunnelClientConn - клиентское соединение с сервером
type GameTunnelClientConn struct {
	// conn - UDP-сокет к серверу
	conn *net.UDPConn

	// config - конфигурация транспорта
	config *Config

	// session - клиентская сессия
	session *ClientSession

	// done - сигнал завершения
	done *done.Instance

	// readBuf - буфер для чтения
	readBuf    []byte
	readOffset int

	closed int32
	mu     sync.Mutex
}

// ClientSession - сессия на стороне клиента
type ClientSession struct {
	// ConnectionID - идентификатор сессии
	ConnectionID []byte

	// Keys - ключи шифрования
	Keys *SessionKeys

	// SendPacketNum - счётчик исходящих пакетов
	SendPacketNum uint32

	// RecvPacketNum - счётчик входящих пакетов
	RecvPacketNum uint32

	// inbound - канал входящих расшифрованных данных
	inbound chan []byte

	// serverAddr - адрес сервера
	serverAddr *net.UDPAddr
}

// Dial устанавливает соединение с сервером GameTunnel
// Это точка входа, регистрируемая в xray-core
func Dial(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	// Получаем конфигурацию
	config := DefaultConfig()
	if streamSettings != nil {
		if c, ok := streamSettings.ProtocolSettings.(*Config); ok {
			config = c
		}
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid GameTunnel config: %w", err)
	}

	// Получаем адрес сервера
	serverAddr := &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	}

	// Создаём UDP-сокет
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP %s: %w", serverAddr.String(), err)
	}

	// Устанавливаем буферы сокета
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)

	// Выполняем хэндшейк
	clientSession, err := performHandshake(conn, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	// Создаём клиентское соединение
	gtConn := &GameTunnelClientConn{
		conn:    conn,
		config:  config,
		session: clientSession,
		done:    done.New(),
	}

	// Запускаем горутину приёма пакетов
	go gtConn.receiveLoop()

	return gtConn, nil
}

// performHandshake выполняет хэндшейк с сервером
func performHandshake(conn *net.UDPConn, config *Config) (*ClientSession, error) {
	// 1. Генерируем пару ключей
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	// 2. Генерируем Connection ID
	connID, err := GenerateConnectionID(int(config.ConnectionIdLength))
	if err != nil {
		return nil, fmt.Errorf("generate connection ID: %w", err)
	}

	// 3. Формируем Client Hello
	handshakePayload := NewHandshakePayload(
		keyPair.PublicKey,
		uint64(time.Now().Unix()),
	)

	clientHello := NewHandshakePacket(connID, 0, handshakePayload.Marshal())
	clientHelloData, err := clientHello.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal client hello: %w", err)
	}

	// 4. Отправляем Client Hello
	_, err = conn.Write(clientHelloData)
	if err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	// 5. Ждём Server Hello
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.HandshakeTimeout) * time.Second))

	buf := make([]byte, MaxPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("receive server hello: %w (timeout=%ds)",
			err, config.HandshakeTimeout)
	}

	// Сбрасываем дедлайн
	conn.SetReadDeadline(time.Time{})

	// 6. Парсим Server Hello
	serverHelloPkt, err := Unmarshal(buf[:n], int(config.ConnectionIdLength))
	if err != nil {
		return nil, fmt.Errorf("unmarshal server hello: %w", err)
	}

	if serverHelloPkt.Type != PacketType_HANDSHAKE {
		return nil, fmt.Errorf("expected handshake packet, got type %d", serverHelloPkt.Type)
	}

	serverHandshake, err := UnmarshalHandshake(serverHelloPkt.Payload)
	if err != nil {
		return nil, fmt.Errorf("unmarshal server handshake: %w", err)
	}

	// 7. Вычисляем общий секрет
	sharedSecret, err := ComputeSharedSecret(keyPair.PrivateKey, serverHandshake.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	// 8. Деривируем ключи (isClient=true)
	sessionKeys, err := DeriveSessionKeys(sharedSecret, config.Key, true)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	// 9. Создаём клиентскую сессию
	clientSession := &ClientSession{
		ConnectionID:  connID,
		Keys:          sessionKeys,
		SendPacketNum: 1, // 0 использован для Client Hello
		inbound:       make(chan []byte, 256),
	}

	return clientSession, nil
}

// receiveLoop - цикл приёма пакетов от сервера
func (c *GameTunnelClientConn) receiveLoop() {
	buf := make([]byte, MaxPacketSize)

	for {
		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}

		// Устанавливаем дедлайн для периодической проверки closed
		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := c.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Проверяем, нужно ли отправить keep-alive
				c.maybeKeepAlive()
				continue
			}
			if atomic.LoadInt32(&c.closed) == 1 {
				return
			}
			continue
		}

		if n == 0 {
			continue
		}

		// Копируем данные
		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Обрабатываем пакет
		c.handlePacket(packet)
	}
}

// handlePacket обрабатывает входящий пакет от сервера
func (c *GameTunnelClientConn) handlePacket(data []byte) {
	if !IsQUICLike(data[0]) {
		return
	}

	pktType, _, err := DecodeFlags(data[0])
	if err != nil {
		return
	}

	switch pktType {
	case PacketType_DATA:
		c.handleDataPacket(data)

	case PacketType_KEEPALIVE:
		// Сервер ответил на keep-alive - ничего не делаем
		return

	case PacketType_CONTROL:
		c.handleControlPacket(data)
	}
}

// handleDataPacket расшифровывает и передаёт данные
func (c *GameTunnelClientConn) handleDataPacket(data []byte) {
	pkt, err := Unmarshal(data, int(c.config.ConnectionIdLength))
	if err != nil {
		return
	}

	// Additional data - заголовок пакета
	connIDLen := int(c.config.ConnectionIdLength)
	adLen := FlagsSize + VersionSize + connIDLen
	if len(data) < adLen {
		return
	}
	additionalData := data[:adLen]

	// Расшифровываем
	plaintext, err := c.session.Keys.Decrypt(pkt.Payload, pkt.PacketNumber, additionalData)
	if err != nil {
		return
	}

	// Обновляем счётчик
	atomic.StoreUint32(&c.session.RecvPacketNum, pkt.PacketNumber)

	// Передаём данные в канал чтения
	select {
	case c.session.inbound <- plaintext:
	default:
		// Буфер полон - дропаем (нормально для UDP)
	}
}

// handleControlPacket обрабатывает управляющий пакет
func (c *GameTunnelClientConn) handleControlPacket(data []byte) {
	pkt, err := Unmarshal(data, int(c.config.ConnectionIdLength))
	if err != nil {
		return
	}

	if len(pkt.Payload) == 0 {
		return
	}

	switch pkt.Payload[0] {
	case 0x00: // Close - сервер закрыл соединение
		c.Close()

	case 0x01: // Ping - отвечаем Pong
		pktNum := atomic.AddUint32(&c.session.SendPacketNum, 1)
		pong := NewControlPacket(c.session.ConnectionID, pktNum, []byte{0x02})
		response, err := pong.Marshal(c.config)
		if err == nil {
			c.conn.Write(response)
		}
	}
}

// maybeKeepAlive отправляет keep-alive если нужно
func (c *GameTunnelClientConn) maybeKeepAlive() {
	if c.config.KeepAliveInterval == 0 {
		return
	}

	pktNum := atomic.AddUint32(&c.session.SendPacketNum, 1)
	keepAlive := NewKeepAlivePacket(c.session.ConnectionID, pktNum)

	data, err := keepAlive.Marshal(c.config)
	if err != nil {
		return
	}

	c.conn.Write(data)
}

// Read читает расшифрованные данные от сервера
func (c *GameTunnelClientConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Проверяем остаток в буфере
	if c.readOffset < len(c.readBuf) {
		n := copy(b, c.readBuf[c.readOffset:])
		c.readOffset += n
		if c.readOffset >= len(c.readBuf) {
			c.readBuf = nil
			c.readOffset = 0
		}
		return n, nil
	}

	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.EOF
	}

	data, ok := <-c.session.inbound
	if !ok {
		return 0, io.EOF
	}

	n := copy(b, data)
	if n < len(data) {
		c.readBuf = data
		c.readOffset = n
	}

	return n, nil
}

// Write отправляет данные серверу через зашифрованный туннель
func (c *GameTunnelClientConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	maxPayload := int(c.config.GetMaxPayloadSize())
	totalWritten := 0

	for totalWritten < len(b) {
		end := totalWritten + maxPayload
		if end > len(b) {
			end = len(b)
		}

		chunk := b[totalWritten:end]
		pktNum := atomic.AddUint32(&c.session.SendPacketNum, 1)

		// Формируем additional data
		connIDLen := int(c.config.ConnectionIdLength)
		tempPkt := NewDataPacket(c.session.ConnectionID, pktNum, nil, c.config.EnablePadding)
		tempFlags := tempPkt.EncodeFlags()
		ad := make([]byte, FlagsSize+VersionSize+connIDLen)
		ad[0] = tempFlags
		ad[1] = byte(FakeQUICVersion >> 24)
		ad[2] = byte(FakeQUICVersion >> 16)
		ad[3] = byte(FakeQUICVersion >> 8)
		ad[4] = byte(FakeQUICVersion)
		copy(ad[FlagsSize+VersionSize:], c.session.ConnectionID)

		// Шифруем
		ciphertext, err := c.session.Keys.Encrypt(chunk, pktNum, ad)
		if err != nil {
			return totalWritten, fmt.Errorf("encrypt: %w", err)
		}

		// Собираем пакет
		pkt := NewDataPacket(c.session.ConnectionID, pktNum, ciphertext, c.config.EnablePadding)
		data, err := pkt.Marshal(c.config)
		if err != nil {
			return totalWritten, fmt.Errorf("marshal: %w", err)
		}

		// Отправляем
		_, err = c.conn.Write(data)
		if err != nil {
			return totalWritten, fmt.Errorf("send: %w", err)
		}

		totalWritten = end
	}

	return totalWritten, nil
}

// Close закрывает клиентское соединение
func (c *GameTunnelClientConn) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	// Отправляем Control Close серверу
	pktNum := atomic.AddUint32(&c.session.SendPacketNum, 1)
	closePkt := NewControlPacket(c.session.ConnectionID, pktNum, []byte{0x00})
	data, err := closePkt.Marshal(c.config)
	if err == nil {
		c.conn.Write(data)
	}

	// Закрываем каналы и сокет
	close(c.session.inbound)
	c.conn.Close()
	c.done.Close()

	return nil
}

// LocalAddr возвращает локальный адрес
func (c *GameTunnelClientConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr возвращает адрес сервера
func (c *GameTunnelClientConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline - заглушка для net.Conn
func (c *GameTunnelClientConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline - заглушка для net.Conn
func (c *GameTunnelClientConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline - заглушка для net.Conn
func (c *GameTunnelClientConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func init() {
	// Регистрируем Dialer в реестре транспортов xray-core
	internet.RegisterTransportDialer(
		"gametunnel",
		func(ctx context.Context, dest xnet.Destination,
			streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
			return Dial(ctx, dest, streamSettings)
		},
	)
}
