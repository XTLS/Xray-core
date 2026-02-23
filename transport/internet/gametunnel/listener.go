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
)

// ====================================================================
// Listener - серверная сторона транспорта GameTunnel
// ====================================================================
//
// Listener слушает UDP-порт, принимает входящие пакеты,
// маршрутизирует их через Hub и предоставляет xray-core
// интерфейс net.Listener для приёма новых соединений.
//
// Жизненный цикл:
//   1. ListenGameTunnel() создаёт UDP-сокет и Hub
//   2. receiveLoop() читает пакеты из UDP-сокета
//   3. Каждый пакет маршрутизируется через Hub.RoutePacket()
//   4. Новые сессии передаются в addConn callback xray-core
//   5. Данные сессий расшифровываются и передаются выше
//   6. Close() останавливает всё
//
// ====================================================================

// Listener реализует internet.Listener для xray-core
type Listener struct {
	// config - конфигурация транспорта
	config *Config

	// conn - UDP-сокет
	conn *net.UDPConn

	// hub - менеджер сессий
	hub *Hub

	// addConn - callback от xray-core для передачи новых соединений
	addConn internet.ConnHandler

	// addr - адрес, на котором слушаем
	addr net.Addr

	// done - сигнал завершения
	done *done.Instance

	// closed
	closed int32

	mu sync.Mutex
}

// GameTunnelConn - обёртка сессии, реализующая net.Conn
// Это то, что xray-core видит как "соединение" с клиентом
type GameTunnelConn struct {
	session *Session
	hub     *Hub
	config  *Config

	// readBuf - буфер для чтения (данные из session.inbound)
	readBuf    []byte
	readOffset int

	local  net.Addr
	remote net.Addr

	closed int32
	mu     sync.Mutex
}

// ListenGameTunnel создаёт и запускает Listener
// Это точка входа, которая регистрируется в xray-core
func ListenGameTunnel(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	// Получаем конфигурацию
	config := DefaultConfig()
	if streamSettings != nil {
		if c, ok := streamSettings.ProtocolSettings.(*Config); ok {
			config = c
		}
	}

	// Валидируем конфиг
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid GameTunnel config: %w", err)
	}

	// Создаём UDP-сокет
	udpAddr := &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP %s: %w", udpAddr.String(), err)
	}

	// Устанавливаем размер буфера сокета
	// Большой буфер важен для gaming-трафика при высокой нагрузке
	conn.SetReadBuffer(4 * 1024 * 1024)  // 4MB read buffer
	conn.SetWriteBuffer(4 * 1024 * 1024) // 4MB write buffer

	// Создаём Hub
	hub := NewHub(config, conn)

	listener := &Listener{
		config:  config,
		conn:    conn,
		hub:     hub,
		addConn: addConn,
		addr:    conn.LocalAddr(),
		done:    done.New(),
	}

	// Устанавливаем callback для новых сессий
	hub.onNewSession = func(session *Session) {
		// Создаём GameTunnelConn и передаём в xray-core
		gtConn := newGameTunnelConn(session, hub, config, listener.addr)
		addConn(gtConn)
	}

	// Запускаем Hub
	hub.Start()

	// Запускаем цикл приёма пакетов
	go listener.receiveLoop()

	return listener, nil
}

// receiveLoop - основной цикл приёма UDP-пакетов
func (l *Listener) receiveLoop() {
	buf := make([]byte, MaxPacketSize)

	for {
		if atomic.LoadInt32(&l.closed) == 1 {
			return
		}

		// Читаем пакет из UDP-сокета
		// Устанавливаем дедлайн чтобы периодически проверять closed
		l.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Таймаут - проверяем closed и читаем дальше
			}
			if atomic.LoadInt32(&l.closed) == 1 {
				return
			}
			// Логируем ошибку, но продолжаем работу
			continue
		}

		if n == 0 {
			continue
		}

		// Копируем данные (buf будет переиспользован)
		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Маршрутизируем пакет через Hub
		session, plaintext, err := l.hub.RoutePacket(packet, remoteAddr)
		if err != nil {
			// Невалидный пакет - игнорируем (может быть сканер или мусор)
			continue
		}

		// Если есть расшифрованные данные - передаём в сессию
		if session != nil && plaintext != nil && len(plaintext) > 0 {
			if err := session.PushInbound(plaintext); err != nil {
				// Буфер переполнен - пакет потерян
				// Для UDP это нормальное поведение
				continue
			}
		}
	}
}

// Addr возвращает адрес, на котором слушает listener
func (l *Listener) Addr() net.Addr {
	return l.addr
}

// Close останавливает listener
func (l *Listener) Close() error {
	if !atomic.CompareAndSwapInt32(&l.closed, 0, 1) {
		return nil
	}

	l.hub.Stop()
	l.conn.Close()
	l.done.Close()

	return nil
}

// ====================================================================
// GameTunnelConn - реализация net.Conn для xray-core
// ====================================================================

func newGameTunnelConn(session *Session, hub *Hub, config *Config, localAddr net.Addr) *GameTunnelConn {
	return &GameTunnelConn{
		session: session,
		hub:     hub,
		config:  config,
		local:   localAddr,
		remote:  session.RemoteAddr,
	}
}

// Read читает расшифрованные данные из сессии
// Реализует io.Reader для xray-core
func (c *GameTunnelConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Если в буфере есть остаток от прошлого чтения
	if c.readOffset < len(c.readBuf) {
		n := copy(b, c.readBuf[c.readOffset:])
		c.readOffset += n
		if c.readOffset >= len(c.readBuf) {
			c.readBuf = nil
			c.readOffset = 0
		}
		return n, nil
	}

	// Читаем новые данные из сессии
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.EOF
	}

	data, ok := <-c.session.inbound
	if !ok {
		return 0, io.EOF
	}

	n := copy(b, data)
	if n < len(data) {
		// Не всё влезло - сохраняем остаток
		c.readBuf = data
		c.readOffset = n
	}

	return n, nil
}

// Write отправляет данные клиенту через зашифрованный туннель
// Реализует io.Writer для xray-core
func (c *GameTunnelConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	// Разбиваем на чанки по максимальному размеру payload
	maxPayload := int(c.config.GetMaxPayloadSize())
	totalWritten := 0

	for totalWritten < len(b) {
		end := totalWritten + maxPayload
		if end > len(b) {
			end = len(b)
		}

		chunk := b[totalWritten:end]
		if err := c.hub.SendToSession(c.session, chunk); err != nil {
			return totalWritten, fmt.Errorf("send to session: %w", err)
		}

		totalWritten = end
	}

	return totalWritten, nil
}

// Close закрывает соединение
func (c *GameTunnelConn) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	// Отправляем Control Close клиенту
	pktNum := atomic.AddUint32(&c.session.SendPacketNum, 1)
	closePayload := []byte{0x00} // Close command
	closePkt := NewControlPacket(c.session.ID, pktNum, closePayload)
	data, err := closePkt.Marshal(c.config)
	if err == nil {
		c.hub.conn.WriteToUDP(data, c.session.RemoteAddr)
	}

	// Удаляем сессию
	c.hub.RemoveSession(c.session.ID)

	return nil
}

// LocalAddr возвращает локальный адрес
func (c *GameTunnelConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr возвращает адрес клиента
func (c *GameTunnelConn) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline устанавливает дедлайн для операций чтения/записи
func (c *GameTunnelConn) SetDeadline(t time.Time) error {
	return nil // UDP-based, дедлайны управляются через keep-alive
}

// SetReadDeadline устанавливает дедлайн для чтения
func (c *GameTunnelConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline устанавливает дедлайн для записи
func (c *GameTunnelConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func init() {
	// Регистрируем Listener в реестре транспортов xray-core
	internet.RegisterTransportListener(
		"gametunnel",
		func(ctx context.Context, address xnet.Address, port xnet.Port,
			streamSettings *internet.MemoryStreamConfig,
			addConn internet.ConnHandler) (internet.Listener, error) {
			return ListenGameTunnel(ctx, address, port, streamSettings, addConn)
		},
	)
}
