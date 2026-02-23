package gametunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ====================================================================
// Hub - менеджер сессий GameTunnel
// ====================================================================
//
// Hub управляет всеми активными сессиями на сервере.
// Каждое уникальное соединение (Connection ID) - отдельная сессия.
//
// Обязанности:
//   - Маршрутизация входящих пакетов по Connection ID
//   - Создание новых сессий при хэндшейке
//   - Удаление мёртвых сессий по таймауту
//   - Мультиплексирование потоков внутри сессии
//   - Отслеживание статистики (трафик, пинг)
//
// ====================================================================

// SessionState - состояние сессии
type SessionState int32

const (
	// SessionState_HANDSHAKE - ожидание завершения хэндшейка
	SessionState_HANDSHAKE SessionState = 0

	// SessionState_ACTIVE - сессия активна, данные передаются
	SessionState_ACTIVE SessionState = 1

	// SessionState_CLOSING - сессия закрывается
	SessionState_CLOSING SessionState = 2

	// SessionState_CLOSED - сессия закрыта
	SessionState_CLOSED SessionState = 3
)

// Session - одно соединение с клиентом
type Session struct {
	// ID - Connection ID сессии
	ID []byte

	// State - текущее состояние сессии
	State SessionState

	// RemoteAddr - адрес клиента (IP:Port)
	RemoteAddr *net.UDPAddr

	// Keys - ключи шифрования для этой сессии
	Keys *SessionKeys

	// LocalKeyPair - локальная пара ключей для хэндшейка
	LocalKeyPair *KeyPair

	// SendPacketNum - счётчик исходящих пакетов (atomic)
	SendPacketNum uint32

	// RecvPacketNum - максимальный принятый номер пакета
	RecvPacketNum uint32

	// CreatedAt - время создания сессии
	CreatedAt time.Time

	// LastActiveAt - время последней активности
	LastActiveAt time.Time

	// BytesSent - отправлено байт
	BytesSent uint64

	// BytesRecv - получено байт
	BytesRecv uint64

	// PacketsSent - отправлено пакетов
	PacketsSent uint64

	// PacketsRecv - получено пакетов
	PacketsRecv uint64

	// Streams - активные мультиплексированные потоки
	Streams map[uint16]*Stream

	// inbound - канал для входящих расшифрованных данных
	// xray-core читает из этого канала
	inbound chan []byte

	// closed - флаг закрытия
	closed int32

	mu sync.RWMutex
}

// Stream - один мультиплексированный поток внутри сессии
type Stream struct {
	// ID - идентификатор потока (0-65535)
	ID uint16

	// Priority - приоритет потока
	// 0 = высший (игры), 1 = средний (веб), 2 = низкий (загрузки)
	Priority uint8

	// BytesSent - отправлено байт в этом потоке
	BytesSent uint64

	// BytesRecv - получено байт в этом потоке
	BytesRecv uint64

	// Active - активен ли поток
	Active bool
}

// Hub - менеджер всех сессий
type Hub struct {
	// sessions - карта Connection ID → Session
	// Ключ - hex-строка от Connection ID для быстрого поиска
	sessions map[string]*Session

	// config - конфигурация транспорта
	config *Config

	// conn - UDP-сокет для отправки/получения
	conn *net.UDPConn

	// onNewSession - callback при создании новой сессии
	// Вызывается после успешного хэндшейка
	onNewSession func(*Session)

	// cleanupInterval - интервал очистки мёртвых сессий
	cleanupInterval time.Duration

	// sessionTimeout - таймаут неактивной сессии
	sessionTimeout time.Duration

	// stats
	totalSessions   uint64
	activeSessions  int32

	mu     sync.RWMutex
	closed int32
}

// NewHub создаёт новый менеджер сессий
func NewHub(config *Config, conn *net.UDPConn) *Hub {
	h := &Hub{
		sessions:        make(map[string]*Session),
		config:          config,
		conn:            conn,
		cleanupInterval: 30 * time.Second,
		sessionTimeout:  time.Duration(config.KeepAliveInterval*3) * time.Second,
	}

	// Если keepalive отключён, ставим таймаут 5 минут
	if config.KeepAliveInterval == 0 {
		h.sessionTimeout = 5 * time.Minute
	}

	return h
}

// Start запускает фоновые горутины хаба
func (h *Hub) Start() {
	// Горутина очистки мёртвых сессий
	go h.cleanupLoop()
}

// Stop останавливает хаб и закрывает все сессии
func (h *Hub) Stop() {
	if !atomic.CompareAndSwapInt32(&h.closed, 0, 1) {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for id, session := range h.sessions {
		session.Close()
		delete(h.sessions, id)
	}
}

// RoutePacket направляет входящий пакет в соответствующую сессию
// Возвращает сессию и расшифрованный payload
// Если сессия не найдена и это Handshake - создаёт новую
func (h *Hub) RoutePacket(data []byte, remoteAddr *net.UDPAddr) (*Session, []byte, error) {
	if len(data) < MinPacketSize {
		return nil, nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	// Быстрая проверка: это GameTunnel пакет?
	if !IsQUICLike(data[0]) {
		return nil, nil, fmt.Errorf("not a GameTunnel packet: invalid flags 0x%02x", data[0])
	}

	// Извлекаем Connection ID из заголовка
	connIDLen := int(h.config.ConnectionIdLength)
	connIDOffset := FlagsSize + VersionSize // после flags + version
	if len(data) < connIDOffset+connIDLen {
		return nil, nil, fmt.Errorf("packet too short for connection ID")
	}

	connID := data[connIDOffset : connIDOffset+connIDLen]
	connIDKey := fmt.Sprintf("%x", connID)

	// Декодируем тип пакета
	pktType, _, err := DecodeFlags(data[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode flags: %w", err)
	}

	// Ищем существующую сессию
	h.mu.RLock()
	session, exists := h.sessions[connIDKey]
	h.mu.RUnlock()

	// Если сессия не найдена
	if !exists {
		if pktType == PacketType_HANDSHAKE {
			// Новый клиент - начинаем хэндшейк
			return h.handleNewHandshake(data, connID, remoteAddr)
		}
		return nil, nil, fmt.Errorf("unknown connection ID: %s", connIDKey)
	}

	// Обновляем адрес клиента (поддержка connection migration)
	session.mu.Lock()
	if session.RemoteAddr.String() != remoteAddr.String() {
		// Клиент сменил IP (переключение WiFi/Mobile)
		session.RemoteAddr = remoteAddr
	}
	session.LastActiveAt = time.Now()
	session.mu.Unlock()

	// Обработка по типу пакета
	switch pktType {
	case PacketType_HANDSHAKE:
		// Повторный хэндшейк - клиент мог потерять ответ
		return h.handleExistingHandshake(session, data)

	case PacketType_DATA:
		return h.handleDataPacket(session, data)

	case PacketType_KEEPALIVE:
		return h.handleKeepAlive(session, data)

	case PacketType_CONTROL:
		return h.handleControlPacket(session, data)

	default:
		return nil, nil, fmt.Errorf("unknown packet type: %d", pktType)
	}
}

// handleNewHandshake обрабатывает хэндшейк от нового клиента
func (h *Hub) handleNewHandshake(data []byte, connID []byte, remoteAddr *net.UDPAddr) (*Session, []byte, error) {
	// Парсим пакет
	pkt, err := Unmarshal(data, int(h.config.ConnectionIdLength))
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal handshake: %w", err)
	}

	// Парсим payload хэндшейка (содержит публичный ключ клиента)
	clientHandshake, err := UnmarshalHandshake(pkt.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal handshake payload: %w", err)
	}

	// Генерируем серверную пару ключей
	serverKeyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate server keypair: %w", err)
	}

	// Вычисляем общий секрет
	sharedSecret, err := ComputeSharedSecret(serverKeyPair.PrivateKey, clientHandshake.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("compute shared secret: %w", err)
	}

	// Деривируем ключи сессии (isClient=false, мы сервер)
	sessionKeys, err := DeriveSessionKeys(sharedSecret, h.config.Key, false)
	if err != nil {
		return nil, nil, fmt.Errorf("derive session keys: %w", err)
	}

	// Создаём сессию
	session := &Session{
		ID:           make([]byte, len(connID)),
		State:        SessionState_ACTIVE,
		RemoteAddr:   remoteAddr,
		Keys:         sessionKeys,
		LocalKeyPair: serverKeyPair,
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
		Streams:      make(map[uint16]*Stream),
		inbound:      make(chan []byte, 256),
	}
	copy(session.ID, connID)

	// Создаём поток по умолчанию (stream 0)
	session.Streams[0] = &Stream{
		ID:       0,
		Priority: 0,
		Active:   true,
	}

	// Регистрируем сессию
	connIDKey := fmt.Sprintf("%x", connID)
	h.mu.Lock()
	h.sessions[connIDKey] = session
	atomic.AddInt32(&h.activeSessions, 1)
	atomic.AddUint64(&h.totalSessions, 1)
	h.mu.Unlock()

	// Отправляем Server Hello
	err = h.sendServerHello(session, serverKeyPair)
	if err != nil {
		return nil, nil, fmt.Errorf("send server hello: %w", err)
	}

	// Вызываем callback
	if h.onNewSession != nil {
		h.onNewSession(session)
	}

	return session, nil, nil
}

// handleExistingHandshake обрабатывает повторный хэндшейк
func (h *Hub) handleExistingHandshake(session *Session, data []byte) (*Session, []byte, error) {
	// Клиент мог не получить Server Hello - отправляем повторно
	if session.LocalKeyPair != nil {
		err := h.sendServerHello(session, session.LocalKeyPair)
		if err != nil {
			return nil, nil, fmt.Errorf("resend server hello: %w", err)
		}
	}
	return session, nil, nil
}

// handleDataPacket обрабатывает пакет с данными
func (h *Hub) handleDataPacket(session *Session, data []byte) (*Session, []byte, error) {
	if session.State != SessionState_ACTIVE {
		return nil, nil, fmt.Errorf("session not active: state=%d", session.State)
	}

	// Парсим пакет
	pkt, err := Unmarshal(data, int(h.config.ConnectionIdLength))
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal data packet: %w", err)
	}

	// Формируем additional data для AEAD (заголовок до payload)
	connIDLen := int(h.config.ConnectionIdLength)
	adLen := FlagsSize + VersionSize + connIDLen
	additionalData := data[:adLen]

	// Расшифровываем payload
	plaintext, err := session.Keys.Decrypt(pkt.Payload, pkt.PacketNumber, additionalData)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt: %w", err)
	}

	// Обновляем статистику
	session.mu.Lock()
	session.RecvPacketNum = pkt.PacketNumber
	session.PacketsRecv++
	session.BytesRecv += uint64(len(plaintext))
	session.mu.Unlock()

	return session, plaintext, nil
}

// handleKeepAlive обрабатывает keep-alive пакет
func (h *Hub) handleKeepAlive(session *Session, data []byte) (*Session, []byte, error) {
	// Keep-alive просто обновляет LastActiveAt (уже сделано выше)
	// Отправляем keep-alive ответ
	pktNum := atomic.AddUint32(&session.SendPacketNum, 1)
	keepAlive := NewKeepAlivePacket(session.ID, pktNum)

	response, err := keepAlive.Marshal(h.config)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal keepalive response: %w", err)
	}

	_, err = h.conn.WriteToUDP(response, session.RemoteAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("send keepalive response: %w", err)
	}

	return session, nil, nil
}

// handleControlPacket обрабатывает управляющий пакет
func (h *Hub) handleControlPacket(session *Session, data []byte) (*Session, []byte, error) {
	pkt, err := Unmarshal(data, int(h.config.ConnectionIdLength))
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal control packet: %w", err)
	}

	// Простейший контрольный протокол:
	// Первый байт payload = код команды
	if len(pkt.Payload) == 0 {
		return session, nil, nil
	}

	switch pkt.Payload[0] {
	case 0x00: // Close - закрытие сессии
		h.RemoveSession(session.ID)
		return session, nil, nil

	case 0x01: // Ping - запрос пинга
		// Отвечаем Pong
		pktNum := atomic.AddUint32(&session.SendPacketNum, 1)
		pongPayload := []byte{0x02} // Pong
		pong := NewControlPacket(session.ID, pktNum, pongPayload)
		response, err := pong.Marshal(h.config)
		if err == nil {
			h.conn.WriteToUDP(response, session.RemoteAddr)
		}
		return session, nil, nil

	case 0x02: // Pong - ответ на пинг
		// Можно замерить RTT
		return session, nil, nil
	}

	return session, nil, nil
}

// sendServerHello отправляет Server Hello клиенту
func (h *Hub) sendServerHello(session *Session, keyPair *KeyPair) error {
	// Формируем handshake payload с нашим публичным ключом
	handshakePayload := NewHandshakePayload(
		keyPair.PublicKey,
		uint64(time.Now().Unix()),
	)

	pktNum := atomic.AddUint32(&session.SendPacketNum, 1)
	pkt := NewHandshakePacket(session.ID, pktNum, handshakePayload.Marshal())

	data, err := pkt.Marshal(h.config)
	if err != nil {
		return fmt.Errorf("marshal server hello: %w", err)
	}

	_, err = h.conn.WriteToUDP(data, session.RemoteAddr)
	if err != nil {
		return fmt.Errorf("send server hello: %w", err)
	}

	return nil
}

// SendToSession отправляет зашифрованные данные клиенту
func (h *Hub) SendToSession(session *Session, payload []byte) error {
	if session.State != SessionState_ACTIVE {
		return fmt.Errorf("session not active")
	}

	pktNum := atomic.AddUint32(&session.SendPacketNum, 1)

	// Формируем additional data (заголовок)
	tempPkt := NewDataPacket(session.ID, pktNum, nil, h.config.EnablePadding)
	tempFlags := tempPkt.EncodeFlags()
	connIDLen := int(h.config.ConnectionIdLength)
	ad := make([]byte, FlagsSize+VersionSize+connIDLen)
	ad[0] = tempFlags
	ad[1] = byte(FakeQUICVersion >> 24)
	ad[2] = byte(FakeQUICVersion >> 16)
	ad[3] = byte(FakeQUICVersion >> 8)
	ad[4] = byte(FakeQUICVersion)
	copy(ad[FlagsSize+VersionSize:], session.ID)

	// Шифруем payload
	ciphertext, err := session.Keys.Encrypt(payload, pktNum, ad)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Собираем пакет
	pkt := NewDataPacket(session.ID, pktNum, ciphertext, h.config.EnablePadding)
	data, err := pkt.Marshal(h.config)
	if err != nil {
		return fmt.Errorf("marshal data packet: %w", err)
	}

	// Отправляем
	_, err = h.conn.WriteToUDP(data, session.RemoteAddr)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}

	// Статистика
	session.mu.Lock()
	session.PacketsSent++
	session.BytesSent += uint64(len(payload))
	session.mu.Unlock()

	return nil
}

// GetSession возвращает сессию по Connection ID
func (h *Hub) GetSession(connID []byte) *Session {
	key := fmt.Sprintf("%x", connID)
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[key]
}

// RemoveSession удаляет сессию
func (h *Hub) RemoveSession(connID []byte) {
	key := fmt.Sprintf("%x", connID)
	h.mu.Lock()
	if session, exists := h.sessions[key]; exists {
		session.Close()
		delete(h.sessions, key)
		atomic.AddInt32(&h.activeSessions, -1)
	}
	h.mu.Unlock()
}

// GetActiveSessions возвращает количество активных сессий
func (h *Hub) GetActiveSessions() int32 {
	return atomic.LoadInt32(&h.activeSessions)
}

// GetTotalSessions возвращает общее количество сессий за всё время
func (h *Hub) GetTotalSessions() uint64 {
	return atomic.LoadUint64(&h.totalSessions)
}

// cleanupLoop периодически удаляет мёртвые сессии
func (h *Hub) cleanupLoop() {
	ticker := time.NewTicker(h.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt32(&h.closed) == 1 {
			return
		}

		now := time.Now()
		var toRemove []string

		h.mu.RLock()
		for key, session := range h.sessions {
			session.mu.RLock()
			if now.Sub(session.LastActiveAt) > h.sessionTimeout {
				toRemove = append(toRemove, key)
			}
			session.mu.RUnlock()
		}
		h.mu.RUnlock()

		// Удаляем мёртвые сессии
		for _, key := range toRemove {
			h.mu.Lock()
			if session, exists := h.sessions[key]; exists {
				session.Close()
				delete(h.sessions, key)
				atomic.AddInt32(&h.activeSessions, -1)
			}
			h.mu.Unlock()
		}
	}
}

// Close закрывает сессию
func (s *Session) Close() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	s.mu.Lock()
	s.State = SessionState_CLOSED
	s.mu.Unlock()

	close(s.inbound)
}

// Read читает расшифрованные данные из сессии
// Реализует интерфейс, совместимый с xray-core
func (s *Session) Read(buf []byte) (int, error) {
	data, ok := <-s.inbound
	if !ok {
		return 0, fmt.Errorf("session closed")
	}

	n := copy(buf, data)
	return n, nil
}

// PushInbound добавляет расшифрованные данные в очередь чтения
func (s *Session) PushInbound(data []byte) error {
	if atomic.LoadInt32(&s.closed) == 1 {
		return fmt.Errorf("session closed")
	}

	select {
	case s.inbound <- data:
		return nil
	default:
		return fmt.Errorf("inbound buffer full, dropping packet")
	}
}

// GetStats возвращает статистику сессии
func (s *Session) GetStats() SessionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return SessionStats{
		ConnectionID: fmt.Sprintf("%x", s.ID),
		RemoteAddr:   s.RemoteAddr.String(),
		State:        s.State,
		BytesSent:    s.BytesSent,
		BytesRecv:    s.BytesRecv,
		PacketsSent:  s.PacketsSent,
		PacketsRecv:  s.PacketsRecv,
		CreatedAt:    s.CreatedAt,
		LastActiveAt: s.LastActiveAt,
		ActiveStreams: len(s.Streams),
	}
}

// SessionStats - статистика сессии для панели управления
type SessionStats struct {
	ConnectionID string       `json:"connectionId"`
	RemoteAddr   string       `json:"remoteAddr"`
	State        SessionState `json:"state"`
	BytesSent    uint64       `json:"bytesSent"`
	BytesRecv    uint64       `json:"bytesRecv"`
	PacketsSent  uint64       `json:"packetsSent"`
	PacketsRecv  uint64       `json:"packetsRecv"`
	CreatedAt    time.Time    `json:"createdAt"`
	LastActiveAt time.Time    `json:"lastActiveAt"`
	ActiveStreams int         `json:"activeStreams"`
}
