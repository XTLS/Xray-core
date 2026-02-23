package gametunnel

import (
	"bytes"
	"testing"
	"time"
)

// ====================================================================
// Тесты пакетов
// ====================================================================

func TestPacketMarshalUnmarshal(t *testing.T) {
	config := DefaultConfig()

	// Генерируем Connection ID
	connID, err := GenerateConnectionID(int(config.ConnectionIdLength))
	if err != nil {
		t.Fatalf("GenerateConnectionID: %v", err)
	}

	// Создаём Data-пакет
	payload := []byte("Hello, GameTunnel!")
	pkt := NewDataPacket(connID, 42, payload, false)

	// Сериализуем
	data, err := pkt.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Проверяем QUIC-совместимость первого байта
	if !IsQUICLike(data[0]) {
		t.Errorf("First byte 0x%02x is not QUIC-like", data[0])
	}

	// Десериализуем
	pkt2, err := Unmarshal(data, int(config.ConnectionIdLength))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Проверяем поля
	if pkt2.Type != PacketType_DATA {
		t.Errorf("Type: got %d, want %d", pkt2.Type, PacketType_DATA)
	}
	if !bytes.Equal(pkt2.ConnectionID, connID) {
		t.Errorf("ConnectionID mismatch")
	}
	if pkt2.PacketNumber != 42 {
		t.Errorf("PacketNumber: got %d, want 42", pkt2.PacketNumber)
	}
	if !bytes.Equal(pkt2.Payload, payload) {
		t.Errorf("Payload: got %q, want %q", pkt2.Payload, payload)
	}
}

func TestPacketWithPadding(t *testing.T) {
	config := DefaultConfig()
	config.EnablePadding = true
	config.PaddingMinSize = 10
	config.PaddingMaxSize = 50

	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))
	payload := []byte("test")
	pkt := NewDataPacket(connID, 1, payload, true)

	data, err := pkt.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal with padding: %v", err)
	}

	// С padding пакет должен быть больше, чем без
	pktNoPad := NewDataPacket(connID, 1, payload, false)
	dataNoPad, _ := pktNoPad.Marshal(config)

	if len(data) <= len(dataNoPad) {
		t.Errorf("Padded packet (%d bytes) should be larger than unpadded (%d bytes)",
			len(data), len(dataNoPad))
	}

	// Десериализация должна работать (padding игнорируется)
	pkt2, err := Unmarshal(data, int(config.ConnectionIdLength))
	if err != nil {
		t.Fatalf("Unmarshal padded: %v", err)
	}
	if !bytes.Equal(pkt2.Payload, payload) {
		t.Errorf("Payload mismatch after padded unmarshal")
	}
}

func TestPacketTypes(t *testing.T) {
	config := DefaultConfig()
	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))

	tests := []struct {
		name    string
		packet  *Packet
		pktType PacketType
	}{
		{"Data", NewDataPacket(connID, 1, []byte("data"), false), PacketType_DATA},
		{"Handshake", NewHandshakePacket(connID, 2, []byte("hello")), PacketType_HANDSHAKE},
		{"KeepAlive", NewKeepAlivePacket(connID, 3), PacketType_KEEPALIVE},
		{"Control", NewControlPacket(connID, 4, []byte{0x00}), PacketType_CONTROL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal(config)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			pkt, err := Unmarshal(data, int(config.ConnectionIdLength))
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if pkt.Type != tt.pktType {
				t.Errorf("Type: got %d, want %d", pkt.Type, tt.pktType)
			}
		})
	}
}

func TestDecodeFlags(t *testing.T) {
	// Валидные флаги (Form=1, Fixed=1)
	flags := byte(0xC0) // 11000000
	pktType, hasPadding, err := DecodeFlags(flags)
	if err != nil {
		t.Fatalf("DecodeFlags: %v", err)
	}
	if pktType != PacketType_DATA {
		t.Errorf("Type: got %d, want DATA", pktType)
	}
	if hasPadding {
		t.Errorf("HasPadding should be false")
	}

	// С padding и типом Handshake
	flags = byte(0xD8) // 11011000 (Form=1, Fixed=1, Type=01, Padding=1)
	pktType, hasPadding, err = DecodeFlags(flags)
	if err != nil {
		t.Fatalf("DecodeFlags: %v", err)
	}
	if pktType != PacketType_HANDSHAKE {
		t.Errorf("Type: got %d, want HANDSHAKE", pktType)
	}
	if !hasPadding {
		t.Errorf("HasPadding should be true")
	}

	// Невалидные флаги (Form=0)
	flags = byte(0x00)
	_, _, err = DecodeFlags(flags)
	if err == nil {
		t.Error("DecodeFlags should fail with Form bit = 0")
	}
}

func TestConnectionIDGeneration(t *testing.T) {
	// Нормальная генерация
	id, err := GenerateConnectionID(8)
	if err != nil {
		t.Fatalf("GenerateConnectionID: %v", err)
	}
	if len(id) != 8 {
		t.Errorf("ConnectionID length: got %d, want 8", len(id))
	}

	// Два ID должны быть разными
	id2, _ := GenerateConnectionID(8)
	if bytes.Equal(id, id2) {
		t.Error("Two generated ConnectionIDs should not be equal")
	}

	// Слишком короткий
	_, err = GenerateConnectionID(3)
	if err == nil {
		t.Error("GenerateConnectionID(3) should fail")
	}

	// Слишком длинный
	_, err = GenerateConnectionID(21)
	if err == nil {
		t.Error("GenerateConnectionID(21) should fail")
	}
}

// ====================================================================
// Тесты криптографии
// ====================================================================

func TestKeyPairGeneration(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Ключи не должны быть нулевыми
	allZero := true
	for _, b := range kp.PublicKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Public key is all zeros")
	}

	// Два KeyPair должны быть разными
	kp2, _ := GenerateKeyPair()
	if kp.PublicKey == kp2.PublicKey {
		t.Error("Two generated key pairs should have different public keys")
	}
}

func TestECDHKeyExchange(t *testing.T) {
	// Генерируем ключи для клиента и сервера
	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Client GenerateKeyPair: %v", err)
	}

	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Server GenerateKeyPair: %v", err)
	}

	// Вычисляем общий секрет с обеих сторон
	clientSecret, err := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)
	if err != nil {
		t.Fatalf("Client ComputeSharedSecret: %v", err)
	}

	serverSecret, err := ComputeSharedSecret(serverKP.PrivateKey, clientKP.PublicKey)
	if err != nil {
		t.Fatalf("Server ComputeSharedSecret: %v", err)
	}

	// Общие секреты должны совпадать (свойство ECDH)
	if clientSecret != serverSecret {
		t.Error("ECDH shared secrets do not match!")
	}
}

func TestSessionKeyDerivation(t *testing.T) {
	// Генерируем общий секрет
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)

	// Деривируем ключи для клиента и сервера
	clientKeys, err := DeriveSessionKeys(sharedSecret, "test-psk", true)
	if err != nil {
		t.Fatalf("Client DeriveSessionKeys: %v", err)
	}

	serverKeys, err := DeriveSessionKeys(sharedSecret, "test-psk", false)
	if err != nil {
		t.Fatalf("Server DeriveSessionKeys: %v", err)
	}

	// Client.SendKey должен совпадать с Server.RecvKey
	if clientKeys.SendKey != serverKeys.RecvKey {
		t.Error("Client.SendKey != Server.RecvKey")
	}

	// Client.RecvKey должен совпадать с Server.SendKey
	if clientKeys.RecvKey != serverKeys.SendKey {
		t.Error("Client.RecvKey != Server.SendKey")
	}

	// SendKey и RecvKey не должны совпадать (разные направления)
	if clientKeys.SendKey == clientKeys.RecvKey {
		t.Error("SendKey and RecvKey should be different")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Полный цикл: генерация ключей → шифрование → расшифровка
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)

	clientKeys, _ := DeriveSessionKeys(sharedSecret, "psk123", true)
	serverKeys, _ := DeriveSessionKeys(sharedSecret, "psk123", false)

	// Клиент шифрует сообщение
	plaintext := []byte("Game packet: player_pos x=100 y=200 z=50")
	additionalData := []byte("header-data")
	packetNum := uint32(1)

	ciphertext, err := clientKeys.Encrypt(plaintext, packetNum, additionalData)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Шифротекст должен отличаться от открытого текста
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext equals plaintext - encryption failed")
	}

	// Шифротекст должен быть длиннее (+ 16 байт Poly1305 tag)
	if len(ciphertext) != len(plaintext)+AuthTagSize {
		t.Errorf("Ciphertext length: got %d, want %d",
			len(ciphertext), len(plaintext)+AuthTagSize)
	}

	// Сервер расшифровывает
	decrypted, err := serverKeys.Decrypt(ciphertext, packetNum, additionalData)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)

	clientKeys, _ := DeriveSessionKeys(sharedSecret, "correct-psk", true)

	// Деривируем ключи с ДРУГИМ PSK
	wrongKeys, _ := DeriveSessionKeys(sharedSecret, "wrong-psk", false)

	plaintext := []byte("secret data")
	ciphertext, _ := clientKeys.Encrypt(plaintext, 1, nil)

	// Расшифровка с неправильным ключом должна провалиться
	_, err := wrongKeys.Decrypt(ciphertext, 1, nil)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestEncryptDecryptWrongPacketNumber(t *testing.T) {
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)

	clientKeys, _ := DeriveSessionKeys(sharedSecret, "", true)
	serverKeys, _ := DeriveSessionKeys(sharedSecret, "", false)

	plaintext := []byte("test")
	ciphertext, _ := clientKeys.Encrypt(plaintext, 1, nil)

	// Расшифровка с другим номером пакета должна провалиться
	// (nonce будет другой → аутентификация не пройдёт)
	_, err := serverKeys.Decrypt(ciphertext, 2, nil)
	if err == nil {
		t.Error("Decrypt with wrong packet number should fail")
	}
}

func TestHandshakePayload(t *testing.T) {
	kp, _ := GenerateKeyPair()
	timestamp := uint64(time.Now().Unix())

	original := NewHandshakePayload(kp.PublicKey, timestamp)

	// Сериализуем
	data := original.Marshal()

	// Десериализуем
	restored, err := UnmarshalHandshake(data)
	if err != nil {
		t.Fatalf("UnmarshalHandshake: %v", err)
	}

	if original.PublicKey != restored.PublicKey {
		t.Error("PublicKey mismatch")
	}
	if original.Timestamp != restored.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", restored.Timestamp, original.Timestamp)
	}
}

// ====================================================================
// Тесты обфускации
// ====================================================================

func TestQUICObfuscatorWrapUnwrap(t *testing.T) {
	config := DefaultConfig()
	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))

	// Создаём пакет
	pkt := NewDataPacket(connID, 1, []byte("game data"), false)
	original, _ := pkt.Marshal(config)

	// Оборачиваем в QUIC
	obfs := &QUICObfuscator{}
	wrapped, err := obfs.Wrap(original)
	if err != nil {
		t.Fatalf("QUIC Wrap: %v", err)
	}

	// Обёрнутый пакет должен быть больше (добавлены SCID, lengths)
	if len(wrapped) <= len(original) {
		t.Errorf("Wrapped (%d) should be larger than original (%d)",
			len(wrapped), len(original))
	}

	// Первый байт должен быть QUIC-like
	if !IsQUICLike(wrapped[0]) {
		t.Errorf("Wrapped packet first byte 0x%02x is not QUIC-like", wrapped[0])
	}

	// Разворачиваем
	unwrapped, err := obfs.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("QUIC Unwrap: %v", err)
	}

	// Должны получить оригинал обратно
	// Версия может отличаться (QUIC obfuscator использует рандомную),
	// поэтому сравниваем только connID и payload часть
	unwrappedPkt, err := Unmarshal(unwrapped, int(config.ConnectionIdLength))
	if err != nil {
		t.Fatalf("Unmarshal unwrapped: %v", err)
	}

	if !bytes.Equal(unwrappedPkt.ConnectionID, connID) {
		t.Error("ConnectionID mismatch after wrap/unwrap")
	}
	if !bytes.Equal(unwrappedPkt.Payload, []byte("game data")) {
		t.Errorf("Payload mismatch: got %q", unwrappedPkt.Payload)
	}
}

func TestWebRTCObfuscatorWrapUnwrap(t *testing.T) {
	config := DefaultConfig()
	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))

	pkt := NewDataPacket(connID, 1, []byte("voip data"), false)
	original, _ := pkt.Marshal(config)

	obfs := &WebRTCObfuscator{}
	wrapped, err := obfs.Wrap(original)
	if err != nil {
		t.Fatalf("WebRTC Wrap: %v", err)
	}

	// Проверяем DTLS заголовок
	if wrapped[0] != dtlsContentTypeApplicationData {
		t.Errorf("Content type: got %d, want %d", wrapped[0], dtlsContentTypeApplicationData)
	}
	if wrapped[1] != dtlsVersion12Major || wrapped[2] != dtlsVersion12Minor {
		t.Errorf("DTLS version: got 0x%02x%02x, want 0xFEFD", wrapped[1], wrapped[2])
	}

	// Разворачиваем
	unwrapped, err := obfs.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("WebRTC Unwrap: %v", err)
	}

	if !bytes.Equal(unwrapped, original) {
		t.Error("WebRTC wrap/unwrap: data mismatch")
	}
}

func TestRawObfuscator(t *testing.T) {
	original := []byte("raw data test")

	obfs := &RawObfuscator{}
	wrapped, _ := obfs.Wrap(original)

	if !bytes.Equal(wrapped, original) {
		t.Error("Raw Wrap should return data as-is")
	}

	unwrapped, _ := obfs.Unwrap(wrapped)
	if !bytes.Equal(unwrapped, original) {
		t.Error("Raw Unwrap should return data as-is")
	}
}

func TestNewObfuscator(t *testing.T) {
	quic := NewObfuscator(ObfuscationMode_QUIC_MIMIC)
	if quic.Name() != "quic-mimic" {
		t.Errorf("QUIC obfuscator name: got %s", quic.Name())
	}

	webrtc := NewObfuscator(ObfuscationMode_WEBRTC_MIMIC)
	if webrtc.Name() != "webrtc-mimic" {
		t.Errorf("WebRTC obfuscator name: got %s", webrtc.Name())
	}

	raw := NewObfuscator(ObfuscationMode_RAW)
	if raw.Name() != "raw" {
		t.Errorf("Raw obfuscator name: got %s", raw.Name())
	}
}

// ====================================================================
// Тесты QUIC Variable-Length Integer
// ====================================================================

func TestQUICVarintEncoding(t *testing.T) {
	tests := []struct {
		value       uint64
		expectedLen int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1073741823, 4},
		{1073741824, 8},
	}

	for _, tt := range tests {
		encoded := encodeQUICVarint(tt.value)
		if len(encoded) != tt.expectedLen {
			t.Errorf("encodeQUICVarint(%d): got %d bytes, want %d",
				tt.value, len(encoded), tt.expectedLen)
		}

		decoded, n, err := decodeQUICVarint(encoded)
		if err != nil {
			t.Errorf("decodeQUICVarint(%d): %v", tt.value, err)
			continue
		}
		if n != tt.expectedLen {
			t.Errorf("decodeQUICVarint(%d): read %d bytes, want %d",
				tt.value, n, tt.expectedLen)
		}
		if decoded != tt.value {
			t.Errorf("decodeQUICVarint: got %d, want %d", decoded, tt.value)
		}
	}
}

// ====================================================================
// Тесты приоритизации
// ====================================================================

func TestPriorityClassification(t *testing.T) {
	pq := NewPriorityQueue(PriorityMode_GAMING)

	// Маленький пакет (игровой) → High
	smallPacket := make([]byte, 100)
	priority := pq.classify(smallPacket)
	if priority != PriorityHigh {
		t.Errorf("Small packet: got priority %d, want High(0)", priority)
	}

	// Средний пакет (веб) → Medium
	mediumPacket := make([]byte, 500)
	priority = pq.classify(mediumPacket)
	if priority != PriorityMedium {
		t.Errorf("Medium packet: got priority %d, want Medium(1)", priority)
	}

	// Большой пакет (загрузка) → Low
	largePacket := make([]byte, 1200)
	priority = pq.classify(largePacket)
	if priority != PriorityLow {
		t.Errorf("Large packet: got priority %d, want Low(2)", priority)
	}
}

func TestPriorityQueueOrdering(t *testing.T) {
	pq := NewPriorityQueue(PriorityMode_GAMING)

	// Добавляем пакеты разных приоритетов
	pq.EnqueueWithPriority([]byte("low"), PriorityLow, nil)
	pq.EnqueueWithPriority([]byte("medium"), PriorityMedium, nil)
	pq.EnqueueWithPriority([]byte("high"), PriorityHigh, nil)

	// Должны выйти в порядке приоритета: High → Medium → Low
	pkt := pq.Dequeue()
	if pkt == nil || string(pkt.Data) != "high" {
		t.Errorf("First dequeue: expected 'high', got %v", pkt)
	}

	pkt = pq.Dequeue()
	if pkt == nil || string(pkt.Data) != "medium" {
		t.Errorf("Second dequeue: expected 'medium', got %v", pkt)
	}

	pkt = pq.Dequeue()
	if pkt == nil || string(pkt.Data) != "low" {
		t.Errorf("Third dequeue: expected 'low', got %v", pkt)
	}

	// Очередь пуста
	pkt = pq.Dequeue()
	if pkt != nil {
		t.Error("Expected nil from empty queue")
	}
}

func TestPriorityQueueStats(t *testing.T) {
	pq := NewPriorityQueue(PriorityMode_GAMING)

	pq.EnqueueWithPriority([]byte("a"), PriorityHigh, nil)
	pq.EnqueueWithPriority([]byte("b"), PriorityHigh, nil)
	pq.EnqueueWithPriority([]byte("c"), PriorityMedium, nil)
	pq.EnqueueWithPriority([]byte("d"), PriorityLow, nil)

	stats := pq.GetStats()
	if stats.HighEnqueued != 2 {
		t.Errorf("HighEnqueued: got %d, want 2", stats.HighEnqueued)
	}
	if stats.MediumEnqueued != 1 {
		t.Errorf("MediumEnqueued: got %d, want 1", stats.MediumEnqueued)
	}
	if stats.LowEnqueued != 1 {
		t.Errorf("LowEnqueued: got %d, want 1", stats.LowEnqueued)
	}
	if stats.TotalEnqueued != 4 {
		t.Errorf("TotalEnqueued: got %d, want 4", stats.TotalEnqueued)
	}
}

// ====================================================================
// Тесты конфигурации
// ====================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MTU != 1400 {
		t.Errorf("MTU: got %d, want 1400", config.MTU)
	}
	if config.Obfuscation != ObfuscationMode_QUIC_MIMIC {
		t.Errorf("Obfuscation: got %d, want QUIC_MIMIC", config.Obfuscation)
	}
	if config.Priority != PriorityMode_GAMING {
		t.Errorf("Priority: got %d, want GAMING", config.Priority)
	}
	if config.MaxStreams != 16 {
		t.Errorf("MaxStreams: got %d, want 16", config.MaxStreams)
	}
}

func TestConfigValidation(t *testing.T) {
	config := &Config{
		MTU:                9999, // Невалидный
		MaxStreams:         0,    // Невалидный
		ConnectionIdLength: 2,   // Невалидный
	}

	config.Validate()

	if config.MTU != 1400 {
		t.Errorf("MTU should be corrected to 1400, got %d", config.MTU)
	}
	if config.MaxStreams != 16 {
		t.Errorf("MaxStreams should be corrected to 16, got %d", config.MaxStreams)
	}
	if config.ConnectionIdLength != 8 {
		t.Errorf("ConnectionIdLength should be corrected to 8, got %d", config.ConnectionIdLength)
	}
}

func TestObfuscationModeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected ObfuscationMode
	}{
		{"quic", ObfuscationMode_QUIC_MIMIC},
		{"quic-mimic", ObfuscationMode_QUIC_MIMIC},
		{"QUIC", ObfuscationMode_QUIC_MIMIC},
		{"webrtc", ObfuscationMode_WEBRTC_MIMIC},
		{"raw", ObfuscationMode_RAW},
		{"unknown", ObfuscationMode_QUIC_MIMIC}, // default
	}

	for _, tt := range tests {
		got := ObfuscationModeFromString(tt.input)
		if got != tt.expected {
			t.Errorf("ObfuscationModeFromString(%q): got %d, want %d",
				tt.input, got, tt.expected)
		}
	}
}

func TestGetMaxPayloadSize(t *testing.T) {
	config := DefaultConfig()
	maxPayload := config.GetMaxPayloadSize()

	// Должен быть положительным и меньше MTU
	if maxPayload == 0 {
		t.Error("MaxPayloadSize should not be 0")
	}
	if maxPayload >= config.MTU {
		t.Errorf("MaxPayloadSize (%d) should be less than MTU (%d)",
			maxPayload, config.MTU)
	}
}

// ====================================================================
// Тест полного цикла: пакет → шифрование → обфускация → деобфускация → расшифровка
// ====================================================================

func TestFullPipeline(t *testing.T) {
	config := DefaultConfig()
	config.EnablePadding = true

	// Генерируем ключи
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)

	clientKeys, _ := DeriveSessionKeys(sharedSecret, "test", true)
	serverKeys, _ := DeriveSessionKeys(sharedSecret, "test", false)

	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))

	// === Клиент отправляет ===

	// 1. Исходные данные
	originalPayload := []byte("player_move: x=150.5 y=200.3 z=0.0 tick=42")

	// 2. Шифруем
	pktNum := uint32(1)
	connIDLen := int(config.ConnectionIdLength)
	ad := make([]byte, FlagsSize+VersionSize+connIDLen)
	// (в реальности ad заполняется из заголовка)

	ciphertext, err := clientKeys.Encrypt(originalPayload, pktNum, ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 3. Формируем пакет
	pkt := NewDataPacket(connID, pktNum, ciphertext, true)
	packetData, err := pkt.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// 4. Обфусцируем
	obfs := NewObfuscator(ObfuscationMode_QUIC_MIMIC)
	obfuscated, err := obfs.Wrap(packetData)
	if err != nil {
		t.Fatalf("Obfuscate: %v", err)
	}

	// === Передача по сети (obfuscated → UDP → сервер) ===

	// === Сервер получает ===

	// 5. Деобфусцируем
	deobfuscated, err := obfs.Unwrap(obfuscated)
	if err != nil {
		t.Fatalf("Deobfuscate: %v", err)
	}

	// 6. Парсим пакет
	receivedPkt, err := Unmarshal(deobfuscated, int(config.ConnectionIdLength))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// 7. Расшифровываем
	decrypted, err := serverKeys.Decrypt(receivedPkt.Payload, receivedPkt.PacketNumber, ad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// 8. Проверяем
	if !bytes.Equal(decrypted, originalPayload) {
		t.Errorf("Full pipeline: got %q, want %q", decrypted, originalPayload)
	}

	t.Logf("Full pipeline OK: %d bytes payload → %d bytes encrypted → %d bytes packet → %d bytes obfuscated",
		len(originalPayload), len(ciphertext), len(packetData), len(obfuscated))
}

// ====================================================================
// Бенчмарки
// ====================================================================

func BenchmarkEncrypt(b *testing.B) {
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)
	keys, _ := DeriveSessionKeys(sharedSecret, "", true)

	payload := make([]byte, 128) // Типичный игровой пакет
	ad := make([]byte, 13)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keys.Encrypt(payload, uint32(i), ad)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)
	clientKeys, _ := DeriveSessionKeys(sharedSecret, "", true)
	serverKeys, _ := DeriveSessionKeys(sharedSecret, "", false)

	payload := make([]byte, 128)
	ad := make([]byte, 13)
	ciphertext, _ := clientKeys.Encrypt(payload, 1, ad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serverKeys.Decrypt(ciphertext, 1, ad)
	}
}

func BenchmarkMarshalPacket(b *testing.B) {
	config := DefaultConfig()
	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))
	payload := make([]byte, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := NewDataPacket(connID, uint32(i), payload, false)
		pkt.Marshal(config)
	}
}

func BenchmarkQUICObfuscate(b *testing.B) {
	config := DefaultConfig()
	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))
	pkt := NewDataPacket(connID, 1, make([]byte, 128), false)
	data, _ := pkt.Marshal(config)
	obfs := &QUICObfuscator{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		obfs.Wrap(data)
	}
}

func BenchmarkFullPipeline(b *testing.B) {
	config := DefaultConfig()
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(clientKP.PrivateKey, serverKP.PublicKey)
	clientKeys, _ := DeriveSessionKeys(sharedSecret, "", true)

	connID, _ := GenerateConnectionID(int(config.ConnectionIdLength))
	payload := make([]byte, 128)
	ad := make([]byte, 13)
	obfs := &QUICObfuscator{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, _ := clientKeys.Encrypt(payload, uint32(i), ad)
		pkt := NewDataPacket(connID, uint32(i), ciphertext, false)
		data, _ := pkt.Marshal(config)
		obfs.Wrap(data)
	}
}
