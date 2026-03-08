package gametunnel

import (
	"sync"
	"time"
)

// ====================================================================
// Приоритизация трафика GameTunnel
// ====================================================================
//
// Онлайн-игры генерируют маленькие частые пакеты (20-200 байт,
// 20-60 раз в секунду). Загрузка файлов или стриминг генерируют
// большие редкие пакеты (1000+ байт).
//
// Без приоритизации большой пакет загрузки может заблокировать
// отправку игрового пакета, увеличивая пинг.
//
// PriorityQueue решает это:
//   - Пакеты классифицируются по размеру
//   - Игровые пакеты (маленькие, частые) уходят первыми
//   - Загрузки (большие) отправляются в промежутках
//   - Стриминг получает средний приоритет
//
// Реализация на ring buffer + mutex (вместо каналов):
//   - Безопасный Peek() без извлечения (для starvation check)
//   - Нет race condition при checkStarvation
//   - Нет потери пакетов
//
// Три уровня приоритета:
//   0 (High)   - игры, VoIP, DNS (< 256 байт)
//   1 (Medium) - веб-страницы, стриминг (256-1024 байт)
//   2 (Low)    - загрузки, обновления (> 1024 байт)
//
// ====================================================================

// PriorityLevel - уровень приоритета
type PriorityLevel uint8

const (
	PriorityHigh   PriorityLevel = 0 // Игры, VoIP, DNS
	PriorityMedium PriorityLevel = 1 // Веб, стриминг
	PriorityLow    PriorityLevel = 2 // Загрузки

	// Количество уровней приоритета
	PriorityLevels = 3

	// Размеры очередей
	HighQueueSize   = 512
	MediumQueueSize = 256
	LowQueueSize    = 128

	// Пороги размеров пакетов для классификации
	HighPriorityMaxSize   = 256  // Пакеты до 256 байт → High
	MediumPriorityMaxSize = 1024 // Пакеты 256-1024 байт → Medium
	// Всё что больше → Low
)

// PriorityPacket - пакет в очереди с метаданными
type PriorityPacket struct {
	// Data - данные для отправки (уже зашифрованные)
	Data []byte

	// Priority - уровень приоритета
	Priority PriorityLevel

	// EnqueuedAt - время постановки в очередь
	// Используется для предотвращения starvation
	EnqueuedAt time.Time

	// Session - сессия, которой принадлежит пакет
	Session *Session
}

// ====================================================================
// Ring Buffer - кольцевой буфер для одного уровня приоритета
// ====================================================================

type priorityRing struct {
	buf  []*PriorityPacket
	head int
	tail int
	size int
	cap  int
}

func newPriorityRing(capacity int) *priorityRing {
	return &priorityRing{
		buf: make([]*PriorityPacket, capacity),
		cap: capacity,
	}
}

func (r *priorityRing) Len() int {
	return r.size
}

func (r *priorityRing) Push(pkt *PriorityPacket) bool {
	if r.size == r.cap {
		return false
	}
	r.buf[r.tail] = pkt
	r.tail = (r.tail + 1) % r.cap
	r.size++
	return true
}

func (r *priorityRing) Pop() *PriorityPacket {
	if r.size == 0 {
		return nil
	}
	pkt := r.buf[r.head]
	r.buf[r.head] = nil // prevent memory leak
	r.head = (r.head + 1) % r.cap
	r.size--
	return pkt
}

// Peek возвращает головной элемент БЕЗ извлечения - безопасная операция
func (r *priorityRing) Peek() *PriorityPacket {
	if r.size == 0 {
		return nil
	}
	return r.buf[r.head]
}

// ====================================================================
// PriorityQueue
// ====================================================================

// PriorityQueue - очередь с приоритизацией
type PriorityQueue struct {
	// queues - три очереди по приоритетам
	queues [PriorityLevels]*priorityRing

	// mode - режим приоритизации
	mode PriorityMode

	// stats
	enqueuedHigh   uint64
	enqueuedMedium uint64
	enqueuedLow    uint64
	dropped        uint64

	// starvationTimeout - максимальное время ожидания в очереди
	// Если пакет ждёт дольше - его приоритет повышается
	starvationTimeout time.Duration

	mu sync.Mutex
}

// NewPriorityQueue создаёт новую очередь с приоритизацией
func NewPriorityQueue(mode PriorityMode) *PriorityQueue {
	pq := &PriorityQueue{
		mode:              mode,
		starvationTimeout: 500 * time.Millisecond, // 500ms starvation guard
	}

	pq.queues[PriorityHigh] = newPriorityRing(HighQueueSize)
	pq.queues[PriorityMedium] = newPriorityRing(MediumQueueSize)
	pq.queues[PriorityLow] = newPriorityRing(LowQueueSize)

	return pq
}

// Enqueue добавляет пакет в очередь с автоматической классификацией
func (pq *PriorityQueue) Enqueue(data []byte, session *Session) bool {
	priority := pq.classify(data)

	pkt := &PriorityPacket{
		Data:       data,
		Priority:   priority,
		EnqueuedAt: time.Now(),
		Session:    session,
	}

	pq.mu.Lock()
	defer pq.mu.Unlock()

	ok := pq.queues[priority].Push(pkt)
	if !ok {
		// Очередь полна - для High-priority пытаемся вытеснить Low
		if priority == PriorityHigh {
			ok = pq.tryBumpLocked(pkt)
		}
		if !ok {
			pq.dropped++
			return false
		}
	}

	pq.updateStatsLocked(priority)
	return true
}

// EnqueueWithPriority добавляет пакет с явно указанным приоритетом
func (pq *PriorityQueue) EnqueueWithPriority(data []byte, priority PriorityLevel, session *Session) bool {
	if priority >= PriorityLevels {
		priority = PriorityLow
	}

	pkt := &PriorityPacket{
		Data:       data,
		Priority:   priority,
		EnqueuedAt: time.Now(),
		Session:    session,
	}

	pq.mu.Lock()
	defer pq.mu.Unlock()

	ok := pq.queues[priority].Push(pkt)
	if !ok {
		pq.dropped++
		return false
	}

	pq.updateStatsLocked(priority)
	return true
}

// Dequeue извлекает следующий пакет для отправки (non-blocking).
// Приоритет: High → (starvation check Low) → Medium → Low
func (pq *PriorityQueue) Dequeue() *PriorityPacket {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// Всегда сначала High
	if pkt := pq.queues[PriorityHigh].Pop(); pkt != nil {
		return pkt
	}

	// Starvation check: безопасный Peek() - НЕ извлекаем пакет
	if lowHead := pq.queues[PriorityLow].Peek(); lowHead != nil {
		if time.Since(lowHead.EnqueuedAt) > pq.starvationTimeout {
			return pq.queues[PriorityLow].Pop()
		}
	}

	// Medium
	if pkt := pq.queues[PriorityMedium].Pop(); pkt != nil {
		return pkt
	}

	// Low
	if pkt := pq.queues[PriorityLow].Pop(); pkt != nil {
		return pkt
	}

	return nil
}

// DequeueBlocking извлекает пакет с блокировкой до получения
// Используется в основном цикле отправки
func (pq *PriorityQueue) DequeueBlocking() *PriorityPacket {
	for {
		pkt := pq.Dequeue()
		if pkt != nil {
			return pkt
		}
		// Короткий sleep вместо busy-wait
		time.Sleep(100 * time.Microsecond)
	}
}

// classify определяет приоритет пакета по его характеристикам
func (pq *PriorityQueue) classify(data []byte) PriorityLevel {
	switch pq.mode {
	case PriorityMode_GAMING:
		return pq.classifyGaming(data)
	case PriorityMode_STREAMING:
		return pq.classifyStreaming(data)
	default:
		return PriorityMedium // Без приоритизации - всё в Medium
	}
}

// classifyGaming - классификация для gaming-режима
// Маленькие пакеты = высокий приоритет (игровой трафик)
func (pq *PriorityQueue) classifyGaming(data []byte) PriorityLevel {
	size := len(data)

	if size <= HighPriorityMaxSize {
		return PriorityHigh
	}

	if size <= MediumPriorityMaxSize {
		return PriorityMedium
	}

	return PriorityLow
}

// classifyStreaming - классификация для streaming-режима
// Средние пакеты = высокий приоритет (видео/аудио чанки)
func (pq *PriorityQueue) classifyStreaming(data []byte) PriorityLevel {
	size := len(data)

	if size <= HighPriorityMaxSize {
		return PriorityHigh // Сигналинг, контроль
	}

	if size <= MediumPriorityMaxSize {
		return PriorityHigh // Медиа-данные - тоже высокий приоритет
	}

	return PriorityMedium // Большие чанки - средний
}

// tryBumpLocked вытесняет Low-priority пакет ради High-priority.
// Вызывается под mu.Lock. Не трогает Medium.
func (pq *PriorityQueue) tryBumpLocked(highPkt *PriorityPacket) bool {
	// Забираем из Low
	dropped := pq.queues[PriorityLow].Pop()
	if dropped == nil {
		return false
	}
	pq.dropped++

	// Кладём high-priority пакет в High очередь
	if ok := pq.queues[PriorityHigh].Push(highPkt); ok {
		return true
	}

	// Не удалось - edge case
	pq.dropped++
	return false
}

func (pq *PriorityQueue) updateStatsLocked(level PriorityLevel) {
	switch level {
	case PriorityHigh:
		pq.enqueuedHigh++
	case PriorityMedium:
		pq.enqueuedMedium++
	case PriorityLow:
		pq.enqueuedLow++
	}
}

// GetStats возвращает статистику очереди
func (pq *PriorityQueue) GetStats() PriorityQueueStats {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	return PriorityQueueStats{
		HighQueued:     pq.queues[PriorityHigh].Len(),
		MediumQueued:   pq.queues[PriorityMedium].Len(),
		LowQueued:      pq.queues[PriorityLow].Len(),
		TotalEnqueued:  pq.enqueuedHigh + pq.enqueuedMedium + pq.enqueuedLow,
		HighEnqueued:   pq.enqueuedHigh,
		MediumEnqueued: pq.enqueuedMedium,
		LowEnqueued:    pq.enqueuedLow,
		Dropped:        pq.dropped,
	}
}

// PriorityQueueStats - статистика для панели управления
type PriorityQueueStats struct {
	HighQueued     int    `json:"highQueued"`
	MediumQueued   int    `json:"mediumQueued"`
	LowQueued      int    `json:"lowQueued"`
	TotalEnqueued  uint64 `json:"totalEnqueued"`
	HighEnqueued   uint64 `json:"highEnqueued"`
	MediumEnqueued uint64 `json:"mediumEnqueued"`
	LowEnqueued    uint64 `json:"lowEnqueued"`
	Dropped        uint64 `json:"dropped"`
}

// ====================================================================
// Bandwidth Estimator - оценка пропускной способности
// ====================================================================

// BandwidthEstimator оценивает текущую пропускную способность
type BandwidthEstimator struct {
	// samples - последние замеры скорости (байт/сек)
	samples    []float64
	maxSamples int

	// lastMeasure - время последнего замера
	lastMeasure time.Time

	// bytesSinceLastMeasure - байт с последнего замера
	bytesSinceLastMeasure uint64

	mu sync.Mutex
}

// NewBandwidthEstimator создаёт новый оценщик
func NewBandwidthEstimator() *BandwidthEstimator {
	return &BandwidthEstimator{
		samples:     make([]float64, 0, 20),
		maxSamples:  20,
		lastMeasure: time.Now(),
	}
}

// RecordBytes записывает количество отправленных/полученных байт
func (be *BandwidthEstimator) RecordBytes(n uint64) {
	be.mu.Lock()
	defer be.mu.Unlock()

	be.bytesSinceLastMeasure += n

	// Замеряем каждую секунду
	elapsed := time.Since(be.lastMeasure)
	if elapsed >= time.Second {
		bytesPerSec := float64(be.bytesSinceLastMeasure) / elapsed.Seconds()

		be.samples = append(be.samples, bytesPerSec)
		if len(be.samples) > be.maxSamples {
			be.samples = be.samples[1:]
		}

		be.bytesSinceLastMeasure = 0
		be.lastMeasure = time.Now()
	}
}

// GetEstimate возвращает текущую оценку пропускной способности (байт/сек)
func (be *BandwidthEstimator) GetEstimate() float64 {
	be.mu.Lock()
	defer be.mu.Unlock()

	if len(be.samples) == 0 {
		return 0
	}

	sum := 0.0
	for _, s := range be.samples {
		sum += s
	}

	return sum / float64(len(be.samples))
}

// GetEstimateMbps возвращает оценку в Мбит/сек
func (be *BandwidthEstimator) GetEstimateMbps() float64 {
	return be.GetEstimate() * 8 / 1_000_000
}

// IsCongestedBy проверяет, перегружен ли канал
func (be *BandwidthEstimator) IsCongestedBy(threshold float64, maxBandwidth float64) bool {
	estimate := be.GetEstimate()
	if maxBandwidth <= 0 {
		return false
	}
	return estimate/maxBandwidth > threshold
}