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
//   - Пакеты классифицируются по размеру и частоте
//   - Игровые пакеты (маленькие, частые) уходят первыми
//   - Загрузки (большие) отправляются в промежутках
//   - Стриминг получает средний приоритет
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

// PriorityQueue - очередь с приоритизацией
type PriorityQueue struct {
	// queues - три очереди по приоритетам
	queues [PriorityLevels]chan *PriorityPacket

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

	mu sync.RWMutex
}

// NewPriorityQueue создаёт новую очередь с приоритизацией
func NewPriorityQueue(mode PriorityMode) *PriorityQueue {
	pq := &PriorityQueue{
		mode:              mode,
		starvationTimeout: 500 * time.Millisecond, // 500ms starvation guard
	}

	pq.queues[PriorityHigh] = make(chan *PriorityPacket, HighQueueSize)
	pq.queues[PriorityMedium] = make(chan *PriorityPacket, MediumQueueSize)
	pq.queues[PriorityLow] = make(chan *PriorityPacket, LowQueueSize)

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

	// Пытаемся добавить в соответствующую очередь
	select {
	case pq.queues[priority] <- pkt:
		pq.updateEnqueueStats(priority)
		return true
	default:
		// Очередь полна
		// Для High-priority: пытаемся вытеснить из Low
		if priority == PriorityHigh {
			return pq.tryBump(pkt)
		}
		pq.mu.Lock()
		pq.dropped++
		pq.mu.Unlock()
		return false
	}
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

	select {
	case pq.queues[priority] <- pkt:
		pq.updateEnqueueStats(priority)
		return true
	default:
		pq.mu.Lock()
		pq.dropped++
		pq.mu.Unlock()
		return false
	}
}

// Dequeue извлекает следующий пакет для отправки
// Приоритет: High → Medium → Low
// С защитой от starvation: если пакет в Low ждёт > starvationTimeout,
// он обрабатывается раньше Medium
func (pq *PriorityQueue) Dequeue() *PriorityPacket {
	// Всегда сначала проверяем High-priority
	select {
	case pkt := <-pq.queues[PriorityHigh]:
		return pkt
	default:
	}

	// Проверяем starvation в Low-priority
	if pq.checkStarvation(PriorityLow) {
		select {
		case pkt := <-pq.queues[PriorityLow]:
			return pkt
		default:
		}
	}

	// Medium-priority
	select {
	case pkt := <-pq.queues[PriorityMedium]:
		return pkt
	default:
	}

	// Low-priority
	select {
	case pkt := <-pq.queues[PriorityLow]:
		return pkt
	default:
	}

	return nil
}

// DequeueBlocking извлекает пакет с блокировкой до получения
// Используется в основном цикле отправки
func (pq *PriorityQueue) DequeueBlocking() *PriorityPacket {
	for {
		// Non-blocking проверка всех очередей по приоритету
		pkt := pq.Dequeue()
		if pkt != nil {
			return pkt
		}

		// Блокирующее ожидание любого пакета
		select {
		case pkt := <-pq.queues[PriorityHigh]:
			return pkt
		case pkt := <-pq.queues[PriorityMedium]:
			return pkt
		case pkt := <-pq.queues[PriorityLow]:
			return pkt
		}
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

	// Маленькие пакеты - скорее всего игры, VoIP, DNS
	// Игровые пакеты обычно 20-200 байт, 20-60 pps
	if size <= HighPriorityMaxSize {
		return PriorityHigh
	}

	// Средние пакеты - веб-трафик, небольшие загрузки
	if size <= MediumPriorityMaxSize {
		return PriorityMedium
	}

	// Большие пакеты - загрузки, стриминг, обновления
	return PriorityLow
}

// classifyStreaming - классификация для streaming-режима
// Средние пакеты = высокий приоритет (видео/аудио чанки)
func (pq *PriorityQueue) classifyStreaming(data []byte) PriorityLevel {
	size := len(data)

	// Для стриминга: аудио/видео пакеты обычно 500-1400 байт
	// Маленькие пакеты (сигналинг) тоже важны
	if size <= HighPriorityMaxSize {
		return PriorityHigh // Сигналинг, контроль
	}

	if size <= MediumPriorityMaxSize {
		return PriorityHigh // Медиа-данные - тоже высокий приоритет
	}

	return PriorityMedium // Большие чанки - средний
}

// tryBump пытается вытеснить Low-priority пакет ради High-priority
func (pq *PriorityQueue) tryBump(highPkt *PriorityPacket) bool {
	// Пытаемся забрать из Low
	select {
	case <-pq.queues[PriorityLow]:
		// Освободили место, но кладём в High
		pq.mu.Lock()
		pq.dropped++ // Low-priority пакет потерян
		pq.mu.Unlock()
	default:
		// Low тоже пуста - пытаемся Medium
		select {
		case <-pq.queues[PriorityMedium]:
			pq.mu.Lock()
			pq.dropped++
			pq.mu.Unlock()
		default:
			// Все очереди полны - дропаем
			pq.mu.Lock()
			pq.dropped++
			pq.mu.Unlock()
			return false
		}
	}

	// Теперь в High должно быть место
	select {
	case pq.queues[PriorityHigh] <- highPkt:
		pq.updateEnqueueStats(PriorityHigh)
		return true
	default:
		pq.mu.Lock()
		pq.dropped++
		pq.mu.Unlock()
		return false
	}
}

// checkStarvation проверяет, не голодает ли очередь
func (pq *PriorityQueue) checkStarvation(level PriorityLevel) bool {
	// Peek в очередь без извлечения
	select {
	case pkt := <-pq.queues[level]:
		isStarving := time.Since(pkt.EnqueuedAt) > pq.starvationTimeout
		// Возвращаем пакет обратно
		select {
		case pq.queues[level] <- pkt:
		default:
			// Не удалось вернуть - очередь переполнена, дропаем
		}
		return isStarving
	default:
		return false
	}
}

// updateEnqueueStats обновляет статистику
func (pq *PriorityQueue) updateEnqueueStats(level PriorityLevel) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

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
	pq.mu.RLock()
	defer pq.mu.RUnlock()

	return PriorityQueueStats{
		HighQueued:     len(pq.queues[PriorityHigh]),
		MediumQueued:   len(pq.queues[PriorityMedium]),
		LowQueued:      len(pq.queues[PriorityLow]),
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
//
// Для адаптивной приоритизации полезно знать текущую
// пропускную способность канала. Если канал перегружен -
// агрессивнее приоритизируем. Если свободен - пропускаем всё.
//
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
// Используется скользящее среднее по последним замерам
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
// threshold - порог использования (0.0-1.0)
// maxBandwidth - максимальная ожидаемая пропускная способность (байт/сек)
func (be *BandwidthEstimator) IsCongestedBy(threshold float64, maxBandwidth float64) bool {
	estimate := be.GetEstimate()
	if maxBandwidth <= 0 {
		return false
	}
	return estimate/maxBandwidth > threshold
}
