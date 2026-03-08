package gametunnel

import (
	"sync"
)

// ====================================================================
// Anti-Replay Window
// ====================================================================
//
// Защита от replay-атак: атакующий перехватывает зашифрованный
// пакет и отправляет его повторно. Без anti-replay сервер примет
// его как валидный (nonce + ключ совпадут).
//
// Реализация: sliding window bitmap на 1024 пакета (как в IPsec).
//   - Отслеживаем максимальный принятый PacketNumber
//   - Храним bitmap для PacketNumbers в окне [max-windowSize, max]
//   - Пакеты старше окна - отбрасываются
//   - Пакеты внутри окна - проверяются по bitmap
//   - Пакеты новее max - принимаются, окно сдвигается
//
// ====================================================================

const (
	// ReplayWindowSize - размер окна anti-replay в пакетах
	// 1024 пакета при 60 pps = ~17 секунд истории
	ReplayWindowSize = 1024
)

// ReplayWindow - скользящее окно для защиты от replay-атак
type ReplayWindow struct {
	// maxSeq - максимальный принятый номер пакета
	maxSeq uint32

	// bitmap - битовая карта принятых пакетов в окне
	bitmap [ReplayWindowSize / 64]uint64

	// initialized - получили ли мы хотя бы один пакет
	initialized bool

	mu sync.Mutex
}

// NewReplayWindow создаёт новое anti-replay окно
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Check проверяет, допустим ли пакет с данным номером,
// и если да - помечает его как принятый.
// Возвращает true если пакет новый, false если replay.
func (rw *ReplayWindow) Check(seq uint32) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if !rw.initialized {
		rw.initialized = true
		rw.maxSeq = seq
		rw.setBit(seq)
		return true
	}

	// Пакет новее максимального - принимаем и сдвигаем окно
	if seq > rw.maxSeq {
		diff := seq - rw.maxSeq
		if diff >= ReplayWindowSize {
			rw.clearAll()
		} else {
			for i := rw.maxSeq + 1; i <= seq; i++ {
				rw.clearBit(i)
			}
		}
		rw.maxSeq = seq
		rw.setBit(seq)
		return true
	}

	// Пакет слишком старый - за пределами окна
	if rw.maxSeq-seq >= ReplayWindowSize {
		return false
	}

	// Пакет внутри окна - проверяем дубликат
	if rw.getBit(seq) {
		return false
	}

	rw.setBit(seq)
	return true
}

func (rw *ReplayWindow) setBit(seq uint32) {
	idx := seq % ReplayWindowSize
	rw.bitmap[idx/64] |= 1 << (idx % 64)
}

func (rw *ReplayWindow) clearBit(seq uint32) {
	idx := seq % ReplayWindowSize
	rw.bitmap[idx/64] &^= 1 << (idx % 64)
}

func (rw *ReplayWindow) getBit(seq uint32) bool {
	idx := seq % ReplayWindowSize
	return (rw.bitmap[idx/64] & (1 << (idx % 64))) != 0
}

func (rw *ReplayWindow) clearAll() {
	for i := range rw.bitmap {
		rw.bitmap[i] = 0
	}
}
