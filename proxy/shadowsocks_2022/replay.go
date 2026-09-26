package shadowsocks_2022

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/utils"
)

const (
	swBlockBitLog = 6                                // 1<<6 == 64 bits
	swBlockBits   = 1 << swBlockBitLog               // 64
	swRingBlocks  = 1 << 7                           // 128
	swBlockMask   = swRingBlocks - 1                 // 127
	swBitMask     = swBlockBits - 1                  // 63
	swSize        = (swRingBlocks - 1) * swBlockBits // 8128
)

type SlidingWindow struct {
	last uint64
	ring [swRingBlocks]uint64
}

func (f *SlidingWindow) Reset() {
	f.last = 0
	f.ring[0] = 0
}

func (f *SlidingWindow) Check(counter uint64) bool {
	switch {
	case counter > f.last:
		return true
	case f.last-counter > swSize:
		return false
	}

	blockIndex := (counter >> swBlockBitLog) & swBlockMask
	bitIndex := counter & swBitMask
	return (f.ring[blockIndex]>>bitIndex)&1 == 0
}

func (f *SlidingWindow) Add(counter uint64) {
	blockIndex := counter >> swBlockBitLog

	if counter > f.last {
		lastBlockIndex := f.last >> swBlockBitLog
		diff := int(blockIndex - lastBlockIndex)
		if diff > swRingBlocks {
			diff = swRingBlocks
		}

		for i := 0; i < diff; i++ {
			lastBlockIndex = (lastBlockIndex + 1) & swBlockMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter
	}

	blockIndex &= swBlockMask
	bitIndex := counter & swBitMask
	f.ring[blockIndex] |= 1 << bitIndex
}

func (f *SlidingWindow) CheckAndAdd(counter uint64) bool {
	if !f.Check(counter) {
		return false
	}
	f.Add(counter)
	return true
}

type ServerUDPSession struct {
	sync.Mutex
	SessionID    uint64
	RemoteCipher atomic.Pointer[cipher.AEAD]
	Window       SlidingWindow
	User         *protocol.MemoryUser
	UserPSK      []byte
	LastActive   atomic.Int64 // Unix timestamp in seconds

	ServerSessionID   uint64
	ServerPacketID    atomic.Uint64
	ServerCipher      cipher.AEAD
	ServerBlockCipher cipher.Block
	ServerChaCha      cipher.AEAD
}

func (s *ServerUDPSession) GetRemoteCipher() cipher.AEAD {
	ptr := s.RemoteCipher.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

func (s *ServerUDPSession) SetRemoteCipher(c cipher.AEAD) {
	s.RemoteCipher.Store(&c)
}

type UDPSessionManager struct {
	sessions  *utils.TypedSyncMap[uint64, *ServerUDPSession]
	timeout   time.Duration
	lastClean atomic.Int64 // Unix timestamp in seconds
}

func NewUDPSessionManager(timeout time.Duration) *UDPSessionManager {
	return &UDPSessionManager{
		sessions: utils.NewTypedSyncMap[uint64, *ServerUDPSession](),
		timeout:  timeout,
	}
}

func (m *UDPSessionManager) GetOrCreate(sessionID uint64) *ServerUDPSession {
	now := time.Now().Unix()
	if s, ok := m.sessions.Load(sessionID); ok {
		s.LastActive.Store(now)
		return s
	}

	s := &ServerUDPSession{
		SessionID: sessionID,
	}
	s.LastActive.Store(now)

	actual, loaded := m.sessions.LoadOrStore(sessionID, s)
	if loaded {
		actual.LastActive.Store(now)
		return actual
	}

	// Trigger cleanup if at least 30 seconds have passed since last cleanup
	last := m.lastClean.Load()
	if now-last > 30 && m.lastClean.CompareAndSwap(last, now) {
		go m.cleanup(now)
	}

	return s
}

func (m *UDPSessionManager) cleanup(now int64) {
	timeoutSec := int64(m.timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	m.sessions.Range(func(k uint64, v *ServerUDPSession) bool {
		if now-v.LastActive.Load() > timeoutSec {
			m.sessions.Delete(k)
		}
		return true
	})
}

func (m *UDPSessionManager) Delete(sessionID uint64) {
	m.sessions.Delete(sessionID)
}
