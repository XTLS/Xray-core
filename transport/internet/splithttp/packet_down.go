package splithttp

import (
	"io"
	"sync"
	"time"
)

// downlinkBuffer — исходящий буфер сессии в режиме packet-down.
// Ядро Xray пишет в него (Write), GET-сегменты забирают данные порциями (TakeSegment).
type downlinkBuffer struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
	notify chan struct{} // «появились данные или буфер закрыт»
	space  chan struct{} // «освободилось место»
	limit  int           // максимум байт в буфере (обратное давление)
}

func newDownlinkBuffer(limit int) *downlinkBuffer {
	return &downlinkBuffer{
		notify: make(chan struct{}, 1),
		space:  make(chan struct{}, 1),
		limit:  limit,
	}
}

// signalDownlink активирует пассивного, не блокируясь, если он уже разбужен.
func signalDownlink(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (d *downlinkBuffer) Write(p []byte) (int, error) {
	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return 0, io.ErrClosedPipe
		}
		if len(d.buf) == 0 || len(d.buf)+len(p) <= d.limit {
			d.buf = append(d.buf, p...)
			d.mu.Unlock()
			signalDownlink(d.notify)
			return len(p), nil
		}
		d.mu.Unlock()
		<-d.space // ждём, пока клиент получит посылку
	}
}

// TakeSegment возвращает до max байт.
// eof=true — буфер закрыт и пуст, сессия окончена.
// Пустой срез без eof — за время wait данных не появилось.
func (d *downlinkBuffer) TakeSegment(max int, wait, gather time.Duration) (seg []byte, eof bool) {
	waitT := time.NewTimer(wait)
	defer waitT.Stop()
	var gatherC <-chan time.Time
	gatherExpired := false

	for {
		d.mu.Lock()
		n := len(d.buf)
		if n > 0 && (n >= max || d.closed || gatherExpired) {
			if n > max {
				n = max
			}
			out := append([]byte(nil), d.buf[:n]...)
			d.buf = d.buf[n:]
			if len(d.buf) == 0 {
				d.buf = nil
			}
			d.mu.Unlock()
			signalDownlink(d.space)
			return out, false
		}
		if n == 0 && d.closed {
			d.mu.Unlock()
			return nil, true
		}
		d.mu.Unlock()

		if n > 0 && gatherC == nil { // данные пошли — даём им немного накопиться
			t := time.NewTimer(gather)
			defer t.Stop()
			gatherC = t.C
		}

		select {
		case <-d.notify:
		case <-gatherC:
			gatherExpired = true
		case <-waitT.C:
			if n == 0 {
				return nil, false
			}
			gatherExpired = true
		}
	}
}

func (d *downlinkBuffer) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	signalDownlink(d.notify)
	signalDownlink(d.space)
	return nil
}
