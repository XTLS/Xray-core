package proxy

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type Scheduler struct {
	Buffer         chan buf.MultiBuffer
	Trigger        chan int
	Error          chan error
	bufferReadLock *sync.Mutex
	writer         buf.Writer
	addons         *Addons
	trafficState   *TrafficState
	ctx            context.Context
}

func NewScheduler(w buf.Writer, addon *Addons, state *TrafficState, context context.Context) *Scheduler {
	var s = Scheduler{
		Buffer: make(chan buf.MultiBuffer, 100),
		Trigger: make(chan int),
		Error: make(chan error, 100),
		bufferReadLock: new(sync.Mutex),
		writer: w,
		addons: addon,
		trafficState: state,
		ctx: context,
	}
	go s.mainLoop()
	if s.addons.Scheduler != nil {
		go s.exampleIndependentScheduler()
	}
	return &s
}

func(s *Scheduler) mainLoop() {
	for trigger := range s.Trigger {
		go func() { // each trigger has independent delay, trigger does not block
			var d = 0 * time.Millisecond
			if s.addons.Delay != nil {
				l, err := rand.Int(rand.Reader, big.NewInt(int64(s.addons.Delay.MaxMillis - s.addons.Delay.MinMillis)))
				if err != nil {
					errors.LogInfoInner(s.ctx, err, "failed to generate delay", trigger)
				}
				d = time.Duration(uint32(l.Int64()) + s.addons.Delay.MinMillis) * time.Millisecond
				time.Sleep(d)
			}

			s.bufferReadLock.Lock() // guard against multiple trigger threads
			var sending = len(s.Buffer)
			if sending > 0 {
				errors.LogDebug(s.ctx, "Scheduler Trigger for ", sending, " buffer(s) with ", d, " ", trigger)
			}
			for i := 0; i<sending; i++ {
				s.Error <- s.writer.WriteMultiBuffer(<-s.Buffer)
			}
			s.bufferReadLock.Unlock()
		}()
	}
}

func(s *Scheduler) exampleIndependentScheduler() {
	for {
		time.Sleep(500 * time.Millisecond)
		s.Trigger <- -1 // send all buffers
	}
}
