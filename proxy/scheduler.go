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
	Buffer            chan buf.MultiBuffer
	Trigger           chan int
	Error             chan error
	closed            chan int
	bufferReadLock    *sync.Mutex
	writer            buf.Writer
	addons            *Addons
	trafficState      *TrafficState
	writeOnceUserUUID *[]byte
	ctx               context.Context
}

func NewScheduler(w buf.Writer, addon *Addons, state *TrafficState, userUUID *[]byte, context context.Context) *Scheduler {
	var s = Scheduler{
		Buffer: make(chan buf.MultiBuffer, 100),
		Trigger: make(chan int),
		Error: make(chan error, 100),
		closed: make(chan int),
		bufferReadLock: new(sync.Mutex),
		writer: w,
		addons: addon,
		trafficState: state,
		writeOnceUserUUID: userUUID,
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
		if len(s.closed) > 0 {
			return
		}
		go func() { // each trigger has independent delay, trigger does not block
			var d = 0 * time.Millisecond
			if s.addons.Delay != nil {
				l, err := rand.Int(rand.Reader, big.NewInt(int64(s.addons.Delay.MaxMillis - s.addons.Delay.MinMillis)))
				if err != nil {
					errors.LogWarningInner(s.ctx, err, "failed to generate delay", trigger)
				}
				d = time.Duration(uint32(l.Int64()) + s.addons.Delay.MinMillis) * time.Millisecond
				time.Sleep(d)
			}

			s.bufferReadLock.Lock() // guard against multiple trigger threads
			var sending = len(s.Buffer)
			if sending > 0 {
				errors.LogDebug(s.ctx, "Scheduler Trigger for ", sending, " buffer(s) with ", d, " ", trigger)
				for i := 0; i<sending; i++ {
					err := s.writer.WriteMultiBuffer(<-s.Buffer)
					if err != nil {
						s.Error <- err
						s.closed <- 1
						return
					}
				}
			} else if trigger > 0 && (s.trafficState.Inbound.IsPadding || s.trafficState.Outbound.IsPadding) && ShouldStartSeed(s.addons, s.trafficState) && !ShouldStopSeed(s.addons, s.trafficState) {
				errors.LogDebug(s.ctx, "Scheduler Trigger for fake buffer with ", d, " ", trigger)
				s.trafficState.NumberOfPacketSent += 1
				mb := make(buf.MultiBuffer, 1)
				mb[0] = XtlsPadding(nil, CommandPaddingContinue, s.writeOnceUserUUID, true, s.addons, s.ctx)
				s.trafficState.ByteSent += int64(mb.Len())
				if s.trafficState.StartTime.IsZero() {
					s.trafficState.StartTime = time.Now()
				}
				err := s.writer.WriteMultiBuffer(mb)
				if err != nil {
					s.Error <- err
					s.closed <- 1
					return
				}
				if buffered, ok := s.writer.(*buf.BufferedWriter); ok {
					buffered.SetBuffered(false)
				}
			}
			s.bufferReadLock.Unlock()
		}()
	}
}

func(s *Scheduler) exampleIndependentScheduler() {
	for {
		if len(s.closed) > 0 {
			return
		}
		s.Trigger <- 1 // send fake buffer if no pending
		time.Sleep(500 * time.Millisecond)
	}
}
