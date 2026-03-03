package session

import "sync"

var spliceCopyInitMu sync.Mutex

type spliceCopySignal struct {
	mu    sync.RWMutex
	state int
	ready chan struct{}
	once  sync.Once
}

func newSpliceCopySignal(state int) *spliceCopySignal {
	s := &spliceCopySignal{
		state: state,
		ready: make(chan struct{}),
	}
	if state == 1 {
		close(s.ready)
	}
	return s
}

func (i *Inbound) ensureSpliceCopy() *spliceCopySignal {
	spliceCopyInitMu.Lock()
	defer spliceCopyInitMu.Unlock()

	if i.spliceCopy == nil {
		i.spliceCopy = newSpliceCopySignal(i.CanSpliceCopy)
	}
	return i.spliceCopy
}

func (i *Inbound) ArmSpliceCopy() {
	s := i.ensureSpliceCopy()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = 2
	s.ready = make(chan struct{})
	s.once = sync.Once{}
	i.CanSpliceCopy = 2
}

func (i *Inbound) EnableSpliceCopy() {
	s := i.ensureSpliceCopy()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == 3 {
		return
	}
	s.state = 1
	i.CanSpliceCopy = 1
	s.once.Do(func() {
		close(s.ready)
	})
}

func (i *Inbound) DisableSpliceCopy() {
	s := i.ensureSpliceCopy()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = 3
	i.CanSpliceCopy = 3
}

func (i *Inbound) SpliceCopyState() int {
	s := i.ensureSpliceCopy()

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.state
}

func (i *Inbound) SpliceCopyReady() bool {
	s := i.ensureSpliceCopy()

	s.mu.RLock()
	state := s.state
	ready := s.ready
	s.mu.RUnlock()

	if state != 1 {
		return false
	}
	select {
	case <-ready:
		return true
	default:
		return false
	}
}

func (o *Outbound) ensureSpliceCopy() *spliceCopySignal {
	spliceCopyInitMu.Lock()
	defer spliceCopyInitMu.Unlock()

	if o.spliceCopy == nil {
		o.spliceCopy = newSpliceCopySignal(o.CanSpliceCopy)
	}
	return o.spliceCopy
}

func (o *Outbound) ArmSpliceCopy() {
	s := o.ensureSpliceCopy()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = 2
	s.ready = make(chan struct{})
	s.once = sync.Once{}
	o.CanSpliceCopy = 2
}

func (o *Outbound) EnableSpliceCopy() {
	s := o.ensureSpliceCopy()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == 3 {
		return
	}
	s.state = 1
	o.CanSpliceCopy = 1
	s.once.Do(func() {
		close(s.ready)
	})
}

func (o *Outbound) DisableSpliceCopy() {
	s := o.ensureSpliceCopy()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = 3
	o.CanSpliceCopy = 3
}

func (o *Outbound) SpliceCopyState() int {
	s := o.ensureSpliceCopy()

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.state
}

func (o *Outbound) SpliceCopyReady() bool {
	s := o.ensureSpliceCopy()

	s.mu.RLock()
	state := s.state
	ready := s.ready
	s.mu.RUnlock()

	if state != 1 {
		return false
	}
	select {
	case <-ready:
		return true
	default:
		return false
	}
}
