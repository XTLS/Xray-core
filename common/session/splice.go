package session

import "sync"

type spliceCopySignal struct {
	ready chan struct{}
	once  sync.Once
}

func newSpliceCopySignal() *spliceCopySignal {
	return &spliceCopySignal{
		ready: make(chan struct{}),
	}
}

func (i *Inbound) ArmSpliceCopy() {
	i.CanSpliceCopy = 2
	i.spliceCopy = newSpliceCopySignal()
}

func (i *Inbound) EnableSpliceCopy() {
	if i.CanSpliceCopy == 3 {
		return
	}
	if i.spliceCopy != nil {
		i.spliceCopy.once.Do(func() {
			close(i.spliceCopy.ready)
		})
	}
	i.CanSpliceCopy = 1
}

func (i *Inbound) DisableSpliceCopy() {
	i.CanSpliceCopy = 3
	i.spliceCopy = nil
}

func (i *Inbound) SpliceCopyState() int {
	return i.CanSpliceCopy
}

func (i *Inbound) SpliceCopyReady() bool {
	if i.spliceCopy != nil {
		select {
		case <-i.spliceCopy.ready:
			return true
		default:
			return false
		}
	}
	return i.CanSpliceCopy == 1
}

func (o *Outbound) ArmSpliceCopy() {
	o.CanSpliceCopy = 2
	o.spliceCopy = newSpliceCopySignal()
}

func (o *Outbound) EnableSpliceCopy() {
	if o.CanSpliceCopy == 3 {
		return
	}
	if o.spliceCopy != nil {
		o.spliceCopy.once.Do(func() {
			close(o.spliceCopy.ready)
		})
	}
	o.CanSpliceCopy = 1
}

func (o *Outbound) DisableSpliceCopy() {
	o.CanSpliceCopy = 3
	o.spliceCopy = nil
}

func (o *Outbound) SpliceCopyState() int {
	return o.CanSpliceCopy
}

func (o *Outbound) SpliceCopyReady() bool {
	if o.spliceCopy != nil {
		select {
		case <-o.spliceCopy.ready:
			return true
		default:
			return false
		}
	}
	return o.CanSpliceCopy == 1
}
