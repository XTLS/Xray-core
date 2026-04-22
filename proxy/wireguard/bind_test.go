package wireguard

import (
	"sync"
	"testing"
)

func TestNetBindCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	bind := &netBind{
		readQueue: make(chan *netReadInfo),
		closedCh:  make(chan struct{}),
	}

	var wg sync.WaitGroup
	panicCh := make(chan interface{}, 18)
	closeBind := func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()
		_ = bind.Close()
	}

	wg.Add(2)
	go closeBind()
	go closeBind()

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go closeBind()
	}

	wg.Wait()
	close(panicCh)

	for p := range panicCh {
		t.Fatalf("Close panicked: %v", p)
	}
}
