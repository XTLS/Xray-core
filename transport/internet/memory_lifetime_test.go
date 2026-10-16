package internet

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestMemoryStreamCloseSealsAndJoins(t *testing.T) {
	s := new(MemoryStreamConfig)
	entered, release := make(chan struct{}), make(chan struct{})
	sentinel := errors.New("cleanup failure")
	if err := s.OnClose(func() error { close(entered); <-release; return sentinel }); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- s.Close() }()
	<-entered
	if err := s.OnClose(func() error { t.Error("late hook ran"); return nil }); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("late registration: %v", err)
	}
	second := make(chan error, 1)
	go func() { second <- s.Close() }()
	select {
	case <-second:
		t.Fatal("second Close did not join cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if !errors.Is(<-first, sentinel) || !errors.Is(<-second, sentinel) {
		t.Fatal("cleanup result was not preserved")
	}
}

func TestMemoryStreamRegistrationRacesClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := new(MemoryStreamConfig)
		var wg sync.WaitGroup
		var mu sync.Mutex
		registered, closed := 0, 0
		start := make(chan struct{})
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := s.OnClose(func() error { mu.Lock(); closed++; mu.Unlock(); return nil }); err == nil {
					mu.Lock()
					registered++
					mu.Unlock()
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; s.Close() }()
		close(start)
		wg.Wait()
		s.Close()
		if closed != registered {
			t.Fatalf("registered=%d closed=%d", registered, closed)
		}
	}
}
