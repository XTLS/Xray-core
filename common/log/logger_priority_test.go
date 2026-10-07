package log

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The first write is deliberately stalled. This saturates the real normal queue
// before priority admission, without depending on scheduler speed or real stdout.
type priorityTestWriter struct {
	entered   chan struct{}
	release   chan struct{}
	wrote     chan string
	closed    chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

func newPriorityTestWriter() *priorityTestWriter {
	return &priorityTestWriter{entered: make(chan struct{}), release: make(chan struct{}), wrote: make(chan string, 512), closed: make(chan struct{})}
}

func (w *priorityTestWriter) Write(s string) error {
	w.once.Do(func() { close(w.entered); <-w.release })
	w.wrote <- strings.TrimSpace(s)
	return nil
}

func (w *priorityTestWriter) Close() error { w.closeOnce.Do(func() { close(w.closed) }); return nil }

func waitPriorityTest(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded logger event missing")
	}
}

func priorityTestRead(t *testing.T, w *priorityTestWriter) string {
	t.Helper()
	select {
	case s := <-w.wrote:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("bounded write missing")
		return ""
	}
}

func TestPriorityLoggerNormalSaturationAndProgress(t *testing.T) {
	w := newPriorityTestWriter()
	l := NewLogger(func() Writer { return w }).(*generalLogger)
	t.Cleanup(func() { l.Close() })
	l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "in-write"})
	waitPriorityTest(t, w.entered)
	for i := 0; i < 128; i++ {
		l.Handle(&GeneralMessage{Severity: Severity_Info, Content: fmt.Sprintf("ordinary-%d", i)})
	}
	for i := 0; i < 10000; i++ {
		l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "ordinary-dropped"})
	}
	if len(l.buffer) != 128 {
		t.Fatalf("normal queue %d", len(l.buffer))
	}
	for i := 0; i < 7; i++ {
		l.Handle(&GeneralMessage{Severity: Severity_Info, Content: fmt.Sprintf("periodic-%d", i), Priority: true})
	}
	if len(l.priority) != 7 {
		t.Fatalf("priority queue %d", len(l.priority))
	}
	close(w.release)
	if got := priorityTestRead(t, w); got != "[Info] in-write" {
		t.Fatal(got)
	}
	for i := 0; i < 7; i++ {
		if got := priorityTestRead(t, w); got != fmt.Sprintf("[Info] periodic-%d", i) {
			t.Fatalf("priority ordering: %s", got)
		}
	}
	if got := priorityTestRead(t, w); got != "[Info] ordinary-0" {
		t.Fatalf("normal progress: %s", got)
	}
	l.Close()
	waitPriorityTest(t, w.closed)
}

func TestPriorityLoggerBoundedOverflowNonblocking(t *testing.T) {
	w := newPriorityTestWriter()
	l := NewLogger(func() Writer { return w }).(*generalLogger)
	l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "in-write"})
	waitPriorityTest(t, w.entered)
	returned := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "priority", Priority: true})
		}
		close(returned)
	}()
	waitPriorityTest(t, returned)
	if len(l.priority) != 128 || len(l.buffer) != 0 {
		t.Fatalf("bounded queues %d/%d", len(l.priority), len(l.buffer))
	}
	l.Close()
	close(w.release)
	waitPriorityTest(t, w.closed)
}

func TestPriorityLoggerCloseAndConcurrentHandle(t *testing.T) {
	w := newPriorityTestWriter()
	l := NewLogger(func() Writer { return w }).(*generalLogger)
	l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "in-write"})
	waitPriorityTest(t, w.entered)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "traffic", Priority: i%2 == 0})
			}
			l.Close()
		}(i)
	}
	wg.Wait()
	close(w.release)
	waitPriorityTest(t, w.closed)
	normal, priority := len(l.buffer), len(l.priority)
	l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "after-close"})
	l.Handle(&GeneralMessage{Severity: Severity_Info, Content: "after-close-priority", Priority: true})
	if len(l.buffer) != normal || len(l.priority) != priority {
		t.Fatal("admission after close")
	}
}

func TestPriorityMessageFormatUnchanged(t *testing.T) {
	normal := &GeneralMessage{Severity: Severity_Info, Content: "same"}
	priority := &GeneralMessage{Severity: Severity_Info, Content: "same", Priority: true}
	if normal.String() != priority.String() || normal.IsPriority() || !priority.IsPriority() {
		t.Fatal("priority changed protocol or flag")
	}
}
