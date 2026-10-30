package splithttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

type closeLifecycleWriter struct {
	http.ResponseWriter
	writeStarted    chan struct{}
	allowWrite      chan struct{}
	deadlineStarted chan struct{}
	allowDeadline   chan struct{}
	writeOnce       sync.Once
	deadlineOnce    sync.Once
	deadlineCalls   atomic.Int32
	handlerReturned atomic.Bool
	lateDeadline    atomic.Bool
}

func (w *closeLifecycleWriter) Write(p []byte) (int, error) {
	close(w.writeStarted)
	<-w.allowWrite
	return w.ResponseWriter.Write(p)
}

func (w *closeLifecycleWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
}

func (w *closeLifecycleWriter) SetWriteDeadline(time.Time) error {
	if w.deadlineCalls.Add(1) == 1 {
		close(w.deadlineStarted)
		<-w.allowDeadline
	}
	if w.handlerReturned.Load() {
		w.lateDeadline.Store(true)
	}
	w.writeOnce.Do(func() { close(w.allowWrite) })
	return nil
}

func TestConcurrentCloseWaitsForDeadline(t *testing.T) {
	w := &closeLifecycleWriter{
		writeStarted: make(chan struct{}), allowWrite: make(chan struct{}),
		deadlineStarted: make(chan struct{}), allowDeadline: make(chan struct{}),
	}
	connection := make(chan *httpServerConn, 1)
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		w.ResponseWriter = writer
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		conn := &httpServerConn{Instance: done.New(), Reader: strings.NewReader(""), ResponseWriter: w}
		connection <- conn
		go func() { _, _ = conn.Write([]byte("download")) }()
		<-conn.Wait()
		select {
		case <-w.deadlineStarted:
		case <-request.Context().Done():
		}
		_ = conn.Close()
		w.handlerReturned.Store(true)
		close(handlerDone)
	}))
	defer server.Close()
	defer func() {
		w.deadlineOnce.Do(func() { close(w.allowDeadline) })
		w.writeOnce.Do(func() { close(w.allowWrite) })
	}()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	conn := <-connection
	<-w.writeStarted
	externalCloseDone := make(chan struct{})
	go func() { _ = conn.Close(); close(externalCloseDone) }()
	select {
	case <-w.deadlineStarted:
	case <-time.After(time.Second):
		t.Fatal("Close waited for the blocked writer without interrupting it")
	}
	responseDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, response.Body); close(responseDone) }()
	select {
	case <-responseDone:
	case <-time.After(time.Second):
	}
	w.deadlineOnce.Do(func() { close(w.allowDeadline) })
	<-externalCloseDone
	<-handlerDone
	<-responseDone
	if w.lateDeadline.Load() {
		t.Fatal("deadline call outlived ServeHTTP during concurrent Close")
	}
}
