package splithttp

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

func TestAcceptsGzip(t *testing.T) {
	cases := map[string]bool{
		"":                    false,
		"identity":            false,
		"gzip":                true,
		"gzip, deflate, br":   true,
		"br, GZIP;q=0.5":      true,
		"x-gzip":              true,
		"gzip;q=0":            false,
		"gzip; q=0.000":       false,
		"*":                   true,
		"*;q=0":               false,
		"gzip;q=0, *;q=1":     false,
		"*;q=0, gzip":         true,
		"identity;q=1, *;q=0": false,
		"gzip;q=1":            true,
		"gzip;q=abc":          false,
		"gzip;q=2":            false,
		"gzip;q=-1":           false,
		"gzip;q=NaN":          false,
		"*;q=abc":             false,
		"gzip;level=1;q=0":    false,
		"gzip;Q=0":            false,
	}
	for in, want := range cases {
		if got := acceptsGzip(in); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", in, got, want)
		}
	}
}

type countingWriter struct {
	http.ResponseWriter
	n atomic.Int64
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.n.Add(int64(n))
	return n, err
}

func (w *countingWriter) Flush() { w.ResponseWriter.(http.Flusher).Flush() }

const testHeartbeats = 3

// sends "hello ", waits until testHeartbeats empty blocks went out, sends "world"
func gzipTestServer(t *testing.T, force bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w := &countingWriter{ResponseWriter: rw}
		useGzip := force || acceptsGzip(r.Header.Get("Accept-Encoding"))
		if useGzip {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.WriteHeader(http.StatusOK)
		c := &httpServerConn{Instance: done.New(), Reader: r.Body, ResponseWriter: w}
		defer c.Close()
		if useGzip {
			if err := c.enableGzip(); err != nil {
				t.Error(err)
				return
			}
			go c.gzipHeartbeat(&RangeConfig{From: 10, To: 10})
		}
		c.Write([]byte("hello "))
		if useGzip {
			want := w.n.Load() + 5*testHeartbeats
			deadline := time.Now().Add(5 * time.Second)
			for w.n.Load() < want {
				if time.Now().After(deadline) {
					t.Error("no heartbeat")
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
		c.Write([]byte("world"))
		if useGzip {
			c.finishGzip()
		}
	}))
}

// the same stream without heartbeats: header, two writes (data block + empty
// block each), final block, trailer
const gzipBaselineLen = 10 + (5 + 6 + 5) + (5 + 5 + 5) + 5 + 8

func TestGzipHeartbeat(t *testing.T) {
	srv := gzipTestServer(t, false)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip") // no transparent decoding
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("no gzip")
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if extra := len(raw) - gzipBaselineLen; extra < 5*testHeartbeats {
		t.Fatalf("%d heartbeat bytes on the wire", extra)
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := io.ReadAll(gr); err != nil || string(out) != "hello world" {
		t.Fatalf("decoded %q, %v", out, err)
	}
}

func TestGzipHeartbeatForce(t *testing.T) {
	for _, force := range []bool{false, true} {
		srv := gzipTestServer(t, force)
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		srv.Close()
		if got := resp.Header.Get("Content-Encoding") == "gzip"; got != force {
			t.Fatalf("force=%v: gzip=%v", force, got)
		}
	}
}

func TestGzipHeartbeatStopsOnClose(t *testing.T) {
	c := &httpServerConn{Instance: done.New(), ResponseWriter: httptest.NewRecorder()}
	if err := c.enableGzip(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		c.gzipHeartbeat(&RangeConfig{From: 10, To: 10})
		close(exited)
	}()
	c.Close()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat goroutine still running after Close")
	}
}

type failingWriter struct {
	*httptest.ResponseRecorder
	fail atomic.Bool
}

func (w *failingWriter) Write(b []byte) (int, error) {
	if w.fail.Load() {
		return 0, io.ErrClosedPipe
	}
	return w.ResponseRecorder.Write(b)
}

func TestGzipHeartbeatClosesOnWriteError(t *testing.T) {
	w := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	c := &httpServerConn{Instance: done.New(), ResponseWriter: w}
	if err := c.enableGzip(); err != nil {
		t.Fatal(err)
	}
	w.fail.Store(true)
	go c.gzipHeartbeat(&RangeConfig{From: 10, To: 10})
	select {
	case <-c.Wait():
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed after heartbeat write error")
	}
}

func TestGzipWriter(t *testing.T) {
	data := make([]byte, 200000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	var raw bytes.Buffer
	g := &gzipWriter{w: &raw}
	raw.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	g.Write(data[:70000])
	g.block(false, nil)
	g.Write(data[70000:])
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	gr, err := gzip.NewReader(&raw)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := io.ReadAll(gr); err != nil || !bytes.Equal(out, data) {
		t.Fatalf("len %d, %v", len(out), err)
	}
}

// a block must be decodable before anything else arrives
func TestGzipWriterNoBuffering(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
		(&gzipWriter{w: pw}).Write([]byte("hello"))
	}()
	gr, err := gzip.NewReader(pr)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(gr, b)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil || string(b) != "hello" {
			t.Fatalf("%q, %v", b, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("block not decodable until more data arrives")
	}
	pw.Close()
}

type shortWriter struct{ max int }

func (w shortWriter) Write(b []byte) (int, error) { return min(len(b), w.max), nil }

func TestGzipWriterShortWrite(t *testing.T) {
	for _, max := range []int{3, 7} { // short block header, short payload
		g := &gzipWriter{w: shortWriter{max}}
		if _, err := g.Write([]byte("hello world")); err != io.ErrShortWrite {
			t.Errorf("max=%d: %v", max, err)
		}
	}
}
