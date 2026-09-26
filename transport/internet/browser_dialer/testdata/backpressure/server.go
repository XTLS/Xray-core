package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	xrayws "github.com/xtls/xray-core/transport/internet/websocket"
)

type countedConn struct {
	net.Conn
	bytes *atomic.Int64
}

func (c countedConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.bytes.Add(int64(n))
	return n, e
}

type countedListener struct {
	net.Listener
	bytes *atomic.Int64
}

func (l countedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return countedConn{c, l.bytes}, nil
}

func main() {
	html := flag.String("html", "", "Browser Dialer HTML")
	size := flag.Int64("bytes", 256<<20, "response bytes")
	legacy := flag.Bool("legacy", false, "use the original raw DialGet reader")
	flag.Parse()
	page, e := os.ReadFile(*html)
	if e != nil {
		panic(e)
	}
	var wire, written, received, gets, protocol atomic.Int64
	var ended atomic.Bool
	var activeMu sync.Mutex
	var active io.ReadCloser
	resume := make(chan struct{})
	var resumeOnce sync.Once
	result := struct {
		sync.Mutex
		Hash     string
		Complete bool
	}{}
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		protocol.Store(int64(r.ProtoMajor))
		defer ended.Store(true)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(*size))
		for written.Load() < *size {
			n, err := w.Write(payload[:min(int64(len(payload)), *size-written.Load())])
			written.Add(int64(n))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	origin.EnableHTTP2 = true
	origin.Listener = countedListener{origin.Listener, &wire}
	origin.StartTLS()
	defer origin.Close()
	dialerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	dialerAddr := dialerListener.Addr().String()
	dialerListener.Close()
	os.Setenv("XRAY_BROWSER_DIALER", dialerAddr)
	browser_dialer.Reload()
	var actualPage []byte
	for i := 0; i < 100; i++ {
		response, err := http.Get("http://" + dialerAddr)
		if err == nil {
			actualPage, _ = io.ReadAll(response.Body)
			response.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	tokenStart := strings.Index(string(actualPage), "/websocket?token=") + len("/websocket?token=")
	if tokenStart < len("/websocket?token=") {
		panic("dialer page unavailable")
	}
	token := strings.SplitN(string(actualPage)[tokenStart:], "\"", 2)[0]
	page = []byte(strings.ReplaceAll(string(page), "csrfToken", token))
	dialerURL, _ := url.Parse("http://" + dialerAddr)
	mux := http.NewServeMux()
	mux.Handle("/websocket", httputil.NewSingleHostReverseProxy(dialerURL))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(page)
	})
	go func() {
		var stream io.ReadCloser
		if *legacy {
			conn, err := browser_dialer.DialGet(origin.URL, http.Header{"Accept": {"*/*"}}, nil)
			if err != nil {
				panic(err)
			}
			stream = xrayws.NewConnection(conn, conn.RemoteAddr(), nil, 0)
		} else {
			var err error
			stream, _, _, err = browser_dialer.DialGetStream(origin.URL, http.Header{"Accept": {"*/*"}}, nil)
			if err != nil {
				panic(err)
			}
		}
		defer stream.Close()
		activeMu.Lock()
		active = stream
		activeMu.Unlock()
		<-resume
		hash := sha256.New()
		buffer := make([]byte, 32768)
		for {
			n, err := stream.Read(buffer)
			if n > 0 {
				received.Add(int64(n))
				hash.Write(buffer[:n])
			}
			if err != nil {
				break
			}
		}
		result.Lock()
		result.Hash = hex.EncodeToString(hash.Sum(nil))
		result.Complete = true
		result.Unlock()
	}()
	mux.HandleFunc("/resume", func(w http.ResponseWriter, r *http.Request) {
		resumeOnce.Do(func() { close(resume) })
		w.WriteHeader(204)
	})
	mux.HandleFunc("/abort", func(w http.ResponseWriter, r *http.Request) {
		activeMu.Lock()
		if active != nil {
			active.Close()
		}
		activeMu.Unlock()
		resumeOnce.Do(func() { close(resume) })
		w.WriteHeader(204)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		result.Lock()
		defer result.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"wireBytes": wire.Load(), "bodyBytes": written.Load(), "receivedBytes": received.Load(), "gets": gets.Load(), "httpMajor": protocol.Load(), "ended": ended.Load(), "hash": result.Hash, "complete": result.Complete})
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println("http://" + listener.Addr().String())
	go func() { io.Copy(io.Discard, os.Stdin); time.Sleep(100 * time.Millisecond); os.Exit(0) }()
	http.Serve(listener, mux)
}
