package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type repeatReader struct {
	p []byte
	i int
}

func (r *repeatReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n := 0
	for n < len(b) {
		if r.i == len(r.p) {
			r.i = 0
		}
		k := copy(b[n:], r.p[r.i:])
		r.i += k
		n += k
	}
	return n, nil
}

func parseBytes(v string) (int64, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return 0, fmt.Errorf("empty")
	}
	m := int64(1)
	switch {
	case strings.HasSuffix(v, "k"):
		m = 1024
		v = strings.TrimSuffix(v, "k")
	case strings.HasSuffix(v, "kb"):
		m = 1024
		v = strings.TrimSuffix(v, "kb")
	case strings.HasSuffix(v, "m"):
		m = 1024 * 1024
		v = strings.TrimSuffix(v, "m")
	case strings.HasSuffix(v, "mb"):
		m = 1024 * 1024
		v = strings.TrimSuffix(v, "mb")
	case strings.HasSuffix(v, "g"):
		m = 1024 * 1024 * 1024
		v = strings.TrimSuffix(v, "g")
	case strings.HasSuffix(v, "gb"):
		m = 1024 * 1024 * 1024
		v = strings.TrimSuffix(v, "gb")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative")
	}
	return n * m, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18082", "listen address")
	maxBody := flag.String("max-body", "2g", "max upload bytes")
	flag.Parse()

	maxBodyBytes, err := parseBytes(*maxBody)
	if err != nil {
		panic(err)
	}

	pat := make([]byte, 32768)
	for i := range pat {
		pat[i] = byte(i)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("bytes")
		if q == "" {
			q = "1m"
		}
		n, err := parseBytes(q)
		if err != nil {
			http.Error(w, "bad bytes", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		rr := &repeatReader{p: pat}
		_, _ = io.CopyN(w, rr, n)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		start := time.Now()
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "ok bytes=%d ms=%d\n", n, time.Since(start).Milliseconds())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})

	s := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Printf("xtessloadserver http://%s (download/upload)\n", *listen)
	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}

