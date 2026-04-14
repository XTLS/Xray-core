package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
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

func pct(vals []int64, p float64) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	if p <= 0 {
		return time.Duration(vals[0])
	}
	if p >= 100 {
		return time.Duration(vals[len(vals)-1])
	}
	i := int(float64(len(vals)-1) * (p / 100.0))
	return time.Duration(vals[i])
}

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:20809", "socks5 address")
	rawURL := flag.String("url", "http://127.0.0.1:18082/download?bytes=8m", "target url")
	method := flag.String("method", "GET", "GET or POST")
	bodyBytes := flag.String("body", "8m", "POST body size (bytes), e.g. 64m")
	c := flag.Int("c", 100, "concurrency")
	d := flag.Duration("d", 30*time.Second, "duration")
	timeout := flag.Duration("timeout", 30*time.Second, "per request timeout")
	insecureTLS := flag.Bool("k", true, "skip tls verify")
	flag.Parse()

	u, err := url.Parse(*rawURL)
	if err != nil {
		panic(err)
	}

	dialer, err := proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		panic(err)
	}

	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           func(ctx context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) },
		MaxIdleConns:          10240,
		MaxIdleConnsPerHost:   10240,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: *timeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: *insecureTLS},
		ForceAttemptHTTP2:     false,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   *timeout,
	}

	var bodyLen int64
	if strings.ToUpper(*method) == "POST" {
		bodyLen, err = parseBytes(*bodyBytes)
		if err != nil {
			panic(err)
		}
	}

	end := time.Now().Add(*d)

	var okCount int64
	var errCount int64
	var bytesCount int64
	var latMu sync.Mutex
	lat := make([]int64, 0, 200000)

	pat := make([]byte, 32768)
	for i := range pat {
		pat[i] = byte(i)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if time.Now().After(end) {
					return
				}
				reqCtx, cancel := context.WithTimeout(context.Background(), *timeout)
				t0 := time.Now()
				var req *http.Request
				if strings.ToUpper(*method) == "POST" {
					rr := &repeatReader{p: pat}
					req, err = http.NewRequestWithContext(reqCtx, "POST", u.String(), io.LimitReader(rr, bodyLen))
					if err != nil {
						cancel()
						atomic.AddInt64(&errCount, 1)
						continue
					}
				} else {
					req, err = http.NewRequestWithContext(reqCtx, "GET", u.String(), nil)
					if err != nil {
						cancel()
						atomic.AddInt64(&errCount, 1)
						continue
					}
				}

				resp, err := client.Do(req)
				if err != nil {
					cancel()
					atomic.AddInt64(&errCount, 1)
					continue
				}
				n, cerr := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				cancel()
				if cerr != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				atomic.AddInt64(&okCount, 1)
				atomic.AddInt64(&bytesCount, n)
				elapsed := time.Since(t0)
				latMu.Lock()
				if len(lat) < cap(lat) {
					lat = append(lat, int64(elapsed))
				}
				latMu.Unlock()
			}
		}()
	}
	wg.Wait()
	dur := time.Since(start)

	latMu.Lock()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50 := pct(lat, 50)
	p90 := pct(lat, 90)
	p99 := pct(lat, 99)
	latMu.Unlock()

	ok := atomic.LoadInt64(&okCount)
	er := atomic.LoadInt64(&errCount)
	bt := atomic.LoadInt64(&bytesCount)
	mbps := float64(bt) / (1024 * 1024) / dur.Seconds()
	rps := float64(ok) / dur.Seconds()
	fmt.Printf("method=%s url=%s socks=%s\n", strings.ToUpper(*method), u.String(), *socksAddr)
	fmt.Printf("duration=%s concurrency=%d timeout=%s\n", dur.Truncate(time.Millisecond), *c, timeout.String())
	fmt.Printf("ok=%d err=%d rps=%.2f bytes=%d MiB/s=%.2f\n", ok, er, rps, bt, mbps)
	if len(lat) > 0 {
		fmt.Printf("latency p50=%s p90=%s p99=%s (samples=%d)\n", p50.Truncate(time.Millisecond), p90.Truncate(time.Millisecond), p99.Truncate(time.Millisecond), len(lat))
	}
}
