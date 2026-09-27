//go:build ignore

// Standalone same-source control/candidate probe. It is not production code.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/task"

	"github.com/xtls/xray-core/core"
	featurestats "github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/proxy"
)

type object = map[string]any

var (
	probeZeroBuffer    bool
	installNativeGuard func(*core.Instance)
	verifyNativeGuard  func() map[string]int64
)

func port() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func start(inbound, outbound object, stats bool) *core.Instance {
	outbound["tag"] = "egress"
	c := object{"log": object{"loglevel": "none"}, "inbounds": []object{inbound}, "outbounds": []object{outbound}}
	if stats {
		c["stats"] = object{}
		c["policy"] = object{"system": object{"statsOutboundUplink": true, "statsOutboundDownlink": true}}
	}
	if probeZeroBuffer {
		p, ok := c["policy"].(object)
		if !ok {
			p = object{}
			c["policy"] = p
		}
		p["levels"] = object{"0": object{"bufferSize": 0}}
	}
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	s, err := core.StartInstance("json", b)
	if err != nil {
		panic(err)
	}
	return s
}

func main() {
	task.E1TraceHook = traceWork
	scenario := flag.String("scenario", "socks", "socks, trojan, ss, vless")
	count := flag.Int("n", 100, "complete application exchanges")
	size := flag.Int("size", 1024, "payload bytes per direction")
	stats := flag.Bool("stats", false, "native outbound statistics")
	warmups := flag.Int("warmup", 1, "fully joined warmup flows")
	greeting := flag.Bool("greeting", false, "server-first response before client payload")
	coalesce := flag.Bool("coalesce", false, "Trojan handshake and payload in one write")
	sniff := flag.Bool("sniff", false, "enable real inbound content sniffing")
	flag.BoolVar(&probeZeroBuffer, "zero-buffer", false, "exercise valid zero buffer policy")
	flag.Parse()
	if *count < 1 || *size < 1 {
		panic("positive n and size required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	target := listener.Addr().String()
	var handlers sync.WaitGroup
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			handlers.Add(1)
			echoEnd := task.E1Work("echo")
			go func() {
				defer echoEnd()
				defer handlers.Done()
				defer c.Close()
				if *greeting {
					c.Write([]byte("ready"))
				}
				io.Copy(c, c)
			}()
		}
	}()
	front := port()
	in := object{"listen": "127.0.0.1", "port": front, "protocol": "socks", "settings": object{"auth": "noauth", "udp": false}}
	if *sniff {
		in["sniffing"] = object{"enabled": true, "destOverride": []string{"http", "tls"}}
	}
	direct := object{"protocol": "freedom", "settings": object{"finalRules": []object{{"action": "allow"}}}}
	out := direct
	const password = "e1-local-test-only"
	const id = "a684455c-b14f-4ae5-9c3f-3422df8cd238"
	if *scenario == "trojan" {
		in["protocol"] = "trojan"
		in["settings"] = object{"clients": []object{{"password": password}}}
	}
	if *scenario == "ss" || *scenario == "vless" {
		remote := port()
		peerIn := object{"listen": "127.0.0.1", "port": remote, "protocol": "shadowsocks", "settings": object{"method": "aes-128-gcm", "password": password, "network": "tcp"}}
		out = object{"protocol": "shadowsocks", "settings": object{"servers": []object{{"address": "127.0.0.1", "port": remote, "method": "aes-128-gcm", "password": password}}}}
		if *scenario == "vless" {
			peerIn["protocol"] = "vless"
			peerIn["settings"] = object{"clients": []object{{"id": id}}, "decryption": "none"}
			out = object{"protocol": "vless", "settings": object{"vnext": []object{{"address": "127.0.0.1", "port": remote, "users": []object{{"id": id, "encryption": "none"}}}}}}
		}
		peer := start(peerIn, direct, *stats)
		defer peer.Close()
	}
	server := start(in, out, *stats)
	defer server.Close()
	if installNativeGuard != nil {
		installNativeGuard(server)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", front)
	payload := make([]byte, *size)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	run := func() {
		var c net.Conn
		var err error
		if *scenario == "trojan" {
			c, err = net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				panic(err)
			}
			hash := sha256.Sum224([]byte(password))
			header := []byte(hex.EncodeToString(hash[:]) + "\r\n")
			header = append(header, 1, 1, 127, 0, 0, 1)
			var p [2]byte
			binary.BigEndian.PutUint16(p[:], uint16(listener.Addr().(*net.TCPAddr).Port))
			header = append(header, p[:]...)
			header = append(header, '\r', '\n')
			if *coalesce {
				header = append(header, payload...)
			}
			if _, err = c.Write(header); err != nil {
				panic(err)
			}
		} else {
			d, e := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: 3 * time.Second})
			if e != nil {
				panic(e)
			}
			c, err = d.Dial("tcp", target)
			if err != nil {
				panic(err)
			}
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if *greeting {
			p := make([]byte, 5)
			if _, err := io.ReadFull(c, p); err != nil || string(p) != "ready" {
				panic(fmt.Sprintf("silent startup greeting %q: %v", p, err))
			}
		}
		written := make(chan error, 1)
		go func() {
			left := payload
			if *scenario == "trojan" && *coalesce {
				left = nil
			}
			for len(left) > 0 {
				n, e := c.Write(left)
				if e != nil {
					written <- e
					return
				}
				if n == 0 {
					written <- io.ErrShortWrite
					return
				}
				left = left[n:]
			}
			if cw, ok := c.(interface{ CloseWrite() error }); ok {
				written <- cw.CloseWrite()
			} else {
				written <- nil
			}
		}()
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(c, reply); err != nil {
			panic(err)
		}
		for i := range reply {
			if reply[i] != payload[i] {
				panic("payload mismatch")
			}
		}
		if err = <-written; err != nil {
			panic(err)
		}
		// Request/response completion only; this is not a whole-runtime join receipt.
	}
	runJoined := func() {
		f := beginFlow()
		run()
		f.wg.Done()
		done := make(chan struct{})
		go func() { f.wg.Wait(); close(done) }()
		deadline := time.NewTimer(10 * time.Second)
		select {
		case <-done:
			deadline.Stop()
		case <-deadline.C:
			panic(fmt.Sprintf("payload workers did not join: %v", f.counts()))
		}
		endFlow(f, *scenario)
	}
	for i := 0; i < *warmups; i++ {
		runJoined()
	}
	// No settlement sleep: payload worker completion is observed.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	clearMeasured()
	started := time.Now()
	for i := 0; i < *count; i++ {
		runJoined()
	}
	elapsed := time.Since(started)
	// No settlement sleep: payload worker completion is observed.
	runtime.ReadMemStats(&after)
	var nativeUp, nativeDown int64
	if *stats {
		manager := server.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
		up := manager.GetCounter("outbound>>>egress>>>traffic>>>uplink")
		down := manager.GetCounter("outbound>>>egress>>>traffic>>>downlink")
		if up == nil || down == nil {
			panic("native outbound counters not installed")
		}
		nativeUp, nativeDown = up.Value(), down.Value()
		if nativeUp <= 0 || nativeDown <= 0 {
			// Preserve the known control counter defect as a reported outcome, not missing cost data.
		}
	}
	server.Close()
	listener.Close()
	done := make(chan struct{})
	go func() { handlers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		panic("local peer handlers did not end")
	}
	result := object{"scenario": *scenario, "n": *count, "payload": *size, "stats": *stats, "native_up_including_warmup": nativeUp, "native_down_including_warmup": nativeDown, "exchange_ns": elapsed.Nanoseconds(), "allocs": after.Mallocs - before.Mallocs, "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "boundary": "client flow + joined inbound/dispatch/task/echo payload workers and socket close; native timers reported separately", "go": runtime.Version(), "os": runtime.GOOS}
	result["server_first"] = *greeting
	result["coalesced"] = *coalesce
	result["sniff"] = *sniff
	result["zero_buffer"] = probeZeroBuffer
	if verifyNativeGuard != nil {
		result["native_guard"] = verifyNativeGuard()
	}
	result["trace_counts"] = measuredCounts
	result["native_timers_remaining_at_payload_end"] = measuredTimers
	result["instrumentation_events"] = measuredEvents
	result["warmups"] = *warmups
	result["native_counters_positive"] = !*stats || (nativeUp > 0 && nativeDown > 0)
	json.NewEncoder(os.Stdout).Encode(result)
}

// All tracing below is test-only and identical in the control and candidate.
type flowTrace struct {
	wg           sync.WaitGroup
	started      [5]atomic.Int64
	finished     [5]atomic.Int64
	timers       atomic.Int64
	timerCreated atomic.Int64
}

var (
	traceMu                        sync.Mutex
	activeFlow                     *flowTrace
	measuredCounts                 [5]int64
	measuredTimers, measuredEvents int64
)

func beginFlow() *flowTrace {
	f := new(flowTrace)
	f.wg.Add(1)
	traceMu.Lock()
	if activeFlow != nil {
		panic("overlapping measured flows")
	}
	activeFlow = f
	traceMu.Unlock()
	return f
}

func traceWork(kind string) func() {
	traceMu.Lock()
	f := activeFlow
	if f == nil {
		traceMu.Unlock()
		return func() {}
	}
	if kind == "timer" {
		f.timers.Add(1)
		f.timerCreated.Add(1)
		traceMu.Unlock()
		return func() { f.timers.Add(-1) }
	}
	index := 0
	switch kind {
	case "inbound":
		index = 0
	case "dispatch":
		index = 1
	case "task":
		index = 2
	case "echo":
		index = 3
	case "setup":
		index = 4
	default:
		panic(kind)
	}
	f.wg.Add(1)
	f.started[index].Add(1)
	traceMu.Unlock()
	return func() { f.finished[index].Add(1); f.wg.Done() }
}

func (f *flowTrace) counts() [5]int64 {
	var r [5]int64
	for i := range r {
		r[i] = f.started[i].Load() - f.finished[i].Load()
	}
	return r
}

func endFlow(f *flowTrace, scenario string) {
	expected := int64(1)
	if scenario == "ss" || scenario == "vless" {
		expected = 2
	}
	for _, i := range []int{0, 1, 4} {
		if f.started[i].Load() != expected {
			panic(fmt.Sprintf("missing admissions %d got%d want%d", i, f.started[i].Load(), expected))
		}
	}
	if f.started[3].Load() != 1 {
		panic("missing echo admission")
	}
	traceMu.Lock()
	if activeFlow != f {
		panic("flow identity")
	}
	activeFlow = nil
	traceMu.Unlock()
	for i := range measuredCounts {
		measuredCounts[i] += f.started[i].Load()
		measuredEvents += f.started[i].Load()
	}
	measuredTimers += f.timers.Load()
	measuredEvents += f.timerCreated.Load()
}
func clearMeasured() { measuredCounts = [5]int64{}; measuredTimers = 0; measuredEvents = 0 }
