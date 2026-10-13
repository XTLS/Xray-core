package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"
)

// These helpers keep state tests independent from the packet/stack regressions.
func stateIPv4Fragment(id uint16, offset int, more bool, data []byte) []byte {
	b := make([]byte, ipv4HeaderSize+len(data))
	b[0], b[8], b[9] = 0x45, 64, protoUDP
	b[12], b[16] = 10, 11
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:], id)
	bits := uint16(offset / 8)
	if more {
		bits |= 0x2000
	}
	binary.BigEndian.PutUint16(b[6:], bits)
	copy(b[ipv4HeaderSize:], data)
	return b
}

func stateIPv6Fragment(id uint32, offset int, more bool, next byte, data []byte) []byte {
	b := make([]byte, ipv6HeaderSize+8+len(data))
	b[0], b[6], b[7], b[8], b[24] = 0x60, 44, 64, 0x20, 0x30
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)-ipv6HeaderSize))
	b[40] = next
	bits := uint16(offset)
	if more {
		bits |= 1
	}
	binary.BigEndian.PutUint16(b[42:], bits)
	binary.BigEndian.PutUint32(b[44:], id)
	copy(b[48:], data)
	return b
}

func TestFragmentStateExpiryAndDuplicates(t *testing.T) {
	var r fragmentReassembler
	defer r.close()
	now := time.Now()
	first := stateIPv4Fragment(1, 0, true, make([]byte, 8))
	r.processAt(first, now)
	f, _ := readIPFragment(first)
	s := r.sets[f.key]
	retained := r.retained
	r.processAt(first, now.Add(59*time.Second))
	if r.retained != retained || !s.expires.Equal(now.Add(fragmentLifetime)) {
		t.Fatal("duplicate changed the allocation budget or first-arrival deadline")
	}
	r.mu.Lock()
	r.expireLocked(now.Add(fragmentLifetime))
	r.armLocked()
	r.mu.Unlock()
	if len(r.sets) != 0 || r.retained != 0 || r.timer != nil {
		t.Fatal("expiry retained state or timer")
	}
}

func TestFragmentStateOverlapTombstone(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			var r fragmentReassembler
			defer r.close()
			now := time.Now()
			makeFragment := func(offset int, more bool, data []byte) []byte {
				if ipv6 {
					return stateIPv6Fragment(1, offset, more, protoUDP, data)
				}
				return stateIPv4Fragment(1, offset, more, data)
			}
			first := makeFragment(0, true, make([]byte, 16))
			r.processAt(first, now)
			r.processAt(makeFragment(8, false, make([]byte, 16)), now.Add(time.Second))
			f, _ := readIPFragment(first)
			s := r.sets[f.key]
			if s == nil || !s.rejected || s.header != nil || s.pieces != nil {
				t.Fatal("overlap did not discard payload and preserve a tombstone")
			}
			if r.processAt(first, now.Add(2*time.Second)) != nil || r.processAt(makeFragment(16, false, make([]byte, 8)), now.Add(3*time.Second)) != nil {
				t.Fatal("rejected datagram resurrected before its deadline")
			}
			if !s.expires.Equal(now.Add(fragmentLifetime)) {
				t.Fatal("overlap refreshed deadline")
			}
			r.processAt(first, now.Add(fragmentLifetime))
			if got := r.processAt(makeFragment(16, false, make([]byte, 8)), now.Add(fragmentLifetime)); got == nil {
				t.Fatal("key could not be reused after original deadline")
			}
		})
	}
}

func TestFragmentStateBounds(t *testing.T) {
	t.Run("keys include tombstones", func(t *testing.T) {
		var r fragmentReassembler
		defer r.close()
		now := time.Now()
		for id := range fragmentKeys {
			// Misaligned MF payload creates a rejection tombstone immediately.
			r.processAt(stateIPv4Fragment(uint16(id), 0, true, []byte{1}), now)
		}
		r.processAt(stateIPv4Fragment(fragmentKeys, 0, true, make([]byte, 8)), now)
		if len(r.sets) != fragmentKeys {
			t.Fatalf("key budget: %d", len(r.sets))
		}
	})
	t.Run("retained capacities", func(t *testing.T) {
		var r fragmentReassembler
		defer r.close()
		now := time.Now()
		data := make([]byte, 32768)
		rejected := false
		for id := range fragmentKeys {
			b := stateIPv4Fragment(uint16(id), 0, true, data)
			r.processAt(b, now)
			f, _ := readIPFragment(b)
			rejected = rejected || r.sets[f.key].rejected
			if r.retained > fragmentBytes {
				t.Fatalf("retained budget exceeded: %d", r.retained)
			}
		}
		if !rejected {
			t.Fatal("byte limit did not reject any set")
		}
	})
	t.Run("pieces and sparse offsets", func(t *testing.T) {
		var r fragmentReassembler
		defer r.close()
		now := time.Now()
		for i := range fragmentPieces + 1 {
			r.processAt(stateIPv4Fragment(1, i*8, true, make([]byte, 8)), now)
		}
		f, _ := readIPFragment(stateIPv4Fragment(1, 0, true, make([]byte, 8)))
		if !r.sets[f.key].rejected {
			t.Fatal("fragment count exceeded")
		}
		r.processAt(stateIPv4Fragment(2, 65000, true, make([]byte, 8)), now)
		if r.retained > 4096 {
			t.Fatalf("sparse offset allocated a gap: %d", r.retained)
		}
	})
}

func TestFragmentStateAtomicIndependence(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		var r fragmentReassembler
		now := time.Now()
		first := stateIPv6Fragment(1, 0, true, protoUDP, make([]byte, 16))
		r.processAt(first, now)
		if rejected {
			r.processAt(stateIPv6Fragment(1, 8, false, protoUDP, make([]byte, 16)), now)
		}
		f, _ := readIPFragment(first)
		s, retained := r.sets[f.key], r.retained
		data := []byte{1, 2, 3, 4, 0, 8, 0, 0}
		got := r.processAt(stateIPv6Fragment(1, 0, false, protoUDP, data), now)
		if got == nil || !bytes.Equal(got[40:], data) || got[6] != protoUDP || r.sets[f.key] != s || r.retained != retained {
			t.Fatal("atomic fragment consulted or altered matching state")
		}
		r.close()
	}
}

func TestFragmentStateIPv6FirstHeaderAndKey(t *testing.T) {
	var r fragmentReassembler
	defer r.close()
	now := time.Now()
	// A later fragment may carry a different Fragment NH and a different prefix.
	tail := stateIPv6Fragment(1, 8, false, protoTCP, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	r.processAt(tail, now)
	first := stateIPv6Fragment(1, 0, true, protoUDP, make([]byte, 8))
	withPrefix := make([]byte, len(first)+8)
	copy(withPrefix, first[:40])
	withPrefix[6], withPrefix[40] = 60, 44
	copy(withPrefix[48:], first[40:])
	binary.BigEndian.PutUint16(withPrefix[4:], uint16(len(withPrefix)-40))
	got := r.processAt(withPrefix, now)
	if got == nil || got[6] != 60 || got[40] != protoUDP || len(got) != 64 || !bytes.Equal(got[56:], tail[48:]) {
		t.Fatal("first fragment did not own the retained header chain")
	}
	if p, ok := parsePacket(got); !ok || p.proto != protoUDP || len(p.payload) != 16 {
		t.Fatal("reconstructed extension chain did not use the existing parser")
	}
}

func TestFragmentStateValidation(t *testing.T) {
	cases := map[string][]byte{
		"IPv4 alignment":               stateIPv4Fragment(1, 0, true, make([]byte, 9)),
		"IPv4 range":                   stateIPv4Fragment(1, 65528, false, make([]byte, 8)),
		"IPv6 alignment":               stateIPv6Fragment(1, 0, true, protoUDP, make([]byte, 9)),
		"IPv6 range":                   stateIPv6Fragment(1, 65528, false, protoUDP, make([]byte, 8)),
		"IPv6 incomplete upper header": stateIPv6Fragment(1, 0, true, protoTCP, make([]byte, 8)),
		"IPv6 nested fragment":         stateIPv6Fragment(1, 0, true, 44, make([]byte, 8)),
		"IPv6 incomplete extension":    stateIPv6Fragment(1, 0, true, 60, []byte{protoUDP, 1, 0, 0, 0, 0, 0, 0}),
	}
	truncated := stateIPv4Fragment(1, 0, true, make([]byte, 16))
	cases["IPv4 truncated"] = truncated[:len(truncated)-1]
	truncated6 := stateIPv6Fragment(1, 0, true, protoUDP, make([]byte, 16))
	cases["IPv6 truncated"] = truncated6[:len(truncated6)-1]
	reserved := stateIPv6Fragment(1, 0, true, protoUDP, make([]byte, 8))
	reserved[43] |= 2
	cases["IPv6 reserved bits"] = reserved
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			var r fragmentReassembler
			defer r.close()
			if r.process(b) != nil {
				t.Fatal("invalid fragment accepted")
			}
			f, _ := readIPFragment(b)
			if s := r.sets[f.key]; s == nil || !s.rejected {
				t.Fatal("invalid fragment did not reject its key")
			}
		})
	}
}

func TestFragmentStateCloseConcurrent(t *testing.T) {
	var r fragmentReassembler
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				r.process(stateIPv4Fragment(uint16(worker*100+i), 0, true, make([]byte, 8)))
			}
		}()
	}
	r.close()
	wg.Wait()
	r.close()
	if !r.closed.Load() || r.sets != nil || r.retained != 0 || r.timer != nil {
		t.Fatal("close did not seal admission and release state")
	}
	if r.process(stateIPv6Fragment(1, 0, false, protoUDP, make([]byte, 8))) != nil {
		t.Fatal("closed owner accepted atomic fragment")
	}
}

func TestFragmentStateFinalLength(t *testing.T) {
	for _, tailFirst := range []bool{false, true} {
		var r fragmentReassembler
		now := time.Now()
		first := stateIPv4Fragment(1, 0, true, make([]byte, 16))
		shortTail := stateIPv4Fragment(1, 8, false, make([]byte, 8))
		if tailFirst {
			r.processAt(shortTail, now)
			r.processAt(first, now)
		} else {
			r.processAt(first, now)
			r.processAt(shortTail, now)
		}
		f, _ := readIPFragment(first)
		if !r.sets[f.key].rejected {
			t.Fatal("inconsistent final length was accepted")
		}
		r.close()
	}
	var r fragmentReassembler
	defer r.close()
	now := time.Now()
	r.processAt(stateIPv4Fragment(2, 24, false, make([]byte, 8)), now)
	otherTail := stateIPv4Fragment(2, 8, false, make([]byte, 8))
	r.processAt(otherTail, now)
	f, _ := readIPFragment(otherTail)
	if !r.sets[f.key].rejected {
		t.Fatal("two different final lengths were accepted")
	}
}

func TestFragmentStateIPv4OptionsAndProtocolKey(t *testing.T) {
	var r fragmentReassembler
	defer r.close()
	now := time.Now()
	first := stateIPv4Fragment(1, 0, true, make([]byte, 8))
	withOptions := make([]byte, len(first)+4)
	copy(withOptions, first[:20])
	withOptions[0] = 0x46
	copy(withOptions[20:24], []byte{1, 1, 1, 0})
	copy(withOptions[24:], first[20:])
	binary.BigEndian.PutUint16(withOptions[2:], uint16(len(withOptions)))
	r.processAt(withOptions, now)
	tcp := stateIPv4Fragment(1, 8, false, make([]byte, 8))
	tcp[9] = protoTCP
	if r.processAt(tcp, now) != nil || len(r.sets) != 2 {
		t.Fatal("IPv4 protocol was omitted from key")
	}
	got := r.processAt(stateIPv4Fragment(1, 8, false, make([]byte, 8)), now)
	if got == nil || len(got) != 40 || got[0] != 0x46 || !bytes.Equal(got[20:24], withOptions[20:24]) || checksum(sum(got[:24], 0)) != 0 || binary.BigEndian.Uint16(got[6:]) != 0 {
		t.Fatal("IPv4 options/length/flags/checksum were not reconstructed")
	}
}

func TestFragmentStateTimerExpiry(t *testing.T) {
	var r fragmentReassembler
	defer r.close()
	first := stateIPv4Fragment(1, 0, true, make([]byte, 8))
	second := stateIPv4Fragment(2, 0, true, make([]byte, 8))
	r.process(first)
	r.process(second)
	f1, _ := readIPFragment(first)
	f2, _ := readIPFragment(second)
	r.mu.Lock()
	r.sets[f1.key].expires = time.Now().Add(10 * time.Millisecond)
	r.sets[f2.key].expires = time.Now().Add(time.Hour)
	r.armLocked()
	r.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		_, firstPending := r.sets[f1.key]
		secondSet := r.sets[f2.key]
		correctTimer := secondSet != nil && r.timer != nil && r.deadline.Equal(secondSet.expires)
		r.mu.Unlock()
		if !firstPending {
			if !correctTimer {
				t.Fatal("expiry did not advance the timer to the next first-arrival deadline")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("idle fragment did not expire without incoming traffic")
}

// The second read is a barrier: the real stack.read has finished handling the
// first packet before it asks this Tun for another. EOF is independently gated.
type fragmentStateTun struct {
	packet   []byte
	ingested chan struct{}
	stop     chan struct{}
	first    bool
	once     sync.Once
}

func (f *fragmentStateTun) Start() error          { return nil }
func (f *fragmentStateTun) Name() (string, error) { return "fragment-state", nil }
func (f *fragmentStateTun) Index() (int, error)   { return 1, nil }
func (f *fragmentStateTun) WritePacket([]byte, []byte) error {
	return nil
}

func (f *fragmentStateTun) Close() error {
	f.once.Do(func() { close(f.stop) })
	return nil
}

func (f *fragmentStateTun) ReadPacket(b []byte) ([]byte, error) {
	if !f.first {
		f.first = true
		return b[:copy(b, f.packet)], nil
	}
	close(f.ingested)
	<-f.stop
	return nil, io.EOF
}

func newFragmentStateStack(t *testing.T) (*stack, *fragmentStateTun, <-chan struct{}) {
	t.Helper()
	device := &fragmentStateTun{
		packet:   stateIPv4Fragment(1, 0, true, make([]byte, 8)),
		ingested: make(chan struct{}), stop: make(chan struct{}),
	}
	created, err := NewStack(context.Background(), StackOptions{Tun: device, MTU: testMTU}, &Handler{})
	if err != nil {
		t.Fatal(err)
	}
	s := created.(*stack)
	readExited := make(chan struct{})
	// Run the same read loop that Start launches, with an explicit completion
	// signal after its defers. ReadPacket returning EOF alone is not that signal.
	go func() {
		s.read()
		close(readExited)
	}()
	t.Cleanup(func() {
		_ = s.Close()
		_ = device.Close()
		select {
		case <-readExited:
		case <-time.After(5 * time.Second):
			t.Error("stack read did not finish after Tun closure")
		}
	})
	select {
	case <-device.ingested:
	case <-time.After(5 * time.Second):
		t.Fatal("stack did not ingest the pending fragment")
	}
	return s, device, readExited
}

func TestFragmentStateStackCleanup(t *testing.T) {
	for _, readError := range []bool{false, true} {
		name := "Close while read is blocked"
		if readError {
			name = "ReadPacket error"
		}
		t.Run(name, func(t *testing.T) {
			s, device, readExited := newFragmentStateStack(t)
			r := &s.fragments
			r.mu.Lock()
			pending := !r.closed.Load() && len(r.sets) == 1 && r.retained > 0 && r.timer != nil
			timer := r.timer
			r.mu.Unlock()
			if !pending {
				t.Fatal("real stack did not retain pending fragment data and timer")
			}
			if readError {
				// Trigger only the Tun error, without calling stack.Close. Observe
				// the asynchronous read exit after its cleanup defer has executed.
				if err := device.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-readExited:
				case <-time.After(5 * time.Second):
					t.Fatal("read-error cleanup did not finish promptly")
				}
			} else {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-readExited:
					t.Fatal("stack.Close test did not keep Tun read independently blocked")
				default:
				}
			}
			r.mu.Lock()
			released := r.closed.Load() && r.sets == nil && r.retained == 0 && r.timer == nil && r.deadline.IsZero()
			r.mu.Unlock()
			if !released {
				t.Fatal("stack lifecycle hook did not seal and release fragment ownership")
			}
			if timer.Stop() {
				t.Fatal("stack lifecycle hook left the first-arrival timer active")
			}
			if r.process(stateIPv4Fragment(2, 0, true, make([]byte, 8))) != nil || r.process(stateIPv6Fragment(2, 0, false, protoUDP, make([]byte, 8))) != nil {
				t.Fatal("stack lifecycle hook did not seal ordinary/atomic fragment admission")
			}
		})
	}
}

func TestFragmentStateUnfragmentedNoAllocations(t *testing.T) {
	packets := map[string][]byte{
		"IPv4": stateIPv4Fragment(1, 0, false, make([]byte, 8)),
		"IPv6": make([]byte, ipv6HeaderSize+8),
	}
	packets["IPv6"][0], packets["IPv6"][6] = 0x60, protoUDP
	binary.BigEndian.PutUint16(packets["IPv6"][4:], 8)
	for name, packet := range packets {
		t.Run(name, func(t *testing.T) {
			var r fragmentReassembler
			defer r.close()
			var got []byte
			allocations := testing.AllocsPerRun(1000, func() {
				got = r.process(packet)
			})
			if allocations != 0 {
				t.Fatalf("unfragmented processing allocated: %g allocations per run", allocations)
			}
			if len(got) != len(packet) || &got[0] != &packet[0] || r.sets != nil || r.retained != 0 || r.timer != nil {
				t.Fatal("unfragmented processing changed packet custody or activated reassembly state")
			}
		})
	}
}
