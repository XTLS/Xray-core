//go:build !wasm
// +build !wasm

package buf

import "testing"

// TestAllocStrategyAdjust exercises every branch of allocStrategy.Adjust:
//   - n >= current  → doubles current
//   - n < current   → sets current = n
//   - current > 8   → caps to 8
//   - current == 0  → clamps to 1
func TestAllocStrategyAdjust(t *testing.T) {
	t.Run("doubles when n >= current", func(t *testing.T) {
		s := allocStrategy{current: 1}
		s.Adjust(1) // 1 >= 1 → 2
		if s.current != 2 {
			t.Fatalf("expected 2, got %d", s.current)
		}
	})

	t.Run("sets to n when n < current", func(t *testing.T) {
		s := allocStrategy{current: 4}
		s.Adjust(1) // 1 < 4 → s.current = 1
		if s.current != 1 {
			t.Fatalf("expected 1, got %d", s.current)
		}
	})

	t.Run("caps at 8 after doubling past 8", func(t *testing.T) {
		s := allocStrategy{current: 8}
		s.Adjust(8) // 8 >= 8 → doubles to 16 → capped to 8
		if s.current != 8 {
			t.Fatalf("expected 8, got %d", s.current)
		}
	})

	t.Run("clamps zero to 1", func(t *testing.T) {
		s := allocStrategy{current: 1}
		s.Adjust(0) // 0 < 1 → s.current = 0 → clamped to 1
		if s.current != 1 {
			t.Fatalf("expected 1, got %d", s.current)
		}
	})

	t.Run("sequential growth then shrink", func(t *testing.T) {
		s := allocStrategy{current: 1}
		// Drive the common warm-up progression used in production traffic.
		for want := uint32(2); want <= 8; want *= 2 {
			s.Adjust(s.current) // doubles each time
			if s.current != want {
				t.Fatalf("expected %d, got %d", want, s.current)
			}
		}
		// Now at 8; one more doubling attempt stays at 8
		s.Adjust(8)
		if s.current != 8 {
			t.Fatalf("expected 8 after cap, got %d", s.current)
		}
		// Shrink back
		// Simulate a low-byte read after prior growth.
		s.Adjust(3) // 3 < 8 → s.current = 3
		if s.current != 3 {
			t.Fatalf("expected 3, got %d", s.current)
		}
	})
}

// TestAllocStrategyAlloc verifies that Alloc() produces the right number of
// non-nil, freshly allocated Buffers.
func TestAllocStrategyAlloc(t *testing.T) {
	for _, n := range []uint32{1, 2, 4, 8} {
		s := allocStrategy{current: n}
		bs := s.Alloc()
		if uint32(len(bs)) != n {
			t.Fatalf("Alloc(%d): expected %d buffers, got %d", n, n, len(bs))
		}
		for i, b := range bs {
			if b == nil {
				t.Fatalf("Alloc(%d): buffer[%d] is nil", n, i)
			}
			// Release to avoid polluting shared buffer pools across test cases.
			b.Release()
		}
	}
}
