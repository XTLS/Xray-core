package noise

import (
	"testing"
)

func TestReplayWindow(t *testing.T) {
	for _, test := range []struct {
		before replayWindow
		nonce  uint64
		result bool
		after  replayWindow
	}{
		// The first message should always be accepted. This is the
		// only case where bitmap&1 == 0.
		{replayWindow{0x0, 0}, 0, true, replayWindow{0x1, 0}},
		{replayWindow{0x0, 0}, 1, true, replayWindow{0x1, 1}},
		{replayWindow{0x0, 0}, 2, true, replayWindow{0x1, 2}},
		{replayWindow{0x0, 0}, 10, true, replayWindow{0x1, 10}},

		// A second message with a nonce of 0 should be rejected.
		{replayWindow{0x1, 0}, 0, false, replayWindow{0x1, 0}},

		// Sequential nonces.
		{replayWindow{0x1, 0}, 1, true, replayWindow{0x3, 1}},
		{replayWindow{0x3, 1}, 2, true, replayWindow{0x7, 2}},
		// Jumping ahead in the sequence.
		{replayWindow{0x7, 2}, 10, true, replayWindow{0x701, 10}},
		// Past nonces that are still in-window.
		{replayWindow{0x701, 10}, 3, true, replayWindow{0x781, 10}},
		{replayWindow{0x781, 10}, 4, true, replayWindow{0x7c1, 10}},
		// Reject replay.
		{replayWindow{0x7c1, 10}, 2, false, replayWindow{0x7c1, 10}},
		// Jumping ahead to create another gap.
		{replayWindow{0x7c1, 10}, 18, true, replayWindow{0x7c101, 18}},
		// Continuing to fill in the first gap.
		{replayWindow{0x7c101, 18}, 5, true, replayWindow{0x7e101, 18}},
		{replayWindow{0x7e101, 18}, 6, true, replayWindow{0x7f101, 18}},

		// Jump ahead far enough to empty the bitmap.
		{replayWindow{^uint64(0), 100}, 200, true, replayWindow{0x1, 200}},
		// Just out of window.
		{replayWindow{0x1, 200}, 200 - 64, false, replayWindow{0x1, 200}},
		// Oldest nonce still in window.
		{replayWindow{0x1, 200}, 200 - 63, true, replayWindow{0x8000000000000001, 200}},
		// Replay of oldest nonce in window.
		{replayWindow{0x8000000000000001, 200}, 200 - 63, false, replayWindow{0x8000000000000001, 200}},
		// Advance by 1.
		{replayWindow{0x8000000000000001, 200}, 200 + 1, true, replayWindow{0x3, 201}},

		// Advance to maximum possible nonce.
		{replayWindow{0x0, 0}, ^uint64(0), true, replayWindow{0x1, ^uint64(0)}},
		{replayWindow{0x1234, 1234}, ^uint64(0), true, replayWindow{0x1, ^uint64(0)}},
		// Wraparound not allowed.
		{replayWindow{0x1, ^uint64(0)}, 0, false, replayWindow{0x1, ^uint64(0)}},
		{replayWindow{0x1, ^uint64(0)}, 1, false, replayWindow{0x1, ^uint64(0)}},
	} {
		rw := test.before
		result := rw.CheckAndUpdate(test.nonce)
		if result != test.result || rw != test.after {
			t.Errorf("%+v CheckAndUpdate(%v) → %v %+v, expected %v %+v",
				test.before, test.nonce, result, rw, test.result, test.after)
		}
	}
}
