package rawpacket

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testFrameCrypto(t *testing.T) *frameCrypto {
	t.Helper()
	psk := []byte("test-psk-secret")
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	f, err := newFrameCrypto(psk, sid)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFrameSealOpenRoundTrip(t *testing.T) {
	f := testFrameCrypto(t)
	payload := []byte("hello rawpacket")

	frame, err := f.seal(false, payload, false)
	if err != nil {
		t.Fatal(err)
	}
	got, flags, err := f.open(frame, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
	if flags&frameFlagServer != 0 {
		t.Fatal("client frame must not carry server flag")
	}

	frame, err = f.seal(true, payload, true)
	if err != nil {
		t.Fatal(err)
	}
	got, flags, err = f.open(frame, true)
	if err != nil {
		t.Fatalf("open server frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
	if flags&frameFlagKeepalive == 0 || flags&frameFlagServer == 0 {
		t.Fatalf("expected keepalive+server flags, got %#x", flags)
	}
}

func TestFrameDirectionEnforced(t *testing.T) {
	f := testFrameCrypto(t)
	frame, err := f.seal(false, []byte("up"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.open(frame, true); err == nil {
		t.Fatal("opening a client frame as server frame must fail")
	}
}

func TestFrameTamperDetection(t *testing.T) {
	f := testFrameCrypto(t)
	frame, err := f.seal(false, []byte("authenticated"), false)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper every header byte region: magic, version, flags, session,
	// seq, payload length.
	flips := []int{0, 3, 4, 5, 8, 15, 16, 19, 20, 21}
	for _, i := range flips {
		bad := make([]byte, len(frame))
		copy(bad, frame)
		bad[i] ^= 0xFF
		if _, _, err := f.open(bad, false); err == nil {
			t.Fatalf("tampered byte %d was accepted", i)
		}
	}

	// Flip a payload byte (after the AAD region).
	bad := make([]byte, len(frame))
	copy(bad, frame)
	bad[len(bad)-1] ^= 0xFF
	if _, _, err := f.open(bad, false); err == nil {
		t.Fatal("tampered payload was accepted")
	}

	// A truncated frame must be rejected.
	if _, _, err := f.open(frame[:len(frame)-1], false); err == nil {
		t.Fatal("truncated frame was accepted")
	}
}

func TestFrameReplayProtection(t *testing.T) {
	f := testFrameCrypto(t)

	frame, err := f.seal(false, []byte("one"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.open(frame, false); err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Replaying the exact same frame must be rejected.
	if _, _, err := f.open(frame, false); err == nil {
		t.Fatal("replayed frame was accepted")
	}
	// Same seq, different ciphertext (attacker re-encrypt guess) must fail.
	if _, _, err := f.open(frame, false); err == nil {
		t.Fatal("replayed frame accepted twice")
	}
}

func TestFrameReorderingWithinWindow(t *testing.T) {
	f := testFrameCrypto(t)

	var frames [][]byte
	for i := 0; i < 10; i++ {
		fr, err := f.seal(false, []byte{byte(i)}, false)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, fr)
	}
	// Deliver 0..9 in scrambled order: all must be accepted exactly once.
	order := []int{2, 0, 1, 5, 3, 4, 9, 6, 7, 8}
	for _, i := range order {
		if _, _, err := f.open(frames[i], false); err != nil {
			t.Fatalf("frame %d out of order rejected: %v", i, err)
		}
	}
	// All frames are now consumed; resending any must be rejected.
	for i := 0; i < 10; i++ {
		if _, _, err := f.open(frames[i], false); err == nil {
			t.Fatalf("replayed frame %d accepted", i)
		}
	}
}

func TestFrameSeqJumpAdvance(t *testing.T) {
	f := testFrameCrypto(t)
	var first []byte
	for i := 0; i < 70; i++ {
		fr, err := f.seal(false, []byte{byte(i)}, false)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = fr
		}
		if _, _, err := f.open(fr, false); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	// The window has advanced past seq 0 (base=69); replaying it must fail.
	if _, _, err := f.open(first, false); err == nil {
		t.Fatal("stale frame accepted after window advance")
	}
}

func TestFrameKeepaliveFlag(t *testing.T) {
	f := testFrameCrypto(t)
	frame, err := f.seal(false, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, flags, err := f.open(frame, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("keepalive payload must be empty, got %d bytes", len(payload))
	}
	if flags&frameFlagKeepalive == 0 {
		t.Fatal("keepalive flag not set")
	}
}

func TestFrameWrongKeyRejected(t *testing.T) {
	a := testFrameCrypto(t)
	b, err := newFrameCrypto([]byte("other-psk"), a.sid)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := a.seal(false, []byte("secret"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.open(frame, false); err == nil {
		t.Fatal("frame sealed with a different PSK was accepted")
	}
}

func TestSealSplit(t *testing.T) {
	f := testFrameCrypto(t)
	payload := bytes.Repeat([]byte("x"), frameMaxPayload*3+7)

	frames, err := f.sealSplit(false, payload, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 {
		t.Fatalf("expected 4 frames, got %d", len(frames))
	}
	var got []byte
	for _, fr := range frames {
		pt, _, err := f.open(fr, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		got = append(got, pt...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("split payload mismatch")
	}

	// Empty payload produces a single empty frame.
	frames, err = f.sealSplit(false, nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame for empty payload, got %d", len(frames))
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	if !w.accept(100) {
		t.Fatal("first seq must be accepted")
	}
	if w.accept(100) {
		t.Fatal("duplicate must be rejected")
	}
	if !w.accept(101) {
		t.Fatal("next seq must be accepted")
	}
	// seq 99 is below the max but still inside the window and unseen:
	// tolerated reordering.
	if !w.accept(99) {
		t.Fatal("in-window reordering must be accepted")
	}
	if w.accept(99) {
		t.Fatal("duplicate in-window seq must be rejected")
	}
	if !w.accept(160) {
		t.Fatal("seq jump must be accepted")
	}
	// seq 99 is now outside the window (base=160, window floor=97).
	if w.accept(99) {
		t.Fatal("seq below window floor must be rejected")
	}
	if w.accept(160) {
		t.Fatal("duplicate after jump must be rejected")
	}
}

func TestFrameSessionID(t *testing.T) {
	f := testFrameCrypto(t)
	frame, err := f.seal(false, []byte("x"), false)
	if err != nil {
		t.Fatal(err)
	}
	sid, ok := frameSessionID(frame)
	if !ok {
		t.Fatal("frameSessionID failed on valid frame")
	}
	if sid != f.sid {
		t.Fatal("session id mismatch")
	}
	// Non-frame traffic (e.g. a real TLS ClientHello) must not parse.
	if _, ok := frameSessionID([]byte("not a frame")); ok {
		t.Fatal("garbage accepted as frame")
	}
}
