package noise

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
)

// sessionPair returns a matched initiator and responder pair of Sessions.
func sessionPair() (*Session, *Session) {
	privkey, err := GeneratePrivkey()
	if err != nil {
		panic(err)
	}
	pubkey := PubkeyFromPrivkey(privkey)

	pre, initMsg, err := InitiateHandshake(nil, pubkey)
	if err != nil {
		panic(err)
	}

	resp, respMsg, err := AcceptHandshake(nil, initMsg, privkey)
	if err != nil {
		panic(err)
	}

	init, err := pre.FinishHandshake(respMsg)
	if err != nil {
		panic(err)
	}

	return init, resp
}

// roundtrip Encrypts payload and Decrypts it again using the given pair of
// Sessions, stopping at any intermediate error.
func roundtrip(init, resp *Session, payload []byte) ([]byte, error) {
	msg, err := init.Encrypt(nil, payload)
	if err != nil {
		return nil, err
	}
	return resp.Decrypt(nil, msg)
}

func TestSessionRoundtrip(t *testing.T) {
	payload := []byte("test")
	init, resp := sessionPair()

	p, err := roundtrip(init, resp, payload)
	if err != nil || !bytes.Equal(p, payload) {
		t.Errorf("Decrypt(Encrypt(%q)) → %q", payload, p)
	}

	init.send.SetNonce(12345678)
	p, err = roundtrip(init, resp, payload)
	if err != nil || !bytes.Equal(p, payload) {
		t.Errorf("Decrypt(Encrypt(%q)) → %q", payload, p)
	}

	// Try an empty payload.
	p, err = roundtrip(init, resp, []byte{})
	if err != nil || !bytes.Equal(p, []byte{}) {
		t.Errorf("Decrypt(Encrypt(%q)) → %q", []byte{}, p)
	}
}

func TestSessionReplay(t *testing.T) {
	payload := []byte("test")
	init, resp := sessionPair()

	for i, test := range []struct {
		nonce       uint64
		expectedErr error
	}{
		{100, nil},
		{100, ErrInvalidNonce},
		{100 - 64, ErrInvalidNonce},
		{100 - 63, nil},
		{noise.MaxNonce, nil},
		{noise.MaxNonce, ErrInvalidNonce},
	} {
		replayBefore := resp.replay
		init.send.SetNonce(test.nonce)
		p, err := roundtrip(init, resp, payload)
		if err != test.expectedErr {
			t.Errorf("%v %v → %v, expected %v", i, test.nonce, err, test.expectedErr)
		} else if err != nil && resp.replay != replayBefore {
			// Decrypt error should not alter the replay window.
			t.Errorf("%v %v → %+v, expected %+v", i, test.nonce, resp.replay, replayBefore)
		} else if err == nil && !bytes.Equal(p, payload) {
			t.Errorf("%v %v → %q, expected %q", i, test.nonce, p, payload)
		}
	}
}

func TestSessionDecryptError(t *testing.T) {
	init, resp := sessionPair()

	// Too short to contain a nonce.
	for _, n := range []int{0, 1, 7} {
		_, err := resp.Decrypt(nil, make([]byte, n))
		if err != errMissingNonce {
			t.Errorf("Decrypt([%v]byte) → %v, expected %v", n, err, errMissingNonce)
		}
	}

	// Long enough to contain a nonce, but no message after that.
	_, err := resp.Decrypt(nil, make([]byte, 8))
	if err == nil {
		t.Errorf("Decrypt([%v]byte) → %v, expected non-nil", 8, err)
	}

	msg, err := init.Encrypt(nil, []byte("test"))
	if err != nil {
		panic(err)
	}
	// Correct nonce, should work.
	_, err = resp.Decrypt(nil, msg)
	if err != nil {
		t.Errorf("Decrypt with correct nonce → %v, expected %v", err, nil)
	}
	// Alter the nonce and try again.
	msg[7] ^= 1
	_, err = resp.Decrypt(nil, msg)
	if err == nil {
		t.Errorf("Decrypt with tweaked nonce → %v, expected non-nil", err)
	}
}
