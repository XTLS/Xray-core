/*
A Session represents a pair of Noise CipherState objects, one for receiving and
one for sending, resulting from a handshake. The Encrypt and Decrypt methods of
Session deal in Noise transport messages with prepended 64-bit big-endian
explicit nonces.

The procedure for getting a Session differs depending on whether you are the
initiator or the responder. As an initiator, call InitiateHandshake to get a
PreSession and an initiator handshake message to send, then call FinishHandshake
with the responder's handshake message to get a Session.
	pre, initMsg, err := InitiateHandshake(nil, pubkey)
	// err check
	// send initMsg to the responder
	// receive respMsg from the responder
	session, err := pre.FinishHandshake(respMsg)
	// err check
As a responder, receive the initiator's handshake message and call
AcceptHandshake on it to get a Session and a handshake message to send back to
the initiator.
	// receive initMsg from the initiator
	session, respMsg, err := AcceptHandshake(nil, initMsg, privkey)
	// err check
	// send respMsg to the initiator
*/
package noise

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/flynn/noise"
)

var errPayload = errors.New("unexpected payload in handshake message")
var errMissingNonce = errors.New("slice is too short to contain a nonce")
var ErrInvalidNonce = errors.New("nonce is already used or out of window")

// PreSession represents a partially initialized Session, from the point of view
// of an initiator that has sent its handshake message but has not yet received
// the responder's handshake message. Call FinishHandshake with the responder's
// handshake message to convert the PreSession into a full Session.
type PreSession struct {
	handshakeState *noise.HandshakeState
}

// Session represents an initialized Noise session, post-handshake with all
// necessary key material.
type Session struct {
	recv, send         *noise.CipherState
	recvLock, sendLock sync.Mutex
	replay             replayWindow
}

// InitiateHandshake prepares a PreSession and returns an initiator handshake
// message to be sent to the responder. out is a byte slice (may be nil) to
// which the handshake message will be appended. pubkey is the responder's
// public key.
func InitiateHandshake(out, pubkey []byte) (*PreSession, []byte, error) {
	config := newConfig()
	config.Initiator = true
	config.PeerStatic = pubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}

	// -> e, es
	out, _, _, err = handshakeState.WriteMessage(out, nil)
	if err != nil {
		return nil, nil, err
	}

	return &PreSession{handshakeState: handshakeState}, out, nil
}

// FinishHandshake completes a handshake with the responder's handshake message
// and converts a PreSession into a Session. The PreSession should not be used
// after calling this method.
func (pre *PreSession) FinishHandshake(msg []byte) (*Session, error) {
	// <- e, es
	payload, send, recv, err := pre.handshakeState.ReadMessage(nil, msg)
	if err != nil {
		return nil, err
	}
	if len(payload) != 0 {
		return nil, errPayload
	}

	return &Session{recv: recv, send: send}, nil
}

// AcceptHandshake accepts an initiator handshake message, and returns a Session
// along with a handshake message to be sent back to the initiator. out is a
// byte slice (may be nil) to which the handshake message will be appended.
// privkey is the responder's private key.
func AcceptHandshake(out, msg, privkey []byte) (*Session, []byte, error) {
	config := newConfig()
	config.Initiator = false
	config.StaticKeypair = noise.DHKey{
		Private: privkey,
		Public:  PubkeyFromPrivkey(privkey),
	}
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}

	// -> e, es
	payload, _, _, err := handshakeState.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, err
	}
	if len(payload) != 0 {
		return nil, nil, errPayload
	}

	// <- e, es
	out, recv, send, err := handshakeState.WriteMessage(out, nil)
	if err != nil {
		return nil, nil, err
	}

	return &Session{recv: recv, send: send}, out, nil
}

// Encrypt produces an encrypted Noise transport message with an explicit nonce.
// It encrypts the plaintext p, prepends the nonce, appends the message to out
// and returns out.
func (session *Session) Encrypt(out, p []byte) ([]byte, error) {
	session.sendLock.Lock()
	defer session.sendLock.Unlock()

	// Prepend the nonce.
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], session.send.Nonce())
	out = append(out, buf[:]...)

	// Encrypt the message.
	return session.send.Encrypt(out, nil, p)
}

// Decrypt decrypts a Noise transport message that has an explicit nonce. It
// appends the plaintext to out and returns out. It returns a non-nil error when
// the message cannot be authenticated or the nonce has already been used or is
// out of window.
func (session *Session) Decrypt(out, msg []byte) ([]byte, error) {
	// Decode the prepended nonce.
	if len(msg) < 8 {
		return nil, errMissingNonce
	}
	var nonce uint64 = binary.BigEndian.Uint64(msg[:8])

	session.recvLock.Lock()
	defer session.recvLock.Unlock()

	// Decrypt the message.
	session.recv.SetNonce(nonce)
	p, err := session.recv.Decrypt(out, nil, msg[8:])
	if err != nil {
		return nil, err
	}

	// The message was authenticated; is its nonce acceptable (i.e., in a
	// recent window and not a replay)? It is important to do this check
	// only after successful decryption+authentication.
	if !session.replay.CheckAndUpdate(nonce) {
		return nil, ErrInvalidNonce
	}

	return p, nil
}
