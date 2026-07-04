// Package handshake implements the olcrtc session handshake.
//
// The handshake runs on the first smux stream (control stream) of a tunnel.
// Wire format on the control stream is length-prefixed JSON: each message is
// a 4-byte big-endian length followed by that many bytes of JSON.
//
//	client                     server
//	  │  CLIENT_HELLO          │
//	  │ ─────────────────────► │
//	  │                        │ AuthHook(claims) → sessionID | err
//	  │  SERVER_WELCOME / REJECT│
//	  │ ◄───────────────────── │
//	  │                        │
//
// After the exchange the control stream stays open; tunnel traffic flows over
// additional smux streams opened by the client. The control stream then
// carries ping/pong liveness and future control messages.
//
//nolint:tagliatelle // JSON keys are the stable wire protocol schema.
package handshake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/framing"
)

// ProtoVersion identifies the wire-format version. Bumped only on breaking
// changes to message layout or semantics.
const ProtoVersion = 1

// MaxMessageSize caps a single handshake frame. 64 KiB is comfortably larger
// than any legitimate HELLO/WELCOME payload and prevents memory blowups from
// malicious peers.
const MaxMessageSize = 64 * 1024

// DefaultTimeout bounds how long either side will wait for the peer's reply
// before bailing out.
const DefaultTimeout = 15 * time.Second

// MsgType labels each protocol message.
type MsgType string

const (
	// TypeHello is the client's first message.
	TypeHello MsgType = "CLIENT_HELLO"
	// TypeWelcome is the server's success reply.
	TypeWelcome MsgType = "SERVER_WELCOME"
	// TypeReject is the server's failure reply.
	TypeReject MsgType = "SERVER_REJECT"
)

// Hello is sent by the client to begin a session.
type Hello struct {
	Version  int            `json:"version"`
	Type     MsgType        `json:"type"`
	DeviceID string         `json:"device_id"`
	Claims   map[string]any `json:"claims,omitempty"`
}

// Welcome is the server's response on a successful handshake.
type Welcome struct {
	Version   int     `json:"version"`
	Type      MsgType `json:"type"`
	SessionID string  `json:"session_id"`
}

// Reject is the server's response when auth fails.
type Reject struct {
	Version int     `json:"version"`
	Type    MsgType `json:"type"`
	Reason  string  `json:"reason"`
}

// Errors returned by [Client] and [Server].
var (
	// ErrRejected wraps a server-side rejection. The reason is in the error message.
	ErrRejected = errors.New("handshake rejected")
	// ErrProtocolVersion is returned when peer announces an incompatible version.
	ErrProtocolVersion = errors.New("incompatible protocol version")
	// ErrUnexpectedMessage is returned when a peer sends the wrong message type.
	ErrUnexpectedMessage = errors.New("unexpected handshake message")
	// ErrFrameTooLarge is returned when a peer announces a frame above [MaxMessageSize].
	ErrFrameTooLarge = framing.ErrFrameTooLarge
)

// AuthFunc is invoked by [Server] after parsing CLIENT_HELLO.
// It returns the session ID to send back to the client, or an error to reject
// the connection. The error's message is forwarded to the client as the
// reject reason, so it should not leak sensitive details.
type AuthFunc func(deviceID string, claims map[string]any) (sessionID string, err error)

// Client performs the client side of the handshake on rw and returns the
// session ID assigned by the server.
func Client(rw io.ReadWriter, deviceID string, claims map[string]any) (string, error) {
	hello := Hello{
		Version:  ProtoVersion,
		Type:     TypeHello,
		DeviceID: deviceID,
		Claims:   claims,
	}
	if err := writeFrame(rw, hello); err != nil {
		return "", fmt.Errorf("send hello: %w", err)
	}

	raw, err := readFrame(rw)
	if err != nil {
		return "", fmt.Errorf("read welcome: %w", err)
	}

	var probe struct {
		Type MsgType `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("parse reply: %w", err)
	}

	switch probe.Type {
	case TypeHello:
		return "", fmt.Errorf("%w: got %q", ErrUnexpectedMessage, probe.Type)
	case TypeWelcome:
		return parseWelcome(raw)
	case TypeReject:
		return parseReject(raw)
	default:
		return "", fmt.Errorf("%w: got %q", ErrUnexpectedMessage, probe.Type)
	}
}

func parseWelcome(raw []byte) (string, error) {
	var w Welcome
	if err := json.Unmarshal(raw, &w); err != nil {
		return "", fmt.Errorf("parse welcome: %w", err)
	}
	if w.Version != ProtoVersion {
		return "", fmt.Errorf("%w: server v%d, client v%d",
			ErrProtocolVersion, w.Version, ProtoVersion)
	}
	return w.SessionID, nil
}

func parseReject(raw []byte) (string, error) {
	var r Reject
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("parse reject: %w", err)
	}
	return "", fmt.Errorf("%w: %s", ErrRejected, r.Reason)
}

// Server performs the server side of the handshake. It reads CLIENT_HELLO,
// invokes auth, and writes the corresponding WELCOME or REJECT. On success it
// returns the parsed Hello and the session ID produced by auth.
func Server(rw io.ReadWriter, auth AuthFunc) (Hello, string, error) {
	raw, err := readFrame(rw)
	if err != nil {
		return Hello{}, "", fmt.Errorf("read hello: %w", err)
	}

	var h Hello
	if err := json.Unmarshal(raw, &h); err != nil {
		_ = writeFrame(rw, Reject{Version: ProtoVersion, Type: TypeReject, Reason: "malformed hello"})
		return Hello{}, "", fmt.Errorf("parse hello: %w", err)
	}
	if h.Type != TypeHello {
		_ = writeFrame(rw, Reject{Version: ProtoVersion, Type: TypeReject, Reason: "expected CLIENT_HELLO"})
		return h, "", fmt.Errorf("%w: got %q", ErrUnexpectedMessage, h.Type)
	}
	if h.Version != ProtoVersion {
		_ = writeFrame(rw, Reject{Version: ProtoVersion, Type: TypeReject, Reason: "protocol version mismatch"})
		return h, "", fmt.Errorf("%w: client v%d, server v%d",
			ErrProtocolVersion, h.Version, ProtoVersion)
	}

	sessionID, err := auth(h.DeviceID, h.Claims)
	if err != nil {
		_ = writeFrame(rw, Reject{Version: ProtoVersion, Type: TypeReject, Reason: err.Error()})
		return h, "", fmt.Errorf("auth: %w", err)
	}

	if err := writeFrame(rw, Welcome{
		Version:   ProtoVersion,
		Type:      TypeWelcome,
		SessionID: sessionID,
	}); err != nil {
		return h, sessionID, fmt.Errorf("send welcome: %w", err)
	}
	return h, sessionID, nil
}

func writeFrame(w io.Writer, msg any) error {
	if err := framing.WriteJSON(w, msg, MaxMessageSize); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	body, err := framing.ReadBytes(r, MaxMessageSize)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return body, nil
}
