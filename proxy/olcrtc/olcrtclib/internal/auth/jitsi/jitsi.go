// Package jitsi implements a pass-through auth provider for self-hosted Jitsi
// Meet instances.
//
// Public Jitsi Meet servers do not require authentication for guest access;
// the only "credentials" the engine needs are the host+room pair extracted
// from a user-supplied room URL. This provider does no HTTP at all - it just
// parses the URL and forwards host+room to the engine via auth.Credentials.
//
// Supported RoomURL forms:
//
//   - "https://meet.example.com/myroom"
//   - "http://meet.example.com/myroom"
//   - "meet.example.com/myroom"
//
// Optional URL path prefixes (e.g. "/jitsi") are preserved as part of the
// host when present, so deployments behind a path-mounted reverse proxy work
// transparently - the j library accepts any host string the WebSocket dial
// can resolve.
package jitsi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth"
)

// CredentialKeyRoom is the auth.Credentials.Extra key that carries the Jitsi
// room name (the conference identifier on the host).
const CredentialKeyRoom = "room"

// ErrInvalidRoomURL is returned when the supplied RoomURL cannot be parsed
// into a host+room pair.
var ErrInvalidRoomURL = errors.New("jitsi: invalid room URL (expected host/room or https://host/room)")

// Provider produces engine credentials for a Jitsi Meet room.
type Provider struct{}

// Engine reports which engine consumes credentials from this auth provider.
func (Provider) Engine() string { return "jitsi" }

const defaultServiceURL = "https://meet.handyweb.org"

// DefaultServiceURL returns the default Jitsi Meet service URL used by config
// defaults and interactive helpers. Users should verify which server is
// accessible in their network: https://meet.small-dm.ru, https://meet1.arbitr.ru, or https://meet.handyweb.org
func (Provider) DefaultServiceURL() string { return defaultServiceURL }

// Issue parses cfg.RoomURL into host+room and returns engine credentials.
//
// The URL field of the returned Credentials carries the Jitsi host (e.g.
// "meet.example.com"); the room name lives in Extra under CredentialKeyRoom.
// Token is unused - Jitsi guest access requires no token.
func (Provider) Issue(_ context.Context, cfg auth.Config) (auth.Credentials, error) {
	host, room, err := parseRoomURL(cfg.RoomURL)
	if err != nil {
		return auth.Credentials{}, err
	}
	return auth.Credentials{
		URL:   host,
		Token: "",
		Extra: map[string]string{CredentialKeyRoom: room},
	}, nil
}

// parseRoomURL splits a Jitsi room URL into (host, room).
//
// Accepts URLs with or without scheme. The host part is the segment before
// the first "/" after stripping the scheme; the room is everything that
// follows, with leading/trailing slashes trimmed.
func parseRoomURL(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", auth.ErrRoomIDRequired
	}
	if idx := strings.Index(raw, "://"); idx >= 0 {
		raw = raw[idx+3:]
	}
	raw = strings.TrimPrefix(raw, "//")
	raw = strings.TrimPrefix(raw, "/")
	slash := strings.Index(raw, "/")
	if slash <= 0 {
		return "", "", fmt.Errorf("%w: %q", ErrInvalidRoomURL, raw)
	}
	host := strings.TrimSpace(raw[:slash])
	room := strings.Trim(raw[slash+1:], "/")
	if host == "" || room == "" {
		return "", "", fmt.Errorf("%w: %q", ErrInvalidRoomURL, raw)
	}
	return host, room, nil
}

func init() { //nolint:gochecknoinits // auth registration is the canonical Go pattern for plugins
	auth.Register("jitsi", Provider{})
}
