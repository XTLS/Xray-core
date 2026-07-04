package wbstream

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
)

// Provider produces LiveKit credentials for the WB Stream service.
type Provider struct{}

// Engine reports which engine consumes credentials from this auth provider.
func (Provider) Engine() string { return "livekit" }

// DefaultServiceURL returns the WB Stream service URL.
func (Provider) DefaultServiceURL() string { return "https://stream.wb.ru" }

// Issue runs the WB Stream auth flow and returns LiveKit credentials.
//
// When cfg.Token is set it is used as the WB account access token directly,
// skipping the anonymous guest-register step so the session joins as that
// account (with whatever publish rights the account holds). When cfg.Token is
// empty the provider registers a guest as before.
func (Provider) Issue(ctx context.Context, cfg auth.Config) (auth.Credentials, error) {
	if cfg.RoomURL == "" || cfg.RoomURL == "any" {
		return auth.Credentials{}, auth.ErrRoomIDRequired
	}

	accessToken := cfg.Token
	if accessToken == "" {
		guest, err := registerGuest(ctx, cfg.Name)
		if err != nil {
			return auth.Credentials{}, fmt.Errorf("register guest: %w", err)
		}
		accessToken = guest
		logger.Infof("wbstream: obtained guest access token, reuse it via auth.token to keep this identity: %s", accessToken)
	}

	roomID := cfg.RoomURL
	if err := joinRoom(ctx, accessToken, roomID); err != nil {
		return auth.Credentials{}, fmt.Errorf("join room: %w", err)
	}

	tok, err := getToken(ctx, accessToken, roomID, cfg.Name)
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("get token: %w", err)
	}

	url := tok.ServerURL
	if url == "" {
		url = defaultWSURL
	}

	return auth.Credentials{
		URL:   url,
		Token: tok.RoomToken,
		Extra: map[string]string{"roomID": roomID},
	}, nil
}

func init() { //nolint:gochecknoinits // auth registration is the canonical Go pattern for plugins
	auth.Register("wbstream", Provider{})
}
