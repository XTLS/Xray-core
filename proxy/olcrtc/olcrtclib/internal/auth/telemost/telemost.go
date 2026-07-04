package telemost

import (
	"context"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/auth"
)

const roomURLPrefix = "https://telemost.yandex.ru/j/"

// Provider produces Goolom credentials for the Yandex Telemost service.
type Provider struct{}

// Engine reports which engine consumes credentials from this auth provider.
func (Provider) Engine() string { return "goolom" }

// DefaultServiceURL returns the Telemost conference base URL.
func (Provider) DefaultServiceURL() string { return "https://telemost.yandex.ru" }

// Issue fetches connection info for a Telemost room and returns engine credentials.
//
// cfg.RoomURL accepts either a full Telemost conference URL
// (https://telemost.yandex.ru/j/<id>) or just the room ID hash. Room
// creation is not supported by the Telemost API; rooms originate in the
// Yandex UI.
func (Provider) Issue(ctx context.Context, cfg auth.Config) (auth.Credentials, error) {
	if cfg.RoomURL == "" {
		return auth.Credentials{}, auth.ErrRoomIDRequired
	}
	roomURL := cfg.RoomURL
	if !strings.HasPrefix(roomURL, "https://") {
		roomURL = roomURLPrefix + roomURL
	}
	info, err := GetConnectionInfo(ctx, roomURL, cfg.Name)
	if err != nil {
		return auth.Credentials{}, fmt.Errorf("get connection info: %w", err)
	}
	return auth.Credentials{
		URL:   info.ClientConfig.MediaServerURL,
		Token: info.PeerID,
		Extra: map[string]string{
			"roomID":           info.RoomID,
			"credentials":      info.Credentials,
			"roomURL":          roomURL,
			"telemetryReferer": roomURL,
		},
	}, nil
}

func init() { //nolint:gochecknoinits // auth registration is the canonical Go pattern for plugins
	auth.Register("telemost", Provider{})
}
