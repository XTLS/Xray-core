// Package telemost is the auth provider for the Yandex Telemost service.
// It fetches the connection metadata (media server URL, peer ID, room ID,
// signing credentials) the Goolom engine needs to join a conference.
//
// Telemost does not expose an API to create rooms - they originate in the
// Yandex UI - so this provider does not implement auth.RoomCreator.
package telemost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/protect"
)

//nolint:gochecknoglobals // overridable base URL for tests
var apiBase = "https://cloud-api.yandex.ru/telemost_front/v2/telemost"

// ErrAPI marks failures returned by the Telemost HTTP API.
var ErrAPI = errors.New("api error")

// ConnectionInfo describes the connection metadata returned by the Telemost API.
//
//nolint:tagliatelle // wire format dictated by the upstream Telemost API
type ConnectionInfo struct {
	RoomID       string `json:"room_id"`
	PeerID       string `json:"peer_id"`
	Credentials  string `json:"credentials"`
	ClientConfig struct {
		MediaServerURL string `json:"media_server_url"`
	} `json:"client_configuration"`
}

// GetConnectionInfo fetches connection metadata for the given Telemost room URL.
func GetConnectionInfo(ctx context.Context, roomURL, displayName string) (*ConnectionInfo, error) {
	u := fmt.Sprintf("%s/conferences/%s/connection", apiBase, url.QueryEscape(roomURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("next_gen_media_platform_allowed", "true")
	q.Add("display_name", displayName)
	q.Add("waiting_room_supported", "true")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Client-Instance-Id", uuid.New().String())
	req.Header.Set("X-Telemost-Client-Version", "187.1.0")
	req.Header.Set("Idempotency-Key", uuid.New().String())
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telemost api status: %w", protect.StatusError(ErrAPI, resp, 4096))
	}

	var info ConnectionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &info, nil
}
