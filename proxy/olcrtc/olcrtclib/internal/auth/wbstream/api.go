// Package wbstream is the auth provider for the WB Stream service. It
// produces LiveKit credentials by registering a guest, joining an existing
// room, and exchanging the guest access token for a room token.
package wbstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/protect"
)

const defaultWSURL = "wss://rtc-el-02.wb.ru"

var apiBase = "https://stream.wb.ru" //nolint:gochecknoglobals // package-level state intentional

var (
	errGuestRegister = errors.New("guest register failed")
	errJoinRoom      = errors.New("join room failed")
	errGetToken      = errors.New("get token failed")
)

type guestRegisterRequest struct {
	DisplayName string `json:"displayName"`
	Device      device `json:"device"`
}

type device struct {
	DeviceName string `json:"deviceName"`
	DeviceType string `json:"deviceType"`
}

type guestRegisterResponse struct {
	AccessToken string `json:"accessToken"`
}

type tokenResponse struct {
	RoomToken string `json:"roomToken"`
	ServerURL string `json:"serverUrl"`
}

func registerGuest(ctx context.Context, displayName string) (string, error) {
	u := apiBase + "/auth/api/v1/auth/user/guest-register"
	reqBody := guestRegisterRequest{
		DisplayName: displayName,
		Device: device{
			DeviceName: "Linux",
			DeviceType: "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP",
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux x86_64)")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("guest register status: %w", protect.StatusError(errGuestRegister, resp, 4096))
	}

	var res guestRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return res.AccessToken, nil
}

func joinRoom(ctx context.Context, accessToken, roomID string) error {
	u := fmt.Sprintf("%s/api-room/api/v1/room/%s/join", apiBase, roomID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte("{}")))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux x86_64)")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("join room status: %w", protect.StatusError(errJoinRoom, resp, 4096))
	}
	return nil
}

func getToken(ctx context.Context, accessToken, roomID, displayName string) (tokenResponse, error) {
	u := fmt.Sprintf("%s/api-room-manager/v2/room/%s/connection-details", apiBase, roomID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("deviceType", "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP")
	q.Add("displayName", displayName)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux x86_64)")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("get token status: %w", protect.StatusError(errGetToken, resp, 4096))
	}

	var res tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return tokenResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return res, nil
}
