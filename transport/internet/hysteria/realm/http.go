package realm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const maxErrorBodySize = 64 * 1024

const (
	PunchNonceSize   = 16
	PunchObfsKeySize = 32
)

var ErrInvalidClientConfig = errors.New("invalid realm client config")
var ErrInvalidRealmID = errors.New("invalid realm id")

type Client struct {
	scheme     string
	hostport   string
	token      string
	httpClient *http.Client
}

type RegisterResponse struct {
	SessionID string `json:"session_id"`
	TTL       int    `json:"ttl"`
}

type HeartbeatResponse struct {
	TTL int `json:"ttl"`
}

type HeartbeatRequest struct {
	Addresses []string `json:"addresses,omitempty"`
}

type PunchMetadata struct {
	Nonce string `json:"nonce"`
	Obfs  string `json:"obfs"`
}

type ConnectRequest struct {
	Addresses []string `json:"addresses"`
	PunchMetadata
}

type ConnectResponse struct {
	Addresses []string `json:"addresses"`
	PunchMetadata
}

type PunchEvent struct {
	Addresses []string `json:"addresses"`
	PunchMetadata
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type StatusError struct {
	StatusCode int
	Response   ErrorResponse
}

func (e *StatusError) Error() string {
	if e.Response.Error != "" || e.Response.Message != "" {
		return fmt.Sprintf("realm server returned %d: %s: %s", e.StatusCode, e.Response.Error, e.Response.Message)
	}
	return fmt.Sprintf("realm server returned %d", e.StatusCode)
}

func NewClient(scheme, host, port, token string) (*Client, error) {
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("%w: scheme must be http or https", ErrInvalidClientConfig)
	}
	if host == "" {
		return nil, fmt.Errorf("%w: host is required", ErrInvalidClientConfig)
	}
	if port == "" {
		return nil, fmt.Errorf("%w: port is required", ErrInvalidClientConfig)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidClientConfig)
	}
	return &Client{
		scheme:     scheme,
		hostport:   net.JoinHostPort(host, port),
		token:      token,
		httpClient: http.DefaultClient,
	}, nil
}

func NewPunchMetadata() (PunchMetadata, error) {
	nonce, err := randHex(PunchNonceSize)
	if err != nil {
		return PunchMetadata{}, err
	}
	obfs, err := randHex(PunchObfsKeySize)
	if err != nil {
		return PunchMetadata{}, err
	}
	return PunchMetadata{
		Nonce: nonce,
		Obfs:  obfs,
	}, nil
}

func (c *Client) Register(ctx context.Context, realmID string, addresses []string) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.doJSON(ctx, http.MethodPost, realmID, "", c.token, addressRequest{Addresses: addresses}, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Deregister(ctx context.Context, realmID, sessionID string) error {
	return c.doJSON(ctx, http.MethodDelete, realmID, "", sessionID, nil, http.StatusNoContent, nil)
}

func (c *Client) Heartbeat(ctx context.Context, realmID, sessionID string, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.doJSON(ctx, http.MethodPost, realmID, "heartbeat", sessionID, req, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Connect(ctx context.Context, realmID string, req ConnectRequest) (*ConnectResponse, error) {
	var resp ConnectResponse
	if err := c.doJSON(ctx, http.MethodPost, realmID, "connect", c.token, req, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type ConnectResponseRequest struct {
	Addresses []string `json:"addresses"`
}

func (c *Client) ConnectResponse(ctx context.Context, realmID, sessionID, nonce string, addresses []string) error {
	subPath := "connects/" + url.PathEscape(nonce)
	return c.doJSON(ctx, http.MethodPost, realmID, subPath, sessionID,
		ConnectResponseRequest{Addresses: addresses}, http.StatusNoContent, nil)
}

func (c *Client) Events(ctx context.Context, realmID, sessionID string) (*EventStream, error) {
	req, err := c.newRequest(ctx, http.MethodGet, realmID, "events", sessionID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, decodeStatusError(resp)
	}
	return newEventStream(resp), nil
}

type addressRequest struct {
	Addresses []string `json:"addresses"`
}

func (c *Client) doJSON(ctx context.Context, method, realmID, subPath, token string, in any, expectedStatus int, out any) error {
	var body io.Reader
	if in != nil {
		bs, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(bs)
	}
	req, err := c.newRequest(ctx, method, realmID, subPath, token, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectedStatus {
		return decodeStatusError(resp)
	}
	if out == nil || resp.Body == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) newRequest(ctx context.Context, method, realmID, subPath, token string, body io.Reader) (*http.Request, error) {
	if realmID == "" || strings.Contains(realmID, "/") {
		return nil, fmt.Errorf("%w: realm id must be a single path segment", ErrInvalidRealmID)
	}
	u := &url.URL{
		Scheme: c.scheme,
		Host:   c.hostport,
		Path:   joinURLPath("v1", url.PathEscape(realmID), subPath),
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func randHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func joinURLPath(parts ...string) string {
	var joined []string
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part == "" {
			continue
		}
		joined = append(joined, part)
	}
	return "/" + strings.Join(joined, "/")
}

func decodeStatusError(resp *http.Response) error {
	var errResp ErrorResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodySize)).Decode(&errResp)
	return &StatusError{
		StatusCode: resp.StatusCode,
		Response:   errResp,
	}
}

type EventStream struct {
	resp    *http.Response
	scanner *bufio.Scanner
}

func newEventStream(resp *http.Response) *EventStream {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	return &EventStream{
		resp:    resp,
		scanner: scanner,
	}
}

func (s *EventStream) Close() error {
	return s.resp.Body.Close()
}

func (s *EventStream) Next() (*PunchEvent, error) {
	var eventName string
	var data strings.Builder
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			if eventName == "" && data.Len() == 0 {
				continue
			}
			if eventName != "punch" {
				eventName = ""
				data.Reset()
				continue
			}
			var ev PunchEvent
			if err := json.Unmarshal([]byte(data.String()), &ev); err != nil {
				return nil, err
			}
			return &ev, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			eventName = value
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
		}
	}
	if err := s.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}
