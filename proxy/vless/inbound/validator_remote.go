package inbound

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

// remoteValidator wraps the in-memory validator and adds remote UUID verification with caching.
// It also emits async notifications on connect/disconnect.
type remoteValidator struct {
	local           *vless.MemoryValidator
	baseURL         string
	checkURL        string
	connectedURL    string
	disconnectedURL string
	client          *http.Client
	cache           sync.Map // map[string]cachedStatus keyed by normalized UUID string
	ttl             time.Duration
}

type cachedStatus struct {
	allowed bool
	expiry  time.Time
}

func newRemoteValidator(local *vless.MemoryValidator, endpoint string) vless.Validator {
	base := strings.TrimRight(endpoint, "/")
	return &remoteValidator{
		local:           local,
		baseURL:         base,
		checkURL:        base + "/check",
		connectedURL:    base + "/connected",
		disconnectedURL: base + "/disconnected",
		client:          &http.Client{Timeout: 5 * time.Second},
		ttl:             6 * time.Hour,
	}
}

func (r *remoteValidator) Add(u *protocol.MemoryUser) error {
	return r.local.Add(u)
}

func (r *remoteValidator) Del(email string) error {
	return r.local.Del(email)
}

func (r *remoteValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	norm := vless.ProcessUUID(id)
	normalized := uuid.UUID(norm)
	key := normalized.String()

	if cached, ok := r.cache.Load(key); ok {
		entry := cached.(cachedStatus)
		if time.Now().Before(entry.expiry) {
			if entry.allowed {
				if user := r.local.Get(id); user != nil {
					return user
				}
				return r.syntheticUser(id)
			}
			return nil
		}
	}

	allowed := r.checkRemote(key)
	r.cache.Store(key, cachedStatus{allowed: allowed, expiry: time.Now().Add(r.ttl)})
	if !allowed {
		return nil
	}

	if user := r.local.Get(id); user != nil {
		return user
	}
	return r.syntheticUser(id)
}

func (r *remoteValidator) GetByEmail(email string) *protocol.MemoryUser {
	return r.local.GetByEmail(email)
}

func (r *remoteValidator) GetAll() []*protocol.MemoryUser {
	return r.local.GetAll()
}

func (r *remoteValidator) GetCount() int64 {
	return r.local.GetCount()
}

func (r *remoteValidator) NotifyConnected(uuidStr string, remoteAddr string) {
	go r.notify(r.connectedURL, uuidStr, remoteAddr)
}

func (r *remoteValidator) NotifyDisconnected(uuidStr string, remoteAddr string) {
	go r.notify(r.disconnectedURL, uuidStr, remoteAddr)
}

func (r *remoteValidator) notify(url, uuidStr string, remoteAddr string) {
	if url == "" {
		return
	}
	payload := map[string]string{
		"uuid":       uuidStr,
		"remoteAddr": remoteAddr,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	_, _ = r.client.Do(req) // fire-and-forget
}

func (r *remoteValidator) syntheticUser(id uuid.UUID) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(id),
		},
	}
}

func (r *remoteValidator) checkRemote(uuidStr string) bool {
	errors.LogInfo(context.Background(), "remote validator calling ", r.checkURL, " for uuid ", uuidStr)
	payload := map[string]string{"uuid": uuidStr}
	body, err := json.Marshal(payload)
	if err != nil {
		errors.LogInfo(context.Background(), "remote validator marshal error: ", err)
		return false
	}

	req, err := http.NewRequest(http.MethodPost, r.checkURL, bytes.NewReader(body))
	if err != nil {
		errors.LogInfo(context.Background(), "remote validator request build error: ", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		errors.LogInfo(context.Background(), "remote validator http error: ", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errors.LogInfo(context.Background(), "remote validator bad status: ", resp.StatusCode)
		return false
	}

	var result struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		errors.LogInfo(context.Background(), "remote validator decode error: ", err)
		return false
	}

	errors.LogInfo(context.Background(), "remote validator status response: ", result.Status)
	return result.Status == 0
}

// Ensure interface compliance.
var _ vless.Validator = (*remoteValidator)(nil)
