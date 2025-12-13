package inbound

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

// remoteValidator wraps the in-memory validator and adds remote UUID verification with caching.
type remoteValidator struct {
	local    *vless.MemoryValidator
	endpoint string
	client   *http.Client
	cache    sync.Map // map[string]cachedStatus keyed by normalized UUID string
	ttl      time.Duration
}

type cachedStatus struct {
	allowed bool
	expiry  time.Time
}

func newRemoteValidator(local *vless.MemoryValidator, endpoint string) vless.Validator {
	return &remoteValidator{
		local:    local,
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
		ttl:      6 * time.Hour,
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

func (r *remoteValidator) syntheticUser(id uuid.UUID) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(id),
		},
	}
}

func (r *remoteValidator) checkRemote(uuidStr string) bool {
	payload := map[string]string{"uuid": uuidStr}
	body, err := json.Marshal(payload)
	if err != nil {
		errors.LogInfo(context.Background(), "remote validator marshal error: ", err)
		return false
	}

	req, err := http.NewRequest(http.MethodPost, r.endpoint, bytes.NewReader(body))
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
