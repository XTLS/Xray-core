package vless

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
	"golang.org/x/sync/singleflight"
)

const (
	defaultExternalTimeout     = 2 * time.Second
	defaultExternalCacheTTL    = 5 * time.Minute
	defaultExternalNegativeTTL = 30 * time.Second
	maxExternalErrorTTL        = 5 * time.Second // transport errors only, so a recovered endpoint is retried quickly
)

// ExternalValidatorConfig configures an ExternalValidator. Zero durations
// fall back to package defaults.
type ExternalValidatorConfig struct {
	URL         string
	Timeout     time.Duration
	CacheTTL    time.Duration
	NegativeTTL time.Duration
	Outbound    string            // tagged outbound to dial the endpoint through, if any
	Headers     map[string]string // sent as-is on every lookup request
}

// externalEntry is a cached lookup result, negative if user is nil.
type externalEntry struct {
	user   *protocol.MemoryUser
	expiry time.Time
}

// ExternalValidator asks an external HTTP endpoint whether a UUID is a valid
// user, caching answers in memory. Lookup failures fail closed into fallback.
// It delegates Add, GetByEmail, GetAll, and GetCount to the base validator
// unmodified, since the external endpoint has no reverse email index and no
// full user listing.
type ExternalValidator struct {
	base Validator

	ctx         context.Context
	url         string
	headers     map[string]string
	client      *http.Client
	cacheTTL    time.Duration
	negativeTTL time.Duration

	cache   sync.Map // ProcessUUID bytes + source IP -> *externalEntry
	group   singleflight.Group
	sweeper *task.Periodic
}

// NewExternalValidator creates an ExternalValidator on top of base, querying
// cfg.URL (with "?uuid=<id>" or "&uuid=<id>" appended) for unknown users.
func NewExternalValidator(ctx context.Context, dispatcher routing.Dispatcher, base Validator, cfg ExternalValidatorConfig) (*ExternalValidator, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New(`"validator" url must be an http(s) URL: `, cfg.URL)
	}

	v := &ExternalValidator{
		base:        base,
		ctx:         ctx,
		headers:     cfg.Headers,
		cacheTTL:    defaultExternalCacheTTL,
		negativeTTL: defaultExternalNegativeTTL,
	}
	timeout := defaultExternalTimeout
	if cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}
	if cfg.CacheTTL > 0 {
		v.cacheTTL = cfg.CacheTTL
	}
	if cfg.NegativeTTL > 0 {
		v.negativeTTL = cfg.NegativeTTL
	}

	sep := "?"
	if u.RawQuery != "" {
		sep = "&"
	}
	v.url = u.String() + sep + "uuid="

	transport := &http.Transport{
		MaxConnsPerHost: 8,
		IdleConnTimeout: 90 * time.Second,
	}
	if cfg.Outbound != "" {
		outbound := cfg.Outbound
		transport.DialContext = func(reqCtx context.Context, network, addr string) (net.Conn, error) {
			var conn net.Conn
			err := task.Run(reqCtx, func() error {
				if tagged.Dialer == nil {
					return errors.New("tagged dialer is not initialized")
				}
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return err
				}
				conn, err = tagged.Dialer(ctx, dispatcher, dest, outbound)
				return err
			})
			return conn, err
		}
	}
	v.client = &http.Client{Transport: transport, Timeout: timeout}

	v.sweeper = &task.Periodic{Interval: time.Minute, Execute: v.sweep}
	common.Must(v.sweeper.Start())
	return v, nil
}

func (v *ExternalValidator) Add(u *protocol.MemoryUser) error {
	return v.base.Add(u)
}

func (v *ExternalValidator) GetByEmail(email string) *protocol.MemoryUser {
	return v.base.GetByEmail(email)
}

func (v *ExternalValidator) GetAll() []*protocol.MemoryUser {
	return v.base.GetAll()
}

func (v *ExternalValidator) GetCount() int64 {
	return v.base.GetCount()
}

// sourcedValidator is a per-connection view of an ExternalValidator whose
// endpoint lookups carry the connection's source IP.
type sourcedValidator struct {
	*ExternalValidator
	ip string
}

func (v sourcedValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	return v.get(id, v.ip)
}

// SourceAware is implemented by validators whose lookups can be scoped to a
// connection's source address.
type SourceAware interface {
	WithSource(source net.Destination) Validator
}

// WithSource returns a Validator whose endpoint lookups carry source's IP,
// caching answers per user-IP pair so the endpoint may limit IPs per user.
func (v *ExternalValidator) WithSource(source net.Destination) Validator {
	if !source.IsValid() {
		return v
	}
	return sourcedValidator{v, source.Address.String()}
}

// externalCacheKey is the cache key for id looked up from ip, or the shared
// prefix of all of id's entries (across source IPs) when ip is empty.
func externalCacheKey(id uuid.UUID, ip string) string {
	uuidKey := ProcessUUID(id)
	return string(uuidKey[:]) + ip
}

// Del evicts cached entries matching the email or UUID, then removes any local user.
func (v *ExternalValidator) Del(e string) error {
	if e == "" {
		return v.base.Del(e)
	}
	uuidKey := "" // ParseString also maps arbitrary strings, so email match stays in play
	if id, err := uuid.ParseString(e); err == nil {
		uuidKey = externalCacheKey(id, "")
	}
	evictedPositive := false
	v.cache.Range(func(key, value interface{}) bool {
		u := value.(*externalEntry).user
		if (uuidKey != "" && strings.HasPrefix(key.(string), uuidKey)) ||
			(u != nil && strings.EqualFold(u.Email, e)) {
			v.cache.Delete(key)
			evictedPositive = evictedPositive || u != nil
		}
		return true
	})
	if err := v.base.Del(e); err != nil && !evictedPositive {
		return err
	}
	return nil
}

// Get a VLESS user with UUID via cache or the endpoint, nil if user doesn't exist.
func (v *ExternalValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	return v.get(id, "")
}

func (v *ExternalValidator) get(id uuid.UUID, ip string) *protocol.MemoryUser {
	if u := v.base.Get(id); u != nil {
		return u
	}
	key := externalCacheKey(id, ip)
	if e, ok := v.cache.Load(key); ok {
		if entry := e.(*externalEntry); time.Now().Before(entry.expiry) {
			return entry.user
		}
	}
	u, _, _ := v.group.Do(key, func() (interface{}, error) {
		user, ttl := v.fetch(id, ip)
		v.cache.Store(key, &externalEntry{user: user, expiry: time.Now().Add(ttl)})
		return user, nil
	})
	return u.(*protocol.MemoryUser)
}

func (v *ExternalValidator) fetch(id uuid.UUID, ip string) (*protocol.MemoryUser, time.Duration) {
	errorTTL := min(v.negativeTTL, maxExternalErrorTTL)
	target := v.url + id.String()
	if ip != "" {
		target += "&ip=" + url.QueryEscape(ip)
	}
	req, err := http.NewRequestWithContext(v.ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errorTTL
	}
	for k, val := range v.headers {
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		errors.LogWarning(v.ctx, "external validator lookup failed: ", err)
		return nil, errorTTL
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 4096)
	if resp.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, body)
		errors.LogWarning(v.ctx, "external validator returned 401 Unauthorized, check configured headers")
		return nil, errorTTL // likely a config problem, not "no such user"; retry soon
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, body)
		return nil, v.negativeTTL
	}

	var r struct {
		Email string `json:"email"`
		Level uint32 `json:"level"`
		Flow  string `json:"flow"`
		TTL   uint32 `json:"ttl"` // optional per-user seconds, overrides cacheTtl
	}
	if err := json.NewDecoder(body).Decode(&r); err != nil {
		errors.LogWarning(v.ctx, "external validator returned invalid JSON: ", err)
		return nil, errorTTL
	}
	if r.Flow != "" && r.Flow != XRV {
		errors.LogWarning(v.ctx, "external validator returned unsupported flow: ", r.Flow)
		return nil, v.negativeTTL
	}

	ttl := v.cacheTTL
	if r.TTL > 0 {
		ttl = time.Duration(r.TTL) * time.Second
	}
	return &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID:   protocol.NewID(id),
			Flow: r.Flow,
		},
		Email: r.Email,
		Level: r.Level,
	}, ttl
}

// sweep keeps random-UUID probes from growing the negative cache without bound.
func (v *ExternalValidator) sweep() error {
	now := time.Now()
	v.cache.Range(func(key, value interface{}) bool {
		if now.After(value.(*externalEntry).expiry) {
			v.cache.Delete(key)
		}
		return true
	})
	return nil
}

// Close implements common.Closable.
func (v *ExternalValidator) Close() error {
	v.client.CloseIdleConnections()
	return errors.Combine(v.sweeper.Close(), common.Close(v.base))
}
