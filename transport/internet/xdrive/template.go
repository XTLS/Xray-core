package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

type authTemplate struct {
	Type       string            `json:"type"`
	Header     map[string]string `json:"header"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	TokenURL   string            `json:"tokenUrl"`
	Form       map[string]string `json:"form"`
	TokenPath  string            `json:"tokenPath"`
	ExpiryPath string            `json:"expiryPath"`
}

type opTemplate struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	NamesRegex string            `json:"namesRegex"`

	// NextPagePath extracts a JSON token for the next list URL's query-escaped {pageToken}.
	NextPagePath string `json:"nextPagePath"`

	// HrefPath makes the operation two-step, as in the Yandex Disk REST API: the first request
	// answers with a JSON body, the URL found at HrefPath is then called with HrefMethod (GET by
	// default), carrying the payload. The URL is used as given, with neither auth nor headers.
	HrefPath   string `json:"hrefPath"`
	HrefMethod string `json:"hrefMethod"`

	presigned     bool
	responseLimit int64
}

type retryTemplate struct {
	Status     []int  `json:"status"`
	RateReason string `json:"rateReason"`
}

type storageTemplate struct {
	Flatten     bool          `json:"flatten"`
	Concurrency int           `json:"concurrency"`
	Auth        authTemplate  `json:"auth"`
	Put         opTemplate    `json:"put"`
	Get         opTemplate    `json:"get"`
	Delete      opTemplate    `json:"delete"`
	List        opTemplate    `json:"list"`
	Retry       retryTemplate `json:"retry"`

	names *regexp.Regexp
}

type templateStorage struct {
	*templateShared
	// a session has a client and inflight of its own, see session
	client   *http.Client
	inflight chan struct{}
	release  func()
}

// templateShared is what the sessions of a storage have in common
type templateShared struct {
	conns       *connPool
	tmpl        *storageTemplate
	tokenClient *http.Client
	folder      string
	secrets     []string

	tokenMu     sync.Mutex
	tokenWG     sync.WaitGroup
	tokenClosed bool
	token       string
	tokenExpiry time.Time
	tokenFlight *templateTokenFlight
}

type templateTokenFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	token   string
	err     error
}

type adapterPermanentError struct{ error }

func (e *adapterPermanentError) Unwrap() error { return e.error }

func permanentAdapterError(err error) error { return &adapterPermanentError{err} }

func isPermanentAdapterError(err error) bool {
	var permanent *adapterPermanentError
	return stderrors.As(err, &permanent)
}

func newTemplateStorage(streamSettings *internet.MemoryStreamConfig, config *Config) (*templateStorage, error) {
	tmpl := &storageTemplate{}
	if err := json.Unmarshal([]byte(config.Template), tmpl); err != nil {
		return nil, errors.New("invalid template").Base(err)
	}
	if tmpl.Put.URL == "" || tmpl.Get.URL == "" || tmpl.List.URL == "" || tmpl.Delete.URL == "" {
		return nil, errors.New("template needs put, get, list and delete operations")
	}
	if tmpl.List.NamesRegex == "" {
		return nil, errors.New("template list needs a namesRegex")
	}
	if tmpl.List.NextPagePath != "" && !strings.Contains(tmpl.List.URL, "{pageToken}") {
		return nil, errors.New("paginated template list URL needs {pageToken}")
	}
	re, err := regexp.Compile(tmpl.List.NamesRegex)
	if err != nil {
		return nil, errors.New("bad namesRegex").Base(err)
	}
	if re.NumSubexp() < 1 {
		return nil, errors.New("namesRegex needs one capture group")
	}
	tmpl.names = re

	conc := tmpl.Concurrency
	if conc <= 0 {
		conc = driveMaxInflight
	}
	if conc > maxTemplateConcurrency {
		conc = maxTemplateConcurrency
	}

	h1Hosts := new(sync.Map)
	client := newServiceClient(context.Background(), h1Hosts, streamSettings, driveTimeout, conc)
	return &templateStorage{
		templateShared: &templateShared{
			conns: newConnPool(config.Xmux, 0, func(connCtx context.Context) *http.Client {
				return newServiceClient(connCtx, h1Hosts, streamSettings, driveTimeout, conc)
			}),
			tmpl:        tmpl,
			tokenClient: client,
			folder:      config.RemoteFolder,
			secrets:     config.Secrets,
		},
		client:   client,
		inflight: make(chan struct{}, conc),
	}, nil
}

// session returns a storage for one session, over the connections of XMUX
// until Close, with the token of s
func (s *templateStorage) session() Storage {
	transport := &sessionTransport{pool: s.conns}
	return &templateStorage{
		templateShared: s.templateShared,
		client:         &http.Client{Transport: transport},
		inflight:       make(chan struct{}, cap(s.inflight)),
		release:        transport.Close,
	}
}

const (
	maxTemplateConcurrency = 256
	adapterMaxListResponse = 32 << 20
	adapterMaxMetadataBody = 1 << 20
	adapterMaxErrorBody    = 64 << 10
)

func adapterObjectLimit(ctx context.Context) int64 {
	limit := int64(maxSegmentBytes)
	if v, ok := ctx.Value(maxBodyKey{}).(int64); ok && v > 0 {
		limit = min(limit, v)
	}
	return limit
}

func readAdapterBody(body io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, limit+1))
	if int64(len(payload)) > limit {
		return nil, permanentAdapterError(errors.New("adapter response exceeds the ", limit, " byte cap"))
	}
	return payload, err
}

func (s *templateStorage) baseVars() map[string]string {
	vars := map[string]string{"folder": s.folder}
	for i, secret := range s.secrets {
		vars["secret"+itoa(i)] = secret
	}
	return vars
}

func subst(tmpl string, vars map[string]string) string {
	if tmpl == "" || !strings.ContainsRune(tmpl, '{') {
		return tmpl
	}
	out := tmpl
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func (s *templateStorage) storedName(name string) string {
	if s.tmpl.Flatten {
		return flatten(name)
	}
	return name
}

func (s *templateStorage) retryable(status int, payload []byte) bool {
	for _, code := range s.tmpl.Retry.Status {
		if status == code {
			return true
		}
	}
	if status == http.StatusForbidden && s.tmpl.Retry.RateReason != "" {
		if reason := jsonString(payload, s.tmpl.Retry.RateReason); reason != "" {
			return true
		}
	}
	return false
}

func (s *templateStorage) authHeaders(ctx context.Context, vars map[string]string) (map[string]string, error) {
	switch s.tmpl.Auth.Type {
	case "", "none":
		return nil, nil
	case "static", "oauth2":
		if s.tmpl.Auth.Type == "oauth2" {
			token, err := s.accessToken(ctx)
			if err != nil {
				return nil, err
			}
			vars["token"] = token
		}
		headers := make(map[string]string, len(s.tmpl.Auth.Header))
		for k, v := range s.tmpl.Auth.Header {
			headers[k] = subst(v, vars)
		}
		return headers, nil
	case "basic":
		user := subst(s.tmpl.Auth.Username, vars)
		pass := subst(s.tmpl.Auth.Password, vars)
		enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		return map[string]string{"Authorization": "Basic " + enc}, nil
	default:
		return nil, permanentAdapterError(errors.New("unsupported auth type: ", s.tmpl.Auth.Type))
	}
}

func (s *templateStorage) accessToken(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.tokenMu.Lock()
	if s.tokenClosed {
		s.tokenMu.Unlock()
		return "", context.Canceled
	}
	if s.token != "" && time.Now().Before(s.tokenExpiry) {
		token := s.token
		s.tokenMu.Unlock()
		return token, nil
	}
	f := s.tokenFlight
	if f == nil {
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), driveTimeout)
		f = &templateTokenFlight{done: make(chan struct{}), cancel: cancel}
		s.tokenFlight = f
		s.tokenWG.Add(1)
		go func() {
			defer s.tokenWG.Done()
			token, lifetime, err := s.fetchTemplateToken(fetchCtx)
			cancel()
			s.tokenMu.Lock()
			f.token, f.err = token, err
			if s.tokenFlight == f {
				s.tokenFlight = nil
				if err == nil {
					s.token = token
					s.tokenExpiry = time.Now().Add(lifetime)
				}
			}
			close(f.done)
			s.tokenMu.Unlock()
		}()
	}
	f.waiters++
	s.tokenMu.Unlock()
	defer func() {
		s.tokenMu.Lock()
		f.waiters--
		if f.waiters == 0 && s.tokenFlight == f {
			s.tokenFlight = nil
			f.cancel()
		}
		s.tokenMu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-f.done:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return f.token, f.err
	}
}

func (s *templateStorage) closeTokenWorkers() {
	s.tokenMu.Lock()
	s.tokenClosed = true
	if f := s.tokenFlight; f != nil {
		s.tokenFlight = nil
		f.cancel()
	}
	s.tokenMu.Unlock()
	s.tokenWG.Wait()
}

func (s *templateStorage) fetchTemplateToken(ctx context.Context) (string, time.Duration, error) {
	form := make(url.Values, len(s.tmpl.Auth.Form))
	vars := s.baseVars()
	for k, v := range s.tmpl.Auth.Form {
		form.Add(k, subst(v, vars))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tmpl.Auth.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, permanentAdapterError(errors.New("failed to build the token request").Base(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" || req.URL.Host == "" {
		return "", 0, permanentAdapterError(errors.New("token URL must be an http(s) URL with an authority"))
	}
	resp, err := s.tokenClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return "", 0, errors.New("failed to fetch the token").Base(err)
	}
	defer resp.Body.Close()
	limit := int64(adapterMaxMetadataBody)
	if resp.StatusCode != http.StatusOK {
		limit = adapterMaxErrorBody
	}
	payload, err := readAdapterBody(resp.Body, limit)
	if err != nil {
		readErr := errors.New("failed to read the token response").Base(err)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			return "", 0, permanentAdapterError(readErr)
		}
		return "", 0, readErr
	}
	if resp.StatusCode != http.StatusOK {
		err := errors.New("the token endpoint answered ", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			return "", 0, permanentAdapterError(err)
		}
		return "", 0, err
	}

	path := s.tmpl.Auth.TokenPath
	if path == "" {
		path = "access_token"
	}
	token := jsonString(payload, path)
	if token == "" {
		return "", 0, permanentAdapterError(errors.New("the token response has no token at ", path))
	}

	lifetime := int64(3600)
	if s.tmpl.Auth.ExpiryPath != "" {
		if n := jsonNumber(payload, s.tmpl.Auth.ExpiryPath); n > 0 {
			lifetime = n
		}
	}
	lifetime = min(lifetime, int64(365*24*60*60))
	if lifetime > 60 {
		lifetime -= 60
	}
	return token, time.Duration(lifetime) * time.Second, nil
}

func (s *templateStorage) invalidateToken() {
	s.tokenMu.Lock()
	s.token = ""
	s.tokenMu.Unlock()
}

func (s *templateStorage) do(ctx context.Context, op *opTemplate, vars map[string]string, body []byte) (int, []byte, error) {
	backoff := driveInitialBackoff
	var lastErr error

	url := op.URL
	if !op.presigned {
		url = subst(url, vars)
	}

	for attempt := 0; attempt < driveMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(jitter(backoff)):
			}
			backoff *= 2
			if backoff > driveMaxBackoff {
				backoff = driveMaxBackoff
			}
		}

		var authHeaders map[string]string
		if !op.presigned {
			headers, err := s.authHeaders(ctx, vars)
			if err != nil {
				if ctx.Err() != nil {
					return 0, nil, ctx.Err()
				}
				if isPermanentAdapterError(err) {
					return 0, nil, err
				}
				lastErr = err
				continue
			}
			authHeaders = headers
		}

		method := op.Method
		if method == "" {
			method = http.MethodGet
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return 0, nil, errors.New("failed to build request").Base(err)
		}
		for k, v := range authHeaders {
			req.Header.Set(k, v)
		}
		for k, v := range op.Headers {
			req.Header.Set(k, subst(v, vars))
		}

		select {
		case s.inflight <- struct{}{}:
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			<-s.inflight
			return 0, nil, err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			<-s.inflight
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = errors.New("request failed").Base(err)
			if errors.Cause(err) == errSessionClosed {
				return 0, nil, lastErr
			}
			continue
		}
		limit := op.responseLimit
		if limit <= 0 {
			switch op {
			case &s.tmpl.Get:
				limit = adapterObjectLimit(ctx)
			case &s.tmpl.List:
				limit = adapterMaxListResponse
			default:
				limit = adapterMaxMetadataBody
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			limit = adapterMaxErrorBody
		} else if op.HrefPath != "" {
			limit = adapterMaxMetadataBody
		}
		payload, err := readAdapterBody(resp.Body, limit)
		resp.Body.Close()
		<-s.inflight
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		if err != nil {
			if isPermanentAdapterError(err) {
				return 0, nil, err
			}
			lastErr = errors.New("failed to read response").Base(err)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized && s.tmpl.Auth.Type == "oauth2" && !op.presigned {
			s.invalidateToken()
			lastErr = errors.New("the service rejected the token")
			continue
		}
		if s.retryable(resp.StatusCode, payload) {
			lastErr = errors.New("the service answered ", resp.StatusCode)
			continue
		}
		return resp.StatusCode, payload, nil
	}
	return 0, nil, lastErr
}

// run performs op, following its href when the operation is two-step.
func (s *templateStorage) run(ctx context.Context, op *opTemplate, vars map[string]string, body []byte) (int, []byte, error) {
	if op.HrefPath == "" {
		return s.do(ctx, op, vars, body)
	}
	status, payload, err := s.do(ctx, op, vars, nil)
	if err != nil || status < 200 || status >= 300 {
		return status, payload, err
	}
	href := jsonString(payload, op.HrefPath)
	if href == "" {
		return 0, nil, errors.New("the response has no href at ", op.HrefPath)
	}
	limit := int64(adapterMaxMetadataBody)
	switch op {
	case &s.tmpl.Get:
		limit = adapterObjectLimit(ctx)
	case &s.tmpl.List:
		limit = adapterMaxListResponse
	}
	return s.do(ctx, &opTemplate{Method: op.HrefMethod, URL: href, presigned: true, responseLimit: limit}, vars, body)
}

func (s *templateStorage) Put(ctx context.Context, name string, data []byte) error {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	body := data
	if s.tmpl.Put.Body != "" {
		vars["data"] = base64.StdEncoding.EncodeToString(data)
		body = []byte(subst(s.tmpl.Put.Body, vars))
	}

	status, payload, err := s.run(ctx, &s.tmpl.Put, vars, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return errors.New("put of ", name, " answered ", status, ": ", string(payload))
	}
	return nil
}

func (s *templateStorage) Get(ctx context.Context, name string) ([]byte, error) {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	status, payload, err := s.run(ctx, &s.tmpl.Get, vars, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case status >= 200 && status < 300:
		return payload, nil
	case status == http.StatusNotFound:
		return nil, errNotFound
	default:
		return nil, errors.New("get of ", name, " answered ", status, ": ", string(payload))
	}
}

func (s *templateStorage) deleteStoredObject(ctx context.Context, name string) error {
	vars := s.baseVars()
	vars["name"] = name
	status, payload, err := s.run(ctx, &s.tmpl.Delete, vars, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || (status >= 200 && status < 300) {
		return nil
	}
	return errors.New("delete of ", name, " answered ", status, ": ", string(payload))
}

func (s *templateStorage) Delete(ctx context.Context, name string) error {
	flat := s.storedName(name)
	if !s.tmpl.Flatten {
		return s.deleteStoredObject(ctx, flat)
	}
	want := flat + flatSeparator
	seen := make(map[string]bool)
	var descendants []string
	// Finish pagination before deleting so offset-based listings cannot skip shifted entries.
	if err := s.listStoredNames(ctx, want, func(name string) {
		if strings.HasPrefix(name, want) && len(name) > len(want) && !seen[name] {
			seen[name] = true
			descendants = append(descendants, name)
		}
	}); err != nil {
		return err
	}
	for _, name := range descendants {
		if err := s.deleteStoredObject(ctx, name); err != nil {
			return err
		}
	}
	return s.deleteStoredObject(ctx, flat)
}

func (s *templateStorage) listStoredNames(ctx context.Context, prefix string, visit func(string)) error {
	vars := s.baseVars()
	vars["prefix"] = prefix
	vars["pageToken"] = ""
	seen := make(map[string]bool)
	for {
		status, payload, err := s.run(ctx, &s.tmpl.List, vars, nil)
		if err != nil {
			return err
		}
		if status == http.StatusNotFound && vars["pageToken"] == "" {
			return nil
		}
		if status < 200 || status >= 300 {
			return errors.New("list of ", prefix, " answered ", status, ": ", string(payload))
		}
		var token string
		if s.tmpl.List.NextPagePath != "" {
			if !json.Valid(payload) {
				return permanentAdapterError(errors.New("invalid JSON in paginated template list response"))
			}
			if node := jsonWalk(payload, s.tmpl.List.NextPagePath); node != nil {
				var ok bool
				token, ok = node.(string)
				if !ok {
					return permanentAdapterError(errors.New("template list continuation token must be a string"))
				}
			}
			if token != "" && seen[token] {
				return permanentAdapterError(errors.New("template list pagination did not advance"))
			}
		}
		for _, match := range s.tmpl.names.FindAllStringSubmatch(string(payload), -1) {
			visit(match[1])
		}
		if token == "" {
			return nil
		}
		seen[token] = true
		vars["pageToken"] = url.QueryEscape(token)
	}
}

func (s *templateStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	flat := s.storedName(prefix)
	want := flat + flatSeparator
	seen := make(map[string]bool)
	var entries []Entry
	err := s.listStoredNames(ctx, flat, func(name string) {
		if !s.tmpl.Flatten {
			entries = append(entries, Entry{Name: name})
			return
		}
		if !strings.HasPrefix(name, want) {
			return
		}
		name = strings.TrimPrefix(name, want)
		if name == "" {
			return
		}
		if cut := strings.Index(name, flatSeparator); cut >= 0 {
			name = name[:cut]
		}
		if !seen[name] {
			seen[name] = true
			entries = append(entries, Entry{Name: name})
		}
	})
	return entries, err
}

func (s *templateStorage) Close() error {
	if s.release != nil {
		s.release()
	}
	return nil
}
