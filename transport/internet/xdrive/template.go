package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
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
	tmpl    *storageTemplate
	client  *http.Client
	folder  string
	secrets []string

	inflight chan struct{}

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
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

	return &templateStorage{
		tmpl:     tmpl,
		client:   newServiceClient(streamSettings, driveTimeout, conc),
		folder:   config.RemoteFolder,
		secrets:  config.Secrets,
		inflight: make(chan struct{}, conc),
	}, nil
}

const maxTemplateConcurrency = 256

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
		return nil, errors.New("unsupported auth type: ", s.tmpl.Auth.Type)
	}
}

func (s *templateStorage) accessToken(ctx context.Context) (string, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()

	if s.token != "" && time.Now().Before(s.tokenExpiry) {
		return s.token, nil
	}

	form := make(map[string]string, len(s.tmpl.Auth.Form))
	vars := s.baseVars()
	values := strings.Builder{}
	first := true
	for k, v := range s.tmpl.Auth.Form {
		form[k] = subst(v, vars)
		if !first {
			values.WriteByte('&')
		}
		first = false
		values.WriteString(k)
		values.WriteByte('=')
		values.WriteString(form[k])
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tmpl.Auth.TokenURL,
		strings.NewReader(values.String()))
	if err != nil {
		return "", errors.New("failed to build the token request").Base(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", errors.New("failed to fetch the token").Base(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", errors.New("failed to read the token response").Base(err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("the token endpoint answered ", resp.StatusCode, ": ", string(payload))
	}

	path := s.tmpl.Auth.TokenPath
	if path == "" {
		path = "access_token"
	}
	token := jsonString(payload, path)
	if token == "" {
		return "", errors.New("the token response has no token at ", path)
	}

	lifetime := int64(3600)
	if s.tmpl.Auth.ExpiryPath != "" {
		if n := jsonNumber(payload, s.tmpl.Auth.ExpiryPath); n > 0 {
			lifetime = n
		}
	}
	if lifetime > 60 {
		lifetime -= 60
	}
	s.token = token
	s.tokenExpiry = time.Now().Add(time.Duration(lifetime) * time.Second)
	return s.token, nil
}

func (s *templateStorage) invalidateToken() {
	s.tokenMu.Lock()
	s.token = ""
	s.tokenMu.Unlock()
}

func (s *templateStorage) do(ctx context.Context, op *opTemplate, vars map[string]string, body []byte) (int, []byte, error) {
	backoff := driveInitialBackoff
	var lastErr error

	for attempt := 0; attempt < driveMaxAttempts; attempt++ {
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

		authHeaders, err := s.authHeaders(ctx, vars)
		if err != nil {
			lastErr = err
			continue
		}

		method := op.Method
		if method == "" {
			method = http.MethodGet
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, subst(op.URL, vars), reader)
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
		resp, err := s.client.Do(req)
		<-s.inflight
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = errors.New("request failed").Base(err)
			continue
		}
		payload, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = errors.New("failed to read response").Base(err)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized && s.tmpl.Auth.Type == "oauth2" {
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

func (s *templateStorage) Put(ctx context.Context, name string, data []byte) error {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	body := data
	if s.tmpl.Put.Body != "" {
		vars["data"] = base64.StdEncoding.EncodeToString(data)
		body = []byte(subst(s.tmpl.Put.Body, vars))
	}

	status, payload, err := s.do(ctx, &s.tmpl.Put, vars, body)
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

	status, payload, err := s.do(ctx, &s.tmpl.Get, vars, nil)
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

func (s *templateStorage) Delete(ctx context.Context, name string) error {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	status, payload, err := s.do(ctx, &s.tmpl.Delete, vars, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || (status >= 200 && status < 300) {
		return nil
	}
	return errors.New("delete of ", name, " answered ", status, ": ", string(payload))
}

func (s *templateStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	vars := s.baseVars()
	flat := s.storedName(prefix)
	vars["prefix"] = flat

	status, payload, err := s.do(ctx, &s.tmpl.List, vars, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, errors.New("list of ", prefix, " answered ", status, ": ", string(payload))
	}

	matches := s.tmpl.names.FindAllStringSubmatch(string(payload), -1)
	if !s.tmpl.Flatten {
		entries := make([]Entry, 0, len(matches))
		for _, m := range matches {
			entries = append(entries, Entry{Name: m[1]})
		}
		return entries, nil
	}

	want := flat + flatSeparator
	seen := make(map[string]bool, len(matches))
	entries := make([]Entry, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if !strings.HasPrefix(name, want) {
			continue
		}
		rest := strings.TrimPrefix(name, want)
		if rest == "" {
			continue
		}
		if cut := strings.Index(rest, flatSeparator); cut >= 0 {
			rest = rest[:cut]
		}
		if seen[rest] {
			continue
		}
		seen[rest] = true
		entries = append(entries, Entry{Name: rest})
	}
	return entries, nil
}

func (s *templateStorage) Close() error {
	return nil
}
