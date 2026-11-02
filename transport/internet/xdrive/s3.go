package xdrive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http/httpguts"
)

type s3Storage struct {
	*s3Shared
	client   *http.Client
	inflight chan struct{}
	release  func()
}

type s3Shared struct {
	conns                *connPool
	base                 url.URL
	prefix               string
	region               string
	accessKey, secretKey string
	token                string
	backoff              time.Duration
}

func s3Region(region string) string {
	if region == "" {
		return "us-east-1"
	}
	return region
}

func ValidateS3Config(c *Config) error {
	if c == nil || c.S3 == nil {
		return errors.New(`service "s3" needs an "s3" object`)
	}
	u, err := url.Parse(c.S3.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("S3 endpoint must be an http(s) URL without credentials, query or fragment")
	}
	if !httpguts.ValidHeaderFieldValue(c.S3.Region) || strings.ContainsAny(c.S3.Region, "/, \t") {
		return errors.New("invalid S3 signing region")
	}
	bucket := c.S3.Bucket
	if !validS3Name(bucket) || strings.Contains(bucket, "/") {
		return errors.New("S3 needs a bucket name without path separators")
	}
	if !c.S3.PathStyle {
		if net.ParseIP(u.Hostname()) != nil {
			return errors.New("S3 virtual-hosted addressing requires a DNS endpoint")
		}
		// In this mode the bucket is part of the HTTP authority, not its path.
		if strings.Trim(bucket, "abcdefghijklmnopqrstuvwxyz0123456789-.") != "" || strings.Contains(bucket, "..") ||
			strings.HasPrefix(bucket, ".") || strings.HasSuffix(bucket, ".") {
			return errors.New("S3 virtual-hosted addressing requires a DNS-compatible bucket name")
		}
	}
	if !validS3Name(strings.TrimSuffix(c.RemoteFolder, "/")) {
		return errors.New("S3 remoteFolder must be a nonempty relative prefix without empty, '.' or '..' components")
	}
	if len(c.Secrets) < 2 || len(c.Secrets) > 3 || c.Secrets[0] == "" || c.Secrets[1] == "" {
		return errors.New("S3 needs AccessKeyID, SecretAccessKey and optionally SessionToken in secrets")
	}
	for _, secret := range c.Secrets {
		if !httpguts.ValidHeaderFieldValue(secret) {
			return errors.New("invalid S3 secret")
		}
	}
	if strings.ContainsAny(c.Secrets[0], "/ ,\t") {
		return errors.New("invalid S3 AccessKeyID")
	}
	return nil
}

func validS3Name(name string) bool {
	for _, ch := range name {
		if ch < 0x20 || ch == 0x7f || ch == '\\' {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func newS3Storage(streamSettings *internet.MemoryStreamConfig, c *Config) (*s3Storage, error) {
	if err := ValidateS3Config(c); err != nil {
		return nil, err
	}
	base, _ := url.Parse(c.S3.Endpoint)
	// Encode the endpoint prefix for SigV4 without turning escaped slashes into separators.
	segments := strings.Split(base.EscapedPath(), "/")
	for i, segment := range segments {
		decoded, _ := url.PathUnescape(segment)
		segments[i] = strings.ReplaceAll(s3EscapePath(decoded), "/", "%2F")
	}
	base.RawPath = strings.Join(segments, "/")
	if !strings.HasSuffix(base.RawPath, "/") {
		base.Path += "/"
		base.RawPath += "/"
	}
	if c.S3.PathStyle {
		base.Path += c.S3.Bucket + "/"
		base.RawPath += s3EscapePath(c.S3.Bucket) + "/"
	} else {
		host := c.S3.Bucket + "." + base.Hostname()
		if base.Port() != "" {
			host = net.JoinHostPort(host, base.Port())
		}
		base.Host = host
	}
	if streamSettings == nil {
		streamSettings = &internet.MemoryStreamConfig{}
	}
	h1Hosts := new(sync.Map)
	newClient := func(ctx context.Context) *http.Client {
		client := newServiceClient(ctx, h1Hosts, streamSettings, driveTimeout, driveMaxInflight)
		// A redirect changes the signed host/path. Do not follow it with the old
		// signature or send the session token to a different endpoint.
		client.CheckRedirect = s3NoRedirect
		return client
	}
	s := &s3Storage{
		s3Shared: &s3Shared{
			conns:     newConnPool(c.Xmux, newClient),
			base:      *base,
			prefix:    strings.TrimSuffix(c.RemoteFolder, "/") + "/",
			region:    s3Region(c.S3.Region),
			accessKey: c.Secrets[0],
			secretKey: c.Secrets[1],
			backoff:   200 * time.Millisecond,
		},
		client:   newClient(context.Background()),
		inflight: make(chan struct{}, driveMaxInflight),
	}
	if len(c.Secrets) == 3 {
		s.token = c.Secrets[2]
	}
	return s, nil
}

func s3NoRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func (s *s3Storage) session() Storage {
	transport := &sessionTransport{pool: s.conns}
	return &s3Storage{
		s3Shared: s.s3Shared,
		client:   &http.Client{Transport: transport, CheckRedirect: s3NoRedirect},
		inflight: make(chan struct{}, cap(s.inflight)),
		release:  transport.Close,
	}
}

func (s *s3Storage) Close() error {
	if s.release != nil {
		s.release()
	}
	return nil
}

// SigV4 requires %20 for spaces, uppercase escapes, and unescaped key separators.
func s3EscapePath(value string) string {
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == '/' {
			out.WriteByte(ch)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[ch>>4])
			out.WriteByte(digits[ch&15])
		}
	}
	return out.String()
}

func s3Hash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func s3HMAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

func (s *s3Storage) sign(req *http.Request, payloadHash string, now time.Time) {
	stamp, date := now.UTC().Format("20060102T150405Z"), now.UTC().Format("20060102")
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	headers := "host:" + req.URL.Host + "\nx-amz-content-sha256:" + payloadHash + "\nx-amz-date:" + stamp + "\n"
	signed := "host;x-amz-content-sha256;x-amz-date"
	if contentType := req.Header.Get("Content-Type"); contentType != "" {
		headers = "content-type:" + contentType + "\n" + headers
		signed = "content-type;" + signed
	}
	if s.token != "" {
		req.Header.Set("X-Amz-Security-Token", s.token)
		headers += "x-amz-security-token:" + strings.Join(strings.Fields(s.token), " ") + "\n"
		signed += ";x-amz-security-token"
	}
	// Sign the escaped path exactly as sent.
	canonical := req.Method + "\n" + req.URL.EscapedPath() + "\n" + req.URL.RawQuery + "\n" +
		headers + "\n" + signed + "\n" + payloadHash
	scope := date + "/" + s.region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + s3Hash([]byte(canonical))
	key := s3HMAC([]byte("AWS4"+s.secretKey), date)
	key = s3HMAC(key, s.region)
	key = s3HMAC(key, "s3")
	key = s3HMAC(key, "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+hex.EncodeToString(s3HMAC(key, toSign)))
}

func (s *s3Storage) target(key string, query url.Values) string {
	u := s.base
	u.Path += key
	u.RawPath += s3EscapePath(key)
	// Parameters have fixed ASCII names and one value each; SigV4 uses %20 for spaces.
	u.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	return u.String()
}

func (s *s3Storage) objectKey(name string) (string, error) {
	if !validS3Name(name) {
		return "", errors.New("invalid relative S3 object name")
	}
	key := s.prefix + name
	if len(key) > 1024 {
		return "", errors.New("S3 object key exceeds 1024 bytes")
	}
	return key, nil
}

// Retries use fresh signatures and hold a concurrency slot until the response body is read.
func (s *s3Storage) do(ctx context.Context, method, key string, query url.Values, body []byte) (int, []byte, error) {
	payloadHash := s3Hash(body)
	backoff := s.backoff
	var lastErr error
	var retryAfter time.Duration
	for attempt := 0; attempt < driveMaxAttempts; attempt++ {
		if attempt > 0 {
			delay := max(jitter(backoff), retryAfter)
			timer := time.NewTimer(min(delay, driveMaxBackoff))
			select {
			case <-ctx.Done():
				timer.Stop()
				return 0, nil, ctx.Err()
			case <-timer.C:
			}
			backoff = min(backoff*2, driveMaxBackoff)
		}
		select {
		case s.inflight <- struct{}{}:
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
		status, payload, after, err := s.attempt(ctx, method, key, query, body, payloadHash)
		<-s.inflight
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		if err != nil && (!retryS3Error(err) || status >= 300 && !retryableStatus(status)) {
			return 0, nil, err
		}
		if err == nil && !retryableStatus(status) {
			return status, payload, nil
		}
		lastErr, retryAfter = err, after
		if lastErr == nil {
			lastErr = s3ResponseError(method, status, payload)
		}
	}
	return 0, nil, lastErr
}

func retryS3Error(err error) bool {
	var dns *net.DNSError
	if stderrors.As(err, &dns) {
		return dns.IsTimeout || dns.IsTemporary
	}
	var op *net.OpError
	var network net.Error
	return stderrors.Is(err, io.EOF) || stderrors.Is(err, io.ErrUnexpectedEOF) || stderrors.Is(err, errStalled) ||
		stderrors.As(err, &op) || stderrors.As(err, &network) && network.Timeout()
}

func (s *s3Storage) attempt(ctx context.Context, method, key string, query url.Values, body []byte, hash string) (int, []byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.target(key, query), bytes.NewReader(body))
	if err != nil {
		return 0, nil, 0, errors.New("failed to build S3 request")
	}
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	s.sign(req, hash, time.Now())
	resp, err := s.client.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			err = urlErr.Err
		}
		return 0, nil, 0, errors.New("S3 request failed").Base(err)
	}
	defer resp.Body.Close()
	limit := int64(maxSegmentBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limit = 64 << 10
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, 0, errors.New("failed to read S3 response (HTTP ", resp.StatusCode, ")").Base(err)
	}
	if int64(len(payload)) > limit {
		return 0, nil, 0, errors.New("S3 response exceeds size limit")
	}
	var after time.Duration
	if raw := resp.Header.Get("Retry-After"); raw != "" {
		if seconds, err := strconv.ParseInt(raw, 10, 32); err == nil && seconds > 0 {
			after = min(time.Duration(seconds)*time.Second, driveMaxBackoff)
		} else if at, err := http.ParseTime(raw); err == nil {
			after = min(max(time.Until(at), 0), driveMaxBackoff)
		}
	}
	return resp.StatusCode, payload, after, nil
}

func s3Missing(status int, payload []byte) bool {
	if status != http.StatusNotFound {
		return false
	}
	code := s3ErrorCode(payload)
	return code == "NoSuchKey" || code == "NotFound"
}

func s3ErrorCode(payload []byte) string {
	var response struct {
		XMLName xml.Name `xml:"Error"`
		Code    string
	}
	if xml.Unmarshal(payload, &response) != nil {
		return ""
	}
	return response.Code
}

func s3ResponseError(method string, status int, payload []byte) error {
	if code := s3ErrorCode(payload); code != "" {
		return errors.New("S3 ", method, " answered ", status, " (", strconv.Quote(code), ")")
	}
	return errors.New("S3 ", method, " answered ", status)
}

func (s *s3Storage) Put(ctx context.Context, name string, data []byte) error {
	key, err := s.objectKey(name)
	if err != nil {
		return err
	}
	status, payload, err := s.do(ctx, http.MethodPut, key, nil, data)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return s3ResponseError("PUT", status, payload)
	}
	return nil
}

func (s *s3Storage) Get(ctx context.Context, name string) ([]byte, error) {
	key, err := s.objectKey(name)
	if err != nil {
		return nil, err
	}
	status, payload, err := s.do(ctx, http.MethodGet, key, nil, nil)
	if err != nil {
		return nil, err
	}
	if s3Missing(status, payload) {
		return nil, errNotFound
	}
	if status != http.StatusOK {
		return nil, s3ResponseError("GET", status, payload)
	}
	return payload, nil
}

type s3ListPage struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool
	NextContinuationToken string
	Contents              []struct{ Key string }
	CommonPrefixes        []struct{ Prefix string }
}

func (s *s3Storage) list(ctx context.Context, prefix, delimiter string, visit func(*s3ListPage) error) error {
	query := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
	if delimiter != "" {
		query.Set("delimiter", delimiter)
	}
	seen := make(map[string]bool)
	for {
		status, payload, err := s.do(ctx, http.MethodGet, "", query, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return s3ResponseError("LIST", status, payload)
		}
		var page s3ListPage
		if err := xml.Unmarshal(payload, &page); err != nil {
			return errors.New("invalid S3 list response")
		}
		// Validate all keys before deleting any objects.
		for _, item := range page.Contents {
			if !strings.HasPrefix(item.Key, prefix) {
				return errors.New("S3 returned an object outside the requested prefix")
			}
		}
		for _, item := range page.CommonPrefixes {
			if !strings.HasPrefix(item.Prefix, prefix) {
				return errors.New("S3 returned a directory outside the requested prefix")
			}
		}
		if page.IsTruncated {
			if page.NextContinuationToken == "" || seen[page.NextContinuationToken] {
				return errors.New("S3 list pagination did not advance")
			}
			seen[page.NextContinuationToken] = true
		}
		if err := visit(&page); err != nil {
			return err
		}
		if !page.IsTruncated {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}

func (s *s3Storage) List(ctx context.Context, prefix string) ([]Entry, error) {
	key, err := s.objectKey(prefix)
	if err != nil {
		return nil, err
	}
	key += "/"
	seen := make(map[string]bool)
	var entries []Entry
	add := func(full string) {
		rest := strings.TrimPrefix(full, key)
		name, _, _ := strings.Cut(rest, "/")
		if name != "" && validS3Name(name) && !seen[name] {
			seen[name] = true
			entries = append(entries, Entry{Name: name})
		}
	}
	err = s.list(ctx, key, "/", func(page *s3ListPage) error {
		for _, item := range page.Contents {
			add(item.Key)
		}
		for _, item := range page.CommonPrefixes {
			add(item.Prefix)
		}
		return nil
	})
	return entries, err
}

func (s *s3Storage) deleteObject(ctx context.Context, key string) error {
	status, payload, err := s.do(ctx, http.MethodDelete, key, nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK && !s3Missing(status, payload) {
		return s3ResponseError("DELETE", status, payload)
	}
	return nil
}

// The trailing "/" prevents deleting streams/abcd when removing streams/abc.
func (s *s3Storage) Delete(ctx context.Context, name string) error {
	key, err := s.objectKey(name)
	if err != nil {
		return err
	}
	if err := s.deleteObject(ctx, key); err != nil {
		return err
	}
	return s.list(ctx, key+"/", "", func(page *s3ListPage) error {
		for _, item := range page.Contents {
			if err := s.deleteObject(ctx, item.Key); err != nil {
				return err
			}
		}
		return nil
	})
}
