package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	flatSeparator       = "~"
	driveInlineLimit    = 12000
	driveMaxAnnounce    = 1 << 20
	driveMaxInflight    = 64
	driveMaxAttempts    = 8
	driveTimeout        = time.Minute
	driveInitialBackoff = 200 * time.Millisecond
	driveMaxBackoff     = 8 * time.Second
	cleanupMaxRetries   = 5
	cleanupRetryDelay   = 2 * time.Second
	cleanupSessionPause = time.Second
	filesURL            = "https://www.googleapis.com/drive/v3/files"
	uploadURL           = "https://www.googleapis.com/upload/drive/v3/files"
)

type (
	maxBodyKey   struct{}
	cleanupKey   struct{}
	namesOnlyKey struct{}
)

type driveLane int

const (
	metadataLane driveLane = iota
	priorityLane
	mediaLane
	laneCount
)

type driveStorage struct {
	*driveShared
	clients     [laneCount]*http.Client
	child       bool
	boundFolder string
	unchecked   sync.Map // peer-selected ID -> expected name, until first verified access
}

type driveShared struct {
	folder, space, clientID, clientSecret, refreshToken, tokenURL string
	tokenClient                                                   *http.Client
	pools                                                         [laneCount]*connPool
	permits                                                       [laneCount]chan struct{}
	headMedia                                                     chan struct{} // reserved HTTP permits, same media pool
	cancel                                                        context.CancelFunc
	sessionGuard                                                  driveSessionGuard
	mu                                                            sync.Mutex
	token                                                         string
	expiry, coolUntil, nextRequest                                time.Time
	coolDelay                                                     time.Duration
	tokenErr                                                      error
	refreshing                                                    chan struct{}
	nextDelete                                                    time.Time
	idLock                                                        chan struct{}
	ids                                                           []string
	idsExpire                                                     time.Time
}

func newDriveStorage(settings *internet.MemoryStreamConfig, config *Config) (*driveStorage, error) {
	if config.RemoteFolder == "" || len(config.Secrets) != 3 || slices.Contains(config.Secrets, "") {
		return nil, errors.New("Drive requires a folder ID, client ID, client secret and refresh token")
	}
	ctx, cancel := context.WithCancel(context.Background())
	hosts := new(sync.Map)
	client := func(ctx context.Context) *http.Client {
		return newServiceClient(ctx, hosts, settings, driveTimeout, driveMaxInflight)
	}
	s := &driveStorage{driveShared: &driveShared{
		folder: config.RemoteFolder, space: "drive", clientID: config.Secrets[0], clientSecret: config.Secrets[1], refreshToken: config.Secrets[2],
		tokenURL: "https://oauth2.googleapis.com/token", tokenClient: client(ctx), cancel: cancel, idLock: make(chan struct{}, 1),
		headMedia: make(chan struct{}, min(4, int(driveMediaConns(config.Xmux)))),
	}}
	if s.folder == "appDataFolder" {
		s.space = s.folder
	}
	// Four ordinary media requests per connection hide request latency;
	// the byte budget and separate head permits bound speculative load.
	for i, limit := range [laneCount]int{48, 8, min(driveMaxInflight, 4*int(driveMediaConns(config.Xmux)))} {
		s.pools[i] = newConnPool(config.Xmux, [laneCount]int32{0, 0, driveMediaConns(config.Xmux)}[i], client)
		s.permits[i] = make(chan struct{}, limit)
	}
	s.tokenClient.CheckRedirect = driveRedirect
	s.openClients()
	return s, nil
}

// Redirect reads only: never convert a mutation to GET or forward a refresh form.
func driveRedirect(req *http.Request, via []*http.Request) error {
	if via[0].Method != http.MethodGet || req.URL.Scheme != "https" || len(via) >= 10 {
		return http.ErrUseLastResponse
	}
	return nil
}

func (s *driveStorage) openClients() {
	for i, pool := range s.pools {
		s.clients[i] = &http.Client{Transport: &sessionTransport{pool: pool, spread: driveLane(i) == mediaLane}, CheckRedirect: driveRedirect}
	}
}

func (s *driveStorage) session() Storage {
	c := &driveStorage{driveShared: s.driveShared, child: true}
	c.openClients()
	return c
}

func (s *driveStorage) Close() error {
	for _, c := range s.clients {
		c.Transport.(*sessionTransport).Close()
	}
	if !s.child {
		s.cancel()
		for _, pool := range s.pools {
			pool.Close()
		}
		s.tokenClient.CloseIdleConnections()
	}
	return nil
}

var errSessionInUse = errors.New("session is live or already being collected")

type driveSessionGuard struct {
	mu       sync.Mutex
	sessions map[string]int // positive: active leases; -1: exclusive cleanup
}

func (g *driveSessionGuard) acquire(prefix string, cleanup bool) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.sessions[prefix]
	if n < 0 || cleanup && n != 0 {
		return nil, errSessionInUse
	}
	if g.sessions == nil {
		g.sessions = make(map[string]int)
	}
	delta := 1
	if cleanup {
		delta = -1
	}
	g.sessions[prefix] = n + delta
	return sync.OnceFunc(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.sessions[prefix] -= delta
		if g.sessions[prefix] == 0 {
			delete(g.sessions, prefix)
		}
	}), nil
}

func (s *driveStorage) holdSession(session string) (func(), error) {
	return s.sessionGuard.acquire(sessionPrefix(session), false)
}

func flatten(name string) string { return strings.ReplaceAll(name, "/", flatSeparator) }

func quoteDriveValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)
}

type tokenRetry struct{ error }

func (e tokenRetry) Unwrap() error { return e.error }

type authError struct{ code string }

func (e authError) Error() string {
	return "Google rejected the OAuth credentials (" + e.code + "); create a new refresh token, see the XDRIVE setup guide"
}

func isAuthError(err error) bool {
	_, ok := err.(authError)
	return ok
}

func (s *driveStorage) fetchToken(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"refresh_token": {s.refreshToken},
		"grant_type":    {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, errors.New("failed to build the token request").Base(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.tokenClient.Do(req)
	if err != nil {
		return "", 0, tokenRetry{errors.New("failed to refresh the access token").Base(err)}
	}
	defer resp.Body.Close()
	if retryableStatus(resp.StatusCode) || resp.StatusCode == http.StatusRequestTimeout {
		s.delayRequests(resp.Header) // Honor Retry-After even when the error body is truncated.
		return "", 0, tokenRetry{errors.New("the token endpoint answered ", resp.StatusCode)}
	}

	body, err := readLimited(resp.Body, 1<<20)
	if err != nil {
		if err == errDriveSize {
			return "", 0, err
		}
		return "", 0, tokenRetry{errors.New("failed to read the token response").Base(err)}
	}
	var parsed struct {
		Error       string `json:"error"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	parseErr := json.Unmarshal(body, &parsed)
	if resp.StatusCode != http.StatusOK {
		switch parsed.Error {
		case "invalid_grant", "invalid_client", "unauthorized_client":
			if parseErr == nil && (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				return "", 0, authError{parsed.Error}
			}
		}
		return "", 0, errors.New("the token endpoint answered ", resp.StatusCode)
	}
	if parseErr != nil {
		return "", 0, errors.New("failed to parse the token response").Base(parseErr)
	}
	if parsed.AccessToken == "" {
		return "", 0, errors.New("the token endpoint returned no access token")
	}
	if parsed.ExpiresIn <= 0 || parsed.ExpiresIn > int64(time.Duration(1<<63-1)/time.Second) {
		return "", 0, errors.New("the token endpoint returned an invalid lifetime")
	}
	return parsed.AccessToken, time.Duration(parsed.ExpiresIn) * time.Second, nil
}

func jitter(backoff time.Duration) time.Duration {
	half := backoff / 2
	if half <= 0 {
		return backoff
	}
	return half + time.Duration(dice.RollInt63n(int64(half)))
}

func rateLimited(payload []byte) bool {
	var parsed struct {
		Error struct {
			Status string `json:"status"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(payload, &parsed) != nil {
		return false
	}
	for _, item := range parsed.Error.Errors {
		switch item.Reason {
		case "rateLimitExceeded", "userRateLimitExceeded", "sharingRateLimitExceeded":
			return true
		}
	}
	return parsed.Error.Status == "RESOURCE_EXHAUSTED"
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusInternalServerError ||
		status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// Convert Retry-After to a local delay. A response Date avoids local clock skew.
func retryAfter(h http.Header, now time.Time) time.Duration {
	raw := h.Get("Retry-After")
	if raw != "" && strings.Trim(raw, "0123456789") == "" {
		n, _ := strconv.ParseUint(raw, 10, 64) // overflow saturates before the duration clamp
		return time.Duration(min(n, uint64((1<<63-1)/time.Second))) * time.Second
	}
	if until, err := http.ParseTime(raw); err == nil {
		if server, err := http.ParseTime(h.Get("Date")); err == nil {
			now = server
		}
		return max(0, until.Sub(now))
	}
	return 0
}

func (s *driveStorage) delayRequests(h http.Header) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.coolUntil) {
		if now.Sub(s.coolUntil) > time.Minute {
			s.coolDelay = 0
		}
		s.coolDelay = min(30*time.Second, max(2*time.Second, 2*s.coolDelay))
		s.coolUntil = now.Add(jitter(s.coolDelay))
	}
	if until := now.Add(retryAfter(h, now)); until.After(s.coolUntil) {
		s.coolUntil = until
	}
	errors.LogDebug(context.Background(), "xdrive cooldown ", time.Until(s.coolUntil))
}

// Reserve spaced starts across all lanes; a later cooldown reschedules the turn.
func (s *driveStorage) waitRequest(ctx context.Context) error {
	for {
		s.mu.Lock()
		now := time.Now()
		delay := max(0, s.coolUntil.Sub(now), s.nextRequest.Sub(now))
		s.nextRequest = now.Add(delay).Add(time.Second / 80)
		s.mu.Unlock()
		if err := sleepContext(ctx, delay); err != nil {
			return err
		}
		if !s.cooling() {
			return nil
		}
	}
}

func multipartBody(metadata, data []byte) ([]byte, string) {
	boundary := rand.Text()
	for bytes.Contains(metadata, []byte(boundary)) || bytes.Contains(data, []byte(boundary)) {
		boundary = rand.Text()
	}
	var body bytes.Buffer
	body.Grow(len(metadata) + len(data) + 3*len(boundary) + 256)
	fmt.Fprintf(&body, "--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n", boundary)
	body.Write(metadata)
	fmt.Fprintf(&body, "\r\n--%s\r\nContent-Type: application/octet-stream\r\n\r\n", boundary)
	body.Write(data)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", boundary)
	return body.Bytes(), "multipart/related; boundary=" + boundary
}

// A canceled caller does not strand other waiters or poison the token cache.
func (s *driveStorage) accessToken(ctx context.Context) (string, error) {
	for {
		s.mu.Lock()
		switch {
		case (s.token != "" || s.tokenErr != nil) && (time.Now().Before(s.expiry) || isAuthError(s.tokenErr)):
			token, err := s.token, s.tokenErr
			s.mu.Unlock()
			return token, err
		case s.refreshing != nil:
			done := s.refreshing
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-done:
				continue
			}
		}
		s.refreshing = make(chan struct{})
		s.mu.Unlock()
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, life, err := s.fetchToken(fetchCtx)
		cancel()
		s.mu.Lock()
		if err == nil {
			s.token, s.expiry = token, time.Now().Add(life-min(time.Minute, life/5))
			s.tokenErr = nil
		} else if ctx.Err() == nil {
			s.token, s.tokenErr, s.expiry = "", err, time.Now().Add(time.Second)
		}
		close(s.refreshing)
		s.refreshing = nil
		s.mu.Unlock()
		return token, err
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (s *driveStorage) cooling() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.coolUntil)
}

var errDriveSize = errors.New("Drive response exceeds size limit")

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, errDriveSize
	}
	return b, err
}

// request holds its permit through consume; only an explicit rejection permits write replay.
func (s *driveStorage) request(ctx context.Context, lane driveLane, method, target, contentType string, body []byte, byteRange string, buffered bool, consume func(*http.Response) error) error {
	var last error
	refreshed := false
	for attempt := 0; attempt < driveMaxAttempts; attempt++ {
		if attempt > 0 {
			errors.LogDebug(ctx, "xdrive request retry seq ", ctx.Value(mediaSeqKey{}), " method ", method, " attempt ", attempt+1, " err ", last)
			if err := sleepContext(ctx, jitter(min(driveMaxBackoff, driveInitialBackoff<<uint(attempt-1)))); err != nil {
				return err
			}
		}
		permits := s.permits[lane]
		var head <-chan struct{}
		if lane == mediaLane && method == http.MethodGet {
			head, _ = ctx.Value(mediaHeadKey{}).(<-chan struct{})
		}
		if isClosedChan(head) {
			permits, head = s.headMedia, nil
		}
		select {
		case permits <- struct{}{}:
		case <-head: // A queued look-ahead request has become the ordered head.
			permits = s.headMedia
			select {
			case permits <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		retry, err := func() (bool, error) {
			defer func() { <-permits }()
			token, err := s.accessToken(ctx)
			if err != nil {
				_, retry := err.(tokenRetry) // No file request has been sent yet.
				return retry, err
			}
			if err := s.waitRequest(ctx); err != nil {
				return false, err
			}
			req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
			if err != nil {
				return false, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			if byteRange != "" {
				req.Header.Set("Range", byteRange)
				req.Header.Set("Accept-Encoding", "identity")
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			if method == http.MethodPost || method == http.MethodPatch {
				req.GetBody = nil
			}
			resp, err := s.clients[lane].Do(req)
			if err != nil {
				return method == http.MethodGet && errors.Cause(err) != errSessionClosed, err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				err := consume(resp)
				// A buffered GET exposes no partial bytes before success; a span can.
				return err != nil && buffered && method == http.MethodGet && err != errDriveSize, err
			}
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "" {
				s.delayRequests(resp.Header) // Other lanes must not wait for this error body to finish.
				return resp.StatusCode == http.StatusTooManyRequests || method == http.MethodGet, fmt.Errorf("Drive %s: HTTP %d", method, resp.StatusCode)
			}
			detail, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			err = fmt.Errorf("Drive %s: HTTP %d: %s", method, resp.StatusCode, detail)
			switch {
			case resp.StatusCode == http.StatusUnauthorized:
				s.mu.Lock()
				if s.token == token {
					s.token = ""
				}
				s.mu.Unlock()
				retry := !refreshed
				refreshed = true
				return retry, authError{"401"}
			case resp.StatusCode == http.StatusForbidden && rateLimited(detail):
				s.delayRequests(resp.Header)
				return true, fmt.Errorf("Drive %s: quota rate limit (HTTP 403)", method)
			case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
				return false, errDriveRange
			case (method == http.MethodPost || method == http.MethodPatch) &&
				(resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge):
				return false, refusedPayload{err}
			case resp.StatusCode == http.StatusNotFound:
				return false, errNotFound
			default:
				return method == http.MethodGet && retryableStatus(resp.StatusCode), err
			}
		}()
		if !retry || err == nil || ctx.Err() != nil {
			return err
		}
		last = err
	}
	return last
}

func (s *driveStorage) bytes(ctx context.Context, lane driveLane, method, target, contentType string, payload []byte, limit int64) ([]byte, error) {
	var data []byte
	err := s.request(ctx, lane, method, target, contentType, payload, "", true, func(resp *http.Response) error {
		var err error
		data, err = readLimited(resp.Body, limit)
		return err
	})
	if err != nil {
		data = nil
	}
	return data, err
}

type driveFile struct {
	MimeType    string    `json:"mimeType,omitempty"`
	Trashed     bool      `json:"trashed,omitempty"`
	CreatedTime string    `json:"createdTime,omitempty"`
	created     time.Time // estimated local instant from Drive's Date and createdTime
	ID          string    `json:"id,omitempty"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Parents     []string  `json:"parents,omitempty"`
}

func (f driveFile) regular() bool {
	return f.MimeType != "" && !strings.HasPrefix(f.MimeType, "application/vnd.google-apps.")
}

// Before using an ID chosen by the peer, bind it to a file in this session.
// Lazy creates already establish identity; eager slots are verified on first use.
func (s *driveStorage) bindRing(ctx context.Context, r ring) error {
	s.boundFolder = s.folder
	if s.folder == "root" || s.folder == "appDataFolder" {
		data, err := s.bytes(ctx, metadataLane, http.MethodGet, filesURL+"/"+s.folder+"?fields=id", "", nil, 4096)
		if err != nil {
			return err
		}
		var f driveFile
		if json.Unmarshal(data, &f) != nil || f.ID == "" {
			return errors.New("cannot resolve Drive folder ID")
		}
		s.boundFolder = f.ID
	}
	for _, t := range []slotTable{r.Up, r.Down} {
		s.unchecked.Store(t.Watermark, flatten(t.name+"/w"))
		for i, id := range t.Slots {
			s.unchecked.Store(id, flatten(t.name+"/s"+strconv.Itoa(i)))
		}
	}
	return nil
}

func (s *driveStorage) writeFile(ctx context.Context, lane driveLane, method, id string, f driveFile, payload []byte) error {
	md, err := json.Marshal(f)
	if err != nil {
		return err
	}
	target, query, typ := filesURL, "?fields=id&supportsAllDrives=true", "application/json"
	if payload != nil {
		target, query = uploadURL, query+"&uploadType=multipart"
		md, typ = multipartBody(md, payload)
	}
	if id != "" {
		target += "/" + url.PathEscape(id)
	} else {
		id = f.ID // ID reserved before the create
	}
	data, err := s.bytes(ctx, lane, method, target+query, typ, md, 4096)
	if err == nil {
		var reply driveFile
		if json.Unmarshal(data, &reply) == nil && reply.ID != "" && (id == "" || reply.ID == id) {
			return nil
		}
		err = errors.New("unexpected Drive file ID in write response")
	}
	if _, refused := err.(refusedPayload); refused || id == "" || isAuthError(err) || ctx.Err() != nil {
		return err
	}
	// One writer per file: confirm the exact frame or ACK without replay.
	verify, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for verify.Err() == nil {
		d, readErr := s.readDescription(verify, id)
		if readErr == nil && d == f.Description {
			if payload == nil || d != "" { // metadata object or a slot frame (one atomic multipart write)
				return nil
			}
			var media []byte // a media announcement has no identifying description
			media, readErr = s.bytes(verify, mediaLane, http.MethodGet, filesURL+"/"+url.PathEscape(id)+"?alt=media&supportsAllDrives=true", "", nil, int64(len(payload)))
			if readErr == nil && bytes.Equal(media, payload) {
				return nil
			}
		}
		if readErr == errDriveScope || isAuthError(readErr) || sleepContext(verify, 150*time.Millisecond) != nil {
			break
		}
	}
	return err
}

var (
	errDriveScope = errors.New("Drive file does not belong to the announced session")
	errDriveRange = errors.New("Drive range not yet available")
)

type refusedPayload struct{ error }

func (s *driveStorage) createSlot(ctx context.Context, id, name, description string, body []byte) error {
	f := driveFile{ID: id, Name: flatten(name), MimeType: "application/octet-stream", Parents: []string{s.folder}, Description: description}
	err := s.writeFile(ctx, writeLane(ctx, body), http.MethodPost, "", f, body)
	if err == nil {
		s.unchecked.Delete(id)
	}
	return err
}

type (
	headKey      struct{}
	mediaHeadKey struct{} // <-chan struct{}, closed on promotion
	mediaSeqKey  struct{} // int64, for request retry diagnostics
)

func writeLane(ctx context.Context, body []byte) driveLane {
	if body != nil {
		return mediaLane
	}
	if ctx.Value(headKey{}) != nil {
		return priorityLane
	}
	return metadataLane
}

func (s *driveStorage) setSlot(ctx context.Context, id, description string, body []byte) error {
	if _, pending := s.unchecked.Load(id); pending {
		if _, err := s.readDescription(ctx, id); err != nil {
			return err
		}
	}
	return s.writeFile(ctx, writeLane(ctx, body), http.MethodPatch, id, driveFile{Description: description}, body)
}

func (s *driveStorage) readDescription(ctx context.Context, id string) (string, error) {
	name, pending := s.unchecked.Load(id)
	fields := "description"
	if pending {
		fields += ",name,parents,trashed,mimeType"
	}
	data, err := s.bytes(ctx, writeLane(ctx, nil), http.MethodGet, filesURL+"/"+url.PathEscape(id)+"?fields="+fields+"&supportsAllDrives=true", "", nil, 64<<10)
	if err != nil {
		return "", err
	}
	var f driveFile
	if err := json.Unmarshal(data, &f); err != nil {
		return "", err
	}
	if pending {
		if !f.regular() || f.Trashed || f.Name != name || !slices.Contains(f.Parents, s.boundFolder) {
			return "", errDriveScope
		}
		s.unchecked.Delete(id)
	}
	return f.Description, nil
}

// readSpan verifies tagged blocks [lo, hi), emitting each payload byte once.
// One retry resumes at its first unemitted block and still proves exact EOF.
func (s *driveStorage) readSpan(ctx context.Context, id string, f slotFrame, lo, hi int, emit func([]byte) error, whole func()) error {
	ctx = context.WithValue(ctx, mediaSeqKey{}, f.seq)
	const stride = slotBodyHeader + slotTagBlock
	n := slotBlocks(f.size)
	total := f.size + slotBodyHeader*n
	pos, stop := lo*slotTagBlock, min(hi*slotTagBlock, f.size) // data offsets
	for attempt := 0; ; attempt++ {
		first := min(pos/slotTagBlock, hi-1)
		start, end := first*stride, min(hi*stride, total)
		var header string
		if start > 0 || end < total {
			header = fmt.Sprintf("bytes=%d-%d", start, end-1)
		}
		bodyFailed := false
		started := time.Now()
		err := s.request(ctx, mediaLane, http.MethodGet, filesURL+"/"+url.PathEscape(id)+"?alt=media&supportsAllDrives=true", "", nil, header, false, func(resp *http.Response) error {
			headers := time.Now()
			bodyFailed = true
			from, to, length := first, hi, end-start
			switch resp.StatusCode {
			case http.StatusOK:
				from, to, length = 0, n, total
				if lo == 0 && whole != nil {
					hi, stop = n, f.size
					whole() // Keep this response; cancel redundant full-body downloads.
					if header != "" {
						errors.LogDebug(ctx, "xdrive media seq ", f.seq, " Range ignored; using one full body")
					}
				}
			case http.StatusPartialContent:
				if resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end-1, total) {
					return errors.New("Drive returned a different media range")
				}
			default:
				return fmt.Errorf("unexpected Drive media status %d", resp.StatusCode)
			}
			if resp.ContentLength >= 0 && resp.ContentLength != int64(length) {
				return errors.New("unexpected Drive media length")
			}
			for i := from; i < to; i++ {
				var tag [slotBodyHeader]byte
				if _, err := io.ReadFull(resp.Body, tag[:]); err != nil {
					return err
				}
				if int64(binary.BigEndian.Uint64(tag[:])) != f.seq {
					return errDriveRange // an older lap of this slot
				}
				for at, blockEnd := i*slotTagBlock, min((i+1)*slotTagBlock, f.size); at < blockEnd; {
					b := make([]byte, min(slotReadChunk, blockEnd-at))
					if _, err := io.ReadFull(resp.Body, b); err != nil {
						return err
					}
					if at+len(b) > pos && at < stop { // skip bytes already emitted
						if err := emit(b[max(pos-at, 0):min(len(b), stop-at)]); err != nil {
							bodyFailed = false
							return err
						}
						pos = min(at+len(b), stop)
					}
					at += len(b)
				}
			}
			var extra [1]byte
			if n, err := io.ReadFull(resp.Body, extra[:]); n != 0 || err != io.EOF {
				return errors.New("Drive media did not end at the declared length").Base(err)
			}
			errors.LogDebug(ctx, "xdrive span seq ", f.seq, " blocks ", lo, "-", hi, " status ", resp.StatusCode, " bytes ", length, " headers ", headers.Sub(started), " body ", time.Since(headers))
			return nil
		})
		if err == nil || attempt != 0 || (!bodyFailed && err != errNotFound && err != errDriveRange) || ctx.Err() != nil {
			return err
		}
		errors.LogDebug(ctx, "xdrive span retry seq ", f.seq, " blocks ", lo, "-", hi, " emitted ", pos-lo*slotTagBlock, " err ", err)
		if err := sleepContext(ctx, driveInitialBackoff); err != nil {
			return err
		}
	}
}

// Frames through slotProgressiveMax use one progressive GET. Larger frames
// use up to four block ranges at once, targeting at least 512 KiB per range.
func (s *driveStorage) readFrameStream(ctx context.Context, id string, f slotFrame, emit func([]byte) error) error {
	if f.size <= 0 || f.mode != slotStream {
		return errors.New("invalid Drive stream frame")
	}
	n := slotBlocks(f.size)
	if f.size <= slotProgressiveMax || s.cooling() {
		return s.readSpan(ctx, id, f, 0, n, emit, nil)
	}
	ctx, cancel := context.WithCancel(ctx)
	tailCtx, stopTails := context.WithCancel(ctx)
	defer stopTails()
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	type part struct {
		chunks chan []byte
		err    error // published by close(chunks)
		full   bool
	}
	parts := make([]part, min(cap(s.headMedia), f.size/(2*slotTagBlock)))
	for i := range parts {
		lo, hi := i*n/len(parts), (i+1)*n/len(parts)
		p := &parts[i]
		p.chunks = make(chan []byte, (hi-lo)*(slotTagBlock/slotReadChunk)+1)
		wg.Go(func() {
			defer close(p.chunks)
			spanCtx := tailCtx
			var whole func()
			if i == 0 {
				spanCtx, whole = ctx, func() { p.full = true; stopTails() }
			}
			p.err = s.readSpan(spanCtx, id, f, lo, hi, func(b []byte) error {
				select {
				case p.chunks <- b:
					return nil
				case <-spanCtx.Done():
					return spanCtx.Err()
				}
			}, whole)
		})
	}
	for i := range parts {
		p := &parts[i]
		for b := range p.chunks {
			if err := emit(b); err != nil {
				return err
			}
		}
		if p.err != nil {
			return p.err
		}
		if p.full {
			return nil
		}
	}
	return nil
}

func (s *driveStorage) takeIDs(ctx context.Context, n int) ([]string, error) {
	select {
	case s.idLock <- struct{}{}:
		defer func() { <-s.idLock }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if n <= 0 || n > 1000 {
		return nil, errors.New("invalid Drive ID count")
	}
	if len(s.ids) < n || time.Now().After(s.idsExpire) {
		count := min(1000, 3*n)
		target := fmt.Sprintf("%s/generateIds?count=%d&space=%s", filesURL, count, s.space)
		data, err := s.bytes(ctx, metadataLane, http.MethodGet, target, "", nil, 256<<10)
		if err != nil {
			return nil, err
		}
		var batch struct {
			IDs []string `json:"ids"`
		}
		if json.Unmarshal(data, &batch) != nil || len(batch.IDs) != count || !validSlotIDs(make(map[string]bool, count), batch.IDs...) {
			return nil, errors.New("invalid Drive ID batch")
		}
		s.ids, s.idsExpire = batch.IDs, time.Now().Add(10*time.Minute)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ids := s.ids[:n:n]
	s.ids = s.ids[n:]
	return ids, nil
}

func (s *driveStorage) Put(ctx context.Context, name string, payload []byte) error {
	return putDriveObject(ctx, s, "", name, payload)
}

func putDriveObject(ctx context.Context, s slotStore, id, name string, payload []byte) error {
	var description string
	if len(payload) <= driveInlineLimit {
		description = base64.StdEncoding.EncodeToString(payload)
		payload = nil
	}
	return s.createSlot(ctx, id, name, description, payload)
}

func (s *driveStorage) find(ctx context.Context, query string, describe, dateEntries bool) ([]driveFile, error) {
	fields := "id,name,mimeType"
	if describe {
		fields += ",description"
	}
	if dateEntries {
		fields += ",createdTime"
	}
	q := url.Values{
		"q":      {"'" + quoteDriveValue(s.folder) + "' in parents and trashed = false and mimeType != 'application/vnd.google-apps.folder' and (" + query + ")"},
		"fields": {"nextPageToken,incompleteSearch,files(" + fields + ")"}, "pageSize": {"1000"}, "spaces": {s.space},
		"supportsAllDrives": {"true"}, "includeItemsFromAllDrives": {"true"},
	}
	var found []driveFile
	seen := make(map[string]bool)
	for {
		var data []byte
		var served, observed time.Time
		err := s.request(ctx, metadataLane, http.MethodGet, filesURL+"?"+q.Encode(), "", nil, "", true, func(resp *http.Response) error {
			if dateEntries {
				observed = time.Now()
				served, _ = http.ParseTime(resp.Header.Get("Date"))
			}
			var err error
			data, err = readLimited(resp.Body, 32<<20)
			return err
		})
		if err != nil {
			return nil, err
		}
		var page struct {
			Files            []driveFile
			NextPageToken    string
			IncompleteSearch bool
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, err
		}
		if page.IncompleteSearch {
			return nil, errors.New("Drive returned an incomplete file listing")
		}
		for _, f := range page.Files {
			if !f.regular() {
				continue // Never read or delete native Drive objects through the flat namespace.
			}
			if dateEntries {
				if served.IsZero() {
					return nil, errors.New("missing Drive listing date")
				}
				created, err := time.Parse(time.RFC3339Nano, f.CreatedTime)
				if err != nil {
					continue // Unknown age: skip this file, not unrelated sessions.
				}
				f.created = observed.Add(-max(0, served.Sub(created)))
			}
			found = append(found, f)
		}
		if page.NextPageToken == "" {
			return found, nil
		}
		if seen[page.NextPageToken] {
			return nil, errors.New("repeated Drive page token")
		}
		seen[page.NextPageToken] = true
		q.Set("pageToken", page.NextPageToken)
	}
}

func (s *driveStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	flat := flatten(prefix) + flatSeparator
	files, err := s.find(ctx, "name contains '"+quoteDriveValue(flat)+"'", ctx.Value(namesOnlyKey{}) == nil, prefix == sessionsDir)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]Entry)
	for _, f := range files {
		suffix, ok := strings.CutPrefix(f.Name, flat)
		if !ok || suffix == "" || f.ID == "" {
			continue
		}
		name, _, child := strings.Cut(suffix, flatSeparator)
		e, seen := entries[name]
		if prefix == sessionsDir {
			if child {
				continue
			}
			if seen { // Multiple physical files must not contribute one age and another payload.
				entries[name] = Entry{}
				continue
			}
		}
		e.Name, e.created = name, f.created
		// A malformed description must not hide an entry from age-based cleanup.
		if !child && f.Description != "" {
			if data, err := base64.StdEncoding.DecodeString(f.Description); err == nil {
				e.Inline = data
			}
		}
		entries[name] = e
	}
	out := slices.Collect(maps.Values(entries))
	return slices.DeleteFunc(out, func(e Entry) bool { return e.Name == "" }), nil
}

var errDriveDuplicate = errors.New("multiple Drive files have the requested name")

func (s *driveStorage) Get(ctx context.Context, name string) ([]byte, error) {
	flat := flatten(name)
	files, err := s.find(ctx, "name = '"+quoteDriveValue(flat)+"'", true, false)
	if err != nil {
		return nil, err
	}
	files = slices.DeleteFunc(files, func(f driveFile) bool { return f.Name != flat || f.ID == "" })
	if len(files) == 0 {
		return nil, errNotFound
	}
	if len(files) != 1 {
		return nil, errDriveDuplicate
	}
	f := files[0]
	limit, _ := ctx.Value(maxBodyKey{}).(int64)
	if limit <= 0 {
		limit = maxSegmentBytes
	}
	if f.Description == "" {
		return s.bytes(ctx, mediaLane, http.MethodGet, filesURL+"/"+url.PathEscape(f.ID)+"?alt=media&supportsAllDrives=true", "", nil, limit)
	}
	b, err := base64.StdEncoding.DecodeString(f.Description)
	if int64(len(b)) > limit {
		return nil, errDriveSize
	}
	return b, err
}

func (s *driveStorage) Delete(ctx context.Context, name string) error {
	if session, ok := strings.CutPrefix(name, streamsDir+"/"); ok && ctx.Value(cleanupKey{}) != nil && safeSessionID(session) {
		release, err := s.sessionGuard.acquire(name, true)
		if err != nil {
			return err
		}
		defer release()
	}
	flat := flatten(name)
	prefix, query := flat+flatSeparator, "name = '"+quoteDriveValue(flat)+"'"
	announcement := strings.HasPrefix(name, sessionsDir+"/")
	if !announcement {
		query += " or name contains '" + quoteDriveValue(prefix) + "'"
	}
	files, err := s.find(ctx, query, false, false)
	if err != nil {
		return err
	}
	if announcement && len(files) > 1 {
		return errDriveDuplicate
	}
	for _, f := range files {
		if f.ID == "" || (f.Name != flat && (announcement || !strings.HasPrefix(f.Name, prefix))) {
			continue
		}
		// Share cleanup pacing across sessions instead of competing with uploads.
		s.mu.Lock()
		when := s.nextDelete
		if now := time.Now(); now.After(when) {
			when = now
		}
		s.nextDelete = when.Add(200 * time.Millisecond)
		s.mu.Unlock()
		if err := sleepContext(ctx, time.Until(when)); err != nil {
			return err
		}
		_, err := s.bytes(ctx, metadataLane, http.MethodDelete, filesURL+"/"+url.PathEscape(f.ID)+"?supportsAllDrives=true", "", nil, 4096)
		if err != nil && err != errNotFound {
			return err
		}
	}
	return nil
}
