package xmc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	yggdrasilRequestTimeout = 15 * time.Second
	yggdrasilMaxBodySize    = 1 << 20
	yggdrasilJoinAttempts   = 2
)

// minecraftServerID computes the login hash used by the Minecraft session
// server: sha1(serverId + sharedSecret + serverPublicKey) rendered like Java's
// BigInteger#toString(16), including a minus sign for two's-complement values.
func minecraftServerID(serverID string, sharedSecret, publicKey []byte) string {
	hash := sha1.New()
	_, _ = hash.Write([]byte(serverID))
	_, _ = hash.Write(sharedSecret)
	_, _ = hash.Write(publicKey)
	digest := hash.Sum(nil)

	negative := digest[0]&0x80 != 0
	if negative {
		digest = twosComplement(digest)
	}
	rendered := strings.TrimLeft(hex.EncodeToString(digest), "0")
	if rendered == "" {
		rendered = "0"
	}
	if negative {
		rendered = "-" + rendered
	}
	return rendered
}

func twosComplement(value []byte) []byte {
	carry := true
	for i := len(value) - 1; i >= 0; i-- {
		value[i] = ^value[i]
		if carry {
			value[i]++
			carry = value[i] == 0
		}
	}
	return value
}

func normalizeMinecraftUUID(value string) (UUID, error) {
	var id UUID
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil {
		return id, fmt.Errorf("invalid minecraft UUID %q: %w", value, err)
	}
	if len(decoded) != len(id) {
		return id, fmt.Errorf("invalid minecraft UUID %q: bad length %d", value, len(decoded))
	}
	copy(id[:], decoded)
	return id, nil
}

func sameYggdrasilID(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, "-", ""), strings.ReplaceAll(b, "-", ""))
}

type yggdrasilAgent struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

type yggdrasilProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type yggdrasilProperty struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}

type yggdrasilAccountProfile struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Properties []yggdrasilProperty `json:"properties"`
}

type yggdrasilAuthenticateRequest struct {
	Agent       yggdrasilAgent `json:"agent"`
	Username    string         `json:"username"`
	Password    string         `json:"password"`
	ClientToken string         `json:"clientToken,omitempty"`
	RequestUser bool           `json:"requestUser,omitempty"`
}

type yggdrasilAuthenticateResponse struct {
	AccessToken       string             `json:"accessToken"`
	ClientToken       string             `json:"clientToken"`
	AvailableProfiles []yggdrasilProfile `json:"availableProfiles"`
	SelectedProfile   *yggdrasilProfile  `json:"selectedProfile"`
}

type yggdrasilRefreshRequest struct {
	AccessToken     string            `json:"accessToken"`
	ClientToken     string            `json:"clientToken,omitempty"`
	SelectedProfile *yggdrasilProfile `json:"selectedProfile,omitempty"`
	RequestUser     bool              `json:"requestUser,omitempty"`
}

type yggdrasilRefreshResponse struct {
	AccessToken     string            `json:"accessToken"`
	ClientToken     string            `json:"clientToken"`
	SelectedProfile *yggdrasilProfile `json:"selectedProfile"`
}

type yggdrasilJoinRequest struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

// yggdrasilError is the error document returned by Yggdrasil APIs.
type yggdrasilError struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"errorMessage"`
}

func (e *yggdrasilError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}

func isYggdrasilForbidden(err error) bool {
	var yggErr *yggdrasilError
	if !errors.As(err, &yggErr) {
		return false
	}
	return yggErr.Status == http.StatusForbidden || yggErr.Code == "ForbiddenOperationException"
}

// yggdrasilConfig is the parsed configuration shared by the client and server
// side of the finalmask.
type yggdrasilConfig struct {
	baseURL  *url.URL
	username string
	password string
	player   string
}

func newYggdrasilConfig(api, username, password, player string) (*yggdrasilConfig, error) {
	baseURL, err := url.Parse(strings.TrimSpace(api))
	if err != nil {
		return nil, fmt.Errorf("invalid yggdrasil api: %w", err)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid yggdrasil api scheme: %q", baseURL.Scheme)
	}
	if baseURL.Host == "" {
		return nil, fmt.Errorf("invalid yggdrasil api: missing host")
	}
	if baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid yggdrasil api: query and fragment are not allowed")
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")

	return &yggdrasilConfig{
		baseURL:  baseURL,
		username: username,
		password: password,
		player:   player,
	}, nil
}

func (c *yggdrasilConfig) endpoint(parts ...string) string {
	u := *c.baseURL
	u.Path = c.baseURL.Path + "/" + strings.Join(parts, "/")
	return u.String()
}

func newYggdrasilHTTPClient() *http.Client {
	return &http.Client{Timeout: yggdrasilRequestTimeout}
}

func doYggdrasilJSON(ctx context.Context, client *http.Client, method, endpoint string, request, response any) error {
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("encode yggdrasil request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("create yggdrasil request: %w", err)
	}
	httpRequest.Header.Set("Accept", "application/json")
	if request != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}

	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("yggdrasil request: %w", err)
	}
	defer httpResponse.Body.Close()

	content, err := io.ReadAll(io.LimitReader(httpResponse.Body, yggdrasilMaxBodySize))
	if err != nil {
		return fmt.Errorf("read yggdrasil response: %w", err)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		yggErr := &yggdrasilError{Status: httpResponse.StatusCode}
		if len(content) > 0 {
			_ = json.Unmarshal(content, yggErr)
		}
		if yggErr.Code == "" {
			yggErr.Code = httpResponse.Status
		}
		return yggErr
	}

	if response == nil || len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	if err := json.Unmarshal(content, response); err != nil {
		return fmt.Errorf("decode yggdrasil response: %w", err)
	}
	return nil
}

func (c *yggdrasilConfig) authenticate(ctx context.Context, client *http.Client, clientToken string) (*yggdrasilAuthenticateResponse, error) {
	var response yggdrasilAuthenticateResponse
	err := doYggdrasilJSON(
		ctx,
		client,
		http.MethodPost,
		c.endpoint("authserver", "authenticate"),
		&yggdrasilAuthenticateRequest{
			Agent:       yggdrasilAgent{Name: "Minecraft", Version: 1},
			Username:    c.username,
			Password:    c.password,
			ClientToken: clientToken,
		},
		&response,
	)
	if err != nil {
		return nil, fmt.Errorf("yggdrasil authenticate: %w", err)
	}
	if response.AccessToken == "" {
		return nil, fmt.Errorf("yggdrasil authenticate: empty access token")
	}
	return &response, nil
}

func (c *yggdrasilConfig) refresh(ctx context.Context, client *http.Client, accessToken, clientToken string, profile yggdrasilProfile) (*yggdrasilRefreshResponse, error) {
	var response yggdrasilRefreshResponse
	err := doYggdrasilJSON(
		ctx,
		client,
		http.MethodPost,
		c.endpoint("authserver", "refresh"),
		&yggdrasilRefreshRequest{
			AccessToken:     accessToken,
			ClientToken:     clientToken,
			SelectedProfile: &profile,
		},
		&response,
	)
	if err != nil {
		return nil, fmt.Errorf("yggdrasil refresh: %w", err)
	}
	if response.AccessToken == "" {
		return nil, fmt.Errorf("yggdrasil refresh: empty access token")
	}
	return &response, nil
}

func (c *yggdrasilConfig) join(ctx context.Context, client *http.Client, accessToken string, profile yggdrasilProfile, serverID string) error {
	err := doYggdrasilJSON(
		ctx,
		client,
		http.MethodPost,
		c.endpoint("sessionserver", "session", "minecraft", "join"),
		&yggdrasilJoinRequest{
			AccessToken:     accessToken,
			SelectedProfile: strings.ReplaceAll(profile.ID, "-", ""),
			ServerID:        serverID,
		},
		nil,
	)
	if err != nil {
		return fmt.Errorf("yggdrasil join: %w", err)
	}
	return nil
}

func (c *yggdrasilConfig) hasJoined(ctx context.Context, client *http.Client, username, serverID string) (*yggdrasilAccountProfile, error) {
	values := url.Values{}
	values.Set("username", username)
	values.Set("serverId", serverID)

	var profile yggdrasilAccountProfile
	err := doYggdrasilJSON(
		ctx,
		client,
		http.MethodGet,
		c.endpoint("sessionserver", "session", "minecraft", "hasJoined")+"?"+values.Encode(),
		nil,
		&profile,
	)
	if err != nil {
		return nil, fmt.Errorf("yggdrasil hasJoined: %w", err)
	}
	if profile.ID == "" && profile.Name == "" {
		return nil, nil
	}
	return &profile, nil
}

type yggdrasilMetadata struct {
	SignaturePublicKey string `json:"signaturePublickey"`
}

// metadata fetches the API description, which carries the public key used to
// sign texture properties. Both the API root and its trailing-slash form are
// tried because implementations differ.
func (c *yggdrasilConfig) metadata(ctx context.Context, client *http.Client) (*yggdrasilMetadata, error) {
	endpoints := []string{c.baseURL.String()}
	if c.baseURL.Path != "" && !strings.HasSuffix(c.baseURL.Path, "/") {
		withSlash := *c.baseURL
		withSlash.Path += "/"
		endpoints = append(endpoints, withSlash.String())
	}

	var lastErr error
	for _, endpoint := range endpoints {
		var metadata yggdrasilMetadata
		if err := doYggdrasilJSON(ctx, client, http.MethodGet, endpoint, nil, &metadata); err != nil {
			lastErr = err
			continue
		}
		return &metadata, nil
	}
	return nil, fmt.Errorf("yggdrasil metadata: %w", lastErr)
}

func parseYggdrasilPublicKey(value string) (*rsa.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("yggdrasil api does not expose signaturePublickey")
	}

	var der []byte
	if block, _ := pem.Decode([]byte(value)); block != nil {
		der = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
		if err != nil {
			return nil, fmt.Errorf("decode signaturePublickey: %w", err)
		}
		der = decoded
	}

	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse signaturePublickey: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signaturePublickey is not an RSA key")
	}
	return key, nil
}

func verifyYggdrasilProperty(key *rsa.PublicKey, value, signature string) error {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(signature)
		if err != nil {
			return fmt.Errorf("decode property signature: %w", err)
		}
	}

	digest := sha1.Sum([]byte(value))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, digest[:], raw); err != nil {
		return fmt.Errorf("verify property signature: %w", err)
	}
	return nil
}

// selectProfile picks the player owned by the authenticated account.
func (c *yggdrasilConfig) selectProfile(response *yggdrasilAuthenticateResponse) (yggdrasilProfile, error) {
	if c.player != "" {
		for _, available := range response.AvailableProfiles {
			if available.Name == c.player {
				return available, nil
			}
		}
		for _, available := range response.AvailableProfiles {
			if strings.EqualFold(available.Name, c.player) {
				return available, nil
			}
		}
		return yggdrasilProfile{}, fmt.Errorf(
			"yggdrasil profile %q is not available for this account",
			c.player,
		)
	}

	if response.SelectedProfile != nil {
		return *response.SelectedProfile, nil
	}
	if len(response.AvailableProfiles) == 1 {
		return response.AvailableProfiles[0], nil
	}
	if len(response.AvailableProfiles) == 0 {
		return yggdrasilProfile{}, fmt.Errorf("yggdrasil account has no available profiles")
	}

	names := make([]string, 0, len(response.AvailableProfiles))
	for _, available := range response.AvailableProfiles {
		names = append(names, available.Name)
	}
	return yggdrasilProfile{}, fmt.Errorf(
		"yggdrasil account has multiple profiles (%s), set \"player\" to choose one",
		strings.Join(names, ", "),
	)
}

type yggdrasilToken struct {
	accessToken string
	clientToken string
	profile     yggdrasilProfile
}

// yggdrasilAuth is the client side login state. Tokens are cached for the
// lifetime of the process and shared by all connections using the same account.
type yggdrasilAuth struct {
	config *yggdrasilConfig
	client *http.Client

	mu    sync.Mutex
	token yggdrasilToken

	keyMu        sync.Mutex
	signatureKey *rsa.PublicKey
}

func newYggdrasilAuth(config *yggdrasilConfig) *yggdrasilAuth {
	return &yggdrasilAuth{
		config: config,
		client: newYggdrasilHTTPClient(),
	}
}

var (
	yggdrasilAuthMu sync.Mutex
	yggdrasilAuths  = make(map[string]*yggdrasilAuth)
)

func yggdrasilAuthFor(api, username, password, player string) (*yggdrasilAuth, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("yggdrasil username and password are required on client")
	}

	config, err := newYggdrasilConfig(api, username, password, player)
	if err != nil {
		return nil, err
	}

	// The cache key uses a digest so plaintext passwords are not retained in
	// the package level map.
	digest := sha256.Sum256([]byte(password))
	key := config.baseURL.String() + "\x00" + username + "\x00" + hex.EncodeToString(digest[:]) + "\x00" + player

	yggdrasilAuthMu.Lock()
	defer yggdrasilAuthMu.Unlock()
	if auth, found := yggdrasilAuths[key]; found {
		return auth, nil
	}
	auth := newYggdrasilAuth(config)
	yggdrasilAuths[key] = auth
	return auth, nil
}

func (a *yggdrasilAuth) loginLocked(ctx context.Context) (yggdrasilToken, error) {
	if a.token.accessToken != "" && a.token.profile.ID != "" {
		return a.token, nil
	}

	response, err := a.config.authenticate(ctx, a.client, a.token.clientToken)
	if err != nil {
		return yggdrasilToken{}, err
	}

	profile, err := a.config.selectProfile(response)
	if err != nil {
		return yggdrasilToken{}, err
	}
	if _, err := normalizeMinecraftUUID(profile.ID); err != nil {
		return yggdrasilToken{}, err
	}

	token := yggdrasilToken{
		accessToken: response.AccessToken,
		clientToken: response.ClientToken,
		profile:     profile,
	}
	if token.clientToken == "" {
		token.clientToken = a.token.clientToken
	}

	// The session server only accepts a token that is already bound to the
	// selected profile, which the API only binds automatically when the
	// account owns exactly one player.
	if response.SelectedProfile == nil || !sameYggdrasilID(response.SelectedProfile.ID, profile.ID) {
		refreshed, err := a.config.refresh(ctx, a.client, token.accessToken, token.clientToken, profile)
		if err != nil {
			return yggdrasilToken{}, err
		}
		token.accessToken = refreshed.AccessToken
		if refreshed.ClientToken != "" {
			token.clientToken = refreshed.ClientToken
		}
		if refreshed.SelectedProfile != nil {
			token.profile = *refreshed.SelectedProfile
		}
	}

	a.token = token
	return token, nil
}

func (a *yggdrasilAuth) login(ctx context.Context) (yggdrasilToken, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loginLocked(ctx)
}

// join performs the standard Minecraft session join and returns the token and
// profile used for the connection. When the cached token has been revoked the
// client logs in again once.
func (a *yggdrasilAuth) join(ctx context.Context, serverID string) (yggdrasilToken, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var lastErr error
	for range yggdrasilJoinAttempts {
		token, err := a.loginLocked(ctx)
		if err != nil {
			return yggdrasilToken{}, err
		}

		err = a.config.join(ctx, a.client, token.accessToken, token.profile, serverID)
		if err == nil {
			return token, nil
		}
		lastErr = err
		if !isYggdrasilForbidden(err) {
			break
		}
		a.token = yggdrasilToken{}
	}
	return yggdrasilToken{}, lastErr
}

// verifyLoginProfile validates the signature of the signed textures property
// returned in Login Success, like a vanilla Minecraft client does.
func (a *yggdrasilAuth) verifyLoginProfile(profile loginProfile) error {
	textures, found := profile.textures()
	if !found {
		return fmt.Errorf("login success has no textures property")
	}
	if !textures.Signed || textures.Signature == "" {
		return fmt.Errorf("textures property is not signed")
	}

	key, err := a.signaturePublicKey()
	if err == nil {
		if verifyErr := verifyYggdrasilProperty(key, textures.Value, textures.Signature); verifyErr == nil {
			return nil
		}
	}

	// The API may have rotated its key pair, so fetch it again and retry once.
	key, refreshErr := a.refreshSignaturePublicKey()
	if refreshErr != nil {
		if err != nil {
			return fmt.Errorf("fetch texture signature key: %w", err)
		}
		return fmt.Errorf("refresh texture signature key: %w", refreshErr)
	}
	if verifyErr := verifyYggdrasilProperty(key, textures.Value, textures.Signature); verifyErr != nil {
		return fmt.Errorf("invalid textures signature: %w", verifyErr)
	}
	return nil
}

func (a *yggdrasilAuth) signaturePublicKey() (*rsa.PublicKey, error) {
	a.keyMu.Lock()
	defer a.keyMu.Unlock()

	if a.signatureKey != nil {
		return a.signatureKey, nil
	}
	key, err := a.fetchSignaturePublicKeyLocked()
	if err != nil {
		return nil, err
	}
	a.signatureKey = key
	return key, nil
}

func (a *yggdrasilAuth) refreshSignaturePublicKey() (*rsa.PublicKey, error) {
	a.keyMu.Lock()
	defer a.keyMu.Unlock()

	key, err := a.fetchSignaturePublicKeyLocked()
	if err != nil {
		return nil, err
	}
	a.signatureKey = key
	return key, nil
}

func (a *yggdrasilAuth) fetchSignaturePublicKeyLocked() (*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), yggdrasilRequestTimeout)
	defer cancel()

	metadata, err := a.config.metadata(ctx, a.client)
	if err != nil {
		return nil, err
	}
	return parseYggdrasilPublicKey(metadata.SignaturePublicKey)
}

// yggdrasilVerifier is the server side hasJoined check.
type yggdrasilVerifier struct {
	config *yggdrasilConfig
	client *http.Client
}

func newYggdrasilVerifier(api string) (*yggdrasilVerifier, error) {
	config, err := newYggdrasilConfig(api, "", "", "")
	if err != nil {
		return nil, err
	}
	return &yggdrasilVerifier{
		config: config,
		client: newYggdrasilHTTPClient(),
	}, nil
}

var (
	yggdrasilVerifierMu sync.Mutex
	yggdrasilVerifiers  = make(map[string]*yggdrasilVerifier)
)

// yggdrasilVerifierFor returns the process-wide verifier of one API root, so
// every connection reuses its HTTP client and its keep-alive connections
// instead of dialing the API again for each login.
func yggdrasilVerifierFor(api string) (*yggdrasilVerifier, error) {
	config, err := newYggdrasilConfig(api, "", "", "")
	if err != nil {
		return nil, err
	}
	key := config.baseURL.String()

	yggdrasilVerifierMu.Lock()
	defer yggdrasilVerifierMu.Unlock()
	if verifier, found := yggdrasilVerifiers[key]; found {
		return verifier, nil
	}
	verifier := &yggdrasilVerifier{
		config: config,
		client: newYggdrasilHTTPClient(),
	}
	yggdrasilVerifiers[key] = verifier
	return verifier, nil
}

// hasJoined returns the signed profile of the player that joined the session,
// or nil when the player has not joined this server ID.
func (v *yggdrasilVerifier) hasJoined(ctx context.Context, username, serverID string) (*yggdrasilAccountProfile, error) {
	return v.config.hasJoined(ctx, v.client, username, serverID)
}
