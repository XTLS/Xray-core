package xmc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func deriveTestRSAKey(t *testing.T, password string) ([]byte, []byte) {
	t.Helper()

	key, err := DeriveRSAKey(password)
	if err != nil {
		t.Fatalf("failed to derive rsa key: %v", err)
	}

	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return x509.MarshalPKCS1PrivateKey(key), publicKey
}

type fakeYggdrasilProfile struct {
	ID   string
	Name string
}

type fakeYggdrasil struct {
	mu sync.Mutex

	profile fakeYggdrasilProfile

	signingKey   *rsa.PrivateKey
	publicKeyPEM string

	authenticateCalls int
	refreshCalls      int
	joinCalls         int

	boundProfile string
	joined       map[string]string // serverId -> profile name
}

func writeFakeYggdrasilJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func newFakeYggdrasilHandler(state *fakeYggdrasil) http.Handler {
	mux := http.NewServeMux()
	prefix := "/api/yggdrasil"

	metadata := func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		key := state.publicKeyPEM
		state.mu.Unlock()
		writeFakeYggdrasilJSON(w, http.StatusOK, fmt.Sprintf(
			`{"meta":{"serverName":"Fake Skin"},"skinDomains":["example.com"],"signaturePublickey":%q}`,
			key,
		))
	}
	mux.HandleFunc(prefix, metadata)
	mux.HandleFunc(prefix+"/", metadata)

	mux.HandleFunc(prefix+"/authserver/authenticate", func(w http.ResponseWriter, r *http.Request) {
		var request yggdrasilAuthenticateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeFakeYggdrasilJSON(w, http.StatusBadRequest, `{"error":"IllegalArgumentException","errorMessage":"bad request"}`)
			return
		}
		if request.Username != "user@example.com" || request.Password != "password" {
			writeFakeYggdrasilJSON(w, http.StatusForbidden, `{"error":"ForbiddenOperationException","errorMessage":"bad credentials"}`)
			return
		}

		state.mu.Lock()
		defer state.mu.Unlock()
		state.authenticateCalls++
		writeFakeYggdrasilJSON(w, http.StatusOK, fmt.Sprintf(
			`{"accessToken":"token-1","clientToken":"client-1","availableProfiles":[{"id":%q,"name":%q}],"selectedProfile":{"id":%q,"name":%q}}`,
			state.profile.ID, state.profile.Name, state.profile.ID, state.profile.Name,
		))
	})

	mux.HandleFunc(prefix+"/authserver/refresh", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.refreshCalls++
		writeFakeYggdrasilJSON(w, http.StatusOK, fmt.Sprintf(
			`{"accessToken":"token-2","clientToken":"client-1","selectedProfile":{"id":%q,"name":%q}}`,
			state.profile.ID, state.profile.Name,
		))
	})

	mux.HandleFunc(prefix+"/sessionserver/session/minecraft/join", func(w http.ResponseWriter, r *http.Request) {
		var request yggdrasilJoinRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeFakeYggdrasilJSON(w, http.StatusBadRequest, `{"error":"IllegalArgumentException","errorMessage":"bad request"}`)
			return
		}

		state.mu.Lock()
		defer state.mu.Unlock()
		state.joinCalls++
		state.boundProfile = request.SelectedProfile
		state.joined[request.ServerID] = state.profile.Name
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc(prefix+"/sessionserver/session/minecraft/hasJoined", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()

		name, found := state.joined[r.URL.Query().Get("serverId")]
		if !found || name != r.URL.Query().Get("username") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		digest := sha1.Sum([]byte("textures-value"))
		signature, err := rsa.SignPKCS1v15(rand.Reader, state.signingKey, crypto.SHA1, digest[:])
		if err != nil {
			writeFakeYggdrasilJSON(w, http.StatusInternalServerError, `{"error":"InternalError"}`)
			return
		}
		writeFakeYggdrasilJSON(w, http.StatusOK, fmt.Sprintf(
			`{"id":%q,"name":%q,"properties":[{"name":"textures","value":"textures-value","signature":%q},{"name":"uploadableTextures","value":"skin,cape"}]}`,
			state.profile.ID, state.profile.Name, base64.StdEncoding.EncodeToString(signature),
		))
	})

	return mux
}

func newFakeYggdrasilServer(t *testing.T) (*fakeYggdrasil, string) {
	t.Helper()

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal signing key: %v", err)
	}

	state := &fakeYggdrasil{
		profile: fakeYggdrasilProfile{
			ID:   "0123456789abcdef0123456789abcdef",
			Name: "SkinUser",
		},
		signingKey:   signingKey,
		publicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		joined:       make(map[string]string),
	}
	server := httptest.NewServer(newFakeYggdrasilHandler(state))
	t.Cleanup(server.Close)

	return state, server.URL + "/api/yggdrasil"
}

func newTestYggdrasilAuth(t *testing.T, api, player string) *yggdrasilAuth {
	t.Helper()
	config, err := newYggdrasilConfig(api, "user@example.com", "password", player)
	if err != nil {
		t.Fatalf("new yggdrasil config: %v", err)
	}
	return newYggdrasilAuth(config)
}

func TestMinecraftServerID(t *testing.T) {
	// Vectors from the Java implementation (SHA-1 hexdigest as a signed
	// BigInteger), including a negative hash.
	for input, want := range map[string]string{
		"Notch": "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48",
		"jeb_":  "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1",
		"simon": "88e16a1019277b15d58faf0541e11910eb756f6",
	} {
		if got := minecraftServerID(input, nil, nil); got != want {
			t.Fatalf("server ID for %q = %q, want %q", input, got, want)
		}
	}

	// Java renders the digest as a signed BigInteger, so mirrors of the
	// two's-complement sign and of leading zero trimming are covered.
	signedHash := func(serverID string, secret, publicKey []byte) string {
		hasher := sha1.New()
		_, _ = hasher.Write([]byte(serverID))
		_, _ = hasher.Write(secret)
		_, _ = hasher.Write(publicKey)
		digest := hasher.Sum(nil)
		value := new(big.Int).SetBytes(digest)
		if digest[0]&0x80 != 0 {
			value.Sub(value, new(big.Int).Lsh(big.NewInt(1), 160))
		}
		return value.Text(16)
	}

	secret := []byte("0123456789abcdef")
	publicKey := []byte("public-key")
	foundPositive := false
	foundNegative := false
	for i := 0; i < 1<<16; i++ {
		serverID := fmt.Sprintf("probe-%d", i)
		got := minecraftServerID(serverID, secret, publicKey)
		want := signedHash(serverID, secret, publicKey)
		if got != want {
			t.Fatalf("server ID for %q = %q, want %q", serverID, got, want)
		}
		if strings.HasPrefix(want, "-") {
			foundNegative = true
		} else {
			foundPositive = true
		}
		if foundPositive && foundNegative {
			return
		}
	}
	t.Fatalf("probe did not cover both hash signs: positive=%v negative=%v", foundPositive, foundNegative)
}

func TestYggdrasilAuthenticateCachesToken(t *testing.T) {
	state, api := newFakeYggdrasilServer(t)
	auth := newTestYggdrasilAuth(t, api, "SkinUser")

	token, err := auth.login(context.Background())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if token.profile.ID != state.profile.ID || token.profile.Name != state.profile.Name {
		t.Fatalf("unexpected profile: %+v", token.profile)
	}

	if _, err := auth.login(context.Background()); err != nil {
		t.Fatalf("second login: %v", err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authenticateCalls != 1 {
		t.Fatalf("token was not cached: authenticate calls = %d", state.authenticateCalls)
	}
	if state.refreshCalls != 0 {
		t.Fatalf("unexpected refresh calls: %d", state.refreshCalls)
	}
}

func TestYggdrasilSelectsPlayerAndBindsToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/yggdrasil/authserver/authenticate", func(w http.ResponseWriter, r *http.Request) {
		writeFakeYggdrasilJSON(w, http.StatusOK, `{"accessToken":"token-1","clientToken":"client-1","availableProfiles":[`+
			`{"id":"0123456789abcdef0123456789abcdef","name":"FirstPlayer"},`+
			`{"id":"fedcba9876543210fedcba9876543210","name":"SecondPlayer"}]}`)
	})

	var refreshed string
	mux.HandleFunc("/api/yggdrasil/authserver/refresh", func(w http.ResponseWriter, r *http.Request) {
		var request yggdrasilRefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode refresh: %v", err)
			return
		}
		if request.SelectedProfile == nil {
			t.Error("refresh did not select a profile")
			return
		}
		refreshed = request.SelectedProfile.Name
		writeFakeYggdrasilJSON(w, http.StatusOK, `{"accessToken":"token-2","clientToken":"client-1","selectedProfile":{"id":"fedcba9876543210fedcba9876543210","name":"SecondPlayer"}}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	auth := newTestYggdrasilAuth(t, server.URL+"/api/yggdrasil", "SecondPlayer")
	token, err := auth.login(context.Background())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if token.profile.Name != "SecondPlayer" || token.accessToken != "token-2" {
		t.Fatalf("unexpected token: %+v", token)
	}
	if refreshed != "SecondPlayer" {
		t.Fatalf("refresh selected %q", refreshed)
	}
}

func TestYggdrasilRejectsMultiplePlayersWithoutSelection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/yggdrasil/authserver/authenticate", func(w http.ResponseWriter, r *http.Request) {
		writeFakeYggdrasilJSON(w, http.StatusOK, `{"accessToken":"token-1","clientToken":"client-1","availableProfiles":[{"id":"0123456789abcdef0123456789abcdef","name":"FirstPlayer"},{"id":"fedcba9876543210fedcba9876543210","name":"SecondPlayer"}]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	auth := newTestYggdrasilAuth(t, server.URL+"/api/yggdrasil", "")
	if _, err := auth.login(context.Background()); err == nil || !strings.Contains(err.Error(), "multiple profiles") {
		t.Fatalf("expected multiple profiles error, got %v", err)
	}
}

func TestYggdrasilRejectsInvalidAPI(t *testing.T) {
	for _, api := range []string{
		"",
		"ftp://example.com/api/yggdrasil",
		"https://example.com/api/yggdrasil?query=1",
		"https://example.com/api/yggdrasil#fragment",
		"/api/yggdrasil",
	} {
		if _, err := newYggdrasilConfig(api, "user", "password", ""); err == nil {
			t.Fatalf("api %q was accepted", api)
		}
	}
}

func TestHandshakeWithYggdrasil(t *testing.T) {
	state, api := newFakeYggdrasilServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	password := "yggdrasil-rsa-seed"
	privateKey, publicKey := deriveTestRSAKey(t, password)
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)

		rawConn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer rawConn.Close()

		verifier, err := newYggdrasilVerifier(api)
		if err != nil {
			t.Errorf("new verifier: %v", err)
			return
		}
		server, err := wrapConnServer(rawConn, nil, password, privateKey, publicKey, nil, verifier)
		if err != nil {
			t.Errorf("wrap server: %v", err)
			return
		}

		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if !bytes.Equal(buf[:n], []byte("hello server")) {
			t.Errorf("unexpected client payload: %q", buf[:n])
			return
		}
		if _, err := server.Write([]byte("hello client")); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawClient.Close()

	// The client intentionally has no pinned server key: Yggdrasil mode accepts
	// the key sent by the server and binds it through the session hash.
	client, err := newClientConn(rawClient, nil, password, nil, "localhost", nil, newTestYggdrasilAuth(t, api, "SkinUser"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("hello server")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	response := make([]byte, len("hello client"))
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(response) != "hello client" {
		t.Fatalf("unexpected response: %q", response)
	}

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake timed out")
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.joinCalls != 1 {
		t.Errorf("join calls = %d", state.joinCalls)
	}
	if state.boundProfile != state.profile.ID {
		t.Errorf("joined profile = %q", state.boundProfile)
	}
}

func TestYggdrasilVerifiesTexturesSignature(t *testing.T) {
	state, api := newFakeYggdrasilServer(t)
	auth := newTestYggdrasilAuth(t, api, "SkinUser")

	signTextures := func(key *rsa.PrivateKey, value string) loginProfile {
		digest := sha1.Sum([]byte(value))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
		if err != nil {
			t.Fatalf("sign textures: %v", err)
		}
		return loginProfile{
			Username: "SkinUser",
			Properties: loginProperties{
				{Name: "textures", Value: value, Signature: base64.StdEncoding.EncodeToString(signature), Signed: true},
			},
		}
	}

	valid := signTextures(state.signingKey, "textures-value")
	if err := auth.verifyLoginProfile(valid); err != nil {
		t.Fatalf("valid textures signature was rejected: %v", err)
	}

	tampered := valid
	tampered.Properties = loginProperties{
		{Name: "textures", Value: "tampered-value", Signature: valid.Properties[0].Signature, Signed: true},
	}
	if err := auth.verifyLoginProfile(tampered); err == nil {
		t.Fatal("tampered textures value was accepted")
	}

	unsigned := loginProfile{
		Username: "SkinUser",
		Properties: loginProperties{
			{Name: "textures", Value: "textures-value"},
		},
	}
	if err := auth.verifyLoginProfile(unsigned); err == nil {
		t.Fatal("unsigned textures property was accepted")
	}

	missing := loginProfile{Username: "SkinUser"}
	if err := auth.verifyLoginProfile(missing); err == nil {
		t.Fatal("missing textures property was accepted")
	}

	// The API may rotate its signing key; the cached key must be refreshed.
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rotated key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rotatedKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rotated key: %v", err)
	}
	state.mu.Lock()
	state.signingKey = rotatedKey
	state.publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	state.mu.Unlock()

	if err := auth.verifyLoginProfile(signTextures(rotatedKey, "textures-value")); err != nil {
		t.Fatalf("rotated textures signature was rejected: %v", err)
	}
}

func TestYggdrasilJoinRetriesAfterForbidden(t *testing.T) {
	var mu sync.Mutex
	authenticateCalls := 0
	joinCalls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/api/yggdrasil/authserver/authenticate", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authenticateCalls++
		calls := authenticateCalls
		mu.Unlock()
		writeFakeYggdrasilJSON(w, http.StatusOK, fmt.Sprintf(
			`{"accessToken":"token-%d","clientToken":"client-1","availableProfiles":[{"id":"0123456789abcdef0123456789abcdef","name":"SkinUser"}],"selectedProfile":{"id":"0123456789abcdef0123456789abcdef","name":"SkinUser"}}`,
			calls,
		))
	})
	mux.HandleFunc("/api/yggdrasil/sessionserver/session/minecraft/join", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		joinCalls++
		calls := joinCalls
		mu.Unlock()
		if calls == 1 {
			writeFakeYggdrasilJSON(w, http.StatusForbidden, `{"error":"ForbiddenOperationException","errorMessage":"Invalid token"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	auth := newTestYggdrasilAuth(t, server.URL+"/api/yggdrasil", "SkinUser")
	token, err := auth.join(context.Background(), "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if token.accessToken != "token-2" {
		t.Fatalf("token = %q", token.accessToken)
	}

	mu.Lock()
	defer mu.Unlock()
	if authenticateCalls != 2 || joinCalls != 2 {
		t.Fatalf("calls: authenticate=%d join=%d", authenticateCalls, joinCalls)
	}
}

func TestYggdrasilLoginFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	password := "yggdrasil-login-failure"
	privateKey, publicKey := deriveTestRSAKey(t, password)
	api := "http://127.0.0.1:1/api/yggdrasil"

	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		verifier, err := newYggdrasilVerifier(api)
		if err != nil {
			return
		}
		server, err := wrapConnServer(rawConn, nil, password, privateKey, publicKey, nil, verifier)
		if err != nil {
			return
		}
		buf := make([]byte, 16)
		_, _ = server.Read(buf)
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawClient.Close()

	client, err := newClientConn(rawClient, nil, password, publicKey, "localhost", nil, newTestYggdrasilAuth(t, api, ""))
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("expected yggdrasil login to fail")
	}
}

func TestYggdrasilPropertyConversion(t *testing.T) {
	properties := propertyListFromYggdrasil([]yggdrasilProperty{
		{Name: "textures", Value: "value", Signature: "signature"},
		{Name: "uploadableTextures", Value: "skin,cape"},
	})
	if len(properties) != 2 {
		t.Fatalf("unexpected properties: %+v", properties)
	}
	if !properties[0].Signed || properties[0].Signature != "signature" {
		t.Fatalf("signed property was not preserved: %+v", properties[0])
	}
	if properties[1].Signed {
		t.Fatalf("unsigned property was marked signed: %+v", properties[1])
	}
	profile := loginProfile{
		Username:   "SkinUser",
		Properties: properties,
	}
	textures, found := profile.textures()
	if !found || textures.Value != "value" {
		t.Fatalf("textures property not found: %+v", profile)
	}
}

func TestYggdrasilVerifierCache(t *testing.T) {
	first, err := yggdrasilVerifierFor("https://skin.example.com/api/yggdrasil")
	if err != nil {
		t.Fatal(err)
	}
	second, err := yggdrasilVerifierFor("https://skin.example.com/api/yggdrasil/")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("the verifier was not reused for the same API root")
	}
}
