package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/validator/rest/oapi_gen"
)

type TestServer struct {
	mu     sync.RWMutex
	byID   map[string]oapi_gen.VlessUser
	byMail map[string]string
}

func NewTestServer() *TestServer {
	return &TestServer{
		byID:   make(map[string]oapi_gen.VlessUser),
		byMail: make(map[string]string),
	}
}

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)

	server := NewTestServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.healthz)
	mux.HandleFunc("/vless/validator/users", server.users)
	mux.HandleFunc("/vless/validator/users/count", server.GetVlessUsersCount)
	mux.HandleFunc("/vless/validator/users/by-id/", server.userByID)
	mux.HandleFunc("/vless/validator/users/by-email/", server.userByEmail)

	log.Printf("REST validator test server starting listen=%s", *listen)
	if err := http.ListenAndServe(*listen, logMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func (t *TestServer) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (t *TestServer) users(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		t.GetAllVlessUsers(w, r)
	case http.MethodPost:
		t.AddVlessUser(w, r)
	default:
		writeProblem(w, r, http.StatusMethodNotAllowed, "Method not allowed", "unsupported method")
	}
}

func (t *TestServer) userByID(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimPrefix(r.URL.Path, "/vless/validator/users/by-id/")
	if rawID == "" {
		writeProblem(w, r, http.StatusBadRequest, "Bad request", "empty uuid")
		return
	}
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "Method not allowed", "unsupported method")
		return
	}
	id, err := uuid.ParseString(rawID)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	t.GetVlessUserByUuid(w, r, oapi_gen.UUID(id))
}

func (t *TestServer) userByEmail(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimPrefix(r.URL.Path, "/vless/validator/users/by-email/")
	if email == "" {
		writeProblem(w, r, http.StatusBadRequest, "Bad request", "empty email")
		return
	}
	switch r.Method {
	case http.MethodGet:
		t.GetVlessUserByEmail(w, r, email)
	case http.MethodDelete:
		t.DeleteVlessUserByEmail(w, r, email)
	default:
		writeProblem(w, r, http.StatusMethodNotAllowed, "Method not allowed", "unsupported method")
	}
}

func (t *TestServer) GetAllVlessUsers(w http.ResponseWriter, r *http.Request) {
	t.mu.RLock()
	users := make([]oapi_gen.VlessUser, 0, len(t.byID))
	for _, user := range t.byID {
		users = append(users, user)
	}
	t.mu.RUnlock()

	log.Printf("storage get_all count=%d", len(users))
	writeJSON(w, http.StatusOK, users)
}

func (t *TestServer) AddVlessUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	log.Printf("storage add raw_body=%s", string(body))

	var user oapi_gen.VlessUser
	if err := json.Unmarshal(body, &user); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "Bad request", err.Error())
		return
	}

	id, err := userID(user)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	email := lowerEmail(user)

	t.mu.Lock()
	defer t.mu.Unlock()

	if email != "" {
		if existingID, ok := t.byMail[email]; ok && existingID != id {
			log.Printf("storage add conflict email=%s existing_id=%s new_id=%s", email, existingID, id)
			writeProblem(w, r, http.StatusConflict, "User already exists", "email already exists")
			return
		}
		t.byMail[email] = id
	}
	t.byID[id] = user

	log.Printf("storage add ok id=%s email=%s users=%d emails=%d account=%s", id, email, len(t.byID), len(t.byMail), compactJSON(user.Account))
	writeJSON(w, http.StatusCreated, user)
}

func (t *TestServer) DeleteVlessUserByEmail(w http.ResponseWriter, r *http.Request, email oapi_gen.Email) {
	key := strings.ToLower(email)

	t.mu.Lock()
	defer t.mu.Unlock()

	id, ok := t.byMail[key]
	if !ok {
		log.Printf("storage delete miss email=%s", key)
		writeProblem(w, r, http.StatusNotFound, "User not found", "email not found")
		return
	}
	delete(t.byMail, key)
	delete(t.byID, id)

	log.Printf("storage delete ok email=%s id=%s users=%d emails=%d", key, id, len(t.byID), len(t.byMail))
	w.WriteHeader(http.StatusNoContent)
}

func (t *TestServer) GetVlessUserByEmail(w http.ResponseWriter, r *http.Request, email oapi_gen.Email) {
	key := strings.ToLower(email)

	t.mu.RLock()
	id, ok := t.byMail[key]
	user := t.byID[id]
	t.mu.RUnlock()

	if !ok {
		log.Printf("storage get_by_email miss email=%s", key)
		writeProblem(w, r, http.StatusNotFound, "User not found", "email not found")
		return
	}

	log.Printf("storage get_by_email ok email=%s id=%s account=%s", key, id, compactJSON(user.Account))
	writeJSON(w, http.StatusOK, user)
}

func (t *TestServer) GetVlessUserByUuid(w http.ResponseWriter, r *http.Request, id oapi_gen.UUID) {
	key := normalizedID(uuid.UUID(id))

	t.mu.RLock()
	user, ok := t.byID[key]
	t.mu.RUnlock()

	if !ok {
		log.Printf("storage get_by_uuid miss id=%s", key)
		writeProblem(w, r, http.StatusNotFound, "User not found", "uuid not found")
		return
	}

	log.Printf("storage get_by_uuid ok id=%s email=%s account=%s", key, lowerEmail(user), compactJSON(user.Account))
	writeJSON(w, http.StatusOK, user)
}

func (t *TestServer) GetVlessUsersCount(w http.ResponseWriter, r *http.Request) {
	t.mu.RLock()
	count := len(t.byMail)
	t.mu.RUnlock()

	log.Printf("storage count=%d", count)
	writeJSON(w, http.StatusOK, oapi_gen.UsersCount{Count: int64(count)})
}

func userID(user oapi_gen.VlessUser) (string, error) {
	rawID, ok := user.Account["id"].(string)
	if !ok || rawID == "" {
		return "", fmt.Errorf("account.id must be a non-empty string")
	}
	id, err := uuid.ParseString(rawID)
	if err != nil {
		return "", err
	}
	return normalizedID(id), nil
}

func normalizedID(id uuid.UUID) string {
	processed := uuid.UUID(vless.ProcessUUID(id))
	return processed.String()
}

func lowerEmail(user oapi_gen.VlessUser) string {
	if user.Email == nil {
		return ""
	}
	return strings.ToLower(*user.Email)
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("response encode error status=%d error=%v", status, err)
	}
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	log.Printf("storage error status=%d title=%q detail=%q path=%s", status, title, detail, r.URL.Path)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oapi_gen.Error{
		Type:     fmt.Sprintf("urn:vless-validator:test:%d", status),
		Title:    title,
		Status:   status,
		Detail:   &detail,
		Instance: stringPtr(r.URL.Path),
	})
}

func stringPtr(value string) *string {
	return &value
}

func compactJSON(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("<json error: %v>", err)
	}
	return string(data)
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("http request method=%s path=%s remote=%s status=%d duration=%s user_agent=%q",
			r.Method, r.URL.Path, r.RemoteAddr, rec.status, time.Since(start), r.UserAgent())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
