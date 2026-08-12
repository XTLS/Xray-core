// Package rest implements a vless.Validator backed by a REST API described
// by rest.yaml, so a node can look up VLESS users from a central store
// instead of holding them in memory.
//
// Config.Address is the base URL of the REST backend, e.g.
// "http://user-store:8080". See rest.yaml for the exact endpoints and
// proxy/vless/validator/rest/test_serv for a minimal reference server.
//
// GetAll/GetCount depend entirely on the backend's own bookkeeping; unlike
// the memory/redis validators there is no local email-index limitation, but
// the same "email required to be listed" convention is expected of backends.
package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/validator/rest/oapi_gen"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	defaultTimeout = 5 * time.Second
)

// Validator stores VLESS users through a REST API.
type Validator struct {
	client  oapi_gen.ClientWithResponsesInterface
	timeout time.Duration
}

func NewValidator(config *Config) (*Validator, error) {
	if config == nil || strings.TrimSpace(config.Address) == "" {
		return nil, errors.New("REST validator address must not be empty")
	}

	client, err := oapi_gen.NewClientWithResponses(strings.TrimSpace(config.Address), oapi_gen.WithHTTPClient(&http.Client{
		Timeout: defaultTimeout,
	}))
	if err != nil {
		return nil, err
	}

	return &Validator{
		client:  client,
		timeout: defaultTimeout,
	}, nil
}

func (v *Validator) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), v.timeout)
}

func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("VLESS user is nil")
	}

	body, err := memoryUserToREST(u)
	if err != nil {
		return err
	}

	ctx, cancel := v.context()
	defer cancel()

	resp, err := v.client.AddVlessUserWithResponse(ctx, body)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to add VLESS user ", u.Email)
		return err
	}
	switch resp.StatusCode() {
	case http.StatusCreated:
		return nil
	case http.StatusConflict:
		return errors.New("User ", u.Email, " already exists.")
	default:
		return logResponseError("add VLESS user", resp.StatusCode(), resp.Body)
	}
}

func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	ctx, cancel := v.context()
	defer cancel()

	resp, err := v.client.DeleteVlessUserByEmailWithResponse(ctx, email)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to delete VLESS user ", email)
		return err
	}
	switch resp.StatusCode() {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return errors.New("User ", email, " not found.")
	default:
		return logResponseError("delete VLESS user", resp.StatusCode(), resp.Body)
	}
}

func (v *Validator) Get(id uuid.UUID) *protocol.MemoryUser {
	processed := uuid.UUID(vless.ProcessUUID(id))

	ctx, cancel := v.context()
	defer cancel()

	resp, err := v.client.GetVlessUserByUuidWithResponse(ctx, oapi_gen.UUID(processed))
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to get VLESS user by uuid")
		return nil
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
		if resp.StatusCode() != http.StatusNotFound {
			logResponseError("get VLESS user by uuid", resp.StatusCode(), resp.Body)
		}
		return nil
	}

	user, err := restUserToMemory(*resp.JSON200)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to decode VLESS user")
		return nil
	}
	return user
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	ctx, cancel := v.context()
	defer cancel()

	resp, err := v.client.GetVlessUserByEmailWithResponse(ctx, strings.ToLower(email))
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to get VLESS user by email ", email)
		return nil
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
		if resp.StatusCode() != http.StatusNotFound {
			logResponseError("get VLESS user by email", resp.StatusCode(), resp.Body)
		}
		return nil
	}

	user, err := restUserToMemory(*resp.JSON200)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to decode VLESS user")
		return nil
	}
	return user
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	ctx, cancel := v.context()
	defer cancel()

	resp, err := v.client.GetAllVlessUsersWithResponse(ctx)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to get all VLESS users")
		return nil
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
		logResponseError("get all VLESS users", resp.StatusCode(), resp.Body)
		return nil
	}

	users := make([]*protocol.MemoryUser, 0, len(*resp.JSON200))
	for _, restUser := range *resp.JSON200 {
		user, err := restUserToMemory(restUser)
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "REST validator: failed to decode VLESS user")
			continue
		}
		users = append(users, user)
	}
	return users
}

func (v *Validator) GetCount() int64 {
	ctx, cancel := v.context()
	defer cancel()

	resp, err := v.client.GetVlessUsersCountWithResponse(ctx)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "REST validator: failed to get VLESS users count")
		return 0
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
		logResponseError("get VLESS users count", resp.StatusCode(), resp.Body)
		return 0
	}
	return resp.JSON200.Count
}

func memoryUserToREST(u *protocol.MemoryUser) (oapi_gen.VlessUser, error) {
	account, ok := u.Account.(*vless.MemoryAccount)
	if !ok {
		return oapi_gen.VlessUser{}, errors.New("VLESS user account has unexpected type")
	}

	accountJSON, err := protojson.Marshal(account.ToProto())
	if err != nil {
		return oapi_gen.VlessUser{}, err
	}
	var restAccount oapi_gen.JSON
	if err := json.Unmarshal(accountJSON, &restAccount); err != nil {
		return oapi_gen.VlessUser{}, err
	}

	restUser := oapi_gen.VlessUser{
		Account: restAccount,
	}
	if u.Email != "" {
		restUser.Email = &u.Email
	}
	if u.Level != 0 {
		restUser.Level = &u.Level
	}
	return restUser, nil
}

func restUserToMemory(u oapi_gen.VlessUser) (*protocol.MemoryUser, error) {
	accountJSON, err := json.Marshal(u.Account)
	if err != nil {
		return nil, err
	}
	accountProto := new(vless.Account)
	if err := protojson.Unmarshal(accountJSON, accountProto); err != nil {
		return nil, err
	}
	account, err := accountProto.AsAccount()
	if err != nil {
		return nil, err
	}

	user := &protocol.MemoryUser{
		Account: account,
	}
	if u.Email != nil {
		user.Email = *u.Email
	}
	if u.Level != nil {
		user.Level = *u.Level
	}
	return user, nil
}

func logResponseError(operation string, status int, body []byte) error {
	err := responseError(operation, status, body)
	errors.LogWarningInner(context.Background(), err, "REST validator: backend call failed")
	return err
}

func responseError(operation string, status int, body []byte) error {
	if len(body) == 0 {
		return errors.New(operation, " failed with HTTP status ", status)
	}
	return errors.New(operation, " failed with HTTP status ", status, ": ", fmt.Sprintf("%s", body))
}
