package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/server"
)

const (
	httpAuthTimeout = 10 * time.Second
)

var _ server.Authenticator = &HTTPAuthenticator{}

var errInvalidStatusCode = errors.New("invalid status code")

type HTTPAuthenticator struct {
	Client *http.Client
	URL    string
}

func NewHTTPAuthenticator(url string, insecure bool) *HTTPAuthenticator {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: insecure,
	}
	return &HTTPAuthenticator{
		Client: &http.Client{
			Transport: tr,
			Timeout:   httpAuthTimeout,
		},
		URL: url,
	}
}

type httpAuthRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   uint64 `json:"tx"`
}

type httpAuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

func (a *HTTPAuthenticator) post(req *httpAuthRequest) (*httpAuthResponse, error) {
	bs, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := a.Client.Post(a.URL, "application/json", bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errInvalidStatusCode
	}
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var authResp httpAuthResponse
	err = json.Unmarshal(respData, &authResp)
	if err != nil {
		return nil, err
	}
	return &authResp, nil
}

func (a *HTTPAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	req := &httpAuthRequest{
		Addr: addr.String(),
		Auth: auth,
		Tx:   tx,
	}
	resp, err := a.post(req)
	if err != nil {
		return false, ""
	}
	return resp.OK, resp.ID
}
