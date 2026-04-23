package champa

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/xtls/xray-core/transport/internet/champa/internal/amp"
	"github.com/xtls/xray-core/transport/internet/champa/internal/armor"
)

func cacheBreaker() []byte {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// exchangeAMP performs one HTTP poll: it constructs the cache-buster URL,
// optionally rewrites it through the AMP cache, optionally rewrites the host
// for domain fronting, and decodes the AMP-armored response body. Lifted from
// champa/champa-client/amp.go.
func exchangeAMP(ctx context.Context, rt http.RoundTripper, serverURL, cacheURL *url.URL, front string, p []byte) (io.ReadCloser, error) {
	u := serverURL.ResolveReference(&url.URL{
		Path: strings.Join([]string{
			"0" + base64.RawURLEncoding.EncodeToString(cacheBreaker()),
			base64.RawURLEncoding.EncodeToString(p),
		}, "/"),
	})

	if cacheURL != nil {
		var err error
		u, err = amp.CacheURL(u, cacheURL, "c")
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	if front != "" {
		_, port, err := net.SplitHostPort(req.URL.Host)
		if err == nil {
			req.URL.Host = net.JoinHostPort(front, port)
		} else {
			req.URL.Host = front
		}
	}

	req.Header.Set("User-Agent", "")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("server returned status %v", resp.Status)
	}
	if _, err := resp.Location(); err == nil {
		// AMP cache "silent redirect" — see champa-client/amp.go for context.
		resp.Body.Close()
		return nil, fmt.Errorf("server returned a Location header")
	}

	dec, err := armor.NewDecoder(bufio.NewReader(resp.Body))
	if err != nil {
		resp.Body.Close()
		return nil, err
	}

	return &struct {
		io.Reader
		io.Closer
	}{Reader: dec, Closer: resp.Body}, nil
}
