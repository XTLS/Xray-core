package external

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/main/confloader"
)

func ConfigLoader(arg string) (out io.Reader, err error) {
	var data []byte
	switch {
	case strings.HasPrefix(arg, "http+unix://"):
		errors.PrintDeprecatedFeatureWarning(`"http+unix://" prefix`, `direct Unix socket path (e.g. /path/socket.sock:/api or @abstract:/api)`)
		data, err = FetchHTTPContent(httpUnixToCanonical(arg))

	case isRemoteSource(arg):
		data, err = FetchHTTPContent(arg)

	case arg == "stdin:":
		data, err = io.ReadAll(os.Stdin)

	default:
		data, err = os.ReadFile(arg)
	}

	if err != nil {
		return
	}
	out = bytes.NewBuffer(data)
	return
}

// FetchHTTPContent issues an HTTP GET against either a regular HTTP(S) URL
// or a Unix socket HTTP endpoint.
//
//	http(s)://host/api          regular HTTP(S)
//	/path/to/socket.sock[:/api] filesystem socket
//	@abstract[:/api]            abstract socket (Linux/Android)
//	@@padded[:/api]             padded abstract socket (HAProxy compat)
//
// When the ":/" separator is omitted on a socket target, the request is
// made to "/".
func FetchHTTPContent(target string) ([]byte, error) {
	httpURL, socketPath := utils.SplitHTTPUnixURL(target)

	parsedTarget, err := url.Parse(httpURL)
	if err != nil {
		return nil, errors.New("invalid URL: ", target).Base(err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if socketPath != "" {
		dialAddr := utils.ResolveSocketPath(socketPath)
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", dialAddr)
			},
		}
	}

	resp, err := client.Do(&http.Request{
		Method: "GET",
		URL:    parsedTarget,
		Close:  true,
	})
	if err != nil {
		return nil, errors.New("failed to dial to ", target).Base(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("unexpected HTTP status code: ", resp.StatusCode)
	}

	content, err := buf.ReadAllToBytes(resp.Body)
	if err != nil {
		return nil, errors.New("failed to read HTTP response").Base(err)
	}

	return content, nil
}

// isRemoteSource reports whether arg should be fetched via HTTP (regular
// network or Unix socket) rather than read from the local filesystem.
// Recognized forms:
//
//   - http(s)://...           regular HTTP(S)
//   - @abstract[:/api]        abstract socket (Linux/Android)
//   - /abs/path:/api          filesystem socket, explicit HTTP path
//   - /abs/path               filesystem socket detected via os.ModeSocket
func isRemoteSource(arg string) bool {
	if arg == "" {
		return false
	}
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return true
	}
	if arg[0] == '@' {
		return true
	}
	if arg[0] != '/' {
		return false
	}
	if strings.Contains(arg, ":/") {
		return true
	}
	info, err := os.Stat(arg)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// httpUnixToCanonical converts the deprecated http+unix:///path/to/socket.sock/api
// URL into the canonical /path/to/socket.sock:/api form by inserting ":"
// between the ".sock" extension and the HTTP path. Inputs without a path
// after ".sock" are returned with just the "http+unix://" prefix stripped.
func httpUnixToCanonical(target string) string {
	raw := strings.TrimPrefix(target, "http+unix://")
	if i := strings.Index(raw, ".sock/"); i >= 0 {
		raw = raw[:i+5] + ":" + raw[i+5:]
	}
	return raw
}

func init() {
	confloader.EffectiveConfigFileLoader = ConfigLoader
}
