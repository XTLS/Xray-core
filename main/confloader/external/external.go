package external

import (
	"bytes"
	"context"
	"net"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/ctlcmd"
	"github.com/xtls/xray-core/main/confloader"
)

func ConfigLoader(arg string) (out io.Reader, err error) {
	var data []byte
	switch {
	case strings.HasPrefix(arg, "http+unix://"):
		data, err = FetchUnixSocketHTTPContent(arg)

	case strings.HasPrefix(arg, "http://"), strings.HasPrefix(arg, "https://"):
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

func FetchHTTPContent(target string) ([]byte, error) {
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return nil, errors.New("invalid URL: ", target).Base(err)
	}

	if s := strings.ToLower(parsedTarget.Scheme); s != "http" && s != "https" {
		return nil, errors.New("invalid scheme: ", parsedTarget.Scheme)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
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

// Format: http+unix:///path/to/socket.sock/api/endpoint
func FetchUnixSocketHTTPContent(target string) ([]byte, error) {
	path := strings.TrimPrefix(target, "http+unix://")
	
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("unix socket path must be absolute")
	}
	
	var socketPath, httpPath string
	
	sockIdx := strings.Index(path, ".sock")
	if sockIdx != -1 {
		socketPath = path[:sockIdx+5]
		httpPath = path[sockIdx+5:]
		if httpPath == "" {
			httpPath = "/"
		}
	} else {
		return nil, errors.New("cannot determine socket path, socket file should have .sock extension")
	}
	
	if _, err := os.Stat(socketPath); err != nil {
		return nil, errors.New("socket file not found: ", socketPath).Base(err)
	}
	
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	defer client.CloseIdleConnections()
	
	resp, err := client.Get("http://localhost" + httpPath)
	if err != nil {
		return nil, errors.New("failed to fetch from unix socket: ", socketPath).Base(err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, errors.New("unexpected HTTP status code: ", resp.StatusCode)
	}
	
	content, err := buf.ReadAllToBytes(resp.Body)
	if err != nil {
		return nil, errors.New("failed to read response").Base(err)
	}
	
	return content, nil
}

func ExtConfigLoader(files []string, reader io.Reader) (io.Reader, error) {
	buf, err := ctlcmd.Run(append([]string{"convert"}, files...), reader)
	if err != nil {
		return nil, err
	}

	return strings.NewReader(buf.String()), nil
}

func init() {
	confloader.EffectiveConfigFileLoader = ConfigLoader
	confloader.EffectiveExtConfigLoader = ExtConfigLoader
}
