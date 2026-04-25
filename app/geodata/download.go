package geodata

import (
	"context"
	go_errors "errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

const idleTimeout = 30 * time.Second

type stage struct {
	target string
	temp   string
}

type downloader struct {
	ctx    context.Context
	client *http.Client
}

type idleConn struct {
	net.Conn
}

func (c *idleConn) Read(b []byte) (int, error) {
	t := time.AfterFunc(idleTimeout, func() {
		_ = c.Close()
	})

	n, err := c.Conn.Read(b)
	if !t.Stop() {
		_ = c.Close()
		return n, errors.New("connection idle timeout")
	}
	return n, err
}

func (c *idleConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func newDownloader(ctx context.Context, dispatcher routing.Dispatcher, outbound string) *downloader {
	return &downloader{
		ctx:    ctx,
		client: newClient(ctx, dispatcher, outbound),
	}
}

func newClient(baseCtx context.Context, dispatcher routing.Dispatcher, outbound string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				var conn net.Conn
				err := task.Run(ctx, func() error {
					if tagged.Dialer == nil {
						return errors.New("tagged dialer is not initialized")
					}
					dest, err := net.ParseDestination(network + ":" + address)
					if err != nil {
						return errors.New("cannot understand address").Base(err)
					}
					c, err := tagged.Dialer(baseCtx, dispatcher, dest, outbound)
					if err != nil {
						return errors.New("cannot dial remote address ", dest).Base(err)
					}
					conn = c
					return nil
				})
				if err != nil {
					return nil, errors.New("cannot finish connection").Base(err)
				}
				return &idleConn{
					Conn: conn,
				}, nil
			},
			TLSHandshakeTimeout:   idleTimeout,
			ResponseHeaderTimeout: idleTimeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("redirected to non-https URL: ", req.URL.String())
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
}

func (d *downloader) download(assets []*Asset) ([]stage, error) {
	staged := make([]stage, 0, len(assets))
	for _, asset := range assets {
		stage, err := d.downloadOne(asset)
		if err != nil {
			clean(staged)
			return nil, err
		}
		staged = append(staged, stage)
	}
	return staged, nil
}

func (d *downloader) downloadOne(asset *Asset) (stage, error) {
	target, err := filesystem.ResolveAsset(asset.File)
	if err != nil {
		return stage{}, err
	}
	errors.LogInfo(d.ctx, "downloading geodata asset from ", asset.Url, " to ", target)

	temp, err := tempFile(target, ".tmp")
	if err != nil {
		return stage{}, err
	}
	tempName := temp.Name()
	keepTemp := false
	defer func() {
		if !keepTemp {
			os.Remove(tempName)
		}
	}()

	if err := d.fetch(asset.Url, temp); err != nil {
		temp.Close()
		return stage{}, err
	}
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return stage{}, err
	}
	if err := temp.Close(); err != nil {
		return stage{}, err
	}

	keepTemp = true
	return stage{
		target: target,
		temp:   tempName,
	}, nil
}

func (d *downloader) fetch(rawURL string, writer io.Writer) error {
	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		io.Copy(io.Discard, resp.Body)
		return errors.New("unexpected status code: ", resp.StatusCode)
	}

	n, err := io.Copy(writer, resp.Body)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("empty response body")
	}
	return nil
}

func clean(assets []stage) {
	for _, asset := range assets {
		if asset.temp != "" {
			os.Remove(asset.temp)
		}
	}
}

type tx struct {
	swaps []swap
}

type swap struct {
	target      string
	backup      string
	hadOriginal bool
}

func swapAll(assets []stage) (*tx, error) {
	t := &tx{}
	for _, asset := range assets {
		s, err := swapOne(asset)
		if err != nil {
			return nil, errors.Combine(err, t.rollback())
		}
		t.swaps = append(t.swaps, s)
	}
	return t, nil
}

func swapOne(asset stage) (swap, error) {
	backup, err := backupFile(asset.target)
	if err != nil {
		return swap{}, err
	}

	s := swap{
		target: asset.target,
		backup: backup,
	}
	if err := os.Rename(asset.target, backup); err != nil {
		if !go_errors.Is(err, os.ErrNotExist) {
			return swap{}, err
		}
		if err := os.Remove(backup); err != nil && !go_errors.Is(err, os.ErrNotExist) {
			return swap{}, err
		}
	} else {
		s.hadOriginal = true
	}

	if err := os.Rename(asset.temp, asset.target); err != nil {
		if s.hadOriginal {
			if restoreErr := os.Rename(backup, asset.target); restoreErr != nil {
				return swap{}, errors.Combine(err, restoreErr)
			}
		}
		return swap{}, err
	}

	return s, nil
}

func (t *tx) rollback() error {
	var errs []error
	for i := len(t.swaps) - 1; i >= 0; i-- {
		if err := t.swaps[i].rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Combine(errs...)
}

func (s swap) rollback() error {
	var errs []error
	if err := os.Remove(s.target); err != nil && !go_errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if s.hadOriginal {
		if err := os.Rename(s.backup, s.target); err != nil {
			errs = append(errs, err)
		}
	} else if err := os.Remove(s.backup); err != nil && !go_errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Combine(errs...)
}

func (t *tx) commit() error {
	var errs []error
	for _, swap := range t.swaps {
		if err := os.Remove(swap.backup); err != nil && !go_errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Combine(errs...)
}

func tempFile(target string, suffix string) (*os.File, error) {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.CreateTemp(dir, "."+filepath.Base(target)+".*"+suffix)
}

func backupFile(target string) (string, error) {
	file, err := tempFile(target, ".bak")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}
